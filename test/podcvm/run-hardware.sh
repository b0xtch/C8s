#!/usr/bin/env bash
# run-hardware.sh: boot pod CVMs on this host and run the hardware suite.
#
# Three guests are booted one after another on QEMU's user-mode network, so
# the script needs neither a cluster nor network privilege:
#
#   a  the launch bundle under test. The whole suite runs against it, once
#      per collateral mode: attest, release, exec, the evidence rejection
#      cases and the tenant probes.
#   b  the same image under another launch key, as a host substituting its
#      own key would boot it. A verifier holding bundle a must refuse it.
#   c  a document signed for another image (TDX only). The guest itself must
#      refuse to stage and power off without ever serving its API.
#
# Usage: test/podcvm/run-hardware.sh
#
#   C8S_POD_IMAGE_DIR     pod guest image directory: disk.raw, firmware and
#                         manifest.json. Required.
#   C8S_POD_PLATFORM      tdx (default) or snp
#   C8S_POD_QEMU          QEMU binary (default qemu-system-x86_64)
#   C8S_POD_QUOTE_SOCKET  host quoting service: a unix socket path or
#                         vsock:<cid>:<port> (default
#                         /var/run/tdx-qgs/qgs.socket when it exists)
#   C8S_POD_VSOCK_CID     guest vsock CID, enabling the fast quote path
#   C8S_POD_PORT          local port published for the agent (default 28443)
#   C8S_POD_COLLATERAL    collateral modes to run (default "required skip")
#   C8S_POD_VCPUS, C8S_POD_MEMORY, C8S_POD_SCRATCH   guest shape (2, 2G, 4G)
#   C8S_POD_BOOT_TIMEOUT  seconds to wait for a guest (default 180)
#   C8S_POD_CONSOLE=1     attach the guest console (dev images only)
#   C8S_POD_OUT           directory for logs and results (default: a new
#                         temporary directory, kept)
#   C8S_BIN               prebuilt linux c8s binary (default: built here)
#   C8S_POD_HW_TEST       prebuilt hardware test binary (default: built here)
#
# QEMU needs /dev/kvm and the quoting socket is usually root's: run as root,
# or as a user that can open both. Exit status is 0 only if every step passed.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image_dir="${C8S_POD_IMAGE_DIR:?set C8S_POD_IMAGE_DIR to the pod guest image directory}"
platform="${C8S_POD_PLATFORM:-tdx}"
qemu="${C8S_POD_QEMU:-qemu-system-x86_64}"
port="${C8S_POD_PORT:-28443}"
modes="${C8S_POD_COLLATERAL:-required skip}"
boot_timeout="${C8S_POD_BOOT_TIMEOUT:-180}"
out="${C8S_POD_OUT:-$(mktemp -d -t c8s-pod-hw.XXXXXX)}"
manifest="$image_dir/manifest.json"
url="https://127.0.0.1:$port"

quote_socket="${C8S_POD_QUOTE_SOCKET-}"
if [[ -z "${C8S_POD_QUOTE_SOCKET+x}" && -S /var/run/tdx-qgs/qgs.socket ]]; then
  quote_socket=/var/run/tdx-qgs/qgs.socket
fi

die() { echo "run-hardware: $*" >&2; exit 2; }
command -v curl >/dev/null || die "curl is required to probe the agent"
[[ -f "$manifest" ]] || die "$manifest is missing"
mkdir -p "$out/bin" || die "cannot create $out"

c8s="${C8S_BIN:-}"
if [[ -z "$c8s" ]]; then
  c8s="$out/bin/c8s"
  (cd "$repo_root" && CGO_ENABLED=0 go build -trimpath -o "$c8s" ./cmd/c8s) || die "building c8s failed"
fi
hwtest="${C8S_POD_HW_TEST:-}"
if [[ -z "$hwtest" ]]; then
  hwtest="$out/bin/podcvm-hw.test"
  (cd "$repo_root" && CGO_ENABLED=0 go test -c -tags podcvm_hardware -o "$hwtest" ./test/podcvm) || die "building the hardware suite failed"
fi
[[ -x "$c8s" && -x "$hwtest" ]] || die "c8s or the hardware suite binary is not executable"

launcher_pid=""
results=()
failed=0

record() { # record <PASS|FAIL> <step> [detail]
  results+=("$1  $2${3:+  ($3)}")
  [[ "$1" == PASS ]] || failed=1
  echo "== $1: $2${3:+ ($3)}"
}

stop_guest() {
  [[ -n "$launcher_pid" ]] || return 0
  kill -TERM "$launcher_pid" 2>/dev/null
  wait "$launcher_pid" 2>/dev/null
  launcher_pid=""
}
trap stop_guest EXIT

now() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$(now)" 'BEGIN { printf "%.1f", b - a }'; }

# boot <name>: start a guest from $out/<name>/bundle in the background.
boot() {
  local name=$1
  local args=(pod-launcher run --platform "$platform" --qemu "$qemu"
    --image-dir "$image_dir" --launch-dir "$out/$name/bundle/opkeydata" --work-dir "$out/$name/vm"
    --name "c8s-pod-hw-$name" --vcpus "${C8S_POD_VCPUS:-2}" --memory "${C8S_POD_MEMORY:-2G}"
    --scratch "${C8S_POD_SCRATCH:-4G}" --network user --port "127.0.0.1:$port:8443")
  [[ -n "$quote_socket" ]] && args+=(--quote-socket "$quote_socket")
  [[ -n "${C8S_POD_VSOCK_CID:-}" ]] && args+=(--vsock-cid "$C8S_POD_VSOCK_CID")
  [[ "${C8S_POD_CONSOLE:-0}" == 1 ]] && args+=(--console)
  "$c8s" "${args[@]}" >"$out/$name/launcher.log" 2>&1 &
  launcher_pid=$!
  boot_started=$(now)
}

# wait_agent: 0 once the agent answers, 1 if the guest exited first, 2 on timeout.
wait_agent() {
  local deadline=$(( $(date +%s) + boot_timeout ))
  while (( $(date +%s) < deadline )); do
    if ! kill -0 "$launcher_pid" 2>/dev/null; then
      wait "$launcher_pid" 2>/dev/null
      launcher_pid=""
      return 1
    fi
    if [[ "$(curl -sk --max-time 2 "$url/healthz" 2>/dev/null)" == ok ]]; then
      return 0
    fi
    sleep 0.2
  done
  return 2
}

bundle() { # bundle <name> <manifest> [extra launch-config flags...]
  local name=$1 for_manifest=$2
  shift 2
  mkdir -p "$out/$name"
  "$c8s" pod launch-config new --out "$out/$name/bundle" --image-manifest "$for_manifest" \
    --tenant hw.tenant-a --sandbox hw-sandbox "$@" >"$out/$name/bundle.log" 2>&1
}

verify() { # verify <bundle name> <collateral> <log>: prints nothing, returns c8s's exit status
  "$c8s" pod verify --url "$url" --bundle "$out/$1/bundle" --image-manifest "$manifest" \
    --collateral "$2" -o json >"$3" 2>&1
}

echo "run-hardware: platform=$platform image=$image_dir qemu=$qemu quote_socket=${quote_socket:-none} vsock_cid=${C8S_POD_VSOCK_CID:-none} out=$out"

# --- guest a: the suite ---------------------------------------------------
if ! bundle a "$manifest" --credential test-token:128; then
  record FAIL "create launch bundle" "$(tail -1 "$out/a/bundle.log")"
else
  boot a
  wait_agent
  case $? in
  0)
    record PASS "guest boots and serves its API" "$(elapsed "$boot_started")s from launch to healthz"
    verify_started=$(now)
    if verify a skip "$out/a/verify.json"; then
      record PASS "c8s pod verify" "$(elapsed "$verify_started")s, collateral skipped"
    else
      record FAIL "c8s pod verify" "$(cat "$out/a/verify.json")"
    fi
    for mode in $modes; do
      if C8S_POD_URL="$url" C8S_POD_BUNDLE="$out/a/bundle" C8S_POD_MANIFEST="$manifest" \
        C8S_POD_COLLATERAL="$mode" "$hwtest" -test.v -test.count=1 >"$out/a/suite-$mode.log" 2>&1; then
        record PASS "hardware suite, collateral $mode" "$(grep -c '^    --- PASS\|^--- PASS' "$out/a/suite-$mode.log") tests"
      else
        record FAIL "hardware suite, collateral $mode" "see $out/a/suite-$mode.log"
      fi
    done
    ;;
  1) record FAIL "guest boots and serves its API" "the guest exited; see $out/a/launcher.log" ;;
  *) record FAIL "guest boots and serves its API" "no answer on $url within ${boot_timeout}s" ;;
  esac
  stop_guest
fi

# --- guest b: the host's own launch key -----------------------------------
if [[ -d "$out/a/bundle" ]] && bundle b "$manifest"; then
  boot b
  if wait_agent; then
    # Control first: the guest is healthy and verifies under its own bundle,
    # so a refusal under bundle a is about the launch key and nothing else.
    if verify b skip "$out/b/verify-own.json"; then
      verify a skip "$out/b/verify-as-a.json"
      status=$?
      if (( status == 2 )); then
        record PASS "a guest launched under another key is refused" "$(sed -n 's/.*"error":"\([^"]*\)".*/\1/p' "$out/b/verify-as-a.json")"
      else
        record FAIL "a guest launched under another key is refused" "c8s pod verify exited $status, want 2"
      fi
    else
      record FAIL "control: guest b verifies under its own bundle" "$(cat "$out/b/verify-own.json")"
    fi
  else
    record FAIL "guest b boots" "see $out/b/launcher.log"
  fi
  stop_guest
fi

# --- guest c: a document signed for another image -------------------------
if [[ "$platform" == tdx ]]; then
  mkdir -p "$out/c"
  first=$(grep -oE '"rtmr2"[[:space:]]*:[[:space:]]*"[0-9a-f]' "$manifest" | tail -c 2 | head -c 1)
  flip=0
  [[ "$first" == 0 ]] && flip=1
  sed -E "s/(\"rtmr2\"[[:space:]]*:[[:space:]]*\")[0-9a-f]/\1$flip/" "$manifest" >"$out/c/manifest.json"
  if cmp -s "$manifest" "$out/c/manifest.json" || ! bundle c "$out/c/manifest.json"; then
    record FAIL "prepare a document for another image" "could not derive a manifest that differs in rtmr2"
  else
    boot c
    wait_agent
    case $? in
    1) record PASS "a guest refuses a document signed for another image" "powered off after $(elapsed "$boot_started")s without serving its API" ;;
    0) record FAIL "a guest refuses a document signed for another image" "the guest served its API" ;;
    *) record FAIL "a guest refuses a document signed for another image" "the guest neither served nor powered off within ${boot_timeout}s" ;;
    esac
    stop_guest
  fi
fi

{
  echo "pod CVM hardware run, $(date -u +%Y-%m-%dT%H:%M:%SZ), host $(hostname), kernel $(uname -r)"
  echo "$("$c8s" --version 2>/dev/null | head -1), $("$qemu" --version 2>/dev/null | head -1)"
  printf '%s\n' "${results[@]}"
} | tee "$out/summary.txt"
echo "run-hardware: logs in $out"
exit "$failed"
