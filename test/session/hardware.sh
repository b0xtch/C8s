#!/usr/bin/env bash
# The hardware test of confidential sessions on one host (docs/sessions.md,
# milestone 1): a key service in a TD of its own, a session daemon with one
# pool that pins it, and an owner who registers its authority, stores a
# credential and starts sessions. Each session is a TD of its own: it is
# claimed, bound, verified from a fresh quote, handed the stored credential by
# the key service and a second one by a key its bind grants, and runs one
# authenticated command that reads both. One session's first command and a
# credential its owner holds go with its bind, sealed to a key its guest made
# for that one bind.
#
# Before that it reads two machines (RTMR[0]) from evidence, the key service's
# and the class's, each from one guest launched under a document that lists
# none, and the documents everything else runs under list them.
#
# Then what must be refused: a key service and a guest whose launch documents
# list no machine, each of the two on a machine its document does not list, a
# guest with a device its class does not have, evidence of
# another image, of a pool under another launch key, a key service that is
# not the one pinned, a tenant nobody registered, a bind under another
# authority, a credential nobody stored, a sandbox image whose content was
# changed, a stranger's key, one session's binding on another session's TD, a
# guest of a pool the key service does not serve. With a dev image it also
# probes what a guest can reach on its host and on other guests, which must
# be nothing.
#
# It runs real TDs, so it needs a TDX host with QEMU, a quoting service and
# passwordless sudo, and two guest images from session-guest-image/build: a
# session image and a key service image of the same kind (both locked, or both
# dev). On the host it makes taps named c8st<n>, one table in the packet
# filter (inet c8s_sessions), and processes; it removes all three when it
# ends, however it ends.
#
#   C8S_BIN                  the c8s binary (default: build/c8s)
#   C8S_SESSION_IMAGE        session image directory (required)
#   C8S_KEY_SERVICE_IMAGE    key service image directory (required)
#   C8S_SESSION_WORK         directory for this run's files and records
#                            (default: a new temporary directory, kept)
#   C8S_SESSION_DEV=1        the images are dev builds: attach their consoles,
#                            hold each refusal to the reason its guest logged,
#                            and probe the guests' network from inside
#   C8S_SANDBOX_STORE        directory written by test/session/sandboximage
#                            (ref, ref-changed, images.store). A locked image
#                            runs a session's code in a sandbox image only, so
#                            a locked run needs it.
#   C8S_QUOTE_SOCKET         the host's quoting service (default:
#                            /var/run/tdx-qgs/qgs.socket)
#   C8S_SESSION_CONFINE      run each VMM as this numeric user id
#   C8S_ACCEPT_TCB           Intel TCB statuses, besides UpToDate, that this
#                            host's platform has, comma-separated (OutOfDate
#                            on a host whose microcode is behind). Every
#                            verifier in the test then accepts them by name:
#                            the owner, the key service of its pool's guests,
#                            and a guest of its key service. Unset, a host
#                            that is behind fails the test at its first
#                            verdict, which names the status.
#   C8S_WARMSTART            the warmstart binary (go build
#                            ./test/session/warmstart). With it the test also
#                            has a binder watch the pool's ready TDs and find
#                            a claimed guest judged, and a caller the pool
#                            does not name shown nothing. The binder then
#                            starts a session with a bind that claims its TD,
#                            which the orchestrator is shown, and loses a TD
#                            to a bind that came first. A bind under an
#                            authority the pool does not name for the binder,
#                            and one from a key it does not name, claim
#                            nothing. A binder names the key service's
#                            replica it judged in its bind, and a guest
#                            takes no bind that names another.
#   C8S_SESSION_PORT, C8S_KEY_SERVICE_PORT, C8S_SESSION_CIDR
#                            the daemon's port (7443), the key service's
#                            loopback port (18543), the guests' block
#                            (10.213.0.0/24)
#
# Exit 0 when every step passed. <work>/summary.txt lists the steps, and
# <work>/records.jsonl keeps what each start and command took.
set -uo pipefail

C8S=${C8S_BIN:-build/c8s}
IMG=${C8S_SESSION_IMAGE:?set C8S_SESSION_IMAGE to a session image directory}
KSIMG=${C8S_KEY_SERVICE_IMAGE:?set C8S_KEY_SERVICE_IMAGE to a key service image directory}
dev=${C8S_SESSION_DEV:-0}
warm=${C8S_WARMSTART:-}
store_dir=${C8S_SANDBOX_STORE:-}
quote_socket=${C8S_QUOTE_SOCKET:-/var/run/tdx-qgs/qgs.socket}
confine=${C8S_SESSION_CONFINE:-}
accept=()
[ -n "${C8S_ACCEPT_TCB:-}" ] && accept=(--accept-tcb-status "$C8S_ACCEPT_TCB")
port=${C8S_SESSION_PORT:-7443}
ks_port=${C8S_KEY_SERVICE_PORT:-18543}
cidr=${C8S_SESSION_CIDR:-10.213.0.0/24}
manifest=$IMG/manifest.json

C8S=$(command -v "$C8S" || true)
[ -n "$C8S" ] && [ -x "$C8S" ] || { echo "no c8s binary: set C8S_BIN" >&2; exit 2; }
C8S=$(readlink -f "$C8S")
[ -f "$manifest" ] && [ -f "$KSIMG/manifest.json" ] || { echo "an image directory holds no manifest.json" >&2; exit 2; }
sudo -n true 2>/dev/null || { echo "this test needs passwordless sudo" >&2; exit 2; }
[ "$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null)" = Y ] || { echo "this host's KVM runs no TD (kvm_intel.tdx is not Y)" >&2; exit 2; }
if ss -ltn 2>/dev/null | grep -q -E ":($port|$ks_port) "; then echo "port $port or $ks_port is taken" >&2; exit 2; fi
if sudo -n nft list table inet c8s_sessions > /dev/null 2>&1; then
    echo "the packet filter holds a table inet c8s_sessions: a session daemon runs here, or one left it behind" >&2
    exit 2
fi
sandbox=() ref="" ref_changed="" store=""
if [ -n "$store_dir" ]; then
    ref=$(cat "$store_dir/ref") ref_changed=$(cat "$store_dir/ref-changed") store=$store_dir/images.store
    [ -n "$ref" ] && [ -f "$store" ] || { echo "$store_dir is no directory written by test/session/sandboximage" >&2; exit 2; }
    sandbox=(--sandbox-image "$ref")
elif [ "$dev" != 1 ]; then
    echo "a locked image needs C8S_SANDBOX_STORE: it runs a session's code in a sandbox image only" >&2
    exit 2
fi

out=${C8S_SESSION_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/c8s-session-hardware.XXXXXX")}
mkdir -p "$out/pki" || exit 2
[ ! -e "$out/summary.txt" ] || { echo "$out holds an earlier run" >&2; exit 2; }
out=$(readlink -f "$out")
run=$(basename "$out")
echo "records in $out"

results=()
failed=0
record() { # record <PASS|FAIL> <step> [detail]
    results+=("$1  $2${3:+  ($3)}")
    [ "$1" = PASS ] || failed=1
    echo "== $1: $2${3:+ ($3)}"
}
# expect <code> <step> <log> <command...>: the command must exit with <code>.
expect() {
    local want=$1 step=$2 log=$3 code began
    shift 3
    began=$(date +%s%N)
    "$@" > "$out/$log.out" 2> "$out/$log.err"
    code=$?
    printf '{"step":"%s","exit":%d,"ms":%d}\n' "$log" "$code" $(( ($(date +%s%N) - began) / 1000000 )) >> "$out/records.jsonl"
    if [ "$code" = "$want" ]; then
        record PASS "$step" "exit $code"
    else
        record FAIL "$step" "exit $code, wanted $want: $(tail -c 300 "$out/$log.err" "$out/$log.out" | tr '\n' ' ')"
    fi
}
check() { # check <step> <condition...>
    local step=$1
    shift
    if "$@"; then record PASS "$step"; else record FAIL "$step"; fi
}
finish() {
    {
        echo "session hardware run $run: $([ "$failed" = 0 ] && echo PASS || echo FAIL)"
        printf '%s\n' "${results[@]}"
    } | tee "$out/summary.txt"
    exit "$failed"
}
# A guest's VMM, by the name its launcher gave it.
guests() { pgrep -cf "[q]emu-system.*guest=$1"; }

# The daemon's certificate and two orchestrators', under one authority, a
# binder's certificate of its own making, and the keys of two tenants and a
# stranger. The pool names the first orchestrator and the binder as its
# binders, each by its key, and the other orchestrator not.
pki=$out/pki
openssl ecparam -name prime256v1 -genkey -noout -out "$pki/ca.key" 2>/dev/null
openssl req -x509 -new -key "$pki/ca.key" -subj "/CN=session test authority" -days 2 -out "$pki/ca.pem" 2>/dev/null
for who in server orchestrator other; do
    openssl ecparam -name prime256v1 -genkey -noout -out "$pki/$who.key" 2>/dev/null
    openssl req -new -key "$pki/$who.key" -subj "/CN=$who" -out "$pki/$who.csr" 2>/dev/null
    printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' > "$pki/$who.ext"
    openssl x509 -req -in "$pki/$who.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca.key" -CAcreateserial -days 2 \
        -extfile "$pki/$who.ext" -out "$pki/$who.pem" 2>/dev/null
done
for who in authority other-authority stranger; do
    openssl ecparam -name prime256v1 -genkey -noout -out "$out/$who.key" 2>/dev/null
done
openssl req -x509 -new -key "$out/stranger.key" -subj "/CN=stranger" -days 2 -out "$out/stranger.pem" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$pki/binder.key" 2>/dev/null
openssl req -x509 -new -key "$pki/binder.key" -subj "/CN=a binder of its own making" -days 2 -out "$pki/binder.pem" 2>/dev/null
# key_digest <certificate>: its public key as a pool's configuration names it.
key_digest() {
    echo "sha256:$(openssl x509 -in "$1" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -c1-64)"
}
# authority_digest <private key>: its public key, named the same way.
authority_digest() {
    echo "sha256:$(openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | sha256sum | cut -c1-64)"
}

# The pool's key first, then the key service's bundle and pin, then the pool's
# bundle, which pins the key service. Each of the two bundles is written
# twice: once listing no machine, for the guest its machine is read from, and
# once with it. Two more pool bundles for the refusals: the pool's image
# under another launch key, and a pool the key service does not list.
pin=$out/ks-pin.json
ks_pool=(--image-manifest "$KSIMG/manifest.json" --pool "$manifest:$out/pool.key.pub" "${accept[@]}")
expect 0 "the pool's launch key" pool-key "$C8S" session launch-config key --out "$out/pool.key"
expect 0 "a key service bundle that lists no machine" ks-bundle-probe "$C8S" session key-service launch-config new --out "$out/ks-probe" "${ks_pool[@]}"

ks_pid="" daemon_pid="" stray_pid="" probe_pid="" events_pid=""
stop_pid() { # stop_pid <pid>
    [ -n "$1" ] || return 0
    sudo -n kill -TERM "$1" 2>/dev/null
    wait "$1" 2>/dev/null
}
drain() {
    [ -f "$out/config.yaml" ] && sudo -n "$C8S" session-daemon drain --config "$out/config.yaml" --wait 3m >> "$out/drain.out" 2>> "$out/daemon.log"
}
cleanup() {
    stop_pid "$events_pid"; events_pid=""
    stop_pid "$daemon_pid"; daemon_pid=""
    drain
    sudo -n nft delete table inet c8s_sessions 2>/dev/null
    stop_pid "$stray_pid"; stray_pid=""
    stop_pid "$probe_pid"; probe_pid=""
    stop_pid "$ks_pid"; ks_pid=""
}
trap cleanup EXIT

launcher=(session-launcher run --platform tdx --vsock-cid auto)
[ -S "$quote_socket" ] && launcher+=(--quote-socket "$quote_socket")
[ -n "$confine" ] && launcher+=(--confine "$confine")
[ "$dev" = 1 ] && launcher+=(--console)
# The shape of the one class: what the daemon launches each of its TDs with,
# and so what every guest launched by hand here is given too.
shape=(--vcpus 4 --memory 16G --low-memory 512M --scratch 4G ${store:+--image-store "$store"})
# The key service's shape.
ks_shape=(--vcpus 2 --memory 4G --low-memory 512M --scratch 2G)
# serving <pid> <port>: wait until the guest of that launcher serves.
serving() {
    local deadline=$(( $(date +%s) + 240 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        kill -0 "$1" 2>/dev/null || return 1
        [ "$(curl -sk --max-time 2 "https://127.0.0.1:$2/healthz" 2>/dev/null)" = ok ] && return 0
        sleep 0.2
    done
    return 1
}
# ends_unserved <step> <log> <port> <network> <launcher arguments...>: a guest
# launched so, with that network, must end by itself, and before it serves.
ends_unserved() {
    local step=$1 log=$2 at=$3 network=$4 began served=0 code
    shift 4
    began=$(date +%s%N)
    sudo -n timeout 120 "$C8S" "${launcher[@]}" "$@" --network "$network" --port "127.0.0.1:$at:8443" > "$out/$log.log" 2>&1 &
    probe_pid=$!
    while kill -0 "$probe_pid" 2>/dev/null; do
        [ "$(curl -sk --max-time 1 "https://127.0.0.1:$at/healthz" 2>/dev/null)" = ok ] && { served=1; break; }
        sleep 0.1
    done
    wait "$probe_pid" 2>/dev/null
    code=$?
    probe_pid=""
    printf '{"step":"%s","exit":%d,"ms":%d}\n' "$log" "$code" $(( ($(date +%s%N) - began) / 1000000 )) >> "$out/records.jsonl"
    if [ "$served" = 0 ] && [ "$code" != 124 ] && grep -q "guest exited on its own" "$out/$log.log"; then
        record PASS "$step"
    else
        record FAIL "$step" "served $served, exit $code: $(tail -c 300 "$out/$log.log" | tr '\n' ' ')"
    fi
}
# launch_ks <bundle> <work directory> <log>: a key service's TD. A replica has
# no network device: its launcher publishes the port it serves on its socket
# to the host, and carries its connections to Intel's service.
launch_ks() {
    sudo -n "$C8S" "${launcher[@]}" --image-dir "$KSIMG" --launch-dir "$1/opkeydata" --work-dir "$2" \
        --name "c8s-key-service-$run" "${ks_shape[@]}" --network none --port "127.0.0.1:$ks_port:8443" > "$3" 2>&1 &
    ks_pid=$!
}

# The key service's launch document lists the machines a replica may be, as
# values of RTMR[0], and a replica whose document lists none serves its state
# and nothing else. The value is read from the evidence of one replica
# launched in the key service's shape under a document that lists nothing.
launch_ks "$out/ks-probe" "$out/ks-probe-vm" "$out/ks-probe.log"
if ! serving "$ks_pid" "$ks_port"; then
    record FAIL "a key service whose document lists no machine serves its state" "$(tail -c 600 "$out/ks-probe.log" | tr '\n' ' ')"
    finish
fi
record PASS "a key service whose document lists no machine serves its state"
expect 0 "the key service's machine is read from its evidence" ks-machine "$C8S" session key-service launch-config machine \
    --bundle "$out/ks-probe" --url "https://127.0.0.1:$ks_port" "${accept[@]}"
ks_machine=$(tr -d '[:space:]' < "$out/ks-machine.out")
if ! [[ $ks_machine =~ ^[0-9a-f]{96}$ ]]; then
    record FAIL "the key service's machine is a register's value" "$ks_machine"
    finish
fi
expect 0 "a pin of that key service" ks-probe-pin "$C8S" session key-service pin --bundle "$out/ks-probe" \
    --url "https://127.0.0.1:$ks_port" --out "$out/ks-probe-pin.json" "${accept[@]}"
expect 2 "an owner sends nothing to a key service whose document lists no machine" register-unpinned \
    "$C8S" session key-service tenant register --key-service "$out/ks-probe-pin.json" --tenant acme --authority-key "$out/authority.key"
check "it said the document lists no machine" grep -q "lists no machine" "$out/register-unpinned.err"
stop_pid "$ks_pid"; ks_pid=""

# A replica's class has no network device. A host that gives it one has built
# another machine, and the replica ends before it reads a file of its host's.
# The document lists no machine, so nothing but the device ends it.
ends_unserved "a key service that is given a network device ends before it serves" ks-network "$ks_port" user \
    --image-dir "$KSIMG" --launch-dir "$out/ks-probe/opkeydata" --work-dir "$out/ks-network-vm" --name "c8s-key-service-network-$run" "${ks_shape[@]}"
if [ "$dev" = 1 ]; then
    check "it said which device" grep -a -q "1af4:1041.*is none a guest of this class is given" "$out/ks-network.log"
fi

# A replica on a machine its document does not list ends before it serves.
# The document here lists the value with one digit changed, which stands for
# a host that built another machine.
other_ks_machine=$( [ "${ks_machine:0:1}" = 0 ] && echo 1 || echo 0 )${ks_machine:1}
expect 0 "a key service bundle that lists another machine" ks-bundle-other "$C8S" session key-service launch-config new --out "$out/ks-other" \
    --key "$out/ks-probe/launch.key" "${ks_pool[@]}" --machine "$other_ks_machine"
ends_unserved "a key service on a machine its document does not list ends before it serves" ks-other-machine "$ks_port" none \
    --image-dir "$KSIMG" --launch-dir "$out/ks-other/opkeydata" --work-dir "$out/ks-other-vm" --name "c8s-key-service-other-$run" "${ks_shape[@]}"
if [ "$dev" = 1 ]; then
    check "it said its machine is none its document lists" grep -a -q "is none of the 1 its launch document lists" "$out/ks-other-machine.log"
fi

# The bundle the key service runs under, signed by the same key, and its pin,
# which is the same for every bundle of that key and image.
expect 0 "the key service's launch bundle, which lists its machine" ks-bundle "$C8S" session key-service launch-config new --out "$out/ks" \
    --key "$out/ks-probe/launch.key" "${ks_pool[@]}" --machine "$ks_machine"
expect 0 "the key service's pin" ks-pin "$C8S" session key-service pin --bundle "$out/ks" --url "https://127.0.0.1:$ks_port" --out "$pin" "${accept[@]}"
check "the pin is the one made before the machine was listed" cmp -s "$pin" "$out/ks-probe-pin.json"

# A launch document lists the machines its guests may be, as values of
# RTMR[0], and a TD whose document lists none takes no bind. The class's value
# is read from the evidence of one guest launched in that shape under a
# document that lists nothing.
probe_port=$((ks_port + 2))
expect 0 "a launch bundle that lists no machine" bundle-probe "$C8S" session launch-config new --out "$out/bundle-probe" \
    --key "$out/pool.key" --key-service "$pin" --image-manifest "$manifest" --pool agents --class s-4x16
sudo -n "$C8S" "${launcher[@]}" --image-dir "$IMG" --launch-dir "$out/bundle-probe/opkeydata" --work-dir "$out/probe-vm" \
    --name "c8s-session-probe-$run" "${shape[@]}" --network user --port "127.0.0.1:$probe_port:8443" > "$out/probe.log" 2>&1 &
probe_pid=$!
if ! serving "$probe_pid" "$probe_port"; then
    record FAIL "a guest whose document lists no machine serves" "$(tail -c 600 "$out/probe.log" | tr '\n' ' ')"
    finish
fi
record PASS "a guest whose document lists no machine serves"
expect 0 "its machine is read from its evidence" machine "$C8S" session launch-config machine --url "https://127.0.0.1:$probe_port" \
    --image-manifest "$manifest" --launch-key "$out/pool.key.pub" "${accept[@]}"
machine=$(tr -d '[:space:]' < "$out/machine.out")
if ! [[ $machine =~ ^[0-9a-f]{96}$ ]]; then
    record FAIL "the machine is a register's value" "$machine"
    finish
fi
expect 2 "an owner sends no bind to a guest whose document lists no machine" bind-unpinned \
    "$C8S" session bind --url "https://127.0.0.1:$probe_port" --image-manifest "$manifest" --launch-key "$out/pool.key.pub" \
    --authority-key "$out/authority.key" --tenant acme --session s8 --out "$out/s8" --timeout 20s "${accept[@]}" "${sandbox[@]}"
check "it said the document lists no machine" grep -q "lists no machine" "$out/bind-unpinned.err" "$out/bind-unpinned.out"
# The guest takes none either, from a caller that sends one unasked.
code=$(curl -sk --max-time 10 -o "$out/bind-raw.out" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' \
    "https://127.0.0.1:$probe_port/v1/bind")
if [ "$code" = 409 ] && grep -q bind_no_machine "$out/bind-raw.out"; then
    record PASS "the guest takes no bind, and says its document lists no machine"
else
    record FAIL "the guest takes no bind, and says its document lists no machine" "HTTP $code: $(head -c 300 "$out/bind-raw.out" | tr '\n' ' ')"
fi
# Nor a sealed message for a session: one comes with a bind or just after
# it, and a guest that no bind has reached reads none.
code=$(curl -sk --max-time 10 -o "$out/sealed-raw.out" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"sealed":"AAAA"}' \
    "https://127.0.0.1:$probe_port/v1/bind/sealed")
if [ "$code" = 409 ] && grep -q fenced "$out/sealed-raw.out"; then
    record PASS "a guest that no bind has reached reads no sealed message"
else
    record FAIL "a guest that no bind has reached reads no sealed message" "HTTP $code: $(head -c 300 "$out/sealed-raw.out" | tr '\n' ' ')"
fi
stop_pid "$probe_pid"; probe_pid=""

expect 0 "the pool's launch bundle, which pins the key service and lists the machine" bundle "$C8S" session launch-config new --out "$out/bundle" \
    --key "$out/pool.key" --key-service "$pin" --image-manifest "$manifest" --pool agents --class s-4x16 --machine "$machine"
expect 0 "a bundle for a pool the key service does not list" bundle-b "$C8S" session launch-config new --out "$out/bundle-b" \
    --key-service "$pin" --image-manifest "$manifest" --pool strangers --class s-4x16 --machine "$machine"
launch_key=$out/bundle/opkeydata/pubkey

# A guest on a machine its document does not list serves nothing: its agent
# ends it before it listens. The document here lists the class's value with
# one digit changed, which stands for a host that built another machine.
other_machine=$( [ "${machine:0:1}" = 0 ] && echo 1 || echo 0 )${machine:1}
expect 0 "a bundle that lists another machine" bundle-other "$C8S" session launch-config new --out "$out/bundle-other" \
    --key "$out/pool.key" --key-service "$pin" --image-manifest "$manifest" --pool agents --class s-4x16 --machine "$other_machine"
ends_unserved "a guest on a machine its document does not list ends before it serves" other-machine "$probe_port" user \
    --image-dir "$IMG" --launch-dir "$out/bundle-other/opkeydata" --work-dir "$out/other-vm" --name "c8s-session-other-$run" "${shape[@]}"
if [ "$dev" = 1 ]; then
    check "it said its machine is none its document lists" grep -a -q "is none of the 1 its launch document lists" "$out/other-machine.log"
fi

# A host that keeps the shape and puts another device in a slot: the network
# card of its choosing where the class has a virtio one. The guest's kernel
# has no driver for it, and the guest ends before it reads a file of its
# host's. The document is the pool's own, which lists this shape's machine.
wrapper=/tmp/c8s-session-$run-qemu.sh
cat > "$wrapper" <<'WRAP'
#!/bin/sh
# QEMU, with the guest's network device replaced by an e1000e.
for arg; do
    shift
    case "$arg" in
    virtio-net-pci,*) arg=$(printf '%s' "$arg" | sed -e 's/^virtio-net-pci,/e1000e,/' -e 's/,disable-legacy=on//') ;;
    esac
    set -- "$@" "$arg"
done
exec qemu-system-x86_64 "$@"
WRAP
chmod 0755 "$wrapper"
ends_unserved "a guest with a device its class does not have ends before it serves" swapped-device "$probe_port" user \
    --qemu "$wrapper" --image-dir "$IMG" --launch-dir "$out/bundle/opkeydata" --work-dir "$out/swapped-vm" --name "c8s-session-swapped-$run" "${shape[@]}"
rm -f "$wrapper"
if [ "$dev" = 1 ]; then
    check "it said which device" grep -a -q "8086:10d3.*is none a guest of this class is given" "$out/swapped-device.log"
fi
# Reference values and a pin that differ from the real ones in one digit.
python3 - "$manifest" "$out/manifest-other.json" "$pin" "$out/ks-pin-other.json" <<'EOF'
import json, sys
def flip(v):
    return ("0" if v[0] != "0" else "1") + v[1:]
m = json.load(open(sys.argv[1]))
m["tdx"]["mrtd"] = flip(m["tdx"]["mrtd"])
json.dump(m, open(sys.argv[2], "w"))
p = json.load(open(sys.argv[3]))
p["image"]["measurement"] = flip(p["image"]["measurement"])
json.dump(p, open(sys.argv[4], "w"))
EOF

# The key service, in a TD of its own, on a loopback port of this host. A
# session guest has no road to it: its launcher carries the connection.
began=$(date +%s%N)
launch_ks "$out/ks" "$out/ks-vm" "$out/ks.log"
if ! serving "$ks_pid" "$ks_port"; then
    record FAIL "the key service serves" "$(tail -c 600 "$out/ks.log" | tr '\n' ' ')"
    finish
fi
record PASS "the key service serves"
printf '{"step":"key-service-boot","ms":%d}\n' $(( ($(date +%s%N) - began) / 1000000 )) >> "$out/records.jsonl"

# The owner holds the key service to its pin before it sends it anything,
# registers its authority, and stores a credential.
printf 'stored-secret-%s' "$run" > "$out/stored"
printf 'released-secret-%s' "$run" > "$out/released"
tenant=(--tenant acme --authority-key "$out/authority.key")
expect 2 "an owner sends nothing to a key service of another image" register-wrong-pin \
    "$C8S" session key-service tenant register --key-service "$out/ks-pin-other.json" "${tenant[@]}"
expect 3 "a credential needs its tenant registered" put-unregistered \
    "$C8S" session key-service credential put api-token --key-service "$pin" "${tenant[@]}" --from-file "$out/stored"
expect 0 "register the tenant's authority" register "$C8S" session key-service tenant register --key-service "$pin" "${tenant[@]}"
expect 0 "store a credential" put "$C8S" session key-service credential put api-token --key-service "$pin" "${tenant[@]}" --from-file "$out/stored"
expect 3 "another key cannot take the tenant's name" register-usurper \
    "$C8S" session key-service tenant register --key-service "$pin" --tenant acme --authority-key "$out/other-authority.key"
expect 3 "another key cannot store the tenant's credential" put-usurper \
    "$C8S" session key-service credential put api-token --key-service "$pin" --tenant acme --authority-key "$out/other-authority.key" --from-file "$out/stored"

# The daemon, with one pool. Its guests' network opens nothing.
{
    echo "listen: 127.0.0.1:$port"
    echo "host: test-host"
    echo "stateDir: $out/state"
    echo "capacity: 4"
    echo "tls: {cert: $pki/server.pem, key: $pki/server.key, clientCA: $pki/ca.pem}"
    echo "network: {mode: tap, guestCIDR: $cidr}"
    echo "vmm:"
    [ -S "$quote_socket" ] && echo "  quoteSocket: $quote_socket"
    [ -n "$confine" ] && echo "  confine: \"$confine\""
    [ "$dev" = 1 ] && echo "  console: true"
    echo "classes:"
    echo "  s-4x16: {vcpus: 4, memory: 16G, lowMemory: 512M, scratch: 4G}"
    echo "pools:"
    echo "  - imageDir: $IMG"
    echo "    launchDir: $out/bundle/opkeydata"
    echo "    depth: 2"
    [ -n "$store" ] && echo "    imageStore: $store"
    # The orchestrator watches the pool. The binder watches it too, and may
    # claim a TD with a bind under the first tenant's authority.
    echo "    binders:"
    echo "      - \"$(key_digest "$pki/orchestrator.pem")\""
    echo "      - {key: \"$(key_digest "$pki/binder.pem")\", authorities: [\"$(authority_digest "$out/authority.key")\"]}"
} > "$out/config.yaml"
start_daemon() {
    sudo -n "$C8S" session-daemon run --config "$out/config.yaml" >> "$out/daemon.log" 2>&1 &
    daemon_pid=$!
}
ready_count() { grep -c '"msg":"a TD is ready"' "$out/daemon.log" 2>/dev/null; }
began=$(date +%s%N)
start_daemon
ok=0
deadline=$(( $(date +%s) + 300 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    [ "$(ready_count)" -ge 2 ] && { ok=1; break; }
    kill -0 "$daemon_pid" 2>/dev/null || break
    sleep 0.2
done
if [ "$ok" != 1 ]; then
    record FAIL "the pool is filled" "$(tail -c 500 "$out/daemon.log" | tr '\n' ' ')"
    finish
fi
record PASS "the pool is filled"
printf '{"step":"pool-fill","tds":2,"ms":%d}\n' $(( ($(date +%s%N) - began) / 1000000 )) >> "$out/records.jsonl"
check "the daemon opened nothing to its guests" sh -c "! sudo -n nft list table inet c8s_sessions | grep -q 'tcp dport'"

orchestrator=(--daemon "127.0.0.1:$port" --daemon-ca "$pki/ca.pem" --daemon-cert "$pki/orchestrator.pem" --daemon-key "$pki/orchestrator.key")
# start_session <name> <out> <tenant> <authority key> <manifest> <launch key> [more]
start_session() {
    local name=$1 dir=$2 who=$3 auth=$4 man=$5 key=$6
    shift 6
    "$C8S" session start "${orchestrator[@]}" --pool agents --wait 120s --image-manifest "$man" --launch-key "$key" \
        --authority-key "$auth" --tenant "$who" --session "$name" --out "$dir" -o json "${accept[@]}" "$@"
}
stored=(--key-service "$pin" --stored-credential api-token:256)
# guest_logged <start log> <pattern>: the console of the TD that start was
# given says so. A locked image has no console: its reasons stay inside.
guest_logged() {
    local td
    td=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("td",""))' "$out/$1.out" 2>/dev/null)
    [ -n "$td" ] && sudo -n grep -a -q -E "$2" "$out/state/tds/$td/launcher.log"
}
# said <log> <field>: a field of the JSON a command printed.
said() {
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2],""))' "$out/$1.out" "$2" 2>/dev/null
}
# quoted <log>: the quote that start judged came with the guest's answer to
# the bind or after it on the bind's own call, so that the start asked the
# daemon for no evidence and the guest for no attestation.
quoted() {
    case "$(said "$1" quote)" in
    answer|call) return 0 ;;
    esac
    return 1
}
# first <log> <field>: a field of what a start says of its first command.
# What the command wrote is printed as its bytes.
first() {
    python3 -c 'import base64,json,sys
value = (json.load(open(sys.argv[1])).get("first_command") or {}).get(sys.argv[2], "")
print(base64.b64decode(value).decode() if sys.argv[2] in ("stdout", "stderr") else value)' "$out/$1.out" "$2" 2>/dev/null
}
reason() { # reason <step> <start log> <pattern>
    [ "$dev" = 1 ] || return 0
    check "$1" guest_logged "$2" "$3"
}

# Evidence that is not what the owner pins. The owner signs nothing, and the
# TD it was shown goes back to the pool.
expect 2 "start refuses a pool of another image" start-wrong-image \
    start_session s0 "$out/s0-wrong-image" acme "$out/authority.key" "$out/manifest-other.json" "$launch_key" "${sandbox[@]}"
expect 2 "start refuses a pool under another launch key" start-wrong-key \
    start_session s0 "$out/s0-wrong-key" acme "$out/authority.key" "$manifest" "$out/bundle-b/opkeydata/pubkey" "${sandbox[@]}"
expect 2 "start refuses a pool that pins another key service" start-wrong-pin \
    start_session s0 "$out/s0-wrong-pin" acme "$out/authority.key" "$manifest" "$launch_key" "${sandbox[@]}" \
    --key-service "$out/ks-pin-other.json" --stored-credential api-token
check "the refused starts wrote no binding" [ ! -e "$out/s0-wrong-image" -a ! -e "$out/s0-wrong-key" -a ! -e "$out/s0-wrong-pin" ]

# What the key service refuses a bound guest. Each costs a TD: a guest that
# took a bind it cannot act on ends.
expect 3 "a tenant nobody registered gets no credential" start-unregistered \
    start_session s0 "$out/s0-unregistered" globex "$out/other-authority.key" "$manifest" "$launch_key" "${sandbox[@]}" "${stored[@]}"
reason "the key service refused it: no authority held for that tenant" start-unregistered \
    'HTTP 403 [a-z_]+: the bind is not signed by an authority this key service holds for its tenant'
expect 3 "a bind under another authority gets none of the tenant's credentials" start-usurper \
    start_session s0 "$out/s0-usurper" acme "$out/other-authority.key" "$manifest" "$launch_key" "${sandbox[@]}" "${stored[@]}"
reason "the key service refused it: not the tenant's authority" start-usurper \
    'HTTP 403 [a-z_]+: the bind is not signed by an authority this key service holds for its tenant'
expect 3 "a credential the tenant has not stored ends the start" start-absent \
    start_session s0 "$out/s0-absent" acme "$out/authority.key" "$manifest" "$launch_key" "${sandbox[@]}" --key-service "$pin" --stored-credential absent
reason "the key service refused it: no such credential" start-absent 'HTTP 404 [a-z_]+: the tenant has stored no credential'
if [ -n "$ref_changed" ]; then
    expect 3 "a sandbox image whose content was changed is not run" start-changed \
        start_session s0 "$out/s0-changed" acme "$out/authority.key" "$manifest" "$launch_key" --sandbox-image "$ref_changed"
fi

# Two sessions of two tenants, each on a TD of its own. The first takes one
# credential from the key service and is handed another by a key its bind
# grants.
expect 0 "start session s1" start-s1 start_session s1 "$out/s1" acme "$out/authority.key" "$manifest" "$launch_key" "${sandbox[@]}" \
    "${stored[@]}" --credential token:256
cat "$out/start-s1.out" >> "$out/records.jsonl"
reason "its guest reached the key service through its launcher" start-s1 'opened a session with the key service'
reason "its guest took the stored credential from the key service" start-s1 'took stored credentials from the key service'
check "its guest answered the bind with a receipt that its quote confirmed" [ "$(said start-s1 receipt)" = True ]
check "that quote came on the bind's own call, or with its answer" quoted start-s1
expect 0 "start session s2, another tenant's" start-s2 start_session s2 "$out/s2" globex "$out/other-authority.key" "$manifest" "$launch_key" "${sandbox[@]}" \
    --credential token:256
cat "$out/start-s2.out" >> "$out/records.jsonl"
expect 3 "a second start of a live session is refused" start-s1-again \
    start_session s1 "$out/s1-again" acme "$out/authority.key" "$manifest" "$launch_key" "${sandbox[@]}"

# A session whose first command and a credential its owner holds go with its
# bind, sealed to the key its guest made for its one bind: the daemon carries
# them unread, the guest has the credential in place before its sandbox
# starts, and runs the command as soon as the sandbox does. The command reads
# that credential and what the key service released at that bind, and leaves
# a line each time it runs.
printf 'sealed-secret-%s' "$run" > "$out/sealed"
expect 0 "start session s3 with its first command and a credential in the bind" start-s3 start_session s3 "$out/s3" acme "$out/authority.key" "$manifest" "$launch_key" \
    "${sandbox[@]}" "${stored[@]}" --sealed-credential "bind-token:256=$out/sealed" \
    -- sh -c 'echo ran >> /tmp/first; cat "$C8S_CREDENTIALS_DIR/api-token"; echo; cat "$C8S_CREDENTIALS_DIR/bind-token"'
cat "$out/start-s3.out" >> "$out/records.jsonl"
check "its guest took the command with the bind" [ "$(first start-s3 with_bind)" = True ]
check "the command read the credential released at that bind" [ "$(first start-s3 stdout | sed -n 1p)" = "stored-secret-$run" ]
check "the command read the credential sealed with that bind" [ "$(first start-s3 stdout | sed -n 2p)" = "sealed-secret-$run" ]
check "its guest had the sealed credential in place before its sandbox started" \
    [ "$(python3 -c 'import json,sys; print(",".join((json.load(open(sys.argv[1])).get("credentials") or {}).get("with_bind") or []))' "$out/start-s3.out")" = bind-token ]
check "the daemon carried the sealed message, and its guest took it" grep -q '"msg":"bound a TD".*"sealed":"taken"' "$out/daemon.log"
check "the host holds the sealed credential in none of the daemon's files" \
    sh -c "! sudo -n grep -r -a -q 'sealed-secret-$run' '$out/state' '$out/daemon.log'"
reason "its guest opened the sealed message while it took the bind" start-s3 'a sealed message came.*taken'
reason "its guest put the sealed credential in place" start-s3 'credential released.*bind-token.*"sealed":true'
s3=(--binding "$out/s3" --image-manifest "$manifest" "${accept[@]}")
expect 0 "a later command in s3" exec-s3 "$C8S" session exec "${s3[@]}" -- cat /tmp/first
check "the first command ran once" [ "$(cat "$out/exec-s3.out")" = ran ]
expect 0 "destroy s3" destroy-s3 "$C8S" session destroy --binding "$out/s3" --daemon-cert "$pki/orchestrator.pem" --daemon-key "$pki/orchestrator.key"

# A binder the pool names watches its ready TDs and judges each before its
# claim: the second of two starts finds its guest judged, by its certificate
# alone. The pool names the binder by its key: the certificate it watches
# under is of its own making, and opens no orchestrator call. A caller the
# pool does not name is shown nothing, and judges its guest at the claim.
ready_tds() { sudo -n sh -c "grep -l '\"state\": *\"ready\"' '$out'/state/tds/*/td.json 2>/dev/null | wc -l"; }
# pool_full: wait until both of the pool's TDs are ready.
pool_full() {
    local deadline=$(( $(date +%s) + 300 ))
    until [ "$(ready_tds)" -ge 2 ] || [ "$(date +%s)" -ge "$deadline" ]; do
        sleep 0.2
    done
}
if [ -n "$warm" ]; then
    # Both of the pool's TDs are ready first, so that the stream shows the
    # second start's guest before any claim can take it.
    pool_full
    watcher=(--daemon "127.0.0.1:$port" --daemon-ca "$pki/ca.pem" --pool agents --image-manifest "$manifest" --launch-key "$launch_key"
        --authority-key "$out/authority.key" --tenant acme --sealed-credential bind-token --commands 1 --wait 120s
        --collateral-cache "$out/cache-watch" "${sandbox[@]}" "${accept[@]}")
    expect 0 "a binder the pool names watches its ready TDs under a certificate of its own" watch \
        "$warm" "${watcher[@]}" --daemon-cert "$pki/orchestrator.pem" --daemon-key "$pki/orchestrator.key" \
        --watch-cert "$pki/binder.pem" --watch-key "$pki/binder.key" --session-prefix w --rounds 2
    cat "$out/watch.out" >> "$out/records.jsonl"
    check "the second start found its guest judged before its claim" \
        sh -c "grep '\"kind\":\"session\"' '$out/watch.out' | sed -n 2p | grep -q '\"ready_ahead\":true'"
    check "the binder fetched the vendor's documents itself before its first start" \
        sh -c "grep '\"kind\":\"documents\"' '$out/watch.out' | grep -v -q '\"error\"'"
    expect 1 "the binder's own certificate claims nothing" watch-claim \
        "$warm" "${watcher[@]}" --daemon-cert "$pki/binder.pem" --daemon-key "$pki/binder.key" --session-prefix y --rounds 1 --wait 5s
    check "the daemon said the call needs an orchestrator's certificate" grep -q "needs an orchestrator's certificate" "$out/watch-claim.err"
    check "both starts sealed a credential with the bind, which the first command read back" \
        [ "$(grep -c '"credential_with_bind":true' "$out/watch.out")" = 2 ]
    expect 0 "a caller the pool does not name starts a session all the same" watch-other \
        "$warm" "${watcher[@]}" --daemon-cert "$pki/other.pem" --daemon-key "$pki/other.key" --session-prefix x --rounds 1
    check "it was shown none of the pool's ready TDs" grep -q "are not watched" "$out/watch-other.err"
    check "it judged its guest at the claim" grep -q '"ready_ahead":false' "$out/watch-other.out"

    # A binder that watches a pool needs no claim: it signs a bind for a ready
    # TD it has judged, and the bind claims that TD. The pool lets the binder,
    # by its key, under the first tenant's authority and no other, and the
    # orchestrator, which ends every session, is shown each one that starts
    # so. Whoever the pool does not name claims nothing with a bind.
    "$C8S" session watch "${orchestrator[@]}" > "$out/events.jsonl" 2> "$out/events.err" &
    events_pid=$!
    as_binder=(--daemon-cert "$pki/binder.pem" --daemon-key "$pki/binder.key" --orchestrator-cert "$pki/orchestrator.pem" --orchestrator-key "$pki/orchestrator.key" --claim-with-bind)
    pool_full
    before=$(ready_tds)
    expect 1 "a binder's bind under an authority its pool does not name for it claims no TD" bind-other-authority \
        "$warm" "${watcher[@]}" "${as_binder[@]}" --authority-key "$out/other-authority.key" --session-prefix n --rounds 1
    check "the daemon said no pool lets that caller claim under that authority" grep -q "no pool lets this caller claim" "$out/bind-other-authority.err"
    expect 1 "a key the pool does not name claims no TD with a bind" bind-stranger \
        "$warm" "${watcher[@]}" --daemon-cert "$out/stranger.pem" --daemon-key "$out/stranger.key" --watch-cert "$pki/binder.pem" --watch-key "$pki/binder.key" \
        --claim-with-bind --session-prefix o --rounds 1
    check "the daemon told it the same" grep -q "no pool lets this caller claim" "$out/bind-stranger.err"
    check "the refused binds took no TD from the pool" [ "$(ready_tds)" = "$before" ]
    expect 3 "nobody but an orchestrator is shown the host's TDs" events-binder \
        "$C8S" session watch --daemon "127.0.0.1:$port" --daemon-ca "$pki/ca.pem" --daemon-cert "$pki/binder.pem" --daemon-key "$pki/binder.key"
    expect 0 "a binder the pool names starts a session with a bind that claims its TD" bind-claims \
        "$warm" "${watcher[@]}" "${as_binder[@]}" --session-prefix b --rounds 1 --keep
    cat "$out/bind-claims.out" >> "$out/records.jsonl"
    check "the start made no claim, and found its guest judged" \
        sh -c "grep '\"kind\":\"session\"' '$out/bind-claims.out' | grep '\"claimed_by_bind\":true' | grep -q '\"ready_ahead\":true'"
    check "it sealed a credential with that bind, which the first command read back" grep -q '"credential_with_bind":true' "$out/bind-claims.out"
    check "the daemon recorded that the bind claimed its TD" grep -q '"msg":"bound a TD".*"session":"b-0".*"claimed_by_bind":true' "$out/daemon.log"
    shown=0
    deadline=$(( $(date +%s) + 30 ))
    until [ "$(date +%s)" -ge "$deadline" ]; do
        grep '"session":"b-0"' "$out/events.jsonl" 2>/dev/null | grep '"state":"running"' | grep -q "\"claimed_by\":\"$(key_digest "$pki/binder.pem")\"" && { shown=1; break; }
        sleep 0.2
    done
    check "the orchestrator was shown the session, running, and the binder that started it" [ "$shown" = 1 ]
    expect 3 "the binder ends no session" destroy-binder "$C8S" session destroy --daemon "127.0.0.1:$port" --daemon-ca "$pki/ca.pem" \
        --daemon-cert "$pki/binder.pem" --daemon-key "$pki/binder.key" --session b-0
    expect 0 "the orchestrator ends the session the binder started" destroy-b0 "$C8S" session destroy "${orchestrator[@]}" --session b-0
    check "the orchestrator was shown its end" sh -c "sleep 1; grep '\"session\":\"b-0\"' '$out/events.jsonl' | grep -q '\"state\":\"ended\"'"
    # Two binders sign for the same TD, and one bind comes first: the other
    # is told the TD is not ready before anything reaches a guest, and its
    # binder signs for the next TD it has judged.
    pool_full
    expect 0 "a binder whose TD another bind took first starts its session on the next" bind-lost \
        "$warm" "${watcher[@]}" "${as_binder[@]}" --lose-first --session-prefix l --rounds 1
    cat "$out/bind-lost.out" >> "$out/records.jsonl"
    check "its first bind was answered as not ready, once" grep -q '"not_ready":1' "$out/bind-lost.out"
    check "its session started all the same, with its sealed credential" grep -q '"credential_with_bind":true' "$out/bind-lost.out"
    stop_pid "$events_pid"; events_pid=""

    # A bind that names a key service names the replica of it that its binder
    # judged, on the vendor's documents as the binder fetched them. From its
    # bind on the guest deals with that replica alone: before it, the guest
    # judged its key service on what its host handed it. A bind that names
    # another replica, which the guest's host leads it to no connection
    # with, is refused, and the guest ends.
    with_ks=(--daemon "127.0.0.1:$port" --daemon-ca "$pki/ca.pem" --daemon-cert "$pki/orchestrator.pem" --daemon-key "$pki/orchestrator.key"
        --pool agents --image-manifest "$manifest" --launch-key "$launch_key" --authority-key "$out/authority.key" --tenant acme
        --key-service "$pin" --stored-credential api-token --commands 1 --wait 120s --collateral-cache "$out/cache-watch" "${sandbox[@]}" "${accept[@]}")
    expect 0 "a binder names the key service's replica it judged, and its guest takes the stored credential there" bind-member \
        "$warm" "${with_ks[@]}" --session-prefix k --rounds 1
    cat "$out/bind-member.out" >> "$out/records.jsonl"
    check "the binder judged that replica before its first start" \
        sh -c "grep '\"kind\":\"members\"' '$out/bind-member.out' | grep -v '\"error\"' | grep -q '\"named\":\[\"sha256:[0-9a-f]\{64\}\"\]'"
    expect 1 "a guest takes no bind that names another replica than the one its key service session is with" bind-other-member \
        "$warm" "${with_ks[@]}" --key-service-member "sha256:$(printf '%064d' 1)" --session-prefix m --rounds 1
    check "the guest said it reached no replica the bind names" grep -q "no replica of its key service that the bind names" "$out/bind-other-member.err"
    if [ "$dev" = 1 ]; then
        check "the guest found its session with a replica the bind does not name, and tried for one it names" \
            sudo -n sh -c "grep -a -q 'the session with the key service is with a replica the bind does not name' '$out'/state/tds/*/launcher.log"
    fi
fi

s1=(--binding "$out/s1" --image-manifest "$manifest" "${accept[@]}")
expect 0 "release a credential to s1" credential "$C8S" session credential put token "${s1[@]}" --from-file "$out/released"
expect 0 "run a command in s1 that reads both credentials" exec "$C8S" session exec "${s1[@]}" -- \
    sh -c 'cat "$C8S_CREDENTIALS_DIR/api-token"; echo; cat "$C8S_CREDENTIALS_DIR/token"; echo'
check "it read the credential the owner stored" [ "$(sed -n 1p "$out/exec.out")" = "stored-secret-$run" ]
check "it read the credential the access key released" [ "$(sed -n 2p "$out/exec.out")" = "released-secret-$run" ]
expect 0 "verify s1 with a fresh quote" verify "$C8S" session verify "${s1[@]}" --timing -o json
check "the fresh quote confirms the receipt kept with the binding" [ "$(said verify receipt)" = True ]
expect 0 "verify s1 with collateral from Intel alone" verify-own "$C8S" session verify "${s1[@]}" --own-collateral-only --collateral-cache "$out/cache-own"
expect 0 "a command under the kept verdict" exec-kept "$C8S" session exec "${s1[@]}" -- true

# What a live session refuses.
expect 2 "verify refuses another image" verify-image "$C8S" session verify --binding "$out/s1" --image-manifest "$out/manifest-other.json" "${accept[@]}"
# A receipt is one guest's word on one bind. Another session's in its place,
# or one that was changed after the guest signed it, is not s1's.
cp -a "$out/s1" "$out/s1-receipt-other" && cp "$out/s2/receipt.json" "$out/s1-receipt-other/receipt.json"
expect 2 "verify refuses another session's receipt" verify-receipt-other \
    "$C8S" session verify --binding "$out/s1-receipt-other" --image-manifest "$manifest" "${accept[@]}" -o json
check "it said the receipt is not this guest's" grep -q "receipt kept with the binding" "$out/verify-receipt-other.out"
cp -a "$out/s1" "$out/s1-receipt-changed" && python3 -c '
import base64, json, sys
kept = json.load(open(sys.argv[1]))
kept["receipt"] = base64.b64encode(base64.b64decode(kept["receipt"]).replace(b"running", b"bound")).decode()
json.dump(kept, open(sys.argv[1], "w"))' "$out/s1-receipt-changed/receipt.json"
expect 2 "verify refuses a receipt that was changed" verify-receipt-changed \
    "$C8S" session verify --binding "$out/s1-receipt-changed" --image-manifest "$manifest" "${accept[@]}" -o json
expect 124 "a stranger's key runs nothing" exec-stranger "$C8S" session exec "${s1[@]}" --key "$out/stranger.key" -- id
"$C8S" session credential put api-token "${s1[@]}" --from-file "$out/released" > "$out/put-access.out" 2> "$out/put-access.err"
code=$?
if [ "$code" != 0 ]; then record PASS "no access key hands over what the key service holds" "exit $code"; else record FAIL "no access key hands over what the key service holds" "exit 0"; fi
td2=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["td"])' "$out/s2/route.json")
"$C8S" session exec --binding "$out/s1" --td "$td2" --image-manifest "$manifest" "${accept[@]}" -- id > "$out/exec-cross.out" 2> "$out/exec-cross.err"
code=$?
if [ "$code" = 125 ] || [ "$code" = 124 ]; then
    record PASS "s1's binding runs nothing on s2's TD" "exit $code"
else
    record FAIL "s1's binding runs nothing on s2's TD" "exit $code"
fi
expect 3 "destroy needs an orchestrator's certificate" destroy-anon "$C8S" session destroy --daemon "127.0.0.1:$port" --daemon-ca "$pki/ca.pem" \
    --daemon-cert "$out/stranger.pem" --daemon-key "$out/stranger.key" --session s1

# What a guest can reach, from inside s1 as the session's user: nothing of
# its host, and no other guest. A dev image runs commands in the guest's own
# network namespace, which is what makes the probe one of the guest's network.
if [ "$dev" = 1 ] && [ -z "$store_dir" ]; then
    probe() { "$C8S" session exec "${s1[@]}" --exec-timeout 4 -- bash -c "exec 3<>/dev/tcp/$1/$2" > /dev/null 2>&1; }
    drops() { sudo -n nft list table inet c8s_sessions | awk '/counter packets/ {for (i = 1; i < NF; i++) if ($i == "packets") s += $(i + 1)} END {print s + 0}'; }
    host_ip=$(ip -4 route get 192.0.2.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}')
    targets=("${host_ip:-192.0.2.1}:22" "${host_ip:-192.0.2.1}:$ks_port")
    while read -r tap_ip; do
        IFS=. read -r a b c d <<< "$tap_ip"
        # The host's end of each tap, and the guest at the other end of it.
        targets+=("$tap_ip:22" "$tap_ip:$port" "$a.$b.$c.$((d + 1)):8443")
    done < <(ip -4 -o addr show | awk '$2 ~ /^c8st/ {split($4, a, "/"); print a[1]}')
    before=$(drops)
    for target in "${targets[@]}"; do
        if probe "${target%:*}" "${target#*:}"; then
            record FAIL "a guest cannot reach $target" "it connected"
        else
            record PASS "a guest cannot reach $target"
        fi
    done
    after=$(drops)
    # The probes left the guest and were dropped here: a probe that never left
    # would prove nothing.
    if [ "$after" -gt "$before" ]; then
        record PASS "the host's filter dropped the guest's attempts" "$((after - before)) packets"
    else
        record FAIL "the host's filter dropped the guest's attempts" "its counters did not move"
    fi
fi

# A daemon restarted under live sessions finds its TDs. A TD that ended keeps
# its VMM until its memory is the host's again, which takes seconds: those
# are waited for first, so that the count is of TDs that live.
live_tds() { sudo -n sh -c "grep -L '\"state\": *\"ended\"' '$out'/state/tds/*/td.json 2>/dev/null | wc -l"; }
deadline=$(( $(date +%s) + 120 ))
until [ "$(guests td-)" = "$(live_tds)" ] || [ "$(date +%s)" -ge "$deadline" ]; do
    sleep 0.2
done
before=$(guests td-)
stop_pid "$daemon_pid"; daemon_pid=""
check "the TDs outlive their daemon" [ "$(guests td-)" = "$before" ]
start_daemon
sleep 2
expect 0 "a command in s1 after the daemon restarted" exec-restart "$C8S" session exec "${s1[@]}" -- true
check "the restarted daemon took its TDs over" [ "$(grep -c '"msg":"took over a TD"' "$out/daemon.log")" -ge 2 ]

# A guest of a pool the key service does not list, booted by hand. The key
# service never judges it, so it takes no bind: its sender is told to come
# back until it gives up.
stray_port=$((ks_port + 1))
sudo -n "$C8S" "${launcher[@]}" --image-dir "$IMG" --launch-dir "$out/bundle-b/opkeydata" --work-dir "$out/stray-vm" \
    --name "c8s-session-stray-$run" "${shape[@]}" --network user --port "127.0.0.1:$stray_port:8443" > "$out/stray.log" 2>&1 &
stray_pid=$!
serving "$stray_pid" "$stray_port"
expect 3 "a guest of a pool the key service does not serve takes no bind" bind-stray \
    "$C8S" session bind --url "https://127.0.0.1:$stray_port" --image-manifest "$manifest" --launch-key "$out/bundle-b/opkeydata/pubkey" \
    --authority-key "$out/authority.key" --tenant acme --session s9 --out "$out/s9" --timeout 20s "${accept[@]}" "${sandbox[@]}" "${stored[@]}"
check "it said its key service had not judged it" grep -q not_ready "$out/bind-stray.err" "$out/bind-stray.out"
if [ "$dev" = 1 ]; then
    check "the key service refused it: a pool it does not serve" \
        grep -a -q -E 'HTTP 403 [a-z_]+: the guest is of no pool this key service serves' "$out/stray.log"
fi
stop_pid "$stray_pid"; stray_pid=""

# Destroy, drain, and what is left on the host.
expect 0 "destroy s1" destroy "$C8S" session destroy --binding "$out/s1" --daemon-cert "$pki/orchestrator.pem" --daemon-key "$pki/orchestrator.key"
expect 124 "a destroyed session runs nothing" exec-gone "$C8S" session exec "${s1[@]}" --timeout 20s -- true
expect 0 "s2 is untouched" exec-s2 "$C8S" session exec --binding "$out/s2" --image-manifest "$manifest" "${accept[@]}" -- true
stop_pid "$daemon_pid"; daemon_pid=""
drain
check "drain ends every TD" [ "$(guests td-)" = 0 ]
check "no tap is left" [ -z "$(ip -o link show | grep c8st)" ]
stop_pid "$ks_pid"; ks_pid=""
check "the key service's TD is gone" [ "$(guests "c8s-key-service-$run")" = 0 ]
# The replica had no network device, and it judged this run's guests: every
# document of Intel's it judged them by came over a connection its launcher
# carried, and so did every guest and owner that reached it.
check "its launcher carried the key service's connections to Intel's service" \
    grep -q '"relay":"vendor [^"]*","connections":[1-9]' "$out/ks.log"
check "its launcher carried the connections the key service took" \
    grep -q '"relay":"published port [0-9]*","connections":[1-9]' "$out/ks.log"
finish
