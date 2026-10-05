#!/usr/bin/env bash
# The warm start of a confidential session, timed on one host
# (docs/session-performance.md): a key service in a TD, a session daemon with
# one pool of two ready TDs, and an orchestrator that holds its connection to
# the daemon and starts one session a round: a claim, the check of the unbound
# guest, a bind that carries the session's first command sealed for the
# guest, the check of the guest's receipt for it, and the command's answer,
# with the quote over the bind's nonce judged beside that command.
# test/session/warmstart is that orchestrator.
#
# The pool's capacity is its depth, so no TD boots while a round is timed, and
# a round begins only when the pool is full again, the last session's TD is
# gone and the host has had its rest.
#
# With C8S_FIRECRACKER set, each round also takes one cold boot and one
# snapshot load of stock Firecracker on the same host, between the rounds.
# That baseline is driven over its serial console, with no channel of a
# platform's on top: it is a floor, and a record says so. With
# C8S_FIRECRACKER_AGENT too, each round takes a second snapshot load whose
# first command goes over vsock to an agent in the guest, which is how a
# session's first command is reached: the baseline to hold a session to.
#
# Records go to <work>/timing.jsonl, one JSON object a line, and what the host
# was to <work>/env.txt, whose first line says which rules of the document's
# method the run kept. The script pins power when asked and samples the one
# baseline; it takes no second baseline (the same guest and VMM with TDX
# off), and it runs beside whatever else the host runs, which it counts.
#
#   C8S_BIN                  the c8s binary (default: build/c8s)
#   C8S_WARMSTART            the warmstart binary (go build ./test/session/warmstart)
#   C8S_SESSION_IMAGE        session image directory (required)
#   C8S_KEY_SERVICE_IMAGE    key service image directory (required)
#   C8S_SANDBOX_STORE        directory written by test/session/sandboximage (required)
#   C8S_SESSION_WORK         directory for this run's files (default: a new
#                            temporary directory, kept)
#   C8S_TIMING_ROUNDS        sessions to start (default 21: the first finds
#                            every cache cold and is left out of a summary)
#   C8S_TIMING_STORED=0      start sessions that take nothing from the key
#                            service, to tell what its part of a bind costs
#   C8S_TIMING_SEALED=1      seal a credential with each bind, beside the
#                            first command, where the default has the guest
#                            take one from the key service
#   C8S_TIMING_WATCH=0       judge each guest at its claim, where the default
#                            watches the pool's ready TDs and judges each
#                            before its claim: work a round does not time,
#                            which the summary names and times beside it
#   C8S_TIMING_WITH_BIND=0   send each first command over a connection once
#                            the guest's receipt is checked, where the default
#                            sends it with the bind
#   C8S_TIMING_QUOTE_FIRST=1 judge each bind's quote before the first command
#                            is sent, where the default takes the command's
#                            answer on the guest's receipt and judges the
#                            quote beside it
#   C8S_TIMING_REST          seconds of rest before each round (default 3): a
#                            long one shows what a start costs once the
#                            guests' connections have sat idle
#   C8S_TIMING_PIN_POWER=1   for the run, set every CPU's governor to
#                            performance and turn off idle states deeper than
#                            C1E; both are put back when the run ends
#   C8S_FIRECRACKER          directory written by firecracker-setup.sh
#   C8S_FIRECRACKER_SAMPLE   the sampling program (default: beside this script)
#   C8S_FIRECRACKER_AGENT    the baseline's guest agent, built for the guest
#                            (CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build
#                            ./test/session/fcagent)
#   C8S_SESSION_DEV=1        the images are dev builds: attach their consoles.
#                            Not a measured configuration.
#   C8S_QUOTE_SOCKET, C8S_SESSION_CONFINE, C8S_ACCEPT_TCB, C8S_SESSION_PORT,
#   C8S_KEY_SERVICE_PORT, C8S_SESSION_CIDR
#                            as for hardware.sh
#
# The logs of what runs under sudo are this user's files, written by this
# shell.
# shellcheck disable=SC2024
set -uo pipefail

C8S=${C8S_BIN:-build/c8s}
WARM=${C8S_WARMSTART:?set C8S_WARMSTART to the warmstart binary}
IMG=${C8S_SESSION_IMAGE:?set C8S_SESSION_IMAGE to a session image directory}
KSIMG=${C8S_KEY_SERVICE_IMAGE:?set C8S_KEY_SERVICE_IMAGE to a key service image directory}
store_dir=${C8S_SANDBOX_STORE:?set C8S_SANDBOX_STORE to a directory written by test/session/sandboximage}
rounds=${C8S_TIMING_ROUNDS:-21}
stored=${C8S_TIMING_STORED:-1}
sealed=${C8S_TIMING_SEALED:-0}
[ "$sealed" = 1 ] && stored=0
watch=${C8S_TIMING_WATCH:-1}
rest=${C8S_TIMING_REST:-3}
pin_power=${C8S_TIMING_PIN_POWER:-0}
fc=${C8S_FIRECRACKER:-}
fc_sample=${C8S_FIRECRACKER_SAMPLE:-$(dirname "$(readlink -f "$0")")/firecracker_sample.py}
fc_agent=${C8S_FIRECRACKER_AGENT:-}
dev=${C8S_SESSION_DEV:-0}
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
WARM=$(readlink -f "$WARM")
[ -x "$WARM" ] || { echo "$WARM is no program" >&2; exit 2; }
[ -f "$manifest" ] && [ -f "$KSIMG/manifest.json" ] || { echo "an image directory holds no manifest.json" >&2; exit 2; }
sudo -n true 2>/dev/null || { echo "this run needs passwordless sudo" >&2; exit 2; }
[ "$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null)" = Y ] || { echo "this host's KVM runs no TD (kvm_intel.tdx is not Y)" >&2; exit 2; }
if sudo -n nft list table inet c8s_sessions > /dev/null 2>&1; then
    echo "the packet filter holds a table inet c8s_sessions: a session daemon runs here, or one left it behind" >&2
    exit 2
fi
ref=$(cat "$store_dir/ref") store=$store_dir/images.store
[ -n "$ref" ] && [ -f "$store" ] || { echo "$store_dir is no directory written by test/session/sandboximage" >&2; exit 2; }
if [ -n "$fc" ]; then
    [ -x "$fc/firecracker" ] && [ -f "$fc_sample" ] || { echo "$fc holds no firecracker, or $fc_sample is missing" >&2; exit 2; }
    fc=$(readlink -f "$fc")
    # The snapshot is taken with the agent this run names, or with none.
    rm -f "$fc/fcagent"
    if [ -n "$fc_agent" ]; then
        [ -f "$fc_agent" ] || { echo "C8S_FIRECRACKER_AGENT=$fc_agent is not a file" >&2; exit 2; }
        install -m 0755 "$fc_agent" "$fc/fcagent"
    fi
elif [ -n "$fc_agent" ]; then
    echo "C8S_FIRECRACKER_AGENT needs C8S_FIRECRACKER" >&2
    exit 2
fi

out=${C8S_SESSION_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/c8s-session-timing.XXXXXX")}
mkdir -p "$out/pki" || exit 2
[ ! -e "$out/timing.jsonl" ] || { echo "$out holds an earlier run" >&2; exit 2; }
out=$(readlink -f "$out")
run=$(basename "$out")
records=$out/timing.jsonl
echo "records in $out"
quiet() { "$@" > /dev/null 2>> "$out/setup.err"; }
die() { echo "FAILED: $*" >&2; tail -c 400 "$out/setup.err" >&2 2>/dev/null; exit 1; }

pki=$out/pki
quiet openssl ecparam -name prime256v1 -genkey -noout -out "$pki/ca.key"
quiet openssl req -x509 -new -key "$pki/ca.key" -subj "/CN=session test authority" -days 2 -out "$pki/ca.pem"
for who in server orchestrator; do
    quiet openssl ecparam -name prime256v1 -genkey -noout -out "$pki/$who.key"
    quiet openssl req -new -key "$pki/$who.key" -subj "/CN=$who" -out "$pki/$who.csr"
    printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' > "$pki/$who.ext"
    quiet openssl x509 -req -in "$pki/$who.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca.key" -CAcreateserial -days 2 \
        -extfile "$pki/$who.ext" -out "$pki/$who.pem"
done
quiet openssl ecparam -name prime256v1 -genkey -noout -out "$out/authority.key"

ks_pid="" daemon_pid="" probe_pid="" governor="" idle_off=()
stop_pid() { # stop_pid <pid>
    [ -n "$1" ] || return 0
    sudo -n kill -TERM "$1" 2>/dev/null
    wait "$1" 2>/dev/null
}
restore_power() {
    [ -n "$governor" ] || return 0
    echo "$governor" | sudo -n tee /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor > /dev/null
    for state in "${idle_off[@]}"; do echo 0 | sudo -n tee "$state" > /dev/null; done
    governor=""
}
cleanup() {
    stop_pid "$daemon_pid"; daemon_pid=""
    [ -f "$out/config.yaml" ] && sudo -n "$C8S" session-daemon drain --config "$out/config.yaml" --wait 3m >> "$out/drain.out" 2>> "$out/daemon.log"
    sudo -n nft delete table inet c8s_sessions 2>/dev/null
    stop_pid "$probe_pid"; probe_pid=""
    stop_pid "$ks_pid"; ks_pid=""
    restore_power
}
trap cleanup EXIT

launcher=(session-launcher run --platform tdx --vsock-cid auto)
[ -S "$quote_socket" ] && launcher+=(--quote-socket "$quote_socket")
[ -n "$confine" ] && launcher+=(--confine "$confine")
[ "$dev" = 1 ] && launcher+=(--console)
shape=(--vcpus 4 --memory 16G --low-memory 512M --scratch 4G --image-store "$store")
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
launch_ks() { # launch_ks <bundle> <work directory> <log>
    sudo -n "$C8S" "${launcher[@]}" --image-dir "$KSIMG" --launch-dir "$1/opkeydata" --work-dir "$2" \
        --name "c8s-key-service-$run" "${ks_shape[@]}" --network none --port "127.0.0.1:$ks_port:8443" > "$3" 2>&1 &
    ks_pid=$!
}

# Two machines are read from evidence first, as in hardware.sh: the key
# service's and the class's, each from one guest under a document that lists
# none.
pin=$out/ks-pin.json
ks_pool=(--image-manifest "$KSIMG/manifest.json" --pool "$manifest:$out/pool.key.pub" "${accept[@]}")
quiet "$C8S" session launch-config key --out "$out/pool.key" || die "the pool's key"
quiet "$C8S" session key-service launch-config new --out "$out/ks-probe" "${ks_pool[@]}" || die "the key service's first bundle"
launch_ks "$out/ks-probe" "$out/ks-probe-vm" "$out/ks-probe.log"
serving "$ks_pid" "$ks_port" || die "the key service's probe never served"
ks_machine=$("$C8S" session key-service launch-config machine --bundle "$out/ks-probe" --url "https://127.0.0.1:$ks_port" "${accept[@]}" 2>> "$out/setup.err") \
    || die "the key service's machine"
stop_pid "$ks_pid"; ks_pid=""
quiet "$C8S" session key-service launch-config new --out "$out/ks" --key "$out/ks-probe/launch.key" "${ks_pool[@]}" --machine "$ks_machine" \
    || die "the key service's bundle"
quiet "$C8S" session key-service pin --bundle "$out/ks" --url "https://127.0.0.1:$ks_port" --out "$pin" "${accept[@]}" || die "the pin"

# The sandbox image is unpacked in every pooled TD before anybody binds it.
pool_doc=(--key "$out/pool.key" --key-service "$pin" --image-manifest "$manifest" --pool agents --class s-4x16 --prestage "$ref")
probe_port=$((ks_port + 2))
quiet "$C8S" session launch-config new --out "$out/bundle-probe" "${pool_doc[@]}" || die "the pool's first bundle"
sudo -n "$C8S" "${launcher[@]}" --image-dir "$IMG" --launch-dir "$out/bundle-probe/opkeydata" --work-dir "$out/probe-vm" \
    --name "c8s-session-probe-$run" "${shape[@]}" --network user --port "127.0.0.1:$probe_port:8443" > "$out/probe.log" 2>&1 &
probe_pid=$!
serving "$probe_pid" "$probe_port" || die "the pool's probe never served"
machine=$("$C8S" session launch-config machine --url "https://127.0.0.1:$probe_port" --image-manifest "$manifest" \
    --launch-key "$out/pool.key.pub" "${accept[@]}" 2>> "$out/setup.err") || die "the class's machine"
stop_pid "$probe_pid"; probe_pid=""
quiet "$C8S" session launch-config new --out "$out/bundle" "${pool_doc[@]}" --machine "$machine" || die "the pool's bundle"

launch_ks "$out/ks" "$out/ks-vm" "$out/ks.log"
serving "$ks_pid" "$ks_port" || die "the key service never served"
printf 'timing-secret-%s' "$run" > "$out/stored"
tenant=(--key-service "$pin" --tenant acme --authority-key "$out/authority.key")
quiet "$C8S" session key-service tenant register "${tenant[@]}" || die "the tenant's registration"
quiet "$C8S" session key-service credential put api-token "${tenant[@]}" --from-file "$out/stored" || die "the stored credential"

binder=sha256:$(openssl x509 -in "$pki/orchestrator.pem" -noout -pubkey 2>> "$out/setup.err" | openssl pkey -pubin -outform DER 2>> "$out/setup.err" | sha256sum | cut -c1-64)
[ ${#binder} = 71 ] || die "the digest of the orchestrator's public key"
{
    echo "listen: 127.0.0.1:$port"
    echo "host: test-host"
    echo "stateDir: $out/state"
    echo "capacity: 2"
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
    echo "    imageStore: $store"
    # The orchestrator binds its sessions itself, and may watch the pool.
    echo "    binders: [\"$binder\"]"
} > "$out/config.yaml"
sudo -n "$C8S" session-daemon run --config "$out/config.yaml" >> "$out/daemon.log" 2>&1 &
daemon_pid=$!

# before-round <n>: return once the pool is full again, the last session's TD
# is gone and the host has rested, having taken the round's baseline samples.
cat > "$out/before-round" <<HOOK
#!/usr/bin/env bash
deadline=\$(( \$(date +%s) + 300 ))
until [ "\$(grep -c '"msg":"a TD is ready"' "$out/daemon.log" 2>/dev/null)" -ge \$((\$1 + 2)) ] && [ "\$(pgrep -cf '[q]emu-system.*guest=td-')" = 2 ]; do
    kill -0 $daemon_pid 2>/dev/null || { echo "the daemon ended" >&2; exit 1; }
    [ "\$(date +%s)" -lt "\$deadline" ] || { echo "the pool never filled" >&2; exit 1; }
    sleep 0.5
done
sleep $rest
if [ -n "$fc" ]; then
    sudo -n python3 "$fc_sample" "$fc" cold >> "$records" || exit 1
    sudo -n python3 "$fc_sample" "$fc" load >> "$records" || exit 1
    if [ -n "$fc_agent" ]; then
        sudo -n python3 "$fc_sample" "$fc" load-vsock >> "$records" || exit 1
    fi
    sleep 1
fi
HOOK
chmod 0755 "$out/before-round"

if [ "$pin_power" = 1 ]; then
    governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
    echo performance | sudo -n tee /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor > /dev/null
    for state in /sys/devices/system/cpu/cpu[0-9]*/cpuidle/state[0-9]*; do
        case "$(cat "$state/name")" in
        POLL|C1|C1E) ;;
        *) [ "$(cat "$state/disable")" = 0 ] && { echo 1 | sudo -n tee "$state/disable" > /dev/null; idle_off+=("$state/disable"); } ;;
        esac
    done
fi
others=$(pgrep -a qemu-system | grep -v -c "guest=td-\|guest=c8s-key-service-$run")
{
    printf 'method: power %s; %s other VMs on the host; TDX on in the firmware; ' "$([ "$pin_power" = 1 ] && echo pinned || echo "as the host had it")" "$others"
    baseline="not sampled"
    [ -n "$fc" ] && baseline="Firecracker over its serial console (a floor), interleaved"
    [ -n "$fc_agent" ] && baseline="Firecracker over vsock to an agent in its guest, and over its serial console (a floor), interleaved"
    printf 'baseline %s; no second baseline; ' "$baseline"
    printf 'before the measured path: the vendor'"'"'s documents fetched by the binder (timed beside the rounds); %s\n' "$([ "$watch" = 1 ] && echo "each ready TD judged when it became ready (timed beside the rounds)" || echo "each TD judged at its claim")"
    echo "run $run, $rounds rounds, $(date -u +%FT%TZ), stored credential $stored, sealed credential $sealed, ready TDs watched $watch, first command with the bind ${C8S_TIMING_WITH_BIND:-1}, quote first ${C8S_TIMING_QUOTE_FIRST:-0}, rest $rest s, Firecracker ${fc:-not sampled}"
    echo "host kernel $(uname -r)"
    lscpu | grep -E "Model name|^CPU\(s\)|Thread|Core|Socket" | sed 's/  */ /g'
    echo "power pinned by this run: $pin_power"
    echo "governor $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor) driver $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver) no_turbo $(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null) preference $(cat /sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference 2>/dev/null)"
    echo "idle states of CPU 0: $(for s in /sys/devices/system/cpu/cpu0/cpuidle/state[0-9]*; do printf '%s%s ' "$(cat "$s/name")" "$([ "$(cat "$s/disable")" = 1 ] && echo '(off)')"; done)"
    echo "TDX module $(cat /sys/firmware/tdx/tdx_module/version 2>/dev/null || sudo -n dmesg 2>/dev/null | grep -o 'TDX module[^,]*' | tail -1)"
    echo "microcode $(grep -m1 microcode /proc/cpuinfo | sed 's/.*: //')"
    qemu-system-x86_64 --version | head -1
    [ -n "$fc" ] && cat "$fc/versions.txt"
    echo "c8s $("$C8S" --version 2>/dev/null | head -1) sha256 $(sha256sum "$C8S" | cut -c1-64)"
    echo "warmstart sha256 $(sha256sum "$WARM" | cut -c1-64)"
    echo "session image mrtd $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tdx"]["mrtd"])' "$manifest") machine $machine"
    echo "key service image mrtd $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tdx"]["mrtd"])' "$KSIMG/manifest.json") machine $ks_machine"
    echo "firmware sha256 $(sha256sum "$IMG/OVMF.tdx.fd" | cut -c1-64)"
    echo "session class 4 vCPUs, 16 GiB; key service 2 vCPUs, 4 GiB; Firecracker guest 4 vCPUs, 16 GiB"
    echo "sandbox image $ref"
    echo "work directory on $(df --output=fstype,source "$out" | tail -1)"
    echo "load $(cat /proc/loadavg)"
    free -g | sed -n 2p
} > "$out/env.txt" 2>&1

if [ -n "$fc" ]; then
    sudo -n python3 "$fc_sample" "$fc" snapshot >> "$records" || die "the Firecracker snapshot"
fi
args=(--daemon "127.0.0.1:$port" --daemon-ca "$pki/ca.pem" --daemon-cert "$pki/orchestrator.pem" --daemon-key "$pki/orchestrator.key"
    --pool agents --image-manifest "$manifest" --launch-key "$out/bundle/opkeydata/pubkey" --authority-key "$out/authority.key"
    --tenant acme --session-prefix "t" --sandbox-image "$ref" --collateral-cache "$out/collateral"
    --rounds "$rounds" --commands 3 --attest --before-round "$out/before-round")
[ "$stored" = 1 ] && args+=(--key-service "$pin" --stored-credential api-token)
[ "$sealed" = 1 ] && args+=(--sealed-credential api-token)
[ "$watch" = 1 ] || args+=(--watch-ready=false)
[ "${C8S_TIMING_QUOTE_FIRST:-0}" = 1 ] && args+=(--quote-first)
[ "${C8S_TIMING_WITH_BIND:-1}" = 0 ] && args+=(--command-with-bind=false)
[ -n "${C8S_ACCEPT_TCB:-}" ] && args+=(--accept-tcb-status "$C8S_ACCEPT_TCB")
"$WARM" "${args[@]}" >> "$records" 2> "$out/warmstart.err" || die "the rounds: $(tail -c 400 "$out/warmstart.err")"
restore_power

# How long each TD took from its launch to ready.
grep -o '"boot_ms":[0-9]*' "$out/daemon.log" | sed 's/"boot_ms":\([0-9]*\)/{"kind":"session-cold","boot_ms":\1}/' >> "$records"
echo "load at the end $(cat /proc/loadavg)" >> "$out/env.txt"
python3 - "$records" <<'EOF' | tee "$out/summary.txt"
import json, statistics, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
def show(label, values, unit):
    values = sorted(values)
    if not values:
        return
    p = lambda q: values[min(len(values) - 1, int(q * len(values)))]
    print(f"{label:34} n={len(values):3}  median {statistics.median(values):9.1f}  p90 {p(0.9):9.1f}  min {values[0]:9.1f}  max {values[-1]:9.1f}  {unit}")
# A round that a refresh of the vendor's documents ran beside is named and
# left out: the refresh is no part of a start.
refreshes = [r for r in rows if r.get("kind") == "refresh"]
def beside(r):
    end = r["at_unix_us"] + max(r.get("first_cmd_us", 0), r.get("confirmed_us", 0))
    return any(f["at_unix_us"] < end and f["at_unix_us"] + f["took_us"] > r["at_unix_us"] for f in refreshes)
sessions = [r for r in rows if r.get("kind") == "session" and r["round"] > 0]
steady = [r for r in sessions if not beside(r)]
for key in ("claim_us", "ready_check_us", "sign_us", "seal_us", "bind_us", "judge_us", "start_us", "first_exec_us", "first_cmd_us", "quote_us", "confirmed_us", "attest_us", "destroy_us"):
    show("session " + key[:-3], [r[key] / 1000 for r in steady if r.get(key)], "ms")
if steady:
    count = lambda key: sum(1 for r in steady if r.get(key))
    print(f"of {len(steady)} rounds, the guest took the first command with its bind in {count('with_bind')}, the command's answer was taken on the receipt in {count('on_receipt')}, and the connection for commands was made ahead in {count('reached_ahead')}; the quote came with the bind's answer in {count('quote_in_answer')}")
    print(f"of {len(steady)} rounds, the guest was judged before its claim in {count('ready_ahead')}, and had a credential sealed with its bind in place in {count('credential_with_bind')}")
show("ready TD judged ahead", [r["ready_judged_us"] / 1000 for r in steady if r.get("ready_judged_us")], "ms (before the round: no part of its times)")
show("vendor documents fetched", [r["took_us"] / 1000 for r in rows if r.get("kind") == "documents"], "ms (before the rounds: no part of their times)")
show("vendor documents refreshed", [r["took_us"] / 1000 for r in refreshes], "ms (beside the rounds)")
if len(sessions) != len(steady):
    print(f"{len(sessions) - len(steady)} rounds ran beside a refresh of the vendor's documents and are left out: rounds {', '.join(str(r['round']) for r in sessions if beside(r))}")
show("session later command", [v / 1000 for r in steady for v in r.get("exec_us", [])], "ms")
first = [r for r in rows if r.get("kind") == "session" and r["round"] == 0]
if first:
    print(f"the first round, caches cold: start {first[0]['start_us'] / 1000:.1f} ms, first command {first[0]['first_cmd_us'] / 1000:.1f} ms")
show("session TD launch to ready", [r["boot_ms"] for r in rows if r.get("kind") == "session-cold"], "ms")
for kind, label, how in (("fc-cold", "Firecracker cold", "serial console: a floor"), ("fc-load", "Firecracker snapshot load", "serial console: a floor"),
                         ("fc-load-vsock", "Firecracker snapshot load", "vsock to an agent in the guest")):
    show(label + " to first command", [r.get("first_cmd_us", r["first_cmd_ms"] * 1000) / 1000 for r in rows if r.get("kind") == kind], f"ms ({how})")
show("Firecracker later command", [r["next_cmd_us"] / 1000 for r in rows if r.get("next_cmd_us")], "ms (vsock to an agent in the guest)")
EOF
head -1 "$out/env.txt" | tee -a "$out/summary.txt"
