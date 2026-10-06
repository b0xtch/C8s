#!/usr/bin/env bash
# The hardware test of the second baseline's guests
# (docs/session-performance.md): session guests that boot with no TEE and
# simulate one in software, from a development build made with the
# c8s_simtee tag. It protects nothing, and exists so that a start can be
# timed with TDX off: this test holds it to working as a TD's does, and to
# never passing for one.
#
# A simulated authority is made and its documents served. A key service
# and a pool of session guests boot from simulating images with no TDX
# object, each on registers its launcher declared from its image's manifest.
# Their machines are read from evidence, a tenant registers and stores a
# credential, and a session starts, runs a command that reads the credential
# and is verified from a fresh quote: all under the simulated authority, by
# the development build alone.
#
# Then what must be refused: the simulation by a release build, which has no
# command, option or configuration word for it; a simulated guest by a
# verifier under the vendor's root, and by one under another simulated
# authority; a launch whose manifest names other files than the ones booted.
# With C8S_SESSION_IMAGE, an image built for a TD, it also checks that
# neither kind of guest runs as the other: a simulating image ends in a TD,
# a TD's image ends without one, and a TD's evidence is nothing to a verifier
# under the simulated authority.
#
# It needs a TDX host with QEMU and passwordless sudo, as hardware.sh does,
# and leaves the host as that test does.
#
#   C8S_SIM_BIN                the c8s binary built with -tags c8s_simtee (required)
#   C8S_BIN                    the release c8s binary (default: build/c8s)
#   C8S_SIM_SESSION_IMAGE      simulating session image directory (required:
#                              C8S_SIMTEE=1 session-guest-image/build)
#   C8S_SIM_KEY_SERVICE_IMAGE  simulating key service image directory (required)
#   C8S_SESSION_IMAGE          a session image built for a TD, of the same
#                              kind (locked or dev), for the checks that
#                              neither kind of guest runs as the other
#   C8S_SESSION_WORK           directory for this run's files (default: a new
#                              temporary directory, kept)
#   C8S_SESSION_DEV=1          the images are dev builds: attach their
#                              consoles and hold each refusal to its reason
#   C8S_SANDBOX_STORE          directory written by test/session/sandboximage;
#                              a locked run needs it
#   C8S_SESSION_OFFERED=0      leave out the check of what a guest takes of
#                              KVM's paravirtual features, and the control of
#                              it and of hardware.sh's. They need bpftrace
#                              and a C compiler on the host
#   C8S_KVM_OFFER              as for hardware.sh
#   C8S_CONTROL_KERNEL         the kernel image that control boots (default:
#                              the host's own, /boot/vmlinuz-<its release>)
#   C8S_QUOTE_SOCKET, C8S_SESSION_CONFINE, C8S_ACCEPT_TCB, C8S_SESSION_PORT,
#   C8S_KEY_SERVICE_PORT, C8S_SESSION_CIDR
#                              as for hardware.sh; the quoting service and the
#                              accepted statuses are for the TD alone
#
# Exit 0 when every step passed. <work>/summary.txt lists the steps.
# The logs of what runs under sudo are this user's files, written by this
# shell.
# shellcheck disable=SC2024
set -uo pipefail

SIM=${C8S_SIM_BIN:?set C8S_SIM_BIN to a c8s binary built with -tags c8s_simtee}
C8S=${C8S_BIN:-build/c8s}
IMG=${C8S_SIM_SESSION_IMAGE:?set C8S_SIM_SESSION_IMAGE to a simulating session image directory}
KSIMG=${C8S_SIM_KEY_SERVICE_IMAGE:?set C8S_SIM_KEY_SERVICE_IMAGE to a simulating key service image directory}
TDIMG=${C8S_SESSION_IMAGE:-}
dev=${C8S_SESSION_DEV:-0}
store_dir=${C8S_SANDBOX_STORE:-}
quote_socket=${C8S_QUOTE_SOCKET:-/var/run/tdx-qgs/qgs.socket}
confine=${C8S_SESSION_CONFINE:-}
accept=()
[ -n "${C8S_ACCEPT_TCB:-}" ] && accept=(--accept-tcb-status "$C8S_ACCEPT_TCB")
port=${C8S_SESSION_PORT:-7443}
ks_port=${C8S_KEY_SERVICE_PORT:-18543}
cidr=${C8S_SESSION_CIDR:-10.213.0.0/24}
manifest=$IMG/manifest.json

for name in SIM C8S; do
    path=$(command -v "${!name}" || true)
    [ -n "$path" ] && [ -x "$path" ] || { echo "${!name} is no program (C8S_SIM_BIN, C8S_BIN)" >&2; exit 2; }
    printf -v "$name" '%s' "$(readlink -f "$path")"
done
[ -f "$manifest" ] && [ -f "$KSIMG/manifest.json" ] || { echo "an image directory holds no manifest.json" >&2; exit 2; }
[ -f "$IMG/SIMULATED-TEE" ] && [ -f "$KSIMG/SIMULATED-TEE" ] || { echo "$IMG or $KSIMG is no image built with C8S_SIMTEE=1" >&2; exit 2; }
[ -z "$TDIMG" ] || [ -f "$TDIMG/manifest.json" ] || { echo "C8S_SESSION_IMAGE=$TDIMG holds no manifest.json" >&2; exit 2; }
sudo -n true 2>/dev/null || { echo "this test needs passwordless sudo" >&2; exit 2; }
if ss -ltn 2>/dev/null | grep -q -E ":($port|$ks_port) "; then echo "port $port or $ks_port is taken" >&2; exit 2; fi
if sudo -n nft list table inet c8s_sessions > /dev/null 2>&1; then
    echo "the packet filter holds a table inet c8s_sessions: a session daemon runs here, or one left it behind" >&2
    exit 2
fi
sandbox=() ref="" ref_ends="" store=""
if [ -n "$store_dir" ]; then
    ref=$(cat "$store_dir/ref") store=$store_dir/images.store
    # A store written before the tool made this image has none of it.
    ref_ends=$(cat "$store_dir/ref-ends" 2>/dev/null || true)
    [ -n "$ref" ] && [ -f "$store" ] || { echo "$store_dir is no directory written by test/session/sandboximage" >&2; exit 2; }
    sandbox=(--sandbox-image "$ref")
elif [ "$dev" != 1 ]; then
    echo "a locked image needs C8S_SANDBOX_STORE: it runs a session's code in a sandbox image only" >&2
    exit 2
fi

out=${C8S_SESSION_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/c8s-session-simtee.XXXXXX")}
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
# unknown <step> <log> <pattern> <command...>: the program must not know
# what the command asks of it, and say so.
unknown() {
    local step=$1 log=$2 pattern=$3 code
    shift 3
    timeout 30 "$@" > "$out/$log.out" 2> "$out/$log.err"
    code=$?
    if [ "$code" != 0 ] && [ "$code" != 124 ] && grep -q -E "$pattern" "$out/$log.err"; then
        record PASS "$step" "exit $code"
    else
        record FAIL "$step" "exit $code: $(tail -c 300 "$out/$log.err" | tr '\n' ' ')"
    fi
}
check() { # check <step> <condition...>
    local step=$1
    shift
    if "$@"; then record PASS "$step"; else record FAIL "$step"; fi
}
finish() {
    {
        echo "simulated TEE hardware run $run: $([ "$failed" = 0 ] && echo PASS || echo FAIL)"
        printf '%s\n' "${results[@]}"
    } | tee "$out/summary.txt"
    exit "$failed"
}

pki=$out/pki
openssl ecparam -name prime256v1 -genkey -noout -out "$pki/ca.key" 2>/dev/null
openssl req -x509 -new -key "$pki/ca.key" -subj "/CN=session test authority" -days 2 -out "$pki/ca.pem" 2>/dev/null
for who in server orchestrator; do
    openssl ecparam -name prime256v1 -genkey -noout -out "$pki/$who.key" 2>/dev/null
    openssl req -new -key "$pki/$who.key" -subj "/CN=$who" -out "$pki/$who.csr" 2>/dev/null
    printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' > "$pki/$who.ext"
    openssl x509 -req -in "$pki/$who.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca.key" -CAcreateserial -days 2 \
        -extfile "$pki/$who.ext" -out "$pki/$who.pem" 2>/dev/null
done
openssl ecparam -name prime256v1 -genkey -noout -out "$out/authority.key" 2>/dev/null

ks_pid="" daemon_pid="" probe_pid="" vendor_pid="" other_vendor_pid=""
stop_pid() { # stop_pid <pid>
    [ -n "$1" ] || return 0
    sudo -n kill -TERM "$1" 2>/dev/null
    wait "$1" 2>/dev/null
}
cleanup() {
    stop_pid "$daemon_pid"; daemon_pid=""
    [ -f "$out/config.yaml" ] && sudo -n "$SIM" session-daemon drain --config "$out/config.yaml" --wait 3m >> "$out/drain.out" 2>> "$out/daemon.log"
    sudo -n nft delete table inet c8s_sessions 2>/dev/null
    stop_pid "$probe_pid"; probe_pid=""
    stop_pid "$ks_pid"; ks_pid=""
    [ -n "$vendor_pid" ] && kill "$vendor_pid" 2>/dev/null
    [ -n "$other_vendor_pid" ] && kill "$other_vendor_pid" 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT

# The simulated authority, and whoever serves its documents.
tee=$out/authority
expect 0 "a simulated authority is made" simtee-new "$SIM" session simtee new --out "$tee"
expect 1 "none is made over another" simtee-again "$SIM" session simtee new --out "$tee"
# serve <directory> <log>: serve an authority's documents, and wait for the
# address.
serve() {
    "$SIM" session simtee vendor --dir "$1" > "$out/$2.log" 2>&1 &
    local pid=$! deadline=$(( $(date +%s) + 20 ))
    until [ -s "$1/vendor" ]; do
        kill -0 "$pid" 2>/dev/null && [ "$(date +%s)" -lt "$deadline" ] || { echo ""; return 1; }
        sleep 0.1
    done
    echo "$pid"
}
vendor_pid=$(serve "$tee" vendor)
if [ -z "$vendor_pid" ]; then
    record FAIL "the authority's documents are served" "$(tail -c 300 "$out/vendor.log" | tr '\n' ' ')"
    finish
fi
record PASS "the authority's documents are served" "$(cat "$tee/vendor")"
simulated=(--simulated-tee "$tee")

# A release build has nothing of this: no command, no option on its launcher
# or on a command that judges evidence, and no word for it in its daemon's
# configuration.
unknown "a release build has no command for a simulated authority" release-command 'unknown (command|flag)' \
    "$C8S" session simtee new --out "$out/authority-release"
check "and made none" test ! -e "$out/authority-release"
check "its help names none, and the development build's does" sh -c "! '$C8S' session --help 2>&1 | grep -q -i simtee && '$SIM' session --help 2>&1 | grep -q simtee"
unknown "a release build's launcher has no option for one" release-launcher 'unknown flag: --simulated-tee' \
    "$C8S" session-launcher run --platform tdx --image-dir "$IMG" --launch-dir "$out" --work-dir "$out/release-vm" "${simulated[@]}"
unknown "nor has a release build's command that judges evidence" release-verify 'unknown flag: --simulated-tee' \
    "$C8S" session verify --binding "$out/none" --image-manifest "$manifest" "${simulated[@]}"
{
    echo "listen: 127.0.0.1:$port"
    echo "host: test-host"
    echo "stateDir: $out/state-release"
    echo "capacity: 1"
    echo "tls: {cert: $pki/server.pem, key: $pki/server.key, clientCA: $pki/ca.pem}"
    echo "network: {mode: user, firstPort: 39100}"
    echo "vmm: {simulatedTEE: $tee}"
    echo "classes:"
    echo "  s-4x16: {vcpus: 4, memory: 16G}"
    echo "pools:"
    echo "  - {imageDir: $IMG, launchDir: $out/none, depth: 1}"
} > "$out/config-release.yaml"
unknown "a release build's daemon refuses a configuration that asks for one" release-daemon 'simulatedTEE' \
    "$C8S" session-daemon run --config "$out/config-release.yaml"

launcher=(session-launcher run --platform tdx --vsock-cid auto)
[ -n "$confine" ] && launcher+=(--confine "$confine")
[ "$dev" = 1 ] && launcher+=(--console)
shape=(--vcpus 4 --memory 16G --low-memory 512M --scratch 4G ${store:+--image-store "$store"})
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
# ends_unserved <step> <log> <port> <program> <launcher arguments...>: a
# guest launched so must end by itself, and before it serves.
ends_unserved() {
    local step=$1 log=$2 at=$3 program=$4 began served=0 code
    shift 4
    began=$(date +%s%N)
    sudo -n timeout 240 "$program" "${launcher[@]}" "$@" --network user --port "127.0.0.1:$at:8443" > "$out/$log.log" 2>&1 &
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
launch_ks() { # launch_ks <bundle> <work directory> <log>
    sudo -n "$SIM" "${launcher[@]}" "${simulated[@]}" --image-dir "$KSIMG" --launch-dir "$1/opkeydata" --work-dir "$2" \
        --name "c8s-key-service-$run" "${ks_shape[@]}" --network none --port "127.0.0.1:$ks_port:8443" > "$3" 2>&1 &
    ks_pid=$!
}

# The key service, with no TEE: its machine is read from the evidence of one
# replica, as a TD's is, and its document then lists it.
pin=$out/ks-pin.json
ks_pool=(--image-manifest "$KSIMG/manifest.json" --pool "$manifest:$out/pool.key.pub")
expect 0 "the pool's launch key" pool-key "$SIM" session launch-config key --out "$out/pool.key"
expect 0 "a key service bundle that lists no machine" ks-bundle-probe "$SIM" session key-service launch-config new --out "$out/ks-probe" "${ks_pool[@]}"
began=$(date +%s%N)
launch_ks "$out/ks-probe" "$out/ks-probe-vm" "$out/ks-probe.log"
if ! serving "$ks_pid" "$ks_port"; then
    record FAIL "a simulating key service boots with no TEE and serves" "$(tail -c 600 "$out/ks-probe.log" | tr '\n' ' ')"
    finish
fi
record PASS "a simulating key service boots with no TEE and serves"
printf '{"step":"ks-boot","ms":%d}\n' $(( ($(date +%s%N) - began) / 1000000 )) >> "$out/records.jsonl"
check "its VMM was asked for no TEE" sh -c "! pgrep -af '[q]emu-system.*guest=c8s-key-service-$run' | grep -q -e tdx-guest -e confidential-guest-support"
check "its launcher said that it runs in none" grep -q "this guest runs in no TEE" "$out/ks-probe.log"
expect 0 "the key service's machine is read from its evidence, under the simulated authority" ks-machine \
    "$SIM" session key-service launch-config machine --bundle "$out/ks-probe" --url "https://127.0.0.1:$ks_port" "${simulated[@]}"
ks_machine=$(tr -d '[:space:]' < "$out/ks-machine.out")
if ! [[ $ks_machine =~ ^[0-9a-f]{96}$ ]]; then
    record FAIL "the key service's machine is a register's value" "$ks_machine"
    finish
fi
# The same guest, as every verifier but the one given the directory sees it.
expect 2 "a release build refuses the simulated key service" ks-release \
    "$C8S" session key-service launch-config machine --bundle "$out/ks-probe" --url "https://127.0.0.1:$ks_port" "${accept[@]}"
expect 2 "so does the development build that is given no directory" ks-vendor-root \
    "$SIM" session key-service launch-config machine --bundle "$out/ks-probe" --url "https://127.0.0.1:$ks_port" "${accept[@]}"
stop_pid "$ks_pid"; ks_pid=""
expect 0 "a key service bundle that lists its machine" ks-bundle "$SIM" session key-service launch-config new --out "$out/ks" \
    --key "$out/ks-probe/launch.key" "${ks_pool[@]}" --machine "$ks_machine"
# A pin is written from the bundle, and judges nothing.
expect 0 "a pin of the key service" ks-pin "$SIM" session key-service pin --bundle "$out/ks" --url "https://127.0.0.1:$ks_port" --out "$pin"

# The pool's class: one guest under a document that lists no machine.
pool_doc=(--key "$out/pool.key" --key-service "$pin" --image-manifest "$manifest" --pool agents --class s-4x16)
[ -n "$ref" ] && pool_doc+=(--prestage "$ref")
probe_port=$((ks_port + 2))
expect 0 "a pool bundle that lists no machine" bundle-probe "$SIM" session launch-config new --out "$out/bundle-probe" "${pool_doc[@]}"
began=$(date +%s%N)
sudo -n "$SIM" "${launcher[@]}" "${simulated[@]}" --image-dir "$IMG" --launch-dir "$out/bundle-probe/opkeydata" --work-dir "$out/probe-vm" \
    --name "c8s-session-probe-$run" "${shape[@]}" --network user --port "127.0.0.1:$probe_port:8443" > "$out/probe.log" 2>&1 &
probe_pid=$!
if ! serving "$probe_pid" "$probe_port"; then
    record FAIL "a simulating session guest boots with no TEE and serves" "$(tail -c 600 "$out/probe.log" | tr '\n' ' ')"
    finish
fi
record PASS "a simulating session guest boots with no TEE and serves"
printf '{"step":"session-boot","ms":%d}\n' $(( ($(date +%s%N) - began) / 1000000 )) >> "$out/records.jsonl"
# The agent serves only where its kernel's log says the kernel zeroes every
# page it frees, as erasing the guest's one-time keys with their helper
# rests on that. A development guest's console has the agent's lines on both.
if [ "$dev" = 1 ]; then
    check "the guest's agent read from its kernel that the kernel zeroes the memory it frees" \
        grep -a -q -E '"msg":"the kernel zeroes the memory it frees","kernel":"mem auto-init: [^"]*heap free:on"' "$out/probe.log"
    check "the guest's agent holds its one-time keys in a key helper" grep -a -q 'the one-time keys are held by a key helper' "$out/probe.log"
fi
expect 0 "the class's machine is read from its evidence" machine "$SIM" session launch-config machine --url "https://127.0.0.1:$probe_port" \
    --image-manifest "$manifest" --launch-key "$out/pool.key.pub" "${simulated[@]}"
machine=$(tr -d '[:space:]' < "$out/machine.out")
if ! [[ $machine =~ ^[0-9a-f]{96}$ ]]; then
    record FAIL "the class's machine is a register's value" "$machine"
    finish
fi
check "two shapes are two machines" test "$machine" != "$ks_machine"
stop_pid "$probe_pid"; probe_pid=""

# What the guest's kernel takes of KVM's paravirtual features, as hardware.sh
# checks of a TD: the guest is launched once more under a VMM that offers
# every one, with every hint, and the host's own trace of that VMM says what
# the guest was answered and what it then reached for. A guest with a
# simulated TEE takes what a TD takes, so that the two differ by the
# hardware and by nothing their kernel takes from its host.
#
# The control of both checks follows it: a kernel that is not this image's,
# the host's own, booted under the same VMM with nothing to run, takes what
# it is offered, and the same trace shows the MSRs it reaches for. A trace
# that showed nothing there would show nothing of a guest either.
offered() {
    local dir vmm control_vmm="" trace=$out/offered.trace tracer launched calls others child
    local control=${C8S_CONTROL_KERNEL:-/boot/vmlinuz-$(uname -r)}
    dir=$(mktemp -d /tmp/c8s-offer.XXXXXX) || return 1
    chmod 755 "$dir"
    if ! cc -shared -fPIC -O2 -o "$dir/kvm-offer-all.so" "${C8S_KVM_OFFER:-$(dirname "$0")/kvmoffer/kvm-offer-all.c}" -ldl 2> "$out/offered-cc.err"; then
        record FAIL "a VMM that offers every paravirtual feature is built" "$(tail -c 300 "$out/offered-cc.err" | tr '\n' ' ')"
        rm -rf "${dir:?}"
        return 1
    fi
    printf '#!/bin/sh\nLD_PRELOAD=%s/kvm-offer-all.so exec %s "$@"\n' "$dir" "$(command -v qemu-system-x86_64)" > "$dir/qemu"
    chmod 755 "$dir/qemu" "$dir/kvm-offer-all.so"
    sudo -n bpftrace -e '
tracepoint:kvm:kvm_cpuid /args->function == 0x40000001/ { @leaf[pid, args->rax, args->rdx] = count(); }
tracepoint:kvm:kvm_msr /args->ecx >= 0x4b564d00 && args->ecx <= 0x4b564dff/ { @msr[pid, args->ecx] = count(); }
tracepoint:kvm:kvm_hypercall { @hypercall[pid, args->nr] = count(); }' > "$trace" 2> "$out/offered-trace.err" &
    tracer=$!
    for _ in $(seq 1 100); do
        grep -q Attach "$trace" "$out/offered-trace.err" 2>/dev/null && break
        kill -0 "$tracer" 2>/dev/null || break
        sleep 0.1
    done
    sudo -n "$SIM" "${launcher[@]}" "${simulated[@]}" --qemu "$dir/qemu" --image-dir "$IMG" --launch-dir "$out/bundle-probe/opkeydata" --work-dir "$out/offered-vm" \
        --name "c8s-session-offered-$run" "${shape[@]}" --network user --port "127.0.0.1:$probe_port:8443" > "$out/offered.log" 2>&1 &
    probe_pid=$!
    launched=0
    serving "$probe_pid" "$probe_port" && launched=1
    vmm=$(pgrep -f "[q]emu-system.*guest=c8s-session-offered-$run" | head -1)
    stop_pid "$probe_pid"; probe_pid=""
    # The control has no root to mount: its kernel takes what it takes, finds
    # nothing to run and stops, which ends its VMM.
    if sudo -n test -r "$control"; then
        sudo -n timeout 60 "$dir/qemu" -name "guest=c8s-offer-control-$run" -machine q35,accel=kvm -cpu host -smp 2 -m 512 \
            -display none -monitor none -serial "file:$out/offered-control.console" -no-reboot \
            -kernel "$control" -append "console=ttyS0 panic=-1" > "$out/offered-control.log" 2>&1 &
        child=$!
        for _ in $(seq 1 50); do
            control_vmm=$(pgrep -f "[q]emu-system.*guest=c8s-offer-control-$run" | head -1)
            [ -n "$control_vmm" ] && break
            sleep 0.1
        done
        wait "$child" 2>/dev/null
    fi
    for child in $(pgrep -P "$tracer"); do sudo -n kill -INT "$child" 2>/dev/null; done
    wait "$tracer" 2>/dev/null
    rm -rf "${dir:?}"
    if [ "$launched" != 1 ] || [ -z "$vmm" ]; then
        record FAIL "a guest whose host offers it every paravirtual feature serves" "$(tail -c 600 "$out/offered.log" | tr '\n' ' ')"
    else
        record PASS "a guest whose host offers it every paravirtual feature serves"
        # 4294967295 is every bit of a register.
        if grep -q "^@leaf\[$vmm, 4294967295, 4294967295\]" "$trace"; then
            record PASS "its host answered the feature leaf with every feature and every hint"
        else
            record FAIL "its host answered the feature leaf with every feature and every hint" "$(grep "^@leaf\[$vmm," "$trace" | tr '\n' ' ')"
        fi
        if grep -q "^@msr\[$vmm," "$trace"; then
            record FAIL "the guest reached for no paravirtual MSR" "$(grep "^@msr\[$vmm," "$trace" | tr '\n' ' ')"
        else
            record PASS "the guest reached for no paravirtual MSR"
        fi
        # KVM's numbers: 5 kicks a halted vCPU, 10 sends an IPI, 11 asks for a
        # vCPU to be run. A guest that boots sends IPIs to several vCPUs at
        # once, which is what the hypercall is for.
        calls=$(sed -n "s/^@hypercall\[$vmm, \([0-9]*\)\]: .*/\1/p" "$trace" | sort -n | tr '\n' ' ')
        others=$(for nr in $calls; do case "$nr" in 5|10|11) ;; *) printf '%s ' "$nr" ;; esac; done)
        if [ -z "$others" ] && [[ " $calls" == *" 10 "* ]]; then
            record PASS "it sent IPIs by its host's hypercall, and its other hypercalls kicked a vCPU or asked for one to be run" "numbers $calls"
        else
            record FAIL "it sent IPIs by its host's hypercall, and its other hypercalls kicked a vCPU or asked for one to be run" "numbers ${calls:-none}"
        fi
    fi
    if [ -z "$control_vmm" ] || ! grep -q "^@leaf\[$control_vmm, 4294967295, 4294967295\]" "$trace"; then
        record FAIL "the control, the host's own kernel as a guest, is offered every paravirtual feature" \
            "$control (C8S_CONTROL_KERNEL names another): $(grep "^@leaf\[${control_vmm:-none}," "$trace" | tr '\n' ' ') $(tail -c 300 "$out/offered-control.log" 2>/dev/null | tr '\n' ' ')"
        return 1
    fi
    record PASS "the control, the host's own kernel as a guest, is offered every paravirtual feature"
    if grep -q "^@msr\[$control_vmm," "$trace"; then
        record PASS "it takes them, and the host's trace shows the MSRs it reaches for" \
            "$(sed -n "s/^@msr\[$control_vmm, \([0-9]*\)\]: .*/\1/p" "$trace" | sort -n | while read -r msr; do printf '0x%x ' "$msr"; done)"
    else
        record FAIL "it takes them, and the host's trace shows the MSRs it reaches for" "none seen"
    fi
}
if [ "${C8S_SESSION_OFFERED:-1}" = 0 ]; then
    echo "== LEFT OUT: what a guest takes of the paravirtual features a host offers, and its control (C8S_SESSION_OFFERED=0)"
elif ! command -v bpftrace > /dev/null || ! command -v cc > /dev/null; then
    record FAIL "the host can offer a guest every paravirtual feature and trace what it takes" "it needs bpftrace and a C compiler: C8S_SESSION_OFFERED=0 leaves the check out"
else
    offered
fi
expect 0 "a pool bundle that lists its machine" bundle "$SIM" session launch-config new --out "$out/bundle" "${pool_doc[@]}" --machine "$machine"

# A launcher declares the registers of the files it boots, and of no others.
# The same image under a manifest that names another disk boots nothing.
mkdir -p "$out/image-other"
for file in "$IMG"/*; do
    [ "$(basename "$file")" = manifest.json ] || ln -sf "$file" "$out/image-other/"
done
python3 - "$manifest" "$out/image-other/manifest.json" <<'EOF'
import json, sys
m = json.load(open(sys.argv[1]))
m["outputs"]["disk_image"]["sha256"] = "ab" * 32
json.dump(m, open(sys.argv[2], "w"))
EOF
unknown "a launcher declares no registers for a disk its manifest does not name" launch-other 'the registers it names are another image' \
    sudo -n "$SIM" "${launcher[@]}" "${simulated[@]}" --image-dir "$out/image-other" --launch-dir "$out/bundle/opkeydata" --work-dir "$out/other-vm" \
    --name "c8s-session-other-$run" "${shape[@]}" --network user --port "127.0.0.1:$probe_port:8443"
check "and started no VMM for it" sh -c "! pgrep -f '[q]emu-system.*guest=c8s-session-other-$run' > /dev/null"

# Before anything else of this test runs beside them: a plain guest's kernel
# clears all of its memory as it boots, through its host's page faults, and
# takes many times as long on a host whose memory other guests hold.
if [ -n "$TDIMG" ]; then
    # Neither kind of guest runs as the other. A simulating image is launched
    # as a TD by a release launcher, and ends before it serves: its init
    # keeps no register beside the hardware's.
    td_launcher=()
    [ -S "$quote_socket" ] && td_launcher=(--quote-socket "$quote_socket")
    ends_unserved "a simulating image ends in a TD" sim-in-td "$probe_port" "$C8S" "${td_launcher[@]}" \
        --image-dir "$IMG" --launch-dir "$out/bundle/opkeydata" --work-dir "$out/sim-in-td-vm" --name "c8s-session-simtd-$run" "${shape[@]}"
    if [ "$dev" = 1 ]; then
        check "it said that a simulation build runs in no TEE" grep -a -q "a simulation build runs in none" "$out/sim-in-td.log"
    fi
    # An image built for a TD is launched with no TEE, and ends before it
    # serves: it has no register to bind its launch key in, and never falls
    # back to a simulation.
    expect 0 "a bundle for the TD's image" bundle-td "$SIM" session launch-config new --out "$out/bundle-td" --image-manifest "$TDIMG/manifest.json" \
        --pool agents --class s-4x16
    ends_unserved "a TD's image ends without a TEE" td-in-sim "$probe_port" "$SIM" "${simulated[@]}" \
        --image-dir "$TDIMG" --launch-dir "$out/bundle-td/opkeydata" --work-dir "$out/td-in-sim-vm" --name "c8s-session-tdsim-$run" "${shape[@]}"
    if [ "$dev" = 1 ]; then
        check "it said that it has no way to bind its launch key" grep -a -q "neither a writable RTMR\[3\] nor an SEV-SNP guest device" "$out/td-in-sim.log"
    fi
    # A TD of that image, and its evidence under both roots.
    sudo -n "$C8S" "${launcher[@]}" "${td_launcher[@]}" --image-dir "$TDIMG" --launch-dir "$out/bundle-td/opkeydata" --work-dir "$out/td-vm" \
        --name "c8s-session-td-$run" "${shape[@]}" --network user --port "127.0.0.1:$probe_port:8443" > "$out/td.log" 2>&1 &
    probe_pid=$!
    if serving "$probe_pid" "$probe_port"; then
        record PASS "a TD of the TD's image serves"
        td=(--url "https://127.0.0.1:$probe_port" --image-manifest "$TDIMG/manifest.json" --launch-key "$out/bundle-td/opkeydata/pubkey")
        expect 0 "a release build takes the TD's evidence" td-release "$C8S" session launch-config machine "${td[@]}" "${accept[@]}"
        expect 2 "a verifier under the simulated authority refuses it" td-simulated "$SIM" session launch-config machine "${td[@]}" "${simulated[@]}"
        expect 0 "the development build that is given no directory takes it as a release build does" td-vendor-root \
            "$SIM" session launch-config machine "${td[@]}" "${accept[@]}"
    else
        record FAIL "a TD of the TD's image serves" "$(tail -c 400 "$out/td.log" | tr '\n' ' ')"
    fi
    stop_pid "$probe_pid"; probe_pid=""
fi


# The key service, the tenant, and the daemon with its pool.
launch_ks "$out/ks" "$out/ks-vm" "$out/ks.log"
if ! serving "$ks_pid" "$ks_port"; then
    record FAIL "the key service serves under the document that lists its machine" "$(tail -c 600 "$out/ks.log" | tr '\n' ' ')"
    finish
fi
record PASS "the key service serves under the document that lists its machine"
printf 'simulated-secret-%s' "$run" > "$out/stored"
tenant=(--key-service "$pin" --tenant acme --authority-key "$out/authority.key")
expect 0 "the tenant registers" register "$SIM" session key-service tenant register "${tenant[@]}" "${simulated[@]}"
expect 0 "and stores a credential" put "$SIM" session key-service credential put api-token "${tenant[@]}" "${simulated[@]}" --from-file "$out/stored"
expect 2 "a release build sends that key service nothing" register-release "$C8S" session key-service tenant register "${tenant[@]}" "${accept[@]}"
{
    echo "listen: 127.0.0.1:$port"
    echo "host: test-host"
    echo "stateDir: $out/state"
    echo "capacity: 3"
    echo "tls: {cert: $pki/server.pem, key: $pki/server.key, clientCA: $pki/ca.pem}"
    echo "network: {mode: tap, guestCIDR: $cidr}"
    echo "vmm:"
    echo "  simulatedTEE: $tee"
    [ -n "$confine" ] && echo "  confine: \"$confine\""
    [ "$dev" = 1 ] && echo "  console: true"
    echo "classes:"
    echo "  s-4x16: {vcpus: 4, memory: 16G, lowMemory: 512M, scratch: 4G}"
    echo "pools:"
    echo "  - imageDir: $IMG"
    echo "    launchDir: $out/bundle/opkeydata"
    echo "    depth: 2"
    [ -n "$store" ] && echo "    imageStore: $store"
} > "$out/config.yaml"
began=$(date +%s%N)
sudo -n "$SIM" session-daemon run --config "$out/config.yaml" >> "$out/daemon.log" 2>&1 &
daemon_pid=$!
ok=0
deadline=$(( $(date +%s) + 300 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    [ "$(grep -c '"msg":"a TD is ready"' "$out/daemon.log" 2>/dev/null)" -ge 2 ] && { ok=1; break; }
    kill -0 "$daemon_pid" 2>/dev/null || break
    sleep 0.2
done
if [ "$ok" != 1 ]; then
    record FAIL "the pool is filled with guests that have no TEE" "$(tail -c 500 "$out/daemon.log" | tr '\n' ' ')"
    finish
fi
record PASS "the pool is filled with guests that have no TEE"
printf '{"step":"pool-fill","tds":2,"ms":%d}\n' $(( ($(date +%s%N) - began) / 1000000 )) >> "$out/records.jsonl"
grep -o '"boot_ms":[0-9]*' "$out/daemon.log" | sed 's/"boot_ms":\([0-9]*\)/{"step":"guest-boot","ms":\1}/' >> "$out/records.jsonl"
check "no VMM of the pool was asked for a TEE" sh -c "! pgrep -af '[q]emu-system.*guest=td-' | grep -q -e tdx-guest -e confidential-guest-support"

# A session, as on a TD: claimed, bound, handed the stored credential by the
# key service, and verified from a fresh quote.
orchestrator=(--daemon "127.0.0.1:$port" --daemon-ca "$pki/ca.pem" --daemon-cert "$pki/orchestrator.pem" --daemon-key "$pki/orchestrator.key")
asked=(--pool agents --wait 120s --image-manifest "$manifest" --launch-key "$out/bundle/opkeydata/pubkey" --authority-key "$out/authority.key"
    --tenant acme --key-service "$pin" --stored-credential api-token:256)
session=("${asked[@]}" "${sandbox[@]}")
expect 0 "a session starts in a guest with no TEE, under the simulated authority" start \
    "$SIM" session start "${orchestrator[@]}" "${session[@]}" --session s1 --out "$out/s1" -o json "${simulated[@]}"
s1=(--binding "$out/s1" --image-manifest "$manifest" "${simulated[@]}")
expect 0 "its command reads the credential the key service released" exec "$SIM" session exec "${s1[@]}" -- \
    sh -c 'cat "$C8S_CREDENTIALS_DIR/api-token"'
check "and it is the one the tenant stored" [ "$(cat "$out/exec.out")" = "simulated-secret-$run" ]
expect 0 "the session is verified from a fresh quote" verify "$SIM" session verify "${s1[@]}" --fresh -o json
check "and the verdict says first that it proves nothing about the guest's hardware" python3 -c 'import json, sys
gaps = json.load(open(sys.argv[1])).get("not_proven") or [""]
sys.exit(0 if "TEE is simulated" in gaps[0] else 1)' "$out/verify.out"
expect 0 "and with documents from the authority's service alone" verify-own "$SIM" session verify "${s1[@]}" --fresh --own-collateral-only --collateral-cache "$out/cache-own"
check "which are kept apart from the vendor's" sh -c "ls '$out/cache-own' | grep -q '^simulated-' && [ \"\$(ls '$out/cache-own' | wc -l)\" = 1 ]"

# The same session, as every other verifier sees it.
expect 2 "a release build refuses the session" verify-release "$C8S" session verify --binding "$out/s1" --image-manifest "$manifest" --fresh "${accept[@]}"
expect 2 "so does the development build that is given no directory" verify-vendor-root "$SIM" session verify --binding "$out/s1" --image-manifest "$manifest" --fresh "${accept[@]}"
expect 2 "a release build starts no session in a guest with no TEE" start-release \
    "$C8S" session start "${orchestrator[@]}" "${session[@]}" --session s2 --out "$out/s2" -o json "${accept[@]}"
other=$out/authority-other
expect 0 "a second simulated authority" simtee-other "$SIM" session simtee new --out "$other"
other_vendor_pid=$(serve "$other" vendor-other)
check "whose documents are served too" test -n "$other_vendor_pid"
expect 2 "a verifier under another simulated authority refuses the session" verify-other \
    "$SIM" session verify --binding "$out/s1" --image-manifest "$manifest" --fresh --simulated-tee "$other" --collateral-cache "$out/cache-other"
expect 0 "the session's own verifier still takes it" verify-again "$SIM" session verify "${s1[@]}" --fresh

expect 0 "the session ends" destroy "$SIM" session destroy --binding "$out/s1" --daemon-cert "$pki/orchestrator.pem" --daemon-key "$pki/orchestrator.key"

# A session whose policy names its image's command as its own process ends
# when that process does. Its guest ends itself and tells its launcher why as
# it goes, which needs no TEE, and powers off once the launcher has kept the
# word: the daemon gives that word as the reason, and nothing of what the
# process exited with. Three guests in a row: a word that only sometimes
# arrives is one a guest took with it.
if [ -n "$ref_ends" ]; then
    said_why() { # said_why <count> <word>: so many guests ended with that word of their own
        local deadline=$(( $(date +%s) + 60 ))
        until [ "$(grep '"msg":"a TD ended"' "$out/daemon.log" 2>/dev/null | grep -c "\"reason\":\"the guest ended: $2\"")" -ge "$1" ]; do
            [ "$(date +%s)" -lt "$deadline" ] || return 1
            sleep 0.2
        done
    }
    for i in 1 2 3; do
        expect 0 "session e$i starts, whose own process is its image's command" "start-e$i" \
            "$SIM" session start "${orchestrator[@]}" "${asked[@]}" --sandbox-image "$ref_ends" --sandbox-process image \
            --session "e$i" --out "$out/e$i" -o json "${simulated[@]}"
        expect 0 "a command has e$i's process end" "end-e$i" "$SIM" session exec --binding "$out/e$i" --image-manifest "$manifest" "${simulated[@]}" -- sh -c ': > /tmp/end'
        check "e$i's guest ended itself and said that its session's process had ended" said_why "$i" "process_ended in phase running"
    done
    check "and none said anything of what its process exited with" sh -c "! grep '\"msg\":\"a TD ended\"' '$out/daemon.log' | grep -q 'status 3'"
fi
# Whoever served the documents takes its address with it.
kill "$vendor_pid" 2>/dev/null
deadline=$(( $(date +%s) + 20 ))
while kill -0 "$vendor_pid" 2>/dev/null && [ "$(date +%s)" -lt "$deadline" ]; do sleep 0.1; done
vendor_pid=""
check "the authority's address is gone with whoever served it" test ! -e "$tee/vendor"
finish
