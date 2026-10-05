#!/usr/bin/env bash
# A burst of session starts, timed on one host (docs/session-performance.md):
# a key service in a TD, a session daemon with one pool of ready TDs, and an
# orchestrator that starts a burst of sessions at the same instant, each with
# a bind that claims its TD and carries a credential and the session's first
# command sealed for the guest. A session's time runs from its own start to
# its first command's answer, and one with no answer two minutes after its
# burst began has failed. test/session/warmstart is that orchestrator.
#
# Beside it stock Firecracker starts as many sessions at the same instant, in
# two ways, each to the same first command, run inside the same image.
# test/session/fcburst drives both. Their guest is the leanest Firecracker
# boots: the agent as init on the image's own tree, which it has read whole,
# as each pooled TD has the image unpacked before a bind. In one way, each
# start loads one snapshot of that guest into a VMM of its own, Firecracker's
# fastest start of a guest that does not run yet. In the other, each start
# takes a guest from a pool booted ahead, as a platform with confidentiality
# off can keep one and as sessions keep TDs: idle, with a connection to its
# agent made. Either start is one message to the agent, with a credential
# and the first command. The guest is the sandbox there, where a TD starts
# one inside its bind.
#
# The three sides take turns burst by burst, in an order that rotates. A
# side's guests are there for its own turn alone: a host's memory does not
# hold a pool of each at a session's full size. So a TD turn starts the
# daemon, lets its pool fill while the orchestrator judges each TD as it
# comes ready, rests, bursts, and ends the daemon with every TD; and
# Firecracker's pool is booted in its turn, rests as long, and is stopped
# after its burst. The TDs with their daemon, Firecracker's VMMs, the key
# service and the programs that start the bursts keep to CPUs of their own.
# The document's second baseline sits out: its guests hold all of their
# memory from boot, and a pool of them does not fit.
#
# Records go to <work>/timing.jsonl, one JSON object a line, and what the
# host was to <work>/env.txt, whose first line says which rules of the
# document's method the run kept.
#
#   C8S_BIN                  the c8s binary (default: build/c8s)
#   C8S_WARMSTART            the warmstart binary (go build ./test/session/warmstart)
#   C8S_SESSION_IMAGE        session image directory (required)
#   C8S_KEY_SERVICE_IMAGE    key service image directory (required)
#   C8S_SANDBOX_STORE        a directory with images.store, an image store
#                            ('c8s session image-store write'), and ref, the
#                            image of it the sessions run, as
#                            name@sha256:<digest> (required)
#   C8S_SESSION_WORK         directory for this run's files (default: a new
#                            temporary directory, kept)
#   C8S_BURST_SESSIONS       sessions a burst starts at once (default 100)
#   C8S_BURST_POOL           ready TDs the pool keeps (default: as many as a
#                            burst starts). With fewer, the rest of a burst
#                            start as the pool's next TDs boot, two at a
#                            time, and their times say so
#   C8S_BURST_ROUNDS         bursts a side (default 4: the first finds every
#                            cache cold and is left out of a summary)
#   C8S_BURST_WATCH          a command line run beside each TD burst, begun
#                            two seconds before the burst is let go, with
#                            the burst's number as its last word: a profiler,
#                            for a trial. A run that has one says so
#   C8S_BURST_LEAVE_FAILED=1 for a trial: leave the TD of a session whose
#                            start failed running until the burst's logs are
#                            kept, and say then whether its guest answers
#   C8S_BURST_KEEP           for a trial: seconds to leave every session of a
#                            TD burst running after the burst, and say then
#                            how each TD of it ended
#   C8S_BURST_SIDES          the sides that take turns, of td, load and pool
#                            (default "td load pool"): fewer for a trial
#   C8S_BURST_COMMAND        each session's first command (default "node -v")
#   C8S_BURST_TD_MIB         host memory a pooled TD is taken to need before
#                            its pool is started (default 1024), and
#   C8S_BURST_RESERVE_MIB    what the pool must leave of the host's available
#                            memory (default 8192): a pool that would not is
#                            not started, and the run says how many fit
#   C8S_TIMING_REST          seconds of rest before each burst (default 5)
#   C8S_TIMING_PIN_POWER=1   for the run, set every CPU's governor to
#                            performance, turn off idle states deeper than
#                            C1E and turn turbo on, and set KVM's halt
#                            polling to none (see the next); all are put
#                            back when the run ends
#   C8S_TIMING_HALT_POLL_NS  for the run, how long KVM lets a halted vCPU
#                            spin for a wakeup before it gives up its CPU
#                            (the host's halt_poll_ns, for every VM on it);
#                            put back when the run ends. Unset, a run that
#                            pins the power sets 0 and any other takes the
#                            host's as it is. Either way the record names it
#   C8S_BURST_CPUS           four CPU lists, as taskset takes them, separated
#                            by spaces: the TDs' with their daemon,
#                            Firecracker's VMMs, the key service's, and the
#                            programs' that start the bursts. Without it the
#                            TDs and Firecracker's VMMs, which are never
#                            there together, both get the host's cores from
#                            the third on but four, the key service the
#                            next and the programs the last three, each core
#                            with its sibling threads (it needs 24 cores for
#                            that)
#   C8S_FIRECRACKER          directory written by firecracker-setup.sh (required)
#   C8S_FIRECRACKER_SAMPLE   the sampling program (default: beside this script)
#   C8S_FIRECRACKER_AGENT    the baseline's guest agent, built for the guest
#                            (CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build
#                            ./test/session/fcagent) (required)
#   C8S_FIRECRACKER_BURST    the fcburst binary (go build ./test/session/fcburst) (required)
#   C8S_IMAGEROOT            the imageroot binary (go build ./test/session/imageroot) (required)
#   C8S_VMM_STAT             the program that says what a side's VMMs have
#                            cost their host (default: vmm_stat.py beside
#                            this script). It is taken before each burst and
#                            when the burst's last command has answered
#   C8S_SESSION_DEV=1        the images are dev builds: attach their consoles,
#                            so that each guest's log is in its launcher's
#   C8S_QUOTE_SOCKET, C8S_SESSION_CONFINE, C8S_ACCEPT_TCB, C8S_SESSION_PORT,
#   C8S_KEY_SERVICE_PORT     as for hardware.sh
#   C8S_SESSION_CIDR         the guests' block (default 10.213.0.0/22: four
#                            addresses a TD)
#
# The logs of what runs under sudo are this user's files, written by this
# shell.
# shellcheck disable=SC2024
set -uo pipefail

C8S=${C8S_BIN:-build/c8s}
WARM=${C8S_WARMSTART:?set C8S_WARMSTART to the warmstart binary}
IMG=${C8S_SESSION_IMAGE:?set C8S_SESSION_IMAGE to a session image directory}
KSIMG=${C8S_KEY_SERVICE_IMAGE:?set C8S_KEY_SERVICE_IMAGE to a key service image directory}
store_dir=${C8S_SANDBOX_STORE:?set C8S_SANDBOX_STORE to a directory with images.store and ref}
fc=${C8S_FIRECRACKER:?set C8S_FIRECRACKER to a directory written by firecracker-setup.sh}
fc_sample=${C8S_FIRECRACKER_SAMPLE:-$(dirname "$(readlink -f "$0")")/firecracker_sample.py}
fc_agent=${C8S_FIRECRACKER_AGENT:?set C8S_FIRECRACKER_AGENT to the fcagent binary}
fc_burst=${C8S_FIRECRACKER_BURST:?set C8S_FIRECRACKER_BURST to the fcburst binary}
imageroot=${C8S_IMAGEROOT:?set C8S_IMAGEROOT to the imageroot binary}
vmm_stat=${C8S_VMM_STAT:-$(dirname "$(readlink -f "$0")")/vmm_stat.py}
sessions=${C8S_BURST_SESSIONS:-100}
depth=${C8S_BURST_POOL:-$sessions}
rounds=${C8S_BURST_ROUNDS:-4}
first_command=${C8S_BURST_COMMAND:-node -v}
rest=${C8S_TIMING_REST:-5}
# The bytes of the credential warmstart seals with each bind.
credential_bytes=48
# What a pool is taken to need of the host's memory before it is started:
# so much a TD, and so much left for whatever else the host runs.
td_mib=${C8S_BURST_TD_MIB:-1024}
reserve_mib=${C8S_BURST_RESERVE_MIB:-8192}
pin_power=${C8S_TIMING_PIN_POWER:-0}
halt_poll=${C8S_TIMING_HALT_POLL_NS:-}
# A run that pins the power settings pins halt polling with them, at none.
[ "$pin_power" = 1 ] && halt_poll=${halt_poll:-0}
halt_poll_file=/sys/module/kvm/parameters/halt_poll_ns
case "$halt_poll" in *[!0-9]*) echo "C8S_TIMING_HALT_POLL_NS is a number of nanoseconds" >&2; exit 2 ;; esac
dev=${C8S_SESSION_DEV:-0}
quote_socket=${C8S_QUOTE_SOCKET:-/var/run/tdx-qgs/qgs.socket}
confine=${C8S_SESSION_CONFINE:-}
accept=()
[ -n "${C8S_ACCEPT_TCB:-}" ] && accept=(--accept-tcb-status "$C8S_ACCEPT_TCB")
port=${C8S_SESSION_PORT:-7443}
ks_port=${C8S_KEY_SERVICE_PORT:-18543}
cidr=${C8S_SESSION_CIDR:-10.213.0.0/22}
if [ "$depth" -lt 1 ] || [ "$depth" -gt "$sessions" ]; then echo "C8S_BURST_POOL is between 1 and C8S_BURST_SESSIONS" >&2; exit 2; fi

program() { # program <path>: the program there, or nothing
    local path
    path=$(command -v "$1" || true)
    [ -n "$path" ] && [ -x "$path" ] && readlink -f "$path"
}
C8S=$(program "$C8S") || { echo "no c8s binary: set C8S_BIN" >&2; exit 2; }
WARM=$(program "$WARM") || { echo "C8S_WARMSTART is no program" >&2; exit 2; }
fc_burst=$(program "$fc_burst") || { echo "C8S_FIRECRACKER_BURST is no program" >&2; exit 2; }
imageroot=$(program "$imageroot") || { echo "C8S_IMAGEROOT is no program" >&2; exit 2; }
[ -f "$IMG/manifest.json" ] && [ -f "$KSIMG/manifest.json" ] || { echo "an image directory holds no manifest.json" >&2; exit 2; }
if [ -f "$IMG/SIMULATED-TEE" ] || [ -f "$KSIMG/SIMULATED-TEE" ]; then echo "an image built with C8S_SIMTEE=1 runs in no TD" >&2; exit 2; fi
sudo -n true 2>/dev/null || { echo "this run needs passwordless sudo" >&2; exit 2; }
[ "$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null)" = Y ] || { echo "this host's KVM runs no TD (kvm_intel.tdx is not Y)" >&2; exit 2; }
ref=$(cat "$store_dir/ref") store=$store_dir/images.store
[ -n "$ref" ] && [ -f "$store" ] || { echo "$store_dir holds no images.store and ref" >&2; exit 2; }
[ -x "$fc/firecracker" ] && [ -f "$fc_sample" ] && [ -f "$fc_agent" ] || { echo "$fc holds no firecracker, or $fc_sample or $fc_agent is missing" >&2; exit 2; }
[ -f "$vmm_stat" ] || { echo "C8S_VMM_STAT=$vmm_stat is not a file" >&2; exit 2; }
command -v mksquashfs > /dev/null || { echo "the baseline's drive needs mksquashfs (squashfs-tools)" >&2; exit 2; }
fc=$(readlink -f "$fc")
if sudo -n nft list table inet c8s_sessions > /dev/null 2>&1; then
    echo "the packet filter holds a table inet c8s_sessions: a session daemon runs here, or one left it behind" >&2
    exit 2
fi

# Where each part of the run keeps to: the TDs with their daemon,
# Firecracker's VMMs, the key service, and the programs that start the
# bursts. The two sides' guests are never there together, and by default
# keep to the same CPUs.
if [ -n "${C8S_BURST_CPUS:-}" ]; then
    read -r cpus_td cpus_fc cpus_ks cpus_drive <<< "$C8S_BURST_CPUS"
    [ -n "${cpus_drive:-}" ] || { echo "C8S_BURST_CPUS is four CPU lists: the TDs', Firecracker's, the key service's, the drivers'" >&2; exit 2; }
else
    # By cores, each with its sibling threads: the first two are left to the
    # host, the last three drive, the one before them is the key service's,
    # and the guests of whichever side has its turn get the rest.
    read -r cpus_td cpus_fc cpus_ks cpus_drive < <(python3 -c '
import glob
cores = sorted({open(p).read().strip() for p in glob.glob("/sys/devices/system/cpu/cpu[0-9]*/topology/core_cpus_list")},
               key=lambda c: int(c.replace("-", ",").split(",")[0]))
cut = lambda a, b: ",".join(cores[a:b])
n = len(cores)
print(cut(2, n - 4), cut(2, n - 4), cut(n - 4, n - 3), cut(n - 3, n) if n >= 24 else "")')
    [ -n "${cpus_drive:-}" ] || { echo "this host has fewer than 24 cores: name the CPUs each part keeps to with C8S_BURST_CPUS" >&2; exit 2; }
fi
# on <CPU list> <command...>: the command in this shell's place, on those
# CPUs. It is called in the background or in a subshell: the process it
# leaves is the command's own, which a signal then reaches.
on() {
    local cpus=$1
    shift
    exec taskset -c "$cpus" "$@"
}

# tdx_keys: how many TDX key IDs the host has in use, one a TD, and
# tdx_capacity: how many it has, which bounds the TDs it holds at once
# whatever its memory. A TD's is freed when the host has taken the TD apart,
# which is after its VMM is gone.
tdx_count() { # tdx_count <file of the root cgroup's misc controller>
    awk '$1 == "tdx" { print $2; found = 1 } END { exit !found }' "/sys/fs/cgroup/$1" 2>/dev/null
}
tdx_keys() { tdx_count misc.current; }
tdx_capacity() { tdx_count misc.capacity; }
available_mib() { awk '/^MemAvailable:/ { print int($2 / 1024) }' /proc/meminfo; }
# pinned_mib: the host's unevictable memory, the gauge of its TDs' private
# pages, which it can neither move out nor drop. What else runs on a host
# moves its available memory by more than a TD's worth.
pinned_mib() { awk '/^Unevictable:/ { print int($2 / 1024) }' /proc/meminfo; }

# What else the host runs, before anything of this run does: the CPU time its
# programs took over five seconds, as a share of one CPU, in all and by
# program for the busiest.
busiest=$(python3 - <<'BUSY'
import collections, os, time
def ticks():
    seen = {}
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/stat") as f:
                name, fields = f.read().rsplit(")", 1)
        except OSError:
            continue
        fields = fields.split()
        # After the name: state, parent, ..., user and system time as the
        # 12th and 13th, and the start time, which tells a reused id, as
        # the 20th.
        seen[(pid, fields[19])] = (name.split("(", 1)[1], int(fields[11]) + int(fields[12]))
    return seen
before, began = ticks(), time.monotonic()
time.sleep(5)
after, took = ticks(), time.monotonic() - began
spent = collections.Counter()
for key, (name, now) in after.items():
    if key[0] != str(os.getpid()):
        spent[name] += now - before.get(key, (name, 0))[1]
share = lambda n: n * 100 / os.sysconf("SC_CLK_TCK") / took
print(f"{share(sum(spent.values())):.0f}")
for name, n in spent.most_common(12):
    if n:
        print(f"  {share(n):5.1f} {name}")
BUSY
)
busy=${busiest%%$'\n'*}
busiest=${busiest#*$'\n'}

out=${C8S_SESSION_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/c8s-session-burst.XXXXXX")}
mkdir -p "$out/pki" || exit 2
[ ! -e "$out/timing.jsonl" ] || { echo "$out holds an earlier run" >&2; exit 2; }
out=$(readlink -f "$out")
run=$(basename "$out")
echo "records in $out"
quiet() { "$@" > /dev/null 2>> "$out/setup.err"; }
die() { echo "FAILED: $*" >&2; tail -c 400 "$out/setup.err" >&2 2>/dev/null; exit 1; }

launcher=(session-launcher run --platform tdx --vsock-cid auto)
[ -S "$quote_socket" ] && launcher+=(--quote-socket "$quote_socket")
[ -n "$confine" ] && launcher+=(--confine "$confine")
[ "$dev" = 1 ] && launcher+=(--console)

# Where this host's frequency driver takes turbo, and what turns it on there.
turbo_file="" turbo_on=""
if [ -e /sys/devices/system/cpu/intel_pstate/no_turbo ]; then
    turbo_file=/sys/devices/system/cpu/intel_pstate/no_turbo turbo_on=0
elif [ -e /sys/devices/system/cpu/cpufreq/boost ]; then
    turbo_file=/sys/devices/system/cpu/cpufreq/boost turbo_on=1
fi
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

ks_pid="" daemon_pid="" probe_pid="" warm_pid="" governor="" turbo="" idle_off=() halt_poll_was=""
stop_pid() { # stop_pid <pid>
    [ -n "$1" ] || return 0
    sudo -n kill -TERM "$1" 2>/dev/null
    wait "$1" 2>/dev/null
}
restore_power() {
    if [ -n "$halt_poll_was" ]; then
        echo "$halt_poll_was" | sudo -n tee "$halt_poll_file" > /dev/null
        halt_poll_was=""
    fi
    [ -n "$governor" ] || return 0
    echo "$governor" | sudo -n tee /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor > /dev/null
    for state in "${idle_off[@]}"; do echo 0 | sudo -n tee "$state" > /dev/null; done
    [ -n "$turbo" ] && echo "$turbo" | sudo -n tee "$turbo_file" > /dev/null
    governor="" turbo=""
}
# shellcheck disable=SC2329 # the trap below runs it
cleanup() {
    [ -n "$warm_pid" ] && kill "$warm_pid" 2>/dev/null
    stop_pid "$daemon_pid"; daemon_pid=""
    [ -f "$out/config.yaml" ] && sudo -n "$C8S" session-daemon drain --config "$out/config.yaml" --wait 5m >> "$out/drain.out" 2>> "$out/daemon.log"
    sudo -n nft delete table inet c8s_sessions 2>/dev/null
    stop_pid "$probe_pid"; probe_pid=""
    stop_pid "$ks_pid"; ks_pid=""
    # A burst that was cut short leaves its VMMs.
    sudo -n pkill -TERM -f "^$fc/firecracker (--api-sock fc.sock|--no-api --config-file $fc/lean-vm.json)" 2>/dev/null
    restore_power
}
trap cleanup EXIT

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
    on "$cpus_ks" sudo -n "$C8S" "${launcher[@]}" --image-dir "$KSIMG" --launch-dir "$1/opkeydata" --work-dir "$2" \
        --name "c8s-key-service-$run" "${ks_shape[@]}" --network none --port "127.0.0.1:$ks_port:8443" > "$3" 2>&1 &
    ks_pid=$!
}

# key_digest <certificate>: its public key as a pool's configuration names it.
key_digest() {
    echo "sha256:$(openssl x509 -in "$1" -noout -pubkey 2>> "$out/setup.err" | openssl pkey -pubin -outform DER 2>> "$out/setup.err" | sha256sum | cut -c1-64)"
}
binder=$(key_digest "$pki/orchestrator.pem")
[ ${#binder} = 71 ] || die "the digest of a public key"

# The key service and the daemon with its pool. Two machines are read from
# evidence first, as in hardware.sh: the key service's and the class's, each
# from one guest under a document that lists none.
manifest=$IMG/manifest.json pin=$out/ks-pin.json probe_port=$((ks_port + 2))
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
quiet "$C8S" session launch-config new --out "$out/bundle-probe" "${pool_doc[@]}" || die "the pool's first bundle"
on "$cpus_td" sudo -n "$C8S" "${launcher[@]}" --image-dir "$IMG" --launch-dir "$out/bundle-probe/opkeydata" --work-dir "$out/probe-vm" \
    --name "c8s-session-probe-$run" "${shape[@]}" --network user --port "127.0.0.1:$probe_port:8443" > "$out/probe.log" 2>&1 &
probe_pid=$!
serving "$probe_pid" "$probe_port" || die "the pool's probe never served"
machine=$("$C8S" session launch-config machine --url "https://127.0.0.1:$probe_port" --image-manifest "$manifest" \
    --launch-key "$out/pool.key.pub" "${accept[@]}" 2>> "$out/setup.err") || die "the class's machine"
stop_pid "$probe_pid"; probe_pid=""
quiet "$C8S" session launch-config new --out "$out/bundle" "${pool_doc[@]}" --machine "$machine" || die "the pool's bundle"

launch_ks "$out/ks" "$out/ks-vm" "$out/ks.log"
serving "$ks_pid" "$ks_port" || die "the key service never served"
tenant=(--key-service "$pin" --tenant acme --authority-key "$out/authority.key")
quiet "$C8S" session key-service tenant register "${tenant[@]}" "${accept[@]}" || die "the tenant's registration"

# The baseline's guest, before the pool takes the host's memory: the image's
# tree as a session's guest unpacks it, as the root of a guest whose init is
# the agent, with a start that brings a credential of the size a session's
# bind does, and that guest's snapshot.
records=$out/timing.jsonl
sudo -n rm -rf "${fc:?}/image" "${fc:?}/image.env" "${fc:?}/busybox"
install -m 0755 "$fc_agent" "$fc/fcagent"
sudo -n "$imageroot" -store "$store" -image "$ref" -out "$fc/image" > "$out/image.env" 2>> "$out/setup.err" || die "the image's tree for the baseline"
sudo -n install -m 0644 "$out/image.env" "$fc/image.env"
# shellcheck disable=SC2086
(on "$cpus_fc" sudo -n python3 "$fc_sample" "$fc" lean "$credential_bytes" $first_command) >> "$records" || die "the lean Firecracker guest"
(on "$cpus_fc" sudo -n python3 "$fc_sample" "$fc" lean-snapshot) >> "$records" || die "the Firecracker snapshot"

{
    echo "listen: 127.0.0.1:$port"
    echo "host: test-host"
    echo "stateDir: $out/state"
    echo "capacity: $depth"
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
    echo "    depth: $depth"
    echo "    imageStore: $store"
    # The orchestrator binds its sessions itself, and watches the pool.
    echo "    binders:"
    echo "      - \"$binder\""
} > "$out/config.yaml"

# The key IDs in use before any TD of a pool, the key service's and those of
# whatever else the host runs in TDs, and how many the host has.
keys_before=$(tdx_keys) || die "this host does not count the TDX key IDs it has in use (the misc controller of its root cgroup)"
keys_all=$(tdx_capacity) || die "this host does not say how many TDX key IDs it has"
[ $(( keys_all - keys_before )) -ge "$depth" ] \
    || die "the host has $keys_all TDX key IDs with $keys_before in use: a pool of $depth TDs cannot stand on it, whatever its memory"

# The daemon runs for a TD turn and no longer. came is how many TDs its log
# says came ready before this start, and filled how long the pool took.
came=0 filled=0 daemon_began=0
start_daemon() {
    came=$(grep -c '"msg":"a TD is ready"' "$out/daemon.log" 2>/dev/null)
    came=${came:-0} daemon_began=$(date +%s)
    # Its launchers and their VMMs inherit where the daemon keeps to.
    on "$cpus_td" sudo -n "$C8S" session-daemon run --config "$out/config.yaml" >> "$out/daemon.log" 2>&1 &
    daemon_pid=$!
}
# pool_full: the pool is full and no TD boots.
pool_full() {
    local deadline
    deadline=$(( $(date +%s) + 3600 ))
    while :; do
        kill -0 "$daemon_pid" 2>/dev/null || die "the daemon ended"
        if [ "$(grep -c '"msg":"a TD is ready"' "$out/daemon.log" 2>/dev/null)" -ge $(( came + depth )) ] \
            && [ "$(pgrep -cf '[q]emu-system.*guest=td-')" = "$depth" ]; then
            filled=$(( $(date +%s) - daemon_began ))
            return 0
        fi
        [ "$(date +%s)" -lt "$deadline" ] || die "the pool never filled: $(( $(grep -c '"msg":"a TD is ready"' "$out/daemon.log") - came )) TDs came ready of $depth, and $(pgrep -cf '[q]emu-system.*guest=td-') VMMs run"
        sleep 0.5
    done
}
# stop_daemon <n>: the daemon is gone, and every TD with it, taken apart by
# the host, their key IDs free again and their memory given back: what runs
# next is not held up by that work. pinned_before is what the host held
# pinned before the pool, and free_before what it had available.
stop_daemon() {
    local deadline gone keys_back
    stop_pid "$daemon_pid"; daemon_pid=""
    sudo -n "$C8S" session-daemon drain --config "$out/config.yaml" --wait 10m >> "$out/drain.out" 2>> "$out/daemon.log" || die "the TDs did not end"
    sudo -n nft delete table inet c8s_sessions 2>/dev/null
    deadline=$(( $(date +%s) + 600 ))
    while [ "$(pgrep -cf '[q]emu-system.*guest=td-')" != 0 ] || [ -n "$(pgrep -f "session-launcher run.*--work-dir $out/state/")" ]; do
        [ "$(date +%s)" -lt "$deadline" ] || die "TDs outlived their daemon"
        sleep 0.5
    done
    gone=$(date +%s.%N)
    while [ "$(tdx_keys)" -gt "$keys_before" ]; do
        [ "$(date +%s)" -lt "$deadline" ] || die "the host still holds $(( $(tdx_keys) - keys_before )) key IDs of TDs that are gone"
        sleep 0.1
    done
    keys_back=$(date +%s.%N)
    # Their memory is back when the host holds pinned what it did before
    # the pool, within a sixteenth of one TD's share.
    while [ "$(pinned_mib)" -gt $(( pinned_before + td_mib / 16 )) ]; do
        [ "$(date +%s)" -lt "$deadline" ] || die "the host holds $(pinned_mib) MiB unevictable after the pool's end, and held $pinned_before before it"
        sleep 0.1
    done
    echo "burst $1: after the last of its TDs' VMMs was gone, the host had their key IDs free again in $(since "$gone" "$keys_back") s and their memory back in $(since "$gone" "$(date +%s.%N)") s ($(pinned_mib) MiB unevictable and $(available_mib) available, $pinned_before and $free_before before the pool)" >> "$out/env.txt"
}
since() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.1f", b - a }'; }
# cold <n>: how long each TD of burst n took from its launch to ready, in
# parts as timing.sh tells them, from the logs the daemon is about to drop.
cold() {
    sudo -n python3 - "$out" "$came" "$1" <<'COLD' >> "$records"
import datetime, json, os, re, sys
d, skip, burst = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
def at(entry):
    # A log's stamp has more digits than a datetime reads.
    stamp = re.sub(r"(\.\d{6})\d+", r"\1", entry["time"]).replace("Z", "+00:00")
    return datetime.datetime.fromisoformat(stamp).timestamp()
# What a guest with a console says of its own bind, of the quote it took
# beside it, of the bind's whole call with what followed its answer, and of
# its first second after it was prepared.
guest_said = {"a bind was served": "guest-bind", "took the quote over the bind's nonce": "guest-quote", "a bind's call ended": "guest-call",
              "a guest's first second prepared": "guest-prepared"}
def entries(path):
    try:
        with open(path, errors="replace") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if isinstance(entry, dict) and "msg" in entry and "time" in entry:
                    yield entry
    except OSError:
        return
came = [e for e in entries(os.path.join(d, "daemon.log")) if e["msg"] == "a TD is ready"][skip:]
for ready in came:
    record = {"kind": "session-cold", "round": burst, "td": ready.get("td"), "boot_ms": ready["boot_ms"]}
    started = asked = None
    said = []
    for entry in entries(os.path.join(d, "state", "tds", str(ready.get("td")), "launcher.log")):
        if entry["msg"] == "starting guest":
            started = at(entry)
        elif entry["msg"].startswith("answered the guest with") and asked is None:
            asked = at(entry)
        # What a guest with a console says of its own bind and of the quote
        # it took beside it, each in parts.
        elif entry["msg"] in guest_said:
            said.append({"kind": guest_said[entry["msg"]], "round": burst, "td": ready.get("td"),
                         **{k: v for k, v in entry.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}})
    if started is not None:
        record["before_vmm_ms"] = round(ready["boot_ms"] - (at(ready) - started) * 1000)
        if asked is not None:
            record["vmm_to_documents_ms"] = round((asked - started) * 1000)
            record["documents_to_ready_ms"] = round((at(ready) - asked) * 1000)
    print(json.dumps(record))
    for each in said:
        print(json.dumps(each))
COLD
    # What the daemon says of each bind of the burst: its own time over it,
    # and the guest's answer as it saw it.
    sudo -n python3 - "$out/daemon.log" "$1" "$sessions" <<'BOUND' >> "$records"
import json, sys
bound = []
for line in open(sys.argv[1], errors="replace"):
    try:
        entry = json.loads(line)
    except ValueError:
        continue
    if isinstance(entry, dict) and entry.get("msg") == "bound a TD":
        bound.append(entry)
for entry in bound[-int(sys.argv[3]):]:
    print(json.dumps({"kind": "daemon-bind", "round": int(sys.argv[2]), "td": entry.get("td"), "took_us": entry.get("took_us"), "guest_us": entry.get("guest_us"), "answer_bytes": entry.get("answer_bytes")}))
BOUND
}

# sample <side> <when> <n>: what that side's VMMs have cost their host so
# far, as a record. Each side's drivers run it before burst n is let go and
# when the burst's last first command has answered, while every guest runs.
# The one before first waits for the side's guests to be idle by their own
# counters, whatever rest they had, and records how long that took.
cat > "$out/sample" <<HOOK
#!/usr/bin/env bash
case "\$1" in td) text='guest=td-' ;; *) text='$fc/firecracker ' ;; esac
[ "\$2" = before ] && set -- "\$1" quiet "\$3"
exec sudo -n python3 "$vmm_stat" "\$1" "\$2" "\$3" "\$text" >> "$records"
HOOK
for side in td load pool; do
    for when in before after; do
        # shellcheck disable=SC2016 # the hook's own argument
        printf '#!/usr/bin/env bash\nexec "%s" %s %s "$1"\n' "$out/sample" "$side" "$when" > "$out/$when-$side"
    done
done
# before-td <n>: the orchestrator's burst first waits here for its turn.
cat > "$out/before-td" <<HOOK
#!/usr/bin/env bash
until [ -e "$out/go.\$1" ]; do
    kill -0 $$ 2>/dev/null || { echo "the run ended" >&2; exit 1; }
    sleep 0.02
done
exec "$out/sample" td before "\$1"
HOOK
chmod 0755 "$out/sample" "$out"/before-* "$out"/after-*

if [ -n "$halt_poll" ]; then
    halt_poll_was=$(cat "$halt_poll_file") || die "this host's KVM names no halt_poll_ns: the run cannot set it"
    echo "$halt_poll" | sudo -n tee "$halt_poll_file" > /dev/null || die "KVM's halt_poll_ns"
fi
# What it is for this run, set by it or found.
halt_polled=$(cat "$halt_poll_file" 2>/dev/null)
if [ "$pin_power" = 1 ]; then
    governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
    echo performance | sudo -n tee /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor > /dev/null
    for state in /sys/devices/system/cpu/cpu[0-9]*/cpuidle/state[0-9]*; do
        case "$(cat "$state/name")" in
        POLL|C1|C1E) ;;
        *) [ "$(cat "$state/disable")" = 0 ] && { echo 1 | sudo -n tee "$state/disable" > /dev/null; idle_off+=("$state/disable"); } ;;
        esac
    done
    # Turbo on: written, so that the run has the state it names and inherits none.
    [ -n "$turbo_file" ] || die "this host's frequency driver names no turbo setting: the run cannot pin it"
    turbo=$(cat "$turbo_file")
    echo "$turbo_on" | sudo -n tee "$turbo_file" > /dev/null
fi

field() { # field <manifest> <dotted path>: that value of it
    python3 -c 'import json,sys
v = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v = v[k]
print(v)' "$1" "$2"
}
others=$(pgrep -a qemu-system | grep -v -c "guest=td-\|guest=c8s-key-service-$run")
{
    printf 'method: power %s; %s other VMs on the host, and its other programs at %s%% of one CPU over the five seconds before the run (listed below); TDX on in the firmware, for every side; ' \
        "$([ "$pin_power" = 1 ] && echo "pinned (governor performance, idle states past C1E off, turbo on)" || echo "as the host had it")" "$others" "$busy"
    printf 'KVM lets a halted vCPU spin %s ns for a wakeup%s; ' "${halt_polled:-an unknown number of}" "$([ -n "$halt_poll" ] && echo ", set by this run")"
    printf 'baselines: Firecracker loading one snapshot of its leanest guest %s times at once, and Firecracker starting as many sessions at once in such guests booted ahead and idle, each to the first command over vsock to an agent that is its guest'"'"'s init on the same image'"'"'s tree, taking turns with the TDs burst by burst in an order that rotates, each side'"'"'s guests there for its own turn alone, which begins with them idle and the host rested; ' "$sessions"
    [ -n "${C8S_BURST_WATCH:-}" ] && printf 'a departure: a program of the trial ran beside each TD burst (%s); ' "$C8S_BURST_WATCH"
    printf 'no second baseline: its guests hold all of their memory from boot; '
    printf 'CPUs: TDs and their daemon %s, Firecracker %s, key service %s, the programs that start the bursts %s; ' "$cpus_td" "$cpus_fc" "$cpus_ks" "$cpus_drive"
    printf 'no claim: each bind claims its TD; before the measured path, on each side: its pool filled, rested %s s and then waited until every guest was idle by KVM'"'"'s own counters for it, the TDs'"'"' with the vendor'"'"'s documents fetched by the binder, each ready TD judged when it became ready and the image unpacked in each, and as that unpacking'"'"'s counterpart each of Firecracker'"'"'s guests having read its file system whole, the one its snapshot was made of (which had also run one command) and each one booted for its pool, which was left the same way with a connection to its agent made; a start that failed or lost its guest counts against its side'"'"'s success rate, and none is left out\n' "$rest"
    echo "run $run, $rounds bursts a side of $sessions sessions on a pool of $depth ready TDs (the host has $keys_all TDX key IDs, $keys_before in use before the pool), $(date -u +%FT%TZ), first command: $first_command, a credential of $credential_bytes bytes sealed with each bind and brought by each of Firecracker's starts, rest $rest s"
    echo "host kernel $(uname -r)"
    lscpu | grep -E "Model name|^CPU\(s\)|Thread|Core|Socket" | sed 's/  */ /g'
    echo "power pinned by this run: $pin_power"
    echo "governor $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor) driver $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver) turbo $([ -n "$turbo_file" ] && { [ "$(cat "$turbo_file")" = "$turbo_on" ] && echo on || echo off; } || echo unknown)$([ -n "$turbo" ] && echo ", set by this run") preference $(cat /sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference 2>/dev/null)"
    echo "idle states of CPU 0: $(for s in /sys/devices/system/cpu/cpu0/cpuidle/state[0-9]*; do printf '%s%s ' "$(cat "$s/name")" "$([ "$(cat "$s/disable")" = 1 ] && echo '(off)')"; done)"
    echo "kvm_intel.tdx $(cat /sys/module/kvm_intel/parameters/tdx); the TDX module is named at the end, by its measurement in a TD's quote"
    echo "transparent huge pages $(cat /sys/kernel/mm/transparent_hugepage/enabled), defrag $(cat /sys/kernel/mm/transparent_hugepage/defrag)"
    echo "KVM halt_poll_ns $halt_polled"
    qemu-system-x86_64 --version | head -1
    cat "$fc/versions.txt"
    m=$IMG/manifest.json km=$KSIMG/manifest.json
    echo "c8s $("$C8S" --version 2>/dev/null | head -1) sha256 $(sha256sum "$C8S" | cut -c1-64); warmstart sha256 $(sha256sum "$WARM" | cut -c1-64); fcburst sha256 $(sha256sum "$fc_burst" | cut -c1-64); fcagent sha256 $(sha256sum "$fc_agent" | cut -c1-64)"
    echo "session image $(basename "$IMG") disk sha256 $(field "$m" outputs.disk_image.sha256) kernel image sha256 $(field "$m" outputs.uki.sha256) firmware sha256 $(field "$m" tdx.firmware.sha256) mrtd $(field "$m" tdx.mrtd) rtmr1 $(field "$m" tdx.rtmr1) rtmr2 $(field "$m" tdx.rtmr2) machine $machine"
    echo "key service image $(basename "$KSIMG") disk sha256 $(field "$km" outputs.disk_image.sha256) kernel image sha256 $(field "$km" outputs.uki.sha256) mrtd $(field "$km" tdx.mrtd) rtmr2 $(field "$km" tdx.rtmr2) machine $ks_machine"
    echo "guest kernel $(field "$m" inputs.kernel.linux_version), guests on taps c8st<n> in $cidr"
    echo "session class 4 vCPUs, 16 GiB; key service 2 vCPUs, 4 GiB; Firecracker guest 4 vCPUs, 16 GiB"
    echo "sandbox image $ref, in a store of $(stat -c %s "$store") bytes sha256 $(sha256sum "$store" | cut -c1-64); its tree as the baseline's guest has it: $(sudo -n du -sm "$fc/image" | cut -f1) MiB"
    echo "work directory on $(df --output=fstype,source "$out" | tail -1)"
    echo "load $(cat /proc/loadavg)"
    free -g | sed -n 2p
    echo "the host's busiest programs over the five seconds before the run, by share of one CPU:"
    echo "$busiest"
} > "$out/env.txt" 2>&1

args=(--daemon "127.0.0.1:$port" --daemon-ca "$pki/ca.pem" --daemon-cert "$pki/orchestrator.pem" --daemon-key "$pki/orchestrator.key"
    --pool agents --image-manifest "$manifest" --launch-key "$out/bundle/opkeydata/pubkey" --authority-key "$out/authority.key"
    --tenant acme --session-prefix "b" --sandbox-image "$ref" --collateral-cache "$out/collateral"
    --rounds 1 --burst "$sessions" --burst-ready "$depth" --first-command "$first_command" --commands 0
    --sealed-credential api-token --claim-with-bind --before-round "$out/before-td" --after-answers "$out/after-td" --wait 60m --timeout 2m
    # A session of a burst sends nothing over a connection of its own, so
    # none is made beside its start.
    --prejudge=false --preconnect=false)
[ -n "${C8S_ACCEPT_TCB:-}" ] && args+=(--accept-tcb-status "$C8S_ACCEPT_TCB")
[ "${C8S_BURST_LEAVE_FAILED:-0}" = 1 ] && args+=(--leave-failed)
[ "${C8S_BURST_KEEP:-0}" -gt 0 ] && args+=(--keep)

# The bursts. Each side's turn begins with its guests idle and the host
# rested, and the side that goes first rotates.
read -r -a sides <<< "${C8S_BURST_SIDES:-td load pool}"
for side in "${sides[@]}"; do
    case "$side" in td|load|pool) ;; *) die "C8S_BURST_SIDES names $side, which is no side" ;; esac
done
for (( n = 0; n < rounds; n++ )); do
    order=("${sides[@]:n % ${#sides[@]}}" "${sides[@]:0:n % ${#sides[@]}}")
    for side in "${order[@]}"; do
        if [ "$side" != td ]; then
            sleep "$rest"
            (on "$cpus_drive" sudo -n "$fc_burst" -dir "$fc" -mode "$side" -sessions "$sessions" -round "$n" -vmm-cpus "$cpus_fc" -rest "${rest}s" \
                -before-burst "$out/before-$side" -after-answers "$out/after-$side") \
                >> "$records" 2>> "$out/fcburst.err" || die "Firecracker's burst $n ($side): $(tail -c 400 "$out/fcburst.err")"
            continue
        fi
        free_before=$(available_mib) pinned_before=$(pinned_mib)
        # A pool the host cannot hold is not started: what else runs here
        # would pay for it.
        [ "$free_before" -ge $(( depth * td_mib + reserve_mib )) ] \
            || die "the host has $free_before MiB available, and a pool of $depth TDs is taken to need $(( depth * td_mib )) with $reserve_mib to spare: $(( (free_before - reserve_mib) / td_mib )) would fit"
        start_daemon
        # The orchestrator judges each TD as it comes ready, while the pool
        # fills, and then waits for its turn.
        on "$cpus_drive" "$WARM" "${args[@]}" --first-round "$n" >> "$records" 2>> "$out/warmstart.err" &
        warm_pid=$!
        pool_full
        sleep "$rest"
        free_after=$(available_mib) pinned_after=$(pinned_mib)
        echo "burst $n: the pool of $depth ready TDs filled in $filled s, two booting at a time, and held $(( $(tdx_keys) - keys_before )) key IDs; the host's unevictable memory, which holds the TDs' private pages, went from $pinned_before MiB to $pinned_after MiB, $(( (pinned_after - pinned_before) / depth )) MiB a ready TD, and its available memory from $free_before MiB to $free_after MiB, $(( (free_before - free_after) / depth )) MiB a ready TD" >> "$out/env.txt"
        watch_pid=""
        if [ -n "${C8S_BURST_WATCH:-}" ]; then
            # shellcheck disable=SC2086
            $C8S_BURST_WATCH "$n" >> "$out/watch.out" 2>&1 &
            watch_pid=$!
            sleep 2
        fi
        : > "$out/go.$n"
        wait "$warm_pid" || die "burst $n: $(tail -c 400 "$out/warmstart.err")"
        [ -n "$watch_pid" ] && wait "$watch_pid"
        warm_pid=""
        echo "burst $n: after it the host held $(pinned_mib) MiB unevictable and had $(available_mib) MiB available" >> "$out/env.txt"
        if [ "${C8S_BURST_KEEP:-0}" -gt 0 ]; then
            sleep "$C8S_BURST_KEEP"
            echo "burst $n: $C8S_BURST_KEEP s after it, $(pgrep -cf '[q]emu-system.*guest=td-') VMMs ran, and the daemon had logged these ends: $(grep '"msg":"a TD ended"' "$out/daemon.log" | sed 's/.*"reason":"\([^"]*\)".*/\1/' | sort | uniq -c | tr '\n' ';')" >> "$out/env.txt"
        fi
        grep -q "\"kind\":\"burst\",\"round\":$n," "$records" || die "burst $n left no record"
        # A burst that lost a session keeps what its guests' launchers
        # logged, which the daemon's end would take with it.
        if grep "\"kind\":\"burst\",\"round\":$n," "$records" | grep -q '"errors"'; then
            mkdir -p "$out/failed-$n"
            # The state directory is the daemon's: its files are read as root.
            while read -r log; do
                sudo -n cat "$log" > "$out/failed-$n/$(basename "$(dirname "$log")").log" 2>/dev/null
            done < <(sudo -n find "$out/state/tds" -maxdepth 2 -name launcher.log 2>/dev/null)
            # What is left of the TDs, and whether each one's guest answers
            # at the far end of its tap.
            {
                pgrep -af '[q]emu-system.*guest=td-' | cut -c1-160
                while read -r tap host_ip; do
                    IFS=. read -r a b c d <<< "$host_ip"
                    guest="$a.$b.$c.$((d + 1))"
                    echo "$tap $guest: health '$(curl -sk --max-time 2 -o /dev/null -w '%{http_code} %{errormsg}' "https://$guest:8443/healthz" 2>&1)' state '$(curl -sk --max-time 2 "https://$guest:8443/v1/state" 2>&1 | cut -c1-200)' ping $(ping -c 1 -W 1 "$guest" > /dev/null 2>&1 && echo answered || echo none)"
                done < <(ip -4 -o addr show | awk '$2 ~ /^c8st/ {split($4, a, "/"); print $2, a[1]}')
            } > "$out/failed-$n/left.txt" 2>&1
            if [ "${C8S_BURST_LEAVE_FAILED:-0}" = 1 ]; then
                # A guest that is ending says why on its console, where it
                # has one: its launcher's log is taken again after a while.
                sleep 15
                while read -r log; do
                    sudo -n cat "$log" > "$out/failed-$n/$(basename "$(dirname "$log")").after.log" 2>/dev/null
                done < <(sudo -n find "$out/state/tds" -maxdepth 2 -name launcher.log 2>/dev/null)
                grep '"msg":"a TD ended"' "$out/daemon.log" | tail -n 40 > "$out/failed-$n/ended.txt"
            fi
        fi
        cold "$n"
        stop_daemon "$n"
    done
done
restore_power

echo "load at the end $(cat /proc/loadavg)" >> "$out/env.txt"
# The TDX module, as the TDs' quotes name it: this host's kernel states no
# version of it.
echo "TDX module MRSEAM $(grep -o '"tdx_module_mrseam":"[0-9a-f]*"' "$records" | sort -u | cut -d'"' -f4 | tr '\n' ' ')" >> "$out/env.txt"

python3 - "$records" "$halt_polled" <<'EOF' | tee "$out/summary.txt"
import json, statistics, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
halt_poll = sys.argv[2] or "not said"
def spread(values):
    values = sorted(values)
    at = lambda q: values[min(len(values) - 1, int(q * len(values)))]
    return f"n={len(values):4}  median {statistics.median(values):8.1f}  p95 {at(0.95):8.1f}  p99 {at(0.99):8.1f}  min {values[0]:8.1f}  max {values[-1]:8.1f}"
def show(label, values, unit="ms"):
    if values:
        print(f"{label:42} {spread(values)}  {unit}")
def score(values, rate):
    """The public board's composite: each of the median, p95 and p99, of the
    times with their lowest and highest twentieth left out, scored against
    ten seconds, weighted 0.60, 0.25 and 0.15, times the rate of success."""
    values = sorted(values)
    cut = len(values) // 20
    kept = values[cut:len(values) - cut] or values
    at = lambda q: kept[min(len(kept) - 1, int(q * len(kept)))]
    part = lambda v: max(0.0, 100 * (1 - v / 10000))
    return (0.60 * part(statistics.median(kept)) + 0.25 * part(at(0.95)) + 0.15 * part(at(0.99))) * rate
def side(name, bursts, sessions, parts):
    print(f"--- {name}")
    steady = [b for b in bursts if b["round"] > 0]
    mine = [s for s in sessions if s["round"] > 0]
    if not steady:
        print("no burst after the first")
        return
    asked, started = sum(b["sessions"] for b in steady), sum(b["started"] for b in steady)
    times = [s["first_cmd_us"] / 1000 for s in mine]
    print(f"{len(steady)} bursts of {steady[0]['sessions']} after the first: {started} of {asked} sessions started, a success rate of {started / asked:.4f}")
    show("start to the first command's answer", times)
    show("  the same from the burst's instant", [(s["offset_us"] + s["first_cmd_us"]) / 1000 for s in mine])
    show("  a session's own start after that instant", [s["offset_us"] / 1000 for s in mine])
    for key, label in parts:
        show("  " + label, [s[key] / 1000 for s in mine if s.get(key)])
    show("a burst's first answer", [b["first_us"] / 1000 for b in steady if b.get("first_us")])
    show("a burst's last answer (wall clock)", [b["wall_us"] / 1000 for b in steady if b.get("wall_us")])
    if times:
        print(f"by the public board's formula, on these times as this host's own client took them: {score(times, started / asked):.2f}")
    for b in bursts:
        when = "the first burst, caches cold" if b["round"] == 0 else f"burst {b['round']}"
        of = [s["first_cmd_us"] / 1000 for s in sessions if s["round"] == b["round"]]
        print(f"{when}: {b['started']} of {b['sessions']} started" + (f", median {statistics.median(of):.1f} ms, last answer at {b.get('wall_us', 0) / 1000:.1f} ms" if of else "")
              + (f", on {b['ready']} ready TDs" if b.get("ready", b["sessions"]) != b["sessions"] else "")
              + ("".join(f"; failed: {e}" for e in b.get("errors", []))))
side("TDs", [r for r in rows if r.get("kind") == "burst"], [r for r in rows if r.get("kind") == "session"],
     (("sign_us", "sign"), ("seal_us", "seal"), ("bind_us", "bind"), ("judge_us", "the receipt's check"), ("first_exec_us", "the first command after the start"),
      ("quote_us", "the bind's quote, after its answer"), ("confirmed_us", "the quote judged, from the start")))
side("Firecracker, each start a snapshot's load", [r for r in rows if r.get("kind") == "fc-load"], [r for r in rows if r.get("kind") == "fc-load-session"],
     (("api_up_us", "the VMM's API socket"), ("loaded_us", "the snapshot loaded and resumed"), ("vsock_connected_us", "the agent's accept")))
side("Firecracker, each start a guest booted ahead", [r for r in rows if r.get("kind") == "fc-pool"], [r for r in rows if r.get("kind") == "fc-pool-session"], ())
show("Firecracker's pool booted, eight at a time", [r["pool_boot_ms"] for r in rows if r.get("kind") == "fc-pool"], "ms (before its burst: no part of a start)")
for r in rows:
    if r.get("kind") == "fc-lean":
        print(f"Firecracker's guest: the agent as init on the image's own tree, {r['bytes']} bytes, booted with: {r['boot_args']}; its first command is {' '.join(r.get('first_command', []))}")
    if r.get("kind") == "fc-lean-snapshot":
        print(f"Firecracker's snapshot: made in {r['snapshot_create_ms']} ms, of that guest {r['agent_up_us'] / 1000:.0f} ms after its VMM started and once it had read its file system whole")
steady = lambda kind: [r for r in rows if r.get("kind") == kind and r.get("round", 0) > 0]
show("the daemon's time over a bind", [r["took_us"] / 1000 for r in steady("daemon-bind") if r.get("took_us")])
show("  of which the guest's answer", [r["guest_us"] / 1000 for r in steady("daemon-bind") if r.get("guest_us")])
# A guest with a console says how long its bind took in parts, each from the
# bind's arrival, and the quote it took beside it.
def told_by(kind, label):
    """A guest's own numbers of one kind: times in ms, the rest as it gave them."""
    told = steady(kind)
    for key in dict.fromkeys(k for r in told for k in r if k not in ("kind", "round", "td")):
        values = [r[key] for r in told if key in r]
        if key.endswith("_us"):
            show(label + key[:-3], [v / 1000 for v in values], "ms (the guest's own clock)")
        else:
            show(label + key, values, "(the guest's own count)")
told_by("guest-bind", "guest's bind, to ")
told_by("guest-quote", "guest's quote: ")
told_by("guest-call", "guest's bind and what followed: ")
told_by("guest-prepared", "guest's first second prepared: ")
cold = [r for r in rows if r.get("kind") == "session-cold"]
show("TD launch to ready", [r["boot_ms"] for r in cold], "ms (two boot at a time, beside whatever else ran)")
show("  VMM start to documents asked", [r["vmm_to_documents_ms"] for r in cold if "vmm_to_documents_ms" in r])
show("  documents asked to ready", [r["documents_to_ready_ms"] for r in cold if "documents_to_ready_ms" in r])
# What a start cost its host on each side: what the side's VMMs ran, waited
# and had KVM do between the burst's go and its last answer, by the sessions.
taken = {}
for r in rows:
    if r.get("kind") == "vmm-stat":
        taken.setdefault((r["side"], r["round"]), {})[r["when"]] = r
for name, key, kind in (("TDs", "td", "burst"), ("Firecracker, a snapshot's load", "load", "fc-load"), ("Firecracker, booted ahead", "pool", "fc-pool")):
    pairs = [(pair["before"], pair["after"], b["sessions"]) for b in rows if b.get("kind") == kind and b["round"] > 0
             for pair in [taken.get((key, b["round"]), {})] if "before" in pair and "after" in pair]
    starts = sum(n for _, _, n in pairs)
    if not starts:
        continue
    def per(*path):
        total = 0
        for before, after, _ in pairs:
            b, a = before, after
            for step in path:
                b, a = b[step], a[step]
            total += a - b
        return total / starts
    ms = lambda *path: per(*path) / 1000
    print(f"--- what a start cost its host: {name} ({starts} starts, each VMM's threads from the burst's go to its last answer)")
    print(f"vCPU threads ran {ms('vcpu', 'ran_us'):8.2f} ms a start and waited for a CPU {ms('vcpu', 'waited_us'):8.2f} ms; sampled by the kernel's tick: in the guest {ms('vcpu', 'guest_us'):.2f}, in the host's kernel {ms('vcpu', 'system_us'):.2f}")
    print(f"other threads ran {ms('other', 'ran_us'):8.2f} ms a start and waited {ms('other', 'waited_us'):8.2f} ms")
    # The same guests idle, over the second before the burst.
    idle = [(pair["idle"], pair["before"]) for b in rows if b.get("kind") == kind and b["round"] > 0
            for pair in [taken.get((key, b["round"]), {})] if "idle" in pair and "before" in pair and pair["before"]["vmms"]]
    if idle:
        guests = sum(before["vmms"] for _, before in idle)
        ran = sum(before[k]["ran_us"] - was[k]["ran_us"] for was, before in idle for k in ("vcpu", "other")) / guests / 1000
        exits = sum(before["kvm"]["exits"] - was["kvm"]["exits"] for was, before in idle) / guests
        wall = statistics.median([b["wall_us"] / 1000 for b in rows if b.get("kind") == kind and b["round"] > 0 and b.get("wall_us")] or [0])
        print(f"idle, in the second before the burst, each guest's VMM ran {ran:.2f} ms and took {exits:.0f} exits; a burst's last answer came {wall:.0f} ms after its go")
    other = per("kvm", "exits") - sum(per("kvm", k) for k in ("halt_exits", "io_exits", "mmio_exits", "irq_exits"))
    print(f"KVM: {per('kvm', 'exits'):.0f} exits a start (halt {per('kvm', 'halt_exits'):.0f}, I/O {per('kvm', 'io_exits'):.0f}, MMIO {per('kvm', 'mmio_exits'):.0f}, interrupts {per('kvm', 'irq_exits'):.0f}, others {other:.0f}), "
          f"{per('kvm', 'pf_fixed'):.0f} page faults resolved, pages mapped anew: {per('kvm', 'pages_4k'):.0f} of 4 KiB and {per('kvm', 'pages_2m'):.0f} of 2 MiB")
    polled = (per("kvm", "halt_poll_success_ns") + per("kvm", "halt_poll_fail_ns")) / 1e6
    print(f"KVM: halted vCPUs spun {polled:.2f} ms a start for a wakeup ({per('kvm', 'halt_successful_poll'):.0f} of {per('kvm', 'halt_attempted_poll'):.0f} spins met one) and then slept {per('kvm', 'halt_wait_ns') / 1e6:.2f} ms; the host's halt_poll_ns is {halt_poll}")
for name, key in (("TDs", "td"), ("Firecracker's booted guests", "pool")):
    waits = [r for r in rows if r.get("kind") == "vmm-quiet" and r["side"] == key and r["vmms"]]
    if waits:
        print(f"{name} were idle by their own counters {statistics.median(r['waited_s'] for r in waits):.0f} s after their rest, at the median of {len(waits)} bursts (at most {max(r['waited_s'] for r in waits):.0f} s): no guest's VMM ran over 10 ms or resolved over 16 page faults in each of two seconds")
outputs = sorted({s.get("first_output", "") for s in rows if s.get("kind") in ("session", "fc-load-session", "fc-pool-session")})
print("the first command wrote: " + ", ".join(repr(o) for o in outputs))
# A start whose command wrote something else did other work than the rest.
if len(outputs) != 1 or not outputs[0]:
    sys.exit("FAILED: the first commands did not all write one answer")
EOF
status=$?
head -1 "$out/env.txt"
exit "$status"
