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
# session's first command is reached: the baseline to hold a session to. That
# command is the work a session's is: the shell of the sandbox image, reading
# a file of the credential's size from a read-only drive. Each round then
# also takes the leanest guest Firecracker boots, the agent as init on that
# shell's own tree, three ways: a load of its snapshot, which is the snapshot
# baseline at its strongest, a cold boot to its first command, and a start in
# such a guest booted ahead and left idle, as a platform with confidentiality
# off can keep a pool of them. A start in that guest is one message to its
# agent, with the credential and the first command.
#
# With C8S_SIM_BIN and the three settings that go with it, the run takes the
# document's second baseline too: the same start in guests that boot with no
# TEE and simulate one in software (a development build made with the
# c8s_simtee tag, which protects nothing). That side has a key service, a
# daemon, a pool and an orchestrator of its own, and the two sides take turns
# round by round, in an order that alternates. A side's round begins only
# when both pools are full and idle, and each side's guests, the two key
# services and the programs that drive the rounds keep to CPUs of their own.
#
# Records go to <work>/timing.jsonl, one JSON object a line (the simulated
# side's to <work>/sim/timing.jsonl), and what the host was to <work>/env.txt,
# whose first line says which rules of the document's method the run kept.
# The script pins power when asked and samples the baselines it is given; it
# runs beside whatever else the host runs, which it counts.
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
#   C8S_TIMING_CLAIM_WITH_BIND=1
#                            make no claim: each round signs its bind for a
#                            ready TD it has judged, and the bind claims that
#                            TD (needs the watch)
#   C8S_TIMING_BINDER=1      with that, run the rounds as a binder under a
#                            certificate of its own making, which the pool
#                            names with the tenant's authority, where the
#                            default runs them as the orchestrator; the
#                            orchestrator ends the sessions either way
#   C8S_TIMING_LOSE_FIRST=1  with that, have a second bind for the same TD
#                            come first in each round, to time what a
#                            collision of two binders costs: a round then
#                            takes both of the pool's TDs
#   C8S_TIMING_WITH_BIND=0   send each first command over a connection once
#                            the guest's receipt is checked, where the default
#                            sends it with the bind
#   C8S_TIMING_QUOTE_FIRST=1 judge each bind's quote before the first command
#                            is sent, where the default takes the command's
#                            answer on the guest's receipt and judges the
#                            quote beside it
#   C8S_TIMING_PRECONNECT=0  leave the connection a first command goes over
#                            to that command, where the default makes it
#                            ahead: its parts are then all on the command's
#                            path, which is how to read what it costs
#   C8S_TIMING_REST          seconds of rest before each round (default 3): a
#                            long one shows what a start costs once the
#                            guests' connections have sat idle
#   C8S_TIMING_IDLE          seconds to watch the pools once the rounds are
#                            over, full and with nothing asked of them
#                            (default 0: not at all): the CPU time each ready
#                            guest's VMM takes while it waits
#   C8S_TIMING_PIN_POWER=1   for the run, set every CPU's governor to
#                            performance, turn off idle states deeper than
#                            C1E and turn turbo on, as a host in production
#                            has it, and set KVM's halt polling to none (see
#                            the next); all are put back when the run ends
#   C8S_TIMING_HALT_POLL_NS  for the run, how long KVM lets a halted vCPU
#                            spin for a wakeup before it gives up its CPU
#                            (the host's halt_poll_ns, for every VM on it);
#                            put back when the run ends. Unset, a run that
#                            pins the power sets 0 and any other takes the
#                            host's as it is. Either way the record names it
#   C8S_SIM_BIN              a c8s binary built with -tags c8s_simtee: with
#                            it the run takes the second baseline, and needs
#                            the next three
#   C8S_SIM_WARMSTART        the warmstart binary built with that tag
#   C8S_SIM_SESSION_IMAGE    simulating session image directory
#                            (C8S_SIMTEE=1 session-guest-image/build)
#   C8S_SIM_KEY_SERVICE_IMAGE
#                            simulating key service image directory
#   C8S_SIM_CONSOLE_IMAGE    a simulating session image with a console (a dev
#                            build of the simulated side's): with it the run
#                            boots that image once, alone and before anything
#                            else, for what its kernel says of clearing the
#                            guest's memory, which most of a simulated
#                            guest's launch to ready is
#   C8S_TIMING_CPUS          five CPU lists, as taskset takes them, separated
#                            by spaces: the TD side's guests' VMMs', the
#                            simulated side's, the platform's own programs'
#                            (each side's key service, its daemon and the
#                            daemon's launchers, and for the run the host's
#                            quoting service or what stands in for it), the
#                            Firecracker baseline's, and the programs' that
#                            drive the rounds. The guests' VMMs share their
#                            CPUs with nothing else of the run. Without it a
#                            run with the second baseline splits the host's
#                            cores from the third on into those five, 6, 6,
#                            4, 4 and the rest, each core with its sibling
#                            threads (it needs 24 cores for that), and a run
#                            of the TD side alone pins nothing
#   C8S_TIMING_QUOTING       0 leaves the host's quoting service on the CPUs
#                            the host has it on, which the record then names
#                            as a departure. Otherwise, in a run that names
#                            CPUs, it keeps to the platform's for the run
#                            and is put back when the run ends
#   C8S_FIRECRACKER          directory written by firecracker-setup.sh
#   C8S_FIRECRACKER_SAMPLE   the sampling program (default: beside this script)
#   C8S_FIRECRACKER_AGENT    the baseline's guest agent, built for the guest
#                            (CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build
#                            ./test/session/fcagent)
#   C8S_FIRECRACKER_BUSYBOX  the static busybox the sandbox image was made
#                            from (default /usr/bin/busybox, as
#                            test/session/sandboximage's): the shell of the
#                            baseline's first command
#   C8S_SESSION_DEV=1        the images are dev builds: attach their consoles.
#                            Not a measured configuration.
#   C8S_QUOTE_SOCKET, C8S_SESSION_CONFINE, C8S_ACCEPT_TCB, C8S_SESSION_PORT,
#   C8S_KEY_SERVICE_PORT, C8S_SESSION_CIDR
#                            as for hardware.sh. The simulated side takes the
#                            daemon's port plus 10, the key service's plus 10
#                            and C8S_SIM_SESSION_CIDR (10.214.0.0/24)
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
# The second baseline's side, when the run takes it.
SIM=${C8S_SIM_BIN:-}
sides=(td)
if [ -n "$SIM" ]; then
    SIMWARM=${C8S_SIM_WARMSTART:?C8S_SIM_BIN needs C8S_SIM_WARMSTART, the warmstart binary built with -tags c8s_simtee}
    SIMIMG=${C8S_SIM_SESSION_IMAGE:?C8S_SIM_BIN needs C8S_SIM_SESSION_IMAGE, a simulating session image directory}
    SIMKSIMG=${C8S_SIM_KEY_SERVICE_IMAGE:?C8S_SIM_BIN needs C8S_SIM_KEY_SERVICE_IMAGE, a simulating key service image directory}
    sides=(td sim)
fi
rounds=${C8S_TIMING_ROUNDS:-21}
stored=${C8S_TIMING_STORED:-1}
sealed=${C8S_TIMING_SEALED:-0}
[ "$sealed" = 1 ] && stored=0
watch=${C8S_TIMING_WATCH:-1}
claim_with_bind=${C8S_TIMING_CLAIM_WITH_BIND:-0}
as_binder=${C8S_TIMING_BINDER:-0}
lose_first=${C8S_TIMING_LOSE_FIRST:-0}
if [ "$claim_with_bind" = 1 ] && [ "$watch" != 1 ]; then echo "C8S_TIMING_CLAIM_WITH_BIND needs the watch" >&2; exit 2; fi
if [ "$claim_with_bind" != 1 ] && { [ "$as_binder" = 1 ] || [ "$lose_first" = 1 ]; }; then
    echo "C8S_TIMING_BINDER and C8S_TIMING_LOSE_FIRST need C8S_TIMING_CLAIM_WITH_BIND=1" >&2
    exit 2
fi
# How many TDs a round takes from a pool, and how many a pool keeps.
per_round=1
[ "$lose_first" = 1 ] && per_round=2
depth=2
rest=${C8S_TIMING_REST:-3}
idle=${C8S_TIMING_IDLE:-0}
pin_power=${C8S_TIMING_PIN_POWER:-0}
halt_poll=${C8S_TIMING_HALT_POLL_NS:-}
# A run that pins the power settings pins halt polling with them, at none.
[ "$pin_power" = 1 ] && halt_poll=${halt_poll:-0}
halt_poll_file=/sys/module/kvm/parameters/halt_poll_ns
case "$halt_poll" in *[!0-9]*) echo "C8S_TIMING_HALT_POLL_NS is a number of nanoseconds" >&2; exit 2 ;; esac
fc=${C8S_FIRECRACKER:-}
fc_sample=${C8S_FIRECRACKER_SAMPLE:-$(dirname "$(readlink -f "$0")")/firecracker_sample.py}
fc_agent=${C8S_FIRECRACKER_AGENT:-}
fc_busybox=${C8S_FIRECRACKER_BUSYBOX:-/usr/bin/busybox}
dev=${C8S_SESSION_DEV:-0}
quote_socket=${C8S_QUOTE_SOCKET:-/var/run/tdx-qgs/qgs.socket}
confine=${C8S_SESSION_CONFINE:-}
accept=()
[ -n "${C8S_ACCEPT_TCB:-}" ] && accept=(--accept-tcb-status "$C8S_ACCEPT_TCB")
port=${C8S_SESSION_PORT:-7443}
ks_port=${C8S_KEY_SERVICE_PORT:-18543}
cidr=${C8S_SESSION_CIDR:-10.213.0.0/24}

program() { # program <path>: the program there, or nothing
    local path
    path=$(command -v "$1" || true)
    [ -n "$path" ] && [ -x "$path" ] && readlink -f "$path"
}
C8S=$(program "$C8S") || { echo "no c8s binary: set C8S_BIN" >&2; exit 2; }
WARM=$(program "$WARM") || { echo "C8S_WARMSTART is no program" >&2; exit 2; }
[ -f "$IMG/manifest.json" ] && [ -f "$KSIMG/manifest.json" ] || { echo "an image directory holds no manifest.json" >&2; exit 2; }
if [ -n "$SIM" ]; then
    SIM=$(program "$SIM") || { echo "C8S_SIM_BIN is no program" >&2; exit 2; }
    SIMWARM=$(program "$SIMWARM") || { echo "C8S_SIM_WARMSTART is no program" >&2; exit 2; }
    [ -f "$SIMIMG/SIMULATED-TEE" ] && [ -f "$SIMKSIMG/SIMULATED-TEE" ] || { echo "$SIMIMG or $SIMKSIMG is no image built with C8S_SIMTEE=1" >&2; exit 2; }
    if [ -f "$IMG/SIMULATED-TEE" ] || [ -f "$KSIMG/SIMULATED-TEE" ]; then
        echo "C8S_SESSION_IMAGE or C8S_KEY_SERVICE_IMAGE is an image built with C8S_SIMTEE=1" >&2
        exit 2
    fi
fi
sudo -n true 2>/dev/null || { echo "this run needs passwordless sudo" >&2; exit 2; }
[ "$(cat /sys/module/kvm_intel/parameters/tdx 2>/dev/null)" = Y ] || { echo "this host's KVM runs no TD (kvm_intel.tdx is not Y)" >&2; exit 2; }
ref=$(cat "$store_dir/ref") store=$store_dir/images.store
[ -n "$ref" ] && [ -f "$store" ] || { echo "$store_dir is no directory written by test/session/sandboximage" >&2; exit 2; }
if [ -n "$fc" ]; then
    [ -x "$fc/firecracker" ] && [ -f "$fc_sample" ] || { echo "$fc holds no firecracker, or $fc_sample is missing" >&2; exit 2; }
    fc=$(readlink -f "$fc")
    # The snapshot is taken with the agent this run names, or with none, and
    # the lean guest is made of the session's shell: a burst's run leaves the
    # tree of its sandbox image here, which that guest would take.
    rm -f "$fc/fcagent" "$fc/busybox"
    sudo -n rm -rf "${fc:?}/image" "${fc:?}/image.env"
    if [ -n "$fc_agent" ]; then
        [ -f "$fc_agent" ] || { echo "C8S_FIRECRACKER_AGENT=$fc_agent is not a file" >&2; exit 2; }
        [ -f "$fc_busybox" ] || { echo "C8S_FIRECRACKER_BUSYBOX=$fc_busybox is not a file" >&2; exit 2; }
        command -v mksquashfs > /dev/null || { echo "the baseline's agent needs mksquashfs (squashfs-tools)" >&2; exit 2; }
        install -m 0755 "$fc_agent" "$fc/fcagent"
        install -m 0755 "$fc_busybox" "$fc/busybox"
    fi
elif [ -n "$fc_agent" ]; then
    echo "C8S_FIRECRACKER_AGENT needs C8S_FIRECRACKER" >&2
    exit 2
fi

# Where each part of the run keeps to: the TD side's guests, the simulated
# side's, the two key services (the first half the TD side's), the
# Firecracker baseline, and the daemons with the programs that drive the
# rounds. Empty lists pin nothing.
cpus_td="" cpus_sim="" cpus_ks="" cpus_fc="" cpus_drive=""
if [ -n "${C8S_TIMING_CPUS:-}" ]; then
    read -r cpus_td cpus_sim cpus_ks cpus_fc cpus_drive <<< "$C8S_TIMING_CPUS"
    [ -n "$cpus_drive" ] || { echo "C8S_TIMING_CPUS is five CPU lists: the TD side's guests' VMMs', the simulated side's, the platform's programs', Firecracker's, the drivers'" >&2; exit 2; }
elif [ -n "$SIM" ]; then
    # By cores, each with its sibling threads: the first two are left to the
    # host, then 6, 6, 4 and 4, and the rest drives.
    read -r cpus_td cpus_sim cpus_ks cpus_fc cpus_drive < <(python3 -c '
import glob
cores = sorted({open(p).read().strip() for p in glob.glob("/sys/devices/system/cpu/cpu[0-9]*/topology/core_cpus_list")},
               key=lambda c: int(c.replace("-", ",").split(",")[0]))
cut = lambda a, b: ",".join(cores[a:b])
print(cut(2, 8), cut(8, 14), cut(14, 18), cut(18, 22), cut(22, len(cores)) if len(cores) >= 24 else "")')
    [ -n "$cpus_drive" ] || { echo "this host has fewer than 24 cores: name the CPUs each part keeps to with C8S_TIMING_CPUS" >&2; exit 2; }
fi
half() { # half <first|second> <CPU list>: that half of its entries
    python3 -c 'import sys
e = sys.argv[2].split(","); h = len(e) // 2
print(",".join(e[:h] if sys.argv[1] == "first" else e[h:]))' "$1" "$2"
}
# on <CPU list> <command...>: the command in this shell's place, on those
# CPUs when a list is given. It is called in the background or in a subshell:
# the process it leaves is the command's own, which a signal then reaches.
on() {
    local cpus=$1
    shift
    if [ -n "$cpus" ]; then exec taskset -c "$cpus" "$@"; else exec "$@"; fi
}

# kernel_order <CPU list>: the same CPUs as the kernel lists them, which is
# how a daemon is told where its guests' VMMs keep to.
kernel_order() {
    python3 -c '
import sys
cpus = set()
for part in sys.argv[1].split(","):
    low, _, high = part.partition("-")
    cpus.update(range(int(low), int(high or low) + 1))
cpus, out = sorted(cpus), []
while cpus:
    end = 0
    while end + 1 < len(cpus) and cpus[end + 1] == cpus[end] + 1:
        end += 1
    out.append(str(cpus[0]) if end == 0 else f"{cpus[0]}-{cpus[end]}")
    cpus = cpus[end + 1:]
print(",".join(out))' "$1"
}

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

out=${C8S_SESSION_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/c8s-session-timing.XXXXXX")}
mkdir -p "$out/pki" || exit 2
[ ! -e "$out/timing.jsonl" ] || { echo "$out holds an earlier run" >&2; exit 2; }
out=$(readlink -f "$out")
run=$(basename "$out")
echo "records in $out"
quiet() { "$@" > /dev/null 2>> "$out/setup.err"; }
die() { echo "FAILED: $*" >&2; tail -c 400 "$out/setup.err" >&2 2>/dev/null; exit 1; }

# What each side is: its programs, its images, where its daemon and its key
# service listen, its guests' block and the prefix of their taps, its
# directory, and the CPUs its guests and its key service keep to. The TD
# side's files are where a run of that side alone has always put them.
declare -A bin warm img ksimg dport kport block prefix dir guest_cpus ks_cpus label
declare -A ks_pid daemon_pid probe_pid warm_pid machine ks_machine
bin[td]=$C8S warm[td]=$WARM img[td]=$IMG ksimg[td]=$KSIMG dport[td]=$port kport[td]=$ks_port block[td]=$cidr prefix[td]="" dir[td]=$out
guest_cpus[td]=$cpus_td ks_cpus[td]=$cpus_ks label[td]="TD"
# What a command that judges evidence is told, and a guest's launcher, read
# by name where a side is stood up.
# shellcheck disable=SC2034
trust_td=("${accept[@]}")
launcher_td=(session-launcher run --platform tdx --vsock-cid auto)
[ -S "$quote_socket" ] && launcher_td+=(--quote-socket "$quote_socket")
tee=""
if [ -n "$SIM" ]; then
    tee=$out/sim/authority
    bin[sim]=$SIM warm[sim]=$SIMWARM img[sim]=$SIMIMG ksimg[sim]=$SIMKSIMG dport[sim]=$((port + 10)) kport[sim]=$((ks_port + 10))
    block[sim]=${C8S_SIM_SESSION_CIDR:-10.214.0.0/24} prefix[sim]=c8su dir[sim]=$out/sim label[sim]="simulated TEE"
    guest_cpus[sim]=$cpus_sim ks_cpus[sim]=""
    if [ -n "$cpus_ks" ]; then
        ks_cpus[td]=$(half first "$cpus_ks") ks_cpus[sim]=$(half second "$cpus_ks")
    fi
    # Always UpToDate: the simulated authority has no other status to accept.
    # shellcheck disable=SC2034
    trust_sim=(--simulated-tee "$tee")
    # shellcheck disable=SC2034
    launcher_sim=(session-launcher run --platform tdx --vsock-cid auto --simulated-tee "$tee")
fi
# table <side>: its daemon's table in the host's packet filter.
table() { echo "c8s_sessions${prefix[$1]:+_${prefix[$1]}}"; }
for side in "${sides[@]}"; do
    ks_pid[$side]="" daemon_pid[$side]="" probe_pid[$side]="" warm_pid[$side]=""
    if sudo -n nft list table inet "$(table "$side")" > /dev/null 2>&1; then
        echo "the packet filter holds a table inet $(table "$side"): a session daemon runs here, or one left it behind" >&2
        exit 2
    fi
    declare -n each=launcher_$side
    [ -n "$confine" ] && each+=(--confine "$confine")
    [ "$dev" = 1 ] && each+=(--console)
    unset -n each
done

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
# A binder's certificate is of its own making: the pool names its key.
quiet openssl ecparam -name prime256v1 -genkey -noout -out "$pki/binder.key"
quiet openssl req -x509 -new -key "$pki/binder.key" -subj "/CN=a binder of its own making" -days 2 -out "$pki/binder.pem"

vendor_pid="" governor="" turbo="" idle_off=() halt_poll_was="" quoting_was=()
stop_pid() { # stop_pid <pid>
    [ -n "$1" ] || return 0
    sudo -n kill -TERM "$1" 2>/dev/null
    wait "$1" 2>/dev/null
}
# The host's quoting service is the platform's too: for the run it keeps to
# the platform's CPUs on the TD side, and it is put back where the host had
# it.
quoting_pids() { pgrep -x qgs; pgrep -x aesm_service; }
keep_quoting() { # keep_quoting <CPU list>
    local pid was
    for pid in $(quoting_pids); do
        was=$(taskset -cp "$pid" 2>/dev/null | sed 's/.*: //') || continue
        [ -n "$was" ] || continue
        sudo -n taskset -a -cp "$1" "$pid" > /dev/null 2>&1 || return 1
        quoting_was+=("$pid $was")
    done
    [ "${#quoting_was[@]}" -gt 0 ]
}
restore_quoting() {
    local each
    for each in "${quoting_was[@]}"; do
        sudo -n taskset -a -cp "${each#* }" "${each%% *}" > /dev/null 2>&1
    done
    quoting_was=()
}
restore_power() {
    restore_quoting
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
cleanup() {
    local side
    for side in "${sides[@]}"; do
        [ -n "${warm_pid[$side]}" ] && kill "${warm_pid[$side]}" 2>/dev/null
        stop_pid "${daemon_pid[$side]}"; daemon_pid[$side]=""
        [ -f "${dir[$side]}/config.yaml" ] && sudo -n "${bin[$side]}" session-daemon drain --config "${dir[$side]}/config.yaml" --wait 3m >> "${dir[$side]}/drain.out" 2>> "${dir[$side]}/daemon.log"
        sudo -n nft delete table inet "$(table "$side")" 2>/dev/null
        stop_pid "${probe_pid[$side]}"; probe_pid[$side]=""
        stop_pid "${ks_pid[$side]}"; ks_pid[$side]=""
    done
    [ -n "$vendor_pid" ] && kill "$vendor_pid" 2>/dev/null
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
launch_ks() { # launch_ks <side> <bundle> <work directory> <log>
    local -n launcher=launcher_$1
    on "${ks_cpus[$1]}" sudo -n "${bin[$1]}" "${launcher[@]}" --image-dir "${ksimg[$1]}" --launch-dir "$2/opkeydata" --work-dir "$3" \
        --name "c8s-key-service-$1-$run" "${ks_shape[@]}" --network none --port "127.0.0.1:${kport[$1]}:8443" > "$4" 2>&1 &
    ks_pid[$1]=$!
}

# The simulated authority, and whoever serves its documents, before anything
# of that side boots.
if [ -n "$SIM" ]; then
    mkdir -p "$out/sim"
    quiet "$SIM" session simtee new --out "$tee" || die "the simulated authority"
    on "${ks_cpus[sim]}" "$SIM" session simtee vendor --dir "$tee" > "$out/sim/vendor.log" 2>&1 &
    vendor_pid=$!
    deadline=$(( $(date +%s) + 20 ))
    until [ -s "$tee/vendor" ]; do
        kill -0 "$vendor_pid" 2>/dev/null && [ "$(date +%s)" -lt "$deadline" ] || die "the simulated authority's documents are not served: $(tail -c 300 "$out/sim/vendor.log")"
        sleep 0.1
    done
fi

# key_digest <certificate>: its public key as a pool's configuration names it.
key_digest() {
    echo "sha256:$(openssl x509 -in "$1" -noout -pubkey 2>> "$out/setup.err" | openssl pkey -pubin -outform DER 2>> "$out/setup.err" | sha256sum | cut -c1-64)"
}
binder=$(key_digest "$pki/orchestrator.pem")
own_binder=$(key_digest "$pki/binder.pem")
authority=sha256:$(openssl pkey -in "$out/authority.key" -pubout -outform DER 2>> "$out/setup.err" | sha256sum | cut -c1-64)
[ ${#binder} = 71 ] && [ ${#own_binder} = 71 ] && [ ${#authority} = 71 ] || die "the digest of a public key"
printf 'timing-secret-%s' "$run" > "$out/stored"
# The size of the credential a session's first command reads back, which the
# baseline's first command reads a file of: the stored one, or the 48 bytes
# the orchestrator makes for a bind, or none.
credential_bytes=0
[ "$stored" = 1 ] && credential_bytes=$(stat -c %s "$out/stored")
[ "$sealed" = 1 ] && credential_bytes=48
first_command() {
    if [ "$credential_bytes" -gt 0 ]; then
        echo "the sandbox image's shell reading a file of $credential_bytes bytes from a read-only drive"
    else
        echo "true"
    fi
}

# stand_up <side>: its key service, its tenant's credential, and its daemon
# with one pool. Two machines are read from evidence first, as in
# hardware.sh: the key service's and the class's, each from one guest under
# a document that lists none.
stand_up() {
    local side=$1 d=${dir[$1]} c=${bin[$1]} manifest=${img[$1]}/manifest.json probe_port=$((${kport[$1]} + 2))
    local -n trust=trust_$1 launcher=launcher_$1
    local pin=$d/ks-pin.json status=()
    # The statuses a key service takes of its pool's guests, and a guest of
    # its key service: the TD side's alone, where the host's platform has one.
    [ "$side" = td ] && status=("${accept[@]}")
    mkdir -p "$d"
    local ks_pool=(--image-manifest "${ksimg[$side]}/manifest.json" --pool "$manifest:$d/pool.key.pub" "${status[@]}")
    quiet "$c" session launch-config key --out "$d/pool.key" || die "$side: the pool's key"
    quiet "$c" session key-service launch-config new --out "$d/ks-probe" "${ks_pool[@]}" || die "$side: the key service's first bundle"
    launch_ks "$side" "$d/ks-probe" "$d/ks-probe-vm" "$d/ks-probe.log"
    serving "${ks_pid[$side]}" "${kport[$side]}" || die "$side: the key service's probe never served"
    ks_machine[$side]=$("$c" session key-service launch-config machine --bundle "$d/ks-probe" --url "https://127.0.0.1:${kport[$side]}" "${trust[@]}" 2>> "$out/setup.err") \
        || die "$side: the key service's machine"
    stop_pid "${ks_pid[$side]}"; ks_pid[$side]=""
    quiet "$c" session key-service launch-config new --out "$d/ks" --key "$d/ks-probe/launch.key" "${ks_pool[@]}" --machine "${ks_machine[$side]}" \
        || die "$side: the key service's bundle"
    quiet "$c" session key-service pin --bundle "$d/ks" --url "https://127.0.0.1:${kport[$side]}" --out "$pin" "${status[@]}" || die "$side: the pin"

    # The sandbox image is unpacked in every pooled TD before anybody binds it.
    local pool_doc=(--key "$d/pool.key" --key-service "$pin" --image-manifest "$manifest" --pool agents --class s-4x16 --prestage "$ref")
    quiet "$c" session launch-config new --out "$d/bundle-probe" "${pool_doc[@]}" || die "$side: the pool's first bundle"
    # A launcher stays with the platform's programs and starts its VMM on
    # the guests' CPUs, in a run that names any.
    local away=()
    [ -n "${guest_cpus[$side]}" ] && away=(--vmm-cpus "$(kernel_order "${guest_cpus[$side]}")")
    on "${ks_cpus[$side]}" sudo -n "$c" "${launcher[@]}" "${away[@]}" --image-dir "${img[$side]}" --launch-dir "$d/bundle-probe/opkeydata" --work-dir "$d/probe-vm" \
        --name "c8s-session-probe-$side-$run" "${shape[@]}" --network user --port "127.0.0.1:$probe_port:8443" > "$d/probe.log" 2>&1 &
    probe_pid[$side]=$!
    serving "${probe_pid[$side]}" "$probe_port" || die "$side: the pool's probe never served"
    machine[$side]=$("$c" session launch-config machine --url "https://127.0.0.1:$probe_port" --image-manifest "$manifest" \
        --launch-key "$d/pool.key.pub" "${trust[@]}" 2>> "$out/setup.err") || die "$side: the class's machine"
    stop_pid "${probe_pid[$side]}"; probe_pid[$side]=""
    quiet "$c" session launch-config new --out "$d/bundle" "${pool_doc[@]}" --machine "${machine[$side]}" || die "$side: the pool's bundle"

    launch_ks "$side" "$d/ks" "$d/ks-vm" "$d/ks.log"
    serving "${ks_pid[$side]}" "${kport[$side]}" || die "$side: the key service never served"
    local tenant=(--key-service "$pin" --tenant acme --authority-key "$out/authority.key")
    quiet "$c" session key-service tenant register "${tenant[@]}" "${trust[@]}" || die "$side: the tenant's registration"
    quiet "$c" session key-service credential put api-token "${tenant[@]}" "${trust[@]}" --from-file "$out/stored" || die "$side: the stored credential"

    {
        echo "listen: 127.0.0.1:${dport[$side]}"
        echo "host: test-host"
        echo "stateDir: $d/state"
        echo "capacity: $depth"
        echo "tls: {cert: $pki/server.pem, key: $pki/server.key, clientCA: $pki/ca.pem}"
        echo "network: {mode: tap, guestCIDR: ${block[$side]}${prefix[$side]:+, tapPrefix: ${prefix[$side]}}}"
        echo "vmm:"
        [ "$side" = td ] && [ -S "$quote_socket" ] && echo "  quoteSocket: $quote_socket"
        [ "$side" = sim ] && echo "  simulatedTEE: $tee"
        [ -n "$confine" ] && echo "  confine: \"$confine\""
        [ -n "${guest_cpus[$side]}" ] && echo "  cpus: \"$(kernel_order "${guest_cpus[$side]}")\""
        [ "$dev" = 1 ] && echo "  console: true"
        echo "classes:"
        echo "  s-4x16: {vcpus: 4, memory: 16G, lowMemory: 512M, scratch: 4G}"
        echo "pools:"
        echo "  - imageDir: ${img[$side]}"
        echo "    launchDir: $d/bundle/opkeydata"
        echo "    depth: $depth"
        echo "    imageStore: $store"
        # The orchestrator binds its sessions itself, and may watch the pool. A
        # binder of its own certificate may watch it too, and claim a TD with a
        # bind under the tenant's authority.
        echo "    binders:"
        echo "      - \"$binder\""
        echo "      - {key: \"$own_binder\", authorities: [\"$authority\"]}"
    } > "$d/config.yaml"
    # The daemon's launchers inherit where the daemon keeps to, and start
    # their VMMs on the guests' CPUs, as its configuration says.
    on "${ks_cpus[$side]}" sudo -n "$c" session-daemon run --config "$d/config.yaml" >> "$d/daemon.log" 2>&1 &
    daemon_pid[$side]=$!
}
# What a plain guest's kernel says of clearing its memory: one boot of a
# simulating image that has a console, alone, on the machine a launcher
# builds, until its init runs.
if [ -n "$SIM" ] && [ -n "${C8S_SIM_CONSOLE_IMAGE:-}" ]; then
    con=$(readlink -f "$C8S_SIM_CONSOLE_IMAGE")
    [ -f "$con/SIMULATED-TEE" ] && [ -f "$con/disk.raw" ] || die "C8S_SIM_CONSOLE_IMAGE is no image built with C8S_SIMTEE=1"
    on "$cpus_sim" sudo -n qemu-system-x86_64 -name "guest=c8s-clearing-$run" -nodefaults -no-user-config -nographic -no-reboot \
        -accel kvm -cpu host -smp 4 -m 16384M -monitor none -serial "file:$out/sim/clearing.log" \
        -machine q35,kernel-irqchip=split,sata=off,smbus=off,i8042=off,hpet=off,usb=off,vmport=off \
        -bios "$con/OVMF.tdx.fd" -drive "file=$con/disk.raw,format=raw,if=none,id=root0,readonly=on" \
        -device virtio-blk-pci,drive=root0,bootindex=0,disable-legacy=on > "$out/sim/clearing.out" 2>&1 &
    clearing_pid=$!
    deadline=$(( $(date +%s) + 240 ))
    until grep -a -q "Run /init as init process" "$out/sim/clearing.log" 2>/dev/null; do
        kill -0 "$clearing_pid" 2>/dev/null && [ "$(date +%s)" -lt "$deadline" ] || die "the console image never ran its init: $(tail -c 300 "$out/sim/clearing.out")"
        sleep 0.2
    done
    stop_pid "$clearing_pid"
    python3 - "$out/sim/clearing.log" "$(basename "$con")" <<'CLEAR' >> "$out/sim/timing.jsonl" || die "the console of $con never showed its kernel clearing its memory"
import json, re, sys
stamped = []
for raw in open(sys.argv[1], "rb"):
    found = re.search(rb"\[\s*(\d+\.\d+)\] (.*)", raw)
    if found:
        stamped.append((float(found.group(1)), found.group(2)))
began = next(i for i, (_, said) in enumerate(stamped) if b"clearing system memory" in said)
init = next(at for at, said in stamped if b"Run /init as init process" in said)
record = {"kind": "clearing", "image": sys.argv[2], "vcpus": 4, "mem_mib": 16384}
if stamped[began][0] > 0:
    # The kernel says when it begins, and its next line comes when it is done.
    record["clear_ms"], record["kernel_to_init_ms"] = round((stamped[began + 1][0] - stamped[began][0]) * 1000), round(init * 1000)
else:
    # A kernel stamps its lines with zero until its clock runs, which in
    # some boots is after it has cleared its memory.
    record["untimed"] = "the kernel's clock had not started when it cleared its memory"
print(json.dumps(record))
CLEAR
fi

for side in "${sides[@]}"; do
    stand_up "$side"
done

# A turn begins once every pool is full again, the last sessions' guests are
# gone and no guest boots: taken[<side>] is how many guests its rounds took.
declare -A taken
for side in "${sides[@]}"; do taken[$side]=0; done
pools_full() {
    local side full deadline=$(( $(date +%s) + 600 ))
    while :; do
        full=1
        for side in "${sides[@]}"; do
            kill -0 "${daemon_pid[$side]}" 2>/dev/null || die "the ${label[$side]} side's daemon ended"
            [ "$(grep -c '"msg":"a TD is ready"' "${dir[$side]}/daemon.log" 2>/dev/null)" -ge $(( ${taken[$side]} + depth )) ] || full=0
        done
        [ "$full" = 1 ] && [ "$(pgrep -cf '[q]emu-system.*guest=td-')" = $(( depth * ${#sides[@]} )) ] && return 0
        [ "$(date +%s)" -lt "$deadline" ] || die "the pools never filled"
        sleep 0.5
    done
}

# before-round <n>: a side's rounds wait here for their turn.
for side in "${sides[@]}"; do
    cat > "${dir[$side]}/before-round" <<HOOK
#!/usr/bin/env bash
until [ -e "${dir[$side]}/go.\$1" ]; do
    kill -0 $$ 2>/dev/null || { echo "the run ended" >&2; exit 1; }
    sleep 0.02
done
HOOK
    chmod 0755 "${dir[$side]}/before-round"
done

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
# The quoting service joins the TD side's other programs of the platform,
# in a run that names CPUs.
quoting=${C8S_TIMING_QUOTING:-1}
if [ -z "${ks_cpus[td]}" ]; then
    quoting=""
elif [ "$quoting" = 0 ]; then
    quoting="the run was told to leave it"
elif keep_quoting "${ks_cpus[td]}"; then
    quoting=kept
else
    restore_quoting
    quoting="none was found that the run could move"
fi
field() { # field <manifest> <dotted path>: that value of it
    python3 -c 'import json,sys
v = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): v = v[k]
print(v)' "$1" "$2"
}
others=$(pgrep -a qemu-system | grep -v -c "guest=td-\|guest=c8s-key-service-[a-z]*-$run")
{
    printf 'method: power %s; %s other VMs on the host, and its other programs at %s%% of one CPU over the five seconds before the run (listed below); TDX on in the firmware, for every side; ' \
        "$([ "$pin_power" = 1 ] && echo "pinned (governor performance, idle states past C1E off, turbo on)" || echo "as the host had it")" "$others" "$busy"
    printf 'KVM lets a halted vCPU spin %s ns for a wakeup%s; ' "${halt_polled:-an unknown number of}" "$([ -n "$halt_poll" ] && echo ", set by this run")"
    baseline="not sampled"
    [ -n "$fc" ] && baseline="Firecracker over its serial console (a floor), interleaved"
    [ -n "$fc_agent" ] && baseline="Firecracker over vsock to an agent in its guest, its first command $(first_command) as a session's is, from a snapshot's load, from its leanest guest booted cold and from one booted ahead and idle, and over its serial console (a floor), interleaved"
    printf 'baseline %s; ' "$baseline"
    if [ -n "$SIM" ]; then
        printf 'second baseline: the same start in guests with no TEE and one simulated in software, taking turns with the TD side round by round in an order that alternates, each turn beginning with every pool full and idle; '
    else
        printf 'no second baseline; '
    fi
    [ -n "$cpus_drive" ] && printf 'CPUs: the TD side'"'"'s VMMs %s, the simulated side'"'"'s %s, the platform'"'"'s own programs (each side'"'"'s key service, daemon and launchers%s) %s, Firecracker %s, the programs that drive the rounds %s; ' \
        "$cpus_td" "${cpus_sim:-none}" "$([ "$quoting" = kept ] && echo ", and for the run the host's quoting service")" "$cpus_ks" "$cpus_fc" "$cpus_drive"
    [ -z "$quoting" ] || [ "$quoting" = kept ] || printf 'a departure: the host'"'"'s quoting service ran on the CPUs the host has it on (%s); ' "$quoting"
    [ "$claim_with_bind" = 1 ] && printf 'no claim: each bind claims its TD%s; ' "$([ "$lose_first" = 1 ] && echo ", and a second bind for that TD comes first")"
    printf 'before the measured path: the vendor'"'"'s documents fetched by the binder (timed beside the rounds); %s%s\n' "$([ "$watch" = 1 ] && echo "each ready TD judged when it became ready (timed beside the rounds)" || echo "each TD judged at its claim")" \
        "$([ "$stored" = 1 ] && echo "; the key service's replica judged by the binder, for its binds to name (timed beside the rounds)")"
    echo "run $run, $rounds rounds, $(date -u +%FT%TZ), stored credential $stored, sealed credential $sealed, ready TDs watched $watch, claim with the bind $claim_with_bind, as a binder of its own certificate $as_binder, a second bind first $lose_first, first command with the bind ${C8S_TIMING_WITH_BIND:-1}, quote first ${C8S_TIMING_QUOTE_FIRST:-0}, connection made ahead ${C8S_TIMING_PRECONNECT:-1}, rest $rest s, Firecracker ${fc:-not sampled}"
    echo "host kernel $(uname -r)"
    lscpu | grep -E "Model name|^CPU\(s\)|Thread|Core|Socket" | sed 's/  */ /g'
    echo "power pinned by this run: $pin_power"
    echo "governor $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor) driver $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_driver) turbo $([ -n "$turbo_file" ] && { [ "$(cat "$turbo_file")" = "$turbo_on" ] && echo on || echo off; } || echo unknown)$([ -n "$turbo" ] && echo ", set by this run") preference $(cat /sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference 2>/dev/null)"
    echo "idle states of CPU 0: $(for s in /sys/devices/system/cpu/cpu0/cpuidle/state[0-9]*; do printf '%s%s ' "$(cat "$s/name")" "$([ "$(cat "$s/disable")" = 1 ] && echo '(off)')"; done)"
    echo "kvm_intel.tdx $(cat /sys/module/kvm_intel/parameters/tdx); the TDX module is named at the end, by its measurement in a TD's quote"
    echo "transparent huge pages $(cat /sys/kernel/mm/transparent_hugepage/enabled), defrag $(cat /sys/kernel/mm/transparent_hugepage/defrag)"
    echo "microcode $(grep -m1 microcode /proc/cpuinfo | sed 's/.*: //')"
    qemu-system-x86_64 --version | head -1
    [ -n "$fc" ] && cat "$fc/versions.txt"
    [ -n "$fc_agent" ] && echo "Firecracker's first command runs the sandbox image's shell: $("$fc/busybox" 2>&1 | head -1) sha256 $(sha256sum "$fc/busybox" | cut -c1-64), from $fc_busybox"
    for side in "${sides[@]}"; do
        m=${img[$side]}/manifest.json km=${ksimg[$side]}/manifest.json
        echo "${label[$side]} side: c8s $("${bin[$side]}" --version 2>/dev/null | head -1) sha256 $(sha256sum "${bin[$side]}" | cut -c1-64); warmstart sha256 $(sha256sum "${warm[$side]}" | cut -c1-64)"
        echo "${label[$side]} side: session image $(basename "${img[$side]}") disk sha256 $(field "$m" outputs.disk_image.sha256) kernel image sha256 $(field "$m" outputs.uki.sha256) firmware sha256 $(field "$m" tdx.firmware.sha256) mrtd $(field "$m" tdx.mrtd) rtmr1 $(field "$m" tdx.rtmr1) rtmr2 $(field "$m" tdx.rtmr2) machine ${machine[$side]}"
        echo "${label[$side]} side: key service image $(basename "${ksimg[$side]}") disk sha256 $(field "$km" outputs.disk_image.sha256) kernel image sha256 $(field "$km" outputs.uki.sha256) mrtd $(field "$km" tdx.mrtd) rtmr2 $(field "$km" tdx.rtmr2) machine ${ks_machine[$side]}"
        echo "${label[$side]} side: guest kernel $(field "$m" inputs.kernel.linux_version), guests on taps ${prefix[$side]:-c8st}<n> in ${block[$side]}"
    done
    if [ -n "$SIM" ]; then
        echo "simulated TEE side: a development build (Go build tag c8s_simtee) under the simulated authority in $tee (root sha256 $(openssl x509 -in "$tee/root.pem" -outform DER 2>/dev/null | sha256sum | cut -c1-64)), its documents served at $(cat "$tee/vendor")"
        echo "simulated TEE side: the registers above are declared by each guest's launcher from the image's manifest, after it held the firmware and the disk to the digests there; no hardware measures them. Its quotes are signed in the guest, and its platform is always UpToDate"
        echo "simulated TEE side: the guest's kernel clears all of its memory when it boots, where a TD's accepts and clears memory as it uses it: its time from launch to ready is that work, named with it in the summary"
    fi
    echo "session class 4 vCPUs, 16 GiB; key service 2 vCPUs, 4 GiB; Firecracker guest 4 vCPUs, 16 GiB"
    echo "sandbox image $ref"
    echo "work directory on $(df --output=fstype,source "$out" | tail -1)"
    echo "load $(cat /proc/loadavg)"
    free -g | sed -n 2p
    echo "the host's busiest programs over the five seconds before the run, by share of one CPU:"
    echo "$busiest"
} > "$out/env.txt" 2>&1

records=$out/timing.jsonl
if [ -n "$fc" ]; then
    (on "$cpus_fc" sudo -n python3 "$fc_sample" "$fc" snapshot "$credential_bytes") >> "$records" || die "the Firecracker snapshot"
    if [ -n "$fc_agent" ]; then
        (on "$cpus_fc" sudo -n python3 "$fc_sample" "$fc" lean "$credential_bytes") >> "$records" || die "the lean Firecracker guest"
        (on "$cpus_fc" sudo -n python3 "$fc_sample" "$fc" lean-snapshot) >> "$records" || die "the lean Firecracker guest's snapshot"
    fi
fi
for side in "${sides[@]}"; do
    d=${dir[$side]}
    args=(--daemon "127.0.0.1:${dport[$side]}" --daemon-ca "$pki/ca.pem" --daemon-cert "$pki/orchestrator.pem" --daemon-key "$pki/orchestrator.key"
        --pool agents --image-manifest "${img[$side]}/manifest.json" --launch-key "$d/bundle/opkeydata/pubkey" --authority-key "$out/authority.key"
        --tenant acme --session-prefix "t" --sandbox-image "$ref" --collateral-cache "$d/collateral"
        --rounds "$rounds" --commands 3 --attest --before-round "$d/before-round")
    [ "$stored" = 1 ] && args+=(--key-service "$d/ks-pin.json" --stored-credential api-token)
    [ "$sealed" = 1 ] && args+=(--sealed-credential api-token)
    [ "$watch" = 1 ] || args+=(--watch-ready=false)
    [ "$claim_with_bind" = 1 ] && args+=(--claim-with-bind)
    [ "$lose_first" = 1 ] && args+=(--lose-first)
    if [ "$as_binder" = 1 ]; then
        # The last of a flag given twice is the one that counts.
        args+=(--daemon-cert "$pki/binder.pem" --daemon-key "$pki/binder.key" --orchestrator-cert "$pki/orchestrator.pem" --orchestrator-key "$pki/orchestrator.key")
    fi
    [ "${C8S_TIMING_QUOTE_FIRST:-0}" = 1 ] && args+=(--quote-first)
    [ "${C8S_TIMING_PRECONNECT:-1}" = 0 ] && args+=(--preconnect=false)
    [ "${C8S_TIMING_WITH_BIND:-1}" = 0 ] && args+=(--command-with-bind=false)
    if [ "$side" = sim ]; then
        args+=(--simulated-tee "$tee")
    elif [ -n "${C8S_ACCEPT_TCB:-}" ]; then
        args+=(--accept-tcb-status "$C8S_ACCEPT_TCB")
    fi
    on "$cpus_drive" "${warm[$side]}" "${args[@]}" >> "$d/timing.jsonl" 2> "$d/warmstart.err" &
    warm_pid[$side]=$!
done

# The rounds. Each side's turn begins with every pool full and idle and the
# host rested, and the side that goes first alternates. The baseline's
# samples come once a round, before the first turn.
for (( n = 0; n < rounds; n++ )); do
    order=("${sides[@]}")
    [ ${#sides[@]} = 2 ] && (( n % 2 == 1 )) && order=("${sides[1]}" "${sides[0]}")
    first=1
    for side in "${order[@]}"; do
        pools_full
        sleep "$rest"
        if [ "$first" = 1 ] && [ -n "$fc" ]; then
            (on "$cpus_fc" sudo -n python3 "$fc_sample" "$fc" cold) >> "$records" || die "a Firecracker cold boot"
            (on "$cpus_fc" sudo -n python3 "$fc_sample" "$fc" load) >> "$records" || die "a Firecracker snapshot load"
            if [ -n "$fc_agent" ]; then
                (on "$cpus_fc" sudo -n python3 "$fc_sample" "$fc" load-vsock) >> "$records" || die "a Firecracker snapshot load over vsock"
                (on "$cpus_fc" sudo -n python3 "$fc_sample" "$fc" lean-load) >> "$records" || die "a load of the lean Firecracker guest's snapshot"
                (on "$cpus_fc" sudo -n python3 "$fc_sample" "$fc" lean-cold) >> "$records" || die "a cold boot of the lean Firecracker guest"
                (on "$cpus_fc" sudo -n python3 "$fc_sample" "$fc" lean-pool "$rest") >> "$records" || die "a start from a Firecracker guest booted ahead"
            fi
            sleep 1
        fi
        first=0
        d=${dir[$side]}
        : > "$d/go.$n"
        deadline=$(( $(date +%s) + 400 ))
        until [ "$(grep -c '"kind":"session"' "$d/timing.jsonl" 2>/dev/null)" -gt "$n" ]; do
            kill -0 "${warm_pid[$side]}" 2>/dev/null || die "the ${label[$side]} side's rounds ended at round $n: $(tail -c 400 "$d/warmstart.err")"
            [ "$(date +%s)" -lt "$deadline" ] || die "the ${label[$side]} side's round $n never ended"
            sleep 0.05
        done
        taken[$side]=$(( ${taken[$side]} + per_round ))
    done
done
for side in "${sides[@]}"; do
    wait "${warm_pid[$side]}" || die "the ${label[$side]} side's rounds: $(tail -c 400 "${dir[$side]}/warmstart.err")"
    warm_pid[$side]=""
done
# What a ready guest costs its host while nobody asks anything of it: the
# CPU time of each pooled guest's VMM, its vCPUs and its device threads
# among it, over a stretch with every pool full.
if [ "$idle" -gt 0 ]; then
    pools_full
    sleep "$rest"
    watchers=()
    for side in "${sides[@]}"; do
        python3 - "$idle" "${dir[$side]}/state" <<'IDLE' >> "${dir[$side]}/timing.jsonl" &
import json, os, sys, time
seconds, state = float(sys.argv[1]), sys.argv[2]
def processes():
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                args = f.read().split(b"\0")
            with open(f"/proc/{pid}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
        except OSError:
            continue
        # After the name: state, parent, ..., and user and system time as
        # the 12th and 13th.
        yield int(pid), [a.decode(errors="replace") for a in args], int(fields[1]), int(fields[11]) + int(fields[12])
def guests():
    """The VMMs whose launchers work under this daemon's state directory."""
    everything = list(processes())
    launchers = {pid for pid, args, _, _ in everything
                 if "session-launcher" in args and any(a.startswith(state + "/") for a in args) and not os.path.basename(args[0]).startswith("sudo")}
    return {pid: ticks for pid, args, parent, ticks in everything if parent in launchers and "qemu" in os.path.basename(args[0])}
before, began = guests(), time.monotonic()
time.sleep(seconds)
after, took = guests(), time.monotonic() - began
tick = os.sysconf("SC_CLK_TCK")
for pid in sorted(before):
    if pid in after:
        print(json.dumps({"kind": "idle", "vmm": pid, "seconds": round(took, 1),
                          "cpu_ms_per_s": round((after[pid] - before[pid]) * 1000 / tick / took, 2)}))
IDLE
        watchers+=($!)
    done
    # These alone: the daemons and the key services are this shell's too.
    wait "${watchers[@]}"
fi
restore_power

# How long each guest took from its launch to ready, and in parts where its
# launcher's log has them: what came before its VMM started, with the time a
# simulated guest's launcher took to hold the image to its manifest; the
# VMM's start to the guest's ask of its host for the vendor's documents; and
# that ask to ready.
for side in "${sides[@]}"; do
    sudo -n python3 - "${dir[$side]}" <<'COLD' >> "${dir[$side]}/timing.jsonl"
import datetime, json, os, re, sys
d = sys.argv[1]
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
for ready in entries(os.path.join(d, "daemon.log")):
    if ready["msg"] != "a TD is ready":
        continue
    record = {"kind": "session-cold", "td": ready.get("td"), "boot_ms": ready["boot_ms"]}
    started = asked = None
    said = []
    for entry in entries(os.path.join(d, "state", "tds", str(ready.get("td")), "launcher.log")):
        if entry["msg"].startswith("this guest runs in no TEE") and "checked_ms" in entry:
            record["checked_ms"] = entry["checked_ms"]
        elif entry["msg"] == "starting guest":
            started = at(entry)
        elif entry["msg"].startswith("answered the guest with") and asked is None:
            asked = at(entry)
        # What a guest with a console says of its own bind and of the quote
        # it took beside it, each in parts.
        elif entry["msg"] in guest_said:
            said.append({"kind": guest_said[entry["msg"]], "td": ready.get("td"),
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
done
echo "load at the end $(cat /proc/loadavg)" >> "$out/env.txt"
# The TDX module, as the TD side's quotes name it: this host's kernel states
# no version of it.
echo "TDX module MRSEAM $(grep -o '"tdx_module_mrseam":"[0-9a-f]*"' "$records" | sort -u | cut -d'"' -f4 | tr '\n' ' ')" >> "$out/env.txt"
summary=("$records")
[ -n "$SIM" ] && summary+=("$out/sim/timing.jsonl")
python3 - "${summary[@]}" <<'EOF' | tee "$out/summary.txt"
import json, statistics, sys
read = lambda path: [json.loads(line) for line in open(path) if line.strip()]
sides = [("TD", read(sys.argv[1]))] + ([("simulated TEE", read(sys.argv[2]))] if len(sys.argv) > 2 else [])
def show(label, values, unit):
    values = sorted(values)
    if not values:
        return
    p = lambda q: values[min(len(values) - 1, int(q * len(values)))]
    print(f"{label:34} n={len(values):3}  median {statistics.median(values):9.1f}  p90 {p(0.9):9.1f}  min {values[0]:9.1f}  max {values[-1]:9.1f}  {unit}")
# A round that a refresh of the vendor's documents ran beside, on either
# side, is named and left out: the refresh is no part of a start.
refreshes = [r for _, rows in sides for r in rows if r.get("kind") == "refresh"]
def beside(r):
    end = r["at_unix_us"] + max(r.get("first_cmd_us", 0), r.get("confirmed_us", 0))
    return any(f["at_unix_us"] < end and f["at_unix_us"] + f["took_us"] > r["at_unix_us"] for f in refreshes)
keys = ("claim_us", "ready_check_us", "members_us", "sign_us", "seal_us", "bind_us", "judge_us", "start_us", "first_exec_us", "first_cmd_us", "quote_us", "confirmed_us", "attest_us", "destroy_us")
# A first command sent over a connection: that connection in parts, wherever
# it was made, and the command's own request on it.
parts = ("conn_dial_us", "conn_handshake_us", "conn_serving_verdict_us", "first_request_us")
medians = {}
for name, rows in sides:
    if len(sides) > 1:
        print(f"--- the {name} side")
    sessions = [r for r in rows if r.get("kind") == "session" and r["round"] > 0]
    steady = [r for r in sessions if not beside(r)]
    for key in keys:
        values = [r[key] / 1000 for r in steady if r.get(key)]
        show("session " + key[:-3], values, "ms")
        if values:
            medians.setdefault(key, {})[name] = statistics.median(values)
    for key in parts:
        show("session " + key[:-3], [r[key] / 1000 for r in steady if r.get(key)], "ms")
    # A guest with a console says how long its bind took in parts, each from
    # the bind's arrival, and the quote it took beside it. The first round's
    # guest is among them.
    for kind, label in (("guest-bind", "guest's bind, to "), ("guest-quote", "guest's quote: "), ("guest-call", "guest's bind and what followed: "),
                        ("guest-prepared", "guest's first second prepared: ")):
        told = [r for r in rows if r.get("kind") == kind]
        for key in dict.fromkeys(k for r in told for k in r if k not in ("kind", "td")):
            values = [r[key] for r in told if key in r]
            if key.endswith("_us"):
                show(label + key[:-3], [v / 1000 for v in values], "ms (the guest's own clock)")
            else:
                show(label + key, values, "(the guest's own count)")
    show("session lost to a bind that came first", [r["lost_us"] / 1000 for r in steady if r.get("lost_us")], "ms (a sign, a seal and a round trip; part of the start)")
    if steady:
        count = lambda key: sum(1 for r in steady if r.get(key))
        if count("claimed_by_bind"):
            print(f"of {len(steady)} rounds, the bind claimed its TD with no claim before it in {count('claimed_by_bind')}, and found that TD taken first in {count('not_ready')}")
        print(f"of {len(steady)} rounds, the guest took the first command with its bind in {count('with_bind')}, the command's answer was taken on the receipt in {count('on_receipt')}, and the connection for commands was made ahead in {count('reached_ahead')}; the quote came with the bind's answer in {count('quote_in_answer')}"
              + (f", and this side asked the daemon for it in {count('quote_asked')}" if count("quote_asked") else ""))
        print(f"of {len(steady)} rounds, the guest was judged before its claim in {count('ready_ahead')}, and had a credential sealed with its bind in place in {count('credential_with_bind')}")
    show("ready TD judged ahead", [r["ready_judged_us"] / 1000 for r in steady if r.get("ready_judged_us")], "ms (before the round: no part of its times)")
    show("vendor documents fetched", [r["took_us"] / 1000 for r in rows if r.get("kind") == "documents"], "ms (before the rounds: no part of their times)")
    members = [r for r in rows if r.get("kind") == "members"]
    show("key service replica judged", [r["took_us"] / 1000 for r in members if not r.get("error")], "ms (before the rounds, and beside them when it failed: no part of their times)")
    if any(r.get("error") for r in members):
        print(f"{sum(1 for r in members if r.get('error'))} judgments of the key service's replica failed: {next(r['error'] for r in members if r.get('error'))}")
    show("vendor documents refreshed", [r["took_us"] / 1000 for r in rows if r.get("kind") == "refresh"], "ms (beside the rounds)")
    if len(sessions) != len(steady):
        print(f"{len(sessions) - len(steady)} rounds ran beside a refresh of the vendor's documents and are left out: rounds {', '.join(str(r['round']) for r in sessions if beside(r))}")
    show("session later command", [v / 1000 for r in steady for v in r.get("exec_us", [])], "ms")
    first = [r for r in rows if r.get("kind") == "session" and r["round"] == 0]
    if first:
        print(f"the first round, caches cold: start {first[0]['start_us'] / 1000:.1f} ms, first command {first[0]['first_cmd_us'] / 1000:.1f} ms")
    cold = [r for r in rows if r.get("kind") == "session-cold"]
    show("session guest launch to ready", [r["boot_ms"] for r in cold], "ms" + (" (its kernel clears all of its memory first)" if name != "TD" else ""))
    show("  before the VMM starts", [r["before_vmm_ms"] for r in cold if "before_vmm_ms" in r], "ms")
    show("    its launcher's check", [r["checked_ms"] for r in cold if "checked_ms" in r], "ms (it holds the firmware and the disk to the image's manifest: no launcher of a TD does)")
    show("  VMM start to documents asked", [r["vmm_to_documents_ms"] for r in cold if "vmm_to_documents_ms" in r], "ms (the guest's first ask of its host)")
    show("  documents asked to ready", [r["documents_to_ready_ms"] for r in cold if "documents_to_ready_ms" in r], "ms")
    show("a plain guest's kernel clearing", [r["clear_ms"] for r in rows if r.get("kind") == "clearing" and "clear_ms" in r],
         "ms for 16 GiB (one boot of the console image, alone, by its kernel's log: part of each launch above)")
    show("ready guest, idle", [r["cpu_ms_per_s"] for r in rows if r.get("kind") == "idle"], "ms of CPU a second, its VMM's with its vCPUs and device threads")
    for r in rows:
        if r.get("kind") == "tee" and r.get("simulated"):
            print(f"this side's guests ran in no TEE: build tag {r['build_tag']}, authority {r['authority']} (root sha256 {r['root']})")
if len(sides) > 1:
    print("--- what the hardware and the vendor's quoting add: the TD side's median less the simulated side's")
    for key in keys:
        both = medians.get(key, {})
        if len(both) == 2:
            td, sim = both["TD"], both["simulated TEE"]
            print(f"{'session ' + key[:-3]:34} {td - sim:+9.1f} ms  (TD {td:.1f}, simulated {sim:.1f})")
rows = sides[0][1]
show("Firecracker snapshot made", [r["snapshot_create_ms"] for r in rows if r.get("kind") == "fc-snapshot"], "ms (before the rounds, after a cold boot: no part of their times)")
for r in rows:
    if r.get("kind") == "fc-snapshot" and r.get("first_command"):
        said = "Firecracker's first command over vsock: " + " ".join(r["first_command"])
        if r.get("credential_bytes"):
            said += f" (a file of {r['credential_bytes']} bytes on a read-only drive, unread before; its shell is busybox sha256 {r['shell_sha256']}, read into the guest's memory before the snapshot)"
        print(said)
for kind, label, how in (("fc-cold", "Firecracker cold", "serial console: a floor"), ("fc-load", "Firecracker snapshot load", "serial console: a floor"),
                         ("fc-load-vsock", "Firecracker snapshot load", "vsock to an agent in the guest")):
    show(label + " to first command", [r.get("first_cmd_us", r["first_cmd_ms"] * 1000) / 1000 for r in rows if r.get("kind") == kind], f"ms ({how})")
show("Firecracker later command", [r["next_cmd_us"] / 1000 for r in rows if r.get("next_cmd_us") and r.get("kind") == "fc-load-vsock"], "ms (vsock to an agent in the guest)")
for r in rows:
    if r.get("kind") == "fc-lean":
        print(f"Firecracker's lean guest: the agent as init on {'the sandbox image' if r.get('image') else 'the session shell'}'s own tree, {r['bytes']} bytes, booted with: {r['boot_args']}")
show("Firecracker lean snapshot's load", [r["first_cmd_us"] / 1000 for r in rows if r.get("kind") == "fc-lean-load"], "ms (VMM start to the first command's answer, over vsock: the snapshot baseline at its strongest)")
show("  its later command", [r["next_cmd_us"] / 1000 for r in rows if r.get("kind") == "fc-lean-load"], "ms (on a connection of its own)")
show("Firecracker lean guest, cold", [r["first_cmd_us"] / 1000 for r in rows if r.get("kind") == "fc-lean-cold"], "ms (VMM start to the first command's answer, over vsock)")
show("  of which to its agent serving", [r["agent_up_us"] / 1000 for r in rows if r.get("kind") == "fc-lean-cold"], "ms")
pooled = [r for r in rows if r.get("kind") == "fc-lean-pool"]
show("Firecracker start, booted ahead", [r["start_us"] / 1000 for r in pooled], f"ms (one message to an idle guest's agent, on a connection made ahead, to the first command's answer; idle {pooled[0]['idle_s'] if pooled else 0:g} s)")
show("  its later command", [r["next_cmd_us"] / 1000 for r in pooled], "ms (on a connection of its own)")
EOF
head -1 "$out/env.txt" | tee -a "$out/summary.txt"
