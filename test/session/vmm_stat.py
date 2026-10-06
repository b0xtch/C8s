#!/usr/bin/env python3
"""What the VMMs of one side of a burst have cost their host so far.

    vmm_stat.py <side> <when> <burst> <text in the VMMs' command lines> [seconds]

It prints one JSON object on a line, summed over every process whose command
line holds the text: how long its vCPU threads and its other threads ran and
how long they waited for a CPU, as the scheduler counts both; the same
threads' CPU time as the kernel samples it, apart as user (of which in the
guest) and system; the memory the processes hold resident, which is a plain
guest's memory and none of a TD's private pages; and what KVM counts for its
VM, such as exits by kind, page faults it resolved and pages it has mapped;
and how the host schedules them: the vCPU threads by scheduling class and by
how many CPUs each may run on, and how many VMMs have a core-scheduling
cookie of their own on every thread, so that no core's two threads run two
guests at once.
With them goes what the host has available and holds unevictable, where it
counts the private pages of TDs; all the CPU the host has given so far, by
the kernel's count at the root of its control groups, and what this program
has taken of it; and what the programs that work for the guests have run, by
kind: the kernel's own threads, the quoting service, the session daemon and
the launchers.
test/session/burst.sh takes it when a burst's last first command has
answered, and before the burst: the difference, by the sessions, is what a
start costs on a side.

With "quiet" for <when> it is the one before the burst, and waits for the
side's guests to be idle by these counters first: it takes them every second
until, for two seconds running, no guest's VMM ran more than QUIET_RUN_MS in
the second and none resolved more than QUIET_FAULTS page faults. It prints
the last two as "idle" and "before", and how long the guests took to come to
rest. Guests that are not quiet after so many seconds, LIMIT unless it is
given some, fail it, and the failure names the busiest's process.

It runs as root: KVM's counters are in debugfs.
"""
import ctypes
import glob
import json
import os
import sys
import time

# What a guest may still do in a second and count as idle: so much of its
# VMM's threads running, in all, and so many page faults resolved.
QUIET_RUN_MS = 10
QUIET_FAULTS = 16
LIMIT = 180

# KVM's counters that are kept, of those it has for a VM: exits by kind, the
# page faults it took and resolved, the pages mapped now, by size, and how
# long halted vCPUs spun for a wakeup before they gave up their CPU.
COUNTERS = ("exits", "halt_exits", "halt_wakeup", "io_exits", "mmio_exits", "irq_exits", "hypercalls", "signal_exits",
            "pf_taken", "pf_fixed", "pages_4k", "pages_2m", "pages_1g", "preemption_reported",
            "halt_attempted_poll", "halt_successful_poll", "halt_poll_success_ns", "halt_poll_fail_ns", "halt_wait_ns")
TICK = os.sysconf("SC_CLK_TCK")
PAGE_KB = os.sysconf("SC_PAGE_SIZE") // 1024
# The scheduling classes by the number the kernel gives each.
CLASSES = {0: "SCHED_OTHER", 1: "SCHED_FIFO", 2: "SCHED_RR", 3: "SCHED_BATCH", 5: "SCHED_IDLE", 6: "SCHED_DEADLINE", 7: "SCHED_EXT"}
# prctl's request for a thread's core-scheduling cookie.
PR_SCHED_CORE, PR_SCHED_CORE_GET = 62, 0


def vcpu(name, guest):
    """Whether a thread is a vCPU's: one named as QEMU's or Firecracker's, or
    one that has run a guest, since QEMU names its threads only when asked."""
    return guest > 0 or name.startswith("CPU ") and name.endswith("/KVM") or name.startswith("fc_vcpu")


def threads(pid):
    """Each thread of a process: its name, and what it ran and waited."""
    for task in glob.glob(f"/proc/{pid}/task/[0-9]*"):
        try:
            with open(task + "/stat") as f:
                name, fields = f.read().rsplit(")", 1)
            with open(task + "/schedstat") as f:
                ran, waited, _ = f.read().split()
        except (OSError, ValueError):
            continue
        fields = fields.split()
        # After the name: user and system time as the 12th and 13th, and the
        # time in a guest, which user time includes, as the 41st, in ticks.
        yield name.split("(", 1)[1], int(ran), int(waited), int(fields[11]), int(fields[12]), int(fields[40])


def cookie(libc, tid):
    """A thread's core-scheduling cookie: 0 for none, and nothing where the
    kernel has no core scheduling or the thread is gone."""
    if libc is None:
        return None
    value = ctypes.c_ulonglong()
    if libc.prctl(PR_SCHED_CORE, PR_SCHED_CORE_GET, tid, 0, ctypes.addressof(value)) != 0:
        return None
    return value.value


def placed(pids):
    """How the host schedules the VMMs: their vCPU threads by class and by
    the CPUs each may run on, and the VMMs whose every thread has one cookie
    that no other VMM has."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    except (OSError, AttributeError):
        libc = None
    classes, cpus, cookies, known = {}, {}, {}, libc is not None
    for pid in pids:
        mine = set()
        for task in glob.glob(f"/proc/{pid}/task/[0-9]*"):
            tid = int(os.path.basename(task))
            try:
                with open(task + "/stat") as f:
                    name, fields = f.read().rsplit(")", 1)
                guest = int(fields.split()[40])
                if vcpu(name.split("(", 1)[1], guest):
                    kind = os.sched_getscheduler(tid) & ~0x40000000
                    kind = CLASSES.get(kind, str(kind))
                    classes[kind] = classes.get(kind, 0) + 1
                    count = str(len(os.sched_getaffinity(tid)))
                    cpus[count] = cpus.get(count, 0) + 1
            except (OSError, ValueError, IndexError):
                continue
            mine.add(cookie(libc, tid))
        cookies[pid] = mine
    if any(None in mine for mine in cookies.values()):
        known = False
    held = [next(iter(mine)) for mine in cookies.values() if len(mine) == 1 and next(iter(mine))]
    apart = sum(1 for c in held if held.count(c) == 1) if known else None
    return {"vcpu_classes": classes, "vcpu_cpus": cpus, "vmms_apart": apart}


def taken(side, when, burst, text):
    """One reading of the side's VMMs, and what each of them ran and faulted."""
    kinds = {kind: {"ran_us": 0, "waited_us": 0, "user_us": 0, "guest_us": 0, "system_us": 0, "threads": 0} for kind in ("vcpu", "other")}
    kvm = dict.fromkeys(COUNTERS, 0)
    vmms = resident_kb = 0
    each = {}
    groups = dict.fromkeys(GROUPS, 0)
    at, given = time.time_ns() // 1000, host_cpu()
    # This program is started with the text too, and so is what started it.
    own = started_by()
    for entry in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                line = f.read().replace(b"\0", b" ").decode(errors="replace")
        except OSError:
            continue
        if int(entry) in own:
            continue
        if text not in line:
            group = grouped(entry, line)
            if group:
                groups[group] += sum(ran for _, ran, *_ in threads(entry)) // 1000
            continue
        vmms += 1
        mine = [0, 0]
        try:
            with open(f"/proc/{entry}/statm") as f:
                resident_kb += int(f.read().split()[1]) * PAGE_KB
        except (OSError, ValueError, IndexError):
            pass
        for name, ran, waited, user, system, guest in threads(entry):
            kind = kinds["vcpu" if vcpu(name, guest) else "other"]
            kind["threads"] += 1
            mine[0] += ran // 1000
            kind["ran_us"] += ran // 1000
            kind["waited_us"] += waited // 1000
            kind["user_us"] += user * 1000000 // TICK
            kind["guest_us"] += guest * 1000000 // TICK
            kind["system_us"] += system * 1000000 // TICK
        for vm in glob.glob(f"/sys/kernel/debug/kvm/{entry}-*"):
            for counter in COUNTERS:
                try:
                    with open(f"{vm}/{counter}") as f:
                        count = int(f.read())
                except (OSError, ValueError):
                    continue
                kvm[counter] += count
                if counter == "pf_fixed":
                    mine[1] += count
        each[entry] = mine
    return {"kind": "vmm-stat", "side": side, "when": when, "round": burst, "vmms": vmms, **kinds, "kvm": kvm,
            "resident_kb": resident_kb, **host_memory(), "t_us": at, "host_cpu_us": given,
            "own_cpu_us": time.process_time_ns() // 1000, "groups_ran_us": groups}, each


# The kinds of program that work for a side's guests, beside their VMMs.
GROUPS = ("kernel", "quoting", "daemon", "launchers")


def grouped(pid, line):
    """The kind of a process that is no VMM of the side, or nothing."""
    if not line:
        # A thread of the kernel's has no command line, and kthreadd started it.
        try:
            with open(f"/proc/{pid}/stat") as f:
                parent = f.read().rsplit(")", 1)[1].split()[1]
        except (OSError, IndexError):
            return None
        return "kernel" if parent == "2" or pid == "2" else None
    program = os.path.basename(line.split(" ", 1)[0])
    if program in ("qgs", "aesm_service"):
        return "quoting"
    if " session-daemon run" in line:
        return "daemon"
    if " session-launcher run" in line:
        return "launchers"
    return None


def host_cpu():
    """All the CPU the host has given so far, in us, or nothing where the
    kernel does not say."""
    try:
        with open("/sys/fs/cgroup/cpu.stat") as f:
            for line in f:
                name, _, value = line.partition(" ")
                if name == "usage_usec":
                    return int(value)
    except (OSError, ValueError):
        pass
    return None


def started_by():
    """This process and each one above it, up to the first of the system."""
    found, pid = set(), os.getpid()
    while pid > 1 and pid not in found:
        found.add(pid)
        try:
            with open(f"/proc/{pid}/stat") as f:
                pid = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return found


def named(pid):
    """A process as a failure names it: its id and the start of its command line."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f"process {pid}: " + f.read(160).replace(b"\0", b" ").decode(errors="replace").strip()
    except OSError:
        return f"process {pid}, gone since"


def host_memory():
    """What the host has available and what it holds unevictable, in kB."""
    found = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                name, _, rest = line.partition(":")
                if name in ("MemAvailable", "Unevictable"):
                    found["host_" + name.lower() + "_kb"] = int(rest.split()[0])
    except (OSError, ValueError, IndexError):
        pass
    return found


def main():
    side, when, burst, text = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    limit = int(sys.argv[5]) if len(sys.argv) > 5 else LIMIT
    if when != "quiet":
        now, now_each = taken(side, when, burst, text)
        print(json.dumps(dict(now, placed=placed(now_each))))
        return
    began, quiet = time.monotonic(), 0
    was, was_each = taken(side, "idle", burst, text)
    while True:
        time.sleep(1)
        now, now_each = taken(side, "before", burst, text)
        # A guest that came or went in the second was not idle through it.
        busiest = [0, 0] if was_each.keys() == now_each.keys() else [QUIET_RUN_MS * 1000 + 1, 0]
        who = "one that came or went in the second" if busiest[0] else ""
        for vmm, (ran, faults) in now_each.items():
            before = was_each.get(vmm, (ran, faults))
            if ran - before[0] > busiest[0]:
                who = named(vmm)
            busiest = [max(busiest[0], ran - before[0]), max(busiest[1], faults - before[1])]
        quiet = quiet + 1 if busiest[0] <= QUIET_RUN_MS * 1000 and busiest[1] <= QUIET_FAULTS else 0
        waited = time.monotonic() - began
        if quiet >= 2:
            break
        if waited > limit:
            sys.exit(f"the {side} side's guests were not idle after {limit} s: in the last second one's VMM ran {busiest[0] / 1000:.1f} ms ({who}) and one resolved {busiest[1]} page faults")
        was, was_each = dict(now, when="idle"), now_each
    print(json.dumps(was))
    # How the guests are placed is read once they are idle: after the reading
    # the burst's cost is counted from.
    print(json.dumps(dict(now, placed=placed(now_each))))
    print(json.dumps({"kind": "vmm-quiet", "side": side, "round": burst, "vmms": now["vmms"], "waited_s": round(waited, 1),
                      "busiest_ran_ms": round(busiest[0] / 1000, 2), "busiest_faults": busiest[1]}))


if __name__ == "__main__":
    main()
