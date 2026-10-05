#!/usr/bin/env python3
"""What the VMMs of one side of a burst have cost their host so far.

    vmm_stat.py <side> <when> <burst> <text in the VMMs' command lines>

It prints one JSON object on a line, summed over every process whose command
line holds the text: how long its vCPU threads and its other threads ran and
how long they waited for a CPU, as the scheduler counts both; the same
threads' CPU time as the kernel samples it, apart as user (of which in the
guest) and system; and what KVM counts for its VM, such as exits by kind,
page faults it resolved and pages it has mapped. test/session/burst.sh takes
it when a burst's last first command has answered, and before the burst:
the difference, by the sessions, is what a start costs on a side.

With "quiet" for <when> it is the one before the burst, and waits for the
side's guests to be idle by these counters first: it takes them every second
until, for two seconds running, no guest's VMM ran more than QUIET_RUN_MS in
the second and none resolved more than QUIET_FAULTS page faults. It prints
the last two as "idle" and "before", and how long the guests took to come to
rest. Guests that are not quiet after LIMIT seconds fail it.

It runs as root: KVM's counters are in debugfs.
"""
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


def taken(side, when, burst, text):
    """One reading of the side's VMMs, and what each of them ran and faulted."""
    kinds = {kind: {"ran_us": 0, "waited_us": 0, "user_us": 0, "guest_us": 0, "system_us": 0, "threads": 0} for kind in ("vcpu", "other")}
    kvm = dict.fromkeys(COUNTERS, 0)
    vmms = 0
    each = {}
    for entry in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                line = f.read().replace(b"\0", b" ").decode(errors="replace")
        except OSError:
            continue
        # This program is started with the text too, and so is what started it.
        if text not in line or "vmm_stat.py" in line:
            continue
        vmms += 1
        mine = [0, 0]
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
    return {"kind": "vmm-stat", "side": side, "when": when, "round": burst, "vmms": vmms, **kinds, "kvm": kvm}, each


def main():
    side, when, burst, text = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    if when != "quiet":
        print(json.dumps(taken(side, when, burst, text)[0]))
        return
    began, quiet = time.monotonic(), 0
    was, was_each = taken(side, "idle", burst, text)
    while True:
        time.sleep(1)
        now, now_each = taken(side, "before", burst, text)
        # A guest that came or went in the second was not idle through it.
        busiest = [0, 0] if was_each.keys() == now_each.keys() else [QUIET_RUN_MS * 1000 + 1, 0]
        for vmm, (ran, faults) in now_each.items():
            before = was_each.get(vmm, (ran, faults))
            busiest = [max(busiest[0], ran - before[0]), max(busiest[1], faults - before[1])]
        quiet = quiet + 1 if busiest[0] <= QUIET_RUN_MS * 1000 and busiest[1] <= QUIET_FAULTS else 0
        waited = time.monotonic() - began
        if quiet >= 2:
            break
        if waited > LIMIT:
            sys.exit(f"the {side} side's guests were not idle after {LIMIT} s: in the last second one's VMM ran {busiest[0] / 1000:.1f} ms and one resolved {busiest[1]} page faults")
        was, was_each = dict(now, when="idle"), now_each
    print(json.dumps(was))
    print(json.dumps(now))
    print(json.dumps({"kind": "vmm-quiet", "side": side, "round": burst, "vmms": now["vmms"], "waited_s": round(waited, 1),
                      "busiest_ran_ms": round(busiest[0] / 1000, 2), "busiest_faults": busiest[1]}))


if __name__ == "__main__":
    main()
