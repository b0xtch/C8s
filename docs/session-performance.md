# Session performance

Status: design. This document sets the bar, names the floors, and fixes how
the numbers are taken. The first numbers taken under its rules are in
[Results](#results); every other row waits for its run.

## The bar

Confidential sessions should match a microVM platform running on the same
hardware with confidential computing off, on everything users see: how fast a
session starts and resumes, how fast its first command answers, how many
sessions a host holds, and how fast work runs inside one. The baseline is
stock Firecracker on a host with TDX off. Where hardware sets a floor, the
floor is measured and published beside the number, rather than hidden in it.

Every milestone meets the bar for what it delivers before it is done, against
the best existing system for that, not only Firecracker: a seal against
Firecracker's snapshots and gVisor's checkpoint, continuous mode against
QEMU's COLO, a move between hosts against live migration. The rows below
name each baseline.

## Where hardware sets a floor

| Floor | Why | What narrows it |
|---|---|---|
| memory bandwidth | every access to private memory is encrypted | nothing in software; measured and published |
| TLB-heavy work | the host maps a TD's private memory in 4 KiB pages today | 2 MiB private mappings, which are on their way into KVM and the VMMs |
| network and storage at CPU saturation | device DMA goes through bounce buffers in shared memory, so every byte is copied once more | larger and fewer copies; trusted device I/O later |
| density | TDs share no memory with one another (no same-page merging, no deduplication), memory must be accepted before use, and the platform's key IDs bound how many TDs a host runs | the tenant VM for many small sessions, accepting memory on use, and giving free memory back |
| cold boot | a TD accepts its private memory 4 KiB at a time before using it, and its kernel must accept the memory that maps its memory before it runs, a share that grows with the TD | accepting nothing ahead of use, and 2 MiB private pages, which would be accepted 2 MiB at a time |

## How sessions hide the rest

- **Warm pools.** A TD boots before anyone asks for it, so a start is a claim,
  which the daemon answers from its own record, and a bind, one round trip to
  the guest that can carry the first command and the credentials the binder
  holds, plus the binder's check, which it can make before the claim, as each
  TD becomes ready. A binder that has made it can skip the claim too, since
  its bind claims the TD it names. Boot time still matters for how fast a pool
  refills after a burst.
- **Hold keeps memory.** A release restarts the vCPUs and renews the lease;
  nothing is read back.
- **Lazy restore.** A restored session runs before its seal has been read
  whole, as it touches its pages.
- **Layers.** A commit is an atomic snapshot and never stops the sandbox, and
  a seal copies memory while the sandbox still runs, so its freeze covers only
  the pages written after. Both write only what changed since the last layer,
  and placing a seal on a slot shares or maps blocks rather than copying them
  where the store allows.
- **Continuous mode.** A seal is the last epoch, so a seal or a move to
  another host takes about an epoch, whatever the session's size, and the
  loss of a host costs an epoch and a restore. The price is a wait on every
  output, up to an epoch and a commit.
- **Templates.** A forked session starts with its repositories cloned and its
  dependencies installed.

## Levers

- **Accept memory on use.** The guest accepts private memory as it needs it
  and nothing ahead, which takes a change to the guest kernel, since stock
  Linux accepts well ahead of need until its watermarks are set. A pooled TD
  then costs the host only what it has touched.
- **Give free memory back.** A TD's private memory returns to its host only
  when the guest converts it to shared, which stock Linux does for no free
  memory, so this too takes a change to the guest kernel: it converts free
  blocks to shared, so the host can reclaim them, and accepts them again,
  zeroed, when it needs them.
- **A trimmed guest.** Firmware built from source for TDs, no boot loader
  between it and the kernel image, a bounce buffer sized to the work, fewer
  devices and drivers, and a smaller kernel and user space boot faster, idle
  cheaper and leave less to attack.
- **The tenant VM.** Many small, mostly idle sessions of one owner share one
  TD behind gVisor, which costs far less memory per session than a TD each.
- **Polling** where latency matters, such as the guest's halt polling, turned
  on through the measured command line.
- **Host-side pre-faulting** of private memory before a bind, which is safe
  because added pages stay pending until the guest accepts them.
- **Reflinks.** The daemon keeps its store of layers and the slots' backing
  files on one XFS or btrfs file system, so placing a seal or a template is a
  reflink rather than a copy. On another file system it maps the layers into
  the `in` slot with device-mapper ([The seal
  slots](session-state.md#the-seal-slots)).
- **Another VMM.** libkrun or Cloud Hypervisor may replace QEMU if they
  support TDX and win on these numbers.

Each lever must keep the rules in
[session-threat-model.md](session-threat-model.md#optimizations-that-must-not-weaken-the-model).

## What to measure

| Metric | Baseline | Session VM |
|---|---|---|
| cold boot | Firecracker boot to a ready guest | TD launch to a ready, unbound guest |
| a boot, in parts | Firecracker's boot, in parts | the firmware's memory acceptance and its waits, loading and measuring the kernel image, the kernel's memory acceptance, bounce buffer and devices, the initrd, user space and the agent, the session with the key service that brings the vendor's documents, and the CPU time the boot burns on every vCPU |
| warm activation | snapshot load to the first command; from a pool of VMs booted ahead, the claim to the first command | claim, if any, and bind to the first command |
| a start, in parts | none | the claim, unless the bind makes it; the binder's check of the ready evidence, or finding the verdict it reached before the claim; signing and sealing; the bind, with the sandbox's start and any answer from the key service inside it; the receipt's check; and the first command, on its own or sent with the bind |
| first authenticated command | the same, over the platform's channel | the same, including the client's verification |
| a burst of 100 starts at once | median and tail latency, success rate, and the host's CPU each start costs, of snapshot loads and of starts from a pool | the same |
| pause and resume | `PATCH /vm` paused, then resumed | hold, then release, to the first effect |
| a request through the egress gateway | the same request through OpenShell's proxy, with TLS ended and a credential put in | the time the gateway adds, with and without a credential, and with a program to attribute |
| snapshot and restore at 1, 4 and 16 GiB | snapshot create and load, and gVisor's checkpoint and restore | seal and restore, to the first instruction |
| a seal, in parts | none | drain, pre-dump, freeze, checkpoint, layer writes, store and commit, at the same sizes |
| a restore, in parts | none | the claim, placing the stack by reflink, by mapping and by copy, the key service's answer, opening the layers, and the first instruction, at the same sizes |
| a commit | Firecracker's diff snapshot of the same amount of change | the whole commit, against the size of what changed, and that the sandbox never stops |
| continuous mode | QEMU's COLO on the same VM, for the delay it adds to output | the epoch each sandbox sustains, the wait it adds to an output, and the CPU and writes it costs, against the same session in commit mode |
| moving a session between hosts | QEMU's live migration of the same VM, and Firecracker's snapshot create, copy and load | a seal in continuous mode on one host to the first effect on another, at 1, 4 and 16 GiB |
| the root's file system | ext4 on the same dm-crypt | btrfs with SHA-256 checksums and with BLAKE2b, for the work inside |
| ending a TD | ending a VM | the host's time to free the TD's memory, per GiB, and its key ID, timed to its VMM's exit, and what that costs the guests beside it and those starting |
| idle memory per session | host memory per idle VM | the same, private and shared apart, per idle TD and per tenant-VM session |
| sessions per host | until the host refuses or slows | the same, and what bounds it first: memory, CPU or the hardware's key IDs |
| work inside | CPU, memory bandwidth, network and storage throughput | the same |

Targets: warm activation and the first command at or below the baseline's
snapshot load to the first command; a restore's first instruction under 300 ms
at a session's full size; seals, restores and moves at or below their
baselines at every size; continuous mode's added output delay at or below
COLO's on the same work; a TD's cold boot at or below the baseline's plus the
memory-acceptance floor; work inside within the published floors.

## Method

- **The same hardware.** The baseline runs on the same host model, with TDX
  off in firmware, or on an identical host. A host with TDX on can cost the
  baseline itself, so a run that keeps TDX on says so.
- **A second baseline**: the same guest and VMM with TDX off, which separates
  the cost of confidentiality from the cost of the VMM. A session image stops
  without a TEE, so this baseline runs a development build of it whose TEE is
  simulated in software: the same image, firmware and kernel but for that,
  with measurements of its own, which its launcher declares from the image's
  manifest where the TDX module would measure them, and quotes in the vendor's
  format under a development root of the same algorithms, signed in the guest,
  on a platform that is always UpToDate, so that every check costs what it
  costs on TDX. The difference is then what the hardware and the vendor's
  quoting add: memory acceptance, the TDX module's exits, bounce buffers for
  device I/O and the quoting service. Only a development build of a verifier
  or key service can accept that root, and then in place of the vendor's,
  never beside it; a release build has no option that would, a session image
  never falls back to the simulation, and a simulation build refuses to run in
  a TD. Where the guest's own work differs without a TEE, the record says so,
  as when a plain VM's kernel zeroes all its memory at boot where a TD's
  accepts it as it goes. A simulated host has one attestation key for all its
  guests, as a host's quoting enclave has for all its TDs, so that what a
  verifier keeps for a platform serves as many guests on both sides. Since
  this baseline's guests hold all their memory from boot, it takes no part in
  the rows a host's memory bounds at a session's full size: a burst of starts,
  idle memory and sessions per host compare with Firecracker alone.
- **The same settings.** Power settings (governor, C-states, turbo) and the
  host's halt polling, which every guest on it shares, are pinned and
  recorded, versions are named, and the sides interleave round by round
  within one run. Nothing else runs on the host during a run: no TD or VM but
  the sides' own, and a side that waits keeps its guests idle, with no boot or
  ending in flight, on cores apart from those of the side being measured, as
  the record lists. Where the host cannot hold every side's guests at once,
  as with pools for a burst of 100, the sides take turns instead, each side's
  guests up only in its own turns, and a turn begins only once the host has
  taken apart the guests of the turn before, their memory freed and a TD's
  key ID free again, which the record times. A guest counts as idle only once
  its own counters show it, its CPU and exits down to an idle guest's rate,
  and never because a fixed rest has passed.
- **Like for like.** Both sides reach their first command the same way, and
  the command does the same work on each. A baseline driven over a serial
  console, with no platform channel, is a floor, and is labeled as one. Work
  either side does before the measured path, such as a snapshot made or ready
  evidence judged before the claim, or the vendor's documents fetched, is
  named and timed beside the number.
- **Published records.** Every number comes with its raw records, the commands
  that made them, the versions of the host kernel, VMM, firmware, TDX module
  and guest, and the host's store: its file system and how layers were placed.
  A reflink measured on a file system mounted from a file on another tests
  correctness, not speed. A round is left out only for a reason its record
  names, such as the first of each side, which runs with its caches cold, and
  the record counts what it left out. A start that fails or loses its guest
  is never left out: it counts against the success rate, even where a retry
  on another guest would save it. A start succeeds only when its first
  command answers as it should and, for a session, its binder keeps its
  verdict.
- **Departures.** A run that departs from any of this names each departure in
  the first line of its record, and every number the departure touches
  carries it.

## Results

### A start from a warm pool, 2026-10-05

Runs 3 and 4 of the day, each of four configurations, on one host: a 24-core
Intel Xeon 6527P, two threads a core, with 128 GiB of memory. In each
configuration three sides took turns round by round, each on cores of its
own: TDs of 4 vCPUs and 16 GiB; the same guest with TDX off, on the simulated
TEE; and Firecracker v1.17.0 loading a full snapshot of a guest of the same
size. Firecracker's first command does a session's work: the sandbox image's
shell reads back a file of the credential's size, which the guest has not
read before. Each side ran 21 rounds a configuration, and only the first, with
its caches cold, is left out. The host ran Linux 7.0 (Ubuntu's 7.0.0-34) and
QEMU 10.2.1, with the performance governor, idle states past C1E off and
turbo on; the guests ran Linux 6.18. The records, with the commands that made
them and every version and digest, the TDX module's by its measurement, are
in [2026-10-05-i27](../test/session/records/2026-10-05-i27/README.md).

Both runs depart from the method twice, and their records say so first. TDX
was on in the firmware for every side, which can slow the two baselines as
well, so these runs may flatter the TD by whatever that costs them; a run with
TDX off in the firmware will say how much. And the host also ran a Kubernetes
control plane and its workloads, which took 0.7 to 1.3 of one CPU over the
five seconds before each configuration; that can only slow a side, and the
sides took turns.

From the claim, if any, and the bind to the first command's answer, in
milliseconds: the median of 20 rounds, with the 90th percentile in brackets.
In the first three configurations the first command rides the bind, and the
binder takes its answer on the guest's receipt while it judges the bind's
quote beside it, as [a start](session-api.md#start) allows. In the fourth the
binder judges the bind's quote before it sends anything, the strictest policy
a binder can hold, and then sends the first command on a connection of its
own.

| A start | Run | TD | TDX off | TDX adds | Firecracker, over vsock | Firecracker's serial console, a floor |
|---|---|---|---|---|---|---|
| a bind that claims its TD, with a credential sealed with it, from the orchestrator | 3 | 7.8 (8.5) | 6.6 (7.3) | 1.2 | 14.5 (15.4) | 8.8 |
| | 4 | 7.7 (8.3) | 6.4 (6.9) | 1.3 | 13.6 (14.7) | 8.1 |
| a bind that claims its TD, with a credential from the key service, from a binder under its own certificate | 3 | 9.4 (10.5) | 8.0 (8.4) | 1.4 | 13.8 (14.8) | 7.9 |
| | 4 | 9.6 (10.6) | 8.2 (8.9) | 1.5 | 13.7 (14.6) | 8.3 |
| a claim, then a bind with a credential from the key service, from the orchestrator | 3 | 10.1 (10.6) | 8.8 (9.3) | 1.3 | 14.4 (15.1) | 8.2 |
| | 4 | 10.1 (11.1) | 8.9 (9.3) | 1.2 | 14.2 (15.2) | 7.9 |
| the second, with the bind's quote judged before the first command is sent | 3 | 14.1 (16.0) | 11.2 (11.8) | 2.9 | 14.0 (14.5) | 8.3 |
| | 4 | 14.3 (15.8) | 11.2 (13.0) | 3.1 | 14.0 (14.5) | 7.5 |

TDX adds is the difference of the medians, before rounding.

In the first three configurations a confidential session's first command
answers 4.1 to 6.7 ms sooner than Firecracker's snapshot load answers the
same command over vsock, and in the first sooner even than Firecracker's
serial console, a floor, so the target for warm activation holds there. With
the quote judged first, the session answers 0.1 to 0.3 ms after that load:
level with it, but short of the target. The hardware and the vendor's quoting
add 1.2 to 1.5 ms to a start, and 2.9 to 3.1 ms when the quote is judged
first and its wait is on the path.

A snapshot's load is the fastest start Firecracker itself offers. A platform
can also keep plain VMs booted ahead in a pool, as sessions keep TDs, and a
VM that already runs answers a command in 1.3 to 1.8 ms here, so a start from
such a pool would by these numbers come sooner than a session's. It is
measured with the burst of 100, as a baseline of its own.

The first configuration in parts, the medians of runs 3 and 4:

| Part | TD | TDX off | Firecracker |
|---|---|---|---|
| the bind: to the guest, which checks and measures it, signs its receipt, starts its sandbox and opens what was sealed with it, and back | 5.4, 5.5 | 4.7, 4.6 | |
| the first command's sealed answer, after the bind's | 1.5, 1.5 | 1.1, 1.0 | |
| the bind's quote, from the bind's answer until it is there, judged and held to the receipt | 4.8, 4.6 | 2.1, 2.0 | |
| the same, from the start | 10.8, 10.7 | 7.7, 7.5 | |
| a later command, on the kept connection | 1.9, 1.9 | 1.7, 1.6 | 1.5, 1.8 |
| one more attestation: a quote over a fresh nonce, judged | 4.2, 4.7 | 2.1, 2.1 | |

With the quote judged first, the bind takes 6.9 ms in a TD, the quote is
there and judged 3.4 to 3.5 ms after it, and the first command, sent then on
a connection of its own, answers 3.5 to 3.6 ms later (3.2 to 3.3 with TDX
off), where riding the bind it answers 1.5 ms after the bind's answer. A TD's
quote came with the bind's answer in 0 or 1 of 20 rounds in the first
configuration, and in 8 to 16 of 20 where the key service made the bind
longer; with TDX off it came in every round.

From launch to a ready guest, a TD takes 2.30 s (p90 2.34 to 2.38): 18 ms
before its VMM starts, 2.21 to 2.22 s to the guest's first ask of its host,
and 65 to 69 ms more to ready. The guest with TDX off takes 4.10 s: 1.05 s
before its VMM, nearly all of it its launcher holding the firmware and the
whole disk to the image's manifest, which a TD leaves to the hardware's
measurement and to its own verity checks as it reads; 3.00 s to its first
ask, of which its kernel's clearing of all 16 GiB is 2.32 to 2.38 s; and 57
ms to ready. Without that check and that clearing it would be ready in about
0.7 s, so by subtraction a TD's boot costs about 1.6 s more than a plain
guest's, which the boot in parts will split into memory acceptance and the
rest. Firecracker boots cold and answers a first command over its serial
console in 1.09 to 1.10 s, but its guest is the Ubuntu root file system of
Firecracker's own tests, which boots to a login prompt, a fuller guest than a
session's. So that is not yet the cold boot baseline, which the boot in parts
measures with the leanest guest Firecracker boots, beside the
memory-acceptance floor the cold boot target is stated against. A ready guest
that waits costs its host 2.3 ms of CPU a second as a TD, and 1.2 to 1.3 ms
with TDX off.

Done before the measured path, and in none of these times, TD and then TDX
off: each ready guest judged by the binder as it became ready, 1.5 to 2.6 ms
and 1.4 to 1.8 ms (medians); the vendor's documents fetched by the binder,
once a configuration, 481 to 816 ms from the vendor's service and 0.6 to 1.0
ms from the simulated authority's; and the key service's replica judged by
the binder, once a configuration, 74 to 82 ms and 7.0 to 7.5 ms. Firecracker's
snapshot was made in 15.5 to 19.3 s, after a cold boot.

Runs 1 and 2, the first under the method
([2026-10-05-i26](../test/session/records/2026-10-05-i26/README.md)), ran the
same TD side, file for file, and the first three configurations, with the
same departures. They gave the TD 7.9 and 8.0 ms in the first, 9.3 and 9.3
in the second and 10.1 and 10.3 in the third. Two things differ: each
simulated guest was then a platform of its own to a verifier, which made that
side's judgment of a ready guest 2.7 to 3.1 ms and did not move its start,
6.7 to 8.7 ms across the three; and Firecracker's first command was the
guest's own `true` rather than a session's work, which gave 12.8 to 13.3 ms
over vsock.
