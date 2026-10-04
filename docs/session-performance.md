# Session performance

Status: design. No number here has been taken under these rules yet; this
document sets the bar, names the floors, and fixes how the numbers will be
taken.

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

- **Warm pools.** A TD boots before anyone asks for it, so a start is a claim
  and a bind, two round trips to the guest, plus the binder's check. Boot time
  still matters for how fast a pool refills after a burst.
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
| warm activation | snapshot load to the first command | claim and bind to the first command |
| a start, in parts | none | claim, ready check, bind (with the key service's answer and the sandbox's start inside it), the binder's check, and the first command |
| first authenticated command | the same, over the platform's channel | the same, including the client's verification |
| a burst of 100 starts at once | median and tail latency, and success rate | the same |
| pause and resume | `PATCH /vm` paused, then resumed | hold, then release, to the first effect |
| a request through the egress gateway | the same request through OpenShell's proxy, with TLS ended and a credential put in | the time the gateway adds, with and without a credential, and with a program to attribute |
| snapshot and restore at 1, 4 and 16 GiB | snapshot create and load, and gVisor's checkpoint and restore | seal and restore, to the first instruction |
| a seal, in parts | none | drain, pre-dump, freeze, checkpoint, layer writes, store and commit, at the same sizes |
| a restore, in parts | none | the claim, placing the stack by reflink, by mapping and by copy, the key service's answer, opening the layers, and the first instruction, at the same sizes |
| a commit | Firecracker's diff snapshot of the same amount of change | the whole commit, against the size of what changed, and that the sandbox never stops |
| continuous mode | QEMU's COLO on the same VM, for the delay it adds to output | the epoch each sandbox sustains, the wait it adds to an output, and the CPU and writes it costs, against the same session in commit mode |
| moving a session between hosts | QEMU's live migration of the same VM, and Firecracker's snapshot create, copy and load | a seal in continuous mode on one host to the first effect on another, at 1, 4 and 16 GiB |
| the root's file system | ext4 on the same dm-crypt | btrfs with SHA-256 checksums and with BLAKE2b, for the work inside |
| ending a TD | ending a VM | the host's time to free the TD's memory, per GiB, and what it costs the TDs beside it |
| idle memory per session | host memory per idle VM | the same, private and shared apart, per idle TD and per tenant-VM session |
| sessions per host | until the host refuses or slows | the same |
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
- **A second baseline**: the same guest image and VMM with TDX off, which
  separates the cost of confidentiality from the cost of the VMM.
- **The same settings.** Power settings (governor, C-states, turbo) are pinned
  and recorded, versions are named, and runs of the two sides interleave.
  Nothing else runs on the host during a run: no other TD or VM.
- **Like for like.** Both sides reach their first command the same way. A
  baseline driven over a serial console, with no platform channel, is a
  floor, and is labeled as one.
- **Published records.** Every number comes with its raw records, the commands
  that made them, the versions of the host kernel, VMM, firmware, TDX module
  and guest, and the host's store: its file system and how layers were placed.
  A reflink measured on a file system mounted from a file on another tests
  correctness, not speed.
