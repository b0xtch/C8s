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

## Where hardware sets a floor

| Floor | Why | What narrows it |
|---|---|---|
| memory bandwidth | every access to private memory is encrypted | nothing in software; measured and published |
| TLB-heavy work | the host maps a TD's private memory in 4 KiB pages today | 2 MiB private mappings, which are on their way into KVM and the VMMs |
| network and storage at CPU saturation | device DMA goes through bounce buffers in shared memory, so every byte is copied once more | larger and fewer copies; trusted device I/O later |
| density | TDs share no memory with one another (no same-page merging, no deduplication), memory must be accepted before use, and the platform's key IDs bound how many TDs a host runs | the tenant VM for many small sessions, accepting memory on use, and giving free memory back |

## How sessions hide the rest

- **Warm pools.** A TD boots before anyone asks for it, so a start is a claim
  and a bind, two round trips to the guest, plus the binder's check. Boot time
  still matters for how fast a pool refills after a burst.
- **Hold keeps memory.** A release restarts the vCPUs and renews the lease;
  nothing is read back.
- **Lazy restore.** A restored session runs before its seal has been read
  whole, as it touches its pages.
- **Templates.** A forked session starts with its repositories cloned and its
  dependencies installed.

## Levers

- **Accept memory on use.** The guest accepts private memory as it needs it,
  so a pooled TD costs the host only what it has touched.
- **Give free memory back.** The guest's free page reporting converts free
  blocks to shared, so the host can reclaim them, and accepts them again,
  zeroed, when it needs them.
- **A trimmed guest.** Fewer devices and drivers, and a smaller kernel and
  user space, boot faster, idle cheaper and leave less to attack.
- **The tenant VM.** Many small, mostly idle sessions of one owner share one
  TD behind gVisor, which costs far less memory per session than a TD each.
- **Polling** where latency matters, such as the guest's halt polling, turned
  on through the measured command line.
- **Host-side pre-faulting** of private memory before a bind, which is safe
  because added pages stay pending until the guest accepts them.
- **Another VMM.** libkrun or Cloud Hypervisor may replace QEMU if they
  support TDX and win on these numbers.

Each lever must keep the rules in
[session-threat-model.md](session-threat-model.md#optimizations-that-must-not-weaken-the-model).

## What to measure

| Metric | Baseline | Session VM |
|---|---|---|
| cold boot | Firecracker boot to a ready guest | TD launch to a ready, unbound guest |
| warm activation | snapshot load to the first command | claim and bind to the first command |
| a start, in parts | none | claim, ready check, bind (with the key service's answer and the sandbox's start inside it), the binder's check, and the first command |
| first authenticated command | the same, over the platform's channel | the same, including the client's verification |
| a burst of 100 starts at once | median and tail latency, and success rate | the same |
| pause and resume | `PATCH /vm` paused, then resumed | hold, then release |
| snapshot and restore at 1, 4 and 16 GiB | snapshot create and load | seal and restore, to the first instruction |
| idle memory per session | host memory per idle VM | the same, per idle TD and per tenant-VM session |
| sessions per host | until the host refuses or slows | the same |
| work inside | CPU, memory bandwidth, network and storage throughput | the same |

Targets: warm activation and the first command at or below the baseline's
snapshot load to the first command; a restore's first instruction under
300 ms at a session's full size; work inside within the published floors.

## Method

- **The same hardware.** The baseline runs on the same host model, with TDX
  off in firmware, or on an identical host. A host with TDX on can cost the
  baseline itself, so a run that keeps TDX on says so.
- **A second baseline**: the same guest image and VMM with TDX off, which
  separates the cost of confidentiality from the cost of the VMM.
- **The same settings.** Power settings (governor, C-states, turbo) are pinned
  and recorded, versions are named, and runs of the two sides interleave.
- **Like for like.** Both sides reach their first command the same way. A
  baseline driven over a serial console, with no platform channel, is a
  floor, and is labeled as one.
- **Published records.** Every number comes with its raw records, the
  commands that made them, and the versions of the host kernel, VMM,
  firmware, TDX module and guest.
