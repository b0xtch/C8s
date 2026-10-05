# Records: a session's start under the method, runs 3 and 4, 2026-10-05

Two runs of [`test/session/timing.sh`](../../timing.sh) on one development
host, each of four configurations, under the method of
[docs/session-performance.md](../../../../docs/session-performance.md#method).
They follow the two runs of [2026-10-05-i26](../2026-10-05-i26/README.md),
whose README says what a directory holds and what each kind of record is.

| Directories | Configuration | Settings |
|---|---|---|
| `w23-m-sb`, `w24-m-sb` | a credential sealed with the bind; the bind claims its TD; the orchestrator binds | `C8S_TIMING_STORED=0 C8S_TIMING_SEALED=1 C8S_TIMING_CLAIM_WITH_BIND=1 C8S_TIMING_IDLE=60` |
| `w23-m-pb`, `w24-m-pb` | a credential from the key service; the bind claims its TD; a binder under a certificate of its own | `C8S_TIMING_CLAIM_WITH_BIND=1 C8S_TIMING_BINDER=1` |
| `w23-m-p`, `w24-m-p` | a credential from the key service; a claim, then the bind | none |
| `w23-m-qb`, `w24-m-qb` | as `-pb`, with the quote over the bind's nonce judged before the first command is sent | `C8S_TIMING_CLAIM_WITH_BIND=1 C8S_TIMING_BINDER=1 C8S_TIMING_QUOTE_FIRST=1` |

`w23` is run 3 and `w24` run 4, each in the table's order.

## The programs

Commits are named by their titles, as in the first records: the branch is
replayed onto the design documents as they change, which gives its commits
other ids, so a version string names the id its commit had when the program
was built.

- **The TD side** is the programs and images of runs 1 and 2, file for file:
  the commit *feat(session): name a simulating build in its version*, c8s
  `v0.34.2-132-gc2011f16`. Each `env.txt` gives the same digests as theirs.
- **The simulated TEE side** is built at *test(session): time a start like
  for like, with a boot in parts*, c8s
  `v0.34.2-137-g36349326+c8s_simtee`, with images built from that tree. It
  holds *fix(session): give a simulated platform one quoting enclave for all
  its guests*.
- **The scripts** are `test/session/timing.sh` and
  `test/session/firecracker_sample.py` as that commit holds them.

## What differs from runs 1 and 2

- **A simulated platform has one attestation key for all its guests**, as a
  host's quoting enclave has for all its TDs. A verifier keeps the outcome
  of the checks that depend only on a platform and the vendor's documents,
  and in runs 1 and 2 every simulated guest was a platform of its own. That
  work is before the measured path on both sides: the binder's judgment of
  a ready guest, and the key service's when a guest opens its session with
  it at boot. A bind finds both verdicts standing. So the simulated side's
  `ready TD judged ahead` fell, and its first command did not move. The
  note in the first records that the difference of the medians understates
  what the hardware adds in `-pb` and `-p` was an inference that these runs
  do not bear out.
- **Firecracker's first command over vsock is the work a session's is**: the
  session's own words, `sh -c 'cat "$C8S_CREDENTIALS_DIR/api-token"'`, run
  by the busybox the sandbox image was built from, on a read-only squashfs
  drive. The guest read the shell into its memory before the snapshot, as a
  pooled TD has the image unpacked before a bind, and had not read the
  file, which is of the credential's size. Later commands are that
  busybox's `true`. In runs 1 and 2 both were the guest's own `true`.
  Building the sandbox image again from that busybox gives the digest the
  sandbox store names: checked by hand before run 3.
- **The fourth configuration** is new.
- **Turbo is on, set by the run and put back**, where runs 1 and 2 recorded
  it as the host had it, which was on.
- **The host's other load is CPU time over the five seconds before a
  configuration starts**, by program, where runs 1 and 2 summed each
  process's share over its whole life.
- **Launch to ready comes in parts** in each `session-cold` record, from the
  launcher's log: `before_vmm_ms`, of which `checked_ms` is the simulated
  side's launcher holding the firmware and the disk to the image's
  manifest; `vmm_to_documents_ms`, to the guest's first ask of its host;
  and `documents_to_ready_ms`.
- **A `clearing` record** in each `sim/timing.jsonl` is one boot of the
  simulating dev image with a console, alone and before anything else of
  the configuration: how long its kernel says it took to clear 16 GiB,
  which is part of every simulated guest's launch to ready.

## The commands

As for the first records, with two more settings:

    C8S_SIM_CONSOLE_IMAGE=<images>/c8s-session-dev-simtee \
    C8S_FIRECRACKER_BUSYBOX=/usr/bin/busybox

Before a run's first configuration the one other VM on the host was stopped,
and the host was left alone for 30 s.

## Where the runs depart from the method

As the first two, and each `env.txt` says so in its first line: TDX is on in
the host's firmware for every side, and the host also ran a Kubernetes
cluster and what was deployed on it.

## What to know when reading them

- **No round was left out but the first**, for the reason the first records
  give.
- **`w24-m-pb`'s `clearing` record reads 0.** The kernel of that one console
  boot had not started its clock when it cleared its memory, so its log
  times nothing before that. The other seven read 2317 to 2381 ms.
- **The simulated TEE side protects nothing.**

## What these copies leave out

As the first records: the directory the runs worked under is shown as
`/work`, the programs the host ran besides Kubernetes' own are summed in one
line of each `env.txt` with their names left out, and the host's microcode
revision is left out. Nothing else differs from what the runs wrote.
