# Records: a session's start under the method, 2026-10-05

Two runs of [`test/session/timing.sh`](../../timing.sh) on one development
host, each of three configurations, under the method of
[docs/session-performance.md](../../../../docs/session-performance.md#method).
The programs and images are this branch's at the commit *feat(session): name
a simulating build in its version*: c8s states `v0.34.2-132-gc2011f16`, with
`+c8s_simtee` for the simulating build, and the images were built from that
tree by `session-guest-image/build`, the simulating pair with `C8S_SIMTEE=1`.

Commits are named here by their titles. The branch was replayed onto later
documents after these runs, which gave its commits other ids and changed no
file but the documents, so a version string names the id its commit had when
the program was built.

| Directories | Configuration | Settings |
|---|---|---|
| `w19-m-sb`, `w20-m-sb` | a credential sealed with the bind; the bind claims its TD; the orchestrator binds | `C8S_TIMING_STORED=0 C8S_TIMING_SEALED=1 C8S_TIMING_CLAIM_WITH_BIND=1 C8S_TIMING_IDLE=60` |
| `w19-m-pb`, `w20-m-pb` | a credential from the key service; the bind claims its TD; a binder under a certificate of its own | `C8S_TIMING_CLAIM_WITH_BIND=1 C8S_TIMING_BINDER=1` |
| `w19-m-p`, `w20-m-p` | a credential from the key service; a claim, then the bind | none |

`w19` is the first run and `w20` the second, each in the table's order.

## What a directory holds

| File | What it is |
|---|---|
| `env.txt` | the host and both sides as the run found them; its first line says which rules of the method the run kept |
| `summary.txt` | the run's own summary of its records |
| `timing.jsonl` | the TD side's records, and Firecracker's |
| `sim/timing.jsonl` | the simulated TEE side's records |
| `config.yaml`, `sim/config.yaml` | each side's daemon configuration |

The records, one JSON object a line, by `kind`:

| Kind | One for each | What it times |
|---|---|---|
| `session` | round | a start in parts, the first command, three later ones, a further attestation and the session's end. Round 0 finds every cache cold, and the summary leaves it out |
| `documents` | side | the binder's fetch of the vendor's documents, before the rounds |
| `members` | side, where the credential comes from the key service | the binder's judgment of the key service's replica, before the rounds |
| `fc-snapshot` | run | the making of Firecracker's snapshot: the boot it was taken from, and `snapshot_create_ms` for the snapshot itself |
| `fc-cold`, `fc-load`, `fc-load-vsock` | round | Firecracker's cold boot and its snapshot load over the serial console, and the load with the first command sent to an agent in the guest over vsock |
| `session-cold` | guest | launch to ready, from the daemon's log |
| `idle` | ready guest, in `-sb` | the CPU time its VMM took over 60 s with nothing asked of it |
| `tee` | simulated side | that its guests ran in no TEE, and under which authority |

A `session` record's `ready_judged_us` is how long the binder took to judge
that guest when it became ready, before the round. That, the two fetches and
the snapshot are the work done before the measured path.

## The commands

Each configuration is one call, with the settings of its row:

    C8S_BIN=<c8s> C8S_WARMSTART=<warmstart> \
    C8S_SESSION_IMAGE=<images>/c8s-session \
    C8S_KEY_SERVICE_IMAGE=<images>/c8s-key-service \
    C8S_SIM_BIN=<simulating c8s> C8S_SIM_WARMSTART=<simulating warmstart> \
    C8S_SIM_SESSION_IMAGE=<images>/c8s-session-simtee \
    C8S_SIM_KEY_SERVICE_IMAGE=<images>/c8s-key-service-simtee \
    C8S_SANDBOX_STORE=<store> C8S_SESSION_WORK=/work/run/<run> \
    C8S_SESSION_CONFINE=64055 C8S_TIMING_PIN_POWER=1 \
    C8S_FIRECRACKER=/work/fc C8S_FIRECRACKER_AGENT=<fcagent> \
    <settings> test/session/timing.sh

Before a run's first configuration the one other VM on the host was stopped,
and the host was left alone for 30 s.

The second run's scripts are `test/session/timing.sh` and
`test/session/firecracker_sample.py` as the commit *test(session): watch idle
pools, and check a lone simulated guest first* holds them. The first run's
timing script was the file as *test(session): check and time guests whose
TEE is simulated* left it, with a first draft of the idle watch that the
later commit adds. The summary program is the timing script's own.

## Where the runs depart from the method

Each `env.txt` says so in its first line.

- TDX is on in the host's firmware for every side, Firecracker included.
- The host also ran a Kubernetes cluster and what was deployed on it, which
  the method's rule that nothing else runs on the host leaves no room for.
  `env.txt` counts that load and lists its busiest programs.

## What to know when reading them

- **The simulated side verifies more than the TD side in `-pb` and `-p`.** A
  verifier keeps, for each platform and for a minute, the outcome of the
  checks that depend only on the platform and the vendor's documents. Every
  TD of a host shares the attestation key of the host's quoting enclave, and
  so is one platform to a verifier. In these runs each simulated guest made
  an attestation key of its own at boot, and so was a platform of its own:
  whoever judged its first quote ran those checks in full. That is the
  binder's judgment of each ready guest, before the round, and the key
  service's judgment of each session's guest, inside the bind. In `-pb` and
  `-p` the simulated side's bind, start and first command therefore carry in
  every round what the TD side's carry in one round of four, and the
  difference of the medians there understates what the hardware adds. `-sb`
  has no such step on its measured path.
- **The count of the host's other load is coarse.** It sums each process's
  share of one CPU over that process's whole life, so a process that started
  a moment before can count for a whole CPU. The second run took it before
  anything of the run started: 93, 181 and 81 in its three configurations,
  where the twelve busiest programs, listed a moment later, sum to 76, 68
  and 68. The first run took it after its own guests had booted, and its
  643 to 655 is mostly the run's own programs.
- **Turbo was on** (`no_turbo 0` in `env.txt`), as the host had it. The run
  pinned the governor and the idle states, and recorded turbo without
  setting it.
- **No round was left out but the first.** The summary leaves out a round
  that a refresh of the binder's documents ran beside, and none did: each
  binder fetched its documents seconds before its first round into a cache
  of the run's own, a document comes due 45 minutes after its fetch, and a
  run's rounds were over within six.
- **The first commands differ.** A session's first command reads its
  credential back through a shell (`sh -c 'cat ...'`), and Firecracker's is
  `true`. The later commands are `true` on both.
- **Firecracker's guest** has 4 vCPUs and 16384 MiB, as the session class
  has, on ordinary pages, with its root file system read-only, the agent on
  a second read-only drive, a vsock device and no network device. Its
  snapshot is a full one, and a load maps its memory file.
- **`w19-m-sb` was stopped by hand.** It ended its rounds and its idle
  watch, then waited on its own daemons for about 22 minutes until it was
  stopped. Its records are whole. It has no `session-cold` records, which
  are gathered at the end, and its `summary.txt` was made afterwards from
  its records by the same program. The first run's other two configurations
  followed it.
- **The simulated TEE side protects nothing.** It is the method's second
  baseline: a development build under an authority made for the run.

## What these copies leave out

The directory the runs worked under is shown as `/work`. The programs the
cluster ran besides Kubernetes' own are summed in one line of each
`env.txt`, with their names left out. The host's microcode revision is left
out. Nothing else differs from what the runs wrote. The addresses that
remain are loopback, the two blocks the script gives its guests, and the
registry on a VM's user network that the sandbox image was stored from.
