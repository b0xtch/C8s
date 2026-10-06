# Records: a burst of 100 starts under the method, 2026-10-06

One run of [`test/session/burst.sh`](../../burst.sh) on one development
host, under the method of
[docs/session-performance.md](../../../../docs/session-performance.md#method):
eleven bursts a side of 100 sessions started at the same instant, the first
of each side left out. Three sides took turns burst by burst:

- **TDs**: a pool of 100 ready TDs of 4 vCPUs and 16 GiB. Each start is a
  bind from the orchestrator that claims its TD and carries a credential and
  the session's first command sealed for the guest, the first configuration
  of the [starts from a warm pool](../2026-10-05-i27/README.md). A start has
  succeeded when the command answers as it should and the binder keeps its
  verdict from the quote over the bind.
- **Firecracker, each start a snapshot's load**: one snapshot of
  Firecracker's leanest guest of the same size, loaded 100 times at once,
  each into a VMM of its own.
- **Firecracker, each start a guest booted ahead**: 100 such guests booted
  before the burst and idle, as a platform with confidentiality off can
  keep a pool.

The first command is `node -v` on every side, in the same image.

| Directory | What ran |
|---|---|
| `b32-m2-100` | the run |

## What the directory holds

`env.txt`, `summary.txt`, `timing.jsonl` and `config.yaml`, as the
[first records](../2026-10-05-i26/README.md#what-a-directory-holds) describe
them. The kinds of record a burst adds:

| Kind | One for each | What it holds |
|---|---|---|
| `burst`, `fc-load`, `fc-pool` | burst of a side | how many started, the first and the last answer from the burst's instant (`first_us`, `wall_us`), for TDs the last kept verdict (`verdict_us`), and over the burst's span (`span_us`) all the CPU the host gave by its kernel's count (`host_cpu_us`) and the part the program that started the burst took (`own_cpu_us`) |
| `session`, `fc-load-session`, `fc-pool-session` | start that succeeded | its own start after the burst's instant (`offset_us`), its parts, the first command's answer (`first_cmd_us`), and for a session the quote judged (`confirmed_us`), both from its own start |
| `td-pool` | TD turn | the pool as it stood before its burst: how long it took to fill, and what it took of the host's available and unevictable memory |
| `vmm-stat` | side, burst and reading | what the side's VMMs had cost their host: `idle` and `before` are a second apart with the guests at rest, `after` is when the burst was over. Their threads' run and wait times, KVM's counters, their resident memory, the host's whole CPU count and the sampler's own share, and what the kernel's threads, the quoting service, the daemon and the launchers had run |
| `vmm-quiet` | side and burst | how long the side's guests took, after their rest, to be idle by their own counters |
| `fc-lean`, `fc-lean-snapshot` | run | Firecracker's guest and the making of its snapshot, before the bursts |
| `session-cold` | TD | launch to ready, in parts, from the daemon's and the launcher's logs |
| `daemon-bind` | bind | the daemon's time over it and the guest's answer inside that |

## The programs

Commits are named by their titles, as in the earlier records.

- **The TD side** is built at *perf(session-agent): read what a bind cost
  once its call has ended*: c8s `v0.34.2-183-g6bd9814d`, with the images
  built from that tree by `session-guest-image/build`. `env.txt` gives every
  digest.
- **The burst's programs** (`test/session/burst.sh`, `vmm_stat.py`,
  `firecracker_sample.py`, `warmstart`, `fcburst`, `fcagent`, `imageroot`)
  are as *test(session): count all of a burst's host CPU, and when each
  verdict is kept* holds them.

## The command

    C8S_BIN=<c8s> C8S_WARMSTART=<warmstart> \
    C8S_SESSION_IMAGE=<images>/c8s-session \
    C8S_KEY_SERVICE_IMAGE=<images>/c8s-key-service \
    C8S_SANDBOX_STORE=<store> C8S_SESSION_WORK=/work/run/b32-m2-100 \
    C8S_SESSION_CONFINE=64055 C8S_TIMING_PIN_POWER=1 \
    C8S_FIRECRACKER=/work/fc C8S_FIRECRACKER_AGENT=<fcagent> \
    C8S_FIRECRACKER_BURST=<fcburst> C8S_IMAGEROOT=<imageroot> \
    C8S_BURST_ROUNDS=11 C8S_BURST_TD_MIB=900 test/session/burst.sh

Before the run the one other VM on the host was stopped, and the host was
left alone for 30 s. `C8S_BURST_TD_MIB=900` is what a pooled TD is taken to
need before its pool is started; the default of 1024 would have left the
check within the host's own swing of available memory.

## Where the run departs from the method

Its `env.txt` says so in its first line.

- TDX is on in the host's firmware for every side, Firecracker included.
- The host also ran a Kubernetes cluster and what was deployed on it.
  `env.txt` counts that load and lists its busiest programs.
- The sides took turns, each side's guests up for its own turn alone, which
  the method allows where the host cannot hold every side's guests at once.
  It cannot: 100 ready TDs took 84,866 MiB of its memory, 75,132 of it their
  private pages; Firecracker's booted guests 53,133 MiB; and a burst of its
  snapshot loads 5,452 MiB, each counted whole though they share their
  snapshot's pages. That is 143,451 MiB together, and the host had 114,273
  MiB available, of which the run leaves 8,192 to what else the host runs.
  The summary ends on the same figures, from the records.

## What to know when reading it

- **The first burst of each side is left out**, as the summary says, and no
  other.
- **A TD burst fills the host's processors.** Its vCPU threads ran 91.6 ms a
  start and waited 528 ms for a processor, on the 36 processors its guests
  keep to: a burst lasts as long as its CPU over its processors, on
  Firecracker's sides as on this one, each at its own cost a start.
- **The whole of the host's CPU is the kernel's count by its tick, and its
  parts are the scheduler's own count of each thread.** Over a burst that
  fills its processors the two agree to within what else ran. Over a short
  burst on idle processors a tick's sample is off by more than that, which
  is why the summary gives their difference.
- **A TD's private pages are the host's unevictable memory**, which is how
  the record counts them: a VMM's resident set holds none of them.
- **Firecracker's guest** has 4 vCPUs and 16384 MiB, as the session class
  has, on ordinary pages: the agent as init on the image's own tree, which
  it has read whole before a start, as each pooled TD has the image unpacked
  before a bind.
- **The time a pool takes to fill is no part of a start**: 100 TDs boot two
  at a time, and `env.txt` gives each fill.

## What this copy leaves out

As the earlier records: the directory the run worked under is shown as
`/work`, and the programs the host ran besides Kubernetes' own are summed in
one line of `env.txt` with their names left out. Nothing else differs from
what the run wrote.
