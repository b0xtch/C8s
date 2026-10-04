# Session threat model

Status: design. It covers confidential sessions as [sessions.md](sessions.md)
describes them; c8s's node-level threat model is unchanged.

## Goals

| Id | Goal |
|---|---|
| G1 | A session's data (code, prompts, credentials, files, process state, model traffic) is readable only inside TDs bound to that session, and by the principals its owner authorized: not by the host, the daemon, the platform's operator, the key service's operator or other sessions |
| G2 | What runs in a session is exactly a published image plus the policy in its bind, and neither changes undetected |
| G3 | A TD is bound to one session, once, and ends rather than being reused |
| G4 | A session never acts from two TDs at once, and never from an older generation |
| G5 | From a browser or an SDK, a user can check which TD serves them, its image and policy, its freshness, the key their connection ends at, the inference identity bound to the session, and the review policy it runs under, if any |
| G6 | The platform keeps only the authority it needs: it can place, hold, seal, restore and end sessions, but not read them or act as their owner, as long as the owner's authority is not the platform's own |
| G7 | What a session says in plaintext is fixed in advance and bounded: the host and the platform learn metadata, what the image's disclosure schema allows and, where the platform reviews sessions, signals within the budget its policy states |

Non-goals, stated so that nobody assumes otherwise:

- **Availability.** The host and the platform can always refuse service,
  delete ciphertext or drop traffic.
- **Metadata.** Which sessions run, when, for how long, how much memory and
  disk they use, how many bytes they send and to where, and which parts of a
  seal a restore reads are all visible to the host.
- **Placement.** The platform places every session, so it can steer one onto
  a host of its choice. Which hosts it may choose is bounded by the TCB levels
  and platforms verifiers accept, and by physical controls.
- **A session's own code.** An agent that leaks its own secrets, through
  prompt injection for example, leaks them over whatever egress its policy
  allows. Egress policy limits this, and it is a control for owners, not a
  guarantee from c8s.
- **Physical attacks on the memory bus**, which Intel and AMD leave out of
  their threat models.

## Trust

**Trusted**, and how a verifier checks each part:

| Part | Why it is trusted | How it is checked |
|---|---|---|
| CPU, microcode and TDX module (or the AMD secure processor's firmware) | the hardware root | the quote's signature to the vendor's root, and the TCB status in the vendor's collateral |
| guest firmware | in MRTD (or the SEV-SNP launch measurement) | pinned |
| guest kernel, initrd, command line, and the root file system with the agent | in RTMR[1], RTMR[2] and the dm-verity root | the image's published manifest |
| the launch key, the bind and later runtime events | the RTMR[3] chain on TDX; HOST_DATA and report data on SEV-SNP | replayed by the verifier |
| the agent and its gateways (egress, inference, the message box) | on the verity root | the same pins |
| the key service | attested code in its own CVMs, a quorum of replicas | each replica verifies the others; binds pin it |
| verifier code and reference values | they make the decision | reproducible builds, each in the public release log; the browser bundle pinned by hash |
| the release log's witnesses | together they keep the log from showing two histories | at least one runs outside the operator's reach, and two of three must cosign |
| the owner's binder and authority key | the owner chose them | the owner's responsibility |

**Untrusted**: the host kernel and KVM, the VMM, the c8s daemon, the launcher
pods and Kubernetes itself, the platform's control plane and staff, storage,
registries, DNS, the network, the quote and collateral services on the host
(collateral is signed by the vendor), and every other session and tenant.
Untrusted parts can deny service and observe metadata. They must not be able
to read a session's data, change it undetected, or obtain its keys or its
owner's authority. A newer release of any of them can cost speed or uptime,
but not confidentiality.

## Adversaries

| Id | Adversary | Can | In scope |
|---|---|---|---|
| A1 | host operator | root on hosts: the VMM, host kernel, firmware settings, the VM's shape and ACPI tables, interrupts, scheduling, page mapping, device emulation, network, disks | yes |
| A2 | platform operator | the orchestrator and its databases, storage, the daemon's API, ingress; the binder too, if the platform runs it | yes |
| A3 | network attacker | anywhere between browsers, the platform, TDs, the key service and inference; can terminate an outer TLS layer | yes |
| A4 | a malicious session | arbitrary code in its own TD, trying to reach other sessions, keys or data | yes |
| A5 | a session's end user, against its owner | crafted prompts, and code the agent runs | for effects outside the session; inside it, the owner's policy decides |
| A6 | supply chain | a compromised package, image, firmware binary or builder | partly: reproducible builds and pins, but no defense against a backdoor in pinned source |
| A7 | physical attacker | memory-bus interposers, cold boot | no; physical controls only |
| A8 | side channels | a co-resident guest or a malicious hypervisor observing caches, stepping instructions or injecting interrupts | partly ([Residuals](#hardware-and-side-channel-residuals)) |

## Threats and mitigations

### Launch and measurement

- **The host boots another image.** MRTD, RTMR[1] or RTMR[2] differ from the
  published pins, and every verifier refuses the evidence.
- **The host declares another VM shape or device set.** RTMR[0] records what
  the host declared to the firmware, and each class publishes its expected
  value. It does not record everything the guest later finds behind emulated
  devices, so the guest also checks its own device set against its class's
  fixed slots and treats every byte from a device as untrusted.
- **A debug or migratable TD.** Verifiers pin the TD's attributes, so neither
  passes.
- **An old TCB.** The vendor's collateral states the platform's TCB status,
  and verifiers require a floor.

### Binding and identity

- **The host binds a TD for an attacker's authority.** The bind is measured,
  so the evidence shows the wrong authority and the owner's verifier refuses
  it; the key service releases a session's keys only for binds its authority
  signed.
- **The host replays a bind into another TD.** The bind names the instance key
  of the one TD it fits.
- **The host rebinds a bound TD.** Binding is one way, and a refused bind
  ends the guest.
- **An outsider binds a pooled TD for itself**, to run on the platform's
  compute. An unbound guest takes the first valid bind it is sent, so the
  daemon lets nothing reach it but its own requests and the bind of its
  claim, and refuses `Connect` to it; TD names are random besides.
- **Stale evidence.** Fresh quotes are made over the binder's nonce in a
  bind's answer, or over a verifier's own nonce through `Connect`, and the
  RA-TLS handshake proves that the key is live.
- **A pooled TD carrying something from an earlier session.** A bound TD never
  returns to a pool, and a pooled TD holds no tenant data, code or keys before
  its bind.

### Keys and the key service

- **Keys go only to attested TDs with a valid bind**, a seal's keys only for
  the latest generation, and a session's lease only to one TD at a time.
- **The key service's operator** can deny service. It cannot read keys, which
  exist unwrapped only inside attested replicas, and it cannot point a
  session at another key service, which the bind pins.
- **Rolling back the key service.** Its replicas trust no disk, and witnesses
  outside the operator's reach cosign its ledger only forward, so neither a
  host nor the operator can bring back an older state
  ([session-key-service.md](session-key-service.md)).

### Seals, restores and forks

- **Rollback.** Generations move only forward, by compare-and-swap, and
  older seals' keys are never released again.
- **Two copies.** The lease, enforced at the guest's gateways, stops a
  session's effects before another TD can take it.
- **A crash replayed.** A process image is restored at most once, so a dead
  TD's generator state never drives new effects.
- **Secrets in forks.** A template is sealed before any secret enters the
  sandbox, and each fork makes its own keys and entropy.
- **The host reads a seal.** A seal is under a key of its own, with dm-verity
  and dm-crypt. The host sees its size and which units a restore reads.

### Data plane

- **`Connect`** splices bytes to the guest; TLS, and c8s-verify's channel for
  browsers, end in the guest, so the host sees ciphertext.
- **Envelopes** are HPKE to the session key and signed by a sender the bind
  names, numbered inside the seal, under a header the encryption
  authenticates, so a gap, a replay, an expired envelope or one moved from
  another session is seen.
- **Egress** leaves only through the guest's proxy, under the allowlist in the
  bind.
- **A session reaching the host or another session.** Each TD has its own
  tap device and /30 network, with no bridge, and the host's packet filter
  drops what a guest sends to the host or to another guest, spoofed sources
  and every connection from outside; egress leaves through one named
  interface only. The host enforces this, so it guards the platform and
  other sessions from a session, not a session from the host.
- **The path to the key service.** A guest reaches its key service only
  through its launcher, which relays one vsock port, for its own guest only,
  to the key service's address. The relay carries the attested channel's
  ciphertext, so like any host part it can only delay or drop it, and the
  sandbox cannot open vsock at all.
- **Inference** leaves only through the guest's gateway, which verifies the
  inference service's attestation before it sends anything.
- **Recorded traffic.** Attested channels use hybrid key exchange, and
  envelopes, session keys and released keys use hybrid HPKE, each with
  ML-KEM-768 and X25519, so traffic recorded today stays closed to a quantum
  computer later. Signatures stay classical where the vendors' roots are,
  since forging one needs a quantum computer at the time of the check.

### Disks and devices

- **Disk contents are untrusted.** Read-only images are checked by digest or
  dm-verity root hash from the bind; seals by their own verity root and key;
  the root file system is under a key the TD makes for its own life.
- **Device emulation is untrusted.** Virtio traffic goes through bounce
  buffers in shared memory, and the guest's drivers treat every value from a
  device as hostile.

### Disclosure

- **A guest that says more than it should.** Everything a guest says in
  plaintext has a type in its image's disclosure schema, which the
  measurements cover, so a guest that said more would be another image, and
  verifiers would refuse it.
- **Logs, consoles and crash dumps.** A session image has no console the host
  can read, its logs stay in the session, and a crash leaves only a code.
- **Review as a way out.** A review policy can send only its signal schema's
  fields and take only its listed actions, on its schedule, within a budget
  the key service keeps, so neither restores, forks nor second TDs add to what
  review reveals.
- **Review aimed at one user.** Review policies apply per class and come from
  the public release log, and the evidence names the one a session runs
  under.
- **Content kept for later review.** None is kept: content is reviewed inside
  the TD as it passes.

### Releases

- **A release shown to one user.** Verifiers accept only what the release log
  holds, with inclusion proofs under cosigned checkpoints, so showing one user
  another image would take the witnesses' collusion.
- **A rushed or rogue release.** An entry needs m of n signers, serves
  synthetic sessions first, and becomes eligible only after a delay in which
  outside auditors can rebuild it.

## Optimizations that must not weaken the model

| Optimization | Rule |
|---|---|
| warm pools | pooled TDs hold no tenant data, code or keys before a bind; the bind is one way and measured; instance keys are made in the guest; pools retire TDs by age and on any TCB change |
| hold | memory stays encrypted; the TSC keeps running, so a released TD renews its lease before any effect |
| host caches of images | public images only, checked in the guest by digest or verity root before anything parses them |
| memory snapshots and clones | only inside the guest and encrypted, never by the host; templates hold no secrets |
| deduplication across tenants | not allowed: it reveals whether two tenants hold the same data |
| skipping attestation on a hot path | never; a verdict may be cached per instance key, since a bind is one way, but it is never skipped |
| sending review signals as they happen | not allowed: they leave on the policy's schedule, padded to one size |
| accepting memory only when used | driven by the guest; the host learns the session's memory high-water mark, which is metadata |
| giving free memory back to the host | only free blocks are converted to shared, and a block comes back through acceptance, which zeroes it |
| host patches, such as pre-faulting or 2 MiB private pages | host code is untrusted anyway: a bug can deny service or crash TDs, but not read private memory without a flaw in the TDX module or the hardware |

## Hardware and side-channel residuals

- **Memory-bus interposers.** Published interposer attacks on DDR4 and DDR5
  defeat TDX's and SEV-SNP's protections. Hosts need physical controls, and
  verifiers can restrict the platforms they accept to known machines.
- **Interrupts and single-stepping.** Published attacks inject interrupts into
  confidential guests or step them instruction by instruction. The guest uses
  constant-time cryptography and a kernel with the published fixes, verifiers
  require current TDX module and microcode levels, and no SMT core is shared
  between tenants.
- **Firmware flaws** are tracked by TCB levels, and verifiers require fixed
  versions.

## What a browser check proves

A passing check supports this claim: the key at the end of this connection is
held by a TD running the published image with these pins, launched by this
pool key, bound to this session by this authority under this policy, fresh as
of the browser's nonce, on a platform at or above this TCB level. What it can
say in plaintext is this disclosure schema, and this review policy's signals
within this budget, or none, each in the public release log. Its gateway
verified this inference identity, and the claim says whether the browser
checked the inference evidence itself or took the gateway's verdict.

It leans on the CPU vendor's root of trust, the published reference values
and the builds behind them, the release log's witnesses, and the integrity of
the verifier code the browser runs.

## Open questions

1. **RTMR[0] per class**, and how much the guest's own device check adds to
   it.
2. **Where the binder runs**, and what a platform-run binder should show.
3. **The access pattern of a lazy restore**, which the host sees.
4. **The key service's witnesses and escrow holders**: who they are
   ([session-key-service.md](session-key-service.md#open-questions)).
5. **Review budgets and signal schemas**: what a platform's rules need
   ([session-disclosure.md](session-disclosure.md#open-questions)).
