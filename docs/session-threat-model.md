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
  guarantee from c8s. Credentials are the exception the gateways close: the
  sandbox holds only placeholders unless the policy marks a credential for it,
  so a hijacked agent can misuse one only at the endpoints it names and cannot
  copy it out ([Credentials and
  egress](session-api.md#credentials-and-egress)).
- **Physical attacks on the memory bus**, which Intel and AMD leave out of
  their threat models.

## Trust

**Trusted**, and how a verifier checks each part:

| Part | Why it is trusted | How it is checked |
|---|---|---|
| CPU, microcode and TDX module (or the AMD secure processor's firmware) | the hardware root | the quote's signature to the vendor's root, and the TCB status in the vendor's collateral |
| guest firmware | in MRTD (or the SEV-SNP launch measurement) | pinned, and built from source with the image, so that auditors can rebuild it |
| guest kernel, initrd, command line, and the root file system with the agent | in RTMR[1], RTMR[2] and the dm-verity root | the image's published manifest |
| the launch key, the bind and later runtime events | the RTMR[3] chain on TDX; HOST_DATA and report data on SEV-SNP | replayed by the verifier |
| the agent and its gateways (egress, inference, the message box) | on the verity root | the same pins |
| the key service | attested code in its own CVMs, a quorum of replicas | each replica verifies the others; binds pin its replicas |
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
- **The host declares another machine.** RTMR[0] records the machine the host
  declared to the firmware: its vCPUs, its memory and how that is split, how
  many PCI functions it has, and the builds of its VMM and firmware. It does
  not record what kind each device is: with milestone 1's QEMU and TDVF, an
  e1000e in the network slot gives the same value as virtio. So a pool's
  launch document lists the values its class may have, and a TD on any other
  machine ends before it serves; verifiers hold a TD to the same list, from
  its measured document, and take the evidence of a TD whose document lists
  none only to read its value. And the guest checks its devices itself, first
  in its load step, before it reads anything its host handed it, and again
  before the agent serves: every PCI function must be of a kind its class has
  (the board's two bridges, and modern-only virtio for its network, its disks
  and its socket to the host, with a console only in a development image), or
  the TD ends.
- **A debug or migratable TD.** Verifiers pin the TD's attributes, so neither
  passes.
- **An old TCB, or a quote from the wrong enclave.** A verifier holds a
  quote's signer to the vendor's TD quoting enclave, by the signer, product
  and attributes it pins, before it fetches anything, then judges the TCB
  status of the platform, the TDX module and the quoting enclave by the
  vendor's published algorithm. UpToDate passes and Revoked never does; any
  other status passes only where the verifier's policy names it, and the
  verdict carries the statuses and the vendor's advisory ids, so a verdict
  reached under an allowance is never taken for one under a stricter policy.
  The guest holds its key service to the same rule, and the key service its
  pools' guests.
- **Old vendor documents.** The vendor signs and dates its collateral and its
  revocation lists, but a document stays within its dates after the vendor
  replaces it, and the vendor reissues its root revocation list rarely. The
  host relays the documents stapled to a ready TD's evidence, so it can relay
  old ones, among them a revocation list from before a CA or a platform's key
  was revoked. So a verifier that sends a guest a secret on its verdict, as
  the key service does with keys and a binder with what it seals with its bind
  or puts over `Connect`, judges on the vendor's documents as it fetched them
  from the vendor itself within the last hour, and keeps a verdict only while
  those are the newest it has. A verifier that cannot reach the vendor for
  longer than that sends no secret, which costs availability only, as the host
  can always cost it. Stapled documents serve verdicts that send no secret,
  such as a binder's before it signs a bind, which holds none. A session that
  already runs meets a revocation through its lease: the key service judges
  each lease holder's platform again as documents change, and renews no lease
  on one it now refuses ([When things
  fail](session-state.md#when-things-fail)).

### Binding and identity

- **The host binds a TD for an attacker's authority.** The bind is measured,
  so the evidence shows the wrong authority and the owner's verifier refuses
  it; the key service releases a session's keys only for binds its authority
  signed.
- **The host replays a bind into another TD.** The bind names the instance key
  of the one TD it fits.
- **The host rebinds a bound TD.** Binding is one way, and a refused bind
  ends the guest.
- **A session that reads its own TD's keys**, while its host shows that TD's
  ready evidence to another binder. Code that breaks out of its sandbox can
  read anything in its TD (A4), the instance key and the key service's channel
  among them, and the evidence the TD gave when it became ready still
  verifies. So nothing another binder relies on rests on them: a bind's
  receipt is signed by a one-time key that the guest erases before anything of
  the tenant runs, a command or credentials a binder sends with its bind are
  sealed to a second one-time key, erased by then too, the key service
  releases only against such a receipt and for one bind per instance key, and
  the bind's quote shows the bind in RTMR[3].
- **A message the host seals.** A ready TD's evidence is public, so anyone can
  seal to its one-time KEM key, and HPKE's base mode does not say who did. So
  each part of a message sealed with a bind carries the authorization it would
  need over `Connect`, from a key the bind grants, and the guest tries only
  the first such message after its bind, so one the host sends first costs the
  binder a trip over `Connect` and no more.
- **A revision the owner did not make, or one beyond the bind.** A revision of
  a session's egress or credential rules is signed by the bind's authority,
  must lie inside the bind's boundary, and is measured before it takes effect,
  so a verifier sees every rule a session has run under ([Policy
  revisions](session-api.md#policy-revisions)).
- **An outsider binds a pooled TD for itself**, to run on the platform's
  compute. An unbound guest takes the first valid bind it is sent, so the
  daemon lets nothing reach it but its own requests, the bind of its claim,
  and a bind that claims it from the orchestrator or from a binder its pool
  names, under an authority the pool names for that binder. It refuses
  `Connect` to an unbound TD, and TD names are random besides.
- **A start the daemon calls not ready.** A daemon can deliver a bind and then
  tell the binder that the TD was not ready, or withhold the guest's answer,
  so a binder that signs for another TD may have started the session in two.
  Nothing reaches a TD the binder did not judge, and the binder keeps the
  session's name for its second bind, so the key service decides between the
  two: it creates a session's record, and grants its lease, for one TD only,
  and the other ends with nothing it did having left its gateways ([Lease
  timing](session-state.md#lease-timing)). The first TD can take that bind
  only before its `notAfter`, and only until its pool's age limit ends it
  unbound. Milestone 1 has no leases, so there both may run and a command
  sealed with a bind may run twice; a binder that must never have that sends
  its command over `Connect`, to the TD whose receipt it holds.
- **A host that sets the guest's clock.** A guest's wall clock is its host's,
  so no check rests on it: durations run on the TD's monotonic clock, which
  the host can stop but not slow, and dates such as a bind's `notAfter` are
  judged by the key service's time ([Lease
  timing](session-state.md#lease-timing)). The guest's check of the key
  service itself comes before it has that time, so it uses floors instead: the
  vendor's documents for the key service's platform must carry at least the
  TCB evaluation data number, and stay valid to at least the date, that the
  guest's measured image carries from its build or a launch document raised.
  The guest judges them again by the key service's time once it has it ([Its
  clock](session-key-service.md#its-clock)). Floors keep out documents older
  than the guest's build but not ones from before a later revocation, so the
  guest sends nothing secret on that check ([A stand-in for the key
  service](#keys-and-the-key-service)).
- **Stale evidence.** A bind's answer is a receipt the guest's one-time key
  signs over the binder's nonce, and the quote over the same nonce follows; a
  verifier can ask for a quote over its own nonce through `Connect`; and the
  RA-TLS handshake proves that the instance key is live. A receipt adds
  freshness, not trust: it is worth what the ready quote that binds its key is
  worth, and what it says of RTMR[3] is the measured agent's word until the
  quote confirms it, so the verdict that is kept rests on the quote, and a
  session whose quote disagrees with its receipt, or never comes, ends. Each
  quote carries the events and phase it covers, so a verifier replays exactly
  those, whatever the guest extends later. A binder that judges ready evidence
  before a claim finds the claimed TD by its certificate's digest, and reuses
  a verdict only while its policy and the vendor's documents the verdict rests
  on are unchanged and current, so a verdict reached ahead is the one it would
  reach at the claim.
- **A pooled TD carrying something from an earlier session.** A bound TD never
  returns to a pool, and a pooled TD holds no tenant data, code or keys before
  its bind.

### Keys and the key service

- **Keys go only to attested TDs with a valid bind**, a seal's keys only for
  the latest generation, and a session's lease only to one TD at a time.
- **The key service's operator** can deny service. It cannot read keys, which
  exist unwrapped only inside attested replicas, and it cannot point a
  session at another key service, which the bind pins.
- **A stand-in for the key service.** A guest has no road to the vendor, so
  before its bind it judges its key service on documents its host carries, and
  a host holding the keys of a platform the vendor has since revoked could
  pass that check with a key service of its own and documents from before the
  revocation. So the guest sends nothing secret on that check, and from its
  bind on takes nothing from a replica, and sends it nothing, unless its
  binder judged it on documents it fetched itself within the hour and the bind
  names it, or a majority of the replicas the guest holds signed a membership
  that adds it ([Which replicas a guest
  trusts](session-key-service.md#which-replicas-a-guest-trusts)).
- **Rolling back the key service.** Its replicas trust no disk, and witnesses
  outside the operator's reach cosign its ledger only forward, so neither a
  host nor the operator can bring back an older state
  ([session-key-service.md](session-key-service.md)).

### Seals, restores and forks

- **Rollback.** Generations move only forward, by compare-and-swap. The key
  service releases only the latest generation's stack, and the guest opens
  every layer it lists and no other, so no older state can be put together
  from layers the host kept.
- **Two copies.** The lease, enforced at the guest's gateways, stops a
  session's effects before another TD can take it, and a TD whose lease is
  stale answers its own API with `lease_stale`, so a client the host steers
  to an old copy learns that it is old. In continuous mode an output leaves
  only once the key service has committed the epoch that produced it, so two
  copies' outputs never both leave, whatever their clocks say.
- **A crash replayed.** In commit mode a session's process image is restored
  at most once, and in continuous mode nothing a restored image's processes
  did after it ever left, so a dead TD's generator state never drives new
  effects. What a restored TD sends carries a new grant number, so it never
  reuses a number the dead TD sent.
- **Secrets in forks.** A template is sealed before any secret enters the
  sandbox, and each fork makes its own keys and entropy.
- **The host reads or changes a seal.** Each layer of a seal is under a key
  of its own, with dm-verity inside dm-crypt, and its key and root hash live
  only in the key service, so the host can neither read a layer nor change a
  block of it undetected. A journal's records are sealed and chained, with
  the last one's hash at the key service. The host sees the layers' sizes,
  each journal record's size class, which layers forks of one template
  share, and which blocks a restore reads.

### Data plane

- **`Connect`** splices bytes to the guest; TLS, and c8s-verify's channel for
  browsers, end in the guest, so the host sees ciphertext.
- **Envelopes** are HPKE to the session key and signed by a sender the bind
  names, numbered inside the seal, under a header the encryption
  authenticates, so a gap, a replay, an expired envelope or one moved from
  another session is seen.
- **Egress** leaves only through the guest's proxy, under the bind's egress
  rules and any revision measured since ([Credentials and
  egress](session-api.md#credentials-and-egress)). Where a rule reads requests
  or a credential is used, the proxy ends TLS inside the TD, so the host sees
  ciphertext either way.
- **A session reaching the host or another session.** Each TD has its own
  tap device and /30 network, with no bridge, and the host's packet filter
  drops what a guest sends to the host or to another guest, spoofed sources
  and every connection from outside; egress leaves through one named
  interface only. The host enforces this, so it guards the platform and
  other sessions from a session, not a session from the host.
- **The path to the key service.** A TD the daemon launches reaches its key
  service only through its launcher, which relays one vsock port, for its
  own guest only, to the key service's address. The relay carries the
  attested channel's ciphertext, so like any host part it can only delay or
  drop it, and the sandbox cannot open vsock at all.
- **What a pooled TD reaches.** Before its bind, the agent answers only the
  daemon's requests and talks only to the key service. Even the vendor's
  documents for its own quotes come from the key service, which checked the
  quote against them and judged their dates by its own clock. So a pooled TD
  fetches nothing from outside the platform. Every verifier still judges the
  documents' dates by its own clock, and one that will send the guest a secret
  judges on documents it fetched itself ([Old vendor
  documents](#launch-and-measurement)).
- **Inference** leaves only through the guest's gateway, which verifies the
  inference service's attestation before it sends anything.
- **Recorded traffic.** Attested channels use hybrid key exchange, and
  envelopes, session keys and released keys use hybrid HPKE, each with
  ML-KEM-768 and X25519, so traffic recorded today stays closed to a quantum
  computer later. Signatures stay classical where the vendors' roots are,
  since forging one needs a quantum computer at the time of the check.

### Disks and devices

- **Disk contents are untrusted.** Read-only images are checked by digest or
  dm-verity root hash from the bind, and seals by each layer's key and root
  hash. The root file system is btrfs with strong checksums, under a key the
  TD makes for its own life, and the roots of its trees never leave the TD's
  memory, so a block the host changes or puts back from earlier fails a
  check ([session-state.md](session-state.md#disks)).
- **Device emulation is untrusted.** Virtio traffic goes through bounce
  buffers in shared memory, and the guest's drivers treat every value from a
  device as hostile. The guest's kernel has drivers only for its class's
  devices, and the guest ends if any PCI function is of another kind, so a
  device the host adds or swaps meets no driver. The kernel also leaves out
  what would read more from the host: PCI hot plug, legacy virtio, the DMI
  tables, EFI variables and runtime services, and the console's magic keys
  (sysrq).

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
| incremental seals and commits | each layer under its own key and root hash, which only the key service holds; no layer is shared across sessions but a template's, among its own forks |
| placing layers by reflink or by mapping | the host shares ciphertext blocks between its own files or maps them into a slot; the guest checks every block it reads against the layer's root hash |
| continuous mode | outputs wait for their epoch's commit; each record is sealed, chained to the one before and padded to a size class, and the last one's hash lives in the key service |
| snapshots for commits | btrfs snapshots inside the TD, under the root's key; the host sees only the layer that leaves |
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
  constant-time cryptography and a kernel with the published fixes and no
  32-bit system call entry, verifiers require current TDX module and microcode
  levels, and no SMT core is shared between tenants.
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

1. **RTMR[0] per class.** A class's value is read today from the evidence of a
   probe TD launched under a document that lists none, which trusts the host
   that launched the probe to have built the class's machine. Deriving the
   value from the class's machine description, so that an auditor needs no
   host and a TD under a document that lists none can end at boot, is still to
   be built.
2. **Where the binder runs**, and what a platform-run binder should show.
3. **The access pattern of a lazy restore**, which the host sees.
4. **The key service's witnesses and escrow holders**: who they are
   ([session-key-service.md](session-key-service.md#open-questions)).
5. **Review budgets and signal schemas**: what a platform's rules need
   ([session-disclosure.md](session-disclosure.md#open-questions)).
6. **What a journal record's size says** about a session, and which size
   classes hide it ([session-state.md](session-state.md#open-questions)).
7. **Allowances by advisory.** Whether a policy should accept a status other
   than UpToDate only for the vendor's advisory ids it names, so that an
   allowance made for one advisory does not admit the next.
8. **The egress schema.** Whether the bind's egress and credential rules take
   OpenShell's network policy schema at a pinned version, limited to the forms
   whose containment is a direct test ([Credentials and
   egress](session-api.md#credentials-and-egress)), so that OpenShell's
   policies within those forms run unchanged, or translate from it.
