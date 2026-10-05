# Confidential sessions

Status: design, with milestone 1 built.
[session-daemon.md](session-daemon.md) describes what runs, and
[Milestones](#milestones) orders the rest.

An agent platform runs each of its users' sessions in a microVM of its own:
the agent or a custom harness, the tools it calls, and a workspace holding
the user's code and files. It pauses idle sessions, resumes them when the
user returns, forks new ones from prepared templates, and moves them across a
fleet. A session holds the most sensitive data its user has: source code,
credentials for repositories and services, prompts and conversations, files,
model traffic and the live state of running processes. Whoever operates the
fleet can read all of it.

A confidential session runs each session in its own confidential VM, a TD on
Intel TDX today and an SEV-SNP guest next. The host, the hypervisor, the
platform's operator and every other session can neither read it nor change it
undetected, and the user can check, from a browser or an SDK, exactly what
runs there and which key their connection reaches.

This document is the overview. The details are in:

| Document | Covers |
|---|---|
| [session-api.md](session-api.md) | the calls a platform makes, the flows built from them, and the other doors |
| [session-daemon.md](session-daemon.md) | for operators, the daemon as built: its calls, configuration and host network, restarts, drains, and what is missing |
| [session-state.md](session-state.md) | holding, committing, sealing, restoring and forking a session, and keeping its processes across the loss of a host; layers, journals, leases, keys and disks |
| [session-key-service.md](session-key-service.md) | the key service: its replicas, leases across leaders, its ledger and witnesses, recovery and release |
| [session-disclosure.md](session-disclosure.md) | what a session says in plaintext, its logs and crashes, and private review of its use |
| [session-threat-model.md](session-threat-model.md) | what each party can and cannot do, and what is out of scope |
| [session-performance.md](session-performance.md) | the performance bar, where hardware sets a floor, and what to measure |

## Why a VM per session

c8s today runs a whole Kubernetes node as one confidential VM. That keeps the
host out, but every pod on the node shares one boundary, so node-as-CVM is
single-tenant ([README](../README.md#node-as-cvm)). An agent platform puts many
users' sessions on each host, so each session needs a boundary of its own.

c8s once gave each pod its own CVM through Kata Containers
(`--cvm-mode=pod`, removed in `f7051215`; see `docs/kata.md` at `204734b7`).
Pod-as-CVM brings that shape back without Kata ([Modes](#modes)), with a
guest that differs from Kata's in four ways, all kept here:

- **The host cannot drive the guest.** It starts the TD and carries its
  packets, and has no channel in: no agent API, no exec path, no log stream
  and no shared file system. Everything that drives the guest arrives over
  its attested endpoint, under keys a signed document names. Kata's host shim
  drove a guest agent, and a policy baked into the guest limited what the
  host could ask.
- **Measured documents decide what runs.** The launch document, and later the
  bind, are measured into RTMR[3] before anything they name starts. Kata let
  the host write the container spec and policed it after the fact.
- **The whole image is pinned.** MRTD, RTMR[1] and RTMR[2] come from the
  image's manifest. Kata's direct kernel boot left RTMR[1] and RTMR[2]
  underivable offline, so the Kata mode pinned MRTD alone.
- **No boot on the user's path.** A pooled TD boots for nobody and becomes one
  session's only when a signed bind, measured and taken once, makes it so,
  after a fence raised as the bind arrives has closed every connection made
  before it but the daemon's own. A start is a few round trips rather than a
  boot, and the TD never returns to the pool.

Sessions extend that guest with what agent platforms need:

- **Hold, seal, restore and fork.** The host cannot snapshot a TD, so a
  session's processes are checkpointed inside the TD, sealed under a new key,
  and restored into a new TD with new keys.
- **One live copy.** A restored session never runs twice, even when the host
  would like it to: the key service holds each session's generation and
  lease, and the guest stops its own effects when its lease goes stale.
- **An API as well as Kubernetes.** A platform that drives VMs directly calls
  the c8s daemon; Kubernetes is one door among several.

What carries over from the Kata design: the host-side runtime may be
privileged and untrusted, because a tampered VMM or image changes the launch
measurement and attestation then fails; enforcement on the host is a
guardrail, never the boundary; launch measurements are predicted per VM
shape; and confidential VMs land only on hosts declared capable.

## The parts

```text
  agent platform: orchestrator, and a binder holding the owner's authority
             |  session API: gRPC over mutual TLS
 +-----------v--------------------------------- host, untrusted ----------+
 | c8s daemon: warm pools, session API, launcher, VMM (QEMU)              |
 | keeps ciphertext only: seals, envelopes                                |
 |                                                                        |
 | +----- TD: one session -------------+   +----- TD: ready ------------+ |
 | | guest agent (measured)            |   | booted, bound to nobody    | |
 | |   bind, keys, gateways, seal      |   | instance key made inside   | |
 | | sandbox: agent, harness, tools    |   +----------------------------+ |
 | | workspace on an encrypted disk    |                                  |
 | +-----------------------------------+                                  |
 +------------------------------------------------------------------------+
          | attested channels (RA-TLS)
  key service (attested CVMs, built from CDS), verifiers, release log
```

| Part | Runs | Trusted | Does |
|---|---|---|---|
| c8s daemon | on each host | no | keeps warm pools, serves the session API, launches TDs, stores ciphertext |
| guest image and agent | in each TD, measured | yes | takes one bind, makes the TD's keys, runs the sandbox, passes every effect through its gateways, seals |
| key service | in attested CVMs | yes, by attestation | releases keys and secrets to attested TDs; holds each session's generation and lease |
| verifiers and reference values | wherever a check runs: a browser, an SDK, the key service | by whoever runs the check | checks evidence against published values |
| orchestrator | the platform's control plane | for availability only | places, holds, seals, restores and ends sessions |
| binder | wherever the owner's authority lives | to decide what a TD becomes | signs binds |
| release log | in public, with witnesses outside the operator's reach | no: verifiers check its proofs | lists every image, class, review policy, key service version and verifier bundle before any verifier accepts it |

The daemon is outside the boundary on purpose. Everything it handles is
public or ciphertext, and every call that changes what a TD is returns
evidence the caller checks. A dishonest daemon can stop sessions, but it
cannot read one, change one undetected or run one twice.

## Rules

1. **The host half is outside the boundary.** Requests and answers carry
   ciphertext, public documents and metadata only.
2. **A guest obeys signed binds and nothing else.** A bind names the TD's
   instance key, the session, its disks and its policy. The guest takes one
   bind, measures it into the TD and refuses every other.
3. **One way.** A TD goes from a pool to bound once and never returns to a
   pool. It ends.
4. **One live copy.** A session runs in at most one TD at a time, under a
   lease the key service grants and the guest enforces.
5. **A new identity per TD.** Instance keys and entropy never cross TDs; a
   restore or a fork gets its own.
6. **Classes, not parameters.** A TD's vCPUs, memory and disk slots are fixed
   at launch and published, per class and image, as reference values.
7. **Plaintext leaves by schema only.** What a guest says in plaintext is
   fixed by its image's disclosure schema
   ([session-disclosure.md](session-disclosure.md)); everything else leaves
   encrypted.
8. **Fail closed.** A check that cannot be made counts as failed. A guest that
   cannot verify a peer, reach the key service or renew its lease stops the
   effect, and no path falls back to plaintext or to an unverified peer.

## Identity and attestation

Session TDs follow c8s's current launch-key and measurement contracts
([operator.md](operator.md#authenticated-launch-configuration)):

- **Image.** A pool boots one measured image: firmware built from source,
  which starts the unified kernel image (kernel, initrd and command line in
  one file) from the image's own disk, with no boot loader between them.
  Verifiers pin MRTD, RTMR[1] and RTMR[2] from the image's published manifest,
  which its build computes, as they do for nodes, and pin the TD's attributes
  so that no debug or migratable TD passes.
- **Pool launch key.** Each TD boots with a signed launch document for its
  pool, naming its class and the key service it trusts
  ([its fields](session-api.md#the-launch-document)). The document's public
  key is bound to the guest as for nodes: the measured initrd extends RTMR[3]
  with it on TDX, and the launcher sets HOST_DATA to its hash on SEV-SNP. The
  agent then measures the document's digest too, into RTMR[3] on TDX and into
  the report data on SEV-SNP, once its signature verifies, since one key may
  sign many documents.
- **Instance key.** The guest makes a key pair at boot. Its digest goes into
  the report data of every report and into the RA-TLS certificate, so the
  evidence names a key that only this TD holds. With it the guest makes a
  hybrid encryption key, ML-KEM-768 with X25519, which the instance key
  signs and to which keys are released, so what reaches the TD stays closed
  to anyone who records it now and has a quantum computer later.
- **One-time keys.** Beside its instance key, a pooled guest makes a signing
  key and a hybrid KEM key, ML-KEM-768 with X25519, for its one bind. Every
  report it makes before that bind carries their digest in its report data,
  beside the instance key's, and its evidence keeps the last such quote. The
  guest signs its answer to the bind with the first as soon as it has measured
  the bind, and opens with the second any message the binder sealed to it with
  the bind, carrying the first command or the credentials the binder holds. It
  uses neither key again, and erases both at once before anything of the
  tenant runs. The instance key must outlive the bind, so code that broke out
  of the sandbox could read it; the one-time keys are gone by then ([A session
  that reads its own TD](session-threat-model.md#binding-and-identity)).
- **Bind.** On TDX the guest extends RTMR[3] with the bind's digest, on top
  of the launch key's seed: the chain a node's per-workload measurement uses
  today. SEV-SNP has no runtime register, so there the guest puts the bind's
  digest into the report data beside the instance key.

From one fresh quote a verifier therefore learns which image runs, which pool
launched it, which session and owner it is bound to, and which key it holds.
For sessions this closes a gap c8s lists for pods today, where a workload's
sandbox identity is vouched for by the mesh CA rather than bound by hardware
([README](../README.md#known-gaps-and-open-items)).

## Releases

Everything a verifier accepts comes from one public, append-only release
log: guest images with their reference values and disclosure schemas,
classes, review policies, the key service's versions, and the verifier
bundles that browsers load. It is binary transparency, with the proofs
checked by every verifier rather than by auditors alone.

- **Proofs, not lists.** A verifier accepts a reference value only with an
  inclusion proof under a checkpoint that witnesses have cosigned, as for the
  key service's ledger
  ([session-key-service.md](session-key-service.md#ledger-and-witnesses)),
  so what one user is shown, every user and auditor can see. The daemon
  staples the proofs to each TD's evidence.
- **No one releases alone.** An entry needs the signatures of m of n named
  release signers.
- **Synthetic sessions first.** A new image or policy serves synthetic
  sessions before it serves real ones.
- **A delay before use.** An entry becomes eligible for real sessions a fixed
  time after it enters the log, 72 hours by default, so outside auditors can
  rebuild it and look before any session runs it. A fix for a vulnerability
  may shorten the delay only with more signatures, and the log says so.
- **Withdrawal.** A later entry can withdraw a release. Verifiers refuse it
  from then on, and pools retire its TDs.

## Modes

| Mode | One CVM per | Started by | Between sessions | Fits |
|---|---|---|---|---|
| node-as-CVM (c8s today) | Kubernetes node | the cluster's provisioning | containers | one tenant renting whole nodes |
| pod-as-CVM | session, as a Kubernetes pod | a launcher in the pod | the hardware boundary | many users' sessions, on platforms that schedule them as pods |
| session VM | session | the c8s daemon | the hardware boundary | many users' sessions, on platforms that drive VMs themselves |
| tenant VM (an option) | tenant or user | either of the above | a software wall, gVisor by default | many small sessions of one owner, for density |

Pod-as-CVM and session VMs run the same measured guest, take the same bind
and keep the same rules. They differ in who starts the TD and how the
platform reaches it:

- **Pod-as-CVM.** A pod's only content is one TD. A launcher in the pod runs
  the VMM and hands the TD the pod's own network interface, so the TD takes
  the pod's address, and Kubernetes' scheduling, quotas and network policy
  apply to it as to any pod. A pool is a set of such pods booted for nobody,
  and a claim takes one. The launcher needs what pods do not usually get:
  KVM, the host's quoting service, the guest image from the host, and the
  right to hand its network interface to the TD. So its namespace must allow
  privileged pods, which costs the cluster's own hardening but not the
  session's, since the launcher, like the daemon, is outside the boundary.
- **Session VM.** The c8s daemon starts TDs itself and serves the session
  API, with no Kubernetes on the host, for a platform that drives VMs
  directly or through the Firecracker-compatible adapter.

One TD per session is the default, as a pod on Kubernetes and from the daemon
elsewhere. No CVM ever holds two tenants. In a tenant VM, a sandbox escape
reaches the same owner's other sessions and nothing outside the VM; whether
that is acceptable is the owner's choice, made per tenant.

### Tradeoffs

| Mode | Gives | Costs | Choose it when |
|---|---|---|---|
| node-as-CVM | the simplest and densest shape: ordinary pods, one attestation per node, and the only shape a managed service without nested virtualization can run | one boundary for the whole node, kubelet included, so one tenant per node; a workload's identity is vouched for by the mesh, not bound by the hardware; nothing per session to hold, seal or restore | one tenant rents whole nodes, or only a cloud's confidential VMs are on offer |
| pod-as-CVM | the hardware boundary per session, with Kubernetes' scheduling, quotas, network policy and warm pools as they are | bare-metal TDX or SEV-SNP hosts; a privileged launcher pod per TD, which weakens the cluster's own hardening; a claim goes through the Kubernetes API and its controllers; per TD, a kernel and memory of its own, and a share of the host's limited supply of confidential VM keys | the platform already schedules its sessions as pods |
| session VM | the hardware boundary per session, on the shortest path: a claim goes from the daemon straight to a pooled TD, with no Kubernetes on the host, and platforms built on Firecracker keep their orchestrator | bare-metal hosts; the platform places sessions across hosts itself; per TD, the same kernel, memory and key costs as a pod CVM | the platform drives VMs itself, or replaces Firecracker |
| tenant VM | density: many small sessions share one TD's kernel and memory, so per-TD costs and the key supply matter less | a software wall between the owner's sessions, so one escape reaches them all; the evidence proves the TD and its owner, while which sandbox a connection reaches is the agent's word; one TD's crash ends every session in it; sandboxes pay gVisor's cost on system calls and I/O | one owner runs many small, mostly idle sessions that may share a wall, such as its own sub-agents |

## A session's life

```text
 pool:  booting --> ready --> claimed --> bound --> running <--> held
                                                      |
                 seal: processes and files, inside <--+
                 the TD, under a new key; TD ends     +--> ended
 restore: a new TD from the pool takes the latest seal, with a new identity
 fork:    many new TDs start from one template sealed before any secret
```

- **Start.** The daemon claims a ready TD and the owner's binder checks its
  evidence and signs a bind, or a binder that checked the pool's ready TDs
  ahead signs a bind for one, which claims it; the guest takes the bind and
  starts the sandbox. The sandbox runs the guest's own init, which stays and
  reaps what commands leave, and runs a process of the session's only when
  the policy names one: the image's own command, or a command sent to it as
  any other is. The session then ends when that process does. The sandbox's
  memory is bounded below its TD's, leaving the guest's own services a
  reserve, so a session that fills it loses processes of its own, never the
  guest's.
- **Hold and release** stop and restart the TD's vCPUs, keeping its memory.
- **Commit** records the session's files as a new layer while it runs,
  without stopping it. In **continuous mode** the guest commits the
  sandbox's processes and files every epoch and holds each output until its
  epoch is committed, so a session survives the loss of its host with its
  processes, and nothing that left is repeated.
- **Seal** checkpoints the sandbox inside the TD into encrypted layers,
  records the new generation at the key service, and ends the TD.
- **Restore** brings the latest seal back into a new TD, with new keys.
- **Fork** starts many sessions from one template.
- **Destroy** ends the TD and deletes the session's ciphertext.

[session-state.md](session-state.md) has the details.

## Doors

- **The session API** ([session-api.md](session-api.md)), the main door, for
  platforms that drive VMs themselves.
- **A Firecracker-compatible adapter**, which serves Firecracker's API paths
  on the session API, so a platform built on Firecracker can switch without
  rewriting its orchestrator. No Firecracker code runs.
- **Kubernetes**, through pod-as-CVM ([Modes](#modes)): a pod per TD, and
  agent-sandbox's warm pools and claims map onto pools and binds.

## Inference, review and browser verification

- **Inference.** Model calls leave a TD only through the guest's inference
  gateway, which verifies the inference service's attestation over that
  service's own attested channel before it sends any input.
- **Review.** A platform that enforces rules of use reviews each session
  inside its TD, under a policy from the release log, and learns only bounded
  signals within a budget per session
  ([session-disclosure.md](session-disclosure.md#private-review)).
- **Browser.** A user's browser verifies the session with c8s-verify's
  challenge-response protocol and post-quantum channel, which reach the
  guest unchanged through `Connect`. The session's evidence carries the
  inference identity its gateway verified and the review policy it runs
  under, so one check covers the agent's VM, the inference it uses and what
  review may say about it, and states which part, if any, it delegates to
  another verifier.

All three are later milestones; this section fixes only where they attach.

## Milestones

Each ends on a repeatable hardware test, with rejection tests for invalid
evidence, and on measurements that place what it delivers against the best
existing system for it, with the hardware floors beside them
([The bar](session-performance.md#the-bar)).

1. **One session on one host.** The daemon keeps a pool; a session starts
   from it; its binder verifies the pinned image and the guest's key over
   fresh evidence; a test credential is released; one authenticated command
   runs; and nothing leaves the guest in plaintext but what its disclosure
   schema allows. Built, with its hardware test in `test/session/hardware.sh`;
   next, its measurement against Firecracker's snapshot load to the first
   command.
2. **Hold, seal and restore.** Hold and release; commits, continuous mode,
   seals and restores inside the TD, as stacks of encrypted layers and
   journals; a root that stays fresh; leases and generations at a key service
   of three replicas; seal keys under dual control; and a guest rebuilt for
   them whose cold boot and idle memory come down to the hardware's floors.
   Measured against Firecracker's snapshots and diff snapshots, gVisor's
   checkpoint and restore, and QEMU's live migration and COLO, with
   confidential computing off, and the guest's cold boot against Firecracker's
   and a Kata Containers TDX guest's.
3. **Templates and forks**, with credentials that the sandbox sees only as
   placeholders, so that no template carries one; measured against many
   Firecracker VMs loaded from one snapshot.
4. **The other doors**: the Firecracker-compatible adapter, measured against
   Firecracker behind the same API, and sessions as pods on Kubernetes
   (pod-as-CVM), measured against Kata Containers' confidential pods.
5. **Inference, review and the browser**: a verified channel to inference;
   egress rules by method, path and program, and revisions measured as they
   take effect, against OpenShell's for what they can express and what they
   add to a request; private review within a budget; the release log and its
   witnesses; then browser verification of the session, its inference
   identity, its review policy and the rules in force.
6. **The whole platform at scale** against the baselines in
   [session-performance.md](session-performance.md): bursts, density and the
   work inside, and optimized from the results.
