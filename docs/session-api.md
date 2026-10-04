# The session API

Status: design, with milestone 1 built. The API is
`c8s.session.v1alpha1`; [session-daemon.md](session-daemon.md) lists the calls
built so far, and [sessions.md](sessions.md) is the overview.

The session API is how an agent platform creates, holds, seals, restores,
forks and ends confidential sessions. The c8s daemon that serves it runs on
the host, outside the trust boundary, and the API is shaped so that it never
has to be trusted: no request or answer carries anything a TD protects, and
every call that changes what a TD is returns evidence that the caller checks.

## Callers

| Caller | Trusted for | Calls | Authenticates with |
|---|---|---|---|
| orchestrator: the platform's control plane | availability, never data | pools, `Claim`, `Bind` (relaying), `Hold`, `Release`, `Commit`, `Seal`, `Destroy`, the flows, `GetStats`, `Watch` | mutual TLS with a service identity; quotas per orchestrator |
| binder: holds or reaches the owner's authority | deciding what a TD becomes | `GetEvidence`; `Bind` directly, or `SignBind` when the daemon calls it during a flow | TLS to an endpoint registered per tenant; the daemon believes nothing it says, and the guest checks the bind's signature |
| verifiers: SDKs, browsers, the key service, the binder | their own checks | `GetEvidence`, `Connect` | none for evidence, which is public; `Connect` carries the verifier's own channel |
| senders and readers of envelopes | their own messages | `Deliver`, `Collect` | the orchestrator's identity or a per-session token; envelopes are sealed and signed inside |
| the platform's review service | the signals its review policy allows | `Collect`, for review batches | the orchestrator's identity; batches are encrypted to its review key |
| guest agent | everything inside its TD | none: it reaches the daemon only over channels it opens, and answers only the host requests the calls below need: fence, bind, evidence, commit and seal | its instance key |

**Who holds the binder decides who can direct a TD.** If the platform runs
the binder, the platform chooses what each TD becomes, and the evidence shows
the platform's key. For protection from the platform as well as from the
host, the binder runs where the owner's authority lives: in the owner's own
client, or in a service of theirs in its own attested CVM.

Out of scope: what a session means to the platform (a project, a thread, a
task); placement across hosts, which belongs to the orchestrator; and the
guest's own API on its TLS port.

## Rules the API keeps

| Rule | What it means for the API |
|---|---|
| R1. The daemon is outside the boundary | requests and answers carry ciphertext, public documents and metadata only |
| R2. Evidence, not answers | every call that changes what a TD is returns its evidence or says how to fetch it fresh; callers act on verified evidence, never on the daemon's word |
| R3. The guest obeys signed binds | the daemon cannot make a guest restore, fork, open a disk or take a credential; it can only supply what a bind names |
| R4. One way | a TD goes from a pool to bound once, and a bound TD never returns to a pool |
| R5. One live copy | a session runs in at most one TD at a time, under a lease (see [session-state.md](session-state.md#generations-and-leases)) |
| R6. A new identity per TD | instance keys and entropy never cross TDs; of the keys, only the session key crosses a restore, under the lease |
| R7. Classes | vCPUs, memory and disk slots are fixed at launch, so a class is a set of reference values, not a parameter |
| R8. Safe to retry | every change takes the caller's request id, and long work returns an operation the caller can poll |
| R9. Blind to content | statistics are what a host sees anyway: VM-level counters, sizes and times; anything else a guest says in plaintext has a type in its image's disclosure schema ([session-disclosure.md](session-disclosure.md)) |

## Resources and states

| Resource | Named by | Holds | Last word |
|---|---|---|---|
| host | the daemon | its TDX module and TCB level, the classes it runs, free capacity | the daemon for capacity; each quote for the TCB |
| class | a name such as `s-4x16` | vCPUs, memory, the disk slots and the launch shape | the published reference values, one set per class and image |
| image | its launch bundle | the measured guest and its manifest | the signed reference values |
| pool | the orchestrator | image, class, hosts, depth per host, age limit, bind grace | the daemon |
| TD | the daemon | host, pool, the instance key's digest, state, the session it serves | its own evidence |
| session | the orchestrator | tenant, binder, state, the live TD, envelope counters | the key service for its generation and lease; the daemon for where it runs |
| seal | session and generation | its layers' ciphertext and sizes, by layer id | the key service, which alone holds the layers' keys and root hashes and knows whether it is the latest |
| template | its own name | a seal made before any secret, and who may fork it | the key service's record of it |
| binder | the tenant | the endpoint the daemon calls during flows | the authority it holds |
| envelope | session and sequence number | sealed bytes, in or out | the guest, which reads only what it can open and authenticate |

**A TD's life.** A TD only moves forward, and every end is final (rule R4):

```text
 booting --> ready --> claimed --> bound --> running <--> held
               ^          |                     |
               +----------+                     +--> sealing --> ended
     claim lapsed, or destroyed before a bind   +--------------> ended
 any state --> ended: destroyed, refused bind, age limit, crash, host lost,
                      lease lost
```

- **booting to ready.** The daemon launches the TD from the pool's bundle. The
  guest checks its launch document, makes its instance key and opens an
  attested session with the key service, which checks the guest's quote, hands
  it the vendor's documents it checked the quote against, for the guest to
  staple to its evidence, and releases nothing until a bind arrives. It is
  ready only once that session is open. Before then it refuses a bind unread,
  as not ready, so a pool whose key service it cannot reach offers no TD.
- **ready to claimed.** `Claim` fences the TD, so that no connection opened
  before the claim survives it, and reserves the TD for a session. A claim
  nobody binds before the bind grace runs out returns the TD to ready, since
  nothing of a tenant has entered it, and so does a `Destroy` of a claimed TD
  that was never sent a bind.
- **claimed to bound.** The guest takes one bind, measures it and refuses
  every other. A refused bind ends the guest. Since an unbound guest takes
  the first valid bind it is sent, the daemon lets nothing reach it before
  then but its own requests and the bind of its claim, and refuses `Connect`
  to it.
- **running and held.** `Hold` stops the TD's vCPUs, and `Release` starts
  them again. A `Commit` records the session's files while it runs; in
  continuous mode the guest commits its processes and files every epoch on
  its own.
- **sealing to ended.** The guest writes its seal, records it at the key
  service and ends.

**A session's life**, as the daemon sees it: new, live (running or held),
sealing, sealed, restoring, live again, and so on until destroyed. The
daemon's view is a cache. The key service decides which generation is the
latest and which TD holds the lease, and a TD that loses its lease ends.

## The calls

The API is gRPC over mutual TLS, with the same messages as JSON over HTTP
for callers that prefer it. Every call that changes something takes the
caller's `request_id`, and a repeat with the same id returns the first
answer and changes nothing (rule R8).

```protobuf
syntax = "proto3";
package c8s.session.v1alpha1;
import "google/protobuf/duration.proto";
import "google/protobuf/timestamp.proto";
// Messages not shown (Pool, Session, Operation, Stats, Event and the small
// requests) carry the fields the resource table lists.
service Pools {
  rpc CreatePool(CreatePoolRequest) returns (Pool);
  rpc UpdatePool(UpdatePoolRequest) returns (Pool);   // depth, or a new image rolled in
  rpc GetPool(GetPoolRequest) returns (Pool);
  rpc DeletePool(DeletePoolRequest) returns (Pool);
}
service Sessions {
  // Primitives
  rpc Claim(ClaimRequest) returns (Claimed);
  rpc Bind(BindRequest) returns (Bound);
  rpc Connect(stream Bytes) returns (stream Bytes);   // first frame names the TD and port
  rpc Deliver(DeliverRequest) returns (Delivered);
  rpc Collect(CollectRequest) returns (stream Envelope);
  rpc Hold(SessionRef) returns (Session);
  rpc Release(SessionRef) returns (Session);
  rpc Commit(CommitRequest) returns (Operation);
  rpc Seal(SealRequest) returns (Operation);
  rpc Destroy(DestroyRequest) returns (Session);
  rpc GetEvidence(EvidenceRequest) returns (Evidence);
  rpc GetStats(SessionRef) returns (Stats);
  rpc Watch(WatchRequest) returns (stream Event);
  // Flows: each calls the session's registered binder
  rpc Start(StartRequest) returns (Operation);
  rpc Restore(RestoreRequest) returns (Operation);
  rpc Fork(ForkRequest) returns (Operation);
}
service Binders {
  rpc RegisterBinder(Binder) returns (Binder);
}
// The daemon calls this on the binder; the binder decides.
service Binder {
  rpc SignBind(SignBindRequest) returns (SignBindResponse);
}
message ClaimRequest {
  string request_id = 1;
  string pool = 2;
  string session = 3;
  google.protobuf.Duration wait = 4;   // how long to wait for a ready TD
  Placement placement = 5;             // host affinity or spread
}
message Claimed {
  string td = 1;
  string host = 2;
  Evidence evidence = 3;
  google.protobuf.Timestamp bind_by = 4;   // the claim lapses after this
}
message BindRequest {
  string request_id = 1;
  string td = 2;
  bytes bind = 3;                      // c8s-bind/v1, canonical JSON
  bytes signature = 4;
  repeated DiskRef disks = 5;          // what the bind names, in its slots
  repeated LayerPlacement layers = 6;  // where each layer sits in the in slot
}
message Bound {
  Evidence evidence = 1;               // includes the bind; fresh over its nonce
}
message Evidence {
  bytes certificate = 1;               // RA-TLS; report data binds the instance key
  bytes launch_document = 2;
  bytes launch_signature = 3;
  repeated string events = 4;          // the digests the guest extended, in order
  bytes bind = 5;                      // when bound
  bytes quote = 6;                     // only in Bound: the guest's evidence envelope (JSON), fresh over the bind's nonce
  bytes collateral = 7;                // the vendor's documents, from the key service, stapled
  repeated bytes release_proofs = 8;   // the release log's proofs for the image, class and policies, stapled
  bytes bind_signature = 9;            // when bound; a verifier holds the bind to it
  string phase = 10;                   // as the guest reports it
}
message DiskRef {
  string slot = 1;                     // root, ro, in or out
  string source = 2;                   // the daemon's name for what goes there
}
message LayerPlacement {
  string layer = 1;                    // the id the guest gave the layer or record
  uint64 offset = 2;                   // bytes into the in slot
  uint64 size = 3;
}
enum SealLevel {
  SEAL_LEVEL_UNSPECIFIED = 0;
  PROCESSES = 1;                       // the sandbox's processes and files
  FILES = 2;                           // the sandbox's files, not its processes
  TEMPLATE = 3;                        // a template, before any secret entered
}
message SealRequest {
  string request_id = 1;
  string session = 2;
  SealLevel level = 3;
}
message CommitRequest {
  string request_id = 1;
  string session = 2;
}
message StartRequest {
  string request_id = 1;
  string pool = 2;
  string session = 3;
  string tenant = 4;
}
message RestoreRequest {
  string request_id = 1;
  string pool = 2;
  string session = 3;
  uint64 generation = 4;               // 0: whatever the key service says is latest
}
message ForkRequest {
  string request_id = 1;
  string pool = 2;
  string template = 3;
  repeated string sessions = 4;        // one new session per name
}
message DeliverRequest {
  string request_id = 1;
  string session = 2;
  bytes body = 3;                      // sealed by the sender
}
message Delivered {
  uint64 seq = 1;
  string session_state = 2;            // live, held or sealed
}
message SignBindRequest {
  string session = 1;
  string tenant = 2;
  Evidence evidence = 3;
  string purpose = 4;                  // start, restore, fork or template
  uint64 generation = 5;
  string template = 6;
}
message SignBindResponse {
  bytes bind = 1;                      // carries the binder's nonce
  bytes signature = 2;
}
```

What each call does, and what a daemon that cheats could do with it:

| Call | Caller | The daemon | The guest | If the daemon cheats |
|---|---|---|---|---|
| `CreatePool` | orchestrator | boots TDs from the bundle on the hosts named, up to the depth, and keeps them there | checks its launch document, makes its instance key, opens its session with the key service | it boots something else, and every verifier refuses the evidence |
| `Claim` | orchestrator | fences a ready TD and returns its evidence; waits up to `wait`, then says when the next will be ready | nothing until a bind | it hands one TD to two sessions, and the guest takes only one bind: denial of service |
| `Bind` | orchestrator or binder | places what the bind names on the TD's slots, and for a restore or a fork the stack's layers on `in`; posts the bind to the guest, and returns the evidence the guest answers with, fresh over the bind's nonce | checks and takes the bind, measures it, opens only the disks it names and the layers the key service releases, restores if it names a generation | it binds a TD to another authority, and every verifier sees the wrong authority in the evidence: denial of service |
| `Connect` | anyone, once the TD is bound | splices bytes to the guest's TLS port without terminating TLS, and holds the stream while a held or sealed session is released or restored; refuses a TD that is not bound yet | serves RA-TLS with its instance key, and c8s-verify's channel | it sees ciphertext, sizes and timing |
| `Deliver`, `Collect` | the platform's application tier; the owner's clients | stores and numbers envelopes | pulls, opens and authenticates them in the sender's order | it drops, delays or replays them, and the guest sees the gap or the repeat: denial of service |
| `Hold`, `Release` | orchestrator | stops and restarts the TD's vCPUs | after a release, renews its lease before any effect leaves | it holds forever: denial of service, with no second copy |
| `Commit` | orchestrator | makes room on the TD's `out` slot, stores the layer the guest writes there, then asks the guest to commit it | snapshots its files without stopping the sandbox, writes what changed since the last layer, records the generation at the key service, keeps its lease and runs on | it loses the layer, and the commit fails |
| `Seal` | orchestrator | makes room on the TD's `out` slot, stores the layers the guest writes there, then asks the guest to commit them | drains its gateways, checkpoints the sandbox if the level keeps processes (in continuous mode, only its last epoch), and writes new layers, each under a new key; then records the generation at the key service and ends | it loses the seal before the commit, and the session runs on at its last generation; after the commit, the key service refuses any older seal in its place |
| `Destroy` | orchestrator | ends the TD and deletes the session's ciphertext; returns a claimed TD that was never sent a bind to its pool, as a lapsed claim does | nothing: ending a TD needs no cooperation | the same as any host stopping a guest |
| `GetEvidence` | anyone | returns what the guest serves, with no fresh quote | serves its certificate, documents, events, bind and phase; it quotes fresh only in a bind's answer or over `Connect` | it serves stale evidence, and the RA-TLS handshake on `Connect` proves whether the key is live |
| `GetStats` | orchestrator | reports what a host sees | nothing | nothing new: the host saw it anyway |
| `Start`, `Restore`, `Fork` | orchestrator | `Claim`, then `SignBind` on the binder, then `Bind` | as for `Bind` | as for each step |

## The launch document

Each pooled TD boots with a launch document, `c8s-session-launch/v1`, signed
by its pool's launch key
([sessions.md](sessions.md#identity-and-attestation)). It names no tenant,
session or workload, so one document serves every TD of a pool, and a TD
learns whose it is only from its bind.

| Field | What it fixes |
|---|---|
| `pool`, `class` | the pool, and the class whose shape the TD was launched with |
| `image` | the measured image the pool boots |
| `machine` | the RTMR[0] values the release log lists for the class, since RTMR[0] records the virtual hardware the host declared; a TD whose RTMR[0] is not among them ends, and a document that lists none is refused |
| `ageLimitSeconds` | the pool's age limit: past it, a TD nobody has bound ends itself, by its own monotonic clock |
| `prestage` | images, by digest, that the guest unpacks before any bind so that a start need not pull them; the same for every TD of the pool, so they hold nothing of a tenant |
| `keyService` | the key service the pool's TDs open their sessions with: its address, its image's pins and its launch key |

## The bind

A bind is a canonical JSON document (RFC 8785), `c8s-bind/v1`, signed by the
owner's authority. The guest refuses a bind with a field it does not know.
The fields and purposes an agent accepts are its image's bind schema. The
build writes it from the agent's own definitions, and publishes it as it does
the disclosure schema: on the image's verity root, beside its manifest, and
in the release log with its reference values
([session-disclosure.md](session-disclosure.md#rules), rule 3).

| Field | What it fixes |
|---|---|
| `authority` | the public key that signs the bind, in PEM, so the measured digest fixes it and verifiers read the session's authority from the evidence |
| `instanceKey` | the digest of the TD's instance key, so the bind fits this TD alone |
| `session`, `tenant` | the session's name, scoped by the authority that signs it |
| `purpose` | `start`, `restore`, `fork` or `template`; with the `generation` a restore expects, or the `template` a fork comes from |
| `disks` | per slot, the root hash or digest of what the guest may open there |
| `policy` | the sandbox's images by digest; who may drive the session (`access`: the keys allowed to run commands, release credentials and open forwarded streams); the credentials it declares, by name, size and where each comes from (`credentials`); its egress allowlist; the inference endpoints it may reach and their pins; the most it may keep once its TD ends (`seal`: none, files or processes) and how it commits while it runs (`commit`: none, `files` on a timer, or `continuous` with an epoch and the size classes of its records); and the wall when the TD is a tenant VM |
| `keyService` | the key service the session trusts: exactly the one in the TD's launch document, which it opened its session with, or none when the session declares no credential from a key service; a TD refuses a bind naming any other |
| `review` | the session's review policy, by its digest in the release log, or none |
| `ownerKey` | under dual control, the owner's key manager: the key its share is wrapped to, and where to ask for it |
| `nonce`, `notAfter` | the binder's nonce, over which the guest answers the bind with fresh evidence, and a short validity, a minute by default, which the guest judges by the key service's time, never by its own wall clock ([Lease timing](session-state.md#lease-timing)) |

The guest measures the bind's digest (rule 2 in
[sessions.md](sessions.md#rules)), so the policy a session runs under is part
of its evidence, and the browser or SDK that verifies it can show the owner
exactly who may drive the session, which images, egress and inference it may
use, what it may keep once its TD ends, and which review policy, if any, may
report on it.

[Milestone 1](sessions.md#milestones) needs `start` binds only, and milestone
2 adds `restore`, the `seal` and `commit` policies and `ownerKey`. The other
purposes, and the `disks` and `review` fields, come with the milestones that
use them; until then an agent refuses them as fields it does not know.

## Flows

### Start

1. The orchestrator calls `Start(session, pool, tenant)`.
2. The daemon claims a ready TD, fencing it.
3. The daemon sends the TD's evidence to the tenant's binder in `SignBind`.
   The binder checks it as any verifier does, on the quote in the TD's RA-TLS
   certificate: the vendor's collateral, the image pins, the TCB level and
   the instance key the quote binds. That quote is as old as the certificate,
   since a guest quotes fresh only in a bind's answer or over `Connect`. Then
   the binder signs a bind naming the TD's instance key, the session, the
   disks (a fresh root, and the read-only images by root hash), the policy, a
   nonce and a `notAfter` a minute away.
4. The daemon calls `Bind`. The guest takes the bind, measures it, and starts
   the sandbox on the root file system it made before any bind, under a key it
   generated. The answer carries a fresh quote over the binder's nonce, with
   the bind in the TD's measurements.

A bind holds no secret, so a stale quote costs at most a wasted bind: keys
and credentials reach a session only after the key service, or the owner's
client over `Connect`, has checked a fresh quote itself.

No boot is on this path: a start is two round trips to the guest plus the
binder's check.

### Hold and release

1. `Hold` stops the TD with QMP's `stop`, on a socket only its launcher holds,
   which stops the vCPUs and QEMU's devices, vhost back ends included. The
   guest is told nothing. A hold may first ask the guest to give back its free
   memory ([Levers](session-performance.md#levers)), so that a held TD costs
   about what its processes hold.
2. `Release` resumes the TD with QMP's `cont`. The guest's clock has moved on
   while it was held, so its gateways find the lease stale and let no effect
   leave until the agent has renewed it at its grant number
   ([session-state.md](session-state.md#lease-timing)). If the key service
   refuses, because another TD now holds the session, this TD ends with "lease
   lost".

A TD has no paravirtual clock to tell it that it was stopped, so its kernel
takes a hold for a stall. The session kernel builds no lockup detector, and
its RCU stall warnings only warn, so a hold of any length panics nothing.
QEMU's TDX code has no handler for a change of run state
(`target/i386/kvm/tdx.c`), so a hold is QEMU's generic stop. Milestone 1's
launcher runs QEMU with no monitor at all, so milestone 2 adds the QMP socket,
and its first test is whether a TD comes back from a hold with its clock,
devices and network intact, after a second, after a lease's length and after
an hour.

### Seal, restore and fork

`Commit` records a session's files while it runs, and continuous mode
commits its processes and files every epoch, holding each output until its
epoch is committed. `Seal` checkpoints the session inside the TD and ends
it, `Restore` brings the latest generation back into a new TD, and `Fork`
starts many sessions from one template. A restore and a fork are each a bind
with a purpose, so a guest restores or forks only when the owner's authority
says so. [session-state.md](session-state.md) specifies them, with the
layers and journals they write and the leases that keep one live copy.

### Moving sessions off a host

A TD cannot migrate between hosts: TD migration is not in Linux or QEMU
today. A session moves the only way a TD can: `Seal` on the old host and
`Restore` on another, with its processes. Connections that leave the sandbox
close at the seal, and the session makes them again as it needs them.
Draining a host, for a TCB recovery or an upgrade, seals every live session
and restores each elsewhere. In continuous mode a seal writes only its last
epoch and the restore runs before its layers are read in full, so a move
stops a session for about an epoch and the start of a restore.

### Destroy

1. `Destroy` ends the TD, which needs no cooperation from the guest, and the
   daemon deletes the session's ciphertext and envelopes.
2. The binder deletes the session at the key service, which tombstones its
   keys; they are gone once the retention period ends. Until then a copy of
   the ciphertext the daemon kept is unreadable without the key service.

## Errors, retries, versions and limits

- **Errors** use gRPC's codes: `NOT_FOUND`; `ALREADY_EXISTS` for a new request
  id that names an existing pool or session; `FAILED_PRECONDITION` for a call
  in the wrong state, such as a bind on a TD claimed for another session or a
  seal its bind does not allow; `ABORTED` when the key service refuses a
  compare-and-swap; `RESOURCE_EXHAUSTED` when no TD is ready within `wait` or
  a quota is reached, with the expected wait in gRPC's `RetryInfo` (for an
  empty pool, how long its last boot took). `UNAVAILABLE` means a lost host or
  an unreachable key service, and is worth a retry. A guest's own refusal
  comes back as a separate detail, so a caller can tell the guest's decision
  from a daemon fault; a daemon could forge one, which only denies service.
- **Retries.** A request id is kept for 24 hours, and a repeat returns the
  stored answer, across a restart too: the daemon keeps the first answers of
  `Claim` and `Bind` in each TD's record on disk, and TDs outlive it, each
  under a launcher process of its own, so a new daemon takes them over.
  `Commit`, `Seal` and the flows return an operation with a phase that the
  caller polls or waits on: draining, writing, storing, committing and done
  for a seal or a commit; claimed, bound, restoring and done for a flow. A
  flow can be cancelled until its bind, and after that only by `Destroy`.
- **Versions.** The package is `c8s.session.v1alpha1`, and fields are only
  ever added. The bind keeps its own schema version, `c8s-bind/v1`.
- **Limits**, per orchestrator: pools, live TDs, held TDs, seal bytes and
  queued envelope bytes per session, each refused past its limit with
  `RESOURCE_EXHAUSTED`.
- **Events** from `Watch`: a TD ready, claimed, bound, held, released,
  sealing or ended (with its reason); a session committed or sealed (with
  its generation) or restored (with whether its processes came back); a
  pool's depth. Continuous mode's epochs are counted in `GetStats`, not sent
  as events.

## Other doors

### The Firecracker-compatible adapter

It serves Firecracker's API paths on the session API, for an orchestrator
written for Firecracker. No Firecracker code runs behind it.

| Firecracker call | Session API |
|---|---|
| `PUT /boot-source`, `/machine-config`, `/drives`, `/network-interfaces` | picks the pool by class and image; only the image's own kernel and a class's shape are accepted |
| `PUT /actions` with `InstanceStart` | `Start`, with the bind from the platform's binder |
| `PATCH /vm` to `Paused`, then `Resumed` | `Hold`, then `Release` |
| `PUT /snapshot/create` | `Seal(PROCESSES)`, or `Seal(TEMPLATE)` |
| `PUT /snapshot/load` | `Restore` for a sealed session, `Fork` for a template |
| `/mmds` | kept, as untrusted input that never carries a secret |
| `/balloon` and its hinting | the guest's own return of free memory, through a change to its kernel ([session-performance.md](session-performance.md#levers)) |
| `/entropy` | accepted and not relied on: the TD seeds itself |
| `/vsock` | bridged to the guest |
| `/metrics` | `GetStats` |

A Firecracker VM can resume after `PUT /snapshot/create`, but a seal ends
its TD, since a process image whose TD ran on would be spent at once
([session-state.md](session-state.md#commit)). So a resume after a snapshot
is a `Restore`.

The difference that matters is `/snapshot/load`. In Firecracker, every VM
loaded from one snapshot starts with that snapshot's memory, and so with its
secrets and its generators' state; Firecracker's own documentation finds "no
generic solution" for user-space generators in clones
(`docs/snapshotting/random-for-clones.md`). Here a fork comes only from a
template sealed before any secret, and each fork makes its own keys.

### Kubernetes

- **Pod-as-CVM** runs each TD in a pod of its own, started by a launcher in
  the pod, for platforms that schedule sessions as pods
  ([Modes](sessions.md#modes)).
- **agent-sandbox**, the Kubernetes SIG Apps project, defines `Sandbox`,
  `SandboxTemplate`, `SandboxWarmPool` and `SandboxClaim`, which map onto the
  session API:

| agent-sandbox | Session API | What changes |
|---|---|---|
| `SandboxWarmPool` | `CreatePool`, `UpdatePool` | the template's pod is a c8s launcher for one class and image |
| `SandboxClaim` | `Start`, through the binder | environment and volumes arrive in the bind after the claim, so they no longer cost a cold start |
| `Sandbox` suspended, then running | `Seal`, then `Restore` | the seal is made, and stays sealed, inside the TD |
| `shutdownTime`, `shutdownPolicy` | `Destroy` | |
| the sandbox router | `Connect` | TLS ends in the guest, not at the router |

## Open questions

1. **A held TD.** Whether a TD survives QMP's `stop` and `cont` with its
   clock, devices and network intact, and how long a hold may last.
2. **The binder's placement.** Which deployments run the binder in the
   owner's client, which in an attested service of the owner's, and what a
   platform-run binder should show in the evidence.
3. **Quotas per tenant** as well as per orchestrator.
