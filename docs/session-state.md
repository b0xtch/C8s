# Session state: holds, seals, leases and keys

Status: design; nothing here is built yet. [sessions.md](sessions.md) is the
overview, and [session-api.md](session-api.md) has the calls.

A session outlives the TD it runs in. It is held while its user is away for a
moment, sealed when they are away for longer, restored into a new TD when
they return, and forked from templates. The host may not snapshot a TD, so
everything here happens inside the guest, and the key service, not the host,
decides which copy of a session is the live one.

## Three ways to pause

| Level | Keeps | The TD | Comes back as |
|---|---|---|---|
| hold | memory, processes, connections | stays, its vCPUs stopped | the same TD, once its lease is renewed |
| seal `PROCESSES` | the sandbox's processes and files, and the agent's state | ends | a new TD, with the processes running |
| seal `FILES` | the workspace | ends | a new TD, with the processes started fresh |

A hold costs a host the TD's memory and nothing else. A seal frees
everything but disk, and its restore pays for reading the seal back.

## Seal

1. The orchestrator calls `Seal(session, PROCESSES)`.
2. The daemon makes room on the TD's writable `out` slot ([Disks](#disks))
   and asks the guest to seal.
3. The guest's gateways finish the effects in flight and start no new ones,
   and the sandbox freezes. The guest checkpoints the sandbox, with gVisor's
   checkpoint or with CRIU for a container sandbox, together with the
   session's writable files and the agent's own state: the session key and
   the envelope counters. It writes them to the `out` slot under a new key,
   with dm-verity over the plaintext and dm-crypt over both. Under dual
   control the new key is made from two shares, one for the key service and
   one wrapped to the owner's key
   ([Dual control](session-key-service.md#dual-control)).
4. As the lease holder, the guest asks the key service to move the session
   from generation g to g+1, naming the new key and verity root, by
   compare-and-swap, which also releases the lease, since its effects have
   already stopped. It answers the host with the generation, the size and the
   digest, and ends.
5. The daemon keeps the slot's contents as seal g+1 and copies them to
   durable storage, since availability is its job.

If the compare-and-swap fails because the TD lost its lease or the generation
moved, another copy exists, so the TD ends without sealing. If the key
service cannot be reached, the seal fails, the sandbox thaws and runs on, and
the orchestrator retries or holds.

## Restore

1. The orchestrator calls `Restore(session, pool)`, typically when an
   envelope arrives for a sealed session.
2. The daemon claims a TD and places the seal on its read-only `in` slot.
   Then it asks the binder for a bind with purpose `restore`, naming the
   session and asking for its latest generation, under the same policy.
3. The daemon calls `Bind`. The guest asks the key service for the session.
   The key service checks the TD's evidence and its bind, grants the lease to
   this TD's instance key, and releases the seal's key and verity root. Under
   dual control it releases its share of the key, and the owner's key manager,
   checking the same evidence and bind, releases the other.
4. The guest asks the daemon where the seal sits on the slot, reads it with
   direct I/O through dm-crypt and dm-verity, and restores on demand, with
   gVisor's background restore or CRIU's lazy pages, so the session runs
   before the whole seal is read. It makes the next session key and drains
   its inbox.

**A process image is restored at most once.** The key service marks a
generation's process image spent when it grants the lease to restore it. A TD
that seals leaves a fresh image at g+1. A TD that dies leaves g's image
spent, so the next restore brings back g's files and the agent's keys but
starts the sandbox's processes fresh, as a reboot would. Restored a second
time, those processes would draw again the random values the dead TD may
already have used in its effects, which is the replay that clones of one
snapshot suffer ([Prior art](#prior-art)). The work done since g is lost
either way.

## Templates and forks

1. **A template is a sealed session.** The binder starts a session whose bind
   marks it as a template, and it does its setup: clones repositories,
   installs dependencies, perhaps warms a language server. Credentials stay
   in the guest's gateways, outside the sandbox, so a template taken after a
   clone carries the checkout but not the token.
2. `Seal(session, TEMPLATE)` checkpoints the sandbox only. The agent refuses
   it once any secret has entered the sandbox itself. The key service records
   the seal as an immutable template of its tenant, released to many TDs and
   leased by none.
3. `Fork(template, pool, sessions)` runs a restore per new session. Each TD
   takes the template's key without a lease, takes a new lease on its own
   session at generation 0, draws its own entropy and makes its own session
   key.
4. **Random state.** A restored kernel and gVisor's random devices draw fresh
   entropy, but a process that seeded its own generator before the seal
   keeps that state. So a template keeps processes only if they hold no
   secret and either draw nothing random before the seal or reseed when the
   sandbox tells them they were restored, as gVisor can. Otherwise the
   template is sealed with no processes running: it keeps its files and gives
   up the warm processes.

## Generations and leases

### What the key service keeps for a session

| Field | What it is |
|---|---|
| name | the session's authority and its id, so two tenants' sessions cannot collide |
| authority | the key whose binds may acquire the session or fork the template; set when the first TD creates the record |
| generation | a counter that only moves forward, by compare-and-swap |
| seal | the latest seal's verity root and key, wrapped under the key service's key |
| lease | the digest of the instance key of the TD that holds the session; the leader keeps its renewals in memory ([session-key-service.md](session-key-service.md#leases-across-a-change-of-leader)) |
| process image | fresh, or spent once a restore of it has been granted the lease |
| session key | the public halves of the current and previous session keys |
| kind | session or template; a template is immutable, released to many and leased by none |
| tombstone | set at delete; the keys go once the retention period ends |
| review budget | what the session has spent of its review policy's budget, today and over its life ([session-disclosure.md](session-disclosure.md#private-review)) |

### What a guest asks of it

Over its attested session with the key service, a guest can acquire a
session (the lease, the key and the verity root, for a bind that names the
session, which spends the generation's process image); renew its lease;
advance the session from g to g+1 with a new seal, only as the lease holder;
release the lease at a clean end; spend from its review budget before a
signal leaves; and take a template's key, with no lease, for a bind that
names the template. The key service judges each call by the
caller's evidence and by its bind, which the session's authority must have
signed.

### Lease timing

- **Defaults.** A lease runs 60 s, and the guest renews it every 15 s. The
  guest lets an effect leave only within 45 s of when it sent its last
  successful renewal, measured by its own clock, and the key service grants
  the lease to another TD only once 60 s have passed since its own last
  answer. So the old TD stops before the new one starts, as long as the
  guest's clock runs no slower than real time.
- **The guest's clock.** On TDX the TSC frequency is fixed when the TD is
  created and the host cannot change it afterwards (inferred; to be checked
  against the TDX module specification). A hold does not stop the TSC, so a
  held TD finds its lease stale when it is released. It may renew a lapsed
  lease as long as no other TD has taken it since.
- **Every effect passes a gateway.** Egress, outgoing envelopes and model
  calls all leave through the measured agent: the egress proxy is the
  sandbox's only way out and the inference gateway its only path to
  inference. The lease check therefore sits in one place. When the lease goes
  stale, the gateways stop passing bytes on every connection, not only new
  ones, and the sandbox can compute but cannot act.

### When things fail

| What happens | What follows |
|---|---|
| the host dies | the lease runs out, and a restore elsewhere takes it after at most 60 s |
| a restored TD dies before it seals | the next restore brings back the files of the last seal and starts the processes fresh, since the image is spent |
| the key service is down | live sessions keep computing, and their effects stop 45 s after their last renewal until it returns; nothing is restored anywhere meanwhile, since only the key service releases keys. That is the price of one live copy, which a longer lease trades against slower recovery from a dead host |
| the host cuts a live TD off from the key service and restores the session elsewhere | the old TD stops its effects at 45 s, and the new one gets the lease after 60 s; at no moment do two copies act |
| the host offers an older seal | the key service releases keys only for the latest generation |
| the host holds a TD past its lease and releases it | its gateways stop every effect until a renewal succeeds, and a refused renewal ends it |

## The session key

An HPKE key pair (RFC 9180), with a hybrid KEM of ML-KEM-768 and X25519, that
the session's first TD makes when its first envelope or secret arrives. Its
public half is published in the TD's evidence, signed with the instance key
that the quote binds, and in the key service's record. Its private half lives
in the agent's state and travels only inside seals. Each restore makes a new
pair, and so does each day a session runs; the previous pair is kept until
the next change, so an envelope sealed to it in the meantime still opens. A
template has none, since it is sealed before any secret.

## Disks

A disk reaches a guest only on a slot the guest has had since boot:

- **Slots are fixed per class.** Every TD of a class boots with the same
  virtio-blk devices, so the set of devices the host declares is part of the
  class's reference values, and nothing is hot-plugged later.
- **Data is placed at offsets.** A slot's backing is a sparse file. The daemon
  copies a seal or a workspace into free units of that file, the guest asks
  where it sits, reads those units with direct I/O and checks them through
  dm-verity and dm-crypt. The guest trusts nothing it reads from a slot more
  than a network connection's bytes.
- **So "attach" is a message** naming an offset on a disk the guest already
  has: no VMM change at run time and no device event in the guest.

| Slot | Guest's access | Holds |
|---|---|---|
| `root` | read and write | a fresh dm-crypt layer for this TD's life, under a key the guest makes |
| `ro` | read only | public images, checked against the digests or root hashes the bind names |
| `in` | read only | seals, templates and workspaces, at offsets |
| `out` | read and write | seals on their way out |

The `in` slot could later be served by the daemon as a network block device,
so that placing a seal is a map entry rather than a copy, and a seal still in
object storage is read block by block as the restore touches it.

## The message box

- **Two queues per session**, an inbox and an outbox, which the daemon stores
  as ciphertext. The daemon numbers envelopes for delivery; the sender
  numbers them again inside the seal, for order and against replay.
- **The guest pulls.** Its agent opens a channel to the daemon's box service,
  reads everything after the last envelope it processed and pushes its
  outbox. No new host request is needed.
- **Envelopes** are HPKE to the session key and signed with a sender key that
  the bind names, so the guest reads only what it can open and authenticate.
  Each envelope's header (version, suite, session, key, sequence number and
  expiry) is HPKE's associated data, so the host cannot move an envelope to
  another session, replay it after it expires, or change its suite.
- **Size.** Up to 1 MiB an envelope by default; files go through the
  workspace.
- **A sealed session's mail waits.** Whether a `Deliver` releases or restores
  the session is the orchestrator's policy.

## The key service

The key service is built from CDS, whose verification and release code it
reuses. CDS today keeps its secrets and volume keys only in process memory
([README](../README.md#known-gaps-and-open-items)), which sessions cannot
afford: a lost generation counter would let an older seal run. So the key
service adds what sessions need:

- **Durable records** for sessions and templates, with generations moved only
  by compare-and-swap, leases, wrapped keys, tombstones and retention.
- **Replicas in attested CVMs**, three to five, sharing a replicated log. A
  replica joins only after the others have verified its evidence, and the
  key that wraps every record exists only inside the replicas.
- **Pins in the bind.** A guest trusts the key service the bind names, by
  measurement, so the platform cannot point a session at a key service of its
  own.

[session-key-service.md](session-key-service.md) has the rest: how leases
survive a change of leader, the ledger and its witnesses, recovery and escrow,
and the release rule.

## Prior art

- **Clones of one snapshot repeat what memory holds.** Brooker et al. list
  what clones of one microVM snapshot share: user-space generator state,
  unique identifiers, and the counters behind nonces. They propose wiping
  marked memory and a generation counter user space can watch, and argue that
  the environment must hold back every side effect until reseeding is done
  ("Restoring Uniqueness in MicroVM Snapshots", 2021). The kernel's generator
  is reseeded through VMGenID, which in Firecracker's words leaves "a race
  window between resuming vCPUs and Linux CSPRNG getting successfully
  re-seeded"; for generators in user space it finds "no generic solution
  under the current programming model"
  (`firecracker:docs/snapshotting/random-for-clones.md`).
- **Lazy restore at scale.** Lambda serves container images and snapshots in
  chunks from tiered caches, deduplicated under convergent encryption ("On-
  demand Container Loading in AWS Lambda", USENIX ATC '23). REAP records a
  function's working set and prefetches it at restore (ASPLOS '21). Lambda
  SnapStart asks functions to make unique values and secrets after a restore,
  in hooks.
- **Confidential VMs.** No published system was found that snapshots a TDX or
  SEV-SNP guest and restores it into new guests with new identities. TD
  migration moves one live TD between hosts and keeps the source and the
  destination from both running on; it does not restore one image into many
  TDs. SEVeriFast speeds up the boot of SEV guests, noting that snapshot
  techniques rely on prefetching, lazy loading or shared deduplicated blocks
  that do not carry over to confidential guests as they are (ASPLOS '24).
- **Enclaves.** Graphene-SGX forks a process by attesting a new enclave and
  sending it a snapshot over an attested channel (USENIX ATC '17). Gu et al.
  checkpoint an enclave from inside under a fresh key, restore it into an
  attested new enclave, and have the source destroy itself so that no two
  copies run ("Secure Live Migration of SGX Enclaves on Untrusted Cloud",
  DSN 2017).

What is new here:

1. **Seals of a confidential VM, restored with new identities.** The seal is
   taken inside the TD, the key service releases its key only to an attested
   TD with a signed bind, and each restore or fork runs with a new instance
   key, new entropy and a new session key: the enclave pattern, carried to
   whole agent sessions.
2. **One live copy that holds against the host.** Platforms that keep a single
   runner do it in their own control planes, which a confidential design
   cannot trust. Here the guest stops its own effects when its lease goes
   stale.
3. **The fence Brooker et al. ask for.** Every effect leaves through the
   guest's gateways, so nothing leaves a restored TD before its lease is
   fresh, and since a process image is restored at most once, a crash never
   replays a generator's state into new effects.
4. **Secrets outside the template, and protected.** Credentials stay in the
   gateways, which run inside the TD, so a template carries none and the host
   reads none.
5. **Lazy restore without a shared key.** Each seal has its own key, so
   contents deduplicate only across forks of one template, and the host sees
   which units a restore reads but not what they hold.

## Open questions

1. **What a seal costs** at a session's full size, and how much of it lazy
   restore hides.
2. **Commits while running**: whether a session's workspace should also be
   sealed periodically, so a dead TD loses less work.
3. **The access pattern of a lazy restore**, which the host sees, and whether
   it needs padding or prefetch of the whole working set.
