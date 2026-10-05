# The session key service

Status: design. Milestone 1 built a first, single replica with what a start
needs: pooled TDs' sessions, acquiring a session at its bind, tenants'
authorities on first use, and stored credentials. Milestone 2 adds sessions'
generations, layers, journals and leases to it, on three replicas on one
host; the rest is not built yet.
[session-state.md](session-state.md) says what sessions ask of the key
service; this document is how it keeps its promises when the hosts it runs
on are untrusted.

The key service decides three things for every session: which generation is
the latest, which TD holds the lease, and who may have the keys. A host that
could roll it back or split it in two could run a session twice or bring back
an old seal, so it is built to hold against the hosts it runs on, against the
platform's operator, and through the loss of its own replicas.

It grows out of CDS, whose verification and release code it reuses, in Go.
CDS keeps what it holds in process memory
([README](../README.md#known-gaps-and-open-items)); the key service adds
replicated records, a ledger that cannot go back, and recovery.

## What it keeps

- **Records.** For each tenant: its authority key, its recovery key and the
  signed chain of their changes. For each session and template: the record in
  [session-state.md](session-state.md#what-the-key-service-keeps-for-a-session).
  For each instance key that has presented a bind: the bind's digest, and for
  each pooled TD with an open session to the key service, the verdict on its
  evidence. And the policy: the reference values it accepts, the TCB statuses
  besides UpToDate it accepts of each pool's guests (in milestone 1,
  `pools[].acceptTCBStatus` in its launch document), the platforms it accepts,
  the operators who may change policy and the escrow holders.
- **Keys are random and kept as records.** Each layer's key is made in the
  guest that writes it, and the key service keeps it as given. Deriving every
  key from one seed would leave a deleted session's keys derivable for as
  long as the seed lives, and generations, leases and tombstones must survive
  a recovery anyway, so the key service recovers records, not a seed.
- **Only the replicas decide.** Records live in the replicas' memory,
  replicated by consensus. The platform may cache what placement needs, but a
  cache never decides, since a host that kept an old copy could replay it.
- **Delete.** Deleting a session replaces its record with a tombstone at
  once, so no replica releases its keys again. Its keys then survive only in
  the encrypted ledger and its snapshots until they age out, after 30 days by
  default; after that, only the escrow holders acting together on a copy
  someone kept could open them ([Escrow](#escrow)). That is the bound on
  deletion the key service states.

## Replicas

- **A quorum in CVMs.** Three replicas at first and five later, each in its
  own CVM on a different host. The key service's image is built and published
  like the guest's, with reference values of its own, and guests and clients
  check a replica's evidence against them. Replicas run Raft, with etcd's
  library, over channels on which each attests the other.
- **Its own machine.** A replica boots with the key service's launch document,
  `c8s-key-service-launch/v1`, which is its policy, signed by the launch key
  that guests and clients pin, and measured at boot. It lists the RTMR[0]
  values the replicas' class may have, under the pools' rule ([The launch
  document](session-api.md#the-launch-document)): a replica on any other
  machine ends before it serves, and under a document that lists none it
  serves its evidence and releases nothing. Guests and clients hold a
  replica's RTMR[0] to that list, and a replica checks its own devices as a
  guest does.
- **The host is the network.** It can drop, delay, reorder or replay messages
  and stop any replica, but it cannot read or forge them inside the attested
  channels. Raft stays safe under exactly that, as long as every replica runs
  it as written, which attestation checks; liveness is the host's to deny, as
  everywhere. From milestone 2 a replica has no network device: its launcher
  listens on a port of the host and carries each connection over vsock, from
  guests and clients, between replicas and out to the vendor's service. A
  replica takes vsock connections only from its own host, which carries the
  same ciphertext it would on a network, and a replica's kernel needs no
  network driver.
- **No disk is trusted.** A replica keeps its log, term, vote and state in
  memory only. One that restarts comes back as a new member with a new
  instance key, joins as a learner, catches up from the leader's snapshot and
  is then promoted, and its old identity leaves the group. A replica that read
  its vote back from a disk the host had replayed could vote twice in one term
  and help elect two leaders; never reading the disk on restart closes that.
- **Reads go through the quorum.** A release reads the generation with Raft's
  ReadIndex, which confirms the leader with a round to a majority, never under
  a leader lease, which etcd's library counts in ticks that stop while the host
  pauses the leader's TD. Grants, seals and restores are Raft writes, each a
  compare-and-swap.
- **Planned moves keep the quorum.** Draining a host adds a replica elsewhere
  first, then removes the old one. Losing a majority at once, as in a power
  cut across the hosts, is a [recovery](#recovery).

## Leases across a change of leader

Renewals are the key service's most frequent call: every live session renews
its lease every 15 s ([Lease timing](session-state.md#lease-timing)). They
must stay cheap, and a change of leader must never let two TDs hold one
session.

- **A renewal is no log entry.** The leader keeps renewals in memory and
  answers them in batches, each batch after a ReadIndex round to a majority
  that began after its renewals arrived. A leader that has lost its majority
  cannot finish such a round, so a deposed leader stops answering renewals.
- **A grant is a log entry.** Granting a session's lease to a new TD is a Raft
  write, which the leader makes only when the lease is free: released by its
  holder, which a seal does, or 60 s past both the last renewal this leader
  answered for that session and this leader's own election.
- **Why that is enough.** An old leader answers a renewal only after a
  majority round that began after the renewal arrived, and no such round can
  finish once a majority has moved to a newer term, which it must have done
  for a new leader to be elected. The guest counts its 45 s from when it sent
  that renewal, so it stops acting at least 15 s before the new leader may
  grant the lease to another TD, however long the host delays any message.

This holds as long as each TD's clock runs at the rate it was created with,
which the TDX module keeps the host from changing (inferred, as in
[session-state.md](session-state.md#lease-timing)). A TLA+ model of leases,
generations and leader changes is checked before the replicated version
ships.

## Ledger and witnesses

- **A ledger on untrusted disks.** Each replica writes every entry it accepts
  to an append-only ledger on its host's disk before it acknowledges the
  entry, encrypted under a ledger key held in memory, as the leaves of a
  Merkle tree, and closed parts of the ledger are copied to two object
  stores. The leader signs a checkpoint of the tree every 5 s, in the C2SP
  checkpoint format. A ledger is read only in a recovery, never by a
  restarting replica.
- **Witnesses keep it from going back.** Each checkpoint goes to witnesses
  that cosign it, with a timestamp, only as an append-only extension of the
  last checkpoint they cosigned for this key service, checked by a
  consistency proof (C2SP's `tlog-witness`). At least one witness runs outside
  the operator's reach, and two of three cosignatures make a checkpoint
  count.
- **Receipts.** An owner's client can ask for an inclusion proof, under a
  cosigned checkpoint, that a release, a seal, a grant or a change of its
  authority is in the ledger, and check it offline. Every release, seal and
  accepted bind is an entry, so an owner can audit its own sessions.

## Recovery

- **When no quorum lives**, new replicas start in recovery mode, take the
  longest valid ledger the hosts and stores offer, and serve nothing until
  enough escrow holders have each checked a recovery replica's evidence with
  their own tool and sent it their share of the recovery key, encrypted to its
  instance key. With enough shares the replica opens the ledger key, checks
  the chain and its signatures, and goes on only if the ledger reaches the
  newest cosigned checkpoint, since the witnesses cosign nothing that falls
  short of it.
- **Accepting a loss.** If no ledger reaches it, the holders can sign a
  statement naming what they accept, and the key service starts a new log that
  names the old log's last checkpoint.
- **No second group.** A host that hid a live group to force a recovery would
  leave two. A leader that has had no cosigned checkpoint for an hour stops
  serving, holders send shares only once an hour has passed since the newest
  cosignature, and witnesses cosign only one line of history, so at most one
  group makes progress.
- **What a recovery can lose.** The epoch rises, and every release carries
  it. A seal recorded after the newest cosigned checkpoint, at most a few
  seconds before the loss, can be missing, so that session comes back at its
  previous generation, with its processes started fresh since that image was
  spent. An owner that wants no such window waits, at seal, for a receipt.

## Escrow

The recovery key wraps the keys of the ledger and its snapshots. The key
service splits it k of n with Shamir's scheme and encrypts each share to its
holder's hardware token, and it is put together only inside an attested
recovery replica. It rotates whenever the holders change and after each
retention period, so old shares open nothing written since. k holders who
combined their shares outside a replica and held a copy of the ledger could
read every key in it: that is escrow's price, and an owner who will not pay it
holds a share of each key, or all of it, itself
([Dual control](#dual-control)). A second key service
in another region could later hold this one's recovery key in its attested
state and release it by the same checks, keeping the holders for the loss of
both.

## Release

The key service releases the keys of a seal's or a template's layers, or a
stored credential, only when all of these hold:

1. The TD's evidence verifies against an image and a class from the release
   log, with their proofs, and against accepted attributes and platform, with
   each TCB level UpToDate or accepted by name for the TD's pool ([An old
   TCB](session-threat-model.md#launch-and-measurement)), on the vendor's
   documents as the key service fetched them itself within the last hour.
2. The request arrives over a live channel to the instance key in that
   evidence.
3. The TD presents a bind naming that instance key, signed by the authority
   the key service holds for the tenant that owns the session, template or
   credential, with its receipt for that bind, signed by the one-time key its
   evidence binds.
4. The bind's purpose and policy allow what is asked.
5. For a session, the generation asked for is the latest, read through the
   quorum, and the lease is free or already this TD's.
6. The key service has not already accepted a different bind for this
   instance key.

- **Off the hot path.** A pooled TD opens its attested session to the key
  service at boot, before it has a tenant. The key service verifies its
  evidence then and keeps the verdict and the evidence by instance key in its
  replicated state, so acquiring a session at bind time costs one round trip
  and one quorum write, and the key service needs no new quote. It answers
  with the vendor's documents it checked the quote against, which it fetches
  from the vendor itself once per platform, asks for again each hour and
  judges by its own clock, and newer ones in a later answer when the vendor
  publishes them. When a newer document arrives it judges again, still with no
  new quote, the evidence it keeps: each pooled TD's, so that no release rests
  on a document it has since replaced ([Old vendor
  documents](session-threat-model.md#launch-and-measurement)), and each lease
  holder's, once for each platform, so that no lease is renewed on a platform
  the vendor has since revoked or a pool no longer accepts ([When things
  fail](session-state.md#when-things-fail)). The TD staples them to its
  evidence, so no TD fetches them itself and no boot waits on the vendor's
  service.
- **Sealed to the instance key.** What is released is also encrypted with
  HPKE, under the hybrid KEM, to the encryption key that the TD's instance key
  signed, inside the attested channel. A log or a proxy that ever saw the
  channel's plaintext would see no key, and traffic recorded now stays closed
  to a quantum computer later.
- **Against the session in the TD.** A TD's instance key and its channel to
  the key service outlive its bind, so code that broke out of the session's
  sandbox could use them to present a bind that another binder signed after
  the host showed it the TD's ready evidence. Rule 3's receipt stops that:
  only the agent, as it takes the TD's one bind, can sign one, since the key
  it signs with is erased before anything of the tenant runs, and rule 6 gives
  an instance key one bind ([A session that reads its own
  TD](session-threat-model.md#binding-and-identity)).

## Who decides

- **Policy** (accepted reference values, accepted TCB statuses, platforms, the
  escrow holders and how many it takes) changes only by a statement that m of
  n named operators sign, applied as a ledger entry.
- **A tenant's authority** changes only under the tenant's current key or its
  registered recovery key, never under an operator's statement. The first
  registration is trust on first use, and the owner's client checks for a
  receipt of it.
- **Upgrades.** A new version's reference values join the policy only from the
  release log ([Releases](sessions.md#releases)), replicas of the new version
  join as learners, and the old ones leave one at a time. Each set of values
  names the oldest version it accepts.
- **No person releases keys.** No operator, escrow holder or support role has
  a call that releases a session's key, a template's or a credential. Keys go
  only to attested TDs, by the rule above, and escrow opens only inside an
  attested recovery replica.

## Dual control

Who holds a session's seal keys is the owner's choice, made per tenant:

| Mode | The key service holds | The owner holds | A seal opens when |
|---|---|---|---|
| platform-held | each layer's and journal's key, under escrow | nothing | the key service releases them |
| dual control | a share of each layer's and journal's key | the other share, in its own key manager | both release their shares to the same attested TD |
| owner-held | generations and leases only | the whole of each key | the owner's key manager releases them |

- **Two shares.** Under dual control the guest that writes a layer or starts
  a journal makes two random shares and derives the key from both. One share
  goes to the key service with the new generation; the other is wrapped to
  the owner's key and stored with the ciphertext. A restoring TD asks for both.
  The key service and the owner's key manager each check its evidence and its
  bind for themselves and release their share encrypted to it, and neither
  share alone opens anything.
- **What each side keeps.** The key service still decides which generation is
  the latest and who holds the lease, so one live copy and freshness hold in
  every mode. The owner can stop every restore at once by withholding its
  share, and escrow opens nothing of the owner's, since an escrowed share is
  half a key.
- **The owner's key manager** checks evidence as a binder does, and may be the
  binder itself. One that unwraps a share for whoever the platform names,
  without checking evidence, would protect the seal at rest and nothing more,
  so it does not qualify. An owner who loses its share loses its sessions.

## Its clock

A replica is a TD, so its wall clock is its host's, and the key service judges
the vendor's collateral, revocation lists and binds' `notAfter` by it. A host
that wound a replica's clock back could pass collateral the vendor has
replaced. So each replica keeps a floor under its time from the witnesses:
asked again, they cosign the newest checkpoint with a fresh timestamp, and a
replica counts an answer only if it came back within 30 s by its own TSC. When
two timestamps of one round agree within a minute, the lower of them, plus the
TSC's count since it arrived, can raise the floor, which never falls. The
replica's time is the later of the floor and its wall clock, and it judges no
dates until it has a floor. A host can then move a replica's time forward,
which only makes it refuse, and never more than 90 s back. Guests take their
time from their session with the key service: its answers carry its time, to
which a guest adds its own monotonic count since, with the round trip as the
error.

A guest checks the key service's evidence before it has that time, so that
check uses floors in place of a clock. The guest's measured image carries the
vendor's TCB evaluation data number current at its build, from the update
channel the key service fetches, and the build's date. A launch document may
raise either, in `keyService.floor`, but never lower it, and both are
measured, so a verifier sees the floors a guest used. The key service puts the
vendor's documents for its own platform in its attested certificate, and the
guest checks that they chain to the vendor's root, that the TCB information
and the quoting enclave's identity carry at least the floor's number, and that
no next-update date among them or the revocation lists falls before the
floor's date. Not-before dates go unjudged, since only a clock could judge
them. The key service's TCB status must then pass as any verifier's does,
UpToDate or accepted by name in the launch document's
`keyService.acceptTCBStatus`, and the guest sends nothing until all of it
passes. Once an answer carries the key service's time, the guest judges the
same documents by it, and each lease renewal brings the key service's newest
documents for its own platform beside the guest's. A key service whose
documents lapse or fall below a floor loses the session: a pooled TD ends,
since it holds nothing, and a bound one treats it as a lapsed lease.

## Scale

Each grant, commit, epoch and seal is one write to the log. Continuous mode
makes a write per session per epoch, so the leader puts all the writes that
reach it during a round into one log entry. A renewal costs a share of a
heartbeat round and no write. A record holds at most a bounded stack's layer
entries and a few journal keys, a few KiB, so ten million sessions fit in a
few tens of GiB per replica (inferred). One key service is one Raft group,
and it splits by tenant into several when one group's write rate is not
enough.

## Prior art

| System | What it does | What the key service takes |
|---|---|---|
| CCF | Raft among attested nodes that never restart; an encrypted ledger on the hosts, with signed Merkle roots and receipts; recovery from k-of-n shares, replaying a ledger its operators choose | the restart rule, the ledger, receipts and shares |
| Signal's SVR2 | Raft in enclaves with state only in memory; a restarted enclave joins under a new identity | memory-only replicas |
| AWS KMS with Nitro Enclaves | returns a key encrypted to the public key in the enclave's attestation document | release sealed to the evidence's key |
| OpenBao | Raft, Shamir unsealing and a transit API, on a host it trusts | Shamir's code and the shape of the transit API |
| Contrast, dstack | keys derived from one seed or root, recovered from an attested peer or sealed to the host | nothing: records, not a seed |
| Nimble | keeps untrusted storage fresh with a quorum of endorsers in TEEs | the aim; witnesses run by others, rather than endorsers its operator runs, keep the ledger from going back even against that operator |

## Build order

1. One replica, with the release rule and records in memory, for milestone
   1 in [sessions.md](sessions.md#milestones).
2. Three replicas on one host, with generations, leases and journals, and
   the TLA+ model of leases, generations and leader changes, for milestone 2:
   a seal is worth only as much as its generation's record.
3. The ledger, witnesses, recovery and escrow.
4. Replicas across hosts.

## Open questions

1. **Witnesses**: who runs them, outside the operator's reach.
2. **Escrow holders**: who they are, and how many it takes.
3. **Renewal and epoch load**: how many live sessions one group carries
   before it splits, with renewals in commit mode and a write each epoch in
   continuous mode.
