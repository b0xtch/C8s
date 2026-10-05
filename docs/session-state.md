# Session state: holds, seals, leases and keys

Status: design. Milestone 2 builds holds, commits, continuous mode, seals and
restores, with leases and generations at the key service, and milestone 3
builds templates and forks ([Milestones](sessions.md#milestones)).
[sessions.md](sessions.md) is the overview, and
[session-api.md](session-api.md) has the calls.

A session outlives the TD it runs in. It is held while its user is away for a
moment, sealed when they are away for longer, restored into a new TD when
they return, and forked from templates. In continuous mode it also outlives
the loss of its host, with its processes. The host may not snapshot a TD, so
everything here happens inside the guest, and the key service, not the host,
decides which copy of a session is the live one.

## Ways to pause

| Level | Keeps | The TD | Comes back as |
|---|---|---|---|
| hold | memory, processes, connections | stays, its vCPUs stopped | the same TD, once its lease is renewed |
| commit | the session's files at one instant, while it runs | runs on | after a crash, a new TD with the files of the last commit, its processes started fresh |
| continuous | the sandbox's processes and files, every epoch | runs on, holding each output until its epoch is committed | after a crash, a new TD with the processes of the last epoch |
| seal `FILES` | the session's files | ends | a new TD, its processes started fresh |
| seal `PROCESSES` | the sandbox's processes and files | ends | a new TD, with the processes running |

Commits and seals also record the agent's own state: the session key and the
envelope counters. A hold costs a host the TD's memory and one of its TD key
IDs, and nothing else. A seal frees everything but disk, and its restore pays
for reading the seal back. A commit costs a write of what changed since the
last one, and bounds what a crash loses. Continuous mode makes every output
wait for the end of its epoch, and in return a crash loses nothing that
anyone outside the TD has seen ([Continuous mode](#continuous-mode)).

The bind says what a session may keep and how it commits
([the bind](session-api.md#the-bind)). `policy.seal` is the most it may keep
once its TD ends: none, files or processes. `policy.commit` is none, `files`
on a timer, or `continuous` with an epoch, which needs `processes`. A session
whose bind keeps none commits nothing and keeps nothing once its TD ends,
and its evidence says so to anyone who checks it.

## Layers

A session's state outside its TD is a stack of layers, with a journal above
them in continuous mode, each written once and never changed:

```text
  journal         continuous mode: a record per epoch since the layers
  ------------------------------------------------------------
  process layer   the processes at a PROCESSES seal or a fold, or none
  ------------------------------------------------------------
  file layer      what changed since the layer below    (newest)
  file layer      ...
  file layer      the files at the first commit or seal
  template layer  a template's files, for a forked session
  ------------------------------------------------------------
  image layers    public, on the ro slot, checked by digest
```

- **A layer is an encrypted, verified file system image**, in the layout of
  c8s's immutable volumes ([volumes.md](volumes.md#the-artifact)): plain
  dm-crypt with `aes-xts-plain64` and a 512-bit key, no header, and a
  dm-verity hash tree appended inside the encryption, in format 1 with SHA-256
  and no superblock, so the tree tells the host nothing, the root hash commits
  to the plaintext, and every parameter comes from the key service's entry
  rather than from the disk. Two things differ. Sectors are 4 KiB, with
  `iv_large_sectors`: volumes keep 512 so that a writer and an opener cannot
  disagree on how sectors are numbered, and one agent both writes and opens
  every layer. And the file system depends on what the layer holds.
- **File layers are EROFS**, made from the sandbox's upper directories the way
  containerd's EROFS snapshotter commits an active snapshot into an EROFS
  blob, with overlayfs whiteouts kept as they are. A restore stacks them under
  overlayfs, beneath a new upper directory on the TD's own root.
- **The process layer is ext4 with journaling off**, written in place: the
  checkpointer writes straight into it, so a memory image of many GiB is
  written once, and the hash tree is added when it is closed. ext4 under
  dm-verity is how Android has long shipped its system partitions.
- **Each layer has its own random key**, made by the guest that writes it,
  and its own salt and root hash. The key service keeps each layer's entry
  (its id, key, salt, root hash and sizes), so the host never holds a key and
  cannot substitute a block: dm-verity refuses any block that is not the one
  the root hash commits to.
- **Ids, not contents.** A layer is named by a random id the guest makes, so
  the host can store, copy and count references to layers without learning
  anything from their names.
- **Bounded stacks.** A commit or a seal writes only what changed since the
  last one, as a new file layer. Once a session's own layers would pass
  eight, or hold more than twice its live data, the guest writes one layer
  with everything above the template's instead, and the older ones can go.
- **Continuous mode adds a journal.** Above its layers, a session in
  continuous mode appends a record per epoch: the pages, process state and
  files that changed in the epoch, sealed under a key that the TD made for
  its own records, and chained to the record before it by hash. The key
  service holds the hash of the last committed record, so the host cannot
  drop, reorder or cut short the records unnoticed. The agent folds the
  journal into new layers in the background, and a restore replays only the
  records after the newest layer.

## The seal slots

A disk reaches a guest only on a slot it has had since boot ([Disks](#disks)),
so seals travel through two slots of fixed capacity:

- **`out`**, read and write, where a guest writes the layers of a commit or a
  seal. Its capacity is the most a seal can need: the class's memory and its
  root, plus their hash trees. Its backing is a sparse file, so capacity
  costs nothing until it is written. A journal's records pass through it
  one epoch at a time, and the daemon frees each record's space once it has
  stored it.
- **`in`**, read only, where the daemon places the layers a restore or a fork
  needs, at offsets it tells the guest. Its capacity covers the largest stack
  that the bound on stacks allows. The guest believes nothing the daemon says
  about the layers: it opens each at the offset given, with the key and root
  hash the key service released, and a wrong offset only fails dm-verity.
- **Placing copies nothing where it can.** The daemon moves layers between its
  store and a slot's backing file with `copy_file_range`, which XFS and btrfs
  complete as a reflink when both files are on one file system, sharing blocks
  rather than copying them, so placing a seal of any size takes about as long
  as placing a small one. On other file systems it can back `in` with a
  device-mapper table that maps each layer's range onto its stored file
  through a loop device, which copies nothing either. Otherwise it copies,
  with direct I/O, since a seal's size in the page cache would be charged to
  the daemon's memory.

## Seal

1. The orchestrator calls `Seal(session, level)`. The daemon releases a held
   TD first.
2. The daemon makes room on the TD's `out` slot and asks the guest to seal.
3. **Drain.** The guest's gateways finish the effects in flight, start no new
   ones, and close every connection the sandbox holds to them, so that the
   checkpoint holds no socket that leaves the sandbox. A connection that
   outlives the drain's limit, 10 s by default, is reset, as a network fault
   would reset it. For `PROCESSES`, a checkpointer that tracks written pages,
   as CRIU's iterative pre-dump does, meanwhile copies the sandbox's memory
   while it still runs, so the freeze that follows covers only the pages
   written after, whatever the session's size. Then the sandbox freezes, and
   the guest snapshots its files ([Commit](#commit)).
4. **Write.** For `PROCESSES`, the guest checkpoints the frozen sandbox into a
   new process layer on `out`, from the pages it has copied and those written
   since: with gVisor's checkpoint for a gVisor sandbox, or with CRIU for a
   container sandbox. Then it writes the files changed since the last layer
   as a new file layer, with the agent's state beside them. It closes each
   layer under dm-verity and keeps its key, salt and root. Under dual control
   each layer's key is made from two shares
   ([Dual control](session-key-service.md#dual-control)). It answers the host
   with each layer's id and size and keeps the sandbox frozen. Its lease
   renewals go on, since the agent itself is not frozen.
5. **Store.** The daemon copies the layers from `out` to durable storage,
   since availability is its job, and then asks the guest to commit them.
6. **Commit.** As the lease holder, the guest asks the key service to move the
   session from generation g to g+1, naming the new stack, by
   compare-and-swap, which also releases the lease, since the session's
   effects have stopped. The guest answers the host with the new generation
   and ends.
7. The daemon records seal g+1, and may delete the layers that no generation
   it keeps still names.

In continuous mode a seal drains as above and then writes only the last
epoch's record, so it takes about an epoch, whatever the session's size.

The order makes a seal safe to lose at any step. Until the commit, g is the
latest generation and its layers are untouched, so a crash, a full disk or a
daemon that never asks to commit costs only this seal: the guest waits for
the commit up to a limit, 5 minutes by default, then thaws the sandbox and
runs on. If the compare-and-swap fails because the TD lost its lease or the
generation moved, another copy exists, so the TD ends. If no answer comes,
the commit may have happened and released the lease, so the guest thaws the
sandbox but keeps its gateways shut until a renewal answers: a renewal names
the current generation, so the TD either runs on at g or, finding g+1, ends.
The orchestrator retries the seal or holds. If the checkpoint fails, the seal
fails with the checkpointer's reason, the sandbox thaws, and the orchestrator
may seal `FILES` instead.

Milestone 1's image has no checkpointer. Milestone 2's adds CRIU with its
library, for container sandboxes, and erofs-utils, to write file layers. The
agent loads device-mapper tables itself, so the guest needs neither cryptsetup
nor veritysetup, and the hash trees it writes are those that `veritysetup
format --no-superblock` writes for the same parameters. The kernel adds what
CRIU needs: checkpoint and restore, soft-dirty page tracking, the socket
diagnostics and userfaultfd. Only the agent may use userfaultfd and the calls
that read or compare other processes: the sandbox's seccomp profile refuses
them, and what else these options add reaches only the sandbox's own processes
and namespaces.

## Commit

A commit records the session's files at one instant, and the sandbox never
stops for it. The agent takes a read-only snapshot of the btrfs subvolume that
holds the sandbox's upper directories, which btrfs makes atomically
([Disks](#disks)), and writes what changed since the previous commit's
snapshot as a new file layer on `out`, with the agent's state beside it. It
finds what changed by comparing the two snapshots, at a cost that follows the
change rather than the session's size: btrfs's forward search skips, without
reading it, every subtree that no transaction since the previous snapshot has
touched (`btrfs_search_forward`, `fs/btrfs/ctree.c`). The daemon stores the
layer, and the guest moves the generation by compare-and-swap and keeps its
lease. Commits run when the orchestrator asks and on a timer the bind may set,
so a TD that dies loses at most the work since its last commit.

A commit never carries processes. The TD runs on from the state it would
record, so its processes go on to draw from their generators what a restore
of that state would draw again: the image would be spent as soon as it was
written. Continuous mode is how processes survive a crash.

## Continuous mode

A session in continuous mode keeps its processes across the loss of its
host. Every epoch, a second or less as the bind sets:

1. As a seal does, the agent copies what the sandbox writes while it runs,
   then freezes it for an instant, checkpoints the pages and process state
   that changed since, snapshots its files, and thaws it.
2. It appends what changed, with the agent's state and the outputs the
   gateways hold, to its journal on `out` as one sealed record
   ([Layers](#layers)). The daemon stores the record, and the guest, as lease
   holder, commits it at the key service: a compare-and-swap from generation
   g to g+1 that names the record's hash.
3. Only then do the gateways release what the sandbox sent during the epoch:
   egress, outgoing envelopes, model calls and the answers of the guest's
   API. What comes in passes at once.

Remus holds a VM's network output until a backup has the checkpoint that
produced it ([Prior art](#prior-art)); continuous mode applies that rule
inside the TD, with the key service in the backup's place. Three things
follow:

- **Nothing that left is repeated.** A restore resumes from the last
  committed epoch, and whatever the dead TD drew from its generators after
  that epoch never left it. So the at-most-once rule of [Restore](#restore)
  does not apply, and an epoch can be restored again if the TD restoring it
  dies too.
- **No clock in the fence.** An epoch's outputs leave only once the key
  service has committed it, and it commits only the lease holder's next
  epoch, so every output that leaves belongs to one line of epochs, whichever
  TD sends it. The key service may therefore grant the lease to a restore at
  once, without waiting for the old lease to run out: the old copy fails its
  next commit and ends, and what it held never leaves. The loss of a host
  costs a session an epoch and a restore.
- **Seals and moves take an epoch.** A seal drains, writes the last epoch and
  ends, and a session moves to another host as a seal and a lazy restore.

After a crash, the restored sandbox's connections that leave it are reset,
as a network fault would reset them, since the dead TD's connections cannot
follow it to another host, and the outgoing envelopes its last epoch held
are sent again under the same numbers. Each TD seals its records under a key
of its own, which its first commit gives the key service, as two shares
under dual control ([Dual control](session-key-service.md#dual-control)).

The cost is a wait on every output, up to an epoch and a commit, and each
epoch an instant's freeze and a write. Records are padded to size classes the
bind sets, since a record's size is what the host learns from it. The
checkpointer must save only what changed since its last save, as CRIU's memory
tracking does. gVisor's checkpoint saves a sandbox's whole memory every time,
so continuous mode runs on container sandboxes, with CRIU, until gVisor's can
do the same. The bind sets the epoch, and milestone 2 measures the epoch each
sandbox sustains before continuous mode becomes anyone's default.

## Restore

1. The orchestrator calls `Restore(session, pool)`, typically when an
   envelope arrives for a sealed session or a TD has died.
2. The daemon claims a TD and places the latest generation's layers on its
   `in` slot, and in continuous mode the journal's records after them. Then it
   asks the binder for a bind with purpose `restore`, naming the session and
   that generation, under the same policy.
3. The daemon calls `Bind`. The guest asks the key service for the session.
   The key service checks the TD's evidence and its bind, refuses any
   generation but the latest, grants the lease to this TD's instance key
   (taking it from its holder at once in continuous mode), and releases the
   stack: each layer's id, key, salt and root, whether the process layer is
   fresh, and in continuous mode the journal's keys and last hash. Under dual
   control it releases its share of each layer's key, and the owner's key
   manager, checking the same evidence and bind, releases the other.
4. The guest opens every layer the key service listed, and no other, at the
   offsets the daemon gave, through dm-crypt and dm-verity, and stacks the
   file layers under overlayfs with a new upper directory on its root. In
   continuous mode it also reads the journal's records after the newest
   layer, checking each record's seal and the chain of hashes up to the one
   the key service holds, and applies their files to the new upper
   directory. If the process layer is fresh, or the journal holds processes,
   it restores the sandbox from them on demand, with gVisor's background
   restore or CRIU's lazy pages, so the session runs before all of it is
   read. Otherwise it starts the sandbox fresh on the restored files. It
   makes the next session key and drains its inbox.

**In commit mode, a process image is restored at most once.** The key service
marks a generation's process layer spent when it grants the lease to a TD that
will release outputs as they happen. A TD that seals leaves a fresh process
layer at g+1. A TD that dies leaves g's spent, so the next restore brings back
g's files and the agent's keys but starts the sandbox's processes fresh, as a
reboot would. Restored a second time, those processes would draw again the
random values the dead TD may already have used in its effects, which is the
replay that clones of one snapshot suffer ([Prior art](#prior-art)). The work
done since the last commit or seal is lost either way. A TD in continuous mode
spends nothing, since its own outputs wait for its own commits.

## Templates and forks

1. **A template is a sealed session.** The binder starts a session whose bind
   has the purpose `template`, and it does its setup: clones repositories,
   installs dependencies, perhaps warms a language server. Credentials stay in
   the guest's gateways, outside the sandbox, which sees them only as
   placeholders ([Credentials and
   egress](session-api.md#credentials-and-egress)), so a template taken after
   a clone carries the checkout but not the token.
2. `Seal(session, TEMPLATE)` writes the sandbox's files as one full EROFS
   layer, compact and reproducible, and a process layer if processes are to
   be kept. The agent refuses it once any secret has entered the sandbox
   itself. The key service records the stack as an immutable template of its
   tenant, released to many TDs and leased by none.
3. `Fork(template, pool, sessions)` runs a restore per new session. Each TD
   takes the template's stack without a lease, takes a new lease on its own
   session at generation 0, draws its own entropy and makes its own session
   key. The new session's record copies the template's layer entries, so
   deleting the template stops new forks and leaves its forks whole, and the
   fork's own commits and seals add layers above them.
4. **One copy on the host.** Every fork of a template reads the same template
   layers, so the host keeps one copy of their ciphertext, places it by
   reflink or maps it, and serves it to all of them from its page cache. This
   is the only sharing across sessions, and it tells the host only what it
   already knew: that these sessions forked from one template.
5. **Random state.** A fork's kernel boots fresh, and gVisor's random devices
   read from it, so both give new entropy, but a process that seeded its own
   generator before the seal keeps that state. So a template keeps processes
   only if they hold no secret and either draw nothing random before the
   seal or reseed in a restore hook, as Lambda SnapStart asks of functions
   ([Prior art](#prior-art)). Otherwise the template is sealed with no
   processes running: it keeps its files and gives up the warm processes.
   This is the one process image restored more than once.

## Generations and leases

### What the key service keeps for a session

| Field | What it is |
|---|---|
| name | the session's authority and its id, so two tenants' sessions cannot collide |
| authority | the key whose binds may acquire the session or fork the template; set when the first TD creates the record |
| generation | a counter that only moves forward, by compare-and-swap |
| stack | the latest generation's layers, oldest first: each layer's id, key (under dual control, the key service's share of it), salt, root hash and sizes; and the process layer, if any, with whether it is fresh or spent |
| journal | in continuous mode, the hash of the last committed record, and the record key of each TD whose records follow the newest layers |
| lease | the digest of the instance key of the TD that holds the session, and the lease's grant number, which rises with every grant; the leader keeps renewals in memory ([session-key-service.md](session-key-service.md#leases-across-a-change-of-leader)) |
| session key | the public halves of the current and previous session keys |
| kind | session or template; a template is immutable, released to many and leased by none |
| template | for a forked session, the template it came from |
| tombstone | set at delete; the keys go once the retention period ends |
| review budget | what the session has spent of its review policy's budget, today and over its life ([session-disclosure.md](session-disclosure.md#private-review)) |

### What a guest asks of it

| Call | Made by | Does |
|---|---|---|
| acquire | a TD whose bind names the session | for `start`, creates the record at generation 0, with this TD's lease, and is refused for a session that has one; for `restore`, grants the lease if it is free, or at once in continuous mode, releases the stack if the bind names the latest generation, and spends its process layer unless the TD runs in continuous mode; for `fork`, releases a template's stack and creates the new session's record at generation 0, with this TD's lease |
| renew | the lease holder | extends the lease at the holder's grant number, even once it has lapsed if no grant has followed, answered inside the attested channel with the key service's time, so no answer can be replayed; it and `advance` are refused once the vendor's documents the key service holds refuse the holder's platform |
| advance | the lease holder | moves the generation from g to g+1 by compare-and-swap, with the new layers or journal record; releases the lease for a seal and keeps it for a commit or an epoch |
| release | the lease holder | frees the lease at a clean end without a seal |
| spend | the lease holder | takes from its review budget before a signal leaves |

The key service judges each call by the caller's evidence and by its bind,
which the session's authority must have signed. Milestone 2's key service is
three replicas on one host, the second step of its build order
([session-key-service.md](session-key-service.md#build-order)), so a replica
can restart without losing anything; a restart of the host still loses every
lease and key, which fails closed. The ledger and replicas across hosts come
next.

### Lease timing

- **Defaults.** A lease runs 60 s, and the guest renews it every 15 s. The
  guest lets an effect leave only within 45 s of when it sent its last
  successful renewal, and the key service grants the lease to another TD
  only once 60 s have passed since its own last answer to the holder. So the
  old TD stops before the new one starts.
- **Continuous mode does not rest on them.** Its outputs wait for commits,
  which renew the lease as they go, so the key service may hand its lease to
  a restore at once ([Continuous mode](#continuous-mode)).
- **Clocks.** Both sides count lease time on their monotonic clocks, which on
  TDX run from the TD's TSC, and never on wall time. A TD's TSC frequency is
  fixed when the TD is created, and the TDX module keeps its offset and
  multiplier from the host ("KVM can't change TSC offset/multiplier as TDX
  module manages them", `arch/x86/kvm/vmx/tdx.c`), so a host can stop a TD but
  not slow its clock; the module's own guarantee is still to be checked
  against its specification. A hold does not stop the TSC, so a held TD finds
  its lease stale when it is released. It may renew a lapsed lease at its
  grant number, which the key service allows only while it has granted the
  lease to no one since, and it never renews one it released.
- **No date rests on the guest's wall clock.** That clock comes from the host,
  and can be wrong by seconds even on an honest one: the kernel loses ticks
  while it accepts memory with interrupts off, before it moves to the TSC. The
  guest counts durations on its monotonic clock and takes the time of day from
  the key service, whose answers carry its time ([Its
  clock](session-key-service.md#its-clock)), adding its own count since and
  taking the round trip as the error. A bind's `notAfter` and an envelope's
  expiry are judged so. The one check it makes before it has that time, of the
  key service's own evidence, holds the vendor's documents to floors from its
  measured image instead.
- **Every effect passes a gateway.** Egress, outgoing envelopes, model calls
  and the guest's own API (commands, credentials released to the sandbox and
  forwarded streams) all pass through the measured agent: the egress proxy is
  the sandbox's only way out, and the inference gateway its only path to
  inference. The lease check therefore sits in one place. When the lease goes
  stale, the gateways stop passing bytes on every connection, not only new
  ones, and the agent answers its API with `lease_stale`. The sandbox can
  compute but cannot act, and a client the host steers to an old copy learns
  that it is old.

### When things fail

| What happens | What follows |
|---|---|
| the host dies | the lease runs out, and a restore elsewhere takes it after at most 60 s, or at once in continuous mode |
| a TD restored in commit mode dies before it commits or seals | the next restore brings back the files of the generation it restored and starts the processes fresh, since the image is spent |
| a TD dies after a commit | the next restore brings back the files of that commit and starts the processes fresh |
| a TD in continuous mode dies | the next restore resumes its processes from the last committed epoch |
| the host loses a seal's layers before the commit | g is still the latest generation; the guest thaws the sandbox and runs on |
| the host loses layers after the commit | the session cannot be restored: availability, which the host can always deny. The daemon keeps a generation's layers until a later generation no longer names them |
| the host places the wrong layer, an old one or another session's | dm-verity refuses its first block, and the guest ends |
| the key service is down | live sessions keep computing, and their effects stop until it returns: at once in continuous mode, whose outputs wait for commits, and 45 s after their last renewal otherwise; nothing is restored anywhere meanwhile, since only the key service releases keys. That is the price of one live copy, which a longer lease trades against slower recovery from a dead host |
| the host of milestone 2's key service restarts | every lease and key is gone: live sessions stop acting, and none can be restored |
| the host cuts a live TD off from the key service and restores the session elsewhere | the old TD stops its effects at 45 s, and the new one gets the lease after 60 s; at no moment do two copies act. In continuous mode the new one gets the lease at once, and the old one's outputs, which wait for commits it can no longer make, never leave |
| the host offers an older seal | the key service releases keys only for the latest generation |
| the host holds a TD past its lease and releases it | its gateways stop every effect until a renewal at its grant number succeeds, which it does only if the key service has granted the lease to no other TD meanwhile; a refused renewal ends it |
| the vendor revokes a platform, or its TCB falls below what a pool accepts | once the key service holds the vendor's documents that say so, it renews no lease and takes no generation from a TD on that platform, after asking the TD for a fresh quote in case the platform was updated under it: the sessions there stop their effects within 45 s, at once in continuous mode, and are restored elsewhere from their last generation. Renewals rest on the newest documents the key service holds, however old, so an outage of the vendor's service delays this but stops no live session |

## The session key

An HPKE key pair (RFC 9180), with a hybrid KEM of ML-KEM-768 and X25519, that
the session's first TD makes when its first envelope or secret arrives. Its
public half is published in the TD's evidence, signed with the instance key
that the quote binds, and in the key service's record. Its private half lives
in the agent's state and travels only inside seals, commits and journal
records. Each restore makes a new pair, and so does each day a session runs;
the previous pair is kept until the next change, so an envelope sealed to it
in the meantime still opens. A template has none, since it is sealed before
any secret.

## Disks

A disk reaches a guest only on a slot the guest has had since boot:

- **Slots are fixed per class.** Every TD of a class boots with the same
  virtio-blk devices, so the set of devices the host declares is part of the
  class's reference values, and nothing is hot-plugged later. Milestone 2's
  classes add the `in` and `out` slots, which changes their RTMR[0] values,
  and the release log lists the new ones per class.
- **Data is placed at offsets.** A slot's backing is a sparse file, or for
  `in` a device-mapper table over the stored layers. The daemon places layers
  in it ([The seal slots](#the-seal-slots)) and tells the guest where they
  sit, and the guest reads them with direct I/O and checks them through
  dm-crypt and dm-verity. The guest trusts nothing it reads from a slot more
  than a network connection's bytes.
- **So "attach" is a message** naming an offset on a disk the guest already
  has: no VMM change at run time and no device event in the guest.

| Slot | Guest's access | Holds |
|---|---|---|
| `root` | read and write | the TD's writable files, the sandbox's upper directories among them: btrfs with SHA-256 or BLAKE2b checksums, under a fresh dm-crypt layer for this TD's life and a key the guest makes |
| `ro` | read only | public images, checked against the digests or root hashes the bind names |
| `in` | read only | the layers of seals and templates, at offsets |
| `out` | read and write | layers and journal records on their way out |

Milestone 1 formats ext4 on `root` in the initrd and runs the sandbox on an
image's unpacked tree there, with no overlay. Milestone 2 formats btrfs
instead, with mkfs.btrfs in the measured image, and gives the sandbox an
overlayfs root: its images and restored file layers below, read only, and
above them an upper directory in a btrfs subvolume, which is what a commit
snapshots.

The `in` slot could later be served by the daemon as a network block device,
so that a layer still in object storage is read block by block as the
restore touches it.

The root is fresh as well as confidential. btrfs checks every tree block it
reads against its own checksum and against the generation its parent records
(`fs/btrfs/disk-io.c`), and every data block against the checksum tree, and
the tops of its trees stay in the TD's memory while it is mounted, which is
the TD's whole life: the guest formats the slot under a new key before any
bind and never mounts it twice. So a block the host changes decrypts to noise
and fails its checksum, and a block it puts back from earlier fails its
parent's generation or the checksum tree. Two rules keep it so: no file may
turn off its data checksums, so the sandbox may not set file attributes
(`FS_IOC_SETFLAGS`); and the agent keeps off the features whose reads walk
back references and may skip the generation check (`fs/btrfs/tree-checker.h`),
such as send, balance and quotas. ext4 or XFS on dm-crypt would keep the root
confidential but not fresh: the host could put back a block it saw earlier,
and a later commit would carry what the session read from it.

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
- **Across a crash.** A restore reads the inbox from the counter its last
  commit, epoch or seal recorded, so delivery is at least once: an envelope
  the dead TD had read comes again, under the number it had before, and a
  receiver that keys its work on that number does it once. What a session
  sends carries the lease's grant number beside its sequence number, so a
  restored TD never reuses a number the dead one sent.
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
  in hooks. CRIU's lazy pages restore a process tree before its memory
  arrives, faulting pages in through userfaultfd.
- **Output held until it is durable.** Remus replicates a running VM to a
  backup by checkpointing it many times a second, and holds the VM's network
  output until the backup has the checkpoint that produced it, so a failover
  repeats nothing the world saw (NSDI '08). Rethink the Sync makes a file
  system's writes look synchronous to anyone outside the computer by holding
  back only the output that depends on them until they are durable
  (OSDI '06).
- **Randomness after a reset.** Ristenpart and Yilek show that virtual
  machines reset to one snapshot reuse randomness in deployed cryptography
  ("When Good Randomness Goes Bad", NDSS 2010).
- **Freshness from counters held elsewhere.** ROTE keeps enclaves' state
  fresh with counters that a group of other enclaves holds (USENIX Security
  '17), and Nimble does the same for confidential cloud services (OSDI '23);
  the key service's generations do it for sessions.
- **Layers.** containerd's EROFS snapshotter keeps each committed snapshot as
  an EROFS blob and mounts an active one as overlayfs over them
  (`containerd:docs/snapshotters/erofs.md`); a session's files take the same
  shape, with each blob encrypted and verified.
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
   taken inside the TD, the key service releases its keys only to an attested
   TD with a signed bind, and each restore or fork runs with a new instance
   key, new entropy and a new session key: the enclave pattern, carried to
   whole agent sessions.
2. **One live copy that holds against the host.** Platforms that keep a single
   runner do it in their own control planes, which a confidential design
   cannot trust. Here the guest stops its own effects when its lease goes
   stale, and in continuous mode no output leaves before the key service has
   committed the state that produced it, so the fence needs no clock.
3. **The fence Brooker et al. ask for.** Every effect leaves through the
   guest's gateways, so nothing leaves a restored TD before its lease is
   fresh, and since a process image is restored at most once in commit mode,
   and nothing leaves before its epoch is committed in continuous mode, a
   crash never replays a generator's state into new effects.
4. **Secrets outside the template, and protected.** Credentials stay in the
   gateways, which run inside the TD, so a template carries none and the host
   reads none.
5. **Incremental seals the host cannot read or roll back.** Each commit or
   seal writes only what changed, as a layer under a key of its own, and a
   restore checks every block it reads against a root hash that only the key
   service holds, for the latest generation only. Contents are shared only
   across forks of one template, and the host sees which blocks a restore
   reads but not what they hold.
6. **Confidential sessions that outlive their hosts, processes and all.** A
   TD's memory never leaves it in the clear, yet in continuous mode the loss
   of its host costs a session an epoch and a restore elsewhere, and repeats
   nothing that left.

## Open questions

1. **What a seal and a restore cost** at a session's full size, and how much
   lazy restore hides.
2. **The access pattern of a lazy restore**, which the host sees, and whether
   it needs padding or a prefetch of the whole layer.
3. **The epoch continuous mode sustains** on each sandbox, the delay it adds
   to every output, and the CPU and writes it costs, and whether CRIU run as a
   service or the agent's own scan of written pages, with CRIU for the full
   image only, takes an epoch faster.
4. **How often to commit**, against what a commit costs a running session.
5. **What a journal record's size says** about a session, since the host sees
   one each epoch, and which size classes hide it, taken from the epochs of an
   idle agent, a compile and a package install.
6. **What btrfs's checksums and copy-on-write cost** the work inside, against
   ext4 on the same dm-crypt.
