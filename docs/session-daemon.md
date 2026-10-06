# The session daemon

Status: built for one host. It serves seven calls of the
[session API](session-api.md): `Claim`, `Bind`, `Connect`, `GetEvidence`,
`WatchReady`, `Watch` and `Destroy`. [What is missing](#what-is-missing) lists
the rest of the design.

`c8s session-daemon` keeps pools of ready TDs on a host and hands them to
sessions. It runs on the host, outside the trust boundary
([sessions.md](sessions.md)). It starts and ends TDs, relays documents and
evidence it does not judge, and carries bytes it cannot read. A daemon that
cheats can deny service and nothing more, because every caller acts on
evidence it verified itself.

```text
 orchestrator, binder,                              host
 owner's client
      |                        +------------------------------------------+
      |  gRPC over TLS         |  c8s session-daemon                      |
      +----------------------->|    pools, claims, binds, Connect streams |
                               |        |                     |           |
                               |   launcher, one per TD    tap c8st<n>    |
                               |        |                  a /30 per TD   |
                               |   +----v---------------------v------+    |
                               |   | VMM: one TD                     |    |
                               |   |   guest agent, RA-TLS on 8443   |    |
                               |   +---------------------------------+    |
                               |   ... up to the host's capacity          |
                               +------------------------------------------+
```

## A session's start

```text
 binder                      daemon                      guest (TD)
   |                           |                            |
   | WatchReady(pool) -------> |                            |
   | <== each ready TD's evidence, as it becomes ready      |
   | judge each: pinned image, pool's launch key, nobody's  |
   |                           |                            |
   | Claim(pool, session) ---> | its own record             |
   | <-- td, evidence, bind_by |                            |
   |                           |                            |
   | find the verdict by the TD's certificate, or judge now |
   | sign a bind for the TD's instance key                  |
   | seal the first command and credentials to its one-time key
   |                           |                            |
   | Bind(td, bind, sealed) -> | bind, sealed ------------> | raises its fence,
   |                           |                            | measures the bind,
   |                           |                            | opens the message,
   |                           |                            | signs its receipt,
   |                           |                            | starts the sandbox
   | <-- receipt ------------- | <-- receipt -------------- |
   | <-- sealed answer ------- | <-- sealed answer -------- | ran the command
   | <-- evidence, quote ----- | <-- state, quote --------- | took the quote
   | hold the quote to the receipt                          | over the bind's
   |                           |                            | nonce
   |                           |                            |
   | Connect(td) ============= bytes =====================> | the TLS session
   |                           |                            | ends in the guest
```

No boot is on this path: a TD boots into its pool before any session asks
for it. A claim asks the guest nothing. The daemon answers it from its own
record, with what the guest said of itself when it became ready, and the
guest learns of its session from the bind, which is when it ends every
connection made to it before. [session-performance.md](session-performance.md)
is where measured times go.

A binder may send one sealed message with its bind: the session's first
command, credentials it holds that the bind says come from its binder, or
both. It is sealed to a key the guest made for its one bind and erases before
anything of the session runs, so the daemon carries it unread. The guest has
the credentials in place before its sandbox starts and runs the command as
soon as the sandbox does. Its answer comes back under the same seal, after
the receipt. A binder goes by that answer and never by what the daemon says
became of the message: with no answer that opens, it releases the
credentials over `Connect` and then sends the command again under the id it
was sealed with, and the guest takes each credential once and runs the
command once.

The quote over the bind's nonce comes on the bind's own call. A guest
answers with its receipt as soon as its sandbox runs and takes the quote
beside it. Once it has the quote, or has given up on one, it sends its state
on the same answer, the document it serves to anyone, and the daemon hands
that on as the guest's evidence in a later message of the call. The sealed
answer and the quote come in the order the guest has them. A binder waits for
the quote there and asks the daemon for no evidence, so a start never waits
on the evidence requests of others. One whose call ends without a quote, or
whose guest says it gave up, asks the guest for an attestation through
`Connect`. The daemon says in its request that it reads the answer to its end
(`C8s-Bind-Quote: follows`), and a guest sends its state there only to a
caller that does: the documents of an answer do not name their kind, and a
caller that hands a guest its bind over a connection of its own reads the
receipt and finds the quote in the state the guest serves.

A binder that the pool names may watch it ([Who may call
what](#who-may-call-what)): the daemon shows it each ready TD's evidence as
the TD becomes ready, and again when its guest comes to serve another
certificate, and tells it when a TD is ready no more, by the SHA-256 of the
certificate that TD was last shown under. The binder judges each then, and at
a claim finds its guest by the certificate in the claim's answer, never by
the TD's name. A TD it was not shown, or whose verdict no longer stands, it
judges at the claim.

What a binder seals with a bind, or sends over `Connect`, goes on a verdict
that rests on the vendor's documents as the binder fetched them from the
vendor itself within the last hour. The documents a host relays with a TD's
evidence serve only a check that sends nothing secret, such as the one before
a bind is signed ([Old vendor
documents](session-threat-model.md#launch-and-measurement)). So a binder
asks the vendor again for each document three quarters of an hour after it
fetched it, keeps the evidence it judged, and judges it again when a newer
document arrives or a verdict nears its end: `session.ReadyVerdicts` does
both, off the path of any start. A binder that cannot reach the vendor for
an hour seals and sends nothing until it can.

`c8s session start` is the client for one session: it claims, judges, signs
with the owner's authority key, binds and verifies again, and writes a
binding directory. A command after `--` goes with the bind as the session's
first, and `--sealed-credential NAME=FILE` seals a credential with it.
`verify`, `credential put`, `exec` and `destroy` then take `--binding` and
reach the guest through the daemon.

### A bind that claims

A binder that watches a pool has judged its ready TDs, so it needs no claim
to learn which guest its bind is for:

```text
 binder                      daemon                      guest (TD)
   |                           |                            |
   | WatchReady(pool) -------> |                            |
   | <== each ready TD's evidence, and each that left ready |
   | judge each as it comes, forget each that left          |
   |                           |                            |
   | take the TD shown first, sign a bind for its instance key,
   | seal the first command and credentials to its one-time key
   |                           |                            |
   | Bind(bind, sealed) -----> | the ready TD of that key:  |
   |                           | claimed for the bind's session
   |                           | bind, sealed ------------> |
   | <-- receipt, td, host --- | <-- receipt -------------- |
   |                           |                            |
   |   or, when a claim or another bind took that TD first: |
   | <-- not ready ----------- | nothing reached a guest    |
   | sign for the next TD it has judged                     |
```

A `Bind` that names no TD claims the ready TD whose instance key the bind
names, for the bind's session, and hands it the bind in the same call. There
is no grace, since the bind is there, and the answer names the TD, which is
the name the session's connections are made by. The daemon reads the bind to
learn the key and the authority it is signed under, as the guest will read
it, and lets only an orchestrator send one, or a binder the pool names, under
an authority the pool names for that binder
([Configuration](#configuration)). Anybody else is refused whatever TDs the
host has, so a bind is no probe for them.

A TD that a claim or another bind took first, or that is gone, is answered
with `FAILED_PRECONDITION` and an `ErrorInfo` of reason `TD_NOT_READY`
(`daemon.NotReady` in the client library), before anything reaches a guest.
The binder then signs for the next TD it has judged: `session.ReadyVerdicts`
hands them out in the order they were shown (`Take`) and passes over those
the stream says left (`Forget`), which it keeps a few seconds longer for a
claim of the binder's own that took one. What that retry costs is a
signature, a seal and a round trip to the daemon. Two binders that watch one
pool and start a session at the same moment sign for the same TD, and one of
them pays it.

An orchestrator learns of a session that started so from `Watch`, which shows
it every TD of the host as it is and then each as it changes: its pool, its
state, the session it serves and, for a TD that a binder's bind claimed, that
binder's key. It ends such a session as it ends any other, with `Destroy` by
the session's name. `c8s session watch` prints that stream, one JSON object a
line.

## Who may call what

| Call | Caller | Needs |
|---|---|---|
| `Claim`, `Bind` of a claimed TD, `Destroy`, `Watch` | an orchestrator | a client certificate that chains to the authority in `tls.clientCA` |
| `Bind` that names no TD | an orchestrator, or a binder the pool names | as above, or a client certificate whose public key the pool's `binders` lists with the authority the bind is signed under |
| `WatchReady` | a binder the pool names | a client certificate whose public key the pool's `binders` lists, whoever issued it: a stream shows how fast the pool refills, which is every tenant's starts together |
| `GetEvidence` | anyone | nothing: what a guest serves to anyone is public. The daemon has a guest answer one request at a time, and everyone who asks meanwhile shares the next, so an answer is of a request sent after its caller asked and no caller keeps another waiting. It has 64 requests of one caller in flight at once and tells that caller to ask again beyond them; a caller is the key of the certificate it presents, or without one its address |
| `Connect` | anyone | nothing at the daemon: the guest authenticates every request under the keys its bind names |

The handshake asks a caller for a certificate and proves that it holds the
key of the one it presents, and nothing more. Each call then decides whose
certificate it takes. An orchestrator's must chain to the authority, which
the daemon checks once per certificate and remembers until the chain's first
certificate ends. A binder's need not: the pool names its key, so a binder
may present a certificate of its own making. That key opens the pool's
stream and, with an authority the pool names for it, a bind that claims one
of the pool's ready TDs. It opens no other orchestrator call: a binder ends
no session and claims none without a bind.

A TD carries connections only once it is bound. Before that, the only bytes
that reach its guest are the daemon's own requests, the bind of its claim,
and a bind that claims it from a caller the pool lets, so a caller that
learns a ready TD's name or its key cannot bind it for itself. TD names are
128 random bits.

Every change takes the caller's `request_id`. A repeat under the same id gets
the first answer and changes nothing, across a restart of the daemon too.

## Configuration

```yaml
listen: 0.0.0.0:7443
host: host-a                    # the name answers carry; default: the host's own
stateDir: /var/lib/c8s/sessions
capacity: 6                     # the most TDs on this host, in every state
tls:
  cert: /etc/c8s/sessions/server.pem
  key: /etc/c8s/sessions/server.key
  clientCA: /etc/c8s/sessions/orchestrators.pem
network:
  mode: tap
  guestCIDR: 10.213.0.0/22      # the daemon's alone: four addresses per TD
  egressInterface: eth0         # optional: without it a guest reaches nothing
  reach: ["192.0.2.7:8443"]     # optional: open to every guest
  dns: [192.0.2.53]
vmm:
  quoteSocket: /var/run/tdx-qgs/qgs.socket
  confine: "64055"              # run the VMM as this user, with no capability
  cpus: "2-19,26-43"            # optional: the CPUs every guest's VMM keeps to; the daemon and its launchers stay on the daemon's
classes:
  s-4x16: {vcpus: 4, memory: 16G, scratch: 8G}
pools:
  - imageDir: /var/lib/c8s/images/c8s-session
    launchDir: /etc/c8s/sessions/agents/opkeydata
    depth: 4
    bindGrace: 30s
    imageStore: /var/lib/c8s/images/images.store
    binders:                    # optional: who may watch the pool's ready TDs
      - "sha256:9f2c..."        # this key watches
      - key: "sha256:41d0..."   # this one also claims a TD with a bind
        authorities: ["sha256:c7a9..."] # that one of these signed
```

| Key | Meaning |
|---|---|
| `capacity` | An upper bound on TDs in every state. A TD's memory is not the host's again until its VMM is gone, and the slot stays taken until then. |
| `classes` | The launch shapes this host offers. A class fixes vCPUs and memory, and with them RTMR[0], so a class is a set of reference values (rule R7 in [session-api.md](session-api.md#rules-the-api-keeps)). |
| `pools[].launchDir` | The `opkeydata` directory of a launch bundle from `c8s session launch-config new`. The pool takes its name and its class from the launch document there. |
| `pools[].depth` | How many TDs the pool keeps ready. Two boot at a time. |
| `pools[].bindGrace` | How long a claim waits for its bind. After it the TD returns to the pool: the daemon sent it nothing, so nothing of a tenant entered it. |
| `pools[].imageStore` | A store of public images (`c8s session image-store write`) handed read-only to every guest, so that a bind which names one starts it without a pull. |
| `pools[].binders` | The callers that may watch the pool's ready TDs with `WatchReady`, each by the SHA-256 of the public key in its certificate, as `sha256:` and 64 hex digits (`openssl x509 -in cert.pem -noout -pubkey \| openssl pkey -pubin -outform DER \| sha256sum`). The certificate may be self-signed. With none, nobody watches the pool. An entry is that digest alone, or a `key` with `authorities`: the tenants' authority keys, named the same way (`openssl pkey -in authority.key -pubout -outform DER \| sha256sum`), whose binds that binder may claim a TD of the pool with. A binder with no authority watches and claims nothing, and an orchestrator needs no entry to claim with a bind. |
| `vmm.console` | Attach each guest's console to its launcher's log. For dev images only: a locked image prints nothing there. |
| `network.tapPrefix` | What the name of each TD's tap begins with, a lower-case letter and up to nine more letters or digits. Default `c8st`. A second daemon on a host takes another: see [Network](#network). |

Relative paths are taken from the configuration file's directory. An unknown
key is an error.

## Network

In `tap` mode each TD has a tap of its own, `c8st<n>`, and four addresses of
`guestCIDR`: the host's end and the guest's. No bridge joins two guests. The
daemon loads one table, `inet c8s_sessions`, into the host's packet filter.
Its rules match the tap names, so they hold for a tap made after they were
loaded:

| Traffic | Verdict |
|---|---|
| a guest to its host, on any address and port | dropped |
| a guest to another guest | dropped |
| a guest sending from an address its tap was not given | dropped |
| anything from outside the host to a guest | dropped |
| the daemon to a guest, and the answers | passes |
| a guest to an address and port in `reach`, on the host or beyond it | passes |
| a guest out through `egressInterface`, under the host's address | passes when one is configured; dropped otherwise |

Every drop is counted (`nft list table inet c8s_sessions`). The table stays
when the daemon exits, because its TDs run on. `egressInterface` needs
`net.ipv4.ip_forward=1`, which the daemon checks and does not set.

The table only closes. Each of the host's own tables judges the same packets,
and a drop in any of them is final, so `reach` and `egressInterface` open
nothing that the host's own packet filter drops. A host that drops what
arrives on an interface it does not know, as a default-deny filter does,
drops what a guest starts until its operator lets `c8st*` through. The
daemon changes no rule outside its own table.

What a sandbox may reach is decided a second time inside the guest, by the
egress policy of its bind, which the host cannot change. The host's rules are
the outer wall: they keep a tenant's guest away from the host's own services
and from other tenants whatever the guest does.

Two daemons can share a host. The second names a `tapPrefix` of its own, and
with it a table of its own, `inet c8s_sessions_<prefix>`, so that each daemon
loads and replaces its own rules alone. Neither prefix may begin the other:
a daemon's rules match every tap whose name starts with its prefix. Each
daemon also needs a `guestCIDR`, a `stateDir` and a port of its own.

`user` mode gives a guest the VMM's user-mode stack, with its TLS port
forwarded to a loopback port. It needs no privilege and filters nothing. It
is for development.

## The pool's machine

A TD has a register, RTMR[0], for what its host declared to the firmware: the
shape of the machine, which is a class's vCPUs, its memory and its split, and
how many devices it has. A pool's launch document lists the values its guests
may hold, and a TD ends at boot if its own is not among them. A TD whose
document lists none boots and says what it is to anyone, and takes no bind:
its host could have built it any machine. An owner's tool sends such a guest
nothing, and a key service opens it no session. The one command that takes
its evidence is the one that reads its machine.

So a pool's document is written twice. The first lists no machine. One guest
is launched from it in the pool's class, and its machine is read from its
evidence:

```sh
c8s session launch-config new --out probe --key pool.key \
    --image-manifest c8s-session/manifest.json --pool agents --class s-4x16
c8s session-launcher run --platform tdx --image-dir c8s-session --launch-dir probe/opkeydata \
    --work-dir /run/c8s/probe --vcpus 4 --memory 16G --low-memory 512M --scratch 4G \
    --vsock-cid auto --network user --port 127.0.0.1:8443:8443 &
c8s session launch-config machine --url https://127.0.0.1:8443 \
    --image-manifest c8s-session/manifest.json --launch-key pool.key.pub
```

The second document lists the value that printed (`--machine`), and the pool
is configured with it. The value is of one shape on one build of the VMM and
the firmware: a class with an image store has one more disk than a class
without, and another value. A document lists up to eight.

What RTMR[0] does not record is what stands in each slot. The agent checks
that itself before it reads anything its host handed it: the guest's PCI bus
must hold its board's two bridges and virtio devices for its network, its
disks and its socket to the host, and nothing else. The guest's kernel has
drivers for those alone.

## With a key service

A pool whose launch document pins a [key service](session-key-service.md)
gives its sessions stored credentials: a tenant stores a secret once, and a
session of that tenant finds it in its sandbox at its first read, with its
owner nowhere near. The key service is a guest of its own, built from the
same profile (`C8S_ROLE=key-service session-guest-image/build`) and booted by
the same launcher from a bundle of the same layout. What is built is one
replica that keeps everything in memory.

The pool's launch key comes first, because each document names the other
side: the key service's lists the pool's public key, and the pool's pins the
key service.

The key service's launch document lists its machines under the pool's rule,
so its bundle is written twice as well. A key service on a machine its
document does not list ends before it serves. One whose document lists none
serves its state and releases nothing, and its machine is read from its
evidence. Guests and owners hold a key service to the list in the document
it measured, so its pin stays the same when the list changes.

```sh
# The operator: a key for the pool, the key service's bundle and pin, the pool's bundle.
c8s session launch-config key --out pool.key
c8s session key-service launch-config new --out ks-probe \
    --image-manifest c8s-key-service/manifest.json \
    --pool c8s-session/manifest.json:pool.key.pub
# ... launch one key service from ks-probe/opkeydata in its shape, then:
ks_machine=$(c8s session key-service launch-config machine --bundle ks-probe \
    --url https://192.0.2.7:8443)
c8s session key-service launch-config new --out ks --key ks-probe/launch.key \
    --image-manifest c8s-key-service/manifest.json \
    --pool c8s-session/manifest.json:pool.key.pub --machine "$ks_machine"
c8s session key-service pin --bundle ks --url https://192.0.2.7:8443 --out ks-pin.json
c8s session launch-config new --out pool --key pool.key --key-service ks-pin.json \
    --image-manifest c8s-session/manifest.json --pool agents --class s-4x16 \
    --machine "$machine"

# The owner: register the tenant's authority once, store a credential, start a session.
c8s session key-service tenant register --key-service ks-pin.json --tenant acme --authority-key authority.key
c8s session key-service credential put api-token --key-service ks-pin.json --tenant acme \
    --authority-key authority.key < token
c8s session start ... --key-service ks-pin.json --stored-credential api-token
```

A guest opens its session with the key service when it boots, while it is
nobody's, so the key service has judged its evidence before any bind. At the
bind the guest presents it, and the key service releases the credential only
if the bind names that guest, is signed by the authority it holds for the
bind's tenant, and declares the credential. The release is sealed to a key
of the guest's under a hybrid of ML-KEM-768 and X25519. Guests and owners
hold the key service to its pin before they send it anything.

A release rests on the key service's verdict as it stands at that moment,
and a guest may wait in its pool for hours. So the key service keeps the
evidence each guest opened with, asks the vendor again for each of its
documents three quarters of an hour after it fetched it, and every minute
judges again, with no new quote, each waiting guest whose verdict no longer
rests on the newest documents it holds or ends within five minutes. It
releases only on a verdict made on documents it fetched within the hour: one
that ran out is made again on the path of the release, and a key service
that cannot reach the vendor for an hour releases nothing until it can. A
guest whose evidence the newer documents refuse is forgotten, and gets
nothing. A verdict also ends with the certificate that carried its evidence,
after a day, so a guest that still waits then opens its session again under
its next certificate, with a fresh quote.

A guest has no road of its own to its key service. Its launcher carries the
connection:

```
 TD of a session            its host                      key service's TD
 +-----------+   vsock    +----------+       TCP         +---------------+
 |   agent   |----------->| launcher |------------------>|  key service  |
 +-----------+  port P    +----------+  the pin's url    +---------------+
       |                                                         |
       +------- one TLS channel, attested at both ends ----------+
```

The launcher listens on a vsock port of the host's, tells its guest the port
in the unsigned `host.json`, and joins what its guest sends there to the
address in the pin. It takes connections from its own guest's context id
alone, a few at a time, and reads nothing of what it carries: the channel
ends in the two TDs, and each holds the other to its evidence. So a session
needs no address, no route and no opening in a packet filter to be given its
keys, and its network stays as closed as its pool's configuration leaves it.
A launcher that carries the connection elsewhere, or nowhere, has a guest
that is never given a credential. A sandbox reaches none of this: its seccomp
profile refuses the socket family.

A TD judges the key service by the vendor's documents, which it asks its
launcher for over a second vsock port of the host's as soon as it has taken
its first quote. It opens its session once the first answer has arrived. The
launchers of one host keep one set of those documents for all their guests
and fetch it anew every ten minutes. Until the session is
open the guest refuses a bind on its headers, unread, and says it is not
ready; the daemon offers it to no claim. A pool whose key service is out of
reach therefore fills with TDs that boot and are never ready.

Those documents are the ones a guest's host chose to hand it, and a host can
hand over a set from before a platform's key was revoked ([A stand-in for
the key service](session-threat-model.md#keys-and-the-key-service)). So a
guest sends its key service nothing secret before its bind, and from its
bind on deals with none but the replicas the bind names
([Which replicas a guest trusts](session-key-service.md#which-replicas-a-guest-trusts)):

```text
 binder                         guest (TD)                   key service
   |                               | open, at boot: judged on what its host
   |                               | handed it ------------------> replica R
   | judge R, on documents fetched from the vendor itself        |
   | <======================= RA-TLS, evidence =================>|
   |                               |                             |
   | Bind(keyService: pin, members: [R])                         |
   | ----------------------------> | its session is with R:      |
   |                               | acquire ------------------> R
   |                               |                             |
   |                               | its session is with another replica:
   |                               | new connection, and a far end whose
   |                               | key is not R's is sent nothing;
   |                               | after three such, bind_no_member
```

A binder judges the replica that answers at the pin's address as it judges
a guest it sends a secret, on the vendor's documents as it fetched them
within the last hour, and its bind names that replica's instance key under
`keyService.members`. `keyservice.Members` keeps that verdict for a binder
that starts many sessions, judges again every minute over a new connection,
and on the path of a bind when the verdict no longer stands. `c8s session
start` and `bind` judge the replica before they claim or sign, so a key
service out of reach costs the pool no claim. A bind that names a key service
and no replica is no bind.

The guest takes the step before the bind has any other effect. If its
session is with a replica the bind names, nothing happens. Otherwise it opens
a session with one that the bind names, over a new connection that it drops
as soon as the handshake shows another key, and after three attempts refuses
the bind with `bind_no_member` and ends, as a guest does that refused any
bind. A bind that names no key service closes the guest's session with its
pool's, and the guest deals with no replica after it.

## Why a TD ended

A guest that ends itself says why as it goes
([What leaves a session](session-disclosure.md#logs-consoles-and-crashes)).
Its init sees the agent end, however it ends, and sends one message of the
disclosure schema to the guest's launcher before it powers the guest off: the
phase the guest had reached and a code.

```
 TD                                   its host
 +-------+ exits, with  +------+ vsock +----------+ end.json +--------+
 | agent |------------->| init |------>| launcher |--------->| daemon |
 +-------+  a status    +------+ port E+----------+          +--------+
     |                     ^            logs the word   the TD's reason,
     +--- its phase, in ---+                            in its log and in
          a file                                        Watch
```

The launcher listens on a vsock port of the host's and names it as `end_port`
in `host.json`. It takes one word, from its own guest's context id, holds it
to the schema, logs it, and writes it to the file the daemon named
(`--end-file`). The daemon gives it as the reason of the TD's end: `the guest
ended: process_ended in phase running`. A guest that says nothing, because its
kernel faulted or its VMM was ended under it, leaves `the guest ended`.

The init writes its word and ends its writing on the stream. The launcher
reads to that end, keeps the word, and closes its own end, and the init
powers the guest off once it has: a guest that powered off on its own write
could take the word with it, still on its way out. Neither side waits on the
other for more than two seconds, and a guest that reaches no launcher ends
all the same. A word that arrived whole is kept though its stream then
failed.

A TD that the daemon ends has the daemon's reason, and its guest is given no
time for a word: `destroyed`, `drained`, or `the guest refused its bind`,
which the daemon acts on as soon as the guest's answer to the bind says so.

| Code | The guest ended because |
|---|---|
| `process_ended` | the process the session's policy names as its own ended. What that process exited with is the session's, and stays in its logs |
| `service_exited` | the agent exited for a reason that has no code of its own yet. The word carries the status |
| `service_killed` | the agent was killed. The word carries the signal, and whether the kernel sent it for memory, by the kill count of the agent's own cgroup |
| `boot_failed` | a step of the guest's boot failed after its launch files were staged. A failure before that has no port to tell |

The agent names a reason of its own by the status it exits with, from a range
that neither a shell nor the Go runtime uses, and writes its phase to a file
as it changes, which the init reads. The codes are for whoever operates the
guests, and nothing that guards a session rests on one.

## Restarts and draining

A TD's launcher runs in a session of its own and outlives the daemon. The
daemon keeps one record per TD under `stateDir`. A daemon started later finds
each launcher by its process id and start time, takes its TD over in the
state the record names, and ends the records whose process is gone. Sessions
keep running across the restart. Their `Connect` streams are cut, and a
client opens new ones.

```sh
c8s session-daemon run --config /etc/c8s/sessions/daemon.yaml
c8s session-daemon drain --config /etc/c8s/sessions/daemon.yaml   # daemon stopped
```

`drain` ends every TD the state directory records, bound or not, and waits
until their memory is the host's again.

## Testing on hardware

`test/session/hardware.sh` (`make test-session-hardware`) runs all of the
above on one TDX host with real TDs: a key service, a daemon with one pool
that pins it, an owner who stores a credential, and sessions of two
tenants. It reads the key service's machine and the class's, each from the
evidence of one guest, and lists them in the two launch documents. It checks
that a session's command reads the stored credential and one that a key of
its bind released, that a first command and a credential sealed with a bind
reach the guest with it, and, given the timing tool, that a binder the pool
names by its key watches under a certificate of its own making and finds a
claimed guest judged ahead, while that certificate claims nothing and a
caller the pool does not name is shown nothing. The binder then starts a
session with a bind that claims its TD, which the orchestrator is shown with
the binder's key and ends, and starts another whose first TD a second bind
took first. A binder also names the key service's replica it judged in a
bind whose guest takes the stored credential from that replica. Then what
must be refused:

| Refused | By whom |
|---|---|
| a registration at a key service whose launch document lists no machine; a bind to a guest whose document lists none | the owner's client, before it sends anything, and the guest, to a caller that sends a bind anyway |
| a machine the launch document does not list, for a key service and for a guest; a device the class does not have | the guest, which ends before it serves |
| evidence of another image, of a pool under another launch key, of a pool that pins another key service | the owner's client, before it signs a bind |
| a key service that is not the one pinned | the owner's client, before it sends anything |
| a bind for a tenant nobody registered, or under another authority; a credential nobody stored | the key service |
| a sandbox image whose content was changed | the guest |
| a stranger's key; one session's binding on another session's TD | the guest |
| a bind to a guest of a pool the key service does not serve | the guest, which is never ready |
| a bind that names another replica of the key service than the one the guest's session is with | the guest, which reaches none the bind names and ends |
| a destroy without an orchestrator's certificate; a claim or a destroy under a binder's own certificate; a binder's bind that claims under an authority its pool does not name for it; a bind that claims from a key the pool does not name; the host's TDs shown to a binder | the daemon |

With dev images it also probes, from inside a guest, every address of its
host and of the other guests, and requires the host's filter to have counted
the attempts as dropped. The script's header lists what it needs and what it
changes on the host while it runs.

## A simulated TEE

[session-performance.md](session-performance.md#method) holds a session's
start to a second baseline: the same guest and VMM with TDX off. A session
image stops without a TEE, so that baseline runs a development build whose
guests simulate one in software. The build is made with the Go build tag
`c8s_simtee`. It protects nothing: its purpose is that every step of a start
costs what it costs in a TD, so that the difference between the two is what
the hardware and the vendor's quoting add.

```
  release build                         development build (c8s_simtee)

  launcher --tdx-guest--> QEMU          launcher --no TEE object--> QEMU
      |                     |               |  checks firmware and disk
      |                 TDX module          |  against manifest.json, then
      |              measures MRTD,         |  declares MRTD, RTMR[0..2]
      |              RTMR[0..2]             v
      v                     v           simtee.json on the launch volume
  +------ TD ------------------+        +------ plain VM ----------------+
  | init: extend RTMR[3]       |        | init: /run/c8s-simtee/rtmr3    |
  | agent: TDREPORT, quote     |        | agent: quote signed in guest   |
  |        from host's QE      |        |        with the platform's QE  |
  |                            |        |        key, which it is handed |
  +----------------------------+        +--------------------------------+
      verifier: Intel's root                verifier: simulated root,
      and Intel's documents                 in place of Intel's, and
                                            'simtee vendor' documents
```

| Part | In a TD | Simulated |
|---|---|---|
| MRTD, RTMR[1], RTMR[2] | measured by the TDX module and the firmware | declared by the guest's launcher from the image's `manifest.json`, after it held the firmware and the disk it hands the VMM to the digests the manifest names |
| RTMR[0] | the firmware's measurement of the machine | the digest of the launcher's description of the machine: vCPUs, memory and its split, and which devices |
| RTMR[3] | extended through the guest's kernel | a file in the guest's memory, made by the init with the launch key's digest and extended by the agent |
| A quote | signed by the host's quoting enclave | the same format, signed in the guest with the key of the simulated platform's one quoting enclave, which each guest's launcher hands it with the platform's certification of that key |
| The vendor's documents | Intel's service | `c8s session simtee vendor`: the same four documents, signed under the simulated authority; the platform is always UpToDate and nothing is revoked |
| The root evidence is held to | Intel's | the simulated authority's, in its place and never beside it |

The authority is a directory. Whoever reads it makes any quote and any
document. It holds one platform, and that platform's quoting enclave: one
attestation key for every guest launched from the directory, as every TD of
a host is quoted by its host's one enclave. A verifier knows a platform by
that key and its certification, and keeps the outcome of the checks that
depend only on the platform and the vendor's documents. So it does for the
guests of one simulated authority what it does for the TDs of one host: the
checks once, and then each guest's own quote.

```sh
c8s session simtee new --out /var/lib/c8s/simtee        # the authority, one platform under it, and its quoting enclave
c8s session simtee vendor --dir /var/lib/c8s/simtee &   # serves its documents, and writes its address there
C8S_SIMTEE=1 C8S_PLATFORM=tdx session-guest-image/build # -> c8s-session-simtee, with its own reference values
```

A daemon of that build launches every guest so with `vmm.simulatedTEE:
/var/lib/c8s/simtee` in its configuration, a launcher with `--simulated-tee`,
and every command that judges evidence takes `--simulated-tee` too. With the
option unset, the development build judges and launches as a release build
does.

What keeps the two kinds apart:

- A release build has none of it. Each hook is a type or a function defined
  twice, by build tag, and the release one is empty: no option, no
  configuration key, and no import of the package that makes simulated
  quotes. `internal/simtee/release_test.go` reads every file's build
  constraint and asks the toolchain what each program links.
- An engine given a simulated authority holds evidence to that root in place
  of the vendor's. It refuses a TD's evidence, as every other engine refuses
  a simulated guest's, and it keeps the authority's documents in a directory
  of their own: they have the addresses of Intel's.
- A simulating image refuses to run in a confidential VM: its init stops
  where it finds a TEE's register or guest device, and so does its agent. An
  image built for a TD stops without one, as always, and never falls back.
- The image build compiles both programs with the tag or neither, refuses a
  prebuilt program of the other kind, and writes `SIMULATED-TEE` beside the
  manifest.
- A program of the development build states its version with `+c8s_simtee`
  at its end, so a record that names versions names the build.
- `c8s session verify --simulated-tee` lists first, among what its verdict
  does not prove, everything about the guest's hardware.

Where a simulated guest's own work differs from a TD's, a run's record says
so:

| Work | In a TD | Simulated |
|---|---|---|
| Memory at boot | accepted and cleared as the guest uses it | all of it cleared by the kernel before the init runs, through the host's page faults: seconds for 16 GiB, and many times that on a host whose memory other guests hold |
| The guest's clock | the TSC, at the rate the TDX module states | the TSC, at the rate the kernel measured at boot: a plain guest's kernel may never finish refining it, and the agent takes the counter under either name |
| A quote | a report from the TDX module, signed by the host's quoting service | one signature in the guest |
| An extend of RTMR[3] | a call into the TDX module | a write to a file in memory |
| Device I/O | through bounce buffers shared with the host | on the guest's own pages |

`test/session/simtee.sh` is this build's hardware test. It starts a session
in a guest with no TEE under the simulated authority, and requires that a
release build has no word for the simulation, that a verifier under Intel's
root or under another simulated authority refuses the session, that a
launcher declares no registers for a disk its manifest does not name, that a
simulating image ends in a TD and a TD's image ends without one, and that a
TD's evidence is refused under the simulated authority. `make test-simtee`
runs the unit tests of the packages the tag changes in that build.
`test/session/timing.sh` takes this side in turn with the TD's when it is
given the development build and its images.

## What is missing

- The other calls of the design: pools made and changed through the API,
  `Hold`, `Release`, `Seal`, `Deliver`, `Collect`, `GetStats`, and the flows
  that call a registered binder (`Start`, `Restore`, `Fork`). Pools come from
  the configuration file, with the binders that may watch them and claim
  their TDs, and the binder of a session is the caller's own.
- Of `Watch`: it shows TDs. The design's events for a commit, a seal, a
  restore and a pool's depth come with those calls.
- The JSON form of the API.
- A second host, and with it placement.
- Quotas per orchestrator. The bounds on open calls are fixed: 64 evidence
  requests of one caller in flight, and 4096 connections for every caller
  together.
- A cgroup per TD, which statistics and memory limits need.
- Of a guest's last word: a code of its own for each reason the agent ends
  a guest (its age limit, a refused bind, each guard), and the kernel's
  fixed code for a fault, through the platform's call for a fatal error.
- Disk slots. A TD has its image, its launch disk, a scratch disk and the
  image store.
- A reload of the daemon's certificate without a restart.
- IPv6 for guests.
- Of the key service: leases and generations, more than one replica, the
  ledger, recovery, a change of a tenant's authority, and deleting a stored
  credential. A replica that stops has forgotten its tenants and their
  credentials. Before its bind a guest judges the key service by the vendor
  documents its own launcher answers with, so the two share a platform for
  now. A bind names one replica: the membership statements by which a guest
  follows a key service whose replicas change come with the replicas. A
  bind's `notAfter` is judged by the guest's own clock, which is its host's:
  the key service serves no time yet. With no lease there is nothing yet to
  refuse a running session whose platform the vendor revokes: the key
  service keeps the evidence each bound guest acquired with for that
  judgment, and a repeat of an acquire is held to it.
- Offering each ready TD to one watcher at a time. Binders that watch one
  pool are all shown the same TDs and sign for the one shown first, so two
  that start a session at the same moment collide, and one signs again.
