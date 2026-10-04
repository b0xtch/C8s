# The session daemon

Status: built for one host. It serves five calls of the
[session API](session-api.md): `Claim`, `Bind`, `Connect`, `GetEvidence` and
`Destroy`. [What is missing](#what-is-missing) lists the rest of the design.

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
 owner's client              daemon                      guest (TD)
   |                           |                            |
   | Claim(pool, session) ---> | fence -------------------> | cuts every earlier
   |                           |                            | connection
   | <-- td, evidence, bind_by | <-- certificate, documents |
   |                           |                            |
   | verify: pinned image, pool's launch key, bound by nobody
   | sign a bind for the TD's instance key
   |                           |                            |
   | Bind(td, bind) ---------> | bind --------------------> | checks, measures,
   |                           |                            | starts the sandbox
   | <-- evidence ------------ | <-- evidence, fresh over the bind's nonce
   |                           |                            |
   | verify under the bind     |                            |
   |                           |                            |
   | Connect(td) ============= bytes =====================> | the TLS session
   |                           |                            | ends in the guest
```

No boot is on this path: a TD boots into its pool before any session asks
for it. [session-performance.md](session-performance.md) is where measured
times go.

`c8s session start` is that client: it claims, verifies, signs with the
owner's authority key, binds and verifies again, and writes a binding
directory. `verify`, `credential put`, `exec` and `destroy` then take
`--binding` and reach the guest through the daemon.

## Who may call what

| Call | Caller | Needs |
|---|---|---|
| `Claim`, `Bind`, `Destroy` | an orchestrator | a client certificate of the authority in `tls.clientCA` |
| `GetEvidence` | anyone | nothing: what a guest serves to anyone is public |
| `Connect` | anyone | nothing at the daemon: the guest authenticates every request under the keys its bind names |

A TD carries connections only once it is bound. Before that, the only bytes
that reach its guest are the daemon's own requests and the bind of its claim,
so a caller that learns a ready TD's name cannot bind it for itself. TD names
are 128 random bits.

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
  reach: ["192.0.2.7:8443"]     # optional: open to every guest, as the key service is
  dns: [192.0.2.53]
vmm:
  quoteSocket: /var/run/tdx-qgs/qgs.socket
  confine: "64055"              # run the VMM as this user, with no capability
classes:
  s-4x16: {vcpus: 4, memory: 16G, scratch: 8G}
pools:
  - imageDir: /var/lib/c8s/images/c8s-session
    launchDir: /etc/c8s/sessions/agents/opkeydata
    depth: 4
    bindGrace: 30s
    imageStore: /var/lib/c8s/images/images.store
```

| Key | Meaning |
|---|---|
| `capacity` | An upper bound on TDs in every state. A TD's memory is not the host's again until its VMM is gone, and the slot stays taken until then. |
| `classes` | The launch shapes this host offers. A class fixes vCPUs and memory, and with them RTMR[0], so a class is a set of reference values (rule R7 in [session-api.md](session-api.md#rules-the-api-keeps)). |
| `pools[].launchDir` | The `opkeydata` directory of a launch bundle from `c8s session launch-config new`. The pool takes its name and its class from the launch document there. |
| `pools[].depth` | How many TDs the pool keeps ready. Two boot at a time. |
| `pools[].bindGrace` | How long a claim waits for its bind. After it the TD returns to the pool: the daemon sent it nothing, so nothing of a tenant entered it. |
| `pools[].imageStore` | A store of public images (`c8s session image-store write`) handed read-only to every guest, so that a bind which names one starts it without a pull. |
| `vmm.console` | Attach each guest's console to its launcher's log. For dev images only: a locked image prints nothing there. |

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

What a sandbox may reach is decided a second time inside the guest, by the
egress policy of its bind, which the host cannot change. The host's rules are
the outer wall: they keep a tenant's guest away from the host's own services
and from other tenants whatever the guest does.

`user` mode gives a guest the VMM's user-mode stack, with its TLS port
forwarded to a loopback port. It needs no privilege and filters nothing. It
is for development.

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

```sh
# The operator: a key for the pool, the key service's bundle and pin, the pool's bundle.
c8s session launch-config key --out pool.key
c8s session key-service launch-config new --out ks \
    --image-manifest c8s-key-service/manifest.json \
    --pool c8s-session/manifest.json:pool.key.pub
c8s session key-service pin --bundle ks --url https://192.0.2.7:8443 --out ks-pin.json
c8s session launch-config new --out pool --key pool.key --key-service ks-pin.json \
    --image-manifest c8s-session/manifest.json --pool agents --class s-4x16

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

In `tap` mode the key service's address and port go in `network.reach`.

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

## What is missing

- The other calls of the design: pools made and changed through the API,
  `Hold`, `Release`, `Seal`, `Deliver`, `Collect`, `GetStats`, `Watch`, and
  the flows that call a registered binder (`Start`, `Restore`, `Fork`). Pools
  come from the configuration file, and the binder is the caller's own.
- The JSON form of the API.
- A second host, and with it placement.
- Quotas per orchestrator. The bounds on open calls are fixed: 64 evidence
  requests and 4096 connections in flight.
- A cgroup per TD, which statistics and memory limits need.
- Disk slots. A TD has its image, its launch disk, a scratch disk and the
  image store.
- A reload of the daemon's certificate without a restart.
- IPv6 for guests.
- Of the key service: leases and generations, more than one replica, the
  ledger, recovery, a change of a tenant's authority, and deleting a stored
  credential. A replica that stops has forgotten its tenants and their
  credentials. A guest judges the key service by the vendor documents its own
  host handed it, so the two share a platform for now.
