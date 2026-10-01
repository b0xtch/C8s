# Pod CVM: one worker pod as its own confidential VM

A pod CVM is one Kubernetes pod whose only content is one confidential VM,
launched for exactly one tenant. Node-as-CVM isolates a node from its host.
A pod CVM isolates one tenant's worker from the host, from the node, and from
every other tenant's worker, and it makes that worker's identity a claim the
hardware signs.

This is the first milestone of pod-as-CVM on current main. It replaces the
Kata-based mode removed in f7051215 with a design built on the launch-key,
image-policy and RA-TLS contracts the node image already uses.

## Status

| Piece | State |
|---|---|
| Signed launch document, measurement chain, verifier trust gate (`pkg/podcvm`) | implemented, unit-tested |
| In-guest agent: stage, attest, credential release, exec (`c8s pod-agent`) | implemented, unit-tested against a simulated TD |
| Verifier engine on real evidence | tested on a captured non-debug TDX quote, including live Intel collateral |
| Host launcher (`c8s pod-launcher`) | implemented, unit-tested with a stand-in VMM |
| Guest image profile (`pod-guest-image/`) | written, build pending |
| Boot, attestation, release and exec on TDX hardware | not yet run |
| SEV-SNP | launch arguments and verifier paths written, never run |
| Workload from an OCI image | schema and measurement order in place, no in-guest runtime yet |

Anything not marked as run on hardware is unverified there. The hardware suite
is `test/podcvm` (build tag `podcvm_hardware`), and `test/podcvm/run-hardware.sh`
boots the guests it needs and runs it. See [Hardware tests](#hardware-tests).

## Shape

```text
 verifier (developer or control plane)            HOST, untrusted
 ─────────────────────────────────────            ───────────────────────────────
 c8s pod launch-config new ──bundle──▶  pod ┌───────────────────────────────────┐
   launch.key (stays here)                  │ c8s pod-launcher run              │
   pubkey, launch.yaml, launch.yaml.sig     │   launch disk (ISO, opkeydata)    │
                                            │   scratch disk (ciphertext only)  │
                                            │   tap = the pod's own interface   │
                                            │   QEMU ─▶ TD                      │
                                            └───────────────┬───────────────────┘
                                         ═══════════════════╪════ TEE boundary ═══
                                            ┌───────────────▼───────────────────┐
                                            │ measured guest image              │
                                            │  initrd: verity root, RTMR[3] ←   │
                                            │          SHA-384(pubkey)          │
                                            │  pod-agent load: launch files,    │
                                            │          network from host.json   │
 c8s pod verify      ◀── RA-TLS :8443 ────▶ │  pod-agent run: verify signature, │
 c8s pod credential put                     │          RTMR[3] ← launch.yaml,   │
 c8s pod exec                               │          instance key, attested   │
                                            │          API, commands as an      │
                                            │          unprivileged user        │
                                            └───────────────────────────────────┘
```

The host starts the VM and carries its packets. It has no control channel into
the guest: no agent RPC, no exec path, no log stream, no shared filesystem.
Everything that drives the guest arrives over the attested endpoint, signed by
a key the launch document names.

## What changed from the Kata mode, and why

| Kata mode (removed) | Pod CVM |
|---|---|
| Host shim drives a guest agent over vsock; a baked OPA policy and ten agent patches constrain what the host may ask | No host-to-guest API exists, so there is nothing to constrain |
| Host writes the container spec; the guest polices it after the fact (post-start kill window) | The signed launch document is the only source of what runs; nothing unmeasured starts |
| TDX pinned MRTD alone, because Kata's direct kernel boot made RTMR[1] and RTMR[2] underivable offline | The image is a confos build: MRTD, RTMR[1] and RTMR[2] come from its manifest and are pinned together |
| Per-pod configuration reached the guest through init-data and a fixed cloud-init default | Per-pod configuration is the signed launch document, bound to the launch key the hardware measures |
| An attestation daemon on guest loopback, reachable by workload code | The agent asks the hardware itself; tenant code cannot obtain a quote |
| kata-deploy, a puller DaemonSet and a version lockstep with upstream Kata | One launcher command and one image directory |

## What is measured

| Register | Covers | Pinned by |
|---|---|---|
| MRTD | TDVF firmware | image `manifest.json` |
| RTMR[1] | boot chain: GPT, systemd-boot, UKI image | image `manifest.json` |
| RTMR[2] | UKI sections: kernel, initrd, command line with the verity root hash | image `manifest.json` |
| RTMR[0] | TD HOB and ACPI, which vary with vCPUs and memory | not pinned, as on the node image |
| RTMR[3] | launch key, then launch document, then workload image | recomputed by the verifier |

The c8s binary, its units and their flags are on the dm-verity root, so they
are covered by RTMR[2]. The agent's behaviour is therefore part of the pinned
image identity.

RTMR[3] is a chain, in the `runtimemeasure` convention the node image and
`c8s get-kubeconfig --workload-image` already use:

```text
RTMR[3] = Seed(pubkey)                     extended by the measured initrd
        ⊕ Event(sha256(launch.yaml))       extended by pod-agent, after the signature verifies
        ⊕ Event(workload image digest)     extended by pod-agent, after the pull verifies,
                                           before the workload starts
```

Measuring the launch key alone would not bind a tenant: the host could boot
the guest with any other document the same key signed. Measuring the document
digest pins which one. The chain is a pure function of the key and the
document, so the agent reads the register before every extend and extends only
what is missing. That makes each extend exactly-once across agent restarts
with no journal file. A register on no prefix of the chain is fatal.

On SEV-SNP there is no runtime register. The launcher commits
`SHA-256(pubkey)` as HOST_DATA, the initrd refuses to boot on a mismatch, and
the document and workload are bound through the attestation transcript below.

## The launch document

`c8s-pod-launch/v1`, strict YAML, signed with ECDSA P-256 over its exact bytes
(`launch.yaml.sig`, same detached format as the node launch document). It
carries no secrets, so the exact bytes a guest measured can be handed to
anyone who needs to verify it.

```yaml
schemaVersion: c8s-pod-launch/v1
id: 3f0c...                # 32 hex, unique per launch
tenant: acme.user-42       # the one security context this CVM belongs to
sandbox: sbx-1
image:                     # the guest build this document was signed for
  platform: tdx
  measurement: <mrtd>
  rtmrs: {1: <rtmr1>, 2: <rtmr2>}
workload:                  # optional
  image: ghcr.io/acme/agent@sha256:<digest>
  command: [/usr/bin/agent]
access:
  exec: [<public key PEM>]          # may run commands and request attestation
  credentials: [<public key PEM>]   # may release credentials and request attestation
credentials:
  - name: inference-token
    maxBytes: 4096
```

Nothing is implicit. The launch key signs the document and holds only the
access the document grants it. `c8s pod launch-config new` grants it both by
default and `--no-launch-key-access` grants it neither.

The guest refuses a document that names another image than the one it booted,
so a signature made for one build is not honoured by another.

## Boot

1. The measured initrd opens the verity root, re-keys the scratch disk with a
   random in-memory key, and extends RTMR[3] with `SHA-384(pubkey)` from the
   `opkeydata` volume (existing confos behaviour).
2. `c8s pod-agent load` copies `launch.yaml` and its signature off the volume
   and renders `host.json`, if present, as a systemd-networkd unit.
   `host.json` is unsigned. It carries only the address the host assigned, and
   it is parsed as hostile input: every value must be exactly an address or a
   bounded integer.
3. `c8s pod-agent run` reads its own measurements from the TDX module, refuses
   a debuggable guest, verifies the document's signature under the staged
   key, confirms RTMR[3] is on this launch's chain (which proves the staged
   key is the measured one), and extends the document digest.
4. It generates the instance key in memory, obtains a quote binding it, and
   serves RA-TLS on `:8443`.
5. It admits the workload: pull and verify, extend, start. The API is up
   during the pull and reports phase `staged`; exec and credentials are
   refused until phase `running`.

If the agent cannot run, the unit powers the guest off after three attempts.
The launcher then exits and the pod restarts to a fresh attestation.

## The agent API

RA-TLS on `:8443`. The serving certificate is self-signed over the instance
key and carries a quote binding that key (`REPORTDATA = SHA-384(pubkey)`, the
standard c8s RA-TLS extension), so existing RA-TLS verifiers can read it.

| Route | Access | Effect |
|---|---|---|
| `GET /healthz` | none | liveness only |
| `POST /v1/attest` | `access.exec` or `access.credentials` | fresh evidence for a 32-byte nonce, plus the launch document, its signature, the measured events and the phase |
| `PUT /v1/credentials/{name}` | `access.credentials` | writes a declared credential to RAM-backed storage readable by the workload user |
| `POST /v1/exec` | `access.exec` | runs one command in the workload context, returns exit status and bounded output |

Authorization is the `operatorauth` token c8s already uses: an ES256 JWT bound
to the method, path and body hash. A captured token authorizes nothing else.
Exec carries a caller-chosen 128-bit id and is at-most-once per id: a retry
joins the run in flight or replays its result, and an id whose result has
aged out is refused.

Commands run as the unprivileged `workload` user with a fixed baseline
environment, in a per-command cgroup that is killed whole when the command
ends. The image has no setuid or setgid file, the agent's unit sets
`NoNewPrivileges`, and only root can reach the TDX device, so tenant code
cannot obtain a quote or extend RTMR[3]. The hardware suite probes each of
these from inside the guest.

A guest launched with `--vsock-cid` has a vsock device, which the agent uses
to reach the host's quoting service. Tenant code can open vsock connections to
host services too. That gives it no quote: a quote starts from a TDREPORT, and
only root can ask the TDX module for one.

Fresh evidence binds one transcript:

```text
binding    = SHA-256("c8s-pod-attest/v1" ‖ 0x00 ‖ nonce ‖ count ‖ event digests)
REPORTDATA = SHA-384(PKIX(instance key) ‖ binding)
```

## What a verifier checks

`pkg/podcvm.VerifyAttestation`, used by `c8s pod verify`, `credential put` and
`exec`. In order:

1. The launch document's signature verifies under the pinned launch key.
2. The document is the pinned one, or names the pinned tenant and sandbox.
3. The document names the pinned image.
4. The expected events are derived from the document. The guest's reported
   events must equal them.
5. Hardware evidence verifies in process: quote signature, QE report, PCK
   chain to the pinned Intel root, and REPORTDATA equal to the transcript over
   the verifier's own nonce and the key the TLS handshake just proved.
6. The guest is not debuggable.
7. MRTD, RTMR[1] and RTMR[2] equal the image manifest's.
8. RTMR[3] equals the launch-key seed extended by exactly the expected events.

A credential is released only after this passes for a fresh nonce, with the
workload admitted. The first attestation pins the instance key for the life of
the client. From then on a new connection presenting another key is refused in
the handshake, and a pooled connection that does not terminate at the pinned
key is closed before a byte of the request is written to it. The second rule
matters when the policy pins tenant and sandbox and leaves the document open:
the handshake then proves the image and nothing about who launched the guest,
so a host could answer an early connection with a guest of the same image that
it launched itself.

`--collateral required` (the default) also fetches Intel TCB info, QE identity
and CRLs and refuses any TCB status other than UpToDate. If Intel PCS cannot
be reached, nothing is released and the result is "no verdict", since nothing
was learned about the evidence. `--collateral skip` checks the signature chain
only, and `c8s pod verify` then reports the platform TCB level and revocation
as not proven.

Exit codes for `verify` and `credential put`: 0 verified, 1 usage, 2 refused,
3 no verdict. `exec` exits with the command's own status, 124 if it could not
be run, 125 if verification refused it.

## What this does not prove

- **That the workload is safe.** Attestation identifies what booted and what
  was admitted. It says nothing about what that code does.
- **Uniqueness.** The host can boot the same image with the same document more
  than once. Each instance has its own key and attests identically. A
  credential goes only to the instance the verifier attested, but the verifier
  cannot tell that no twin exists.
- **Availability.** The host can refuse to run the guest or drop its packets.
- **Guest time.** The guest clock starts from a host-supplied value, and
  tokens are accepted within five minutes of skew. Replay protection rests on
  exec ids and attestation nonces, which the host cannot influence.
- **The provenance of `manifest.json`.** The verdict is only as good as the
  reference values it was given.
- **TCB level, with `--collateral skip`.**

## Assessment

KRAB vector, provisional until the hardware run and a reproducibility gate:
`A3 | R[f1/o?/l?/a?] | B2 | K4`.

Verified facts:

- The verifier reaches Intel's root directly; no third-party attestation
  service is trusted (A3). Tested against a real quote.
- A fresh verifier nonce and the TLS key are both in REPORTDATA and compared
  exactly; the key is pinned for the client's lifetime (B2).
- Release requires the exact image tuple, the exact RTMR[3] chain, and the
  live bound session (K4). Tested against a simulated TD.

Assumptions and unknowns:

- R is unscored for the OS, loader and agent until the pod image is built
  twice and compared. confos gates this for the node image; the pod image has
  no gate yet. The firmware is Ubuntu's packaged TDVF, source available.
- Nothing here has run on TDX hardware yet.
- K4 holds for verifiers using this library. A caller that releases a secret
  some other way is outside it.

## Launching

```sh
c8s pod launch-config new --out sbx-1 --image-manifest manifest.json \
  --tenant acme.user-42 --sandbox sbx-1 --credential inference-token

# in the pod, on the host
c8s pod-launcher run --platform tdx --image-dir /images/c8s-pod \
  --launch-dir /launch --work-dir /work --vcpus 2 --memory 2G \
  --quote-socket /var/run/tdx-qgs/qgs.socket --vsock-cid 1042

c8s pod verify --url https://$POD_IP:8443 --bundle sbx-1 --image-manifest manifest.json
c8s pod credential put inference-token --url https://$POD_IP:8443 \
  --bundle sbx-1 --image-manifest manifest.json < token.txt
c8s pod exec --url https://$POD_IP:8443 --bundle sbx-1 \
  --image-manifest manifest.json -- sh -c 'wc -c < $C8S_CREDENTIALS_DIR/inference-token'
```

`--network tap` (the default) hands the pod's own interface to the guest: same
address, same MAC, frames redirected at L2. The launcher opens the tap and
vhost-net and passes QEMU the descriptors, so the VMM needs no network
privilege of its own. `--network user` is QEMU's user-mode stack with
forwarded ports, for bring-up without NET_ADMIN.

The launcher is untrusted. It checks the bundle's signature before starting
QEMU only so that a bundle which could never boot fails immediately and
legibly.

## Building the image

```sh
C8S_PLATFORM=tdx pod-guest-image/build
```

The script compiles the in-guest binary from this checkout and stages it into
a confos build of the `c8s-pod` profile, with `kernel/pod.config` merged into
the guest kernel (vsock, for the millisecond quote path). `C8S_DEV=1` builds a
debug image with a serial console and host-visible logs, at a different
measurement.

## Hardware tests

```sh
C8S_POD_IMAGE_DIR=/path/to/output/c8s-pod test/podcvm/run-hardware.sh
```

The script boots three guests in turn on QEMU's user-mode network, so it needs
no cluster:

| Guest | What it shows |
|---|---|
| a, the bundle under test | The suite passes once per collateral mode: attest, release, exec, 13 evidence rejection cases on real evidence, wrong callers and policies, exec idempotency, and the tenant probes. |
| b, the same image under another launch key | A verifier holding bundle a refuses it, after a control shows it verifies under its own bundle. |
| c, a document signed for another image | The guest refuses to stage and powers off without serving its API. |

Boot refusals for a tampered document, a missing signature and a swapped key
are covered against the simulated TD only: the launcher checks a bundle before
it boots one, so the script cannot hand a guest those inputs.

## Known gaps

- No container runtime in the guest yet. A document with a workload image is
  staged and then refused at admission.
- Encrypted persistent workspaces, pause and resume, and warm pools are later
  milestones.
- CDS does not yet accept pod CVM evidence: `ImagePin.Anchor` checks the bare
  launch-key seed, and a pod CVM's RTMR[3] carries events on top of it.
- The browser verification path (c8s-verify) is not wired to this endpoint.
- The guest image is the general confos base. It is not yet tuned for boot
  time or memory.
