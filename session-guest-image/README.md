# Session guest image

The measured guest image of a confidential session: one confidential VM for
one session. The design and the trust model are in
[docs/sessions.md](../docs/sessions.md).

It is a [confidential-os-builder](https://github.com/confidential-dot-ai/confidential-os-builder)
profile, built the way `node-guest-image/` is: the profile and the kernel
fragment live here, and a confos checkout is only the builder.

```sh
C8S_PLATFORM=tdx session-guest-image/build     # -> <confos>/output/c8s-session/
```

The output directory holds `disk.raw`, the firmware (`OVMF.tdx.fd` on TDX, one
IGVM file per vCPU count on SEV-SNP) and `manifest.json`. The manifest carries
the reference values a verifier pins: MRTD, RTMR[1] and RTMR[2] on TDX.

Beside the manifest the build publishes the image's two schemas, each printed
by the binary it staged (`c8s session schema`):

| File | What it fixes |
|---|---|
| `disclosure-schema.json` | every message the agent sends a caller it has not authenticated, and the bound of each field: a code from a list, a flag, a counter, a digest or a public document ([session-disclosure.md](../docs/session-disclosure.md)) |
| `bind-schema.json` | every member a bind may carry and the purposes the agent accepts; a bind with any other member is refused ([session-api.md](../docs/session-api.md#the-bind)) |

The same two files are on the image's verity root, so the measurements cover
them, and the agent ends a guest whose files are not the schemas it is
compiled from. `c8s session schema bind --check bind-schema.json` compares a
published file with a build.

## What is in it

| Piece | Where | Why it is measured |
|---|---|---|
| `c8s` binary | `/usr/local/bin/c8s`, compiled from this checkout by `build` | It is the agent: it verifies the launch document, takes the one bind, extends RTMR[3] and serves the attested API |
| `c8s-session-load.service` | verity root | Copies the launch files off the `opkeydata` volume and renders the host's network request |
| `c8s-session-agent.service` | verity root | Its flags are the agent's configuration, so they are part of the image identity |
| `c8s-session-firewall.service` and `/etc/c8s-session/firewall.nft` | verity root | The inbound filter: only the agent's port may be reached from outside the guest |
| `/etc/c8s-session/disclosure-schema.json`, `bind-schema.json` | verity root, written by `build` | What the agent says in plaintext and what it takes in a bind. The agent checks both against its own definitions before it serves |
| `/etc/sysctl.d/50-c8s-session.conf` | verity root | No tunnel device in a new network namespace. The limit on user namespaces is the agent's to set: it makes the sandbox's and then has the kernel make no other |
| `crun`, `nft` | distribution packages | crun runs the sandbox image a bind names, driven by the agent alone; nft loads the filter |
| `sandbox` user (2000:2000) | `/etc/passwd`, written at build time | A session's commands run as this user in a dev image, when a bind names no sandbox image |
| `kernel/session.config` | merged into the guest kernel | Adds vsock, which the agent uses to reach the host's quoting service and its key service, user namespaces for the sandbox's container, nftables for the filter, and transparent huge pages on request. |

The base image contributes the kernel, the measured initrd that binds the
launch key, the dm-verity root and the encrypted ephemeral state volume. This
profile adds no attestation daemon, and nothing in it takes orders from the
host.

`mkosi.finalize` strips every setuid and setgid bit and fails the build if one
survives, fails it if crun or nft is missing, and masks the distribution's
`nftables.service`, which would replace the image's filter with an open one.
The agent unit sets `NoNewPrivileges`, which the sandbox and every command run
for a session inherit.

## Knobs

| Variable | Meaning |
|---|---|
| `C8S_PLATFORM` | Required: `tdx` or `snp`. The agent refuses to stage on the other TEE. |
| `C8S_DEV=1` | Debug image: console, root autologin on it, journal forwarded to it, a bind accepted with no sandbox image, and a sandbox image accepted from a plain-HTTP registry at `10.0.2.2:5000` for tests. A different measurement and host-readable logs. Never ship. |
| `C8S_ROLE=key-service` | Build the [key service](../docs/session-key-service.md)'s image: this image with `c8s session-key-service run` as its measured service where the agent is. It has reference values of its own. |
| `C8S_NAME` | Output name (default `c8s-session` or `c8s-key-service`, with `-dev` for a dev build) |
| `C8S_MEMORY` | Default memory recorded in the manifest (default `1G`) |
| `C8S_BINARY` | Stage this prebuilt linux/amd64 binary and skip the compile |
| `CONFOS_DIR` | confos checkout to build with (default: a sibling of this repository) |

## Status

No reproducibility check runs for this image yet. The node image's check
builds twice and compares measurements; this image needs the same, on a second
builder, before its manifest is worth pinning in production.

The key service's image is this profile with another service on its verity
root, so it also carries crun and the sandbox user, which a key service has
no use for. A profile of its own comes with the key service's replication.

The design calls for a session image with no console
([session-disclosure.md](../docs/session-disclosure.md)). This profile's
locked build offers no login and attaches no console getty; the kernel's own
console is still to come.

`bin/setup` in confos installs host packages from a pinned snapshot and allows
downgrades. Build in a throwaway VM or container: on a host you care about it
can move systemd and QEMU backwards.
