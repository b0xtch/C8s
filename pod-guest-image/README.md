# Pod guest image

The measured guest image of a pod CVM: one worker pod, one confidential VM,
one tenant. Design and trust model are in [docs/pod-cvm.md](../docs/pod-cvm.md).

It is a [confidential-os-builder](https://github.com/confidential-dot-ai/confidential-os-builder)
profile, built the way `node-guest-image/` is: the profile and the kernel
fragment live here, and a confos checkout is only the builder.

```sh
C8S_PLATFORM=tdx pod-guest-image/build     # -> <confos>/output/c8s-pod/
```

The output directory holds `disk.raw`, the firmware (`OVMF.tdx.fd` on TDX, one
IGVM file per vCPU count on SEV-SNP) and `manifest.json`. The manifest carries
the reference values a verifier pins: MRTD, RTMR[1] and RTMR[2] on TDX.

## What is in it

| Piece | Where | Why it is measured |
|---|---|---|
| `c8s` binary | `/usr/local/bin/c8s`, compiled from this checkout by `build` | It is the agent: it verifies the launch document, extends RTMR[3] and serves the attested API |
| `c8s-pod-load.service` | verity root | Copies the launch files off the `opkeydata` volume and renders the host's network request |
| `c8s-pod-agent.service` | verity root | Its flags are the agent's configuration, so they are part of the image identity |
| `workload` user (2000:2000) | `/etc/passwd`, written at build time | Tenant commands run as this user |
| `kernel/pod.config` | merged into the guest kernel | Adds vsock, which the agent uses to reach the host's quoting service |

The base image contributes the kernel, the measured initrd that binds the
launch key, the dm-verity root and the encrypted ephemeral state volume. This
profile adds no attestation daemon and no container runtime.

`mkosi.finalize` strips every setuid and setgid bit and fails the build if one
survives. The agent unit sets `NoNewPrivileges`, which every tenant command
inherits.

## Knobs

| Variable | Meaning |
|---|---|
| `C8S_PLATFORM` | Required: `tdx` or `snp`. The agent refuses to stage on the other TEE. |
| `C8S_DEV=1` | Debug image: console, root autologin on it, journal forwarded to it. A different measurement and host-readable logs. Never ship. |
| `C8S_NAME` | Output name (default `c8s-pod`, or `c8s-pod-dev`) |
| `C8S_MEMORY` | Default memory recorded in the manifest (default `1G`) |
| `C8S_BINARY` | Stage this prebuilt linux/amd64 binary and skip the compile |
| `CONFOS_DIR` | confos checkout to build with (default: a sibling of this repository) |

## Status

Built and booted on Intel TDX (docs/pod-cvm.md, "Results on hardware"). Two
builds from the same inputs on one build machine gave identical `disk.raw` and
`uki.efi` and the same MRTD, RTMR[1] and RTMR[2].

There is no CI check for that yet. The node image's check builds twice and
compares measurements; this image needs the same, on a second builder, before
its manifest is worth pinning in production.

`bin/setup` in confos installs host packages from a pinned snapshot and allows
downgrades. Build in a throwaway VM or container: on a host you care about it
can move systemd and QEMU backwards.
