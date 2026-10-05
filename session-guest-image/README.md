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

The output directory holds `disk.raw`, the firmware (`OVMF.tdx.fd` on TDX,
built from source by `firmware/build`; one IGVM file per vCPU count on
SEV-SNP) and `manifest.json`. The manifest carries
the reference values a verifier pins: MRTD, RTMR[1] and RTMR[2] on TDX.

Beside the manifest the build publishes the image's two schemas, each printed
by the program it staged (`c8s-session-guest schema`):

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
| `c8s-session-init` | the initramfs's `/init`, compiled from this checkout by `build` (`cmd/c8s-session-init`) | It is the guest's first and only init: it opens the verity root the command line names, makes the encrypted state volume, binds the launch key, and starts what `init.json` lists |
| `c8s-session-guest` | `/usr/local/bin/c8s-session-guest`, compiled from this checkout by `build` (`cmd/c8s-session-guest`) | It is the agent: it verifies the launch document, takes the one bind, extends RTMR[3] and serves the attested API. It holds the agent, the key service and the schema command, and nothing else of c8s. `build` compiles it with `GOEXPERIMENT=runtimesecret`: the agent erases the one-time keys it makes for its bind before anything of a tenant runs, and that mode of Go's runtime is what erases what signing and decrypting with them left on a stack or the heap. An agent built without it runs no guest |
| `c8s-sandbox-init` | `/usr/local/bin/c8s-sandbox-init`, compiled from this checkout by `build` (`cmd/c8s-sandbox-init`) | It is the first process of a sandbox's container until the session's bind names the sandbox's process, and then becomes that process. The agent makes the container around it before any bind, so a bind only has a process to start |
| `/etc/c8s-session/init.json` | verity root, written by `mkosi.sync` | Everything that runs in the guest: two steps and one service, by path, with their arguments. The agent's flags are its configuration, so they are part of the image identity |
| `/etc/c8s-session/firewall.nft` | verity root | The inbound filter: only the agent's port may be reached from outside the guest |
| `/etc/c8s-session/disclosure-schema.json`, `bind-schema.json` | verity root, written by `build` | What the agent says in plaintext and what it takes in a bind. The agent checks both against its own definitions before it serves |
| `/etc/sysctl.d/50-c8s-session.conf` | verity root | No tunnel device in a new network namespace. The limit on user namespaces is the agent's to set: it makes the sandbox's and then has the kernel make no other |
| `crun`, `nft`, `mke2fs` | distribution packages | crun runs the sandbox image a bind names, driven by the agent alone; nft loads the filter; mke2fs makes the state volume's file system, each boot |
| `sandbox` user (2000:2000) and its home | `/etc/passwd` and `/home/sandbox`, written at build time | A session's commands run as this user in a dev image, when a bind names no sandbox image |
| `kernel/session.config` | merged into the guest kernel | Adds vsock, which the agent uses to reach the host's quoting service, its key service and Intel's documents, user namespaces for the sandbox's container, nftables for the filter, and transparent huge pages on request. Removes every console but the one that discards, and every driver for a device a session guest is not given |

The builder contributes the kernel, the layout of the dm-verity root and the
distribution's packages. The initramfs is this repository's: `build` packs
the init into it alone and passes it with `--initrd`. This profile adds no
attestation daemon, and nothing in it takes orders from the host.

`mkosi.finalize` strips every setuid and setgid bit and fails the build if one
survives, and fails it if a program the init runs, a file the agent checks or
the sandbox user is missing.

## What runs in the guest

The kernel starts `c8s-session-init`, and nothing else is ever started that
`init.json` does not name. There is no service manager, no shell initrd, no
network daemon, no DHCP client, no resolver and no login program.

| Order | What | By |
|---|---|---|
| 1 | The root: dm-verity over the root partition, under the hash on the measured command line, read-only. A block that fails its hash stops the guest | init |
| 2 | The state volume: dm-crypt over the scratch disk under a key made this boot and kept nowhere, a fresh file system, and a writable layer over each directory listed in `/usr/lib/confai/state.d`. Without a scratch disk, a tmpfs | init |
| 3 | The launch key: read from the `opkeydata` volume, staged read-only, and its digest extended into RTMR[3] (TDX) or checked against HOST_DATA (SEV-SNP). A guest with a key it cannot bind stops | init |
| 4 | The kernel's file systems, the settings in `sysctl.d`, the loopback interface, a control group for the service | init |
| 5 | `c8s-session-guest session-agent load`: a check of the guest's devices, then the launch files off the volume and the host's network request set on the one interface. The key service's image has no interface, and its step sets none | step |
| 6 | `nft -f /etc/c8s-session/firewall.nft` | step |
| 7 | The agent, or the key service in its image | service |

The init sets `no_new_privs` before the first step, which the sandbox and
every command run for a session inherit. It reaps what is orphaned, and it
powers the guest off when a step fails or the service ends: a guest whose
agent is gone can be neither verified nor controlled.

## The machine

A session guest's launcher builds it a network device, block devices and a
socket to the host, all virtio of the current kind, on a board with no disk
controller, no keyboard controller, no USB and no timer but the CPU's own.
The kernel has drivers for those devices and for no other: no network card,
no SCSI or ATA, no input, no sensor, and no code that takes a device plugged
in later.

A key service replica's launcher builds it the same machine without the
network device. A replica serves on a port of its socket to the host, which
its launcher publishes on a port of the host, and it asks Intel's service
over connections its launcher carries. Each of those is a TLS session that
ends in the replica or at Intel, so the launcher reads none of it.

Before the guest reads a file its host handed it, the load step
lists the functions on its PCI bus and ends the guest if one is of another
kind: in the key service's image, a network device is one. The agent does
the same before it serves, and so does a replica. A TD's RTMR[0] records the
shape its host declared, which the launch document lists and the agent
checks, and a TD whose document lists no machine takes no bind
([session-daemon.md](../docs/session-daemon.md#the-pools-machine)).

## Boot path

The firmware starts the kernel image, and the kernel starts the image. There
is no boot loader between them.

| Step | What it is | Where it is measured |
|---|---|---|
| Firmware | TDVF, built by `firmware/build` from edk2 at a pinned commit: a release build without the UEFI shell | MRTD |
| Kernel image | the UKI, installed as the boot partition's fallback application (`Bootloader=uki`) | RTMR[1], and its kernel, initrd and command line in RTMR[2] |
| Kernel | the builder's hardened kernel with `kernel/session.config` and the patches in `kernel/patches/` | part of the UKI |
| Init | `c8s-session-init`, the one file of the initramfs | part of the UKI |
| Root | the verity root, under the hash on the command line | part of the UKI's command line |

A boot loader would be one more measured program, would read a configuration
file that nothing measures, and waits for a key nobody can press.

The kernel carries three source patches, applied in name order by the
builder's `--kernel-patch`. Each is named by hash in the manifest
(`kernel_patches_sha256`).

| Patch | What it changes |
|---|---|
| `0001` | A confidential guest accepts its memory as it uses it. Before its watermarks are set, the kernel accepted a block for every page allocation, and so a guest held memory it had never touched. It now accepts only what an allocation needs. |
| `0002` | `vm.accept_memory_mb`: the agent can accept memory ahead of a sandbox at a time of its choosing, where otherwise the first task to touch it pays. |
| `0003` | Memory the firmware already accepted is used, in every zone, before more is accepted. |

The bounce buffer that every virtio transfer goes through starts at 32 MiB
and grows on demand (`CONFIG_SWIOTLB_DYNAMIC`, `swiotlb=16384`). The kernel's
own choice for a confidential guest is 6% of memory up to 1 GiB, turned from
private to shared one page at a time during boot.

## Knobs

| Variable | Meaning |
|---|---|
| `C8S_PLATFORM` | Required: `tdx` or `snp`. The agent refuses to stage on the other TEE. |
| `C8S_DEV=1` | Debug image: a console that the kernel, the init and the agent log to, a bind accepted with no sandbox image, and a sandbox image accepted from a plain-HTTP registry at `10.0.2.2:5000` for tests. A different measurement and host-readable logs. Never ship. |
| `C8S_ROLE=key-service` | Build the [key service](../docs/session-key-service.md)'s image: this image with `c8s-session-guest session-key-service run` as its measured service where the agent is, and a load step that takes no network device. It has reference values of its own. |
| `C8S_NAME` | Output name (default `c8s-session` or `c8s-key-service`, with `-dev` for a dev build) |
| `C8S_MEMORY` | Default memory recorded in the manifest (default `1G`) |
| `C8S_BINARY` | Stage this prebuilt linux/amd64 `c8s-session-guest` and skip the compile |
| `C8S_INIT_BINARY` | Pack this prebuilt static linux/amd64 init and skip its compile |
| `C8S_SANDBOX_INIT_BINARY` | Stage this prebuilt static linux/amd64 `c8s-sandbox-init` and skip its compile |
| `CONFOS_DIR` | confos checkout to build with (default: a sibling of this repository) |
| `C8S_TDX_FIRMWARE` | Boot this TDX firmware file. Unset, `firmware/build` builds it from source into `build/session-firmware/` |

## Status

The build needs three things of the builder that its main branch does not
have yet: `--kernel-patch`, `--initrd`, and a prediction of RTMR[1] for a
boot partition whose fallback application is the UKI. `build` stops if one of
the first two is missing. With the third missing the manifest's RTMR[1] is
wrong, and the agent refuses its launch document on the first boot.

The init's SEV-SNP path, which checks the launch key against HOST_DATA, is
covered by unit tests and has not run on hardware.

The firmware is built with the build machine's own compiler, outside the
builder's pinned tools. Two machines agree on MRTD only if they agree on the
toolchain, and no check compares two builds yet.

No reproducibility check runs for this image yet. The node image's check
builds twice and compares measurements; this image needs the same, on a second
builder, before its manifest is worth pinning in production.

The key service's image is this profile with another service on its verity
root, so it also carries crun and the sandbox user, which a key service has
no use for. A profile of its own comes with the key service's replication.

## No console

A locked build's kernel has no serial driver, no virtual terminal, no virtio
console, no boot console and no network console, and reads no console from
the host's ACPI tables. Its one console is the kernel's null device, which
discards. The agent reads the kernel's list of consoles before it serves and
ends a guest that has any other. Nobody logs in: the image starts no login
program. What the init and the agent log goes to that null device, so a
locked guest keeps no log.

What a guest says before its kernel runs is outside this: the firmware and
the boot stub can write to a serial port a host attaches. They run before the
guest has a launch document, a key or a session, so nothing of a session is
theirs to say. The firmware is a release build, which prints none of the
step-by-step log a debug build writes to its debug port.

Of [session-disclosure.md](../docs/session-disclosure.md), three things are
not built: a reason code that a guest leaves when it ends, the owner's way to
read a session's logs, and a schema for what the key service answers. A
guest that ends is known to its host as ended and no more.

`bin/setup` in confos installs host packages from a pinned snapshot and allows
downgrades. Build in a throwaway VM or container: on a host you care about it
can move systemd and QEMU backwards.
