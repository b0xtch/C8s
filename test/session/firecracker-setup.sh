#!/usr/bin/env bash
# firecracker-setup.sh <directory>
#
# Fetch the newest release of stock Firecracker and the guest kernel and root
# file system its own project publishes for its tests, into one directory,
# for the baseline of timing.sh. The release is held to the checksum
# published beside it, and versions.txt records what was fetched. Nothing is
# installed: remove the directory and it is gone.
set -euo pipefail
dir=${1:?directory}
mkdir -p "$dir"
cd "$dir"
ARCH=x86_64
release_url=https://github.com/firecracker-microvm/firecracker/releases
latest=$(basename "$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$release_url/latest")")
curl -fsSL "$release_url/download/$latest/firecracker-$latest-$ARCH.tgz" -o "firecracker-$latest-$ARCH.tgz"
curl -fsSL "$release_url/download/$latest/firecracker-$latest-$ARCH.tgz.sha256.txt" -o "firecracker-$latest-$ARCH.tgz.sha256.txt"
sha256sum -c "firecracker-$latest-$ARCH.tgz.sha256.txt"
tar -xzf "firecracker-$latest-$ARCH.tgz"
cp "release-$latest-$ARCH/firecracker-$latest-$ARCH" firecracker
chmod +x firecracker
rm -rf "release-$latest-$ARCH"

S3=https://s3.amazonaws.com/spec.ccfc.min
prefix=$(curl -fsSL "$S3?list-type=2&prefix=firecracker-ci/&delimiter=/" \
    | grep -oP "(?<=<Prefix>)firecracker-ci/[0-9]{8}-[^/]+/(?=</Prefix>)" | sort | tail -1)
kernel_key=$(curl -fsSL "$S3?list-type=2&prefix=${prefix}${ARCH}/vmlinux-" \
    | grep -oP "(?<=<Key>)(${prefix}${ARCH}/vmlinux-[0-9]+\.[0-9]+\.[0-9]{1,3})(?=</Key>)" | sort -V | tail -1)
rootfs_key=$(curl -fsSL "$S3?list-type=2&prefix=${prefix}${ARCH}/ubuntu-" \
    | grep -oP "(?<=<Key>)(${prefix}${ARCH}/ubuntu-[0-9]+\.[0-9]+\.squashfs)(?=</Key>)" | sort -V | tail -1)
curl -fsSL "$S3/$kernel_key" -o vmlinux
curl -fsSL "$S3/$rootfs_key" -o rootfs.squashfs
{
    echo "firecracker $latest sha256 $(sha256sum "firecracker-$latest-$ARCH.tgz" | cut -c1-64)"
    echo "kernel $kernel_key sha256 $(sha256sum vmlinux | cut -c1-64)"
    echo "rootfs $rootfs_key sha256 $(sha256sum rootfs.squashfs | cut -c1-64)"
    ./firecracker --version | head -1
} | tee versions.txt
du -sh -- *
