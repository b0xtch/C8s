#!/usr/bin/env python3
"""One sample of the Firecracker baseline of test/session/timing.sh, run as root.

  firecracker_sample.py <dir> cold        boot to a guest that takes a command
  firecracker_sample.py <dir> snapshot    boot, log in, and snapshot the paused guest
  firecracker_sample.py <dir> load        snapshot load to the first command

<dir> is a directory written by firecracker-setup.sh. Prints one JSON record.
Times are milliseconds from the start of the VMM's process. The guest is
driven over its serial console, which is the VMM's own standard input and
output: no network, no key, no login service beyond the console's. That is a
floor for Firecracker: any authenticated channel a platform puts on top costs
more.

  ready_ms       a shell is at the console (cold) or the load returned
  first_cmd_ms   a command typed at the shell has printed its answer
"""
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

VCPUS, MEM_MIB = 4, 16384
BOOT_ARGS = "console=ttyS0 reboot=k panic=1 quiet"
PROMPT = re.compile(rb"[#$] $")
LOGIN = re.compile(rb"login: |[#$] $")
PASSWORD = re.compile(rb"[Pp]assword: |[#$] $")


def ms(since):
    return (time.monotonic_ns() - since) // 1_000_000


class Console:
    """The guest's serial console: what the VMM writes, and a way to type."""

    def __init__(self, process, log):
        self.process, self.log = process, log
        self.seen = b""
        self.changed = threading.Condition()
        threading.Thread(target=self.read, daemon=True).start()

    def read(self):
        while True:
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                return
            self.log.write(chunk)
            self.log.flush()
            with self.changed:
                self.seen += chunk
                self.changed.notify_all()

    def wait(self, pattern, timeout=120):
        """Wait until the console has shown pattern, and forget what came before it."""
        deadline = time.monotonic() + timeout
        with self.changed:
            while True:
                found = pattern.search(self.seen)
                if found:
                    self.seen = self.seen[found.end():]
                    return found
                left = deadline - time.monotonic()
                if left <= 0 or self.process.poll() is not None:
                    raise SystemExit(f"the console never showed {pattern.pattern!r}: {self.seen[-300:]!r}")
                self.changed.wait(min(left, 0.5))

    def pending(self, text):
        """Whether the console has shown text since the last wait."""
        with self.changed:
            return text in self.seen

    def type(self, text):
        os.write(self.process.stdin.fileno(), text.encode())


class Unix(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self.unix = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.unix)
        self.sock = s


def api(sock, method, url, body):
    c = Unix(sock)
    c.request(method, url, json.dumps(body), {"Content-Type": "application/json"})
    r = c.getresponse()
    data = r.read()
    c.close()
    if r.status not in (200, 204):
        raise SystemExit(f"{method} {url}: {r.status} {data!r}")


def command(console, n):
    """Type a command whose answer is not in what was typed, and wait for it."""
    console.type(f"echo fc-$(({n}+1))\n")
    console.wait(re.compile(f"fc-{n + 1}\\b".encode()))


def stop(p):
    p.terminate()
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def main():
    d, kind = os.path.abspath(sys.argv[1]), sys.argv[2]
    sock = f"{d}/fc.sock"
    if os.path.exists(sock):
        os.unlink(sock)
    log = open(f"{d}/console.log", "ab")
    record = {"kind": "fc-" + kind, "vcpus": VCPUS, "mem_mib": MEM_MIB}
    pipes = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if kind in ("cold", "snapshot"):
        cfg = f"{d}/vm.json"
        with open(cfg, "w") as f:
            json.dump({
                "boot-source": {"kernel_image_path": f"{d}/vmlinux", "boot_args": BOOT_ARGS},
                # The published root file system, as the project's own tests boot it: read-only.
                "drives": [{"drive_id": "rootfs", "path_on_host": f"{d}/rootfs.squashfs", "is_root_device": True, "is_read_only": True}],
                "machine-config": {"vcpu_count": VCPUS, "mem_size_mib": MEM_MIB},
            }, f)
        args = [f"{d}/firecracker", "--config-file", cfg] + (["--no-api"] if kind == "cold" else ["--api-sock", sock])
        since = time.monotonic_ns()
        p = subprocess.Popen(args, **pipes)
        try:
            console = Console(p, log)
            first = console.wait(LOGIN)
            if b"login" in first.group(0):
                # A console that logs in by itself says so on the same line,
                # at once. One that waits for a name says nothing more.
                automatic, deadline = False, time.monotonic() + 0.3
                while not automatic and time.monotonic() < deadline:
                    automatic = console.pending(b"automatic login")
                    time.sleep(0.002)
                if automatic:
                    console.wait(PROMPT)
                else:
                    console.type("root\n")
                    asked = console.wait(PASSWORD)
                    if b"assword" in asked.group(0):
                        console.type("root\n")
                        console.wait(PROMPT)
            record["ready_ms"] = ms(since)
            command(console, 41)
            record["first_cmd_ms"] = ms(since)
            if kind == "snapshot":
                for old in ("snap.state", "snap.mem"):
                    if os.path.exists(f"{d}/{old}"):
                        os.unlink(f"{d}/{old}")
                api(sock, "PATCH", "/vm", {"state": "Paused"})
                began = time.monotonic_ns()
                api(sock, "PUT", "/snapshot/create",
                    {"snapshot_type": "Full", "snapshot_path": f"{d}/snap.state", "mem_file_path": f"{d}/snap.mem"})
                record["snapshot_create_ms"] = ms(began)
        finally:
            stop(p)
    elif kind == "load":
        since = time.monotonic_ns()
        p = subprocess.Popen([f"{d}/firecracker", "--api-sock", sock], **pipes)
        try:
            console = Console(p, log)
            while not os.path.exists(sock):
                time.sleep(0.0005)
            record["api_up_ms"] = ms(since)
            api(sock, "PUT", "/snapshot/load", {
                "snapshot_path": f"{d}/snap.state",
                "mem_backend": {"backend_type": "File", "backend_path": f"{d}/snap.mem"},
                "resume_vm": True,
            })
            record["ready_ms"] = ms(since)
            command(console, 54)
            record["first_cmd_ms"] = ms(since)
        finally:
            stop(p)
    else:
        raise SystemExit("cold, snapshot or load")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
