#!/usr/bin/env python3
"""One sample of the Firecracker baseline of test/session/timing.sh, run as root.

  firecracker_sample.py <dir> cold        boot to a guest that takes a command
  firecracker_sample.py <dir> snapshot    boot, log in, and snapshot the paused guest
  firecracker_sample.py <dir> load        snapshot load to the first command
  firecracker_sample.py <dir> load-vsock  the same, with the command sent to an agent in the guest

<dir> is a directory written by firecracker-setup.sh. Prints one JSON record.
Times are from the start of the VMM's process, in milliseconds and, for the
first command, in microseconds too.

cold and load drive the guest over its serial console, which is the VMM's
own standard input and output: no network, no key, no login service beyond
the console's. That is a floor for Firecracker: any channel a platform puts
on top costs more.

load-vsock reaches the first command the way a session's is reached: over a
connection to an agent in the guest, which runs it and answers. It needs
<dir>/fcagent, the program of test/session/fcagent built for the guest, when
the snapshot is taken: the guest is given it on a second, read-only drive
and starts it before it is paused. The agent authenticates nobody and
encrypts nothing, so this is still less than a platform would run.

  ready_ms       a shell is at the console (cold) or the load returned
  first_cmd_ms   a command has given its answer
  first_cmd_us   the same in microseconds
  next_cmd_us    load-vsock: what one more command took, over a connection of
                 its own to the guest that now runs
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
# The port the guest's agent listens on, and the guest's address on vsock.
AGENT_PORT, GUEST_CID = 5000, 3
BOOT_ARGS = "console=ttyS0 reboot=k panic=1 quiet"
PROMPT = re.compile(rb"[#$] $")
LOGIN = re.compile(rb"login: |[#$] $")
PASSWORD = re.compile(rb"[Pp]assword: |[#$] $")


def ms(since):
    return (time.monotonic_ns() - since) // 1_000_000


def us(since):
    return (time.monotonic_ns() - since) // 1_000


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


def over_vsock(d, argv, record=None, since=0, patience=5.0):
    """Send one command to the guest's agent and return its answer.

    The VMM listens on a Unix socket and takes the guest's port on a first
    line. A guest that was just resumed may not take a connection at once:
    one that is refused is made again. With a record, how many connections
    it took and when the guest's agent had accepted the one that served go
    into it.
    """
    deadline = time.monotonic() + patience
    attempts = 0
    while True:
        attempts += 1
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(patience)
        try:
            s.connect(f"{d}/v.sock")
            s.sendall(f"CONNECT {AGENT_PORT}\n".encode())
            lines = s.makefile("rb")
            if lines.readline().startswith(b"OK "):
                if record is not None:
                    record["vsock_connections"], record["vsock_connected_us"] = attempts, us(since)
                s.sendall(json.dumps({"argv": argv}).encode() + b"\n")
                answer = json.loads(lines.readline() or b"null")
                if answer and not answer.get("error") and answer.get("exit_code") == 0:
                    return answer
                raise SystemExit(f"the guest's agent answered {answer!r}")
        except (OSError, ValueError):
            pass
        finally:
            s.close()
        if time.monotonic() > deadline:
            raise SystemExit("the guest's agent took no connection")
        time.sleep(0.0002)


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
    for stale in ("v.sock",):
        if os.path.exists(f"{d}/{stale}"):
            os.unlink(f"{d}/{stale}")
    if kind in ("cold", "snapshot"):
        cfg = f"{d}/vm.json"
        machine = {
            "boot-source": {"kernel_image_path": f"{d}/vmlinux", "boot_args": BOOT_ARGS},
            # The published root file system, as the project's own tests boot it: read-only.
            "drives": [{"drive_id": "rootfs", "path_on_host": f"{d}/rootfs.squashfs", "is_root_device": True, "is_read_only": True}],
            "machine-config": {"vcpu_count": VCPUS, "mem_size_mib": MEM_MIB},
        }
        agent = kind == "snapshot" and os.path.exists(f"{d}/fcagent")
        if agent:
            # The agent's program, as a second drive that holds nothing else:
            # the guest copies it out by its size. A drive is whole sectors.
            program = open(f"{d}/fcagent", "rb").read()
            with open(f"{d}/agent.img", "wb") as f:
                f.write(program + b"\0" * (-len(program) % 512))
            machine["drives"].append({"drive_id": "agent", "path_on_host": f"{d}/agent.img", "is_root_device": False, "is_read_only": True})
            machine["vsock"] = {"guest_cid": GUEST_CID, "uds_path": f"{d}/v.sock"}
        with open(cfg, "w") as f:
            json.dump(machine, f)
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
            record["first_cmd_ms"], record["first_cmd_us"] = ms(since), us(since)
            if agent:
                # Memory is the one place in this guest a program can be
                # written to and run from.
                console.type(f"mount -o remount,exec /dev/shm; head -c {len(program)} /dev/vdb > /dev/shm/fcagent && chmod +x /dev/shm/fcagent"
                             f" && (/dev/shm/fcagent {AGENT_PORT} < /dev/null > /dev/null 2>&1 &); sleep 0.5; echo agent-$((1+1))\n")
                console.wait(re.compile(rb"agent-2\b"))
                over_vsock(d, ["true"])
                record["agent"] = True
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
    elif kind in ("load", "load-vsock"):
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
            record["ready_ms"], record["ready_us"] = ms(since), us(since)
            if kind == "load-vsock":
                over_vsock(d, ["true"], record, since)
            else:
                command(console, 54)
            record["first_cmd_ms"], record["first_cmd_us"] = ms(since), us(since)
            if kind == "load-vsock":
                again = time.monotonic_ns()
                over_vsock(d, ["true"])
                record["next_cmd_us"] = us(again)
        finally:
            stop(p)
    else:
        raise SystemExit("cold, snapshot, load or load-vsock")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
