#!/usr/bin/env python3
"""One sample of the Firecracker baseline of test/session/timing.sh, run as root.

  firecracker_sample.py <dir> cold              boot to a guest that takes a command
  firecracker_sample.py <dir> snapshot [bytes [command...]]
                                                boot, log in, and snapshot the paused guest
  firecracker_sample.py <dir> load              snapshot load to the first command
  firecracker_sample.py <dir> load-vsock        the same, with the command sent to an agent in the guest
  firecracker_sample.py <dir> lean [bytes [command...]]
                                                make the leanest guest's root file system
  firecracker_sample.py <dir> lean-cold         boot that guest to its first command
  firecracker_sample.py <dir> lean-pool [seconds]
                                                boot it, leave it idle, and start a session in it
  firecracker_sample.py <dir> lean-snapshot     boot it and snapshot it, paused
  firecracker_sample.py <dir> lean-load         load that snapshot and start a session in it

<dir> is a directory written by firecracker-setup.sh. Prints one JSON record.
Times are from the start of the VMM's process, in milliseconds and, for the
first command, in microseconds too.
Each VMM is started with a core-scheduling cookie of its own, where the
host's kernel has them, as a session's launcher starts a guest's VMM.

cold and load drive the guest over its serial console, which is the VMM's
own standard input and output: no network, no key, no login service beyond
the console's. That is a floor for Firecracker: any channel a platform puts
on top costs more.

load-vsock reaches the first command the way a session's is reached: over a
connection to an agent in the guest, which runs it and answers. When the
snapshot is taken it needs <dir>/fcagent, the program of test/session/fcagent
built for the guest, and <dir>/busybox, the static busybox the session's
sandbox image was made from. The guest is given both on a second, read-only
drive, a squashfs it mounts. It reads the shell into its memory, as a pooled
session guest has its sandbox image unpacked before a bind, and starts the
agent before it is paused.

The first command is then the work a session's is. With bytes, it is the
session's own words: that shell reading a file of that many bytes, which the
guest has not read before, from the read-only drive, as a session's first
command reads its credential back. With none it is true, as a session's is
that has no credential. Later commands are that shell's true, as a
session's are. The agent authenticates nobody and encrypts nothing, so this
is still less than a platform would run.

With <dir>/image, the tree of a sandbox image as test/session/imageroot
unpacks it, the drive is that tree in place of the one shell, and the agent
runs inside it, as a session's commands run inside their sandbox: a command
named after bytes is then the first command, found as the image finds it.
<dir>/image.env, if it is there, is the image's environment, a variable a
line.

The lean guest is the least Firecracker boots that takes a session's first
command: the kernel, and the agent as its init on a root file system that is
the sandbox image's tree, or the session's shell alone, with no other user
space, no console and the boot arguments of Firecracker's own boot time
test. lean-cold is its cold boot: from the VMM's start to the answer of a
first command. lean-pool is a start from a pool of such guests booted ahead,
as a platform with confidentiality off can keep them: the guest has booted,
read its file system whole, run one command and sat idle for seconds, a
connection to its agent is made,
and the start is one message on it, with the credential and the first
command, to that command's answer. The agent writes the credential where a
session's goes, in memory, and the command reads it back. The guest is the
sandbox there: nothing is started inside it for the session. lean-snapshot
and lean-load are a snapshot's load at its strongest: the lean guest, with
its file system read whole and one command run, paused and snapshotted, and
a start that loads it into a new VMM and sends the same message on a
connection made then.

  ready_ms       a shell is at the console (cold) or the load returned
  agent_up_us    lean guests: the agent took a connection
  start_us       lean-pool: the message's send to the first command's answer
  first_cmd_ms   a command has given its answer
  first_cmd_us   the same in microseconds
  next_cmd_us    load-vsock: what one more command took, over a connection of
                 its own to the guest that now runs
"""
import base64
import ctypes
import errno
import hashlib
import http.client
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

# The session class's size. A trial of test/session/burst.sh may give the
# guest other vCPUs.
VCPUS, MEM_MIB = int(os.environ.get("C8S_FIRECRACKER_VCPUS", "4")), 16384
# The port the guest's agent listens on, and the guest's address on vsock.
AGENT_PORT, GUEST_CID = 5000, 3
BOOT_ARGS = "console=ttyS0 reboot=k panic=1 quiet"
# The arguments of Firecracker's own boot time test, which has no console,
# with the agent as init. C8S_FC_LEAN_CONSOLE=1 keeps the console, to read a
# guest that does not come up.
LEAN_ARGS = "reboot=k panic=1 pci=off nomodule 8250.nr_uarts=0 i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd swiotlb=noforce"
LEAN_CONSOLE_ARGS = "console=ttyS0 reboot=k panic=1 pci=off nomodule i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd swiotlb=noforce"
# Where the guest mounts the agent's drive, in memory since its root is
# read-only, and a session's own first command: test/session/warmstart sends
# these words.
DRIVE, CREDENTIAL = "/run/drive", "api-token"
# Where the agent and the credential are in a sandbox image's tree.
HOME = ".c8s"
READ_BACK = ["sh", "-c", 'cat "$C8S_CREDENTIALS_DIR/' + CREDENTIAL + '"']
PROMPT = re.compile(rb"[#$] $")
LOGIN = re.compile(rb"login: |[#$] $")
PASSWORD = re.compile(rb"[Pp]assword: |[#$] $")


# The C library, loaded before any VMM is started: apart calls into it in a
# child that has only just been forked.
try:
    LIBC = ctypes.CDLL(None, use_errno=True)
    LIBC.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
except (OSError, AttributeError):
    LIBC = None


def apart():
    """Give the VMM that is about to start a core-scheduling cookie of its
    own, as a session's launcher gives a guest's VMM: a core's two threads
    then never run it and another guest at the same time. It runs in the
    forked child, before its exec, and every thread the VMM makes takes the
    cookie from it. A host whose cores have one thread each has nothing to
    keep apart, and one with two and no core scheduling starts no VMM."""
    if LIBC is None:
        return
    # PR_SCHED_CORE with PR_SCHED_CORE_CREATE, for the calling thread.
    if LIBC.prctl(62, 1, 0, 0, 0) == 0 or ctypes.get_errno() == errno.ENODEV:
        return
    reason = os.strerror(ctypes.get_errno())
    try:
        with open("/sys/devices/system/cpu/smt/active") as f:
            two = f.read().strip() == "1"
    except OSError:
        two = False
    if two:
        raise OSError(f"this host's cores run two threads each, and its kernel gives a VMM no core-scheduling cookie: {reason}")


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


def connected(d, patience=5.0):
    """A connection the guest's agent has taken: the socket, its lines, and how many tries it took.

    The VMM listens on a Unix socket and takes the guest's port on a first
    line. A guest that was just started or resumed may not take a connection
    at once: one that is refused is made again.
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
                return s, lines, attempts
        except OSError:
            pass
        s.close()
        if time.monotonic() > deadline:
            raise SystemExit("the guest's agent took no connection")
        time.sleep(0.0002)


def ask_on(s, lines, argv, credentials=None, read=None):
    """Send one request on a connection the agent has taken, and return its answer.

    With read, the agent first reads every file of that directory's file
    system.
    """
    request = {"argv": argv}
    if read:
        request["read"] = read
    if credentials:
        request["credentials"] = {name: base64.b64encode(value).decode() for name, value in credentials.items()}
    try:
        s.sendall(json.dumps(request).encode() + b"\n")
        answer = json.loads(lines.readline() or b"null")
    except (OSError, ValueError) as e:
        raise SystemExit(f"the guest's agent gave no answer: {e}")
    finally:
        s.close()
    if answer and not answer.get("error") and answer.get("exit_code") == 0:
        return answer
    raise SystemExit(f"the guest's agent answered {answer!r}")


def over_vsock(d, argv, record=None, since=0, patience=5.0, credentials=None, read=None):
    """Send one command to the guest's agent, on a connection of its own, and return its answer.

    With a record, how many connections it took and when the guest's agent
    had accepted the one that served go into it.
    """
    s, lines, attempts = connected(d, patience)
    if record is not None:
        record["vsock_connections"], record["vsock_connected_us"] = attempts, us(since)
    return ask_on(s, lines, argv, credentials, read)


def agent_drive(d, size):
    """Write <d>/agent.img and return the file a first command reads back.

    The drive holds the agent, a file of size bytes when a session has a
    credential, and what commands run from: the tree of a sandbox image when
    <d>/image holds one, and otherwise the session's shell under the names a
    command finds it by. Nothing in it is compressed: a read costs a read.
    """
    if not shutil.which("mksquashfs"):
        raise SystemExit("mksquashfs (squashfs-tools) makes the drive of the guest's agent")
    # Text, as a session's credential is.
    secret = os.urandom((size + 1) // 2).hex()[:size].encode() if size else b""
    stage = tempfile.mkdtemp(dir=d)
    try:
        source, beside = stage, []
        if os.path.isdir(f"{d}/image"):
            # The image's tree as it is, with the agent and the credential
            # under a name of their own.
            source = f"{d}/image"
            beside = ["-p", f"{HOME} d 755 0 0", "-p", f"{HOME}/fcagent f 755 0 0 cat {shlex.quote(d + '/fcagent')}"]
            if size:
                with open(f"{stage}/secret", "wb") as f:
                    f.write(secret)
                beside += ["-p", f"{HOME}/credentials d 755 0 0",
                           "-p", f"{HOME}/credentials/{CREDENTIAL} f 444 0 0 cat {shlex.quote(stage + '/secret')}"]
        else:
            os.mkdir(f"{stage}/bin")
            for program, name in (("fcagent", "fcagent"), ("busybox", "bin/busybox")):
                shutil.copyfile(f"{d}/{program}", f"{stage}/{name}")
                os.chmod(f"{stage}/{name}", 0o755)
            for applet in ("sh", "cat", "true"):
                os.symlink("busybox", f"{stage}/bin/{applet}")
            if size:
                os.mkdir(f"{stage}/credentials")
                with open(f"{stage}/credentials/{CREDENTIAL}", "wb") as f:
                    f.write(secret)
            os.chmod(stage, 0o755)
        image = f"{d}/agent.img"
        if os.path.exists(image):
            os.unlink(image)
        subprocess.run(["mksquashfs", source, image, "-noappend", "-all-root", "-no-xattrs", "-noI", "-noD", "-noF", "-noX", "-no-progress"] + beside,
                       check=True, stdout=subprocess.DEVNULL)
    finally:
        shutil.rmtree(stage)
    return secret


def lean_drive(d):
    """Write <d>/lean.img, the root file system of the leanest guest.

    It is the tree of a sandbox image when <d>/image holds one, and otherwise
    the session's shell under the names a command finds it by, with the agent
    as init, its environment beside it, an empty directory for credentials,
    and the directories the agent mounts the kernel's file systems on.
    """
    if not shutil.which("mksquashfs"):
        raise SystemExit("mksquashfs (squashfs-tools) makes the lean guest's root file system")
    stage = tempfile.mkdtemp(dir=d)
    try:
        env = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
        source = f"{d}/image"
        if os.path.isdir(source):
            if os.path.exists(f"{d}/image.env"):
                with open(f"{d}/image.env") as f:
                    env = [line.rstrip("\n") for line in f if "=" in line]
        else:
            source = f"{stage}/root"
            os.makedirs(f"{source}/bin")
            shutil.copyfile(f"{d}/busybox", f"{source}/bin/busybox")
            os.chmod(f"{source}/bin/busybox", 0o755)
            for applet in ("sh", "cat", "true"):
                os.symlink("busybox", f"{source}/bin/{applet}")
            os.chmod(source, 0o755)
            env = ["PATH=/bin"]
        env.append(f"C8S_CREDENTIALS_DIR=/{HOME}/credentials")
        with open(f"{stage}/env", "w") as f:
            f.write("\n".join(env) + "\n")
        beside = ["-p", f"{HOME} d 755 0 0", "-p", f"{HOME}/fcagent f 755 0 0 cat {shlex.quote(d + '/fcagent')}",
                  "-p", f"{HOME}/env f 644 0 0 cat {shlex.quote(stage + '/env')}", "-p", f"{HOME}/credentials d 700 0 0"]
        for mount in ("proc", "sys", "dev", "tmp", "run"):
            if not os.path.lexists(f"{source}/{mount}"):
                beside += ["-p", f"{mount} d 755 0 0"]
        image = f"{d}/lean.img"
        if os.path.exists(image):
            os.unlink(image)
        subprocess.run(["mksquashfs", source, image, "-noappend", "-all-root", "-no-xattrs", "-noI", "-noD", "-noF", "-noX", "-no-progress"] + beside,
                       check=True, stdout=subprocess.DEVNULL)
    finally:
        shutil.rmtree(stage)


def lean_machine(d):
    """Write <d>/lean-vm.json, the lean guest as a VMM is told of it, and return its boot arguments.

    The vsock socket is named under the VMM's own directory, so that many
    VMMs boot from the one file, each in a directory of its own.
    """
    console = os.environ.get("C8S_FC_LEAN_CONSOLE") == "1"
    args = (LEAN_CONSOLE_ARGS if console else LEAN_ARGS) + f" init=/{HOME}/fcagent"
    with open(f"{d}/lean-vm.json", "w") as f:
        json.dump({
            "boot-source": {"kernel_image_path": f"{d}/vmlinux", "boot_args": args},
            "drives": [{"drive_id": "rootfs", "path_on_host": f"{d}/lean.img", "is_root_device": True, "is_read_only": True}],
            "machine-config": {"vcpu_count": VCPUS, "mem_size_mib": MEM_MIB},
            "vsock": {"guest_cid": GUEST_CID, "uds_path": "v.sock"},
        }, f)
    return args


def lean_boot(d, pipes):
    """Start a VMM that boots the lean guest, and return it with when it was started."""
    since = time.monotonic_ns()
    return subprocess.Popen([f"{d}/firecracker", "--no-api", "--config-file", f"{d}/lean-vm.json"], cwd=d, **pipes), since


def lean_first(d):
    """The lean guest's first command, a credential of the size it reads back, and what it must write."""
    with open(f"{d}/lean.json") as f:
        first = json.load(f)
    size = first["credential_bytes"]
    # Text, as a session's credential is, and made for this start.
    secret = os.urandom((size + 1) // 2).hex()[:size].encode() if size else b""
    return first, ({CREDENTIAL: secret} if size else None), secret


def lean_answer(first, secret, answer, record):
    if first["reads_back"]:
        if base64.b64decode(answer.get("stdout") or "") != secret:
            raise SystemExit("the first command did not read back the credential its start brought")
    else:
        record["first_output"] = base64.b64decode(answer.get("stdout") or "")[:64].decode(errors="replace").strip()


def agent_start(d):
    """The line that mounts the agent's drive in the guest and starts the agent."""
    # The drive is read once, whole, before the snapshot.
    mount = f"mount -o remount,exec /dev/shm; mkdir -p {DRIVE} && mount -o ro /dev/vdb {DRIVE}"
    if not os.path.isdir(f"{d}/image"):
        # The agent runs from memory, the one place in this guest a program
        # can be written to, and finds the session's shell before the
        # guest's own.
        return (f"{mount} && cat {DRIVE}/bin/busybox > /dev/null && cp {DRIVE}/fcagent /dev/shm/fcagent"
                f" && (PATH={DRIVE}/bin:$PATH C8S_CREDENTIALS_DIR={DRIVE}/credentials /dev/shm/fcagent {AGENT_PORT} < /dev/null > /dev/null 2>&1 &)")
    # The agent runs inside the image's tree, under the image's environment
    # and no other, with the guest's own /proc, /dev and /sys in it.
    env = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
    if os.path.exists(f"{d}/image.env"):
        with open(f"{d}/image.env") as f:
            env = [line.rstrip("\n") for line in f if "=" in line]
    env.append(f"C8S_CREDENTIALS_DIR=/{HOME}/credentials")
    return (f"{mount} && (mount -t proc proc {DRIVE}/proc; mount --rbind /dev {DRIVE}/dev; mount --rbind /sys {DRIVE}/sys;"
            f" find {DRIVE} -xdev -type f -exec cat {{}} + > /dev/null 2>&1;"
            f" env -i {' '.join(shlex.quote(v) for v in env)} chroot {DRIVE} /{HOME}/fcagent {AGENT_PORT} < /dev/null > /dev/null 2>&1 &)")


def stop(p):
    p.terminate()
    try:
        p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def main():
    d, kind = os.path.abspath(sys.argv[1]), sys.argv[2]
    size = int(sys.argv[3]) if len(sys.argv) > 3 and kind in ("snapshot", "lean") else 0
    named = sys.argv[4:]
    sock = f"{d}/fc.sock"
    if os.path.exists(sock):
        os.unlink(sock)
    log = open(f"{d}/console.log", "ab")
    record = {"kind": "fc-" + kind, "vcpus": VCPUS, "mem_mib": MEM_MIB}
    pipes = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=apart)
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
            if not os.path.exists(f"{d}/busybox") and not os.path.isdir(f"{d}/image"):
                raise SystemExit(f"{d} holds neither busybox, the static busybox the session's sandbox image was made from, nor image, that image's tree")
            secret = agent_drive(d, size)
            machine["drives"].append({"drive_id": "agent", "path_on_host": f"{d}/agent.img", "is_root_device": False, "is_read_only": True})
            # By a name under the VMM's own directory: a VMM that loads the
            # snapshot elsewhere has a socket of its own there.
            machine["vsock"] = {"guest_cid": GUEST_CID, "uds_path": "v.sock"}
        with open(cfg, "w") as f:
            json.dump(machine, f)
        args = [f"{d}/firecracker", "--config-file", cfg] + (["--no-api"] if kind == "cold" else ["--api-sock", sock])
        since = time.monotonic_ns()
        p = subprocess.Popen(args, cwd=d, **pipes)
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
                console.type(agent_start(d) + "; sleep 0.5; echo agent-$((1+1))\n")
                console.wait(re.compile(rb"agent-2\b"), timeout=300)
                over_vsock(d, ["true"])
                # A command that was named says what it will; the others read
                # the credential back, or nothing.
                first = {"argv": named or (READ_BACK if size else ["true"]), "stdout": None if named else base64.b64encode(secret).decode()}
                with open(f"{d}/first.json", "w") as f:
                    json.dump(first, f)
                record["agent"], record["first_command"], record["credential_bytes"] = True, first["argv"], size
                if os.path.isdir(f"{d}/image"):
                    record["image"] = True
                else:
                    with open(f"{d}/busybox", "rb") as f:
                        record["shell_sha256"] = hashlib.sha256(f.read()).hexdigest()
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
        p = subprocess.Popen([f"{d}/firecracker", "--api-sock", sock], cwd=d, **pipes)
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
                with open(f"{d}/first.json") as f:
                    first = json.load(f)
                answer = over_vsock(d, first["argv"], record, since)
                if first["stdout"] is None:
                    record["first_output"] = base64.b64decode(answer.get("stdout") or "")[:64].decode(errors="replace").strip()
                elif (answer.get("stdout") or "") != first["stdout"]:
                    raise SystemExit("the first command did not read back the file its snapshot's drive holds")
            else:
                command(console, 54)
            record["first_cmd_ms"], record["first_cmd_us"] = ms(since), us(since)
            if kind == "load-vsock":
                again = time.monotonic_ns()
                over_vsock(d, ["true"])
                record["next_cmd_us"] = us(again)
        finally:
            stop(p)
    elif kind == "lean":
        for needed in ("fcagent",) + (() if os.path.isdir(f"{d}/image") else ("busybox",)):
            if not os.path.exists(f"{d}/{needed}"):
                raise SystemExit(f"{d} holds no {needed}")
        lean_drive(d)
        record["boot_args"] = lean_machine(d)
        # A command that was named says what it will; the others read the
        # credential back, or nothing.
        first = {"argv": named or (READ_BACK if size else ["true"]), "reads_back": bool(size) and not named, "credential_bytes": size}
        with open(f"{d}/lean.json", "w") as f:
            json.dump(first, f)
        record["first_command"], record["credential_bytes"], record["image"] = first["argv"], size, os.path.isdir(f"{d}/image")
        record["bytes"] = os.path.getsize(f"{d}/lean.img")
    elif kind in ("lean-cold", "lean-pool"):
        first, credentials, secret = lean_first(d)
        p, since = lean_boot(d, pipes)
        try:
            Console(p, log)
            if kind == "lean-cold":
                s, lines, record["vsock_connections"] = connected(d, 30.0)
                record["agent_up_us"] = us(since)
                lean_answer(first, secret, ask_on(s, lines, first["argv"], credentials), record)
                record["first_cmd_ms"], record["first_cmd_us"] = ms(since), us(since)
            else:
                # The guest as a pool keeps it: booted, its file system read
                # whole, as a pooled session guest has its image unpacked, a
                # command run in it, idle for a while, and a connection to
                # its agent made.
                over_vsock(d, ["true"], record, since, 30.0, read="/")
                record["agent_up_us"] = record.pop("vsock_connected_us")
                s, lines, _ = connected(d)
                record["idle_s"] = float(sys.argv[3]) if len(sys.argv) > 3 else 2.0
                time.sleep(record["idle_s"])
                began = time.monotonic_ns()
                answer = ask_on(s, lines, first["argv"], credentials)
                record["start_us"] = us(began)
                lean_answer(first, secret, answer, record)
                again = time.monotonic_ns()
                over_vsock(d, ["true"])
                record["next_cmd_us"] = us(again)
        finally:
            stop(p)
    elif kind == "lean-snapshot":
        lean_first(d)
        for old in ("lean.state", "lean.mem"):
            if os.path.exists(f"{d}/{old}"):
                os.unlink(f"{d}/{old}")
        since = time.monotonic_ns()
        p = subprocess.Popen([f"{d}/firecracker", "--api-sock", sock, "--config-file", f"{d}/lean-vm.json"], cwd=d, **pipes)
        try:
            Console(p, log)
            # As a pool keeps the guest: its file system read whole, and a
            # command run in it.
            over_vsock(d, ["true"], record, since, 30.0, read="/")
            record["agent_up_us"] = record.pop("vsock_connected_us")
            api(sock, "PATCH", "/vm", {"state": "Paused"})
            began = time.monotonic_ns()
            api(sock, "PUT", "/snapshot/create",
                {"snapshot_type": "Full", "snapshot_path": f"{d}/lean.state", "mem_file_path": f"{d}/lean.mem"})
            record["snapshot_create_ms"] = ms(began)
        finally:
            stop(p)
    elif kind == "lean-load":
        first, credentials, secret = lean_first(d)
        since = time.monotonic_ns()
        p = subprocess.Popen([f"{d}/firecracker", "--api-sock", sock], cwd=d, **pipes)
        try:
            Console(p, log)
            while not os.path.exists(sock):
                time.sleep(0.0005)
            record["api_up_ms"] = ms(since)
            api(sock, "PUT", "/snapshot/load", {
                "snapshot_path": f"{d}/lean.state",
                "mem_backend": {"backend_type": "File", "backend_path": f"{d}/lean.mem"},
                "resume_vm": True,
            })
            record["ready_ms"], record["ready_us"] = ms(since), us(since)
            s, lines, record["vsock_connections"] = connected(d)
            record["vsock_connected_us"] = us(since)
            lean_answer(first, secret, ask_on(s, lines, first["argv"], credentials), record)
            record["first_cmd_ms"], record["first_cmd_us"] = ms(since), us(since)
            again = time.monotonic_ns()
            over_vsock(d, ["true"])
            record["next_cmd_us"] = us(again)
        finally:
            stop(p)
    else:
        raise SystemExit("cold, snapshot, load, load-vsock, lean, lean-cold, lean-pool, lean-snapshot or lean-load")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
