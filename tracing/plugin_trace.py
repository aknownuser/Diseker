"""
Host-side parser for the QEMU TCG syscall plugin's output (syscall_trace.c).

The plugin writes lines like:

    CALL vcpu=0 num=11 a1=0x7ef00 a2=0x7ef40 a3=0x0 a4=0x0
    RET  vcpu=0 num=11 ret=0

This module turns that raw stream into a behavioral summary: syscall names and
frequencies, behavior categories (mirroring Rules/test-rules.rules), network and
anti-analysis activity, and process-creation events derived from fork/clone/
vfork return values.

Scope / honesty: the TCG callback does not carry the guest PID/ppid or argv, so
this produces a *flat* behavioral summary and a list of created child PIDs — not
the full per-process tree with command lines that in-guest auditd gives. Full
report parity needs guest introspection (see tracing/README.md). Numbers are
ARM-EABI; other arches currently fall back to sys_<n> names.
"""

import re


# Curated ARM-EABI syscall number -> name map, focused on the
# behavior/security-relevant calls. Unknown numbers fall back to "sys_<n>".
ARM_EABI_SYSCALLS = {
    1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 6: "close",
    8: "creat", 9: "link", 10: "unlink", 11: "execve", 12: "chdir",
    14: "mknod", 15: "chmod", 19: "lseek", 20: "getpid", 21: "mount",
    23: "setuid", 26: "ptrace", 37: "kill", 38: "rename", 39: "mkdir",
    40: "rmdir", 41: "dup", 42: "pipe", 45: "brk", 54: "ioctl", 55: "fcntl",
    63: "dup2", 74: "sethostname", 83: "symlink", 85: "readlink",
    93: "ftruncate", 94: "fchmod", 95: "fchown", 114: "wait4", 120: "clone",
    121: "setdomainname", 122: "uname", 125: "mprotect", 128: "init_module",
    129: "delete_module", 146: "writev", 162: "nanosleep", 168: "poll",
    172: "prctl", 174: "rt_sigaction", 183: "getcwd", 190: "vfork",
    192: "mmap2", 195: "stat64", 197: "fstat64", 199: "getuid32",
    213: "setuid32", 214: "setgid32", 217: "getdents64", 220: "madvise",
    221: "fcntl64", 238: "tkill", 248: "exit_group", 263: "clock_gettime",
    281: "socket", 282: "bind", 283: "connect", 284: "listen", 285: "accept",
    286: "getsockname", 287: "getpeername", 288: "socketpair", 289: "send",
    290: "sendto", 291: "recv", 292: "recvfrom", 293: "shutdown",
    294: "setsockopt", 295: "getsockopt", 296: "sendmsg", 297: "recvmsg",
    309: "add_key", 310: "request_key", 311: "keyctl", 316: "inotify_init",
    322: "openat", 323: "mkdirat", 324: "mknodat", 328: "unlinkat",
    329: "renameat", 330: "linkat", 331: "symlinkat", 332: "readlinkat",
    349: "signalfd", 351: "eventfd", 355: "signalfd4", 356: "eventfd2",
    358: "dup3", 359: "pipe2", 366: "accept4", 379: "finit_module",
    387: "execveat",
}

SYSCALL_TABLES = {
    "arm": ARM_EABI_SYSCALLS,
}

# Behavior categories, mirroring the keys in Rules/test-rules.rules.
CATEGORIES = {
    "process": {"fork", "vfork", "clone", "execve", "execveat", "exit",
                "exit_group", "kill", "wait4", "getpid", "tkill"},
    "file": {"open", "openat", "creat", "link", "linkat", "unlink", "unlinkat",
             "symlink", "symlinkat", "mknod", "mknodat", "rename", "renameat",
             "read", "write", "chmod", "fchmod", "chown", "fchown",
             "ftruncate", "getdents64", "readlink", "readlinkat"},
    "network": {"socket", "bind", "connect", "listen", "accept", "accept4",
                "send", "sendto", "recv", "recvfrom", "sendmsg", "recvmsg",
                "setsockopt", "getsockopt", "shutdown", "setdomainname"},
    "kernel_module": {"init_module", "delete_module", "finit_module",
                      "add_key", "request_key", "keyctl"},
    "events_fd": {"signalfd", "signalfd4", "eventfd", "eventfd2"},
    "pipe": {"pipe", "pipe2", "dup", "dup2", "dup3"},
    "anti_analysis": {"ptrace", "prctl", "setuid", "setuid32", "setgid32",
                      "uname", "sethostname"},
}

# Calls worth surfacing individually as potential IOCs.
SECURITY_SYSCALLS = {"ptrace", "init_module", "delete_module", "finit_module",
                     "kill", "add_key", "request_key", "setuid", "setuid32",
                     "mount", "mprotect"}

PROCESS_SPAWN = {"fork", "vfork", "clone"}

_LINE_RE = re.compile(
    r"^(?P<kind>CALL|RET)\s+vcpu=(?P<vcpu>\d+)\s+num=(?P<num>-?\d+)(?P<rest>.*)$")
_RET_RE = re.compile(r"ret=(?P<ret>-?\d+)")


def _name(num, table):
    return table.get(num, "sys_%d" % num)


def _category_of(name):
    for cat, members in CATEGORIES.items():
        if name in members:
            return cat
    return None


def summarize(lines, arch="arm"):
    """Summarize an iterable of trace lines into a behavioral report dict."""
    table = SYSCALL_TABLES.get(arch, {})

    by_name = {}
    by_category = {}
    security_events = {}
    network = {}
    process_creations = []
    exec_count = 0
    total_calls = 0

    for line in lines:
        m = _LINE_RE.match(line.strip())
        if not m:
            continue
        num = int(m.group("num"))
        name = _name(num, table)

        if m.group("kind") == "CALL":
            total_calls += 1
            by_name[name] = by_name.get(name, 0) + 1
            cat = _category_of(name)
            if cat:
                by_category[cat] = by_category.get(cat, 0) + 1
            if name in SECURITY_SYSCALLS:
                security_events[name] = security_events.get(name, 0) + 1
            if _category_of(name) == "network":
                network[name] = network.get(name, 0) + 1
            if name in ("execve", "execveat"):
                exec_count += 1
        else:  # RET
            if name in PROCESS_SPAWN:
                rm = _RET_RE.search(m.group("rest"))
                # A positive return in the parent is the new child's PID.
                if rm and int(rm.group("ret")) > 0:
                    process_creations.append(
                        {"syscall": name, "child_pid": int(rm.group("ret"))})

    return {
        "backend": "qemu-plugin",
        "arch": arch,
        "total_syscalls": total_calls,
        "unique_syscalls": len(by_name),
        "by_name": dict(sorted(by_name.items(), key=lambda kv: kv[1], reverse=True)),
        "by_category": by_category,
        "process_creations": process_creations,
        "exec_count": exec_count,
        "security_events": security_events,
        "network": network,
        "notes": [
            "Per-syscall PID/ppid and argv are not available from the TCG "
            "trace; this is a flat behavioral summary plus child PIDs derived "
            "from fork/clone/vfork returns. Full per-process attribution needs "
            "guest introspection (see tracing/README.md).",
        ],
    }


def summarize_file(path, arch="arm"):
    with open(path, "r", errors="replace") as fp:
        return summarize(fp, arch=arch)
