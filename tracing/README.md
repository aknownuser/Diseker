# Host-side syscall tracing (QEMU TCG plugin)

This directory holds the plugin that will let Diseker record a sample's syscalls
**from the host**, replacing the in-guest `auditd` that a sample can currently
detect. QEMU calls the plugin's callbacks as the guest executes, so inside the
guest there is no tracer, no ptrace, and no auditd to find.

> Status: **scaffolding.** `auditd` remains the default `syscall_backend` in
> `config.yml`. This plugin is the foundation for flipping that to
> `qemu-plugin`. It cannot be built or tested on macOS (no QEMU source); build
> it on the Linux analysis host.

## Prerequisites

- A QEMU **built with plugins enabled**:
  ```
  ./configure --enable-plugins && make
  ```
- The public header `qemu-plugin.h` (in the QEMU tree under `include/qemu/`).

## Build

```
make QEMU_INCLUDE=/path/to/qemu/include/qemu
# -> libsyscall_trace.so
```

## Run

```
qemu-system-arm ... \
    -plugin ./libsyscall_trace.so,out=/path/run/syscalls.log \
    -d plugin
```

The guest NIC MAC and drop path are already randomized by `stealth.py`; adding
`-plugin` removes the last in-guest instrumentation artifact.

## Remaining work before flipping the default to `qemu-plugin`

1. **Process attribution.** The TCG syscall callback gives the syscall number
   and arguments at the CPU level — not the guest PID/ppid or `argv`. The HTML
   report is built around a process tree, so we need guest introspection: read
   the current task's PID/comm from the guest `task_struct` via its CR3. This is
   kernel-version-specific and is the main open problem.
2. **A parser adapter.** `Parser.LogParser`/`EventParser` currently parse
   `ausearch -i` text into `Event` objects. A new adapter must translate this
   plugin's `CALL/RET` lines (plus the attribution from step 1) into the same
   `Event` shape so `report.py` is unchanged.
3. **Wire it in.** When `stealth.syscall_backend == "qemu-plugin"`,
   `DynamicAnalyser` should append the `-plugin ...` args to the QEMU command
   (via `stealth.py`) and skip `apply_rule.sh`/the auditd harvesting entirely.
