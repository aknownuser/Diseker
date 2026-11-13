#! /bin/bash
#
# starter_stealth.sh SAMPLE_PATH [DURATION_SECONDS]
#
# Stealth guest agent. Unlike starter.sh it does NOT run tcpdump inside the
# guest — network traffic is captured on the host side of the TAP interface
# (see netcapture.py), so the sample never sees a capture process. The only
# in-guest instrumentation left is auditd, and only while
# stealth.syscall_backend == "auditd"; the host-side QEMU syscall tracer
# (tracing/) is the path to removing even that.
#
# Syscall logs are written where extract.sh expects them (/root/logs/syscalls)
# using the "<pid>.<ppid>.logs" naming the host-side Parser keys off.

SAMPLE="$1"
DURATION="${2:-60}"

BASE=$(pwd)
SYSCALL_PATH=logs/syscalls
mkdir -p "$SYSCALL_PATH"

# Launch the sample in the background and record its PID.
"$SAMPLE" &
APP_PID="$!"
echo "pid=$APP_PID"

# Give it time to act (delayed payloads are a known limitation; see LIMITS.md).
sleep "$DURATION"

# Dump the root process's syscalls, then walk its children.
ausearch -i -p "$APP_PID" -m SYSCALL >"$SYSCALL_PATH/$APP_PID.logs"
./follower.sh "$APP_PID" "$BASE/$SYSCALL_PATH"

exit 0
