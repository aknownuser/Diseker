#! /bin/bash
#
# starter_min.sh SAMPLE_PATH [DURATION_SECONDS]
#
# Minimal guest agent for the qemu-plugin syscall backend. Because syscalls are
# traced on the HOST (QEMU TCG plugin), there is nothing to collect inside the
# guest: no auditd, no tcpdump, no log harvesting. This just launches the sample
# and waits out the analysis window. It is the smallest possible guest footprint.

SAMPLE="$1"
DURATION="${2:-60}"

"$SAMPLE" &
APP_PID="$!"
echo "pid=$APP_PID"

sleep "$DURATION"
exit 0
