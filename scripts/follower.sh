#! /bin/bash
#
# follower.sh PPID DEST_FOLDER
#
# Runs inside the emulated guest, invoked by starter.sh once the sample's main
# process has run. It walks the process tree spawned by the sample: for every
# descendant PID it finds in the audit log, it dumps that PID's SYSCALL records
# to a separate file and then recurses into that PID's own children.
#
# Output file naming is significant: the host-side Parser.LogParser keys the
# process tree off "<pid>.<ppid>.logs", so this script MUST write exactly that.

PPID_IN="$1"
DEST="$2"

if [ -z "$PPID_IN" ] || [ -z "$DEST" ]; then
	echo "Usage: follower.sh PPID DEST_FOLDER" >&2
	exit 1
fi

AUDIT_LOG=/var/log/audit/audit.log
mkdir -p "$DEST"

follow() {
	local ppid="$1"

	# Child PIDs this ppid spawned, as recorded by auditd. The leading space
	# in ' pid=' avoids matching the 'ppid=' field on the same line.
	for pid in $(ausearch -i --ppid "$ppid" -m SYSCALL 2>/dev/null \
			| grep -oE ' pid=[0-9]+' | cut -d= -f2 | sort -u); do

		[ -z "$pid" ] && continue
		[ "$pid" = "$ppid" ] && continue

		# Dump this child's syscalls, tagged with its parent (ppid) so the
		# report can rebuild the tree edge.
		ausearch -i -p "$pid" -m SYSCALL <"$AUDIT_LOG" >"$DEST/${pid}.${ppid}.logs"

		# Recurse into this child's own descendants.
		follow "$pid"
	done
}

follow "$PPID_IN"
exit 0
