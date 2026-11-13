#! /bin/bash
#
# apply_rule.sh [rules_file]
#
# Runs inside the emulated guest BEFORE the sample is launched. It loads the
# auditd ruleset so that every syscall of interest (process, file, network,
# kernel-module activity) is recorded to /var/log/audit/audit.log, which
# starter.sh / follower.sh later harvest per-PID.
#
# The ruleset is deployed next to this script by the host (DynamicAnalyser),
# defaulting to /root/test-rules.rules.

RULES="${1:-/root/test-rules.rules}"

if [ ! -f "$RULES" ]; then
	echo "[apply_rule] ruleset not found: $RULES" >&2
	exit 1
fi

# Make sure the audit daemon is running (name differs across init systems).
service auditd start 2>/dev/null \
	|| /etc/init.d/auditd start 2>/dev/null \
	|| auditd 2>/dev/null

# Clear any pre-existing rules, then load ours and enable auditing.
auditctl -D >/dev/null 2>&1
auditctl -R "$RULES"
auditctl -e 1 >/dev/null 2>&1

echo "[apply_rule] loaded $(auditctl -l 2>/dev/null | wc -l) rules from $RULES"
exit 0
