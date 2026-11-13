"""
Host-side network capture.

In the legacy flow the guest ran `tcpdump` on itself (see scripts/starter.sh) —
a process the sample can see in `ps`/`/proc` and use to detect analysis. Here we
capture on the *host* side of the virtual NIC instead: the guest's interface is
a TAP device on the host (config.yml: `-netdev tap,...,ifname=tap0`), so the host
can sniff every packet the guest sends/receives while the guest sees a clean
machine with no capture running.

The per-protocol slicing and the snort pass that starter.sh / DynamicAnalyser
used to do are reproduced here so the downstream Parser.NetworkParser consumes
exactly the same files (dns_net.pcap, telnet_net.pcap, snort_alerts.txt, ...).
"""

import os
import signal
import subprocess


# (output filename, tcpdump filter expression) — filenames carry the protocol
# keyword NetworkParser dispatches on, so these names are load-bearing.
PROTO_FILTERS = [
    ("ftp_net.pcap",    "port ftp or ftp-data"),
    ("ntp_net.pcap",    "port 123"),
    ("rdp_net.pcap",    "port 3389"),
    ("icmp_net.pcap",   "icmp"),
    ("dns_net.pcap",    "port 53"),
    ("telnet_net.pcap", "port 23"),
    ("http_net.pcap",   "port 80 or port 443"),
]


class HostCapture:
    """Capture + post-process traffic for one analysis run, entirely host-side."""

    def __init__(self, iface, out_dir):
        self.iface = iface
        self.out_dir = out_dir
        self.pcap = os.path.join(out_dir, "net_logs.pcap")
        self._proc = None

    def start(self):
        """Begin capturing on the TAP interface. Non-blocking."""
        os.makedirs(self.out_dir, exist_ok=True)
        # -U = packet-buffered (flush as we go, so a hard stop loses nothing),
        # -s 0 = full packets, -n = no name resolution (no spurious DNS of ours).
        self._proc = subprocess.Popen(
            ["tcpdump", "-i", self.iface, "-n", "-s", "0", "-U", "-w", self.pcap],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return self._proc

    def stop(self):
        """Stop the capture, giving tcpdump a chance to flush its buffers."""
        if self._proc and self._proc.poll() is None:
            self._proc.send_signal(signal.SIGINT)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def slice_commands(self):
        """The tcpdump argv for each per-protocol slice (pure, for testing)."""
        cmds = []
        for fname, filt in PROTO_FILTERS:
            out = os.path.join(self.out_dir, fname)
            cmds.append(["tcpdump", "-nn", "-r", self.pcap, "-w", out] + filt.split())
        return cmds

    def slice_protocols(self):
        """Split the full capture into the per-protocol pcaps the parser reads."""
        if not os.path.exists(self.pcap):
            return
        for cmd in self.slice_commands():
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def run_snort(self, snort_conf="/etc/snort/snort.conf", snort_log_dir="tmp/"):
        """Run snort over the capture, writing alerts where NetworkParser looks."""
        if not os.path.exists(self.pcap):
            return
        alerts = os.path.join(self.out_dir, "snort_alerts.txt")
        with open(alerts, "w") as fp:
            subprocess.run(
                ["snort", "-q", "-A", "console", "-c", snort_conf,
                 "-r", self.pcap, "-l", snort_log_dir],
                stdout=fp, stderr=subprocess.DEVNULL)

    def finalize(self, snort_conf="/etc/snort/snort.conf", snort_log_dir="tmp/"):
        """Stop capture, then slice + snort — the full post-run pipeline."""
        self.stop()
        self.slice_protocols()
        self.run_snort(snort_conf, snort_log_dir)
