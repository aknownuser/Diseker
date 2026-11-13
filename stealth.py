"""
Fingerprint randomization — the first line of sandbox stealth.

A sample that wants to evade analysis looks for the cheap, static tells of an
emulated environment: a QEMU MAC OUI, the `buildroot` hostname, a predictable
drop path like /root/tobe_executed. This module randomizes those per run so two
analyses never look alike and none of them look like the stock QEMU image.

Everything here is pure Python and deterministic when given a seeded RNG, so it
is unit-testable without booting anything.
"""

import re
import random


# Real NIC-vendor OUI prefixes to impersonate. Deliberately excludes QEMU
# (52:54:00) and every virtualization OUI a sample would flag as a sandbox:
# VMware (00:0C:29 / 00:50:56), VirtualBox (08:00:27), Hyper-V (00:15:5D),
# Xen (00:16:3E). These are physical IoT/consumer-hardware vendors instead.
DEFAULT_OUI_POOL = [
    "B8:27:EB",  # Raspberry Pi Foundation
    "DC:A6:32",  # Raspberry Pi (Trading)
    "00:1D:0F",  # TP-LINK Technologies
    "50:C7:BF",  # TP-LINK Technologies
    "00:E0:4C",  # Realtek Semiconductor
    "00:14:6C",  # Netgear
    "1C:BD:B9",  # D-Link International
    "00:1B:11",  # D-Link
]

# Plausible IoT/appliance hostnames to replace "buildroot".
DEFAULT_HOSTNAME_POOL = [
    "router", "gateway", "dvr", "ipcam", "nas", "ap", "switch", "device",
]

# Benign-looking process names to drop the sample as, instead of
# "tobe_executed". Tracking is by PID, so a mundane name costs us nothing.
DEFAULT_SAMPLE_NAMES = [
    "update", "cfgd", "sysinit", "watchdog", "klogd", "udhcpc", "netcfg",
]
DEFAULT_SAMPLE_DIRS = ["/tmp", "/var/tmp", "/var/run"]


# A guest NIC MAC in a QEMU command line, e.g. "...,mac=52:54:00:00:EE:03".
_MAC_RE = re.compile(r"mac=([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")


def random_mac(oui_pool=None, rng=random):
    """Return a MAC with a real-vendor OUI and three random vendor octets."""
    oui = rng.choice(oui_pool or DEFAULT_OUI_POOL)
    tail = ":".join("%02X" % rng.randint(0, 255) for _ in range(3))
    return "%s:%s" % (oui.upper(), tail)


def random_hostname(pool=None, rng=random):
    """Return a plausible, unique-ish hostname (e.g. 'router-3f9a')."""
    base = rng.choice(pool or DEFAULT_HOSTNAME_POOL)
    return "%s-%04x" % (base, rng.randint(0, 0xFFFF))


def random_sample_path(names=None, dirs=None, rng=random):
    """Return a randomized, benign-looking absolute path to drop the sample."""
    name = rng.choice(names or DEFAULT_SAMPLE_NAMES)
    directory = rng.choice(dirs or DEFAULT_SAMPLE_DIRS)
    return "%s/%s" % (directory, name)


def apply_fingerprint_to_cmd(cmd, mac=None):
    """
    Rewrite the NIC MAC in a QEMU command line to `mac`.

    If the template has no mac= token the command is returned unchanged (the
    machine assigns one itself); callers that need a MAC should put a mac= in
    the config template so there is something to rewrite.
    """
    if mac and _MAC_RE.search(cmd):
        return _MAC_RE.sub("mac=%s" % mac, cmd)
    return cmd


class Fingerprint:
    """The randomized identity chosen for a single analysis run."""

    def __init__(self, mac, hostname, sample_path):
        self.mac = mac
        self.hostname = hostname
        self.sample_path = sample_path

    @classmethod
    def generate(cls, stealth_cfg=None, rng=random):
        """Build a Fingerprint from the optional stealth: config section."""
        cfg = stealth_cfg or {}
        return cls(
            mac=random_mac(cfg.get("mac_oui_pool"), rng=rng),
            hostname=random_hostname(cfg.get("hostname_pool"), rng=rng),
            sample_path=random_sample_path(
                cfg.get("sample_name_pool"), cfg.get("sample_dir_pool"), rng=rng),
        )

    def as_dict(self):
        return {"mac": self.mac, "hostname": self.hostname,
                "sample_path": self.sample_path}

    def __str__(self):
        return "Fingerprint(mac=%s, hostname=%s, sample=%s)" % (
            self.mac, self.hostname, self.sample_path)
