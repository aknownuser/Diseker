"""
Per-architecture QEMU command builder.

The goal is "least configuration from the operator": to add support for a new
architecture you should only have to drop an image + kernel into config.yml, not
hand-write a full qemu-system command line. This module holds the per-arch
knowledge (which QEMU binary, machine type, console, root device, NIC, DTB) and
synthesizes the command from the paths the operator provides.

An explicit `cmd:` in config.yml always wins — build_command is only used when a
target entry has no `cmd` — so hand-tuned command lines (e.g. the arm/32 image)
keep working unchanged.

The command is emitted with a literal "{image}" placeholder for the rootfs, so
the caller substitutes the per-run image copy via str.format(image=...), exactly
as with a config-provided cmd. The NIC `mac=` is a real-vendor default here and
is rewritten per run by stealth.apply_fingerprint_to_cmd when stealth is on.
"""

import utils as ut


# Default NIC MAC for stealth-OFF runs: a real Realtek OUI, never a QEMU OUI.
DEFAULT_MAC = "00:E0:4C:00:00:01"

# Per-arch QEMU profile. qemu binary is chosen separately (it varies with
# endianness for MIPS). "blk" set => split virtio drive/device (aarch64 virt).
PROFILES = {
    "arm":     {"machine": "versatilepb", "console": "ttyAMA0,115200",
                "root": "/dev/sda", "drive": "if=scsi,format=raw",
                "nic": "rtl8139", "dtb": True},
    "aarch64": {"machine": "virt", "cpu": "cortex-a53", "smp": 1,
                "console": "ttyAMA0", "root": "/dev/vda",
                "drive": "if=none,format=raw,id=hd0", "blk": "virtio-blk-device",
                "nic": "virtio-net-device", "dtb": False},
    "mips":    {"machine": "malta", "console": "ttyS0", "root": "/dev/sda",
                "drive": "if=ide,format=raw", "nic": "e1000", "dtb": False},
    "x86":     {"machine": "pc", "console": "ttyS0", "root": "/dev/sda",
                "drive": "if=ide,format=raw", "nic": "e1000", "dtb": False},
    "x86_64":  {"machine": "pc", "console": "ttyS0", "root": "/dev/sda",
                "drive": "if=ide,format=raw", "nic": "e1000", "dtb": False},
    "ppc64":   {"machine": "pseries", "console": "hvc0", "root": "/dev/sda",
                "drive": "if=scsi,format=raw", "nic": "e1000", "dtb": False},
}


def qemu_binary(arch, bits, endian):
    """Pick the qemu-system-* binary. For MIPS the binary encodes endianness."""
    arch_n = ut.normalize_arch(arch)
    bits_n = ut.normalize_bits(bits)
    le = ut.normalize_endian(endian) == "le"
    if arch_n == "arm":
        return "qemu-system-arm"
    if arch_n == "aarch64":
        return "qemu-system-aarch64"
    if arch_n == "x86":
        return "qemu-system-i386"
    if arch_n == "x86_64":
        return "qemu-system-x86_64"
    if arch_n == "ppc64":
        return "qemu-system-ppc64"
    if arch_n == "mips":
        if bits_n == 64:
            return "qemu-system-mips64el" if le else "qemu-system-mips64"
        return "qemu-system-mipsel" if le else "qemu-system-mips"
    raise Exception("No QEMU binary mapping for arch=%s" % arch_n)


def supported():
    """Canonical arch keys this builder can synthesize a command for."""
    return sorted(PROFILES.keys())


def build_command(arch, bits, endian, kernel, image="{image}", dtb=None, tap="tap0", mac=None):
    """
    Synthesize a qemu-system command line for (arch, bits, endian).

    `image` defaults to the literal "{image}" placeholder (substituted later by
    the caller). Raises a clear, actionable error when the config is missing a
    piece the architecture requires (kernel, dtb) or when the arch is unknown.
    """
    arch_n = ut.normalize_arch(arch)
    prof = PROFILES.get(arch_n)
    if prof is None:
        raise Exception("No arch profile for '%s'. Add one to "
                        "archprofiles.PROFILES, or provide an explicit 'cmd' in "
                        "config.yml for this target." % arch_n)
    if not kernel:
        raise Exception("arch %s needs a 'kernel' path in config.yml" % arch_n)

    mac = mac or DEFAULT_MAC
    parts = [qemu_binary(arch_n, bits, endian), "-M", prof["machine"]]
    if prof.get("cpu"):
        parts += ["-cpu", prof["cpu"]]
    if prof.get("smp"):
        parts += ["-smp", str(prof["smp"])]
    parts += ["-nographic", "-kernel", kernel]

    if prof.get("dtb"):
        if not dtb:
            raise Exception("arch %s needs a 'dtb' path in config.yml" % arch_n)
        parts += ["-dtb", dtb]

    # Root disk: virtio machines split the backend drive from the device.
    if prof.get("blk"):
        parts += ["-drive", "file=%s,%s" % (image, prof["drive"]),
                  "-device", "%s,drive=hd0" % prof["blk"]]
    else:
        parts += ["-drive", "file=%s,%s" % (image, prof["drive"])]

    parts += ["-append", '"rootwait root=%s console=%s"' % (prof["root"], prof["console"])]

    # Host-side TAP networking + NIC. mac= is rewritten by stealth when enabled.
    parts += ["-netdev", "tap,id=intnet,ifname=%s,script=no,downscript=no" % tap,
              "-device", "%s,netdev=intnet,mac=%s" % (prof["nic"], mac)]

    return " ".join(parts)
