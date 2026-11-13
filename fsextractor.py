"""
Firmware preparation utility (standalone, upstream of the sandbox).

IoT malware frequently ships inside a vendor firmware blob. This module carves
the root filesystem out of such a blob (binwalk + unsquashfs) and identifies
the target CPU architecture, so the result can be fed to the sandbox:

    diseker.py -i <sample_from_fs> -a <detected_arch>

It is intentionally decoupled from the host<->guest orchestration in
Orchestrator.py: carving a filesystem and booting a sample are separate
concerns. (The previous version pulled in SandboxUnit and a stale
cfg["images"]["debian"] emulator schema; both are gone.)
"""

import os
import subprocess
import time
import argparse
import tarfile

import magic

import utils as ut


def identify_platform(filepath):
    """
    Identify an ELF's architecture from libmagic output.

    Returns a (format, canonical_arch) tuple suitable for config.yml / the CLI
    -a flag, or None if the file is not a recognised ELF. Arch names are passed
    through utils.normalize_arch so they line up with the emulator config keys.
    """
    try:
        filetype = magic.from_file(filepath)
    except Exception as e:
        # Some libmagic builds raise but still include the CPU info in the
        # exception message, so fall back to parsing that text.
        filetype = str(e)

    if "ELF 32-bit" in filetype:
        if "ARM" in filetype:
            return ("ELF", ut.normalize_arch("arm"))
        if "80386" in filetype:
            return ("ELF", ut.normalize_arch("x86"))
        if "MIPS" in filetype:
            # Big- vs little-endian MIPS both map to the same config key.
            return ("ELF", ut.normalize_arch("mipsel" if "LSB" in filetype else "mips"))
        if "PowerPC" in filetype:
            return ("ELF", ut.normalize_arch("powerpc"))
    if "ELF 64-bit" in filetype:
        if "x86-64" in filetype:
            return ("ELF", ut.normalize_arch("x86_64"))
        if "aarch64" in filetype or "ARM aarch64" in filetype:
            return ("ELF", ut.normalize_arch("aarch64"))
        if "PowerPC" in filetype:
            return ("ELF", ut.normalize_arch("ppc64"))
    return None


def find_arch_in_tree(path):
    """Walk an extracted filesystem and return the first identifiable
    (format, canonical_arch), or None if nothing was recognised."""
    for dir_name, _subdirs, file_list in os.walk(path, topdown=False):
        for file in file_list:
            res = identify_platform(os.path.join(dir_name, file))
            if res is not None:
                return res
    return None


def extract(file_path):
    """
    Carve the (squashfs) root filesystem out of a firmware blob with binwalk,
    unpack it, and tar it up next to the extracted tree.

    Returns the path to the unpacked filesystem, or None if no filesystem
    could be located inside the blob.
    """
    dest_path = os.path.splitext(os.path.basename(file_path))[0]

    binwalk_call = subprocess.run(["binwalk", file_path], stdout=subprocess.PIPE)
    lines = binwalk_call.stdout.decode(errors="replace").splitlines()

    # Scan every entry for a filesystem signature and take its byte offset.
    # The last filesystem match wins (matches the original intent); the first
    # whitespace-separated token on a binwalk row is the decimal offset.
    offset = None
    for line in lines:
        low = line.lower()
        if "filesystem" in low or "squashfs" in low:
            tokens = line.split()
            if tokens and tokens[0].isdigit():
                offset = int(tokens[0])

    if offset is None:
        return None

    os.makedirs(dest_path, exist_ok=True)
    subprocess.run(["dd", "bs=1", "skip=" + str(offset),
                    "if=" + str(file_path), "of=" + dest_path + "/filesystem"])
    time.sleep(2)

    # Currently only squashfs images are handled (the common IoT case).
    os.system("unsquashfs -f -d " + dest_path + "/fs " + dest_path + "/filesystem")

    fs_path = dest_path + "/fs"
    with tarfile.open(dest_path + "/fs_tar", "x:") as tar:
        tar.add(fs_path, arcname=os.path.basename(fs_path))
    return fs_path


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        prog="fsextractor.py",
        description="Carve a root filesystem out of an IoT firmware image and "
                    "identify its CPU architecture, ready to feed to diseker.py")
    ap.add_argument("firmware", help="Firmware blob to carve")
    args = ap.parse_args()

    fs = extract(args.firmware)
    if fs is None:
        print("[-] No filesystem found in %s" % args.firmware)
        raise SystemExit(1)

    print("[+] Filesystem extracted to %s" % fs)
    detected = find_arch_in_tree(fs)
    if detected is None:
        print("[-] Could not identify the architecture from the extracted tree")
    else:
        fmt, arch = detected
        print("[+] Detected %s / %s" % (fmt, arch))
        print("    Next: diseker.py -i <sample_from_%s> -c config.yml -a %s" % (fs, arch))
