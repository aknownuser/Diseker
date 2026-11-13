import yaml
import datetime
import pytz
import string
import random
import hashlib

# NOTE: paramiko / scp are imported lazily inside the SSH helpers below so the
# core analysis pipeline (QEMU console via pexpect) can run without the SSH
# stack installed. Only the optional ssh_* / scp / sftp helpers need them.

# IPV4SEG = r'(?:^| )(?P<address>((?:[1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(?:[1-9]?\d|1\d{2}|2[0-4]\d|25[0-5]))(?P<slash>/)?(?(slash)(?P<cidr>[0-9]|[12][0-9]|3[0-2]))(?:$| )'

IPV4ADDR = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
# from http://vernon.mauery.com/content/projects/linux/ipv6_regex
IPV6ADDR = r'(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}\Z)|' \
        r'(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}\Z)|' \
        r'(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}\Z)|' \
        r'(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}\Z)|' \
        r'(\A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}\Z)|' \
        r'(\A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}\Z)|' \
        r'(\A(([0-9a-f]{1,4}:){1,7}|:):\Z)|' \
        r'(\A:(:[0-9a-f]{1,4}){1,7}\Z)|' \
        r'(\A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|' \
        r'(\A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|' \
        r'(\A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|' \
        r'(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|' \
        r'(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|' \
        r'(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,2}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|' \
        r'(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,1}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|' \
        r'(\A(([0-9a-f]{1,4}:){1,5}|:):(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|' \
        r'(\A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)'

URLS = r'^(ftps?|https?|chrome):\/\/[^\s$.?#].[^\s]*'


def ssh_execute(host, port, user, password, commands, noprompt=False, logout=True):
    import paramiko
    result = None
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=user, password=password)
        if type(commands) == type(str()):
            stdin, stdout, stderr = ssh.exec_command(commands, timeout=10)
            if noprompt == False:
                result = "".join(stdout.readlines())
        if type(commands) == type(list()):
            result = {}
            for command in commands:
                stdin, stdout, stderr = ssh.exec_command(command, timeout=10)
                result[command] = "".join(stdout.readlines())
        if logout:
            ssh.close()
        else:
            return ssh  # Return SSH object to logout later
    except Exception as e:
        print("[+] Error in ssh_execute: %s" % (e,))
    return result


def ssh_prompt(host, port, user, password):
    ssh = ssh_execute(host, port, user, password, "uname -a", noprompt=False, logout=False)

    while True:
        cmd = input(">>")
        if cmd == "exit_ssh":
            ssh.close()
            break
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
        print("".join(stdout.readlines()))


def sftp(host, port, user, password, src_file, dst_file):
    import paramiko
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=user, password=password)
        sftp = ssh.open_sftp()
        sftp.put(src_file, dst_file)
    except Exception as e:
        print ("[+] Error in scp: %s" % (e,))


def scp(host, port, user, password, src_file, dest_file, dir=True):
    import paramiko
    import scp as sp
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=user, password=password)
        scp_obj = sp.SCPClient(ssh.get_transport())
        scp_obj.put(src_file, recursive=dir,remote_path=dest_file)
        scp_obj.close()

    except Exception as e:
        print("[+] Error in scp: %s" % (e,))


# load a yaml file and return the values
def get_config(file):
    cfg = None
    with open(file) as ymlfile:
        # Loader is mandatory on modern PyYAML; SafeLoader is enough here.
        cfg = yaml.load(ymlfile, Loader=yaml.SafeLoader)
    return cfg


# Canonical architecture keys used in config.yml. Both the CLI (-a) and the
# radare2 auto-detection produce a variety of spellings for the same target;
# this maps every spelling we expect onto one canonical config key.
ARCH_ALIASES = {
    "arm": "arm", "armel": "arm", "armhf": "arm",
    "aarch64": "aarch64", "aarch": "aarch64", "arm64": "aarch64",
    "x86": "x86", "x86_32": "x86", "i386": "x86", "i686": "x86", "ia32": "x86",
    "x86_64": "x86_64", "amd64": "x86_64", "x64": "x86_64",
    "ppc": "ppc64", "ppc64": "ppc64", "ppcp": "ppc64", "powerpc": "ppc64",
    "mips": "mips", "mipsel": "mips",
}


def normalize_arch(arch):
    """Map any accepted arch spelling onto the canonical config.yml key."""
    if arch is None:
        return None
    return ARCH_ALIASES.get(str(arch).lower(), str(arch).lower())


def normalize_bits(bits):
    """Config bit keys are integers (32/64); coerce whatever we were given."""
    if bits is None:
        return None
    return int(bits)


def get_rand_string(length, codef=string.ascii_letters):
    """
    Random string generator
    :param length: Length of the string
    :param codef: Codification to use, by default the ASCII is being used
    :return: random string
    """
    return ''.join(random.choice(codef) for i in range(length))


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


def entropy(string):
    """
    Measures the entropy of the a string and returns a value
    :param string:
    :return:
    """
    import math
    log2 = lambda x: math.log(x) / math.log(2)
    exr = {}
    t_len = len(string)
    infoc = 0
    for each in string:
        try:
            exr[each] += 1
        except:
            exr[each] = 1
    freq = 0
    for k, v in exr.items():
        freq = 1.0 * v / t_len
    infoc += freq * log2(freq)
    infoc *= -1

    return infoc

# QEMU command lines now live entirely in config.yml (cfg[arch][bits]["cmd"],
# with "{image}" substituted per-run). The old hardcoded get_qemu_command here
# used a stale cfg["images"]["debian"] schema and had no callers — removed to
# keep a single source of truth for emulator invocation.


# From date to miliseconds since epoch
def from_date_to_msepoch(year, month, day, hour, minute, seconds, microseconds=None):
    if microseconds is not None:
        return int((datetime.datetime(year, month, day, hour, minute, microsecond=microseconds,tzinfo=pytz.UTC) - datetime.datetime(1970, 1, 1,tzinfo=pytz.UTC)).total_seconds()*1000)
    return int((datetime.datetime(year, month, day, hour, minute, second=seconds,tzinfo=pytz.UTC) - datetime.datetime(1970, 1, 1,tzinfo=pytz.UTC)).total_seconds()*1000)