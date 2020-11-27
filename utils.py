import paramiko
import scp as sp
import yaml
import datetime
import pytz
import string
import random
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
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=user, password=password)
        sftp = ssh.open_sftp()
        sftp.put(src_file, dst_file)
    except Exception as e:
        print ("[+] Error in scp: %s" % (e,))


def scp(host, port, user, password, src_file, dest_file, dir=True):
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
        cfg = yaml.load(ymlfile)
    return cfg


def get_rand_string(length, codef=string.ascii_letters):
    """
    Random string generator
    :param length: Length of the string
    :param codef: Codification to use, by default the ASCII is being used
    :return: random string
    """
    return ''.join(random.choice(codef) for i in range(length))

# Static function get QEMU command, this one can be used by any one or any class, since
# it has been defined to establish the scope of the program, it should only be changed
# if a major change is done to the architecture

#TODO: Needs to be improved  and we need to add more ARCHs in a correct way
def get_qemu_command(arch, cfg):

    sim = {"arm": "qemu-system-arm",
           "mips": "qemu-system-mips",
           "x86": "qemu-system-i386"}

    result = "%s -M malta -kernel %s\
     -hda %s \
     -net user,hostfwd=tcp::10022-:22\
     -net nic\
     -monitor stdio \
     -append \"root=/dev/sda1 console=tty0\"" % (sim[arch], cfg["images"]["debian"]["kernel"], cfg["images"]["debian"]["image"])

    return result


# From date to miliseconds since epoch
def from_date_to_msepoch(year, month, day, hour, minute, seconds, microseconds=None):
    if microseconds is not None:
        return int((datetime.datetime(year, month, day, hour, minute, microsecond=microseconds,tzinfo=pytz.UTC) - datetime.datetime(1970, 1, 1,tzinfo=pytz.UTC)).total_seconds()*1000)
    return int((datetime.datetime(year, month, day, hour, minute, second=seconds,tzinfo=pytz.UTC) - datetime.datetime(1970, 1, 1,tzinfo=pytz.UTC)).total_seconds()*1000)