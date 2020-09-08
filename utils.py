import paramiko
import scp as sp


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
        print ("[+] Error in scp: %s" % (e,))