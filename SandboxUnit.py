import pexpect
import utils as ut
import time

class Unit:

    def __init__(self, fs_path, user, password, host="localhost", port=10022):
        self.fs_path = fs_path
        self.user = user
        self.password = password
        self.host = host
        self.port = port
        self.alive=False

    def execute(self, qemu_command):

        qemu = pexpect.spawn(qemu_command, timeout=240)
        time.sleep(2)
        try:
            qemu.expect('(qemu).*')
            qemu.sendline("loadvm init")
            time.sleep(3)

            self.alive = qemu.isalive()
            if not qemu.isalive():
                raise Exception("[QEMU] Machine was unable to start")
            # Send file system to QEMU VM
            ut.scp(self.host, self.port, self.user, self.password, self.fs_path, "/root", dir=False)
            qemu.wait()
        except Exception as e:
            print("[-] Error: %s" % e)
            if qemu.isalive():
                self.alive=False
                qemu.close()