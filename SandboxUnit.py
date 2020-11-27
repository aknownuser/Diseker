import pexpect
import utils as ut
import time
import shutil
import os


class CommandBuilder:

    def __init__(self, arch, bit, endianess, file):
        self.arch = arch
        self.bit = bit
        self.endianess = endianess
        self.file = file
        try:
            os.mkdir("tmp")
        except:
            pass
        self._image = None
        self._kernel = None

    def build(self, cfg):

        # Random name for the copy of the new file system to emulate
        self._fs = os.path.join(cfg["tmp"], ut.get_rand_string(6))

        base = cfg[self.arch][self.bit]
        image = None
        if self.endianess == "le":
            self._kernel = base["kernelle"]
            image = base["imagele"]
        else:
            self._kernel = base["kernel"]
            image = base["image"]
        if image is not None:
            shutil.copy(image, self._fs)
        else:
            raise Exception("Path was not found in configuration file")
        # os.system('e2cp -G 0 -O 0 -P 777 starter.sh %s:/root/' % self._fs)
        # os.system('e2cp -G 0 -O 0 -P 777 follower.sh %s:/root/' % self._fs)

        os.system('e2cp -G 0 -O 0 -P 755 %s %s:/root/tobe_executed'%(self.file, self._fs))

        return base["cmd"].format(kernel=self._kernel, fs=self._fs)

    def extract_logs(self):
        path = os.path.join(self._fs, ut.get_rand_string(7))
        os.makedirs(path)
        os.system('e2cp ./scripts/extract.sh %s %s' % (self._fs, path))
        return path

    def cleanup(self):
        # Remove the copied filesystem
        pth = self.extract_logs()
        shutil.rmtree(self._fs)
        return pth


class Unit:

    def __init__(self, cfg, fs_path, file, arch, endianess, bit):
        self.fs_path = fs_path
        self.file = file
        self.alive = False

        self.passw = cfg[arch]["pass"]
        self.host = cfg[arch]["host"]
        self.port = cfg[arch]["port"]

        self.arch = arch
        self.bit = bit
        self.endian = endianess
        self.cfg = cfg

    def execute(self):
        self.cmd_builder = CommandBuilder(self.arch, self.bit, self.endian, self.file)
        qemu_cmd = self.cmd_builder.build(self.cfg)

        self.qemu = pexpect.spawn(qemu_cmd, timeout=240)
        time.sleep(2)

        try:
            self.qemu.expect('buildroot login:')
            self.qemu.sendline(self.host)
            time.sleep(2)
            self.qemu.expect('#')
            self.qemu.sendline('./apply_rule.sh')
            self.qemu.expect('#')
            self.qemu.sendline('./starter.sh tobe_executed')
            self.alive = self.qemu.isalive()
            # We first wait to get the bash again, we may need to check that out and improve it
            self.qemu.expect('#')

        except Exception as e:
            print("[-] Error: %s" % e)
            if self.qemu.isalive():
                self.alive = False
                self.qemu.close()

        """try:
            self.qemu.expect('(qemu).*')
            self.qemu.sendline("loadvm init")
            time.sleep(3)

            self.alive = self.qemu.isalive()
            if not self.qemu.isalive():
                raise Exception("[QEMU] Machine was unable to start")
            # Send file system to QEMU VM
            #ut.scp(self.host, self.port, self.user, self.password, self.fs_path, "/root", dir=False)
            self.qemu.wait()
        except Exception as e:
            print("[-] Error: %s" % e)
            if self.qemu.isalive():
                self.alive=False
                self.qemu.close()
        """
        return self.cmd_builder.cleanup()

    def kill(self):
        if hasattr(self, "qemu"):
            self.qemu.close(force=True)
        self.cmd_builder.cleanup()
