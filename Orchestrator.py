import threading
import re
import r2pipe
import base64
import utils
import math
import pexpect
import utils as ut
import time
import shutil
import os
import threading
import queue

from binwalk.core import common as bin_common


class Analyser:

    def __init__(self, file_path):
        self.file_path = file_path

    def analyse(self):
        # To be implemented by the child class
        pass


class StaticAnalyser(Analyser):

    def __init__(self, file_path):
        super().__init__(file_path)
        self.out = {}
        self.out["file"] = {}
        self.out["func"] = {}
        self.out["sections"] = []
        self.out["strings"] = {}
        self.out["entropy"] = []

    def analyse(self):
        r2 = r2pipe.open(self.file_path)
        r2.cmd("aa")
        # Get file basic information
        aux = r2.cmdj("iIj")
        self.out["file"]["arch"] = aux["arch"]
        self.out["file"]["size"] = aux["binsz"]
        self.out["file"]["class"] = aux["class"]
        self.out["file"]["bits"] = aux["bits"]
        self.out["file"]["md5"] = r2.cmd("ph md5")[:-1]
        self.out["file"]["sha1"] = r2.cmd("ph sha1")[:-1]
        self.out["file"]["sha256"] = r2.cmd("ph sha256")[:-1]
        # Get functions and their offset and size (only the ones that Radare could read the name of)
        aux = r2.cmdj("aflj")
        self.out["func"]["known"] = [{"offset":val["offset"], "name":val["name"],"size":val["size"]}for val in aux if "fcn" not in val["name"]]
        self.out["func"]["cknown"] = len(self.out["func"]["known"])
        self.out["func"]["cunknown"] = len(aux) - self.out["func"]["cknown"]

        # Get sections available their name and size
        self.out["sections"] = [{"name":val["name"], "size": val["size"], "addr":val["paddr"]} for val in r2.cmdj("iSj")]

        # Get the entropy of the file in sections of 10240 bytes
        # aux1 = r2.syscmdj("rahash2 -r -a entropy -b 128 -B %s" % self.file_path)
        self.out["entropy"] = self._file_entropy()

        # Get all the strings from the binary
        aux = r2.cmdj("izzj")
        # The string are encoded in base64, this function
        decode = lambda x, t: base64.b64decode(x.encode('ascii')).decode(t) if t in ["utf8", "utf16", "ascii"] else "unknown Type"

        # Get all the strings larger than 10 characters
        self.out["strings"]["all"] = [{"section": x['section'], "type":x['type'], "length":x['length'], "string": decode(x['string'], x['type'])} for x in aux['strings'] if x['length'] > 10]

        # Get only the interesting strings, the ones that contain a hardcoded IPv4, IPv6 or URL
        self.out["strings"]["inter"] = self._interesting_strings(self.out["strings"]["all"])
        r2.quit()

    def _interesting_strings(self, dictionary_str):

        result = []
        ipv4_regex = re.compile(utils.IPV4ADDR)
        ipv6_regex = re.compile(utils.IPV6ADDR)
        urls_regex = re.compile(utils.URLS)

        for str_dic in dictionary_str:
            if ipv4_regex.search(str_dic["string"]) is not None or ipv6_regex.search(str_dic["string"]) is not None \
                    or urls_regex.search(str_dic["string"]) is not None:

                result.append(str_dic)

        return result

    def _file_entropy(self, block_size=None):
        result = []
        fp = bin_common.BlockFile(self.file_path, mode="r")
        data_points = 2048
        if block_size is None:
            block_size = fp.size / data_points
            block_size = int(block_size + ((1024 - block_size) % 1024))

        # The default value if the approximation didn't work
        if block_size <= 0:
            block_size = 1024

        while True:
            offset = fp.tell()

            data, dlen = fp.read_block()
            if dlen < 1:
                break
            i = 0

            while i < dlen:
                entp = self._shannon_entropy(data[i:i+block_size])
                result.append((offset+i, entp))
                i += block_size

        return result

    def _shannon_entropy(self, data):
        '''
        Performs shanon entropy
        :param data:
        :return:
        '''

        entp = 0

        if data:
            length = len(data)
            observ = dict(((chr(x), 0) for x in range(0, 256)))
            for b in data:
                observ[b] += 1
            for i in range(0, 256):
                p_i = float(observ[chr(i)]) / length
                if p_i > 0:
                    entp -= p_i * math.log(p_i, 2)

            return entp / 8


class DynamicAnalyser(Analyser):

    def __init__(self, file, config, arch, bit, endianess):
        super().__init__(file)
        self.file = file
        self.alive = False
        self.cfg = config
        self.arch = arch
        self.bit = bit
        self.endian = endianess

    def analyse(self):

        self.cmd_builder = CommandBuilder(self.arch, self.bit, self.endian, self.file)
        qemu_cmd = self.cmd_builder.build(self.cfg)

        self.qemu = pexpect.spawn(qemu_cmd, timeout=240)
        time.sleep(2)

        try:
            self.qemu.expect('buildroot login:')
            self.qemu.sendline('root')
            time.sleep(2)
            self.qemu.expect('#')
            self.qemu.sendline('./apply_rule.sh')
            self.qemu.expect('#')
            self.qemu.sendline('./starter.sh tobe_executed')
            self.alive = self.qemu.isalive()
            # We first wait to get the bash again, we may need to check that out and improve it
            self.qemu.expect('#')

            # Wait for sometime so the execution can be though to be complete
            self.qemu.waitnoecho(5)
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


class Unit(threading.Thread):

    def __init__(self, cfg_path, fs_path, file):
        super(Unit, self).__init__()

        self.fs_path = fs_path
        self.file = file
        self.alive = False
        self.static = StaticAnalyser(self.file)
        self.cfg = ut.get_config(cfg_path)
        self.dynamic_logs = None
        #self.passw = cfg[arch]["pass"]
        #self.host = cfg[arch]["host"]
        #self.port = cfg[arch]["port"]

        #self.arch = arch
        #self.bit = bit
        #self.endian = endianess
        #self.cfg = cfg

    def run(self):

        #Execute the static analyser
        self.static.analyse()
        #TODO: Endianess of the file is not checked properly
        self.dynamic = DynamicAnalyser(self.file, self.cfg,
                                       self.static.out["file"]["arch"],
                                       self.static.out["file"]["bits"],
                                       "le")
        # Execute the dynamic analyser

        self.dynamic_logs = self.dynamic.analyse()
    """
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

        \"""try:
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
        \"""
        return self.cmd_builder.cleanup()
    """

    def kill(self):
        if hasattr(self, "dynamic"):
            self.dynamic.kill()


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


class Orchestrator:

    def __init__(self, max_threads, cfg):
        self.max_th = max_threads
        self.unit_jobs = []
        self.cfg = cfg

    def add_job(self, job_cmd):
        pass

    def execute_group(self, instances):
        pass

    def execute_ordered_group(self, list_instances):
        pass

    def execute_once(self):
        pass

    def wait_finish(self):
        pass
