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
import asyncio
from dbconnections import *
from binwalk.core import common as bin_common
import report as rep
import json
from pexpect import popen_spawn
import sys
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

    def get_hash(self):
        r2 = r2pipe.open(self.file_path)
        return r2.syscmdj("rahash2 -j -a sha256 %s" % self.file_path)["hash"]

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

    def json(self):
        return json.dumps(self.out)

    def save_as_json(self, path):
        path = os.path.join(path, "static_analysis_%s.json" % (os.path.basename(self.file_path)))
        with open(path, "w") as fl:
            json.dump(self.out, fl)


class DynamicAnalyser(Analyser):

    def __init__(self, file, config, arch, bit, exectime):
        super().__init__(file)
        self.file = file
        self.alive = False
        self.cfg = config
        self.arch = arch
        self.bit = bit
        self._fs = None
        self.exectime = exectime

    def analyse(self):
        # Random name for the copy of the new file system to emulate
        path = os.path.join(self.cfg["tmp"], ut.get_rand_string(5))
        # Make DIR
        os.makedirs(path)
        self._fs = os.path.join(path, ut.get_rand_string(8))
        logname = os.path.join(path, ut.get_rand_string(8))

        base = self.cfg[self.arch][self.bit]
        image = base["image"]

        if image is not None:
            shutil.copy(image, self._fs)
        else:
            raise Exception("Path was not found in configuration file")

        # os.system('e2cp -G 0 -O 0 -P 777 starter.sh %s:/root/' % self._fs)
        # os.system('e2cp -G 0 -O 0 -P 777 follower.sh %s:/root/' % self._fs)

        os.system('e2cp -G 0 -O 0 -P 755 %s %s:/root/tobe_executed' % (self.file, self._fs))

        qemu_cmd = base["cmd"].format(image=self._fs)

        self.qemu = pexpect.spawn("%s" % qemu_cmd, timeout=305, searchwindowsize=500, encoding='utf-8')
        self.qemu.logfile = open(logname, "w", encoding='utf-8')

        time.sleep(2)

        try:
            self.qemu.expect("buildroot login: ")
            self.qemu.sendline("root")
            time.sleep(2)
            self.qemu.expect('#')
            self.qemu.sendline("./apply_rule.sh")
            self.qemu.expect('#')
            self.qemu.sendline('./starter.sh tobe_executed')
            self.alive = True
            # We first wait to get the bash again, we may need to check that out and improve it
            self.qemu.expect('#')

            # Wait for sometime so the execution can be though to be complete
            time.sleep(self.exectime)

        except Exception as e:
            print("[-] Error: %s" % e)

            self.cleanup()
            if self.qemu.isalive():
                self.alive = False
                self.qemu.close()
        finally:
            self.alive = False
            self.qemu.logfile.close()
            os.system("rm %s" % logname)
            self.qemu.close()
            time.sleep(1)
            self._extract_logs(path)
        return path

    def _extract_logs(self, path):
        if not os.path.exists(path):
            os.makedirs(path)
        os.system('scripts/extract.sh %s %s' % (self._fs, path))
        os.system('snort -q -A console -c /etc/snort/snort.conf -r %s/logs/network/net_logs.pcap -l tmp/ > '
                  '%s/logs/network/snort_alerts.txt' % (path, path))

    def kill(self):
        if hasattr(self, "qemu"):
            self.qemu.close(force=True)
        self.cleanup()

    def cleanup(self):
        if self._fs is not None:
            os.system("rm %s" % self._fs)


class Unit(threading.Thread):

    def __init__(self, cfg, fs_path, file, exectime=120, arch=None, bits=None):
        threading.Thread.__init__(self)

        self.fs_path = fs_path
        self.file = file
        self.alive = False
        self.static_analyser = StaticAnalyser(file)
        self.cfg = cfg
        self.dynamic_logs = None
        self.exectime = exectime
        self._arch = arch
        self._bit = bits
        # Connect with DB if its already done then OKEY

    def run(self):
        #Execute the static analyser
        self.static_analyser.analyse()
        if self._arch is not None and self._bit is not None:
            self.dynamic = DynamicAnalyser(self.file, self.cfg,
                                           self._arch,
                                           self._bit,
                                           self.exectime)
        else:
            self.dynamic = DynamicAnalyser(self.file, self.cfg,
                                           self.static_analyser.out["file"]["arch"],
                                           self.static_analyser.out["file"]["bits"],
                                           self.exectime)
        # Execute the dynamic analyser

        self.dynamic_logs = self.dynamic.analyse()
        self.dynamic.cleanup()

    def kill(self):
        if hasattr(self, "dynamic"):
            self.dynamic.kill()


# For this think I may need to use ASYNC IO with queues
class Orchestrator:

    def __init__(self, max_threads, cfg):
        self.max_th = max_threads

        self.unit_jobs = []
        self.reports_list = []
        self.client = MongoConnection()
        self.client.connect()

        self.cfg = ut.get_config(cfg)
        self.results = []

    def execute_group(self, instances):
        pass

    def execute_ordered_group(self, list_instances):
        pass

    def execute_once(self, cmd):
        hash256 = ut.sha256_checksum(cmd["file"])
        val = self.client.get_data(hash256)
        if val is None:
            unit = Unit(self.cfg, "", cmd["file"], arch=cmd["arch"], bits=cmd["bits"])
            unit.start()
            unit.join()
            report = rep.ReportGenerator(self.cfg["schema_path"],  unit.dynamic_logs, unit.static_analyser.out,
                                         os.path.basename(cmd["file"]),
                                         outfolder=cmd["out"])
            unit.static_analyser.save_as_json(cmd["out"])
            rep_path = report.generate()
            result = {}
            result["reports_path"] = rep_path
            result["logs_path"] = unit.dynamic_logs
            result["filename"] = os.path.basename(cmd["file"])
            result["hash"] = val
            result["scan_count"] = 0
            self.client.put_data(result)
            return result
        else:
            return val

    def wait_finish(self):
        pass
