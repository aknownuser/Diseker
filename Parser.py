import re
import os
import ThreadManagement as th
from pypacker import ppcap
from pypacker.layer4 import tcp, udp
from pypacker.layer3 import ip, icmp
from pypacker.layer12 import ethernet
from pypacker.layer567 import telnet, dns, ntp, http
import utils

NETWORK = "network"
SYSCALL = "syscalls"
INET = "inet"
#Todo IRC, FTP and RDP
ICMP = "ICMP"
TELNET = "TELNET"
DNS = "DNS"
NTP = "NTP"
HTTP = "HTTP"
SNORT = "SNORT"

class Tree:

    def __init__(self, value):
        self.value=value
        self.children= list()

    def print_level(self, level):
        spacing = "-" * level
        str=spacing + ""
        for child in self.children:
            str += "%s: %s\n" % (child[0], child[1])
            str += child.print_level(level+1)
        return str


class Event:

    def __init__(self):
        self.time = ""
        self.syscall = ""
        self.success = None
        self.network = False
        self.fullcmd = False
        self.ownership = list()
        self.command = ""
        self.arguments = list()
        self.arg_items = list()
        self.index = []

    def rep_values(self):
        return [self.time, self.syscall]+self.ownership+[self.arg_items, self.success]

    def get_address(self):
        if self.network and len(self.arg_items) > 1:
            return self.arg_items[1]
        else:
            if not self.network:
                raise Exception("Not a network event")
            else:
                raise Exception("Address unrecognized")

    def get_ownership_str(self):
        return "UID: %s \nSUID: %s\nGUID: %s" %(self.ownership[0], self.ownership[1], self.ownership[2])

    def get_arguments_str(self):
        string = ""
        for i, arg in enumerate(self.arguments):
            string += "p%d: %s\n" % (i, str(arg))
        return string

    def get_items_str(self):
        string = ""
        for i, arg in enumerate(self.arg_items):
            string += "- %s \n" % str(arg)
        return string

    def __str__(self):
        return "%s CALL=%s NET=%s SUCC=%s, %s, cmd=%s, arg=%s, items=%s, NetLogsIndex=%s"%(self.time, self.syscall, self.network,
                                                                          self.success, self.ownership, self.command,
                                                                          self.arguments, self.arg_items,self.index)


class NetworkEvent:

    def __init__(self):
        self.time = ""
        self.src = ""
        self.dst = ""
        self.s_port = ""
        self.d_port = ""
        self.p = ""
        self.data = ""

    def __init__(self, time, src, dst, s_port, d_port, p, data):
        self.time = time
        self.src = src
        self.dst = dst
        self.s_port = s_port
        self.d_port = d_port
        self.p = p
        self.data = data

    def contains_address(self, address):
        return address == self.src or address == self.dst

    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dest

    def __str__(self):
        return "[%s] %s: %s:%s -> %s:%s,  %s "%(self.p, self.time, self.src, self.s_port, self.dst, self.d_port, self.data)


class LogParser:

    def __init__(self, path):
        self.path = path
        self.proctree = {}

    def parse(self):
        for root, dirs, files in os.walk(self.path, topdown=False):
            for name_fl in files:
                name_fl_plt = name_fl.split(".")
                pid = name_fl_plt[0]
                values = ""
                if len(name_fl_plt) > 2:
                    values=name_fl_plt[1]

                self.proctree[pid] = (values, EventParser(os.path.join(root,name_fl), populate=True).event)

    def _get_base_command_pid(self, pid):
        _, evts = self.proctree[pid]
        cnt = 0
        evt = evts[cnt]
        while not evt.fullcmd and cnt < len(evts):
            cnt += 1
            evt = evts[cnt]

        if not evt.fullcmd:
            evt = None

        return evt

    def _get_base_command_evt(self, evts):
        cnt = 0
        evt = evts[cnt]
        while not evt.fullcmd and cnt < len(evts):
            cnt += 1
            evt = evts[cnt]

        if not evt.fullcmd:
            evt = None

        return evt

    def get_process_tree(self):
        keys = self.proctree.keys()
        proc_tree = {}

        for key in sorted(keys):
            res = None
            ppid, evts = self.proctree[key]
            base_evt = self._get_base_command_evt(evts)
            if base_evt is not None:
                res = (key, base_evt.command)
            else:
                res = (key, "")
            try:
                proc_tree[ppid].append(res)
            except Exception as e:
                proc_tree[ppid] = [res]

        return proc_tree

    def print_pid(self, key):
        pass

    def json(self):
        pass


class EventParser:

    def __init__(self, path_logs, populate=False):
        self._path = path_logs
        if populate:
            self.event = self.populate()

    def populate(self):
        events = []
        rel = 0
        with open(self._path) as lg:
            ppid = ""
            for event in self._each_chunk(lg, "----"):
                evt = Event()
                lines = event.split("\n")

                for line in lines:
                    if line == "":
                        continue
                    fields = line.split(" ")

                    if fields[0] in ("type=PROCTITLE", "type=CWD"):
                        continue
                    elif fields[0] == "type=PATH":
                        dict = self._gen_dict(fields[4:], "=")
                        evt.arg_items.append(dict["name"])

                    elif fields[0] == "type=SOCKADDR":
                        dict = self._gen_dict(fields[4:], "=")
                        try:
                            if dict["fam"] == "inet":
                                evt.arg_items += [dict["fam"], dict["laddr"],dict["lport"]]
                                evt.network = True
                            elif dict["fam"] == "netlink":
                                evt.arg_items += [dict["fam"], dict["nlnk-fam"], dict["nlnk-pid"]]
                        except KeyError as e:
                            evt.arg_items += [val for key, val in dict.items()]
                            evt.network = True
                    elif fields[0] == "type=EXECVE":
                        dict = self._gen_dict(fields[4:], "=")

                        argc = int(dict["argc"])
                        for pos in range(0, argc):
                            evt.command += dict["a%s"%pos]+" "
                        evt.fullcmd = True

                    elif fields[0] == "type=SYSCALL":
                        dict = self._gen_dict(fields[4:], "=")
                        if ppid == "":
                            ppid = dict["ppid"]
                        evt.syscall = dict["syscall"]
                        evt.ownership = [dict["uid"], dict["suid"], dict["euid"]]
                        if evt.command == "":
                            evt.command = dict["exe"]
                        evt.arguments = [dict["a0"], dict["a1"], dict["a2"], dict["a3"]]
                        if dict["success"] == "yes":
                            evt.success = True
                        else:
                            evt.success = False

                        # if dict["pid"] not in self._treelogs.keys():
                        #    self._treelogs[dict["pid"]] = []
                        raw_ts = re.search("\d*/\d*/\d* \d*:\d*:\d*.\d*", line).group(0).split(" ")
                        # Change from string to numerical
                        date =raw_ts[0].split("/")
                        date = [int(val) for val in date]
                        date[2] = date[2]+2000
                        hour = raw_ts[1].split(":")
                        d_hour= []
                        for i, val in enumerate(hour):
                            if i == len(hour)-1:
                                s=val.split(".")
                                micro=int(s[1])
                                s = int(s[0])
                                d_hour.append(s)
                                d_hour.append(micro)
                            else:
                                d_hour.append(int(val))
                        evt.time = utils.from_date_to_msepoch(date[2], date[1], date[0],d_hour[0],d_hour[1],d_hour[2],microseconds=d_hour[3])
                        evt.rel_time = rel
                        events.append(evt)
                        rel += 1

        return events

    def json(self):
        pass

    def save_as_json(self, path):
        pass

    def _gen_dict(self, fields,separator):
        dict={}
        for field in fields:
            aux = field.split(separator)
            if len(aux) == 2:
                dict[aux[0]] = aux[1]
        return dict

    def _each_chunk(self, stream, separator, buff_size=1028):
        buffer = ''
        while True:  # until EOF
            chunk = stream.read(buff_size)  # I propose 4096 or so
            if not chunk:  # EOF?
                yield buffer
                break
            buffer += chunk
            while True:  # until no separator is found
                try:
                    part, buffer = buffer.split(separator, 1)
                except ValueError:
                    break
                else:
                    yield part


class NetworkParser:

    def __init__(self, path):
        self.data = {}
        self.statistics = {}
        self._path=path

    def get_entry(self, key):
        return self.data[key]

    def _thread_func(self, file):
        if "dns" in file.lower():
            self.data[DNS] = dns_parser(file)

        elif "icmp" in file.lower():
            self.data[ICMP] = icmp_parser(file)

        elif "ntp" in file.lower():
            self.data[NTP] = ntp_parser(file)

        elif "telnet" in file.lower():
            self.data[TELNET] = telnet_parser(file)

        elif "http" in file.lower():
            self.data[HTTP] = http_parser(file)

    def parse(self, maxworkers=5):

        files = os.listdir(self._path)
        pool = th.ThreadPool(maxworkers)
        for file in files:
            pool.add_task(self._thread_func, os.path.join(self._path, file))
        pool.wait_completion()

        with open(os.path.join(self._path, "snort_alerts.txt")) as sn_alerts:
            self.data["SNORT"] = set()
            pattern = re.compile(r"\[\*\*] .* \[\*\*]")
            for line in sn_alerts.readlines():

                for match in pattern.findall(line):
                    self.data["SNORT"].add(match)


    def get_evts_address(self, protocol, adr):
        evt = []
        try:
            for i, val in enumerate(self.data[protocol]):
                if val.arg_items[0] == INET:
                    if val.arg_items[1] == adr:
                        evt.append(val)
            return evt

        except KeyError as e:
            return None

    def get_pos_evts_address(self, protocol, adr):
        pos = []
        try:

            for i, val in enumerate(self.data[protocol]):
                if val.contains_address(adr):
                    pos.append(i)
            return len(pos), pos
        except KeyError as e:
            return len(pos), pos


    def json(self):
        pass


def dns_parser(filename):
    reader = ppcap.Reader(filename=filename)
    events = []
    for ts, buf in reader:
        ts = round(int(ts)/1000000)

        eth = ethernet.Ethernet(buf)
        iply = eth[ethernet.Ethernet, ip.IP]
        udply = eth[ethernet.Ethernet, ip.IP, udp.UDP]
        dns_ent = eth[ethernet.Ethernet, ip.IP, udp.UDP, dns.DNS]
        if dns_ent is not None:
            populate = {}
            aux = {}
            if dns_ent.answers_amount != 0:
                populate["ANS"] = []
                for a in dns_ent.answers:
                    aux["addr"] = a.address_s
                    aux["name"] = a.name_s
                    aux["type"] = a.type
                    populate["ANS"].append(aux)

                events.append(NetworkEvent(ts, iply.src_s, iply.dst_s, udply.sport, udply.dport, "DNS", populate))

            elif dns_ent.questions_amount != 0:
                populate["REQ"] = []
                aux = {}
                for q in dns_ent.queries:
                    aux["name"] = q.name_s
                    aux["type"] = q.type
                    populate["REQ"].append(aux)
                events.append(NetworkEvent(ts, iply.src_s, iply.dst_s, udply.sport, udply.dport, "DNS", populate))

    return events


def icmp_parser(filename):
    reader = ppcap.Reader(filename=filename)
    icmp_events = []
    for ts, buf in reader:
        ts = round(int(ts) / 1000000)
        eth = ethernet.Ethernet(buf)
        iply = eth[ethernet.Ethernet, ip.IP]
        icmp_obj = eth[ethernet.Ethernet, ip.IP, icmp.ICMP]
        if icmp_obj is not None:
            if icmp_obj.type == icmp.ICMP_ECHO_REPLY:
                icmp_events.append(NetworkEvent(ts, iply.src_s, iply.dst_s, 0, 0, "ICMP", "REPLAY"))
            elif icmp_obj.type == icmp.ICMP_ECHO:
                icmp_events.append(NetworkEvent(ts, iply.src_s, iply.dst_s, 0, 0, "ICMP", "ECHO"))
            elif icmp_obj.type == icmp.ICMP_UNREACH:
                icmp_events.append(NetworkEvent(ts, iply.src_s, iply.dst_s, 0, 0, "ICMP", "UNREACHED"))

    return icmp_events


def ntp_parser(filename):
    reader = ppcap.Reader(filename=filename)
    ntp_events = []
    count = 0
    for ts, buf in reader:
        ts = round(int(ts) / 1000000)
        eth = ethernet.Ethernet(buf)
        iply = eth[ethernet.Ethernet, ip.IP]
        udply = eth[ethernet.Ethernet, ip.IP, udp.UDP]
        ntp_obj = eth[ethernet.Ethernet, ip.IP, udp.UDP, ntp.NTP]

        if ntp_obj is not None:
            if ntp_obj.DIR_SAME:
                aux = NetworkEvent(ts, iply.src_s, iply.dst_s, udply.sport, udply.dport, "NTP", 1)
                item = ntp_events.__getitem__(aux)
                if item == None:

                    ntp_events.append(aux)
                else:
                    item.data += 1
    return ntp_events


def telnet_parser(filename):
    reader = ppcap.Reader(filename=filename)
    stoc=[]
    ctos=[]
    for ts, buf in reader:
        ts = round(int(ts) / 1000000)
        eth = ethernet.Ethernet(buf)
        iply = eth[ethernet.Ethernet, ip.IP]
        tcply = eth[ethernet.Ethernet, ip.IP, tcp.TCP]
        telnet_obj = eth[ethernet.Ethernet, ip.IP, tcp.TCP, telnet.Telnet]
        if telnet_obj is not None:
            if tcply.sport == 23:
                stoc.append(NetworkEvent(ts, iply.src_s, iply.dst_s, tcply.sport, tcply.dport, "Telnet",
                                            telnet_obj.telnet_data))
            else:
                ctos.append(NetworkEvent(ts, iply.src_s, iply.dst_s, tcply.sport, tcply.dport, "Telnet",
                                            telnet_obj.telnet_data))
        del eth
        del iply
        del tcply
        del telnet_obj

    def data_parser(tel_data):
        res=""
        for byte_v in tel_data:
            try:
                res += str(byte_v, 'ascii')
            except:
                pass
        return res

    def message_grouping(stream, s):
        result = []
        cnt = 0
        evt_cnt = cnt
        while cnt < len(stream):
            val = data_parser(stream[cnt].data)

            if s in val or len(val) > len(s):
                stream[cnt].data = val
                result.append(stream[cnt])
                cnt += 1
            elif val != '':
                aux = ""
                cnt += 1
                evt_cnt = cnt
                while cnt < len(stream) and aux != s:
                    aux = data_parser(stream[cnt].data)
                    if aux != '':
                        val += aux
                    cnt += 1

                stream[evt_cnt].data = val
                result.append(stream[evt_cnt])
            else:
                cnt += 1

        return result

    result_stoc = message_grouping(stoc, "\r\n")
    result_ctos = message_grouping(ctos, "\r\x00")
    result = result_stoc + result_ctos
    result.sort(key=lambda x: x.time)
    return result


def http_parser(filename):
    reader = ppcap.Reader(filename=filename)
    result = []
    for ts, buf in reader:
        ts = round(int(ts) / 1000000)
        eth = ethernet.Ethernet(buf)
        iply = eth[ethernet.Ethernet, ip.IP]
        tcply = eth[ethernet.Ethernet, ip.IP, tcp.TCP]
        http_obj = eth[ethernet.Ethernet, ip.IP, tcp.TCP, http.HTTP]

        if http_obj is not None:
            result.append(NetworkEvent(ts, iply.src_s, iply.dst_s, tcply.sport, tcply.dport, "HTTP",
                                            http_obj.startline))

    return result

if __name__ == "__main__":
    #parser_obj = EventParser("6043.logs", "6043",populate=True)
    #parser_path = LogParser("2504", "Logs/")
    #parser_path.parse()
    #network = NetworkParser("test/funny")
    #network.parse()
    rs = http_parser("test/my_pc_traffic.pcap")

    print("Hello")