import re
import os


class Event:

    def __init__(self):
        self.time = ""
        self.syscall = ""
        self.ownership = list()
        self.command = ""
        self.arguments = list()
        self.arg_items = list()


class NetworkEvent:

    def __init__(self):
        self.time = ""
        self.src = ""
        self.dst = ""
        self.s_port = ""
        self.d_port = ""
        self.p = ""
        self.data = ""


class LogParser:

    def __init__(self, ppid, path):
        self.ppid = ppid
        self.path = path
        self.proctree = {}

    def parse(self):
        for root, dirs, files in os.walk(self.path, topdown=False):
            for name_fl in files:
                name_fl_plt = name_fl.split(".")
                pid = name_fl_plt[0]
                values = []
                if len(name_fl_plt) > 2:
                    values.append(name_fl_plt[1])

                self.proctree[pid] = (values, EventParser(os.path.join(root,name_fl), populate=True).event)

    def json(self):
        pass


class EventParser:

    def __init__(self, path_logs, populate=False):
        self._path = path_logs
        if populate:
            self.event = self.populate()

    def populate(self):
        events = []
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
                        if dict["fam"] == "inet":
                            evt.arg_items += [dict["fam"], dict["laddr"],dict["lport"]]
                        elif dict["fam"] == "netlink":
                            evt.arg_items += [dict["fam"], dict["nlnk-fam"], dict["nlnk-pid"]]

                    elif fields[0] == "type=SYSCALL":
                        dict = self._gen_dict(fields[4:], "=")
                        if ppid == "":
                            ppid = dict["ppid"]
                        evt.syscall = dict["syscall"]
                        evt.ownership = [dict["uid"], dict["suid"], dict["euid"]]
                        evt.command = dict["exe"]
                        evt.arguments = [dict["a0"], dict["a1"], dict["a2"], dict["a3"]]

                        # if dict["pid"] not in self._treelogs.keys():
                        #    self._treelogs[dict["pid"]] = []
                        evt.time = re.search("\d*/\d*/\d* \d*:\d*:\d*.\d*:\d*", line).group(0).split(" ")[1]
                        events.append(evt)

        return events

    def json(self):
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

    def __init__(self):
        self.data = []

    def get_entry(self):
        pass

    def parse(self):
        pass

    def json(self):
        pass


class TelnetNetworkParser(NetworkParser):

    def __init__(self):
        super.__init__()

    def parse(self):
        pass


if __name__ == "__main__":
    #parser_obj = EventParser("6043.logs", "6043",populate=True)
    parser_path = LogParser("2504", "Logs/")
    parser_path.parse()
    print("Hello")