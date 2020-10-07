import re

class Node:

    def __init__(self, types, items):
        self.type=types
        self.items= items

class Event:

    def __init__(self):
        self.syscall = ""
        self.ownership = list()
        self.command = ""
        self.arguments = list()
        self.arg_items = list()


class EventParser:

    def __init__(self, path_logs, pid, populate=False):
        self._path = path_logs
        self._treelogs = {}
        if populate:
            self.populate()

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
                        events.append(evt)

        return events

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



if __name__ == "__main__":
    parser_obj = Parser("6043.logs", "6043",populate=True)