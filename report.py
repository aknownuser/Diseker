import Parser as pr
import os
import bs4

"""
class PDF(FPDF):

    def __init__(self):
        super().__init__()
        self.header = None

    def header(self, header=None):
        header=header

    def footer(self, footer=None):
        footer=footer

    def add_title(self, text):
        self.set_xy(0.0, .0)
        self.set_font('Arial', 'B', 19)
        self.cell(w=20.0, h=40.0, align='C', txt=text, border=0)

    def add_table(self, title, header, data=None):
        self.header = header
        for col in header:
            self.cell(w=40, h=7, text=col, border=1)

        if data is not None:
            for row in data:
                for val in row:
                    self.cell(w=40, h=6, text=val, border=1)

    def add_row(self, row):
        for val in row:
            self.cell(w=40, h=6, text=val, border=1)

    def end_table(self):
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, 'Page %s' % self.page_no(), 0, 0, 'C')
"""


class HTML:

    def __init__(self, template, name):
        self.fp_temp = open(template)
        self.soup = bs4.BeautifulSoup(self.fp_temp, "html.parser")
        self.name = name

    def put_general_info(self, info):
        self.soup.find(id="file_name").string = self.name
        self.soup.find(id="file_size").string = str(info["size"])
        self.soup.find(id="file_type").string = info["class"]
        self.soup.find(id="file_arch").string = info["arch"]
        self.soup.find(id="file_md5").string = info["md5"]
        self.soup.find(id="file_sha1").string = info["sha1"]
        self.soup.find(id="file_sha256").string = info["sha256"]

    def _rows_creation(self, rows, row_names):
        tbody = self.soup.new_tag("tbody")

        for row in rows:
            tr = self.soup.new_tag("tr")

            for name in row_names:
                th = self.soup.new_tag("th")
                if row[name] is not str:
                    th.string = str(row[name])
                else:
                    th.string = row[name]
                tr.append(th)
            tbody.append(tr)
        return tbody

    def put_static_strings(self, strings):
        col_names = ["section", "type", "length", "string"]
        # Set table of interesting strings
        self.soup.find(id="inter_strings_table").append(self._rows_creation(strings["inter"], col_names))

        # Set table for all strings.
        self.soup.find(id="all_strings_table").append(self._rows_creation(strings["all"], col_names))

    def put_functions(self, funcs):
        col_names = ["offset", "name", "size"]
        self.soup.find(id="known_func_table").append(self._rows_creation(funcs["known"], col_names))
        self.soup.find(id="n_known_func").string = str(funcs["cknown"])
        self.soup.find(id="n_unknown_func").string = str(funcs["cunknown"])

    def put_sections(self, sections):
        col_names = ["name", "addr", "size"]
        self.soup.find(id="sections_table").append(self._rows_creation(sections, col_names))

    def write(self):
        with open("Report/second.html", "w", encoding="utf-8") as fp:
            fp.write(str(self.soup))

        self.fp_temp.close()


class ReportGenerator:

    def __init__(self, schema, pth_dynamic_logs, static_logs, filename):
        self.schema = schema
        self.report = None
        self.pth_dynamic_logs = pth_dynamic_logs
        self.static_logs = static_logs

        self.filename = filename

        self._nevts = None
        self._sevts = None

        self._protocols = [pr.NTP, pr.ICMP, pr.DNS, pr.TELNET, pr.HTTP]

    def generate(self):
        self.report = HTML(self.schema, self.filename)

        # Populate the static logs
        self.report.put_general_info(self.static_logs["file"])
        self.report.put_static_strings(self.static_logs["strings"])
        self.report.put_functions(self.static_logs["func"])
        self.report.put_sections(self.static_logs["sections"])


        # Correlate the logs of the dynamic analysis

        self._nevts = pr.NetworkParser(os.path.join(self.pth_dynamic_logs, pr.NETWORK))
        self._sevts = pr.LogParser(os.path.join(self.pth_dynamic_logs, pr.SYSCALL))

        self._nevts.parse()
        self._sevts.parse()

        self._correlate_logs()

        # Populate the results

    def _correlate_logs(self):

        for key, ppid_events in self._sevts.proctree.items():
            for i, evt in enumerate(ppid_events[1]):
                if evt.network and evt.success:
                    # Get the type of sock created if network event is found

                    for prot in self._protocols:
                        try:
                            size, pos = self._nevts.get_pos_evts_address(prot, evt.get_address())

                            if size != 0:
                                self._sevts.proctree[key][1][i].index.append((prot, pos))
                        except Exception as e:
                            pass




if __name__ == "__main__":
    report = ReportGenerator("", "/home/pc/TFM/Code/Diseker/logs")
    report.generate()
