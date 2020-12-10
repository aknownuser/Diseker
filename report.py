import Parser as pr
import os
import bs4
import shutil
from matplotlib import pyplot as plt
import utils as ut
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

    def _rows_creation_obje(self, rows, row_names):

        tbody = self.soup.new_tag("tbody")

        for row in rows:
            tr = self.soup.new_tag("tr")

            for name in row_names:
                th = self.soup.new_tag("td")
                if row.__dict__[name] is not str:
                    th.string = str(row.__dict__[name])
                else:
                    th.string = row.__dict__[name]
                tr.append(th)
            tbody.append(tr)
        return tbody

    def _rows_creation(self, rows, row_names):
        tbody = self.soup.new_tag("tbody")

        for row in rows:
            tr = self.soup.new_tag("tr")

            for name in row_names:
                th = self.soup.new_tag("td")
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

    def put_snort_alerts(self, alert_set):
        root = self.soup.find(id="snort_rules")
        if len(alert_set) == 0:
            div = self.soup.new_tag("div", **{'class': 'card-header alert-info', 'role': 'alert'})
            div.string = "No alerts were triggered"
            root.append(div)
        else:
            for alert in alert_set:
                div = self.soup.new_tag("div", **{'class': 'card-header alert-warning', 'role': 'alert'})
                div.string = alert
                root.append(div)

    def put_icmp(self, icmp):
        col_names = ["src","dst","data"]
        self.soup.find(id="icmp_table").append(self._rows_creation_obje(icmp, col_names))

    def put_ntp(self, ntp):
        col_names = ["src","dst","data"]
        self.soup.find(id="ntp_table").append(self._rows_creation_obje(ntp, col_names))

    def put_telnet(self, telnet):
        col_names = ["src", "dst", "data"]
        self.soup.find(id="ntp_table").append(self._rows_creation_obje(telnet, col_names))

    def put_http(self, http):
        col_names = ["src", "dst", "data"]
        self.soup.find(id="ntp_table").append(self._rows_creation_obje(http, col_names))

    def put_dns(self, dns):
        col_names = ["src", "dst", "data"]

        tbody = self.soup.new_tag("tbody")

        for row in dns:
            tr = self.soup.new_tag("tr")

            for name in col_names:
                th = self.soup.new_tag("td")
                if name != "data":
                    if row.__dict__[name] is not str:
                        th.string = str(row.__dict__[name])
                    else:
                        th.string = row.__dict__[name]
                else:
                    try:
                        answer = row.__dict__[name]["ANS"]
                        holder = ""
                        th.string = "Answer"
                        tr.append(th)
                        th = self.soup.new_tag("td")

                        for ans in answer:
                            holder += "Type: %s - %s -> %s\n" % (str(ans["type"]), ans["name"], ans["addr"])
                        pre = self.soup.new_tag("pre")
                        pre.string = holder

                        th.append(pre)

                    except Exception as e:

                        answer = row.__dict__[name]["REQ"]
                        holder = ""
                        th.string = "Query"
                        tr.append(th)
                        th = self.soup.new_tag("td")

                        for ans in answer:
                            holder += "Type: %s - %s \n" % (str(ans["type"]), ans["name"])
                        pre = self.soup.new_tag("pre")
                        pre.string = holder

                        th.append(pre)

                tr.append(th)
            tbody.append(tr)

        self.soup.find(id="dns_all_table").append(tbody)

    def put_entropy_image(self, entropy, path):
        plt.figure(figsize=(8, 4))
        plt.plot([x/1000 for x,_ in entropy ], [y for _,y in entropy])
        plt.title("Entropy of the file")
        plt.xlabel("Step in file (kb)")
        plt.ylabel("Entropy")
        plt.savefig(os.path.join(path, "entropy.png"), dpi=150)

    def put_process_tree(self, process_tree, inde=' '):

        def recursive_tree(parent_in, tree, indent=''):
            text_in = ""
            base = None
            if isinstance(parent_in, tuple):
                text_in = "%s - %s\n" % (str(parent_in[0]), str(parent_in[1]))
                base = parent_in[0]
            else:
                text_in = parent_in
                base = text_in

            if base not in tree.keys():
                return text_in

            for child in tree[base][:-1]:
                text_in += indent + '|-'
                text_in += recursive_tree(child, tree, indent + '| ')
            child = tree[base][-1]
            text_in += indent + '`-'
            text_in += recursive_tree(child, tree, indent + '  ')
            return text_in

        parent = ''
        text = recursive_tree(parent, process_tree, indent=inde)
        self.soup.find(id="process_tree").string = text

    def _gen_card_collaps(self, id, title, table=False, colnames=None):
        """
        Generates a collapsable card with internal table if needed or just an empty target div with no table header,
        This can be used to create that structure on the fly (Could consider factory pattern to do this in the future )
        :param id:
        :param title:
        :param table:
        :param colnames:
        :return:
        """
        b_div = self.soup.new_tag("div", **{'class': 'card'})
        head_div = self.soup.new_tag("div", id="%s_header" % id, **{'class': 'card-header'})
        h5 = self.soup.new_tag("h5", **{'class':"mb-0"})
        btn = self.soup.new_tag("button", **{'class': 'btn', 'data-toggle': 'collapse', 'data-target': '#%s_target'%id,
                                             'area-controls': '%s_target'%id})
        btn.string = title
        h5.append(btn)
        head_div.append(h5)
        b_div.append(head_div)

        # Create the body of the card
        div_to_populate = self.soup.new_tag("div", id="%s_to_populate"%id)

        target_div =  self.soup.new_tag("div", id="%s_target"%id, **{'class': 'collapse', 'area-labelledby': '%s_header'%id})
        card_body = self.soup.new_tag("div", **{'class': 'card-body'})

        if table:
            if colnames is None:
                raise Exception("Can't create a table header without column names")
            # Create the columns header
            tr = self.soup.new_tag("tr")
            for name in colnames:
                th = self.soup.new_tag("th", **{'scope': 'col'})
                th.string = name
                tr.append(th)

            thead = self.soup.new_tag("thead")
            thead.append(tr)

            table_t = self.soup.new_tag("table", **{'class': 'table table-hover'})
            # Add the header and the field to be populated afterwords to the table
            table_t.append(thead)
            table_t.append(div_to_populate)
            card_body.append(table_t)
        else:
            #The table is not being created, then the field to populte needs to be set to card_body
            card_body.append(div_to_populate)
        # Add the card body to the target div
        target_div.append(card_body)
        # Add the target div to the base div
        b_div.append(target_div)

        return b_div, div_to_populate

    # TODO add the network events of each syscall. NOT WORKING PROPERLY
    def put_syscalls_per_pid(self, proc_events):

        col_names = ["syscall","success" "ownership", "arg_items", "arguments"]
        col_pseudo_names = ["Syscall", "Success" , "Ownership", "Items accessed", "Parameters"]
        pids = sorted(proc_events.keys())
        root = self.soup.find(id="detailed_processes")

        for pid in pids:
            # Create the table title so its recognised
            tag_id = ut.get_rand_string(5)
            base_div, div_to_populate = self._gen_card_collaps(tag_id, "System calls", True, col_pseudo_names)
            div_head = self.soup.new_tag("h6")

            # Add main fields to the root div
            root.append(div_head)
            root.append(base_div)

            ppid, events = proc_events[pid]

            tbody = self.soup.new_tag("tbody")

            for row in events:
                tr = self.soup.new_tag("tr")

                if row.fullcmd:
                    div_head.string = "PID: %s, PPID: %s, CMD: %s" % (pid, ppid, row.command)
                # Put the name of the syscall and if successful
                td = self.soup.new_tag("td")
                td.string = row.syscall
                tr.append(td)
                td = self.soup.new_tag("td")
                td.string = str(row.success)
                tr.append(td)
                # Set pre and put ownership
                pre = self.soup.new_tag("pre")
                pre.string = row.get_ownership_str()
                td = self.soup.new_tag("td")
                td.append(pre)
                tr.append(td)

                # Set pre and put accessed items
                pre = self.soup.new_tag("pre")
                pre.string = row.get_items_str()
                td = self.soup.new_tag("td")
                td.append(pre)
                tr.append(td)

                # Set pre and put parameters
                pre = self.soup.new_tag("pre")
                pre.string = row.get_arguments_str()
                td = self.soup.new_tag("td")
                td.append(pre)
                tr.append(td)

                tbody.append(tr)

            div_to_populate.append(tbody)

    def write(self, path):

        with open(os.path.join(path, "report.html"), "w", encoding="utf-8") as fp:
            fp.write(str(self.soup))

        self.fp_temp.close()


class ReportGenerator:

    def __init__(self, schema, pth_dynamic_logs, static_an, filename, outfolder="."):
        self.schema = schema
        self.report = None
        self.pth_dynamic_logs = pth_dynamic_logs
        self.static_an = static_an

        self.filename = filename

        self.outfolder = outfolder
        # Copy all the template in the destination folder
        shutil.copytree("Report", os.path.join(self.outfolder, self.filename))

        self._nevts = None
        self._sevts = None

        self._protocols = [pr.NTP, pr.ICMP, pr.DNS, pr.TELNET, pr.HTTP]

    def generate(self):
        self.report = HTML(os.path.join(self.schema, "template.html"), self.filename)

        # Populate the static logs
        self.report.put_general_info(self.static_an["file"])
        self.report.put_entropy_image(self.static_an["entropy"], path=os.path.join(self.outfolder, self.filename))
        self.report.put_static_strings(self.static_an["strings"])
        self.report.put_functions(self.static_an["func"])
        self.report.put_sections(self.static_an["sections"])

        # Save as json
        #self.static_an.save_as_json(self.outfolder)

        # Correlate the logs of the dynamic analysis

        self._nevts = pr.NetworkParser(os.path.join(self.pth_dynamic_logs, "logs", pr.NETWORK))
        self._sevts = pr.LogParser(os.path.join(self.pth_dynamic_logs, "logs", pr.SYSCALL))

        self._nevts.parse()
        self._sevts.parse()
        self._correlate_logs()

        # Populate file with dynamic logs
        # Process tree
        self.report.put_process_tree(self._sevts.get_process_tree())
        #Syscalls
        self.report.put_syscalls_per_pid(self._sevts.proctree)

        # Put Snort alerts
        self.report.put_snort_alerts(self._nevts.data[pr.SNORT])

        # Put ICMP data
        self.report.put_icmp(self._nevts.data[pr.ICMP])

        # Put NTP data
        self.report.put_ntp(self._nevts.data[pr.NTP])

        # Put DNS data
        self.report.put_dns(self._nevts.data[pr.DNS])

        # Put Telnet
        self.report.put_telnet(self._nevts.data[pr.TELNET])

        # put http
        #self.report.put_http(self._nevts.data[pr.HTTP])

        # Write report
        self.report.write(os.path.join(self.outfolder, self.filename))

        return self.outfolder

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