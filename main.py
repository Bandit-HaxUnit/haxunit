"""
Updates
- Added Web UI
- Added Local DB (SQLite)
- All info is now being stored also in Local DB
- Naabu uses full list of subdomains instead of IP's found from DNScan

To-do:
- Extend naabu portscan with also IP's found after httpx scan
- Add reverse DNS for all IP's discovered by HTTPx
"""

import subprocess
from os import geteuid

class color():
    HEADER = '\033[95m'
    OK = '\033[94m'
    FAIL = '\033[91m'
    SUCCESS = '\033[92m'
    RESET = '\033[0m'
    WARNING = '\033[93m'
    BOLD = '\033[1m'

stop = False
for package_requirement, apt_name in (
        ("unzip", "unzip"),
        ("pip3", "python3-pip"),
        ("git", "git"),
        ("docker", "docker.io"),
    ):
    retval = subprocess.call(["which", package_requirement])
    if retval != 0:
        print(f"{package_requirement} not installed:\napt install {apt_name}\n")
        if geteuid() == 0:
            print(f"Running as root - installing automatically..")
            subprocess.call([f"apt install -y {apt_name}"], shell=True)
        else:
            stop = True

if stop:
    exit()

subprocess.call(["clear"])

from requests import get, post
import sqlite3 as sl

from json import dumps, loads
import urllib3
urllib3.disable_warnings()
from subprocess import PIPE, Popen
from os.path import exists
from os import mkdir
import argparse
from datetime import datetime
import socket

class HaxUnit:
    sqlite = sl.connect('haxunit-scans.db', isolation_level=None)

    c99_key = ""

    acunetix_email = ""
    acunetix_password = ""
    yes_answers = ("y", "yes", "ye")

    all_subdomains = []
    all_ports = []
    all_subdomains_up = []
    timestamp = datetime.now()

    def __init__(self, site, mode, verbose, python_bin, dir_path, iserver, itoken, acu_session, yolo, update, install_all):
        self.site = site
        self.verbose = verbose
        self.quick = True if mode == "quick" else False
        self.python_bin = python_bin
        self.dir_path = dir_path
        self.yolo = yolo
        self.update = update
        self.install_all = install_all

        self.iserver = iserver
        self.itoken = itoken

        self.acu_session = acu_session

        with self.sqlite:
            self.sqlite.execute("""
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    domain TEXT
                );
            """)

            self.sqlite.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    domain_id TEXT,
                    timestamp TEXT,
                    all_subdomains TEXT,
                    all_subdomains_up TEXT,
                    all_ips TEXT,
                    nrich_portscan TEXT,
                    gau_unfurl_domains TEXT,
                    httpx_result TEXT,
                    dnscan_domains TEXT,
                    dnscan_ips TEXT,
                    subfinder_subdomains TEXT,
                    crtsh_subdomains TEXT,
                    naabu_portscan TEXT,
                    nuclei_result TEXT,
                    loot TEXT,
                    status TEXT
                );
            """)

        self._cmd("clear")

        print(color.BOLD)
        print("""                                                                         
  _    _            _    _       _ _   
 | |  | |          | |  | |     (_) |  
 | |__| | __ ___  _| |  | |_ __  _| |_ 
 |  __  |/ _` \ \/ / |  | | '_ \| | __|
 | |  | | (_| |>  <| |__| | | | | | |_ 
 |_|  |_|\__,_/_/\_\\____/|_| |_|_|\__|
                                       
                                       v3.0 by the butcher""")

        print()

        if self.install_all:
            self._install_all()
            self._print("Init", "All tools are successfully installed - good luck!", color.SUCCESS)
            exit()
        elif not self.site:
            self._print("Init", "Please pass a domain (-d)", color.FAIL)
            exit()

        print("\n[HaxUnit] Target:", site)
        print(color.RESET)



    def _print(self, title="", text="", color_type=""):
        print(f"[{color.BOLD}HaxUnit{color.RESET}] [{color.OK}{title}{color.RESET}] {color_type}{text}{color.RESET}")

    def _add_domain_to_db(self):

        with self.sqlite:
            data = list(self.sqlite.execute(f"SELECT id FROM domains WHERE domain = '{self.site}'"))
            if data:
                self.domain_id = data[0][0]
                self._print("Local DB", f"Domain scanned previously - ID: {self.domain_id}")
            else:
                self._print("Local DB", "Domain not scanned previously - adding to `domains` table")

                with self.sqlite:
                    self.sqlite.execute(f"INSERT INTO domains (id, domain) values (NULL, '{self.site}')")

                self.domain_id = list(self.sqlite.execute(f"SELECT id FROM domains WHERE domain = '{self.site}'"))[0][0]
                self._print("Local DB", f"Domain ID: {self.domain_id}")

    def _create_scan_in_db(self):

        with self.sqlite:
            self.sqlite.execute(f"""
                INSERT INTO scans
                    (id, domain_id, timestamp, all_subdomains, all_subdomains_up, all_ips, nrich_portscan, gau_unfurl_domains, httpx_result, dnscan_domains,
                    dnscan_ips, subfinder_subdomains, crtsh_subdomains, naabu_portscan, nuclei_result, loot, status)
                values
                    (NULL, '{self.domain_id}', '{self.timestamp}', "", "", "", "", "", "", "", "", "", "", "", "", "", "1")
            """)

            self.scan_id = list(self.sqlite.execute(f"SELECT id FROM scans WHERE domain_id = '{self.domain_id}'"))[-1][0]
            self._print("Local DB", f"Created row to save scan results with ID: {self.scan_id}")

    def _install(self, name, download, file, bin, tar_gz=False):
        if not exists(f"tools/{name}") or self.update:
            for text, cmd in (
                    (f"Downloading {name}", f"wget {download} --quiet"),
                    ("Extracting tar.gz", f"tar xf {file}") if tar_gz else ("Extracting zip", f"unzip {file}"),
                    (f"Moving {name} to bin", f"sudo mv {bin} /usr/local/bin/{name}") if name != "getau" else (f"Moving {name} to bin", f"sudo mv {bin} /usr/local/bin/getau"),
                    ("Cleanup", f"rm -f {file} README.md LICENSE.md LICENSE"),
                    ("-", f"touch tools/{name}")
            ):
                if text and cmd:
                    self._print("Installer", f"{name} - {text}")
                    self._cmd(cmd)

            if name == "nuclei":
                self._cmd("nuclei -update-templates -update-directory templates")
                self._cmd("nuclei --update")


    def _cmd(self, cmd):
        cmd = " ".join(cmd.split())
        if self.verbose:
            self._print("CMD", cmd)
        subprocess_cmd = Popen(
            cmd,
            shell=True,
            stdout=PIPE
            # stdout=PIPE if self.verbose else subprocess.DEVNULL,
            # stderr=PIPE if self.verbose else subprocess.STDOUT
        )
        subprocess_return = subprocess_cmd.stdout.read().decode("utf-8").strip()
        if subprocess_return:
            print(subprocess_return)
        return subprocess_return

    def _ask(self, question):
        if self.yolo:
            return True
        return True if input(question).lower() in self.yes_answers else False

    def _read(self, file_name, text=False):
        try:
            if text:
                return "\n".join(list(set([_.strip() for _ in open(f"{self.dir_path}/{file_name}", "r").readlines()])))
            else:
                return list(set([_.strip() for _ in open(f"{self.dir_path}/{file_name}", "r").readlines()]))
        except FileNotFoundError:
            if text:
                return "FileNotFoundError"
            else:
                return []


    def _write_subdomains(self, mode="a"):
        with open(f"{self.dir_path}/all_subdomains.txt", mode) as f:
            all_subdomains_text = "\n".join([_ for _ in list(set(self.all_subdomains)) if _])
            f.write(all_subdomains_text)

            with self.sqlite:
                self.sqlite.execute(f"UPDATE scans SET all_subdomains = '{all_subdomains_text}' WHERE id = {self.scan_id}")


    def _dnscan(self):
        if not exists(f"tools/dnscan"):
            for text, cmd in (
                    ("Cloning dnscan", "git clone https://github.com/rbsec/dnscan.git tools/dnscan"),
                    ("Installing python3 requirements", f"{self.python_bin} -m pip install -r tools/dnscan/requirements.txt"),
            ):
                self._print("DNScan", text)
                self._cmd(cmd)

        self._cmd(f"""{self.python_bin} tools/dnscan/dnscan.py -r -t 100 -d {self.site} -R 1.1.1.1 \
                     -o {self.dir_path}/dnscan_domains.txt -i {self.dir_path}/dnscan_ips.txt \
                     -w tools/dnscan/subdomains-100.txt \
                     {"" if self.verbose else "> /dev/null"}""")

        # {'subdomains-100.txt' if self.quick else 'subdomains-100.txt'}
        # 1000 takes quite some time - so disabled this for now

        try:
            subdomains = list(set([_.split(" - ")[1].strip() for _ in open(f"{self.dir_path}/dnscan_domains.txt", "r").readlines() if ' - ' in _]))

            self._ask_to_add(subdomains, reask_same_tld=True)

            with self.sqlite:
                dnscan_domains_text = "\n".join(subdomains)
                self.sqlite.execute(f"UPDATE scans SET dnscan_domains = '{dnscan_domains_text}' WHERE id = {self.scan_id}")

                dnscan_ips_text = self._read("dnscan_ips.txt", True)
                self.sqlite.execute(f"UPDATE scans SET dnscan_ips = '{dnscan_ips_text}' WHERE id = {self.scan_id}")
        except FileNotFoundError:
            pass

    def _nrich(self):
        self._cmd(f"nrich  {self.dir_path}/all_ips.txt > {self.dir_path}/nrich_result.txt")

        nrich_result_text = self._read("nrich_result.txt", True)

        with self.sqlite:
            self.sqlite.execute(f"UPDATE scans SET nrich_portscan = '{nrich_result_text}' WHERE id = {self.scan_id}")

    def _httpx(self):
        self._cmd(f"httpx -l {self.dir_path}/all_subdomains.txt {'' if self.verbose else '-silent'} -o {self.dir_path}/httpx_result.csv -td -cdn -csv -timeout 15")

        awk_cmd = """awk -F "," {'print $9 "," $10 "," $11 "," $12 "," $13 "," $14 "," $16 "," $20 "," $23 "," $32 '}"""
        self._cmd(f"cat {self.dir_path}/httpx_result.csv | {awk_cmd} > {self.dir_path}/httpx_parsed.csv")

        awk_cmd_2 = """awk -F "," {'print $3'} | awk -F ":" {'print $1 ":" $2'} """
        self._cmd(f"cat {self.dir_path}/httpx_parsed.csv | {awk_cmd_2} | tail -n +2 > {self.dir_path}/all_subdomains_up.txt")

        awk_cmd_3 = """awk -F "," {'print $1'}"""
        self._cmd(f"cat httpx_parsed.csv | {awk_cmd_3} | tail -n +2 | tr -d '[]' | sort -u >> {self.dir_path}/httpx_ips.txt")

        self._cmd(f"cat {self.dir_path}/httpx_ips.txt {self.dir_path}/dnscan_ips.txt | sort -u > {self.dir_path}/all_ips.txt")

        self.all_subdomains_up = self._remove_unwanted_domains(self._read("all_subdomains_up.txt"))

        all_subdomains_up_text = self._read("all_subdomains_up.txt", True)
        httpx_parsed_text = self._read("httpx_parsed.csv", True)
        all_ips_text = self._read("all_ips.txt", True)

        with self.sqlite:
            self.sqlite.execute(f"UPDATE scans SET all_subdomains_up = '{all_subdomains_up_text}' WHERE id = {self.scan_id}")
            self.sqlite.execute(f"UPDATE scans SET all_ips = '{all_ips_text}' WHERE id = {self.scan_id}")
            self.sqlite.execute(
                f"UPDATE scans SET httpx_result = ? WHERE id = ?",
                (httpx_parsed_text, self.scan_id, )
            )



    def _naabu(self):
        input_file = self._read("all_subdomains.txt")

        if not input_file:
            self._print("Naabu", "all_subdomains.txt is empty - skipping")
        else:

            self._cmd(f"sudo naabu -l {self.dir_path}/all_subdomains.txt -p 80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9943,9980,9981,12443,16080,18091,18092,20720,28017 -c 100 {'' if self.verbose else '-silent'} -no-color -exclude-cdn -o {self.dir_path}/naabu_portscan.txt")

            try:
                ip_ports = self._read("naabu_portscan.txt")
                self._ask_to_add(ip_ports)
                self.all_ports.extend(ip_ports)

                with self.sqlite:
                    naabu_portscan_text = self._read("naabu_portscan.txt", True)
                    self.sqlite.execute(f"UPDATE scans SET naabu_portscan = '{naabu_portscan_text}' WHERE id = {self.scan_id}")
            except FileNotFoundError:
                pass


    def _subfinder(self):
        self._print("Subfinder", "Process started")
        self._cmd(f"subfinder -d {self.site} {'' if self.verbose else '-silent'} -recursive -t 100 -nW -nC -all -o {self.dir_path}/subfinder_subdomains.txt")
        self._ask_to_add(self._read("subfinder_subdomains.txt"))

        with self.sqlite:
            subfinder_subdomains_text = self._read("subfinder_subdomains.txt", True)
            self.sqlite.execute(f"UPDATE scans SET subfinder_subdomains = '{subfinder_subdomains_text}' WHERE id = {self.scan_id}")


    def _crtsh(self):
        self._print("crt.sh", "Gathering subdomains from crt.sh")

        try:
            response = get(f"https://crt.sh/?q=.{self.site}&output=json").json()
            subdomains = list(set([_["common_name"] for _ in response if '*' not in _]))

            with self.sqlite:
                subdomains_text = "\n".join(subdomains)
                self.sqlite.execute(f"UPDATE scans SET crtsh_subdomains = '{subdomains_text}' WHERE id = {self.scan_id}")

            self._ask_to_add(subdomains)
        except:
            self._print("crt.sh", "Request to crt.sh failed", color.FAIL)


    def _nuclei(self):
        self._cmd(f"""nuclei -l {self.dir_path}/all_subdomains_up.txt
                        -t templates
                        {"-stats -metrics" if self.verbose else "-silent "} 
                        -o {self.dir_path}/nuclei_result.txt
                        -bulk-size 100
                        -c 100
                        {'-severity high,critical' if self.quick else ""} 
                        -no-timestamp
                        {f"-interactsh-url {self.iserver}" if self.iserver else ""}
                        {f"-itoken {self.itoken}" if self.itoken else ""}
                    """)

        self._cmd("""grep -v "aws\-bucket\-service\|google\-bucket\-service\|nginx\-version\|unencrypted\-bigip\-ltm\-cookie\|\-detect\|missing\-\|display\-via\-header\|detect\-options\|old\-copyright\|iis\-shortname\|HTTP\-TRACE\|robots\-txt\|generic\-tokens\|package\-json\|composer\-config\|fingerprinthub" %s/nuclei_result.txt | awk {'print $3 " " $1 " " $4 " " $5'} | sort > %s/loot.txt""" % (self.dir_path, self.dir_path))

        with self.sqlite:
            nuclei_result_text = self._read("nuclei_result.txt", True)
            self.sqlite.execute(f"UPDATE scans SET nuclei_result = '{nuclei_result_text}' WHERE id = {self.scan_id}")

            loot_text = self._read("loot.txt", True)
            self.sqlite.execute(f"UPDATE scans SET loot = '{loot_text}' WHERE id = {self.scan_id}")

    def _check_ip(self):
        ipaddress = get("http://ifconfig.me/ip").text

        ip_check = get(f"https://blackbox.ipinfo.app/lookup/{ipaddress}").text

        if ip_check != "Y":
            if self._ask(f"{color.WARNING}(!) Your IP ({ipaddress}) does not seem to be a proxy or VPN, would you like to quit? {color.RESET}"):
                exit()

    def _remove_unwanted_domains(self, domain_list):
        unwanted_domains = (
            "cloudfront.net",
            "googleusercontent.com",
            "akamaitechnologies.com",
            "amazonaws.com",
            "salesforce-communities.com",
            "cloudflaressl.com",
            "cloudflare.net",
            "cloudflare.com",
            "transip.nl",
            "transip.eu",
            "transip.net",
            "azure-dns.com",
            "azure-dns.org",
            "azure-dns.net",
        )

        return [_ for _ in domain_list if (not _.endswith(unwanted_domains) and not _.startswith("*"))]

    def _ask_to_add(self, ask_domains, reask_same_tld=False):
        ask_domains = [domain for domain in list(set(ask_domains)) if domain not in self.all_subdomains]
        ask_domains = self._remove_unwanted_domains(ask_domains)

        if ask_domains:
            print()
            for d in ask_domains:
                print(d)
            print()

            if self._ask(f"\nWould you like to add {len(ask_domains)} domains to the list? "):
                self.all_subdomains.extend(ask_domains)
                return True
            elif reask_same_tld:
                self._ask_to_add(list(set([_ for _ in ask_domains if _.endswith(self.site)])))
                return True
        return False

    def _cleanup(self):
        for file in (
            # "all_subdomains.txt",
            #"all_subdomains_up.txt",
            # "dnscan_ips.txt",
            # "dnscan_domains.txt",
            # "subfinder_subdomains.txt",
        ):
            self._cmd(f"rm -f {self.dir_path}/{file}")


    def _sonar_search(self):
        self._print("Sonar search", "Process started")

        try:
            domain_name = self.site.split(".")[0]

            all_sonar_subdomains = []

            sonar_domains = loads(get(f"https://sonar.omnisint.io/tlds/{domain_name}", timeout=15).text)

            for domain in sonar_domains:
                sonar_subdomains = get(f"https://sonar.omnisint.io/subdomains/{domain}", timeout=15).text.strip()
                if sonar_subdomains != "null":
                    all_sonar_subdomains.extend(loads(sonar_subdomains))

            self._ask_to_add(all_sonar_subdomains, reask_same_tld=True)
        except:
            self._print("Sonar search", "Sonar search failed - skipping", color.FAIL)

    def _sonar_reverse_dns(self):
        self._print("Sonar reverse DNS", "Sonar reverse dns started")

        # Add reverse DNS for all IP's discovered by HTTPx

        try:
            domain_name = self.site.split(".")[0]

            domain_ip = socket.gethostbyname(self.site)
            domain_ip_split = domain_ip.split(".")
            domain_ip_range = f"{domain_ip_split[0]}.{domain_ip_split[1]}.{domain_ip_split[2]}.0/32"

            self._print("Sonar reverse DNS", f"Domain IP: {domain_ip}\n")

            use_whole_range = self._ask("Do you want to scan whole range (x.x.x.0/32)? ")

            reverse_dns_domains = loads(get(f"https://sonar.omnisint.io/reverse/{domain_ip_range if use_whole_range else domain_ip}").text)

            if use_whole_range:
                all_domains = []
                for ip in reverse_dns_domains:
                    all_domains.extend(reverse_dns_domains[ip])
                reverse_dns_domains = list(set(all_domains))

            reverse_dns_domains = self._remove_unwanted_domains(reverse_dns_domains)

            if not self._ask_to_add(reverse_dns_domains):
                containing_domain = list(set([_ for _ in reverse_dns_domains if domain_name in _]))

                if containing_domain:
                    print()
                    for d in containing_domain:
                        print(d)

                    self._ask_to_add(containing_domain)
        except:
            self._print("Sonar reverse DNS", "Sonar reverse dns failed - skipping", color.FAIL)


    def _c99_subdomains(self):
        self._print("C99", "Getting subdomains from C99 API")

        try:
            response = get(f"https://api.c99.nl/subdomainfinder?key={self.c99_key}&domain={self.site}")

            invalid_strings = [
                "Make sure you fill in a valid domain",
                "No subdomains found for this domain"
            ]

            if not any(x in response.text for x in invalid_strings):
                subdomains = [_.strip() for _ in response.text.split("<br>") if _]
                self._ask_to_add(subdomains)
        except:
            self._print("C99", "Request failed!", color.FAIL)

    def _install_lepus(self):
        if not exists("tools/lepus"):
            self._print("Lepus", "Cloning Lepus from git")
            self._cmd("git clone https://github.com/gfek/Lepus.git tools/lepus")

            self._cmd(f"{self.python_bin} -m pip install -r tools/lepus/requirements.txt")

    def _dnsx(self):
        pass

    def _interactsh(self):
        pass

    def _install_acunetix(self):
        if not exists("acunetix_docker"):
            self._print("Acunetix", "Installing Acunetix Docker")

            self._cmd("git clone https://github.com/vncloudsco/acu807155.git acunetix_docker")

            new_email = input("\n\nPlease enter acunetix email (leave blank for default: contact@manhtuong.net): ")
            if new_email:
                self._cmd(f"sed -i 's/contact@manhtuong.net/{new_email}/g' acunetix_docker/Dockerfile")
                self.acunetix_email = new_email

            new_password = input("\nPlease enter acunetix password (leave blank for default: Abcd1234): ")
            if new_password:
                self._cmd(f"sed -i 's/Abcd1234/{new_password}/g' acunetix_docker/Dockerfile")
                self.acunetix_password = new_password

            self._cmd("docker build -t aws acunetix_docker")
            self._cmd("docker run -it -d -p 3443:3443 aws")

            self._print("Acunetix", "Installed successfully - available at https://localhost:3443/", color.SUCCESS)
            # try:
            #     get("https://localhost:3443/", verify=False, timeout=10)
            #     print("[HaxUnit] Installed successfully - available at https://localhost:3443/")
            # except:
            #     print("[HaxUnit] Installed failed for some reason - skipping")


    def _acunetix(self):

        if self.acu_session:
            self._print("Acunetix", "Starting acunetix")

            data = {}
            cookies = {'ui_session': self.acu_session}
            headers = {'x-auth': self.acu_session, 'Content-Type': 'application/json'}

            print()
            for d in self.all_subdomains_up:
                print(d)
            print()

            self._print("Acunetix", f"Active subdomain count: {len(self.all_subdomains_up)}")

            target_group_data = {"name":self.site,"description":""}
            group_id = post('https://localhost:3443/api/v1/target_groups', headers=headers, cookies=cookies, data=dumps(target_group_data), verify=False).json()["group_id"]

            if len(self.all_subdomains_up) < 30 and self._ask("[HaxUnit] Do you want to scan all subdomains using acunetix? "):
                data = {
                    "targets": [{
                        "address": subdomain,
                        "description": ""
                    } for subdomain in self.all_subdomains_up],
                    "groups": [group_id]
                }
            elif self._ask("[HaxUnit] Do you want to scan only the main domain using acunetix? "):
                main_domain = [_ for _ in self.all_subdomains_up if f"//{self.site}" in _][0]
                self._print("Acunetix", "Main domain: {main_domain}")
                data = {
                    "targets": [{
                        "address": main_domain,
                        "description": ""
                    }],
                    "groups": [group_id]
                }

            if data:

                response = post('https://localhost:3443/api/v1/targets/add', headers=headers, cookies=cookies, data=dumps(data), verify=False).json()

                for target in response["targets"]:

                    data = {
                        "profile_id": "11111111-1111-1111-1111-111111111111",
                        "ui_session_id": "56eeaf221a345258421fd6ae1acca394",
                        "incremental": False,
                        "schedule": {
                            "disable": False,
                            "start_date": None,
                            "time_sensitive": False
                        },
                        "target_id": target["target_id"]
                    }

                    post('https://localhost:3443/api/v1/scans', headers=headers, cookies=cookies, data=dumps(data), verify=False)


    def _securitytrails(self):
        domain = "test.com"
        response = get(f"https://securitytrails.com/_next/data/8153b487/list/apex_domain/{domain}.json").json()

        subdomains = [_ for _ in response["pageProps"]["apexDomainData"]["data"]["records"]]

        for s in subdomains:
            print(s["hostname"])

    def _gau_unfurl(self):
        self._cmd(f"cat {self.dir_path}/all_subdomains.txt | getau | unfurl --unique domains > {self.dir_path}/gau_unfurl_domains.txt")

        gau_unfurl_domains = self._read("gau_unfurl_domains.txt")
        self._ask_to_add(gau_unfurl_domains)

        with self.sqlite:
            gau_unfurl_domains_text = self._read("gau_unfurl_domains.txt", True)
            self.sqlite.execute(f"UPDATE scans SET gau_unfurl_domains = '{gau_unfurl_domains_text}' WHERE id = {self.scan_id}")


    def _update_scan_status(self, status):
        with self.sqlite:
            self.sqlite.execute(f"UPDATE scans SET status = '{status}' WHERE id = {self.scan_id}")

        self._print("Local DB", f"Status set to: {status}")

    def _install_nrich(self):
        for cmd in (
                "wget https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/latest/nrich_latest_amd64.deb",
                "sudo dpkg -i nrich_latest_amd64.deb",
                "rm nrich_latest_amd64.deb",
        ):
            self._cmd(cmd)

    def _install_all(self):

        # self._install_nrich()
        # self._install_acunetix()
        # self._install_lepus()

        self._install(
            name="httpx",
            download="https://github.com/projectdiscovery/httpx/releases/download/v1.1.5/httpx_1.1.5_linux_amd64.zip",
            file="httpx_1.1.5_linux_amd64.zip",
            bin="httpx"
        )

        self._install(
            name="naabu",
            download="https://github.com/projectdiscovery/naabu/releases/download/v2.0.5/naabu_2.0.5_linux_amd64.zip",
            file="naabu_2.0.5_linux_amd64.zip",
            bin="naabu"
        )

        self._install(
            name="subfinder",
            download="https://github.com/projectdiscovery/subfinder/releases/download/v2.4.9/subfinder_2.4.9_linux_amd64.zip",
            file="subfinder_2.4.9_linux_amd64.zip",
            bin="subfinder"
        )

        self._install(
            name="nuclei",
            download="https://github.com/projectdiscovery/nuclei/releases/download/v2.5.9/nuclei_2.5.9_linux_amd64.zip",
            file="nuclei_2.5.9_linux_amd64.zip",
            bin="nuclei"
        )

        self._install(
            name="dnsx",
            download="https://github.com/projectdiscovery/dnsx/releases/download/v1.0.7/dnsx_1.0.7_linux_amd64.zip",
            file="dnsx_1.0.7_linux_amd64.zip",
            bin="dnsx"
        )

        self._install(
            name="interactsh",
            download="https://github.com/projectdiscovery/interactsh/releases/download/v1.0.1/interactsh-client_1.0.1_Linux_x86_64.zip",
            file="interactsh-client_1.0.1_Linux_x86_64.zip",
            bin="interactsh-client"
        )

        self._install(
            name="getau",
            download="https://github.com/lc/gau/releases/download/v2.0.8/gau_2.0.8_linux_amd64.tar.gz",
            file="gau_2.0.8_linux_amd64.tar.gz",
            bin="gau",
            tar_gz=True
        )

        self._install(
            name="unfurl",
            download="https://github.com/tomnomnom/unfurl/releases/download/v0.2.0/unfurl-linux-amd64-0.2.0.tgz",
            file="unfurl-linux-amd64-0.2.0.tgz",
            bin="unfurl",
            tar_gz=True
        )




def script_init(args) -> str:
    """Create scans folder, workspace and the current scan folder"""

    if not exists("scans"):
        mkdir("scans")

    if not exists("tools"):
        mkdir("tools")

    if not exists(f"scans/{args.domain}"):
        mkdir(f"scans/{args.domain}")

    dir_path = f"scans/{args.domain}/{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"
    mkdir(dir_path)

    return dir_path


def main():

    parser = argparse.ArgumentParser(description='HaxUnit')
    parser.add_argument('-d', '--domain', type=str, help='the website to recon: example.com', required=False)
    parser.add_argument('-m', '--mode', type=str, help='you can set to scan `quick` or `extensive`', default='extensive')
    parser.add_argument('-v', '--verbose', type=bool, help='print more information', default=True)
    parser.add_argument('-b', '--bin', type=str, help='set which python bin to use', default='python3')
    parser.add_argument('-is', '--iserver', type=str, help='interactsh server url for self-hosted instance', default='')
    parser.add_argument('-it', '--itoken', type=str, help='authentication token for self-hosted interactsh server', default='')
    parser.add_argument('-acu', '--acunetix', type=str, help='', default='')
    parser.add_argument('-y', '--yolo', type=bool, help='yes to all', default=False)
    parser.add_argument('-u', '--update', type=bool, help='update all tools', default=False)
    parser.add_argument('-i', '--install', help='install all tools', default=False, action="store_true")


    args = parser.parse_args()
    dir_path = script_init(args)

    hax = HaxUnit(
        site=args.domain,
        mode=args.mode,
        verbose=args.verbose,
        python_bin=args.bin,
        dir_path=dir_path,
        iserver=args.iserver,
        itoken=args.itoken,
        acu_session=args.acunetix,
        yolo=args.yolo,
        update=args.update,
        install_all=args.install,
    )

    try:
        # hax._install_acunetix()
        # hax._lepus()

        hax._check_ip()
        hax._add_domain_to_db()
        hax._create_scan_in_db()
        hax._sonar_search()
        # hax._c99_subdomains()
        hax._dnscan()
        hax._subfinder()
        hax._crtsh()
        hax._write_subdomains()
        hax._naabu()
        hax._write_subdomains("w")
        hax._gau_unfurl()
        # hax._write_subdomains("w")
        hax._httpx()
        hax._nrich()
        hax._sonar_reverse_dns()
        # hax._acunetix()
        hax._nuclei()
        hax._cleanup()

        print(f"\ncd {dir_path}\n")

        hax._update_scan_status("2")

    except ValueError as e:
        print(e)
        print()
        print("Invalid URL was given (-d)")
        hax._update_scan_status("3")
    except KeyboardInterrupt:
        print()
        hax._cleanup()
        hax._update_scan_status("3")
        print("Cleaning up - bye!")
        quit()
    except Exception as e:
        print(e)
        print("\nUnexpected error")
        hax._update_scan_status("3")

if __name__ == '__main__':
    main()
