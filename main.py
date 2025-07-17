#!/usr/bin/env python3
"""
HaxUnit - Comprehensive reconnaissance and security assessment tool for web domains.
"""

# Standard library imports
import argparse
import csv
import hashlib as h
import ipaddress
import json
import os
import platform as p
import time
import uuid as u
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime
from os import getenv, mkdir
from os.path import exists
from subprocess import PIPE, Popen
from traceback import print_exc
from urllib.parse import urlparse
from json import dumps

# Third-party imports
import urllib3
from dotenv import load_dotenv
from freeGPTFix import Client
from requests import get, post
from rich.console import Console
from rich.markdown import Markdown

# Disable SSL warnings
urllib3.disable_warnings()

# Load environment variables
load_dotenv()

# Global start time for elapsed time tracking
start_time = time.time()


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    OK = '\033[94m'
    FAIL = '\033[91m'
    SUCCESS = '\033[92m'
    RESET = '\033[0m'
    WARNING = '\033[93m'
    BOLD = '\033[1m'


class HaxUnit:
    """Main class for HaxUnit reconnaissance tool."""
    
    # Class constants
    YES_ANSWERS = ("y", "yes", "ye", "yh", "oui", "si", "ok")
    VERSION = "v4.2" # 42 is the answer to life, the universe, and everything
    
    def __init__(
        self,
        site: str,
        mode: str,
        verbose: bool,
        python_bin: str,
        dir_path: str,
        iserver: str,
        itoken: str,
        use_acunetix: bool,
        yes_to_all: bool,
        update: bool,
        install_all: bool,
        wpscan_api_token: str,
        use_notify: bool,
        cloud_upload: bool,
        htb: bool,
        fuzz: bool,
        use_gpt: bool,
        skip_installers: bool
    ):
        """
        Initialize HaxUnit with configuration parameters.
        
        Args:
            site: Target domain to scan
            mode: Scan mode ('quick' or 'extensive')
            verbose: Enable verbose output
            python_bin: Python binary to use
            dir_path: Directory path for scan results
            iserver: Interactsh server URL
            itoken: Interactsh authentication token
            use_acunetix: Enable Acunetix integration
            yes_to_all: Auto-confirm all prompts
            update: Update all tools
            install_all: Install all required tools
            wpscan_api_token: WPScan API token
            use_notify: Enable notifications
            cloud_upload: Upload results to cloud
            htb: HackTheBox mode
            fuzz: Enable fuzzing
            use_gpt: Enable GPT suggestions
            skip_installers: Skip tool installation checks
        """
        # Initialize instance variables
        self.site = site
        self.all_subdomains = [site] if site else []
        self.all_subdomains_up = []
        self.timestamp = datetime.now()
        self.hostname = ""
        
        # Configuration flags
        self.verbose = verbose
        self.quick = mode == "quick"
        self.python_bin = python_bin
        self.dir_path = dir_path
        self.yes_to_all = yes_to_all
        self.update = update
        self.install_all = install_all
        self.skip_installers = skip_installers
        
        # API keys and tokens
        self.wpscan_api_token = wpscan_api_token or getenv("WPSCAN_API_KEY")
        self.acunetix_api_key = getenv("ACUNETIX_API_KEY")
        self.haxunit_api_key = getenv("HAXUNIT_API_KEY", "")
        self.pdcp_api_key = getenv("PDCP_API_KEY")
        
        # Acunetix configuration
        self.acunetix_threshold = 30
        self.use_acunetix = use_acunetix
        
        # Interactsh configuration
        self.iserver = iserver
        self.itoken = itoken
        
        # Feature flags
        self.fuzz = fuzz
        self.use_gpt = use_gpt
        self.use_notify = use_notify
        self.cloud_upload = cloud_upload
        
        # HTB specific configuration
        self.htb = htb
        if self.htb:
            self.ip = deepcopy(self.site)
        
        # Other instance variables
        self.wp_result_filenames = []
        self.anonymous_hwid = self._get_anonymous_hwid()
        
        # Display banner
        self._print_banner()
        
        # Handle installation mode
        if self.install_all:
            self.install_all_tools()
            self.print("Init", "All tools are successfully installed.", Colors.SUCCESS)
            print()
            self.print(
                "INFO", 
                "Please run 'source ~/.bashrc' or restart your terminal for changes to take effect.", 
                Colors.WARNING
            )
            exit()
        
        # Validate site parameter
        if not self.site:
            self.print("Init", "Please pass a domain (-d)", Colors.FAIL)
            exit()
        
        # Check tools installation
        if not self.check_tools() and not self.skip_installers:
            self.print("Init", "Please install all tools first using --install", Colors.FAIL)
            exit()
        
        # Initialize subdomains file
        self.write_subdomains()
        
        print(f"\n[HaxUnit] Target: {site}")
        print(Colors.RESET)
    
    @staticmethod
    def _print_banner():
        """Display the HaxUnit banner."""
        print(Colors.BOLD)
        print(f"""
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░  ░░░░  ░░░      ░░░  ░░░░  ░░  ░░░░  ░░   ░░░  ░░        ░░        ░
▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒▒  ▒▒  ▒▒▒  ▒▒▒▒  ▒▒    ▒▒  ▒▒▒▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒
▓        ▓▓  ▓▓▓▓  ▓▓▓▓    ▓▓▓▓  ▓▓▓▓  ▓▓  ▓  ▓  ▓▓▓▓▓  ▓▓▓▓▓▓▓▓  ▓▓▓▓
█  ████  ██        ███  ██  ███  ████  ██  ██    █████  ████████  ████
█  ████  ██  ████  ██  ████  ███      ███  ███   ██        █████  ████
██████████████████████████████████████████████████████████████████████

                                       {HaxUnit.VERSION} - haxunit.com""")
    @staticmethod
    def print(title: str = "", text: str = "", color_type: str = "") -> None:
        """
        Print formatted output with timestamp and color.
        
        Args:
            title: Section title
            text: Message text
            color_type: Color code to use
        """
        elapsed_time = time.time() - start_time
        time_running = time.strftime("%M:%S", time.gmtime(elapsed_time))
        
        print(
            f"[{Colors.BOLD}HaxUnit{Colors.RESET}] "
            f"[{time_running}] "
            f"[{Colors.OK}{title}{Colors.RESET}] "
            f"{color_type}{text}{Colors.RESET}"
        )
    
    @staticmethod
    def is_ip_address(string: str) -> bool:
        """
        Check if a string is a valid IP address.
        
        Args:
            string: String to check
            
        Returns:
            bool: True if valid IP address, False otherwise
        """
        try:
            ipaddress.ip_address(string)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def _get_anonymous_hwid() -> str:
        """
        Generate anonymous hardware ID for telemetry.
        
        Returns:
            str: SHA256 hash of system information
        """
        system_info = {
            'a': p.node(),
            'b': p.system(),
            'c': p.release(),
            'd': p.version(),
            'e': p.machine(),
            'f': p.processor(),
            'g': str(u.getnode())
        }
        
        info_string = '|'.join(f'{k}={v}' for k, v in system_info.items())
        return h.sha256(info_string.encode()).hexdigest()

    def motd(self):
        """Display random noise for operators"""
        try:
            response = get("https://www.affirmations.dev/") # haxunit endpoint down - threw html in my face
            affirmation = json.loads(response.text)["affirmation"] 
            self.print("MOTD", affirmation)
        except Exception:
            pass

    def cmd(self, cmd: str, silent: bool = False) -> str:
        """
        Execute a shell command and return output.
        
        Args:
            cmd: Command to execute
            silent: Suppress output if True
            
        Returns:
            str: Command output
        """
        cmd = " ".join(cmd.split())
        
        if self.verbose and not silent:
            self.print("CMD", cmd)
        
        process = Popen(cmd, shell=True, stdout=PIPE)
        output = process.stdout.read().decode("utf-8").strip()
        
        if output and not silent:
            print(output)
        
        return output

    def ask(self, question: str) -> bool:
        """
        Ask user a yes/no question.
        
        Args:
            question: Question to ask
            
        Returns:
            bool: True if user answered yes
        """
        if self.yes_to_all:
            return True
        return input(question).lower() in self.YES_ANSWERS

    def read(self, file_name: str, text: bool = False) -> str | list:
        """
        Read file contents.
        
        Args:
            file_name: Name of file to read
            text: Return as single string if True, list of lines if False
            
        Returns:
            str or list: File contents
        """
        file_path = f"{self.dir_path}/{file_name}"
        
        try:
            with open(file_path, "r") as f:
                lines = [line.strip() for line in f.readlines()]
                unique_lines = list(set(lines))
                
                if text:
                    return "\n".join(unique_lines)
                return unique_lines
        except FileNotFoundError:
            return "FileNotFoundError" if text else []

    def write_subdomains(self, mode: str = "a") -> None:
        """
        Write subdomains to file.
        
        Args:
            mode: File open mode ('a' for append, 'w' for write)
        """
        file_path = f"{self.dir_path}/all_subdomains.txt"
        unique_subdomains = [sub for sub in set(self.all_subdomains) if sub]
        
        with open(file_path, mode) as f:
            content = "\n".join(unique_subdomains) + "\n"
            f.write(content)

    def check_tools(self) -> bool:
        """
        Check if all required tools are installed.
        
        Returns:
            bool: True if all tools are installed
        """
        required_tools = [
            "dnsx", "subfinder", "katana", "unfurl", "alterx",
            "dnsx", "naabu", "httpx", "nuclei", "notify", "ffuf"
        ]
        
        for tool in required_tools:
            if not self.cmd(f"command -v {tool}", silent=True):
                return False
        return True

    def httpx(self) -> None:
        """Run httpx to check which subdomains are active."""
        self.print("HTTPx", "Checking active subdomains...")
        
        # Run httpx scan
        httpx_cmd = (
            f"httpx -l {self.dir_path}/all_subdomains.txt "
            f"{'' if self.verbose else '-silent'} "
            f"-o {self.dir_path}/httpx_result.csv -td -cdn -csv -timeout 15 "
            f"{'-dashboard' if self.cloud_upload else ''}"
        )
        self.cmd(httpx_cmd)
        
        # Extract active subdomains
        awk_cmd = """awk -F "," {'print $11'}"""
        self.cmd(
            f"cat {self.dir_path}/httpx_result.csv | {awk_cmd} | "
            f"tail -n +2 | sort -u > {self.dir_path}/all_subdomains_up.txt"
        )
        
        # Extract IPs
        awk_cmd_ip = """awk -F "," {'print $22'}"""
        self.cmd(
            f"cat {self.dir_path}/httpx_result.csv | {awk_cmd_ip} | "
            f"sort -u | head -n -1 >> {self.dir_path}/httpx_ips.txt"
        )
        
        # Combine all IPs
        self.cmd(
            f"cat {self.dir_path}/httpx_ips.txt {self.dir_path}/dnsx_ips.txt | "
            f"sort -u > {self.dir_path}/all_ips.txt"
        )
        
        self.all_subdomains_up = self.remove_unwanted_domains(
            self.read("all_subdomains_up.txt")
        )
        
        self.event("httpx_result", "httpx_result.csv")

    def naabu(self) -> None:
        """Run naabu port scanner on discovered subdomains."""
        input_file = self.read("all_subdomains.txt")
        
        if not input_file:
            self.print("Naabu", "all_subdomains.txt is empty - skipping")
            return
        
        self.print("Naabu", "Starting port scan...")
        
        naabu_cmd = (
            f"naabu -l {self.dir_path}/all_subdomains.txt "
            f"-c 100 {'' if self.verbose else '-silent'} "
            f"-no-color -top-ports 1000 -exclude-cdn -ep 80,443 "
            f"-o {self.dir_path}/naabu_portscan.txt"
        )
        self.cmd(naabu_cmd)
        
        self.ask_to_add(self.read("naabu_portscan.txt"))
        self.write_subdomains()

    def subfinder(self) -> None:
        """Run subfinder to discover subdomains from passive sources."""
        if self.htb or self.is_ip_address(self.site):
            return
        
        self.print("Subfinder", "Process started")
        
        subfinder_cmd = (
            f"subfinder -d {self.site} "
            f"{'' if self.verbose else '-silent'} "
            f"-t 100 -nW -all -o {self.dir_path}/subfinder_subdomains.txt"
        )
        self.cmd(subfinder_cmd)
        
        self.ask_to_add(self.read("subfinder_subdomains.txt"))

    def chaos(self) -> None:
        """Run chaos-client to discover subdomains from Chaos database."""
        if self.htb or self.is_ip_address(self.site):
            return
        
        if not self.pdcp_api_key:
            self.print("Chaos", "PDCP_API_KEY not found in environment, skipping", Colors.WARNING)
            return
        
        self.print("Chaos", "Querying ProjectDiscovery Chaos database")
        
        chaos_cmd = (
            f"chaos -d {self.site} "
            f"-key {self.pdcp_api_key} "
            f"{'-silent' if not self.verbose else ''} "
            f"-o {self.dir_path}/chaos_subdomains.txt"
        )
        self.cmd(chaos_cmd)
        
        self.ask_to_add(self.read("chaos_subdomains.txt"))

    def nuclei(self) -> None:
        """Run nuclei vulnerability scanner on active subdomains."""
        self.print("Nuclei", "Starting vulnerability scan...")
        
        nuclei_cmd = (
            f"nuclei -l {self.dir_path}/all_subdomains_up.txt "
            f"{'-stats' if self.verbose else '-silent'} "
            f"-o {self.dir_path}/nuclei_result.txt "
            f"-bulk-size 100 -c 100 -no-httpx "
            f"-ept dns,ssl -etags detect,headers,waf,technologies,tech,wp-plugin,wordpress,whois "
            f"-eid robots-txt,missing-sri "
            f"{'-cloud-upload' if self.cloud_upload else ''} "
            f"{f'-interactsh-url {self.iserver}' if self.iserver else ''} "
            f"{f'-itoken {self.itoken}' if self.itoken else ''}"
        )
        self.cmd(nuclei_cmd)
        
        self.event("nuclei_result", "nuclei_result.txt")
        self.event("scan_finished")

    def check_ip(self) -> None:
        """Check if current IP is suitable for scanning."""
        if self.htb:
            return
        
        try:
            ip_address = get("http://ifconfig.me/ip").text
            ip_check = get(f"https://blackbox.ipinfo.app/lookup/{ip_address}").text
            
            # Mask IP for privacy
            masked_ip = '.'.join(ip_address.split('.')[:2] + ['***', '***'])
            self.print("IP Address", masked_ip)
            self.event("scan_started")
            
            if ip_check != "Y":
                warning_msg = (
                    f"{Colors.WARNING}(!) Your IP ({masked_ip}) seems to be a "
                    f"residential/mobile IP address, would you like to continue? {Colors.RESET}"
                )
                if not self.ask(warning_msg):
                    raise KeyboardInterrupt
        except Exception as e:
            self.print("Error", f"Failed to check IP: {str(e)}", Colors.FAIL)

    @staticmethod
    def remove_unwanted_domains(domain_list: list) -> list:
        """
        Remove unwanted domains from list.
        
        Args:
            domain_list: List of domains to filter
            
        Returns:
            list: Filtered domain list
        """
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
            "error"
        )
        
        filtered_domains = []
        for domain in domain_list:
            if (not domain.endswith(unwanted_domains) and 
                not domain.startswith("*") and 
                domain):
                filtered_domains.append(domain)
        
        return filtered_domains

    def ask_to_add(self, domains: list, reask_same_tld: bool = False) -> bool:
        """
        Ask user to add discovered domains to scan list.
        
        Args:
            domains: List of domains to add
            reask_same_tld: Re-ask for same TLD domains only
            
        Returns:
            bool: True if domains were added
        """
        # Filter out already known domains
        new_domains = [d for d in set(domains) if d not in self.all_subdomains]
        new_domains = self.remove_unwanted_domains(new_domains)
        
        if not new_domains:
            return False
        
        # Display domains
        print()
        for domain in new_domains:
            print(domain)
        print()
        
        if self.ask(f"\nWould you like to add {len(new_domains)} domains to the list? "):
            self.all_subdomains.extend(new_domains)
            self.write_subdomains("w")
            return True
        elif reask_same_tld:
            # Filter for same TLD and ask again
            same_tld_domains = [d for d in new_domains if d.endswith(self.site)]
            return self.ask_to_add(same_tld_domains)
        
        return False

    def dnsx_subdomains(self) -> None:
        """Use dnsx to bruteforce subdomains."""
        if self.is_ip_address(self.site):
            return
        
        self.print("DNSx", "Started subdomain bruteforce")
        
        wordlist = "data/subdomains-1000.txt" if self.quick else "data/subdomains-10000.txt"
        dnsx_cmd = (
            f"dnsx -d {self.site} -w {wordlist} "
            f"{'--stats' if not self.quick else ''} "
            f"-wd {self.site} -o {self.dir_path}/dnsx_result.txt -r 8.8.8.8 -stats"
        )
        self.cmd(dnsx_cmd)
        
        self.ask_to_add(self.read("dnsx_result.txt"))
        
        # Recursive bruteforce if requested
        if (self.read("dnsx_result.txt") and 
            self.ask("\nWould you like to continue recursively bruteforce the found subdomains? ")):
            self._recursive_dnsx_bruteforce()

    def _recursive_dnsx_bruteforce(self) -> None:
        """Perform recursive subdomain bruteforce."""
        self.print("DNSx", "Started multi-threaded recursive bruteforce")
        all_found_subdomains = []
        
        try:
            for iteration in range(100):
                print()
                self.print("DNSx", f"Iteration: {iteration}")
                
                # Determine which file to read
                if iteration == 0:
                    file_to_read = "dnsx_result.txt"
                else:
                    file_to_read = f"dnsx_recursive_iter_{iteration - 1}_result.txt"
                
                self.print("DNSx", f"Reading file: {file_to_read}")
                dnsx_result = self.read(file_to_read)
                
                if not dnsx_result:
                    break
                
                self.print("DNSx", f"List of subdomains: {dnsx_result}")
                all_found_subdomains.extend(dnsx_result)
                
                # Run bruteforce on each subdomain in parallel
                def dnsx_brute(subdomain):
                    output_file = f"{self.dir_path}/dnsx_recursive_iter_{iteration}_result.txt"
                    self.cmd(
                        f"dnsx -silent -d {subdomain} -wd {subdomain} "
                        f"-w data/subdomains-1000.txt -wd {self.site} "
                        f"-o {output_file} -r 8.8.8.8"
                    )
                
                with ThreadPoolExecutor(max_workers=5) as pool:
                    pool.map(dnsx_brute, dnsx_result)
                    
        except KeyboardInterrupt:
            self.print("DNSx", "Bruteforce stopped")
        
        self.ask_to_add(all_found_subdomains)

    def dnsx_ips(self) -> None:
        """Get A records for all subdomains."""
        if self.is_ip_address(self.site):
            return
        
        self.print("DNSx", "Get A records")
        
        dnsx_cmd = (
            f"dnsx -l {self.dir_path}/all_subdomains.txt "
            f"-a -resp-only -silent | sort -u > {self.dir_path}/dnsx_ips.txt"
        )
        self.cmd(dnsx_cmd)

    def acunetix(self) -> None:

        def acunetix_up():
            try:
                get("https://host.docker.internal:3443/api/v1/target_groups", verify=False)
                return True
            except ConnectionError:
                return False

        if self.use_acunetix and self.acunetix_api_key and acunetix_up():
            self.print("Acunetix", "Starting acunetix")
            self.event("using_acunetix")

            data = {}
            cookies = {'ui_session': self.acunetix_api_key}
            headers = {'x-auth': self.acunetix_api_key, 'Content-Type': 'application/json'}

            print()
            for d in self.all_subdomains_up:
                print(d)
            print()

            self.print("Acunetix", f"Active subdomain count: {len(self.all_subdomains_up)}")

            all_groups = get("https://host.docker.internal:3443/api/v1/target_groups", headers=headers, verify=False).json()["groups"]

            try:
                group_id = next(row["group_id"] for row in all_groups if row["name"] == self.site)
            except StopIteration:
                group_id = None

            if group_id:
                self.print("Acunetix", f"Group already exists: {group_id}")
            else:
                self.print("Acunetix", "Creating new group")

                group_id = post(
                    'https://host.docker.internal:3443/api/v1/target_groups',
                    headers=headers,
                    cookies=cookies,
                    data=dumps({"name": self.site, "description": ""}),
                    verify=False
                ).json()["group_id"]

            if len(self.all_subdomains_up) < self.acunetix_threshold and self.ask(
                    "[HaxUnit] Do you want to scan all subdomains using acunetix? "):
                data = {
                    "targets": [{
                        "address": subdomain,
                        "description": ""
                    } for subdomain in self.all_subdomains_up],
                    "groups": [group_id]
                }
            elif self.ask("[HaxUnit] Do you want to scan only the main domain using acunetix? "):
                main_domain = [_ for _ in self.all_subdomains_up if f"//{self.site}" in _][0]
                self.print("Acunetix", f"Main domain: {main_domain}")
                data = {
                    "targets": [{
                        "address": main_domain,
                        "description": ""
                    }],
                    "groups": [group_id]
                }

            if data:

                response = post('https://host.docker.internal:3443/api/v1/targets/add', headers=headers, cookies=cookies,
                                data=dumps(data), verify=False).json()

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

                    post('https://host.docker.internal:3443/api/v1/scans', headers=headers, cookies=cookies, data=dumps(data),
                         verify=False)

                self.print("Acunetix", f"Scan(s) started!")

    def katana(self) -> None:
        """Run katana web crawler to discover additional endpoints."""
        self.print("Katana", "Starting web crawling...")
        
        depth = "-d 1" if self.quick else ""
        katana_cmd = (
            f"katana -list {self.dir_path}/all_subdomains.txt {depth} | "
            f"unfurl format %d:%P | sed 's/:$//g' | "
            f"sort -u > {self.dir_path}/katana_domains.txt"
        )
        self.cmd(katana_cmd)
        
        self.ask_to_add(self.read("katana_domains.txt"))

    def alterx(self) -> None:
        """Generate subdomain permutations using alterx."""
        if self.is_ip_address(self.site):
            return
        
        self.print("Alterx", "Generating subdomain permutations...")
        
        enrich_flag = "" if self.quick else "-enrich"
        alterx_cmd = (
            f"alterx -l {self.dir_path}/all_subdomains.txt {enrich_flag} | "
            f"sort -u | dnsx -silent > {self.dir_path}/alterx_result.txt"
        )
        self.cmd(alterx_cmd)
        
        self.ask_to_add(self.read("alterx_result.txt"))

    def notify(self):
        if self.use_notify:
            self.event("using_notify")

            def get_severity_emoji(severity):
                severity_mapping = {
                    'info': '🟢',
                    'low': '🟡',
                    'medium': '🟠',
                    'high': '🔴',
                    'critical': '🚨',
                    'unknown': '❓'
                }
                return severity_mapping.get(severity.lower(), '❓')

            def transform_label(label):
                return ' '.join(word.capitalize() for word in label.replace('-', ' ').split())

            def add_emojis_and_format(result):
                formatted_lines = []
                for line in result.strip().split('\n'):
                    parts = line.split()
                    if len(parts) < 4:
                        formatted_lines.append(f"❓ {line}")
                        continue
                    label, protocol, severity, rest = parts[0].strip('[]'), parts[1].strip('[]'), parts[2].strip(
                        '[]'), ' '.join(parts[3:])
                    label_parts = label.split(':')
                    label_main = transform_label(label_parts[0])
                    label_sub = f": {transform_label(label_parts[1])}" if len(label_parts) > 1 else ''
                    emoji = get_severity_emoji(severity)
                    formatted_lines.append(f"{emoji} | {label_main}{label_sub} - {protocol.upper()} | {rest}")
                return '\n'.join(formatted_lines)

            with open(f"{self.dir_path}/nuclei_result.txt", "r") as f:
                nuclei_result = f.read()

            use_local_config = "-provider-config notify-config.yaml" if exists("notify-config.yaml") else ""

            self.cmd(f'echo "[$(date +"%Y-%m-%d")] Finished scan for these hosts:" | notify -silent {use_local_config}')

            self.cmd(f"notify -i {self.dir_path}/all_subdomains_up.txt -silent -bulk {use_local_config}")
            self.cmd(f"""notify -silent {use_local_config} <<< "$(echo -e '```'$(cat {self.dir_path}/all_subdomains_up.txt)'```')" """)

            self.cmd(f'echo "[$(date +"%Y-%m-%d")] Nuclei results:" | notify -silent {use_local_config}')

            if nuclei_result:
                with open(f"{self.dir_path}/nuclei_result_formatted.txt", "w", encoding='utf-8') as f:
                    f.write(add_emojis_and_format(nuclei_result))

                self.cmd(f"notify -i {self.dir_path}/nuclei_result_formatted.txt -bulk -silent {use_local_config}")

                if any(sev in nuclei_result for sev in ['high', 'critical']):
                    self.cmd(f'echo "⚠️ ️High severity issues found <!channel>" | notify -silent {use_local_config}')
                elif any(sev in nuclei_result for sev in ['low', 'medium']):
                    self.cmd(f'echo "⚠️ Medium/Low severity issues found <!channel>" | notify -silent {use_local_config}')
            else:
                self.cmd(f'echo "✅ No results" | notify -silent {use_local_config}')

            if self.wp_result_filenames:
                self.cmd(f'echo "[$(date +"%Y-%m-%d")] WPScan results:" | notify -silent {use_local_config}')
                for wp_result_filename in self.wp_result_filenames:
                    self.cmd(f"notify -i {self.dir_path}/{wp_result_filename} -bulk -silent {use_local_config}")

    def event(self, message: str = None, filename: str = None) -> None:
        """
        Send telemetry event to HaxUnit server.
        
        Args:
            message: Event message
            filename: Associated filename
        """
        try:
            url = "https://app.haxunit.com/handle_event"
            
            data = {
                "domain": self.site,
                "message": message,
                "hwid": self.anonymous_hwid,
                "api_key": self.haxunit_api_key
            }
            
            if filename:
                data["filename"] = filename
                file_path = f'{self.dir_path}/{filename}'
                with open(file_path, 'rb') as file:
                    post(url, data=data, files={'file': file})
            else:
                post(url, data=data)
        except Exception:
            pass

    def droopescan(self):
        pass

    def subwiz(self) -> None:
        """Use AI to predict additional subdomains."""
        if self.is_ip_address(self.site):
            return
        
        self.print("Subwiz", "Predicting subdomains with AI...")
        
        subwiz_cmd = (
            f"subwiz -i {self.dir_path}/all_subdomains.txt "
            f"-o {self.dir_path}/subwiz_results.txt"
        )
        self.cmd(subwiz_cmd)
        
        self.ask_to_add(self.read("subwiz_results.txt"))

    def add_hosts(self, hosts: list) -> None:
        for host in hosts:
            command = f"echo '{self.ip} {host}' >> /etc/hosts"
            self.cmd(command)
            docker_command = f"""docker exec -u root awvs sh -c "{command}" """
            self.cmd(docker_command)
            self.print("HTB", f"Added '{host}' to /etc/hosts")

    def htb_add_hosts(self):
        if self.htb:
            response = get(f'http://{self.site}', allow_redirects=False)

            if response.status_code in (301, 302):
                redirected_url = response.headers.get('Location')

                if redirected_url:
                    self.hostname = redirected_url.split('//')[-1].rstrip("/")
                    self.site = self.hostname
                    self.all_subdomains.extend([self.site, f'http://{self.site}', f'https://{self.site}'])
                    self.add_hosts([self.site])
                    self.write_subdomains()
            else:
                self.print("HTB", "No redirection found")

    def ffuf_vhosts_check(self, file):
        with open(f'{self.dir_path}/{file}', mode='r') as file:
            vhosts = [row[0] for row in csv.reader(file)][1:]
            if vhosts:
                self.ask_to_add([f'http://{vhost}.{self.site}' for vhost in vhosts])
                self.add_hosts([f"{vhost}.{self.hostname}" for vhost in vhosts])

    def ffuf_vhosts(self):
        if (self.htb and self.hostname) or (self.fuzz and self.hostname):
            self.cmd(f'cewl {self.hostname} | grep -v CeWL | sort -u > {self.dir_path}/cewl_wordlist.txt')

            if self.read("cewl_wordlist.txt"):
                self.cmd(f"ffuf -w {self.dir_path}/cewl_wordlist.txt -u http://{self.hostname}  -H 'Host: FUZZ.{self.site}' -mc 200,401 -of csv -o {self.dir_path}/ffuf_vhosts_cewl.csv")

            if self.read("ffuf_vhosts_cewl.csv"):
                self.ffuf_vhosts_check("ffuf_vhosts_cewl.csv")

            self.cmd(f"ffuf -w data/subdomains-1000.txt -u http://{self.hostname}  -H 'Host: FUZZ.{self.site}' -mc 200,401 -of csv -o {self.dir_path}/ffuf_vhosts.csv")
            if self.read("ffuf_vhosts.csv"):
                self.ffuf_vhosts_check("ffuf_vhosts.csv")

    def run_ffuf(self, url, output_file, wordlist, output_format="json"):
        cmd = f"ffuf -u {url.rstrip('/')}/FUZZ -w {wordlist} -o {output_file} -of {output_format} -fc 403"
        self.cmd(cmd)

    def ffuf_scan(self, url, directory=""):
        # Generate the output file name and path for directories
        dir_output_file = os.path.join(self.dir_path, "ffuf",
                                       f"{url.replace('://', '_').replace('/', '_')}_{directory.replace('/', '_')}_dirs.json")

        # Run the ffuf scan for directories
        self.run_ffuf(f"{url}/{directory}", dir_output_file, f"data/raft-{'small' if self.quick else 'large'}-directories-lowercase.txt")

        found_directories = self.parse_ffuf_results(dir_output_file)

        if len(found_directories) > 10:
            if self.ask(f"More than 10 directories found. Would you like to continue scanning all of these? "):
                self.print("FFUF", "Continuing scanning directories")
                for sub_dir in found_directories:
                    self.ffuf_scan(url, f"{directory}/{sub_dir}")

        # After scanning directories, fuzz for files in the current directory
        self.scan_files_in_directory(url, directory)

    def scan_files_in_directory(self, url, directory=""):
        # Generate the output file name and path for files
        file_output_file = os.path.join(self.dir_path, "ffuf",
                                        f"{url.replace('://', '_').replace('/', '_')}_{directory.replace('/', '_')}_files.json")

        # Run the ffuf scan for files in the current directory
        self.run_ffuf(f"{url}/{directory}", file_output_file, f"data/raft-{'small' if self.quick else 'large'}-files-lowercase.txt")

    def parse_ffuf_results(self, file_path):
        directories = []
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                status_count = sum(1 for result in data.get("results", []) if result.get("status") in (200, 301, 302))

                if status_count > 50:
                    self.print("FFUF", "More than 50 results with status 200, 301, or 302. Skipping addition of directories.")
                    return []

                for result in data.get("results", []):
                    if result.get("status") in (200, 301, 302):
                        new_directory = result.get("input", {}).get("FUZZ")
                        if new_directory and new_directory not in directories:
                            directories.append(new_directory)

        except json.JSONDecodeError:
            print(f"Error parsing JSON in file: {file_path}")
        except Exception as e:
            print(f"An error occurred with file {file_path}: {e}")

        return directories

    def extract_ffuf_results(self, base_dir):
        found_urls = []

        for root, _, files in os.walk(base_dir):
            for file in files:
                if file.endswith(".json"):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                        try:
                            data = json.load(f)
                            for result in data.get("results", []):
                                if len(data.get("results", [])) > 50:
                                    self.print("FFUF", "More than 50 results found. Skipping addition of URLs.")
                                elif result.get("url"):
                                    found_urls.append(result.get("url").replace('//', '/').replace(':/', '://'))
                        except json.JSONDecodeError:
                            print(f"Error parsing JSON in file: {file_path}")
                        except Exception as e:
                            print(f"An error occurred with file {file_path}: {e}")

        return found_urls

    def ffuf(self):
        if self.fuzz:
            for url in self.all_subdomains_up:
                self.ffuf_scan(url)

            self.ffuf_result = self.extract_ffuf_results(f"{self.dir_path}/ffuf/")

            if self.ffuf_result:
                with open(f"{self.dir_path}/ffuf_result.txt", "w") as f:
                    f.write("\n".join(self.ffuf_result))

    def report_gen(self):
        self.cmd(f"python3 report_gen.py -d {self.dir_path} -o {self.dir_path}/report.pdf")

        self.print("Report", "Report generated:")
        self.print("Report", f"{self.dir_path}/report.pdf")

    def wpscan(self):

        def single_wpscan(wp_domain):
            filename = wp_domain.replace("https://", "").replace("http://", "").replace(".", "_").replace("/", "").replace(":", "_").strip()
            self.cmd(f"docker run -it --rm wpscanteam/wpscan --update --url {wp_domain} {f'--api-token {self.wpscan_api_token}' if self.wpscan_api_token else ''} --ignore-main-redirect --disable-tls-checks >> {self.dir_path}/wpscan_{filename}.txt")
            self.wp_result_filenames.append(f"wpscan_{filename}.txt")

        self.cmd(f"grep WordPress {self.dir_path}/httpx_result.csv | awk -F ',' {{'print $11'}} | sort -u > {self.dir_path}/wordpress_domains.txt")
        wordpress_domains = self.read("wordpress_domains.txt")

        if wordpress_domains:
            for domain in wordpress_domains:
                print(domain)
            print()

            if self.ask(f"Would you like to run wpscan on all ({len(wordpress_domains)}) domains? "):
                self.event("using_wpscan")

                with ThreadPoolExecutor(max_workers=5) as pool:
                    pool.map(single_wpscan, wordpress_domains)

    def gpt(self):
        if self.use_gpt:
            nuclei_result = self.read("nuclei_result.txt")

            nuclei_text = "\n".join([_ for _ in nuclei_result if "[info]" not in _])
            print(nuclei_text)

            if nuclei_text:

                gpt_result = Client.create_completion("gemini", f"""
                    I am pentesting my website, these are the result from the tool nuclei.
                    How can a attacker exploit these?
                    
                    {nuclei_text}
                """)

                console = Console()
                console.print(Markdown(gpt_result['text']))

    def install_wpscan(self):
        self.print("Installer", "Checking for wpscan Docker image...")
        if not self.cmd("command -v docker", silent=True):
            self.print("Installer", "Docker is not installed. WPScan installation requires Docker.", Colors.FAIL)
        else:
            result = self.cmd("docker images -q wpscanteam/wpscan", silent=True)
            if result:
                self.print("Installer", "Docker image 'wpscanteam/wpscan' is already installed.", Colors.SUCCESS)
            else:
                self.print("Installer", "Pulling Docker image 'wpscanteam/wpscan'...")
                self.cmd("docker pull wpscanteam/wpscan")

    def install_docker(self):
        self.print("Installer", "Checking for Docker...")
        if not self.cmd("command -v docker", silent=True):
            self.print("Installer", "Docker not found. Installing...")
            self.cmd("sudo apt-get update -y")
            self.cmd("sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common")
            self.cmd("curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -")
            self.cmd('sudo add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"')
            self.cmd("sudo apt-get update -y")
            self.cmd("sudo apt-get install -y docker-ce")
            self.print("Installer", "Docker installed successfully.", Colors.SUCCESS)
        else:
            self.print("Installer", "Docker is already installed.", Colors.SUCCESS)

    def install_go(self):
        self.print("Installer", "Checking for Go...")
        if not self.cmd("command -v go", silent=True):
            self.print("Installer", "Go is not installed. Please install it first.", Colors.FAIL)
            self.print("Installer", "Visit https://golang.org/doc/install for instructions.", Colors.FAIL)
            exit()
        else:
            self.print("Installer", "Go is already installed.", Colors.SUCCESS)

    def add_go_to_path(self):
        user_shell = self.cmd("echo $SHELL")

        if "zsh" in user_shell:
            shell_config_file = "~/.zshrc"
        elif "bash" in user_shell:
            shell_config_file = "~/.bashrc"
        else:
            self.print("ERROR", "Unsupported shell. Only bash or zsh are supported.")
            return

        self.cmd(f"echo 'export PATH=$PATH:$HOME/go/bin' >> {shell_config_file}")

        self.cmd(f"export PATH=$PATH:$HOME/go/bin")

    def install_all_tools(self):
        self.install_docker()
        self.install_wpscan()

        self.install_go()
        self.add_go_to_path()

        self.print("Installer", "Checking for libpcap-dev dependency...")
        # Redirect stderr to dev/null to avoid printing errors if package is not found
        if "install ok installed" in self.cmd("dpkg -s libpcap-dev 2>/dev/null", silent=True):
            self.print("Installer", "libpcap-dev is already installed.", Colors.SUCCESS)
        else:
            self.print("Installer", "Package 'libpcap-dev' not found. Installing for naabu dependency...")
            self.cmd("sudo apt-get update -y")
            self.cmd("sudo apt-get install -y libpcap-dev")

        # Install pdtm first, as it's used to manage other tools
        self.print("Installer", "Checking for pdtm...")
        if not self.cmd("command -v pdtm", silent=True):
            self.print("Installer", "pdtm not found. Installing...")
            self.cmd("go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest")
        else:
            self.print("Installer", "pdtm is already installed.", Colors.SUCCESS)

        # Install all projectdiscovery tools using pdtm
        self.print("Installer", "Installing all ProjectDiscovery tools via pdtm...")
        self.cmd("pdtm -ia -bp $HOME/go/bin")

        # Update nuclei templates
        self.print("Installer", "Updating nuclei templates...")
        self.cmd("nuclei -update-templates")

        # A dictionary of other essential command-line tools to check and install
        other_tools = {
            "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
            "unfurl": "go install github.com/tomnomnom/unfurl@latest",
            "ffuf": "go install -v github.com/ffuf/ffuf/v2@latest"
        }

        for tool, install_cmd in other_tools.items():
            self.print("Installer", f"Checking for {tool}...")
            if not self.cmd(f"command -v {tool}", silent=True):
                self.print("Installer", f"{tool} not found. Installing...")
                self.cmd(install_cmd)
            else:
                self.print("Installer", f"{tool} is already installed.", Colors.SUCCESS)


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure argument parser.
    
    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    parser = argparse.ArgumentParser(description='HaxUnit - Web Domain Reconnaissance Tool')
    
    # Required arguments
    parser.add_argument(
        '-d', '--domain',
        type=str,
        help='the website to recon: example.com'
    )
    
    # Scan configuration
    parser.add_argument(
        '-m', '--mode',
        type=str,
        choices=['quick', 'extensive'],
        default='quick',
        help='set scan mode'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        default=True,
        help='print more information'
    )
    
    # Tool configuration
    parser.add_argument(
        '-b', '--bin',
        type=str,
        default='python3',
        help='set which python bin to use'
    )
    
    # Interactsh configuration
    parser.add_argument(
        '-is', '--iserver',
        type=str,
        default='',
        help='interactsh server URL for self-hosted instance'
    )
    
    parser.add_argument(
        '-it', '--itoken',
        type=str,
        default='',
        help='authentication token for self-hosted interactsh server'
    )
    
    # Integration options
    parser.add_argument(
        '-acu', '--use-acunetix',
        action='store_true',
        default='',
        help='Enable Acunetix integration'
    )
    
    parser.add_argument(
        '--wpscan-api-token',
        type=str,
        default='',
        help='The WPScan API Token to display vulnerability data'
    )
    
    # Behavior options
    parser.add_argument(
        '-y', '--yes',
        action='store_true',
        help='yes to all prompts'
    )
    
    parser.add_argument(
        '-u', '--update',
        action='store_true',
        help='update all tools'
    )
    
    parser.add_argument(
        '-i', '--install',
        action='store_true',
        help='install all tools'
    )
    
    parser.add_argument(
        '--skip-installers',
        action='store_true',
        help='Skip tool installation checks'
    )
    
    # Output options
    parser.add_argument(
        '--use-notify',
        action='store_true',
        help='Run notify on completion'
    )
    
    parser.add_argument(
        '--cloud-upload',
        action='store_true',
        help='Upload results to ProjectDiscovery cloud'
    )
    
    # Special modes
    parser.add_argument(
        '--htb',
        action='store_true',
        help='HackTheBox mode'
    )
    
    parser.add_argument(
        '--fuzz',
        action='store_true',
        help='Enable ffuf fuzzing'
    )
    
    parser.add_argument(
        '--use-gpt',
        action='store_true',
        help='Enable GPT suggestions'
    )
    
    return parser


def initialize_scan_directory(domain: str) -> str:
    """
    Create directory structure for scan results.
    
    Args:
        domain: Target domain
        
    Returns:
        str: Path to scan directory
    """
    if not domain:
        return ""
    
    # Create main scans folder
    scans_folder = "scans"
    if not exists(scans_folder):
        mkdir(scans_folder)
    
    # Create domain-specific folder
    domain_folder = os.path.join(scans_folder, domain)
    if not exists(domain_folder):
        mkdir(domain_folder)
    
    # Create timestamped scan folder
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    scan_path = os.path.join(domain_folder, timestamp)
    mkdir(scan_path)
    
    # Create subdirectories
    ffuf_folder = os.path.join(scan_path, "ffuf")
    mkdir(ffuf_folder)
    
    return scan_path


def parse_domain(domain_input: str) -> str:
    """
    Parse and clean domain input.
    
    Args:
        domain_input: Raw domain input
        
    Returns:
        str: Cleaned domain
    """
    if not domain_input:
        return ""
    
    parsed = urlparse(domain_input)
    return parsed.netloc if parsed.netloc else parsed.path


def main():
    """Main entry point for HaxUnit."""
    # Parse arguments
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Clean domain input
    if args.domain:
        args.domain = parse_domain(args.domain)
    
    # Initialize scan directory
    scan_directory = initialize_scan_directory(args.domain)
    
    # Create HaxUnit instance
    hax = HaxUnit(
        site=args.domain,
        mode=args.mode,
        verbose=args.verbose,
        python_bin=args.bin,
        dir_path=scan_directory,
        iserver=args.iserver,
        itoken=args.itoken,
        use_acunetix=args.use_acunetix,
        yes_to_all=args.yes,
        update=args.update,
        install_all=args.install,
        wpscan_api_token=args.wpscan_api_token,
        use_notify=args.use_notify,
        cloud_upload=args.cloud_upload,
        htb=args.htb,
        fuzz=args.fuzz,
        use_gpt=args.use_gpt,
        skip_installers=args.skip_installers
    )
    
    try:
        # Run reconnaissance workflow
        hax.motd()
        hax.htb_add_hosts()
        hax.ffuf_vhosts()
        hax.check_ip()
        
        # Subdomain discovery
        hax.dnsx_subdomains()
        hax.subfinder()
        hax.chaos()
        hax.katana()
        hax.alterx()
        hax.subwiz()
        
        # Network reconnaissance
        hax.dnsx_ips()
        hax.naabu()
        hax.httpx()
        
        
        # Vulnerability scanning
        hax.ffuf()
        hax.wpscan()
        hax.acunetix()
        hax.nuclei()
        
        # Post-processing
        hax.notify()
        hax.gpt()
        hax.report_gen()
        
        # Display completion message
        print(f"\ncd {scan_directory}\n")
        
    except KeyboardInterrupt:
        print(
            f"[{Colors.BOLD}HaxUnit{Colors.RESET}] "
            f"[{Colors.OK}KeyboardInterrupt{Colors.RESET}] "
            f"{Colors.WARNING}Aborted{Colors.RESET}"
        )
    except Exception:
        print_exc()
        print(
            f"[{Colors.BOLD}HaxUnit{Colors.RESET}] "
            f"[{Colors.FAIL}Error{Colors.RESET}] "
            f"{Colors.WARNING}An error occurred - report it at "
            f"https://haxunit.com/discord.php{Colors.RESET}"
        )


if __name__ == '__main__':
    main()
