<h1 align="center">
  <img src="static/logo.png" alt="httpx" width="200px"></a>
  <br>
</h1>

<p align="center">
  <a href="#intro">Intro</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#running-haxunit">Running HaxUnit</a> •
  <a href="#functions">Functions</a>
</p>

# Intro
HaxUnit combines multiple active and passive subdomain enumeration tools and port scanning tools with vulnerability discovery tools.

For each subdomain enumeration tool you'll be prompted to add the new discovered subdomains to the list.</br>
If you see unrelated subdomains you can decline and you'll be asked again with only subdomains of the same domain as the input.

If you don't want to be asked to add the domains you can use the `-y` parameter.

# Installation


Requirements (you can run `main.py` as root to automatically install these, except python3):
- `python3` (>=3.8)
- `unzip`
- `pip3`
- `git`
- `docker`


Clone repository and automatically install all dependencies:
```commandline
$ git clone https://github.com/Bandit-HaxUnit/haxunit
$ cd haxunit
$ python3 main.py --install
```

# Docker
Not available yet - the installation is easy however.

# Usage

```commandline
usage: main.py [-h] [-d DOMAIN] [-m MODE] [-v VERBOSE] [-b BIN] [-is ISERVER] [-it ITOKEN] [-acu ACUNETIX] [-y YOLO]
               [-u UPDATE] [-i]

HaxUnit

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        the website to recon: example.com
  -m MODE, --mode MODE  you can set to scan `quick` or `extensive`
  -v VERBOSE, --verbose VERBOSE
                        print more information
  -b BIN, --bin BIN     set which python bin to use
  -is ISERVER, --iserver ISERVER
                        interactsh server url for self-hosted instance
  -it ITOKEN, --itoken ITOKEN
                        authentication token for self-hosted interactsh server
  -acu ACUNETIX, --acunetix ACUNETIX
  -y YOLO, --yolo YOLO  yes to all
  -u UPDATE, --update UPDATE
                        update all tools
  -i, --install         install all tools
```

# Running HaxUnit
Run a scan on `example.com`
```commandline
python3 main.py -d example.com
```

Results are saved in `scans/example.com/timestamp/` and also a local SQLite database.


## Web
W.I.P. - Preview coming soon!

# Functions

| Function           | Type                            | Description                                                                                           |
|--------------------|---------------------------------|-------------------------------------------------------------------------------------------------------|
| check_ip           | Security                        | Check if user IP is from a VPN, Proxy or a VPS to prevent leaking real IP (optional)                  |
| add_domain_to_db   | DB                              | Add domain name to table in database                                                                  |
| create_scan_in_db  | DB                              | Create a new scan in database to save results and to use in website                                   |
| sonar_search       | Subdomain discovery             | Use omnisint (FDNS) to search for other TLD's with same name                                          |
| c99_subdomains     | Subdomain discovery             | Use c99's API to find subdomains                                                                      |
| dnscan             | Subdomain discovery             | Use dnscan to find subdomains and recursively brute force subdomains (includes wildcard detection)    |
| subfinder          | Subdomain discovery             | Use subfinder to find subdomains                                                                      |
| crtsh              | Subdomain discovery             | Use crt.sh website to find subdomains                                                                 |
| write_subdomains   | File                            | Write list of subdomains to file                                                                      |
| naabu              | Port scan + Subdomain discovery | Run naabu on the list of subdomains using list of common ports to discover HTTP services              |
| gau_unfurl         | Subdomain discovery             | Gather all URL's on the list of subdomains and parse the domain using unfurl                          | 
| httpx              | Subdomain list validation       | Check all found subdomains if they are active                                                         | 
| nrich              | Port scan + Subdomain discovery | Faster alternative to active port scanning to naabu                                                   | 
| sonar_reverse_dns  | Subdomain discovery             | Find subdomains using reverse dns search from omnisint (FDNS)                                         |
| acunetix           | Vulnerability discovery         | Automatically creates a group for the site and starts scans of the subdomains to find vulnerabilities |
| nuclei             | Vulnerability discovery         | Uses all found active subdomains to search for vulnerabilities                                        | 
| cleanup            | Cleanup                         | Cleaning up of log files and more                                                                     |


# Flowchart
![Flowchart](/static/flowchart.png)

# Credits
Huge shoutout to https://github.com/projectdiscovery for all their amazing tools.