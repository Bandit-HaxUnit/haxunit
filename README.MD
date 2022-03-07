<h1 align="center">
  <img src="static/logo.png" alt="haxunit" width="200px"></a>
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

# To-do
- Add host header bruteforce tool to discover virtual hosts

# Installation


Requirements
- `python3` (>=3.8)
- `go` (>=1.17)
- `docker` 

Clone repository, install python requirements and automatically install all tools:
```commandline
$ git clone https://github.com/Bandit-HaxUnit/haxunit
$ cd haxunit
$ python3 -m pip install requirements.txt
$ python3 main.py --install
```

# Docker
Not available yet - the installation is easy however.

# Usage

```commandline
usage: main.py [-h] [-d DOMAIN] [-m MODE] [-v VERBOSE] [-b BIN] [-is ISERVER] [-it ITOKEN] [-acu ACUNETIX] [-y YES] [-u UPDATE] [-i]

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
  -y YES, --yes YES     yes to all
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

# Functions

| Function          | Type                            | Description                                                                                           |
|-------------------|---------------------------------|-------------------------------------------------------------------------------------------------------|
| sonar_search      | Subdomain discovery             | Use omnisint (FDNS) to search for other TLD's with same name                                          |
| dnsx_subdomains   | Subdomain discovery             | Use dnsx to find subdomains and brute force subdomains                                                |
| subfinder         | Subdomain discovery             | Use subfinder to find subdomains                                                                      |
| gau_unfurl        | Subdomain discovery             | Gather all URL's on the list of subdomains and parse the domain using unfurl                          |
 | dnsx_ips          | Get IP addresses                | Use dnsx to fetch A records                                                                           |
| sonar_reverse_dns | Subdomain discovery             | Find subdomains using reverse dns search from omnisint (FDNS)                                         |
| nrich             | Port scan + Subdomain discovery | Faster alternative to active port scanning to naabu                                                   | 
| naabu             | Port scan + Subdomain discovery | Run naabu on the list of subdomains using list of common ports to discover HTTP services              |
| httpx             | Subdomain list validation       | Check all found subdomains if they are active                                                         |
| acunetix          | Vulnerability discovery         | Automatically creates a group for the site and starts scans of the subdomains to find vulnerabilities |
| nuclei            | Vulnerability discovery         | Uses all found active subdomains to search for vulnerabilities                                        |

# Workflow
<h1 align="center">
  <img src="static/workflow.png" alt="workflow"></a>
  <br>
</h1>

# Credits
Huge shoutout to https://github.com/projectdiscovery for all their amazing tools.