<h1 align="center">
  <img src="static/logo.png" alt="haxunit" width="200px">
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
- Add https://github.com/Josue87/AnalyticsRelationships
- Add https://github.com/0xInfection/LogMePwn

# Docker installation (recommended)

To ensure a successful installation I recommend using HaxUnit with Docker.

It will take a couple minutes the first time.

```bash
git clone https://github.com/Bandit-HaxUnit/haxunit && cd haxunit
chmod +x rebuild.sh && ./rebuild.sh
```

If everything went well, you'll be in the container ready to run HaxUnit:
```
[HaxUnit] Installation complete - you can start scanning now.
root@2de01337lf4a:/app# python3 main.py -d example.com
```


### Updating HaxUnit using Docker 
If you want to use the latest version of HaxUnit you can use the following command:

```bash
git pull && ./rebuild.sh
```


# Manual installation

Requirements
- `python3` (>=3.8)
- `go` (>=1.17) 
- `unzip` (used until I implement `go get` soon to install tools)
- `docker`

You can install Acunetix by uncommenting `self.install_acunetix()`

Clone repository, install python requirements and automatically install all tools:
```commandline
git clone https://github.com/Bandit-HaxUnit/haxunit
cd haxunit
python3 -m pip install -r requirements.txt
chmod +x install.sh
./install.sh
```

# Post Installation Instructions

## subfinder
Subfinder will work after using the installation instructions however to configure Subfinder to work with certain services, you will need to have setup API keys.</br>
<a href="https://github.com/projectdiscovery/subfinder#post-installation-instructions">More info</a>

## wpscan
The WPScan CLI tool uses the WordPress Vulnerability Database API to retrieve WordPress vulnerability data in real time.</br>

For WPScan to retrieve the vulnerability data an API token must be supplied via the `--wpscan-api-token` parameter.</br>

You can also set it as environment variable in  by renaming `.env.example` to `.env` and filling in your API key.</br>
```WPSCAN_API_KEY=```

An API token can be obtained by registering an account on <a href="https://wpscan.com/register">WPScan.com</a>.

# Usage

```commandline
usage: main.py [-h] [-d DOMAIN] [-m MODE] [-v VERBOSE] [-b BIN] [-is ISERVER] [-it ITOKEN] [-acu ACUNETIX] [-y YES] [-u UPDATE] [-i] [-r RESOLVERS]
               [--wpscan-api-token WPSCAN_API_TOKEN]

HaxUnit

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN the website to recon: example.com
  -m MODE, --mode MODE  you can set to scan `quick` or `extensive`
  -v VERBOSE, --verbose VERBOSE print more information
  -b BIN, --bin BIN     set which python bin to use
  -is ISERVER, --iserver ISERVER interactsh server url for self-hosted instance
  -it ITOKEN, --itoken ITOKEN authentication token for self-hosted interactsh server
  -acu ACUNETIX, --acunetix ACUNETIX
  -y YES, --yes YES     yes to all
  -u UPDATE, --update UPDATE update all tools
  -i, --install         install all tools
  -r RESOLVERS, --resolvers RESOLVERS dnsx - list of resolvers to use (file or comma separated)
  --wpscan-api-token WPSCAN_API_TOKEN The WPScan API Token to display vulnerability data
```

# Running HaxUnit
Run a scan on `example.com`
```commandline
python3 main.py -d example.com
```

Results are saved in `scans/example.com/timestamp/`

# Using Acunetix

HaxUnit uses Acunetix's REST API to automatically create groups and start scans.</br>
You can select to scan all found subdomains or only the main domain.

To generate an API key go to `https://localhost:3443/#/profile`

Pass this API key to `-acu` like the following:

```commandline
python3 main.py -d example.com -acu 2940ad8c0a5b3df4d7028d5f3c06e936c0a42bb5a50d24c69a64e81cd21d62b12
```

You can also set it as environment variable in `.env`</br>
```ACUNETIX_API_KEY=```

<h1 align="center">
  <img src="static/acunetix_api_key.png" alt="acunetix_api_key" width="100%">
  <br>
</h1>


# Functions

| Function          | Type                            | Description                                                                                           |
|-------------------|---------------------------------|-------------------------------------------------------------------------------------------------------|
| sonar_search      | Subdomain discovery             | Use omnisint (FDNS) to search for other TLD's with same name                                          |
| dnsx_subdomains   | Subdomain discovery             | Use dnsx to find subdomains and brute force subdomains                                                |
| subfinder         | Subdomain discovery             | Use subfinder to find subdomains                                                                      |
| gau_unfurl        | Subdomain discovery             | Gather all URL's on the list of subdomains and parse the domain using unfurl                          |
| ripgen            | Subdomain discovery             | Generate and test subdomain permutations                                                              |
 | dnsx_ips          | Get IP addresses                | Use dnsx to fetch A records                                                                           |
| sonar_reverse_dns | Subdomain discovery             | Find subdomains using reverse dns search from omnisint (FDNS)                                         |
| nrich             | Port scan + Subdomain discovery | Faster alternative to active port scanning to naabu                                                   | 
| naabu             | Port scan + Subdomain discovery | Run naabu on the list of subdomains using list of common ports to discover HTTP services              |
| httpx             | Subdomain list validation       | Check all found subdomains if they are active                                                         |
| wpscan            | Vulnerability discovery         | WordPress Security Scanner                                                                            |
| acunetix          | Vulnerability discovery         | Automatically creates a group for the site and starts scans of the subdomains to find vulnerabilities |
| nuclei            | Vulnerability discovery         | Uses all found active subdomains to search for vulnerabilities                                        |

# Workflow
<h1 align="center">
  <img src="static/workflow.png" alt="workflow"></a>
  <br>
</h1>

# Credits
Huge shoutout to https://github.com/projectdiscovery for all their amazing tools.