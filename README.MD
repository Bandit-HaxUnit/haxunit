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

<p align="center">
   <a href="https://haxunit.com" style="font-size:50px">HaxUnit.com</a></br>
   <a href="https://discord.gg/83xfCdRP7Y" style="font-size:50px">Join the Discord!</a></br>
</p>

# 📘Intro

HaxUnit is a Python script designed for comprehensive reconnaissance and security assessment of web domains. It integrates various tools for subdomain enumeration, port scanning, vulnerability scanning, and more.</br>
</br>
HaxUnit is focused on simplicity and aims to be the best and most complete solution for web security assessments.
## ✨ Features

- **Subdomain Enumeration**: Uses tools like Subfinder, DNSx, and custom bruteforce methods.
- **Port Scanning**: Utilizes Naabu for fast port scanning across discovered subdomains.
- **Vulnerability Scanning**: Integrates Nuclei for detecting security issues across web applications.
- **WordPress Scanning**: Uses WPScan to identify vulnerabilities in WordPress installations.
- **Acunetix Integration**: Provides optional integration with Acunetix for web application security scanning.

## 🔥 Docker (recommended)</summary>

 For a reliable installation, it's recommended to use HaxUnit with Docker Compose.
 
 This initial setup may take a few minutes:
 
1. **Clone the Repository:**

 ```bash
git clone https://github.com/Bandit-HaxUnit/haxunit && cd haxunit 
```

2. (optional) **Rename `.env.example` to `.env` and fill in the API keys.**

```commandline
ACUNETIX_THRESHOLD=30
ACUNETIX_API_KEY=
NUCLEI_API_KEY=
WPSCAN_API_KEY=
```

3. **Build and Run Docker Compose:**

```bash
chmod +x rebuild-compose.sh && ./rebuild-compose.sh
 ```
 
 Once the installation completes successfully, you'll be inside the Docker container, ready to execute HaxUnit:
 
 ```
🎉 Installation Complete! 🎉
HaxUnit is now ready to rock!
Time to find those vulnerabilities and patch them like a pro! 🕵️‍♂️🔍

🚀 To start scanning, run the following command:
haxunit -d <domain>
 ```

# 🛠️ Install HaxUnit Manually

Make sure you have the following software installed on your system:

- `python3` (>=3.10)
- `go` (>=1.122) 
- `docker.io` (>=20.10.7)

1. **Clone the Repository:**

    Open a terminal and run the following command to clone the repository and navigate into the project directory:
    ```sh
    git clone https://github.com/Bandit-HaxUnit/haxunit && cd haxunit
    ```

2. **Install `python3.11-venv` (if needed):**

    If you don't have the `venv` module installed, you may need to install it. Run one of the following commands depending on your Python version:
    ```sh
    sudo apt update
    sudo apt install python3.11-venv
    ```
    Or for Python 3.10:
    ```sh
    sudo apt update
    sudo apt install python3.10-venv
    ```

3. **Create a Virtual Environment:**

    Create a virtual environment named `haxunit-venv`:
    ```sh
    python3 -m venv haxunit-venv
    ```

4. **Activate the Virtual Environment:**

    Activate the virtual environment using the following command:
    ```sh
    source haxunit-venv/bin/activate
    ```

    Note: To deactivate the virtual environment later, you can simply run `deactivate`.

5. **Install the Required Packages:**

    With the virtual environment activated, install the necessary packages:
    ```sh
    python3 -m pip install -r requirements.txt
    ```

6. **Run the Installation Script:**

    Finally, run the main script with the `--install` flag:
    ```sh
    haxunit --install
    ```
   
If everything is installed correctly you should see the following output:
```commandline
[HaxUnit] [Init] All tools are successfully installed - good luck!
```


# 📖 Usage
```commandline
haxunit -h
```

This will display help for the tool. Here are all the switches it supports.

```commandline
usage: main.py [-h] [-d DOMAIN] [-m {quick,extensive}] [-v] [-b BIN] [-is ISERVER] [-it ITOKEN] [-acu] [-y] [-u] [-i] [--wpscan-api-token WPSCAN_API_TOKEN]
               [--use-notify] [--cloud-upload]

HaxUnit

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        the website to recon: example.com
  -m {quick,extensive}, --mode {quick,extensive}
                        set scan mode
  -v, --verbose         print more information
  -b BIN, --bin BIN     set which python bin to use
  -is ISERVER, --iserver ISERVER
                        interactsh server URL for self-hosted instance
  -it ITOKEN, --itoken ITOKEN
                        authentication token for self-hosted interactsh server
  -acu, --use-acunetix  Acunetix API key
  -y, --yes             yes to all
  -u, --update          update all tools
  -i, --install         install all tools
  --wpscan-api-token WPSCAN_API_TOKEN
                        The WPScan API Token to display vulnerability data
  --use-notify          Run notify on completion
  --cloud-upload        Upload results to ProjectDiscovery cloud
 ```

### Examples

Run a quick scan on `example.com`:
```commandline
haxunit -d example.com
```

Run a quick scan on `example.com` saying yes to adding domains by default:
```commandline
haxunit -d example.com -y
```

Run an extensive scan on `example.com` using Acunetix and uploading results to ProjectDiscovery cloud:
```commandline
haxunit -d example.com -m extensive --use-acunetix --cloud-upload 
```

### Viewing Results

Results from the scan will be saved in the following directory structure:

```markdown
scans/
└── example.com/
    └── timestamp/
```

Replace `example.com` with your target domain and `timestamp` with the date and time when the scan was conducted. 
This structure organizes scan results chronologically under the respective domain folder within the scans directory.


# 🤖 Automate using Apache Airflow

This repository includes a sample Apache Airflow DAG that automates the HaxUnit scanning process.



### Setup instructions

1. **Clone the Repository**:</br>
Clone this repository into the `dags` directory of your Apache Airflow installation.
```commandline
 git clone https://github.com/Bandit-HaxUnit/haxunit && cd haxunit
```

2. **Rename `.env.example` to `.env` and fill in the API keys.**

```commandline
ACUNETIX_THRESHOLD=30
ACUNETIX_API_KEY=
NUCLEI_API_KEY=
WPSCAN_API_KEY=
```

3. **Configure Notifications**:</br>
To receive notifications upon completion, rename `notify-config.yaml.example` to `notify-config.yaml`.</br>

Example configuration for Slack notifications:

```bash
slack:
  - id: "slack"
    slack_channel: "automated-pentest"
    slack_username: "HackerBot"
    slack_format: "{{data}}"
    slack_webhook_url: "https://hooks.slack.com/services/XXXXX"
```

4. **Setup the DAG**:</br>
Rename `dags.py.example` to `dags.py` and configure it according to your needs.</br>
<br/>Don't forget to use `--use-notify` to enable notifications.

5. **Build and Run HaxUnit**:</br>
After configuring the notification settings, build and run HaxUnit with the following command:

```bash
chmod +x rebuild-compose.sh && ./rebuild-compose.sh
```

### That's It!
By following these steps, you can now automate your pentests using Apache Airflow. Enjoy the streamlined process!



# 🛡️ Acunetix

HaxUnit utilizes Acunetix's REST API to automate group creation and initiate scans.</br>

To generate an API key, visit [Profile Page](https://localhost:3443/#/profile).

Insert the API key in the `.env` file.
```commandline
ACUNETIX_API_KEY=
```

Rebuild docker compose to apply the changes:
```commandline
./rebuild-compose.sh
```


To run HaxUnit with Acunetix, use the following command:
```commandline
haxunit -d example.com --use-acunetix
```




<details>
  <summary>Installing Acunetix</summary>

 To install Acunetix, execute the following command:

```commandline
bash <(wget -qO- https://raw.githubusercontent.com/Bandit-HaxUnit/acu/main/install.sh) vouu/acuss:14.7.220228146
```

This will download and install the Acunetix container. </br>
Once the installation is complete, you can start using Acunetix with HaxUnit.

Acunetix can be accessed at https://localhost:3443. <br>

<details>
   <summary>Use the following default credentials to log in:</summary>

```commandline
Username: awvs@awvs.com
Password: Awvs@awvs.com
```
</details>

</details>

# 🔍 Functions

| Function        | Type                  | Description                                                                                           |
|-----------------|-----------------------|-------------------------------------------------------------------------------------------------------|
| dnsx_subdomains | Subdomain discovery   | Use dnsx to find subdomains and brute force subdomains                                                |
| subfinder       | Subdomain discovery   | Use subfinder to find subdomains                                                                      |
| katana          | Crawling              | Gather all URL's on the list of subdomains and parse the domain using unfurl                          |
| ripgen          | Subdomain permutation | Generate and test subdomain permutations                                                              |
| dnsx_ips        | Fetch IP addresses    | Use dnsx to fetch A records                                                                           |
| naabu           | Port scan discovery   | Run naabu on the list of subdomains using list of common ports to discover HTTP services              |
| httpx           | Subdomain validation  | Check all found subdomains if they are active                                                         |
| wpscan          | Vulnerability scanner | WordPress Security Scanner                                                                            |
| acunetix        | Vulnerability scanner | Automatically creates a group for the site and starts scans of the subdomains to find vulnerabilities |
| nuclei          | Vulnerability scanner | Uses all found active subdomains to search for vulnerabilities                                        |

# 📂 Workflow
<img src="static/workflow.png" alt="workflow">

# 🙏 Credits
### Special thanks to the team at [ProjectDiscovery](https://github.com/projectdiscovery) for their incredible range of tools.

</br></br>
<p align="center">
   <a href="https://haxunit.com" style="font-size:50px">HaxUnit.com</a></br>
   <a href="https://discord.gg/83xfCdRP7Y" style="font-size:50px">Join the Discord!</a></br>
</p>