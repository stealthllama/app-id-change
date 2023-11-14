# app-id-change
This is a collection of scripts used to automation the configuration of PAN-OS vulnerability protection profiles and custom reports used to track rules and applications that may be impacted by changes to App-ID signatures.

## Requirements
- Python3
- certifi==2023.7.22
- charset-normalizer==3.3.2
- idna==3.4
- python-dotenv==1.0.0
- requests==2.31.0
- urllib3==2.0.7

## Installation
1. Clone the git repo

```bash
git clone https://github.com/stealthllama/app-id-change
```

2. Change into the repo directory

```bash
cd app-id-change
```

3. Create a python virtual environment

```bash
python3 -m venv .venv
```

4. Activate the virtual environment

```bash
source .venv/bin/activate
```

5. Install the required python packages

```bash
pip install -r requirements.txt
```

## Usage
The repo contains two scripts used to create configuration on a Panorama instance.  You will need administrative access to the Panorama instance and the ability to write configuration and run reports.

The `app-id-profile.py` script is used to create a new vulnerability management profile or update an existing one to match on threat logs containing an `app-id-change` threat category.

```bash
usage: app-id-profile.py [-h] [-d DEVICEGROUP] panorama profile

Create or update a vulnerability protection profiles to check for app-id-change events

positional arguments:
  panorama              The IP or FQDN of the Panorama instance
  profile               The name of the Vulnerability Protection Profile

options:
  -h, --help            show this help message and exit
  -d DEVICEGROUP, --devicegroup DEVICEGROUP
                        The name of the Panorama Device Group
```

The `app-id-report.py` script is used to create a new custom report that will be scheduled to run daily and provide summary details of the rules and applications that will be impacted by a pending App-ID signature change.

```bash
usage: app-id-report.py [-h] [-d DEVICEGROUP] panorama

Create a report that summarizes app-id-change events

positional arguments:
  panorama              The IP or FQDN of the Panorama instance

options:
  -h, --help            show this help message and exit
  -d DEVICEGROUP, --devicegroup DEVICEGROUP
                        The name of the Panorama Device Group
```

Both scripts take an optional argument of `-d DEVICEGROUP` or `--devicegroup DEVICEGROUP`.  If this argument is not provided the configuration will be shared with all device groups.

## Authentication
The scripts authenticate to the Panorama API using HTTP Basic Authentication.  They require the environment variables `PANORAMA_USERNAME` and `PANORAMA_PASSWORD` that should contain the Panorama adminstrator's username and password respectively.  These may be defined in a `.env` file located in the local directory or `$HOME` directory.

