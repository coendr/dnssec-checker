# DNSSEC Zone Checker

## Build Status

#### Gitlab CI
Stable Build: 
[![pipeline status](https://gitlab.com/hermeias/dnssec-checker/badges/master/pipeline.svg)](https://gitlab.com/hermeias/dnssec-checker/commits/master)
[![coverage report](https://gitlab.com/hermeias/dnssec-checker/badges/master/coverage.svg)](https://gitlab.com/hermeias/dnssec-checker/commits/master)  
Development Build: 
[![pipeline status](https://gitlab.com/hermeias/dnssec-checker/badges/develop/pipeline.svg)](https://gitlab.com/hermeias/dnssec-checker/commits/develop)
[![coverage report](https://gitlab.com/hermeias/dnssec-checker/badges/develop/coverage.svg)](https://gitlab.com/hermeias/dnssec-checker/commits/develop)

## Features
- ZSK lookup in domain child zone RRset
- DS lookup in domain parent zone RRset
- Email notification based on results RRset
- Repeated search when lookup unsuccessful


## Requirements
- Python 3.7 or later with pip installed
- Pip Libraries
    - dnspython3 (Version 1.15.0 or later)
    - validate_email (Version 1.3 or later)

## Installation

#### OSX and Linux

1. Install the required pip libraries  
`pip3 install -r requirements.txt`

2. Copy config.json.example over to config.json  
`cp config.json.example config.json`

3. Add your credentials in the config.json (See [Configuration](#configuration))


#### Windows
1. Install the required pip libraries   
`pip install -r requirements.txt`

2. Copy config.json.example over to config.json

3. Add your credentials in the config.json (See [Configuration](#configuration))

## Configuration
Config.json
```
  "DOMAIN_NAME": "domain.nl",           # Domain name RRset to lookup in the resolver (Required)
  "ZSK": "",                            # ZSK DNSKEY that needs to be checked in the currrent RRset (Optional)
  "DS": "",                             # DS that needs to be checked in the currrent RRset (Optional)
  "SMTP_SENDER":"email@domain.nl",      # Email addres that send the email (Optional if USE_EMAIl is False)
  "SMTP_PASSWORD": "...",               # Password of the Senders email (Optional if USE_EMAIl is False)
  "SMTP_SERVER":"smtp.domain.nl",       # SMTP Server of the Sender email (Optional if USE_EMAIl is False)
  "SMTP_PORT":465,                      # SMTP Port of the SMTP Server [465 | 587] (Optional if USE_EMAIl is False)
  "SMTP_RECEIVER": "email@domain.nl",   # Email address that receives the email (Optional if USE_EMAIl is False)
  "USE_EMAIL": "True",                  # Enable email sending [True | False] (REQUIRED)
  "CONTINUE_AFTER_ONE_TRY": "True",     # Retry after one go [True | False] (REQUIRED)
```

## How to run

#### With configuration

1. Start the Script  
    Windows:
    `$ pyhton main.py`  
    Mac OS and Linux: 
    `$ pyhton3 main.py`

2. Wait until the script finds your given ZSK and/ or DS in the RRset of the given domain

3. Wait until the script ends and take the following action. 
   ZSK Updated: Transfer the domain  
   DS Updated: Update the parent zone NS record of the domain

#### With optional arguments
1. Start the Script

    ZSK only:  
    Windows: `$ pyhton main.py -dm <DOMAIN> -zsk <ZSK>`  
    Mac OS and Linux: `$ pyhton3 main.py -dm <DOMAIN> -zsk <ZSK>`
    
    DS only:  
    Windows: `$ pyhton main.py -dm <DOMAIN> -ds <DS>`  
    Mac OS and Linux: `$ pyhton3 main.py -dm <DOMAIN> -ds <DS>`
    
    Both ZSK and DS:  
    Windows: `$ pyhton main.py -dm <DOMAIN> -zsk <ZSK> -ds <DS>`  
    Mac OS and Linux: `$ pyhton3 main.py -dm <DOMAIN> -zsk <ZSK> -ds <DS>`
    
2. Wait until the script finds your given ZSK and/ or DS in the RRset of the given domain

3. Wait until the script ends and take the following action. 
    ZSK Updated: Transfer the domain  
    DS Updated: Update the parent zone NS record of the domain
    
## Usage:
```
  $ python main.py
  -h, --help                    show help message and exit  
  -v, --version                 show program's version number and exit  
  -r, --repeat                  Repeat Querying after one try  
  -e, --email                   Send email after done querying (Must have config.json file enabled)  
  -dm DOMAIN, --domain DOMAIN   Search the given domain in resolver  
  -zsk ZSK                      Search the given ZSK key in the domain current child zone RRset  
  -ds DS                        Search the DS in the domain current Parent Zone RRset  
```