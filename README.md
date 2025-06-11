# IPSee - Network package sniffer

IPSee is a python script to collect packages and return the protocols header fields.

# Project structure

```
camed_ipsee/
├── ipsee.py                                # Main script
├── net_helper.py                           # Helper to network interfaces selection
├── logs/
│   └── ipsee.log                           # The IPSee capture log
├── requirements.txt                        # Required python libraries
├── README.md                               # This file
```

# Installation

## Dependences

    Python 3.12 or higher

## How to install

    $ virtualenv venv
    $ source venv/bin/activate
    $ pip3 install -r requirements.txt

# How to execute

    $ sudo su
    $ source venv/bin/activate
    $ python3 ipsee.py