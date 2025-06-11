# IPSee - Network package sniffer

IPSee is a python script used to collect TCP/IP packages and return header fields of the protocol.

**Disclamer**: Currently, this script focuses on MQTT packets, but can be extended to any packet transported by TCP/IP.

# Project structure

```
camed_ipsee/
├── ipsee.py                                # Main script
├── net_helper.py                           # Helper to network interfaces selection
├── logs/
│   └── ipsee.log                           # The IPSee capture log
├── model/
│   └── model.pickle                        # The machine learn model pickle file
├── results/
│   └── output_cep_analysis.csv             # The CEP analysis output csv file
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