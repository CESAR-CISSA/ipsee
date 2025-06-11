#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IPSee - Network package sniffer
======================================

Python script to collect MQTT packages
and return header fields of protocols

======================================
"""


from scapy.all import sniff, IP, TCP, ls
from scapy.contrib.mqtt import MQTT
from net_helper import NetworkInterfaceManager
import logging
import sys
import io


# Tee class to write to multiple outputs
class Tee:
    def __init__(self, *files):
        self.files = files

    def write(self, data):
        for f in self.files:
            f.write(data)
            f.flush()

    def flush(self):
        for f in self.files:
            f.flush()


class MQTTSniffer:
    def __init__(self, log_file, iface, sport, dport):
        self.log_file = log_file
        self.iface = iface
        self.dport = dport
        self.sport = sport

        log_array = []
        self.log_array = log_array

        logging.basicConfig(filename=self.log_file, level=logging.INFO, format='%(message)s')
        logging.info("Starting IPSee...")
    

    def packet_callback(self, packet):
        if IP in packet and TCP in packet and (packet[TCP].sport == sport or packet[TCP].dport == dport) and MQTT in packet:
            captured_output = io.StringIO()
            original_stdout = sys.stdout
            sys.stdout = Tee(original_stdout, captured_output)

            print("------------------------------------------------------------------------------------")
            print(">> IP Summary:")
            ls(packet[IP])

            print("\n>> TCP Summary:")
            ls(packet[TCP])

            print("\n>> MQTT Summary:")
            ls(packet[MQTT])
            print("------------------------------------------------------------------------------------\n")

            sys.stdout = original_stdout
            logging.info(f"{captured_output.getvalue().strip()}")
    

    def start_sniffing(self):
        print(f"Capturing packets from interface {iface} on port {dport} and logging to {log_file}...")

        try:
            sniff(iface=self.iface, filter=f"tcp and port {dport}", prn=self.packet_callback)
        except KeyboardInterrupt:
            print("\nIPSee was interrupted.")
            logging.info("IPSee was interrupted by user.")
        finally:
            logging.info("Finishing IPSee.")


def main(log_file, iface, sport, dport):
    sniffer = MQTTSniffer(log_file, iface, sport, dport)
    sniffer.start_sniffing()


if __name__ == "__main__":
    manager = NetworkInterfaceManager()
    selected_interface = manager.choose_interface_cli()

    log_file = "logs/ipsee.log"
    iface = selected_interface
    sport = 1883
    dport = 1883

    main(log_file, iface, sport, dport)

