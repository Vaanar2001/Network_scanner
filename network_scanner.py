#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-r", "--range", dest="range", help="set the range of network")
    options, arguments = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for answer in answered_list:
        client_dict = {"ip": answer[1].psrc, "mac": answer[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(result_list):
    print("IP\t\t\tMAC ADDRESS\n-----------------------------------------------")
    for result in result_list:
        print(result["ip"] + "\t\t" + result["mac"])

options = get_arguments()
ip = options.range

scan_result = scan(ip)
print_result(scan_result)

