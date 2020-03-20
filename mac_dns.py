import ipaddress
import sys

import yaml
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


def main():
    conf = _read_config()


def _read_config():
    with open("mac_dns.yaml", 'r') as fs:
        return yaml.safe_load(fs)


def _get_mac_ip_mapping():
    mapping = {}
    ips = ipaddress.ip_network('192.168.1.0/30')
    for ip in ips:
        broadcast = Ether(dst="FF:FF:FF:FF:FF:FF")
        arp_request = ARP(pdst=str(ip))
        package = broadcast / arp_request
        ans, uans = srp(package, iface="eth0", timeout=0.1, verbose=False)

        for snd, rcv in ans:
            if rcv:
                ip = rcv[ARP].psrc
                mac = rcv[Ether].src
                mapping[mac] = ip
    return mapping


if __name__ == "main":
    sys.exit(main())
