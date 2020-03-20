import ipaddress
import sys

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


def main():
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
                print(f"{ip} - {mac}")


if __name__ == "main":
    sys.exit(main())
