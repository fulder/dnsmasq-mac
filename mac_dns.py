import ipaddress

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp



broadcast = Ether(dst="FF:FF:FF:FF:FF:FF")
arp_request = ARP(pdst="192.168.1.1/24")
ans, uans = srp(broadcast / arp_request, iface="enp0s31f6", timeout=2, inter=1)

for snd, rcv in ans:
    print(rcv.sprintf(r"%Ether.src% - %ARP.psrc%"))
print("\nScan complete")
