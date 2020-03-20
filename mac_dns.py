import ipaddress
import logging
import sys

import yaml
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

logger = logging.getLogger(__name__)


def setup_logger():
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    logger.addHandler(handler)


def main():
    conf = _read_config()
    logger.setLevel(conf["log_level"])

    mapping = _get_mac_ip_mapping(conf["iprange"], conf["interface"])


def _read_config():
    config_file = "mac_dns.yaml"
    logger.info(f"Loading config from {config_file}")
    with open(config_file, 'r') as fs:
        return yaml.safe_load(fs)


def _get_mac_ip_mapping(ip_range: str, interface: str):
    logger.info("Starting MAC search")
    mapping = {}
    ips = list(ipaddress.ip_network(ip_range).hosts())
    count = 1
    for ip in ips:
        logger.info(f"Sending ARP broadcast for IP {ip} ({count}/{len(ips)})")
        broadcast = Ether(dst="FF:FF:FF:FF:FF:FF")
        arp_request = ARP(pdst=str(ip))
        package = broadcast / arp_request
        ans, uans = srp(package, iface=interface, timeout=0.1, verbose=False)

        for snd, rcv in ans:
            if rcv:
                ip = rcv[ARP].psrc
                mac = rcv[Ether].src
                mapping[mac] = ip
        count += 1
    return mapping


if __name__ == "main":
    setup_logger()
    sys.exit(main())
