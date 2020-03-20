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

    ips = _get_ip_range_list(conf["iprange"])

    mapping = _get_mac_ip_mapping(ips, conf["interface"])
    _create_hosts_file(conf["mapping"], mapping, conf["output_config"])


def _read_config():
    config_file = "mac_dns.yaml"
    logger.info(f"Loading config from {config_file}")
    with open(config_file, 'r') as fs:
        return yaml.safe_load(fs)


def _get_ip_range_list(ip_range):
    if "/32" in ip_range:
        ips = [ipaddress.IPv4Address(ip_range.split("/32")[0])]
    elif "/" not in ip_range:
        ips = [ipaddress.IPv4Address(ip_range)]
    else:
        ips = list(ipaddress.ip_network(ip_range).hosts())

    if not ips:
        raise Exception(f"No ips found in range: {ip_range}")

    return ips


def _get_mac_ip_mapping(ips: list, interface: str):
    logger.info("Starting MAC search")
    mapping = {}

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


def _create_hosts_file(domain_mapping: list, ip_mac_map: dict, out_file: str):
    file_lines = []
    print(ip_mac_map)
    for dns_map in domain_mapping:
        mac = dns_map["mac"].lower()

        if mac not in ip_mac_map:
            raise Exception(f"Could not find mac: {mac} in scanned IPs. Range can be invalid")

        ip = ip_mac_map[mac]
        name = dns_map["name"]
        file_lines.append(f"{ip}\t{name}\n")

    with open(out_file, "w") as fw:
        fw.writelines(file_lines)


if __name__ == "__main__":
    setup_logger()
    sys.exit(main())
