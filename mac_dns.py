import ipaddress
import logging
import os
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
    mac_dns = _mac_list_to_dict(conf["mapping"])

    mapping = _get_mac_ip_mapping(ips, conf["interface"], mac_dns)
    _create_hosts_file(mapping, conf["output_config"])


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


def _mac_list_to_dict(mapping: list):
    mac_to_name = {}
    for m in mapping:
        mac_to_name[m["mac"].lower()] = m["name"]
    return mac_to_name


def _get_mac_ip_mapping(ips: list, interface: str, mac_names: dict):
    logger.info("Starting MAC search")
    ip_dns_mapping = {}

    count = 1
    for ip in ips:
        logger.info(f"Sending ARP broadcast for IP {ip} ({count}/{len(ips)})")

        if len(ip_dns_mapping) == len(mac_names):
            break

        broadcast = Ether(dst="FF:FF:FF:FF:FF:FF")
        arp_request = ARP(pdst=str(ip))
        package = broadcast / arp_request
        ans, uans = srp(package, iface=interface, timeout=0.1, verbose=False)

        for snd, rcv in ans:
            if rcv:
                ip = rcv[ARP].psrc
                mac = rcv[Ether].src

                if mac in mac_names:
                    ip_dns_mapping[ip] = mac_names[mac]

        logger.info(f"Found MACs: {len(ip_dns_mapping)} / {len(mac_names)}")
        count += 1

    if len(ip_dns_mapping) != len(mac_names):
        logger.warning(f"Found ips: {ip_dns_mapping}")
        raise Exception("Couldn't find all specified MAC addresses, make sure the range is correct")
    return ip_dns_mapping


def _create_hosts_file(ip_dns_mapping: dict, out_file: str):
    current_conf = None
    if os.path.isfile(out_file):
        with open(out_file, "r") as fr:
            current_conf = fr.readlines()

    lines_to_write = []
    for ip in ip_dns_mapping:
        name = ip_dns_mapping[ip]
        lines_to_write.append(f"{ip}\t{name}\n")

    if set(current_conf) == set(lines_to_write):
        logger.info(f"Output file: {out_file} already up to date")
        return

    with open(out_file, "w") as fw:
        fw.writelines(lines_to_write)

    # Create a file to notfiy reload_config.sh script
    open("trigger_reload", "w").close()


if __name__ == "__main__":
    setup_logger()
    sys.exit(main())
