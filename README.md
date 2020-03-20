This script uses [scapy](https://github.com/secdev/scapy) and, performing an ARP scan, creates a hosts file mapping IP with a domain name from specified MAC to domain name list.

# Running

* Edit `mac_dns.yaml.example` config file to your liking
* Remove the `.example` suffix from `mac_dns.yaml.example`
* `sudo python3 mac_dns.py`

# Example

Lets assume there exists a device with a MAC address `AA:BB:11:22:33:44` with corresponding LAN IP address: `192.168.1.139` 
Config:
```yaml
# IP Range
iprange: "192.168.1.1/24"

# Interface to use for the arp scan
interface: "eth0"

# Log level
log_level: "INFO"

# MAC to Domain Name mapping
mapping:
  - mac: "AA:BB:11:22:33:44"
    name: "myname.domain.com"

# hosts config path to write IP - DNS name entries to
output_config: "hosts.conf"
``` 

* `sudo python3 mac_dns.py` produces `hosts.conf`:
```
192.168.1.139	myname.domain.com
```

