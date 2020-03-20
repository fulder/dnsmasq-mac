#!/bin/sh

# Sending SIGHUP (-1) will reload config see: 
# https://serverfault.com/questions/723292/dnsmasq-doesnt-automatically-reload-when-entry-is-added-to-etc-hosts

while true
do
    python3 mac_dns.py
    if test -f "trigger_reload"; then
        pkill -1 dnsmasq
        rm trigger_reload
    fi
    sleep 10
done