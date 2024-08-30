#!/usr/bin/env python3
import os
import socket

import dns.query
import dns.resolver
import dns.update
import dns.tsigkeyring
from flask import Flask, jsonify

# Configuration
keyname = os.getenv("NSUPDATE_KEYNAME", "your-default-key-here")
keyval = os.getenv("NSUPDATE_KEY", "your-default-key-here")
dnsserver = os.getenv("DNS_SERVER", "<DNS SERVER IP ADDRESS>")
zone = os.getenv("DNS_ZONE", "zone.example.com")
ttl = 600

# Security enhancements
def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except socket.error:
        return False
    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:
        return False
    return True

def is_valid_address(address):
    return is_valid_ipv4_address(address) or is_valid_ipv6_address(address)

def get_ip_type(ip):
    return 'A' if is_valid_ipv4_address(ip) else 'AAAA'

def get_full_ptr(ip):
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"

def is_valid_hostname(host):
    return all(c.isalnum() or c == '-' for c in host) and len(host) <= 255

def host_in_dns(host):
    try:
        fqdn = f"{host}.{zone}"
        answers = dns.resolver.resolve(fqdn, 'A' if is_valid_ipv4_address(dnsserver) else 'AAAA')
        return bool(answers)
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.NXDOMAIN:
        return False

def get_ip(host):
    fqdn = f"{host}.{zone}"
    try:
        answers = dns.resolver.resolve(fqdn, 'A' if is_valid_ipv4_address(dnsserver) else 'AAAA')
        return answers[0].to_text()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

def rev_in_dns(ip):
    try:
        ptr_record = get_full_ptr(ip)
        answers = dns.resolver.resolve(ptr_record, 'PTR')
        return bool(answers)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False

app = Flask(__name__)

@app.route('/')
def home():
    return 'Mikrotik DHCP DNS Updater'

@app.route('/update/<host>/<ip>', methods=['POST'])
def update(host=None, ip=None):
    if not host or not ip:
        return "Invalid request", 400

    if not is_valid_address(ip):
        return "Invalid IP address", 400

    if not is_valid_hostname(host):
        return "Invalid hostname", 400

    if host_in_dns(host):  # delete old entries
        delete(host)

    fqdn = f"{host}.{zone}"
    t = get_ip_type(ip)
    ptr = get_full_ptr(ip)

    try:
        update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({keyname: keyval}), keyalgorithm=dns.tsig.HMAC_MD5)
        update.add(host, ttl, t, ip)
        update.add(ptr, ttl, 'PTR', fqdn)

        response = dns.query.tcp(update, dnsserver)
        print(response)
        return "OK", 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/delete/<host>', methods=['POST'])
def delete(host=None):
    if not is_valid_hostname(host):
        return "Invalid hostname", 400

    if not host_in_dns(host):
        return "Host not found in DNS", 404

    ip = get_ip(host)
    if not ip:
        return "IP not found for host", 404

    t = get_ip_type(ip)

    try:
        update = dns.update.Update(zone, keyring=dns.tsigkeyring.from_text({keyname: keyval}), keyalgorithm=dns.tsig.HMAC_MD5)
        if rev_in_dns(ip):
            ptr = get_full_ptr(ip)
            update.delete(ptr, 'PTR')

        update.delete(host, t)

        response = dns.query.tcp(update, dnsserver)
        print(response)
        return "OK", 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
