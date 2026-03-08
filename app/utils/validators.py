import ipaddress
import re

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def is_bogon_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private or
            addr.is_loopback or
            addr.is_link_local or
            addr.is_multicast or
            addr.is_reserved or
            addr.is_unspecified
        )
    except ValueError:
        return False

def is_valid_domain(domain: str) -> bool:
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def is_valid_hash(hash_value: str) -> bool:
    hash_value = hash_value.strip().lower()
    if re.match(r'^[a-f0-9]{32}$', hash_value):
        return True
    if re.match(r'^[a-f0-9]{40}$', hash_value):
        return True
    if re.match(r'^[a-f0-9]{64}$', hash_value):
        return True
    return False

def get_hash_type(hash_value: str) -> str | None:
    hash_value = hash_value.strip().lower()
    if re.match(r'^[a-f0-9]{32}$', hash_value):
        return "md5"
    if re.match(r'^[a-f0-9]{40}$', hash_value):
        return "sha1"
    if re.match(r'^[a-f0-9]{64}$', hash_value):
        return "sha256"
    return None