#!/usr/bin/env python

import struct, socket, re


def validate_ip(ip):
     """Check if the IP address has correct format.
     
     return validated and trimmed IP address as string or False if not valid
     """
     if not ip:
         return False
     ip = ip.strip()
     m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
     if m:
         a1, a2, a3, a4 = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
         if a1<256 and a2<256 and a3<256 and a4<256:
             ip_canon = "{}.{}.{}.{}".format(a1, a2, a3, a4)
             return ip_canon
     return False


def validate_port(port):
    """Port number format validator
    return validated port number as string or False if not valid"""
    if not port:
        return False
    port = port.strip()
    if port.isdigit() and int(port) > 0 and int(port) < 65536:
        return port
    return False