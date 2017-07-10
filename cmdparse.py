#!/usr/bin/env python

import sys, logging, urlparse, re
import iputil, route
from route import Rule

log = logging.getLogger("route.cmdparse")


def convert_iface(iface):
    """Convert iface string like 'any', 'eth', 'eth0' to route iface naming like *, eth+, eth0. """
    if iface == 'any':
        return '*'
    else:
        # append '+' quantifier to iface
        if not iface[-1].isdigit():
            iface += '+'
        return iface


class PathError(Exception):
    def __init__(self, path, msg=''):
        Exception.__init__(self, 'Incorrect path: {}. {}'.format(path, msg))


def parse_command_path(path):
    # split url path into parts, lowercase, trim trailing slash, return tuple
    def path_parts(path):
        path = path.strip().lower()
        if path == '/help':
            return 'help', None
        # Right Syntax: /???
        if len(path) < 1 or path[0] != '/':
            raise PathError(path)

        if path[-1] == '/':
            path = path[:-1]
        p = map(str.strip, path.split('/'))
        p = tuple(p[1:])
        return p

    p = path_parts(path)

    # for path = '/' return 'help' action
    if not p or p[0] == 'help':
        return 'help', None

    # action: ADD or DEL
    action = p[0]

    # RULE_TARGETS =  ['ADD', 'DEL']
    if action.upper() in route.RULE_TARGETS:
        try:
            return action, build_rule(p)
        except ValueError, e:
            raise PathError(path, e.message)
    elif action == 'list':
        if len(p) == 1:
            return action, None
        
    raise PathError(path)


# From the path parts tuple build and return Rule for add/del type of command
def build_rule(p):
    # Check target valid or not
    target = p[0].upper()
    if target not in route.RULE_TARGETS:
        raise ValueError('The action should be one of {}'.format(route.RULE_TARGETS))

    ip = gw = mask = iface = ""

    if target == 'ADD':
        if len(p) < 1:
            raise ValueError('Not enough details to construct the rule')
        # Add default gateway: /add/ip
        elif len(p) == 2 and iputil.validate_ip(p[1]):
            gw = p[1];
        elif len(p) < 4:
            raise ValueError('Invalid rule')
        # Add network to Routing Table. Can use /add/ip/mask/gw or /iface
        elif len(p) >= 4:
            ip = iputil.validate_ip(p[1])
            if not ip:
                raise ValueError('Incorrect IP address')  
            mask = iputil.validate_ip(p[2])
            if not mask:
                raise ValueError('Invalid netmask address')  
            # p3 is gateway or dev              
            gw = iputil.validate_ip(p[3])
            if not gw:
                iface = p[3]
                if len(iface) > 16:
                    raise ValueError('Interface name too long. Max 16 characters')
                iface = convert_iface(iface)
                gw = ''
            # /add/ip/mask/gw/iface
            if len(p) == 5:
                iface = p[4]
                if len(iface) > 16:
                    raise ValueError('Interface name too long. Max 16 characters')
                iface = convert_iface(iface)

    elif target == 'DEL':
        # Delete default gateway: /delete/ip
        if len(p) == 2 and iputil.validate_ip(p[1]):
            gw = p[1];
        elif len(p) < 3:
            raise ValueError('Not enough details to construct the rule')
        # /del/ip/mask
        elif len(p) >= 3 and iputil.validate_ip(p[1]):
            ip = p[1]
            if not ip:
                raise ValueError('Incorrect IP address')
            mask = p[2]
            if not mask:
                raise ValueError('Invalid netmask address')
        # /del/ip/mask + /gateway or /dev
            if len(p) == 4:
                gw = iputil.validate_ip(p[3])
                if not gw:
                    iface = p[3]
                    if len(iface) > 16:
                        raise ValueError('Interface name too long. Max 16 characters')
                    iface = convert_iface(iface)
                    gw = ''
            # del/ip/mask/gateway/dev
            elif len(p) == 5:
                gw = iputil.validate_ip(p[3])
                if not gw:
                    raise ValueError('Incorrect gateway address')
                iface = p[4]
                if len(iface) > 16:
                    raise ValueError('Interface name too long. Max 16 characters')
                iface = convert_iface(iface)

    return Rule({'target': target, 'Destination': ip, 'Gateway': gw, 'Genmask': mask, 'Iface': iface})


def parse_command(url):
    parsed = urlparse.urlparse(url)
    path = parsed.path
    action, rule = parse_command_path(path)

    return (action, rule)