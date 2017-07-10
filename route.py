#!/usr/bin/env python

import inspect, re, subprocess, logging, json, iputil
from collections import namedtuple
from threading import RLock

# Follow the logging convention:
# - Modules intended as reusable libraries have names 'lib.<modulename>' what allows to configure single parent 'lib' logger for all libraries in the consuming application
# - Add NullHandler (since Python 2.7) to prevent error message if no other handlers present. The consuming app may add other handlers to 'lib' logger or its children.
log = logging.getLogger('lib.{}'.format(__name__))
log.addHandler(logging.NullHandler())

# note that the 'in' attribute from route output was renamed to 'inp' to avoid python keyword clash
ROUTE_HEADERS = ['Destination', 'Gateway', 'Genmask', 'Flags', 'Metric', 'Ref', 'Use', 'Iface']
RULE_ATTRS =    ['target', 'Destination', 'Gateway', 'Genmask', 'Flags', 'Metric', 'Ref', 'Use', 'Iface']
RULE_TARGETS =  ['ADD', 'DEL']


RuleProto = namedtuple('Rule', RULE_ATTRS)

class Rule(RuleProto):
    #Lightweight immutable value object to store Route rule
    def __new__(_cls, *args, **kwargs):
        #Construct Rule tuple from a list or a dictionary
        if args:
            if len(args) != 1:
                raise ValueError('The Rule constructor takes either list, dictionary or named properties')
            props = args[0]
            if isinstance(props, list):
                return RuleProto.__new__(_cls, *props)
            elif isinstance(props, dict):
                d = {'target': '', 'Destination': '', 'Gateway': '', 'Genmask': '', 'Flags': '', 'Metric': '', 'Ref': '', 'Use': '', 'Iface': ''}
                d.update(props)
                return RuleProto.__new__(_cls, **d)
            else:
                raise ValueError('The Rule constructor takes either list, dictionary or named properties')
        elif kwargs:
            return RuleProto.__new__(_cls, **kwargs)
        else:
            return RuleProto.__new__(_cls, [])

    def __eq__(self, other):
        #Rule equality should ignore such parameters like num, pkts, bytes
        if isinstance(other, self.__class__):
            return self.target == other.target and self.Destination == other.Destination and self.Gateway == other.Gateway and self.Genmask == other.Genmask and self.Flags == other.Flags and self.Metric == other.Metric and self.Ref == other.Ref and self.Use == other.Use and self.Iface == other.Iface
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)


class Route:
    # global lock for system Route access
    lock = RLock()
    # store ipt_path as class variable, it's a system wide singleton anyway
    ipt_path = 'route'

    def __init__(self, rules):
        # check the caller function name - the poor man's private constructor
        if inspect.stack()[1][3] == 'load':
            # after this initialization self.rules should be read-only
            self.rules = rules
        else:
            raise Exception("Use Route.load() to create an instance with loaded current list of rules")

    @staticmethod
    def load():
        rules = Route._route_list()
        inst = Route(rules)
        return inst

    @staticmethod
    def verify_install():
        #Check if Route installed
        try:
            cmd = [Route.ipt_path] + ['-n']
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        #except OSError, e:
        except subprocess.CalledProcessError, e:
            log.error("Could not find {}. Check if it is correctly installed and if the path is correct.".format(Route.ipt_path))
            raise e

    @staticmethod
    def _route_list():
        #List and parse Route rules.
        rules = []
        out = Route.exe(['-n'])

        for line in out.split('\n'):
            line = line.strip()
            if "Destination" in line:
                # check if Route output headers make sense 
                assert line.split() == ROUTE_HEADERS
                continue
            columns = line.split()
            # First column is a IP Address. Because using "route -n"
            if columns and iputil.validate_ip(columns[0]):
                # Target is not defined in Routing Table
                target = 'NULL'
                columns.insert(0, target)
                rule = Rule(columns)
                rules.append(rule)
        return rules
    
    @staticmethod
    def rule_to_command(r):
        lcmd = []
        if r.Destination:
            lcmd.append('-net')
            lcmd.append(r.Destination)
        if r.Genmask:
            lcmd.append('netmask')
            lcmd.append(r.Genmask)
        if r.Gateway:
            # Not value -net meaning that add/delete default gatway
            if not r.Destination:
                lcmd.append('default')
            lcmd.append('gateway')
            lcmd.append(r.Gateway)
        if r.Iface:
            lcmd.append('dev')
            lcmd.append(r.Iface)


        return lcmd

    @staticmethod
    def exe_rule(modify, rule):
        assert modify == 'I' or modify == 'D'
        lcmd = Route.rule_to_command(rule)
        if modify == 'I':
            return Route.exe(['add'] + lcmd)
        else:
            return Route.exe(['delete'] + lcmd)

    @staticmethod
    def exe(lcmd):
        cmd = [Route.ipt_path] + lcmd
        print("RUN COMMAND: {}".format(cmd))
        print("DEBUG =========================================================================")

        try:
            log.debug('Route.exe(): {}'.format(' '.join(cmd)))
            with Route.lock:
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            if out: 
                log.debug("Route.exe() output: {}".format(out))
            return out
        except subprocess.CalledProcessError, e:
            log.error("Error code {} returned when called '{}'. Command output: '{}'".format(e.returncode, e.cmd, e.output))
            raise e