#!/usr/bin/env python

from __future__ import print_function
import sys

# Check Python version
pytver = sys.version_info
# sys.version_info(major=2, minor=7, micro=10, releaselevel='final', serial=0)
if pytver[0] == 2 and pytver[1] >= 7:
    pass
else:
    print("Route requires python 2.7")
    sys.exit(1)


import argparse, logging, re, sys, struct, socket, subprocess, signal, time, json, os
from Queue import Queue, PriorityQueue
from threading import Thread
import config, routeconfig, cmdparse, iputil, routethreads, route
from sslserver import SSLServer, PlainServer, BasicAuthRequestHandler, CommonRequestHandler
from route import Route

   
log = logging.getLogger('route')

def perr(msg):
    print(msg, file=sys.stderr)

def create_requesthandlers(routeconf, cmd_queue):
    """Create RequestHandler type. This is a way to avoid global variables: a closure returning a class type that binds routeconf and cmd_queue inside. """

    ver = '0.0.0'
    try:
        version_file = os.path.join(os.path.dirname(__file__), '_version.py')
        with open(version_file) as f:
            verline = f.read().strip()
            VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
            mo = re.search(VSRE, verline, re.M)
            if mo:
                ver = mo.group(1)
            else:
                log.error('Could not find version string in {}'.format(version_file))
    except IOError, e:
        log.error('Could not read {}: {} {}'.format(version_file, e.strerror, e.filename))
    server_ver = 'Security/{}'.format(ver)


    def process(handler, modify, urlpath):
        # modify should be 'D' for DELETE or 'I' for ADD or 'L' for LIST
        assert modify in ['D', 'I', 'L']
        log.debug('PROCESS: {}, URLPATH: {}'.format(modify, urlpath))
      
        try:
            action, rule = cmdparse.parse_command(urlpath)
            log.debug('ACTION: {}   RULE: {}'.format(action, rule))
            if modify == 'L':
                # /help
                if action == 'help':
                    resp = 'READ README'
                    log.debug(resp)
                    log.debug("=========================================================================")
                    return handler.http_resp(200, resp)
                # /list
                elif action == 'list':
                    rules = Route.load().rules
                    list_of_dict = map(route.Rule._asdict, rules)  
                    resp = json.dumps(list_of_dict)
                    log.debug('LIST ROUTE RULES: %s', resp)
                    log.debug("=========================================================================")
                    # Code 200: OK The request has succeeded.
                    return handler.http_resp(200, resp)

            if modify in ['D', 'I'] and action.upper() in route.RULE_TARGETS:
                
                #Convert route.Rule look like JSON
                x = str(rule)
                x = x.replace('Rule', '')
                x = x.replace('(', '{\'')
                x = x.replace(')', '}')
                x = x.replace('=', '\':')
                x = x.replace(', ', ', \'')
                x = x.replace('\'', '\"')
                
                x = json.dumps(x)
                x = json.loads(x)
                log.info(x)
                
                #Run command with ctup
                ctup = (modify, rule)
                cmd_queue.put_nowait(ctup)
                return handler.http_resp(200, x)
            else:
                raise Exception('Unrecognized command.')
        except Exception, e:
            msg = 'ERROR: {}'.format(e.message)
            log.info(msg)
            # Code 400: BAD REQUEST
            return handler.http_resp(400, msg)
            

    class LocalRequestHandler(CommonRequestHandler):
        
        def version_string(self):
            return server_ver

        def go(self, modify, urlpath, remote_addr):
            process(self, modify, urlpath)

        def do_modify(self, modify):
            self.go(modify, self.path, self.client_address[0])

        # -XPUT flag
        def do_PUT(self):
            self.go('I', self.path, self.client_address[0])
        
        # -XDELETE flag
        def do_DELETE(self):
            self.go('D', self.path, self.client_address[0])
    
        # -XGET flag
        def do_GET(self):
            self.go('L', self.path, self.client_address[0])
    

    class OutwardRequestHandler(BasicAuthRequestHandler):
        
        def version_string(self):
            return server_ver

        def creds_check(self, user, password):
            return user == routeconf.auth_username() and password == routeconf.auth_password()

        def go(self, modify, urlpath, remote_addr):
            process(self, modify, urlpath)

        # -XPUT flag
        def do_PUT(self):
            self.go('I', self.path, self.client_address[0])
    
        # -XDELETE flag
        def do_DELETE(self):
            self.go('D', self.path, self.client_address[0])
    
        # -XGET flag
        def do_GET(self):
            self.go('L', self.path, self.client_address[0])
    
   
    return LocalRequestHandler, OutwardRequestHandler


def create_args_parser():
    CONFIG_FILE = '/home/vinhht/route/config/route.conf'
    # TODO change default log level to INFO
    LOG_LEVEL = 'DEBUG'
    LOG_FILE = '/home/vinhht/route/route.log'
    parser = argparse.ArgumentParser(description='route - Route API')
    parser.add_argument('-f', default=CONFIG_FILE, metavar='CONFIGFILE', dest='configfile', help='route config file (default {})'.format(CONFIG_FILE))
    parser.add_argument('--loglevel', default=LOG_LEVEL, help='Log level (default {})'.format(LOG_LEVEL), choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('--logfile', default=LOG_FILE, help='Log file (default {})'.format(LOG_FILE))
    parser.add_argument('-v', help='Verbose console output. Sets DEBUG log level for stderr logger (default ERROR)', action='store_true')
    return parser

def parse_args():
    parser = create_args_parser()
    args = parser.parse_args()
    args.loglevelnum = getattr(logging, args.loglevel)
    return args

def __sigTERMhandler(signum, frame):
    log.debug("Caught signal {}. Exiting".format(signum))
    perr('')
    stop()

def stop():
    logging.shutdown()
    sys.exit(1)


def main():

    args = parse_args()
    try:
        config.set_logging(log, args.loglevelnum, args.logfile, args.v)
    except config.ConfigError, e:
        perr(e.message)
        sys.exit(1)

    if args.v:
        log.info('Console logging in verbose mode')

    log.info("Logging to file: {}".format(args.logfile))
    log.info("File log level: {}".format(args.loglevel))

    try:
        routeconf = routeconfig.RouteConfig(args.configfile)
    except IOError, e:
        perr(e.message)
        create_args_parser().print_usage()
        sys.exit(1)

    Route.ipt_path = routeconf.route_path()

    # Check whether the route command is installed
    try:
        Route.verify_install()
    except Exception, e:
        log.critical(e)
        sys.exit(1)

    # Install signal handlers
    signal.signal(signal.SIGTERM, __sigTERMhandler)
    signal.signal(signal.SIGINT, __sigTERMhandler)
    
    # Show all rule
    rules = Route.load().rules
    log.debug("=============================== All Rules ===============================\n{}".format("\n".join(map(str, rules))))
    log.debug("=========================================================================")

    log.info("Starting SERVER")

    cmd_queue = Queue()

    routethreads.CommandProcessor(cmd_queue).start()

    LocalHandlerClass, OutwardHandlerClass = create_requesthandlers(routeconf, cmd_queue)
    if routeconf.is_outward_server():
        server_address = (routeconf.outward_server_ip(), int(routeconf.outward_server_port()))
        httpd = SSLServer(
                    server_address, 
                    OutwardHandlerClass, 
                    routeconf.outward_server_certfile(), 
                    routeconf.outward_server_keyfile())
        routethreads.ServerRunner(httpd).start()

    if routeconf.is_local_server():
        server_address = ('127.0.0.1', int(routeconf.local_server_port()))
        httpd = PlainServer(
                    server_address, 
                    LocalHandlerClass)
        routethreads.ServerRunner(httpd).start()

    # wait forever
    time.sleep(1e9)


if __name__ == "__main__":
    main()