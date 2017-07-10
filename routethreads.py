#!/usr/bin/env python

from __future__ import print_function
from threading import Thread
import time, logging
import iputil, route
from route import Route

log = logging.getLogger('route.routethreads')


class CommandProcessor(Thread):

    def __init__(self, cmd_queue):
        Thread.__init__(self)
        self.cmd_queue = cmd_queue
        self.setDaemon(True)

    def run(self):
        while True:
            modify, rule = self.cmd_queue.get()
            try:
                if modify == 'I':
                    Route.exe_rule(modify, rule)
                elif modify == 'D':
                    Route.exe_rule(modify, rule)
                elif modify == 'L':
                    pass
            finally:    
                self.cmd_queue.task_done()


class ServerRunner(Thread):

    def __init__(self, httpd):
        Thread.__init__(self)
        self.httpd = httpd
        self.setDaemon(True)

    def run(self):
        sa = self.httpd.socket.getsockname()
        log.info("Serving HTTP on {} port {}".format(sa[0], sa[1]))
        self.httpd.serve_forever()