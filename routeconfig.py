#!/usr/bin/env python

import logging, sys, types, os.path, re
import config, iputil
from ConfigParser import NoOptionError

log = logging.getLogger('route.routeconfig')

class RouteConfig(config.Config):

    def __init__(self, path):
        
        try:
            config.Config.__init__(self, path)

            # Fail early validations. Read all properties to validate and show config dependencies
            # Also display a short error message for the user instead of full stacktrace
            if self.is_outward_server():
                self.outward_server_port()
                self.outward_server_ip()
            if self.is_local_server():
                self.local_server_port()
                self.is_local_server_authentication()
            self.is_non_restful()
            if self.is_outward_server() or self.is_local_server_authentication():
                self.auth_username()
                self.auth_password()
            self.route_path()
        except config.ConfigError, e:
            log.error(str(e))
            sys.exit(1)
        except Exception, e:
            # other errors need to be wrapped to include the config file path info
            log.error(self.config_error(str(e)))
            sys.exit(1)            

        try:
            # provide more info for these options if not given correctly
            if self.is_outward_server():
                self.outward_server_certfile()
                self.outward_server_keyfile()
        except config.ConfigError, e:
            log.error(str(e))
            log.error('Before running Route you must generate or import certificates. See README')
            sys.exit(1)
 

    def is_outward_server(self):
        return self._getflag("outward.server", "outward.server not enabled. Ignoring outward.server.port and outward.server.ip if present.")
    
    def outward_server_port(self):
        if self.is_outward_server():
            port = self._get("outward.server.port")
            if port and iputil.validate_port(port):
                return port
            else:
                raise self.config_error("Wrong outward.server.port value. It should be a single number from the 1..65535 range")
        else:
            self.config_error("outward.server.port read while outward.server not enabled")
    

    def outward_server_ip(self):
        if self.is_outward_server():
            try:
                return self._get("outward.server.ip")
            except NoOptionError, e:
                raise self.config_error(str(e))
        else:
            raise self.config_error("outward.server.ip read while outward.server not enabled")
    
    def outward_server_certfile(self):
        if self.is_outward_server():
            return self._getfile("outward.server.certfile")
        else:
            raise self.config_error("outward.server.certfile read while outward.server not enabled")
 

    def outward_server_keyfile(self):
        if self.is_outward_server():
            return self._getfile("outward.server.keyfile")
        else:
            raise self.config_error("outward.server.keyfile read while outward.server not enabled")


    def is_local_server(self):
        return self._getflag("local.server", "local.server not enabled. Ignoring local.server.port if present.")
    
    
    def local_server_port(self):
        if self.is_local_server():
            try:
                port = self._get("local.server.port")
                if port and iputil.validate_port(port):
                    return port
                else:
                    raise self.config_error("Wrong local.server.port value. It should be a single number from the 1..65535 range")
            except NoOptionError, e:
                raise self.config_error(str(e))
        else:
            raise self.config_error("local.server.port read while local.server not enabled")
    
    def is_non_restful(self):
        return self._getflag("non.restful")
    
    def is_local_server_authentication(self):
        if self.is_local_server():
            return self._getflag("local.server.authentication")
        else:
            raise self.config_error("local.server.authentication read while local.server not enabled")
    
    
    def auth_username(self):
        if self.is_outward_server() or self.is_local_server_authentication():
            try:
                username = self._get("auth.username")
                if username:
                    return username
                else:
                    raise self.config_error("auth.username cannot be empty")
            except NoOptionError, e:
                raise self.config_error(str(e))
        else:
            raise self.config_error("auth.username read while outward.server not enabled and local.server.authentication not enabled")
    
    
    def auth_password(self):
        if self.is_outward_server() or self.is_local_server_authentication():
            try:
                password = self._get("auth.password")
                if password:
                    return password
                else:
                    raise self.config_error("auth.password cannot be empty")
            except NoOptionError, e:
                raise self.config_error(str(e))
        else:
            raise self.config_error("auth.password read while outward.server not enabled and local.server.authentication not enabled")


    def route_path(self):
        ipt = self._get('route.path')
        if ipt:
            return ipt
        else:
            raise self.config_error('route.path cannot be empty')
