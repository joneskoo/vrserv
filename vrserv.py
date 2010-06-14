#!/usr/bin/env python
# Encoding: UTF-8

from twisted.internet import protocol, reactor, defer
from twisted.protocols import basic
from twisted.python import log

import string
import sys
import random
import md5
import socket
import time
import re
import warnings

class VrservClient(object):
        def __init__(self, ip, mac, cclass):
                self.ip = ip
                self.mac = mac
                self.cclass = cclass
        
        def __cmp__(self, other):
                # This is for comparing VrservClients.
                # If all conditions match,
                if (self.ip != other.ip):
                    return cmp(self.ip, other.ip)
                if (self.mac != other.mac):
                    return cmp(self.mac, other.mac)
                if (self.cclass != other.cclass):
                    return cmp(self.cclass, other.cclass)
                return 0
                
class UnknownCommandError(Exception):
        pass

class InvalidMacAddressError(Exception):
        pass


#class VrservLog(FileLogObserver):
#        def emit(self, logevent):
#                if 'debug' not in logevent:
#                        FileLogObserver.emit(self, logevent)
#
#
#x = Foo('jokufile')
#log.startLoggingWithObserver(x.emit, false)
                        


class VrservProtocol(basic.LineOnlyReceiver):
        """docstring for VrservProtocol"""
        
        helpString = """
         ADD <ip> <mac> <class>
         DEL <ip> <mac> <class>
         RESET
         STATUS
         HELP
         QUIT"""
        
        AUTH_CMDS = ['AUTH', 'CHALLENGE', 'PING', 'HELP', 'QUIT']
        
        authenticated = False
        timeOut = 300

        def runScript(self, script, params):
                proto = ProcessLauncherProtocol()
                params.insert(0, script)
                reactor.spawnProcess(proto, script, params)
        
        def checkMac(self, mac):
                if not re.match('^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac):
                        return False
                if re.match('^[0:]*$', mac):
                        return False
                if re.match('^[fF:]*$', mac):
                        return False
                return True

        def authenticateResponse(self, line):
                '''Correct answer is: md5(secret + challenge).
                '''
                # Calculate correct auth-key:
                m = md5.new(self.factory.secret + self.challenge)
                correct = m.hexdigest()
                log.msg("D: correct answer: %s" % correct)
                if line == correct:
                        return True
                else:
                        return False
        

        #
        # do_*  / command processing functions #
        #
        def do_HELP(self):
                self.successResponse("Help is here")
                self.sendLine(self.helpString)
        
        def do_QUIT(self):
                self.successResponse("Bye!")
                self.transport.loseConnection()
        
        def do_AUTH(self, authkey):
                if self.authenticated is True:
                        self.failResponse("Already authenticated")
                        return
                if self.authenticateResponse(authkey):
                        self.authenticated = True
                        self.successResponse("Authentication successful")
                else:
                        self.failResponse("Authentication failed")
        
        def do_CHALLENGE(self):
                self.successResponse("CHALLENGE %s" % self.challenge)
        
        def do_PING(self):
                self.successResponse("PONG %d" % int(time.time()))
        
        def do_ADD(self, ip, mac, cclass, dummyauth=None):
                # Validate input (ip, mac)
                socket.inet_aton(ip) #raises socket.error if fails
                if self.checkMac(mac) == False:
                        raise InvalidMacAddressError(mac)
                
                c = VrservClient(ip, mac, cclass)
                log.msg("ADD.SH %s %s %s" % (c.ip, mac, c.cclass))
                self.runScript('add.sh', [ip, mac, cclass])
                if c not in self.factory.clients:
                    self.factory.clients.append(c)
                self.successResponse("Client added successfully")

        def do_DEL(self, ip, mac, cclass, dummyauth=None):
                socket.inet_aton(ip)
                if self.checkMac(mac) == False:
                        raise InvalidMacAddressError(mac)
                log.msg("DEL.SH %s %s %s" % (ip, mac, cclass))
                self.runScript('del.sh', [ip, mac, cclass])
                
                try:
                    c = VrservClient(ip, mac, cclass)
                    self.factory.clients.remove(c)
                    self.successResponse("Client removed successfully")
                except ValueError, e:
                    self.successResponse("Client not found, but we did our best")

        def do_VERIFY(self, ip, mac, cclass, dummyauth=None):
                c = VrservClient(ip, mac, cclass)
                try:
                        self.factory.clients.index(c)
                        self.successResponse("1 Client exists")
                except ValueError, e:
                        self.successResponse("0 Client doesn't exist")

        def do_RESET(self, dummyauth=None):
                    log.msg("RESET.SH")
                    self.runScript('reset.sh', [])
                    self.factory.clients = []
                    self.successResponse("Reset successful")
        
        def do_STATUS(self, dummyauth=None):
                self.successResponse("Client listing follows:")
                i = 0
                for c in self.factory.clients:
                        i = i + 1
                        self.transport.write("Client %4d: IP:%15s MAC:<%17s>\r\n" % (i, c.ip, c.mac))
        
        
        #
        # Event processing
        #
        def successResponse(self, response):
                log.msg("sent '+OK %s'" % response, debug=1)
                self.sendLine("+OK %s" % response)
        
        def failResponse(self, response):
                log.msg("sent '-ERR %s'" % response, debug=1)
                self.sendLine("-ERR %s" % response)
                
        def lineReceived(self, line):
                log.msg("received -> " + repr(line), debug=1)
                
                #self.resetTimeout()
                
                try:
                        return self.processCommand(*line.split(' '))
                except (TypeError, UnknownCommandError, InvalidMacAddressError, socket.error), e:
                        self.failResponse('%s: %s' % (e.__class__.__name__, e) )
        
        def connectionMade(self):
                log.msg("D: new connection")
                self.challenge = "%032x" % random.getrandbits(128)
                self.successResponse(self.challenge)

        def processCommand(self, command, *args):
                command = string.upper(command)
                if command not in self.AUTH_CMDS and self.authenticated == False:
                        self.failResponse("Not authenticated")
                        return
                log.msg("D: %s %s" % (repr(command), repr(args)))
                f = getattr(self, 'do_' + command, None)
                if f:
                        return f(*args)
                raise UnknownCommandError(command)
# -------------------------------------------------------------------
# END OF VrservProtocol
# -------------------------------------------------------------------



class VrservFactory(protocol.ServerFactory):
        protocol = VrservProtocol
        secret = 'abdec53578488cb51d87e0e21d40a638'
        clients = []
        log.startLogging(open('vrserv.log', 'w'))
        
class ProcessLauncherProtocol(protocol.ProcessProtocol):
        def connectionMade(self):
            self.transport.closeStdin()
        
        def errReceived(self, data):
            log.err(data)
        
    
reactor.listenTCP(30100, VrservFactory())
reactor.run()
