'''
Coursera:
- Software Defined Networking (SDN) course
-- Programming Assignment: Layer-2 Firewall Application
Professor: Nick Feamster
Teaching Assistant: Arpit Gupta
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
''' Add your imports here ... '''



log = core.getLogger()

''' Add your global variables here ... '''

class Rule:

    def __init__(self):
        self._match = of.ofp_match()
        self._next = Rule.DummyRule()
        self._allow = True

    def tcp (self, src, dst):
        self._match.tcp_src = src
        self._match.tcp_dst = dst

    def ip (self, src, dst, proto):
        self._match.nw_src = src
        self._match.nw_dst = dst
        self._match.nw_proto = proto

    def ethernet (self, src, dst):
        self._match.dl_src = src
        self._match.dl_dst = dst

    def allow(self, allow):
        self._allow = allow

    def next (self, rule):
        self._next = rule

    def match (self, packet):
        if not self.match_tcp(packet):
            return False
        if not self.match_ip(packet):
            return False
        if not self.match_ethernet(packet):
            return False
        return True

    def match_tcp (self, packet):
        tcp = packet.find("tcp")
        if tcp is None:
            return True
        if self._match.tcp_src is not None and self._match.tcp_src != tcp.tcp.srcport:
            return False
        if self._match.tcp_dst is not None and self._match.tcp_dst != tcp.tcp.dstport:
            return False
        return True

    def match_ip (self, packet):
        ip = packet.find("ipv4")
        if ip is None:
            return True
        if self._match.nw_src is not None and self._match.nw_src != ip.srcip:
            return False
        if self._match.nw_dst is not None and self._match.nw_dst != ip.dstip:
            return False
        if self._match.nw_proto is not None and self._match.nw_proto != ip.protocol:
            return False
        return True

    def match_ethernet (self, packet):
        ethernet = packet.find("ethernet")
        if ethernet is None:
            return True
        if self._match.dl_src is not None and self._match.dl_src != ethernet.src:
            return False
        if self._match.dl_dst is not None and self._match.dl_dst != ethernet.dst:
            return False
        return True

    def is_allowed (self, packet):
        if self.match(packet):
            return self._allow and self._next.is_allowed(packet)
        else:
            return self._next.is_allowed(packet)

    class DummyRule:

        def is_allowed(self, packet):
            return True

class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

        #TODO: Config rules
        self._chain = Rule()
        self._chain.ip("10.0.0.1", "10.0.0.2", None)
        self._chain.allow(False)

    def _handle_PacketIn (self, event):
        self.learn(event.parsed)
        if self.is_allowed(event.parsed):
            self.send(event)
        
    def _handle_ConnectionUp (self, event):
        return

    def learn (self, packet):
        #TODO: Add to table
        return

    def send (self, event):
        #TODO: Use table
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
        event.connection.send(msg)

    def is_allowed(self, packet):
        return self._chain.is_allowed(packet)


def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
