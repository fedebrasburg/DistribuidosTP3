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
import pox.lib.packet as pkt
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
        self._match.tp_src = src
        self._match.tp_dst = dst

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
        return rule

    def match (self, packet):
        return self.match_tcp(packet) and self.match_ip(packet) and self.match_ethernet(packet)

    def match_tcp (self, packet):
        tcp = packet.find("tcp")
        if tcp is None:
            return not self.requires_tcp_match()
        elif self._match.tp_src is not None and self._match.tp_src != tcp.srcport:
            return False
        elif self._match.tp_dst is not None and self._match.tp_dst != tcp.dstport:
            return False
        else:
            return True

    def match_ip (self, packet):
        ip = packet.find("ipv4")
        if ip is None:
            return not self.requires_ip_match()
        elif self._match.nw_src is not None and self._match.nw_src != ip.srcip:
            return False
        elif self._match.nw_dst is not None and self._match.nw_dst != ip.dstip:
            return False
        elif self._match.nw_proto is not None and self._match.nw_proto != ip.protocol:
            return False
        else:
            return True

    def match_ethernet (self, packet):
        ethernet = packet.find("ethernet")
        if ethernet is None:
            return not self.requires_ethernet_match()
        elif self._match.dl_src is not None and self._match.dl_src != ethernet.src:
            return False
        elif self._match.dl_dst is not None and self._match.dl_dst != ethernet.dst:
            return False
        else:
            return True

    def requires_tcp_match (self):
        return self._match.tp_src is not None or self._match.tp_dst is not None

    def requires_ip_match (self):
        return self._match.nw_src is not None or self._match.nw_dst is not None or self._match.nw_proto is not None

    def requires_ethernet_match (self):
        return self._match.dl_src is not None or self._match.dl_dst is not None

    def is_allowed (self, packet):
        if self.match(packet):
            return self._allow
        else:
            return self._next.is_allowed(packet)

    class DummyRule:

        def is_allowed(self, packet):
            return True

class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

        #1. Se deben descartar todos los mensajes cuyo puerto destino sea 80
        rule1 = Rule()
        rule1.tcp(None, 80)
        rule1.allow(False)

        #2. Se deben descartar todos los mensajes que provengan del host 1, tengan como puerto destino el 5001, y esten utilizando el protocolo UDP
        rule2 = Rule()
        rule2.ip("10.0.0.1", None,  pkt.ipv4.UDP_PROTOCOL) 
        rule2.tcp(None,"5001")
        rule2.allow(False)

        #3. Debe elegir dos host cualquiera y los mismos no deben poder comunicarse de ninguna forma
        rule3 = Rule()
        rule3.ip("10.0.0.1", "10.0.0.2", None)
        rule3.allow(False)

        rule4 = Rule()
        rule4.ip("10.0.0.2", "10.0.0.1", None)
        rule4.allow(False)

        self._chain = rule1
        self._chain.next(rule2).next(rule3).next(rule4)
        
    def _handle_PacketIn (self, event):
        allowed = self.is_allowed(event.parsed)
        if allowed:
            self.send(event)
        self.log(event.parsed, allowed)
        
    def _handle_ConnectionUp (self, event):
        return

    def send (self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
        event.connection.send(msg)

    def is_allowed (self, packet):
        return self._chain.is_allowed(packet)

    def log (self, packet, allowed):
        tcp = self.log_tcp(packet)
        ip = self.log_ip(packet)
        ethernet = self.log_ethernet(packet)
        if allowed:
            log.debug("[ALLOWED]: %s %s %s" % (tcp, ip, ethernet))
        else:
            log.debug("[DISCARDED]: %s %s %s" % (tcp, ip, ethernet))

    def log_tcp (self, packet):
        tcp = packet.find("tcp")
        if tcp is None:
            return ""
        else:
            return "[TCP.port]: %s -> %s" % (tcp.srcport, tcp.dstport)

    def log_ip (self, packet):
        ip = packet.find("ipv4")
        if ip is None:
            return ""
        elif ip.protocol == pkt.ipv4.TCP_PROTOCOL:
	    return "[IP.TCP]: %s -> %s" % (ip.srcip, ip.dstip)
        elif ip.protocol == pkt.ipv4.UDP_PROTOCOL:
            return "[IP.UDP]: %s -> %s" % (ip.srcip, ip.dstip)
        elif ip.protocol == pkt.ipv4.ICMP_PROTOCOL:
            return "[IP.ICPM]: %s -> %s" % (ip.srcip, ip.dstip)
        elif ip.protocol == pkt.ipv4.IGMP_PROTOCOL:
            return "[IP.IGMP]: %s -> %s" % (ip.srcip, ip.dstip)
        else:
            return ""

    def log_ethernet (self, packet):
        ethernet = packet.find("ethernet")
        if ethernet is None:
            return ""
        return "[ETHERNET.%s]: %s -> %s" % (pkt.ETHERNET.ethernet.getNameForType(ethernet.type), ethernet.src, ethernet.dst)
   
def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
