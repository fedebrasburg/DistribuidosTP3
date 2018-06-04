#!/usr/bin/python
# -*- coding: utf-8 -*-
# sudo mn --custom ./Parte1/parte1.py --topo customTopo --arp --mac --switch ovsk
from mininet.topo import Topo

import math

def get_switch_amount(switch_level): 
    sum = math.pow(2,switch_level -1) 
    while (0 < switch_level -1):
        sum = sum + math.pow(2,switch_level -1) 
        switch_level -= 1
    return sum

def createLayers(self, layersCount):
    switchAmount = get_switch_amount(layersCount)
    print "Switch amount: " + str(switchAmount)
    layers = []
    c = 1
    id = 1
    for i in range((layersCount * 2) - 1):
        switchAmount -= c
        if (switchAmount < 0):
            raise ValueError('Error')
        switchesInLayer = []
        for x in range(c):
            switchesInLayer.append(self.addSwitch('s' + str(id) ))
            id += 1
        layers.append(switchesInLayer)
        if(switchAmount < c):
            c /= 2
        else:
            c *= 2
    return layers

def addEdges(self, layers):
    for i in range(len(layers) - 1):
        n = 0
        if len(layers[i]) < len(layers[i + 1]):
            for v in layers[i]:
                self.addLink(v, layers[i+1][n])
                self.addLink(v, layers[i+1][n+1])
                n += 2
        else:
            for v in layers[i+1]:
                self.addLink(layers[i][n], v)
                self.addLink(layers[i][n+1], v)
                n += 2

def createHosts(self, hostsAmount):
    hosts = []
    for i in range(hostsAmount):
        hosts.append(self.addHost('h'+str(i+1)))
    return hosts

def addHosts(self, layers, hosts):
    for i in range(len(hosts)):
        if ( i <= len(hosts)/2 ):
            self.addLink(hosts[i], layers[0][0])
        else:
            self.addLink(hosts[i], layers[len(layers)-1][0])



class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self,layers, hosts):
        "Create custom topo."
	print "Layers ",layers
	print "Hosts ",hosts
        # Initialize topology
        Topo.__init__( self )

        layers = createLayers(self, layers)
        addEdges(self, layers)
        addHosts(self, layers, createHosts(self, hosts))


topos= {'customTopo': MyTopo}



