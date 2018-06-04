#!/usr/bin/python
# -*- coding: utf-8 -*-
# sudo mn --custom ./Parte1/parte1.py --topo customTopo --arp --mac --switch ovsk
from mininet.topo import Topo

import math

def createLayers(self, layersCount):
    layers = []
    id = 1
    for i in range(layersCount):
	switch =  self.addSwitch('s' + str(id) )
        id += 1
        layers.append(switch)
    return layers

def addEdges(self, layers):
    for i in range(len(layers) - 1):
    	self.addLink(layers[i],layers[i+1])

def createHosts(self, hostsAmount):
    hosts = []
    for i in range(hostsAmount):
        hosts.append(self.addHost('h'+str(i+1)))
    return hosts

def addHosts(self, layers, hosts):
    for i in range(len(hosts)):
        if ( i %2==0 ):
            self.addLink(hosts[i], layers[0])
        else:
            self.addLink(hosts[i], layers[len(layers)-1])



class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self,layers):
        "Create custom topo."
	print "Layers ",layers
        # Initialize topology
        Topo.__init__( self )
	hosts = 4
        layers = createLayers(self, layers)
        addEdges(self, layers)
        addHosts(self, layers, createHosts(self, hosts))


topos= {'customTopo': MyTopo}



