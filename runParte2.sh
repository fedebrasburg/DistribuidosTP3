#!/bin/bash

sudo mn --custom ./Parte2/parte2.py --topo customTopo,$1 --arp --mac --switch ovsk --controller remote

