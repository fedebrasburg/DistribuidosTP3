#!/bin/bash

sudo mn --custom ./Parte1/parte1.py --topo customTopo,$1,$2 --arp --mac --switch ovsk   --controller remote

