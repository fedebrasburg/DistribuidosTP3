#!/bin/bash

cp ./Parte2/firewall.py ~/pox/
~/pox/pox.py log.level --DEBUG firewall
