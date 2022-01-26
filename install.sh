#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

mkdir /var/bonk && cd bonk
wget https://raw.githubusercontent.com/KevOub/bonk/master/audit.rules -O audit.rules
cp audit.rules /etc/audit/rules.d/audit.rules  
augenrules --load
sudo systemctl restart auditd
wget https://github.com/KevOub/bonk/blob/master/bonk?raw=true -O bonk
chmod 600 bonk
./bonk