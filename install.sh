#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   printf "\n[*] Script must be run as root\n"
   exit 1
fi

if command -v bonk &> /dev/null
then
    echo "bonk is already installed"
    exit
fi

if command -v audit &> /dev/null
then
    service auditd stop
    service audit stop
    exit
fi

mkdir -p /var/log/bonk/
touch /var/log/bonk/bonk.log
mkdir -p /etc/bonk/
wget -O /etc/bonk/bonk.json https://github.com/KevOub/bonk/blob/dev2/config.json?raw=true 


wget -O /usr/sbin/bonk https://github.com/KevOub/bonk/blob/dev2/bonk?raw=true 
chmod u+x /usr/sbin/bonk; out="$?"

if [[ $out -eq 0 ]]; then
   echo "Installed the bonk"
else
   echo "failed to install bonk"
fi