#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   printf "\n[*] Script must be run as root\n"
   exit 1
fi

wget -O /usr/sbin/bonk https://github.com/KevOub/bonk/blob/master/bonk?raw=true 
chmod u+x /usr/sbin/bonk
echo "Installed the bonk"