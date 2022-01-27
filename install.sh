#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

wget https://github.com/KevOub/bonk/blob/master/bonk?raw=true -O /usr/sbin/bonk
chmod u+x /usr/sbin/bonk
echo "Installed the bonk"