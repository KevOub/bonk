#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

mkdir /var/bonk
wget https://github.com/KevOub/bonk/blob/master/bonk?raw=true -O /var/bonk/bonk
chmod 600 /var/bonk/bonk
