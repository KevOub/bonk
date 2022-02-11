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
    echo "todo remove audit"
    exit
fi

if command -v auditd &> /dev/null
then
    echo "todo remove audit"
    exit
fi


wget -O /usr/sbin/bonk https://github.com/KevOub/bonk/blob/master/bonk?raw=true 
chmod u+x /usr/sbin/bonk; out="$?"

if [[$out -eq 0]]; then
   echo "Installed the bonk"
else
   echo "failed to install bonk"
fi