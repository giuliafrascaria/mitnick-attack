#!/bin/sh


gcc -Wall -Wextra -O3 -o dos -lnet -lpcap dos.c
gcc -Wall -Wextra -O3 -o attack -lnet -lpcap attack.c
gcc -Wall -Wextra -O3 -o enable -lnet enable.c

