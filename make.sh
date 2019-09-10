#!/bin/sh

gcc -Wall -Wextra -O3 -o attack -lnet -lpcap attack.c
