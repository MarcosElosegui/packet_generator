#!/bin/sh

cd "$(dirname "$0")" || exit

iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

./packet_generator "$@" # -dst <dest_addr> -src <src_addr> -m <subnet_mask> -p <dest_port> -a <protocolo/ataque> -t <numero de threads>