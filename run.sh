#!/bin/sh

cd "$(dirname "$0")" || exit

iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

./packet_generator "$@" # <dest_addr> <src_addr> <subnet_mask> <dest_port> <protocolo/ataque>