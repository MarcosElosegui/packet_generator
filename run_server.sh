#!/bin/sh

cd "$(dirname "$0")" || exit

./server "$@" # -prt <protocolo> -p <puerto>