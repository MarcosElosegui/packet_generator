#!/bin/sh

cd "$(dirname "$0")" || exit

./server "$@" # <protocolo> <puerto>