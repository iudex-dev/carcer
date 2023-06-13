#!/bin/sh
rm -f .output .error .trace.output.*
g++ -o a.out $1 -static
shift 1
strace -ff -o .trace.output ./carcer -o .output -e .error ./a.out $*
chown pauek:pauek a.out .trace.output.* .output .error