#!/bin/sh
set -e

case $1 in
  build)
    clang -o carcer carcer.c -lseccomp
    ;;
  clean)
    rm -f a.out carcer .output .error .trace.output.* 
    ;;
  dockerize)
    docker buildx build . --tag=iudex-carcer
    ;;
  trace)
    rm -f .output .error .trace.output.*
    if [ -z "$2" ]; then
      echo "usage: do.sh trace <program.cc>"
      exit 1
    fi
    g++ -o a.out $2 -static
    shift 1
    strace -ff -o .trace.output ./carcer -o .output -e .error ./a.out $*
    chown pauek:pauek a.out .trace.output.* .output .error
    ;;
  test)
    sudo /home/pauek/.deno/bin/deno run -A test.ts
    ;;
  *)
    echo "usage: do.sh <build | clean | dockerize | test | trace>"
    ;;
esac
