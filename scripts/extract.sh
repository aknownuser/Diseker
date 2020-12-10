#!/bin/bash

if [ $# -lt 2 ]
then
  echo "Usage: extract.sh filesystem dest_folder"
  exit 1
fi

SYSCALL=logs/syscalls
NET=logs/network
mkdir -p $2/$SYSCALL
mkdir -p $2/$NET

syscall_logs=$(e2ls $1:/root/$SYSCALL)

for fl in $syscall_logs
do
  e2cp $1:/root/$SYSCALL/$fl $2/$SYSCALL
done

net_logs=$(e2ls $1:/root/$NET)

for fl in $net_logs
do
  e2cp $1:/root/$NET/$fl $2/$NET
done

exit 0