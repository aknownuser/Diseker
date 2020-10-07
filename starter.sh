#! /bin/bash

function process_follower {
  while read line
  do
    ausearch -i -p "$line" -m SYSCALL > $/"$line"".$1".logs
    process_follower $1 $2

  done< <(auserach -i --ppid "$1" -m SYSCALL | grep SYSCALL | cut -d ' ' -f 15 | cut -d '=' -f 2 | uniq -d)
}
#Lets execute the file and obtain the file PID
NAME=$1

./$NAME &
APP_PID="$!"

echo "The pid of the process is $APP_PID"
sleep 1m

ps -o pid,tname,cmd -T $APP_PID

mkdir -p tmp

ausearch -i -p "$APP_PID" -m SYSCALL > tmp/$APP_PID.logs

process_follower $APP_PID tmp