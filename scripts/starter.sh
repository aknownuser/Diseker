#! /bin/bash

function process_follower {
	
#	echo "Starting values PID=$1 Folder=$2"
	#for pid in $(ausearch -i --ppid $1 -m SYSCALL | grep SYSCALL | cut -d ' ' -f 15 | cut -d '=' -f 15 | cut -d '=' -f 2 | uniq -d)
	#do
	#	echo "Loop: PID = $PID PPID=$1" 
	#	process_follower $pid $2

	#	ausearch -i -p $pid -m SYSCALL > $2/"$pid"".$1".logs
	#done

	while read pid
	do
		echo "Loop: PID = $pid PPID = $1"
		if [ "$pid" == " " ]
		then
			continue
		fi
		
		process_follower "$pid" "$2"
		
		ausearch -i -p $pid -m SYSCALL < /var/log/audit/audit.log  > $2/"$pid"".$1".logs

		#while [ ! -f /var/log/audit/audit.log ]; do sleep 1; done

		#process_follower $pid $2

	done< <(ausearch -i --ppid $1 -m SYSCALL | grep SYSCALL | cut -d ' ' -f 15 | cut -d '=' -f 2 | uniq -d)
}

#Lets execute the file and obtain the file PID
BASE=$(pwd)
NAME=$1
SYSCALL_PATH=logs/syscalls
NET_PATH=logs/network

mkdir -p $NET_PATH
mkdir -p $SYSCALL_PATH

tcpdump -nn -s0 -w $NET_PATH/net_logs.pcap &

TCPDUMP_PID="$!"

./$NAME &
APP_PID="$!"

echo "The pid of the process is $APP_PID"

sleep 1m

echo "First Analysis" 

ausearch -i -p "$APP_PID" -m SYSCALL > $SYSCALL_PATH/$APP_PID.logs

#process_follower $APP_PID tmp

./follower.sh $APP_PID $BASE/$SYSCALL_PATH

kill -15 $TCPDUMP_PID

# Get the FTP traffic 
tcpdump -nn -vA -r $NET_PATH/net_logs.pcap port ftp or ftp-data -w $NET_PATH/ftp_net.pcap

#Get NTP traffic 
tcpdump -nn -vA -r $NET_PATH/net_logs.pcap port 123 -w $NET_PATH/ntp_net.pcap

#Get RDP traffic
tcpdump -nn -r $NET_PATH/net_logs.pcap "port 3389" -w $NET_PATH/rdp_net.pcap

#Get ICMP traffic
tcpdump -nn -r $NET_PATH/net_logs.pcap icmp -w $NET_PATH/icmp_net.pcap

#Get DNS traffic
tcpdump -nn -r $NET_PATH/net_logs.pcap "port 53" -w $NET_PATH/dns_net.pcap

#Get Telnet traffic 
tcpdump -nn -r $NET_PATH/net_logs.pcap "port 23" -w $NET_PATH/telnet_net.pcap

#Get HTTP/s traffic
tcpdump -nn -r $NET_PATH/net_logs.pcap port 80 or port 443 -w $NET_PATH/http_net.pcap
