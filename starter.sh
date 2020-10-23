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
NAME=$1

mkdir -p network
mkdir -p tmp

tcpdump -nn -s0 -w network/net_logs.pcap & 
TCPDUMP_PID="$!"

./$NAME &
APP_PID="$!"

echo "The pid of the process is $APP_PID"

sleep 1m

echo "First Analysis" 

ausearch -i -p "$APP_PID" -m SYSCALL > tmp/$APP_PID.logs 

#process_follower $APP_PID tmp

./follower.sh $APP_PID tmp

kill -9 $TCPDUMP_PID

# Get the FTP traffic 
tcpdump --vAs0 -r network/net_logs.pcap "port ftp or ftp-data" >network/ftp_net.logs 

#Get NTP traffic 
tcpdump --vAs0 -r network/net_logs.pcap "port 123" >network/ntp_net.logs

#Get RDP traffic 
tcpdupm -r network/net_logs.pcap "port 3389" > network/rdp_net.logs

#Get ICMP traffic
tcpdump -r network/net_logs.pcap icmp > network/icmp_net.logs

#Get DNS traffic
tcpdump -r network/net_logs.pcap "port 53" >network/dns_net.logs

#Get Telnet traffic 
tcpdump -r network/net_logs.pcap "port 23" >network/telnet_net.logs

#ausearch -i --ppid "$APP_PID" -m SYSCALL | grep SYSCALL | cut -d ' ' -f 15 | cut -d '=' -f 2 | uniq -d
