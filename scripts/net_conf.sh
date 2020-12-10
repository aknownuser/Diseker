#! /bin/bash

function usage {
  echo "./net_conf.sh physical_interface";
}

function except {
  if [ $1 -ne 0 ]; then
    echo "ERROR when executing $2"
    exit "$1";
  fi
}

if [ "$#" -ne 2 ]; then
  echo "Not enough parameters";
  usage;
  exit 1;
fi

echo ">> Creating bridge"
ip link add br0 type bridge
except $? "[Bridge]"

echo ">> Creating TAP0"
ip tuntap add dev tap0 mode tap
except $? "[Creating TAP0]"
echo ">> Creating TAP1"
ip tuntap add dev tap1 mode tap
except $? "[Creating TAP1]"
echo ">> Creating TAP2"
ip tuntap add dev tap2 mode tap
except $? "[Creating TAP2]"
echo ">> Creating TAP3"
ip tuntap add dev tap3 mode tap
except $? "[Creating TAP3]"

echo ">> Bridging interface $1"
ip link set "$1" master br0
except $? "[Bridge interface $1]"
echo ">> Bridging interface TAP0"
ip link set tap0 master br0
except $? "[Bridge interface tap0]"
echo ">> Bridging interface TAP1"
ip link set tap1 master br0
except $? "[Bridge interface tap1]"
echo ">> Bridging interface TAP2"
ip link set tap2 master br0
except $? "[Bridge interface tap2]"
echo ">> Bridging interface TAP3"
ip link set tap3 master br0
except $? "[Bridge interface tap3]"

ip link set dev br0 up

# Add the address
echo ">> Adding address $2 to br0"
dhcpd br0
except $?

# Add address to the tap devices
ip addr add 10.10.1.2/24 dev tap0
except $?
ip addr add 10.10.1.3/24 dev tap1
except $?
ip addr add 10.10.1.4/24 dev tap2
except $?
ip addr add 10.10.1.5/24 dev tap3
except $?

echo ">> Getting up the taps"
#Set up all the taps and interfaces
ip link set tap1 up
except $?
ip link set tap2 up
except $?
ip link set tap0 up
except $?
ip link set tap3 up
except $?


sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.10.1.0/24 -j MASQUERADE



# Set the routing with
 # ip address delete $PREFIX dev eth0
 # ip address add $PREFIX dev br0
 # ip route add default via $ROUTE dev br0
# Try not to delete the previous addresses and attenpt to create a new network
echo "Everything went well enjoy"
exit 0