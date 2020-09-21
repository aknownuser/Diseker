#! /bin/bash

function usage {
  echo "./net_conf.sh physical_interface address_to_use route_address";
}

function except {
  if [ $1 -ne 0 ]; then
    echo "ERROR when executing $2"
    exit "$1";
  fi
}

if [ "$#" -ne 3 ]; then
  echo "Not enough parameters";
  usage;
  exit 1;
fi

echo ">> Creating bridge"
ip link add br0 type bridge
except $? "[Bridge]"

echo ">> Creating TAP1"
ip tuntap add dev tap1 mode tap
except $? "[Creating TAP1]"
echo ">> Creating TAP2"
ip tuntap add dev tap2 mode tap
except $? "[Creating TAP2]"

echo ">> Bridging interface $1"
ip link set "$1" master br0
except $? "[Bridge interface $1]"
echo ">> Bridging interface TAP1"
ip link set tap1 master br0
except $? "[Bridge interface tap1]"
echo ">> Bridging interface TAP2"
ip link set tap2 master br0
except $? "[Bridge interface tap2]"

ip link set dev br0 up

# Add the address
echo ">> Adding address $2 to br0"
ip addr add "$2" dev br0
except $?
echo ">> Adding route $3 to br0"
# Add the the route via
ip route add default via "$3" dev br0
except $?
echo ">> Getting up the taps"
#Set up all the taps and interfaces
ip link set tap1 up
except $?
ip link set tap2 up
except $?
# Set the routing with
 # ip address delete $PREFIX dev eth0
 # ip address add $PREFIX dev br0
 # ip route add default via $ROUTE dev br0
# Try not to delete the previous addresses and attenpt to create a new network
echo "Everything went well enjoy"
exit 0