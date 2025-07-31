#!/bin/bash
set -euo pipefail -x

# specify a hardware device, or default to ext0
DEV=${DEV:=ext0}

# re-create netns
ip netns del ns1 || true
ip netns add ns1

# setup veth devices
ip link add veth1-root type veth peer veth1-ns1 netns ns1

ip addr add 10.0.1.1/24 dev veth1-root
ip netns exec ns1 ip addr add 10.0.1.2/24 dev veth1-ns1

# set links up
ip link set veth1-root up
ip netns exec ns1 ip link set veth1-ns1 up

# enable GRO on veth peers
ethtool -K veth1-root gro on
ip netns exec ns1 ethtool -K veth1-ns1 gro on

# poke a hole in iptables (optional)
sudo iptables -A INPUT -i veth1-root -j ACCEPT

# attach redirect program
target_mac=$(sudo ip netns exec ns1 ip -json l show dev veth1-ns1  | jq .[].address | tr -d \")
./xdp_loader $DEV veth1-root $target_mac
