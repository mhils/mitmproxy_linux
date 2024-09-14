#!/bin/sh

set -x

# Delete the tap10 interface
sudo ip link set tap10 down
sudo ip tuntap del dev tap10 mode tap

# Remove the iptables rules for NAT and forwarding
sudo iptables -t nat -D POSTROUTING -s 192.0.2.2 -j MASQUERADE
sudo iptables -D FORWARD -i tap10 -s 192.0.2.2 -j ACCEPT
sudo iptables -D FORWARD -o tap10 -d 192.0.2.2 -j ACCEPT

# Save the iptables rules to make them persistent across reboots
sudo sh -c "iptables-save > /etc/iptables/rules.v4"

echo "Cleanup completed."
