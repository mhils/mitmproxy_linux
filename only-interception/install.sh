#!/bin/sh

set -x

sudo sysctl -w net.ipv4.ip_forward=1

# Create and configure the tap10 interface
sudo ip tuntap add dev tap10 mode tap user $USER
sudo ip link set tap10 up
sudo ip addr add 192.168.1.100 peer 192.168.1.101 dev tap10

# Verify the tap10 interface status
echo "Checking tap10 interface status:"
ip addr show tap10

sudo ip route add 192.168.1.0/24 dev tap10
sudo ip route add default via 192.168.1.101 dev tap10

# Verify the routing table
echo "Checking routing table:"
ip route

# Detect the primary network interface
PRIMARY_IFACE=$(ip route | grep default | grep -v linkdown | awk '{print $5}')
echo PRIMARY_IFACE=$PRIMARY_IFACE

# Apply iptables rules for NAT and forwarding
sudo iptables -t nat -A POSTROUTING -o $PRIMARY_IFACE -j MASQUERADE
sudo iptables -A FORWARD -i tap10 -o $PRIMARY_IFACE -j ACCEPT
sudo iptables -A FORWARD -i $PRIMARY_IFACE -o tap10 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Verify iptables rules
echo "Checking iptables rules:"
sudo iptables -t nat -L -v -n
sudo iptables -L -v -n

# Save the iptables rules to make them persistent across reboots
# sudo sh -c "iptables-save > /etc/iptables/rules.v4"

echo "Setup completed."
