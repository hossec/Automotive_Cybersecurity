#!/bin/bash
set -e

echo "[*] Cleaning old lab ..."

# =========================
# Cleanup
# =========================
ip netns del ecuA 2>/dev/null || true
ip netns del ecuC 2>/dev/null || true
ip netns del ecuD 2>/dev/null || true
ip link del br-doip 2>/dev/null || true

# =========================
# Create namespaces
# =========================
ip netns add ecuA
ip netns add ecuC
ip netns add ecuD

# =========================
# Create bridge
# =========================
ip link add br-doip type bridge
ip link set br-doip up

# =========================
# Create veth pairs
# =========================
ip link add vethA type veth peer name vethA-br
ip link add vethC type veth peer name vethC-br
ip link add vethD type veth peer name vethD-br

# =========================
# Attach veth to namespaces
# =========================
ip link set vethA netns ecuA
ip link set vethC netns ecuC
ip link set vethD netns ecuD

# =========================
# Attach bridge-side veths
# =========================
ip link set vethA-br master br-doip
ip link set vethC-br master br-doip
ip link set vethD-br master br-doip

ip link set vethA-br up
ip link set vethC-br up
ip link set vethD-br up

# =========================
# Configure ECU A (Tester)
# =========================
ip netns exec ecuA ip addr add 10.0.0.20/24 dev vethA
ip netns exec ecuA ip link set vethA up
ip netns exec ecuA ip link set lo up

# =========================
# Configure ECU C (Target ECU)
# =========================
ip netns exec ecuC ip addr add 10.0.0.10/24 dev vethC
ip netns exec ecuC ip link set vethC up
ip netns exec ecuC ip link set lo up

# =========================
# Configure ECU D (Attacker)
# =========================
ip netns exec ecuD ip addr add 10.0.0.30/24 dev vethD
ip netns exec ecuD ip link set vethD up
ip netns exec ecuD ip link set lo up

# =========================
# Done
# =========================
echo "[+] DoIP bridge lab ready"
echo "[+] Nodes:"
echo "    ecuA (Tester)   -> 10.0.0.20"
echo "    ecuC (ECU)      -> 10.0.0.10"
echo "    ecuD (Attacker) -> 10.0.0.30"
