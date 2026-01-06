#!/bin/bash
set -e

echo "[*] Cleaning old lab ..."

# =========================
# Cleanup
# =========================
for ns in ecuA ecuB ecuC ecuD; do
    ip netns del $ns 2>/dev/null || true
done
ip link del br-doip 2>/dev/null || true

# =========================
# Create namespaces
# =========================
ip netns add ecuA   # Tester (IPv6 only)
ip netns add ecuB   # IPv4 only
ip netns add ecuC   # ECU (IPv4 + IPv6)
ip netns add ecuD   # Attacker (IPv4 + IPv6)

# =========================
# Create bridge
# =========================
ip link add br-doip type bridge
ip link set br-doip up

# =========================
# Create veth pairs
# =========================
ip link add vethA type veth peer name vethA-br
ip link add vethB type veth peer name vethB-br
ip link add vethC type veth peer name vethC-br
ip link add vethD type veth peer name vethD-br

# =========================
# Attach veth to namespaces
# =========================
ip link set vethA netns ecuA
ip link set vethB netns ecuB
ip link set vethC netns ecuC
ip link set vethD netns ecuD

# =========================
# Attach bridge-side veths
# =========================
for i in A B C D; do
    ip link set veth${i}-br master br-doip
    ip link set veth${i}-br up
done

# =========================
# ECU A – Tester (IPv6 ONLY)
# =========================
ip netns exec ecuA ip -6 addr add fd00::20/64 dev vethA
ip netns exec ecuA ip link set vethA up
ip netns exec ecuA ip link set lo up

# =========================
# ECU B – IPv4 ONLY
# =========================
ip netns exec ecuB ip addr add 10.0.0.20/24 dev vethB
ip netns exec ecuB ip link set vethB up
ip netns exec ecuB ip link set lo up

# =========================
# ECU C – Target ECU (IPv4 + IPv6)
# =========================
ip netns exec ecuC ip addr add 10.0.0.10/24 dev vethC
ip netns exec ecuC ip -6 addr add fd00::10/64 dev vethC
ip netns exec ecuC ip link set vethC up
ip netns exec ecuC ip link set lo up

# =========================
# ECU D – Attacker (IPv4 + IPv6)
# =========================
ip netns exec ecuD ip addr add 10.0.0.30/24 dev vethD
ip netns exec ecuD ip -6 addr add fd00::30/64 dev vethD
ip netns exec ecuD ip link set vethD up
ip netns exec ecuD ip link set lo up

# =========================
# Done
# =========================
echo "[+] DoIP bridge lab ready"
echo "[+] Nodes:"
echo "    ecuA (Tester)   -> IPv6 only  fd00::20"
echo "    ecuB (Button)   -> IPv4 only  10.0.0.20"
echo "    ecuC (Main)      -> IPv4 10.0.0.10 | IPv6 fd00::10"
echo "    ecuD (Attacker) -> IPv4 10.0.0.30 | IPv6 fd00::30"
