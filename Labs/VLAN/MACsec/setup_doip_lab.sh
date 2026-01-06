#!/bin/bash
set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "[!] ERROR: This script must be run as root"
    echo "[!] Please run: sudo $0"
    exit 1
fi

# Ensure netns directory exists and is shared
mkdir -p /var/run/netns
mount --make-shared /var/run/netns 2>/dev/null || true

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
echo "[+] Creating network namespaces..."
ip netns add ecuA
ip netns add ecuC
ip netns add ecuD

# =========================
# Create bridge
# =========================
echo "[+] Creating bridge..."
ip link add br-doip type bridge
ip link set br-doip up

# =========================
# Create veth pairs
# =========================
echo "[+] Creating veth pairs..."
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
# MACsec Configuration
# =========================
echo "[+] Configuring MACsec..."

# Pre-shared key (PSK) for MACsec
# In production, use proper key management (EAP-TLS, 802.1X)
MACSEC_KEY="0123456789abcdef0123456789abcdef"

# =========================
# Bring up base interfaces FIRST
# =========================
ip netns exec ecuA ip link set lo up
ip netns exec ecuA ip link set vethA up

ip netns exec ecuC ip link set lo up
ip netns exec ecuC ip link set vethC up

# Get actual MAC addresses of the veth interfaces
MAC_A=$(ip netns exec ecuA ip link show vethA | grep link/ether | awk '{print $2}')
MAC_C=$(ip netns exec ecuC ip link show vethC | grep link/ether | awk '{print $2}')

echo "[+] Detected MAC addresses:"
echo "    ECU A (vethA): $MAC_A"
echo "    ECU C (vethC): $MAC_C"

# =========================
# Configure ECU A (Tester) with MACsec
# =========================
echo "[+] Configuring ECU A (Tester) with MACsec..."

# Create MACsec interface
ip netns exec ecuA ip link add link vethA macsec0 type macsec encrypt on

# Configure transmit secure channel (TX)
ip netns exec ecuA ip macsec add macsec0 tx sa 0 pn 1 on key 01 $MACSEC_KEY

# Configure receive secure channel (RX) - expects traffic from ECU C
# Use the ACTUAL MAC address of ECU C's vethC interface
ip netns exec ecuA ip macsec add macsec0 rx port 1 address $MAC_C
ip netns exec ecuA ip macsec add macsec0 rx port 1 address $MAC_C sa 0 pn 1 on key 01 $MACSEC_KEY

# Bring up MACsec interface
ip netns exec ecuA ip link set macsec0 up

# Assign IP to MACsec interface
ip netns exec ecuA ip addr add 10.0.0.20/24 dev macsec0

echo "[✓] ECU A configured with MACsec"

# =========================
# Configure ECU C (Target ECU) with MACsec
# =========================
echo "[+] Configuring ECU C (Target ECU) with MACsec..."

# Create MACsec interface
ip netns exec ecuC ip link add link vethC macsec0 type macsec encrypt on

# Configure transmit secure channel (TX)
ip netns exec ecuC ip macsec add macsec0 tx sa 0 pn 1 on key 01 $MACSEC_KEY

# Configure receive secure channel (RX) - expects traffic from ECU A
# Use the ACTUAL MAC address of ECU A's vethA interface
ip netns exec ecuC ip macsec add macsec0 rx port 1 address $MAC_A
ip netns exec ecuC ip macsec add macsec0 rx port 1 address $MAC_A sa 0 pn 1 on key 01 $MACSEC_KEY

# Bring up MACsec interface
ip netns exec ecuC ip link set macsec0 up

# Assign IP to MACsec interface
ip netns exec ecuC ip addr add 10.0.0.10/24 dev macsec0

echo "[✓] ECU C configured with MACsec"

# =========================
# Configure ECU D (Attacker) - NO MACsec
# =========================
echo "[+] Configuring ECU D (Attacker) - NO MACsec..."
ip netns exec ecuD ip addr add 10.0.0.30/24 dev vethD
ip netns exec ecuD ip link set vethD up
ip netns exec ecuD ip link set lo up

echo "[!] ECU D has NO MACsec - cannot decrypt traffic"

# =========================
# Test connectivity
# =========================
echo ""
echo "[+] Testing MACsec connectivity..."
sleep 1

if ip netns exec ecuA ping -c 2 -W 2 10.0.0.10 > /dev/null 2>&1; then
    echo "[✓] SUCCESS: ECU A can ping ECU C (MACsec working!)"
else
    echo "[!] WARNING: Cannot ping - checking configuration..."
    echo ""
    echo "ECU A interface status:"
    ip netns exec ecuA ip addr show macsec0
    echo ""
    echo "ECU C interface status:"
    ip netns exec ecuC ip addr show macsec0
fi

# =========================
# Done
# =========================
echo ""
echo "=========================================="
echo "[+] DoIP bridge lab with MACsec ready"
echo "=========================================="
echo ""
echo "Nodes:"
echo "  ecuA (Tester)   -> 10.0.0.20 [MACsec ENABLED]"
echo "  ecuC (ECU)      -> 10.0.0.10 [MACsec ENABLED]"
echo "  ecuD (Attacker) -> 10.0.0.30 [NO MACsec - LOCKED OUT]"
echo ""
echo "Security Features:"
echo "  ✓ Layer 2 encryption (AES-GCM-128)"
echo "  ✓ Frame authentication"
echo "  ✓ Replay protection"
echo "  ✓ Pre-shared key: $MACSEC_KEY"
echo ""
echo "MAC Addresses (configured automatically):"
echo "  ecuA: $MAC_A"
echo "  ecuC: $MAC_C"
echo ""
echo "Test Commands:"
echo "  # Manual ping test:"
echo "  sudo ip netns exec ecuA ping 10.0.0.10"
echo ""
echo "  # View MACsec stats:"
echo "  sudo ip netns exec ecuA ip -s macsec show"
echo "  sudo ip netns exec ecuC ip -s macsec show"
echo ""
echo "  # Start ECU server:"
echo "  sudo ip netns exec ecuC python3 ecu_c_doip_server.py"
echo ""
echo "  # Start client (direct connection, no UDP discovery):"
echo "  sudo ip netns exec ecuA python3 ecu_a_doip_client_direct.py"
echo "=========================================="