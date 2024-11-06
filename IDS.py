from collections import defaultdict
from scapy.all import rdpcap
import time

# Function to check for potential DDoS attacks
def DdosChecker(packets, traffic_threshold=100, syn_flood_threshold=50, time_window=60):
    traffic_counter = defaultdict(int)  # To track number of packets per IP
    syn_counter = defaultdict(int)  # To track SYN packets from each IP
    
    # Track the start time of packet analysis
    start_time = time.time()
    
    # Loop through each packet and analyze
    for packet in packets:
        # Check if the packet has IP layer
        if packet.haslayer('IP'):
            # Extract source IP and timestamp
            src_ip = packet['IP'].src
            timestamp = packet.time
            
            # If the time window is exceeded, reset the counters and start a new window
            if timestamp - start_time > time_window:
                start_time = time.time()  # Reset time window
                traffic_counter.clear()  # Clear packet counters
                syn_counter.clear()  # Clear SYN counters
            
            # Count packets from each IP
            traffic_counter[src_ip] += 1
            
            # Detect SYN packets (for SYN flood detection)
            if packet.haslayer('TCP') and packet['TCP'].flags == 'S':  # SYN flag check
                syn_counter[src_ip] += 1

    # Check for potential DDoS (high traffic and SYN floods)
    detected_attacks = []

    # Check for high volume of packets from various IPs
    for ip, count in traffic_counter.items():
        if count > traffic_threshold:  # Adjust threshold based on expected traffic volume
            detected_attacks.append(f"High Traffic from IP: {ip}, {count} packets in a short time.")

    # Check for potential SYN flood attack (many SYN packets from different IPs)
    for ip, count in syn_counter.items():
        if count > syn_flood_threshold:  # Adjust threshold based on traffic volume
            detected_attacks.append(f"Potential SYN Flood from IP: {ip}, {count} SYN packets.")
    
    return detected_attacks

# Function to read and process pcap file, then check for DDoS attacks
def analyze_pcap(path):
    # Read the pcap file
    packets = rdpcap(path)
    
    # Check for DDoS attacks
    attacks = DdosChecker(packets)
    
    return attacks

# Main function
def main():
    # User input for the pcap file path
    path = input("Enter the path to the .pcap file: ")
    
    # Analyze the pcap file for potential DDoS attacks
    attacks = analyze_pcap(path)
    
    # Display the result
    if attacks:
        for attack in attacks:
            print(attack)
    else:
        print("No DDoS attacks detected.")

# Calling the main function to run the program
if __name__ == "__main__":
    main()
