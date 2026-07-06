import os
import sys
from scapy.all import rdpcap, IP, TCP, UDP

def analyze_pcap(file_path, max_packets=None):
    print(f"[*] Starting analysis of: {file_path}")
    
    # Verify file existence to prevent runtime crashes
    if not os.path.exists(file_path):
        print(f"[-] Error: File {file_path} not found!")
        sys.exit(1)
        
    try:
        # rdpcap loads the entire file and returns a list-like data structure called PacketList. 
        # Each element in this list represents one raw packet.
        packets = rdpcap(file_path)
        print(f"[+] Successfully loaded {len(packets)} packets.")

        # Determine the subset of packets to scan based on configuration
        packets_to_scan = packets[:max_packets] if max_packets else packets
        if max_packets:
            print(f"[*] Development Mode: Scanning only the first {max_packets} packets.")
        else:
            print("[*] Production Mode: Scanning the entire PCAP file.")
        
        # Iterate over the specified slice of packets for verification
        for i, packet in enumerate(packets_to_scan):
            print(f"\n--- Packet #{i+1} ---")
            
            # 1. Extract foundational fields (always present in any packet type)
            timestamp = float(packet.time)
            packet_length = len(packet)
            
            # Initialize default values for defensive coding (handles non-IP packets)
            src_ip = "N/A"
            dst_ip = "N/A"
            src_port = "N/A"
            dst_port = "N/A"
            l4_protocol = "other"  # Default classification matching assignment requirements
            
            # 2. Extract Layer 3 data if the IP layer is present
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Check for Layer 4 protocols and extract ports if applicable
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    l4_protocol = "tcp"
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    l4_protocol = "udp"
                elif packet.haslayer('ICMP'):
                    l4_protocol = "icmp"
                    # ICMP functions at Layer 3 and lacks port numbers; defaults remain "N/A"
            
            # Print the extracted fields clearly and explicitly
            print(f"Timestamp: {timestamp}")
            print(f"Packet Length: {packet_length} Bytes")
            print(f"Source IP: {src_ip} | Destination IP: {dst_ip}")
            print(f"Source Port: {src_port} | Destination Port: {dst_port}")
            print(f"Protocol: {l4_protocol}")

    except Exception as e:
        print(f"[-] An error occurred during analysis: {e}")

if __name__ == "__main__":
    # Get PCAP file path from environment or use local default
    pcap_path = os.getenv("PCAP_PATH", "sample.pcap")
    
    # Get max packets limit from environment (defaults to 20 for dev safety)
    # Setting MAX_PACKETS to "0" or leaving it empty will trigger a full production scan
    env_max_packets = os.getenv("MAX_PACKETS", "20")
    max_packets_val = int(env_max_packets) if env_max_packets and env_max_packets != "0" else None
    
    # Execute the analysis
    analyze_pcap(pcap_path, max_packets=max_packets_val)
