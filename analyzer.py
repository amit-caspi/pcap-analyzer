import os
import sys
import time
from scapy.all import rdpcap, IP, TCP, UDP
from elasticsearch import Elasticsearch, helpers

# def connect_elasticsearch():
#     """Establishes connection to the Elasticsearch cluster."""
#     es_url = os.getenv("ES_URL", "http://localhost:9200")
#     es = Elasticsearch(es_url)
    
#     # Ping the cluster to verify it's up and reachable
#     if not es.ping():
#         print(f"[-] Could not connect to Elasticsearch at {es_url}")
#         sys.exit(1)
        
#     print(f"[+] Successfully connected to Elasticsearch at {es_url}")
#     return es

def connect_elasticsearch():
    # .strip() removes any hidden spaces or newlines from the environment variable
    es_url = os.getenv("ES_URL", "http://elasticsearch:9200").strip()
    print(f"[*] Attempting connection to: '{es_url}'")
    es = Elasticsearch(es_url)
    
    try:
        # info() is highly verbal and will throw the exact network exception if it fails
        info = es.info()
        print(f"[+] Successfully connected! Cluster: {info.get('cluster_name')}")
        return es
    except Exception as e:
        print(f"[-] CRITICAL FAILURE: Could not connect to {es_url}")
        print(f"[-] Exact Python Error: {type(e).__name__} - {str(e)}")
        sys.exit(1)

def analyze_pcap(file_path, max_packets=None):
    print(f"[*] Starting analysis of: {file_path}")
    
    # Verify file existence to prevent runtime crashes
    if not os.path.exists(file_path):
        print(f"[-] Error: File {file_path} not found!")
        sys.exit(1)
        
    # Connect to Elasticsearch before starting the analysis
    es = connect_elasticsearch()
    index_name = "pcap-packets"
        
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
        
        # Buffer to store documents for Bulk ingestion
        bulk_actions = []
        
        # Iterate over the selected packets
        for i, packet in enumerate(packets_to_scan):
            
            # 1. Extract foundational fields (always present in any packet type)
            raw_timestamp = float(packet.time)
            packet_length = len(packet)
            
            # Convert raw epoch timestamp to ISO 8601 format for accurate Elasticsearch indexing
            formatted_time = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(raw_timestamp)) + f".{int((raw_timestamp % 1) * 1000):03d}Z"
            
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
                    src_port = str(packet[TCP].sport)
                    dst_port = str(packet[TCP].dport)
                    l4_protocol = "tcp"
                elif UDP in packet:
                    src_port = str(packet[UDP].sport)
                    dst_port = str(packet[UDP].dport)
                    l4_protocol = "udp"
                elif packet.haslayer('ICMP'):
                    l4_protocol = "icmp"
                    # ICMP functions at Layer 3 and lacks port numbers; defaults remain "N/A"
            
            # Create the Elasticsearch document layout
            doc = {
                "_index": index_name,
                "_source": {
                    "timestamp": formatted_time,
                    "packet_length": packet_length,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "l4_protocol": l4_protocol
                }
            }
            bulk_actions.append(doc)
            
            # Flush the buffer and send to Elasticsearch in batches of 1,000 for efficiency
            if len(bulk_actions) >= 1000:
                helpers.bulk(es, bulk_actions)
                bulk_actions = []
                print(f"[+] Indexed up to packet #{i+1}...")
                
        # Ingest any remaining packets left in the buffer
        if bulk_actions:
            helpers.bulk(es, bulk_actions)
            
        print(f"[+] Successfully finished indexing packets into '{index_name}'.")

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

