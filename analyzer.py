import os
import sys
import time
from scapy.all import rdpcap, IP, TCP, UDP
from elasticsearch import Elasticsearch, helpers

def connect_elasticsearch():
    """
    Establishes and verifies a connection to the Elasticsearch cluster.
    Reads configuration from environment variables and returns the client and index name.
    """
    elastic_url = os.getenv("ELASTIC_URL", "http://elasticsearch:9200").strip()
    elastic_index = os.getenv("ELASTIC_INDEX", "pcap-packets").strip()
    
    print(f"[*] Attempting connection to: '{elastic_url}'")
    es = Elasticsearch(elastic_url)
    
    try:
        info = es.info()
        print(f"[+] Successfully connected! Cluster: {info.get('cluster_name')}")
        return es, elastic_index
    except Exception as e:
        print(f"[-] CRITICAL FAILURE: Could not connect to {elastic_url}")
        print(f"[-] Exact Python Error: {type(e).__name__} - {str(e)}")
        sys.exit(1)

def send_bulk_with_retry(es_client, actions):
    """
    Attempts to send data to Elasticsearch in bulk.
    Retries upon failure based on the configured environment variable.
    """
    max_retries = int(os.getenv("ELASTIC_MAX_RETRIES", "3"))
    
    for attempt in range(1, max_retries + 1):
        try:
            helpers.bulk(es_client, actions)
            return
        except Exception as e:
            # Extract the error type and a truncated message to avoid log flooding
            error_type = type(e).__name__
            error_msg = str(e)[:250] + "..." if len(str(e)) > 250 else str(e)
            
            print(f"[-] Write failure (Attempt {attempt}/{max_retries}) | {error_type}: {error_msg}")
            
            if attempt == max_retries:
                print("[-] CRITICAL: Failed to write data after all retries. Exiting.")
                sys.exit(1)
            
            print("[*] Retrying in 2 seconds...")
            time.sleep(2)

def analyze_pcap(file_path, max_packets=None):
    """
    Parses a PCAP file and ingests its packets into Elasticsearch.
    Handles data extraction, formatting, and batching.
    """
    print(f"[*] Starting analysis of: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"[-] Error: File {file_path} not found!")
        sys.exit(1)
        
    # Get both the client and the configured index name safely
    es, index_name = connect_elasticsearch()
        
    try:
        # rdpcap loads the entire file and returns a list-like data structure called PacketList. 
        # Each element in this list represents one raw packet.
        packets = rdpcap(file_path)
        print(f"[+] Successfully loaded {len(packets)} packets.")

        packets_to_scan = packets[:max_packets] if max_packets else packets
        if max_packets:
            print(f"[*] Scanning only the first {max_packets} packets.")
        else:
            print("[*] Scanning the entire PCAP file.")
        
        bulk_actions = []
        
        for i, packet in enumerate(packets_to_scan):
            raw_timestamp = float(packet.time)
            packet_length = len(packet)
            
            # Convert epoch timestamp to ISO 8601 format for Elasticsearch. 
            formatted_time = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(raw_timestamp)) + f".{int((raw_timestamp % 1) * 1000):03d}Z"
            
            src_ip = "N/A"
            dst_ip = "N/A"
            src_port = "N/A"
            dst_port = "N/A"
            l4_protocol = "other"
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
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
            
            doc = {
                "_index": index_name,
                # Use a deterministic ID based on the file name and packet index to ensure idempotency.
                # This prevents data duplication if the ingestion script is run multiple times on the same dataset.
                "_id": f"{file_path}_{i}", 
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
            
            if len(bulk_actions) >= 1000:
                send_bulk_with_retry(es, bulk_actions)
                bulk_actions = []
                print(f"[+] Indexed up to packet #{i+1}...")

        # Flush any remaining packets in the buffer.        
        if bulk_actions:
            send_bulk_with_retry(es, bulk_actions)
            
        print(f"[+] Successfully finished indexing packets into '{index_name}'.")

    except Exception as e:
        print(f"[-] An error occurred during analysis: {e}")

if __name__ == "__main__":
    pcap_path = os.getenv("PCAP_PATH", "sample.pcap")
    
    env_max_packets = os.getenv("MAX_PACKETS", "20")
    max_packets_val = int(env_max_packets) if env_max_packets and env_max_packets != "0" else None
    
    analyze_pcap(pcap_path, max_packets=max_packets_val)

