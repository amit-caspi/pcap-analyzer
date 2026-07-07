import os
import sys
import time
from scapy.all import rdpcap, IP, TCP, UDP
from elasticsearch import Elasticsearch, helpers
from prometheus_client import start_http_server, Counter, Gauge

# ==========================================
# PROMETHEUS METRICS DEFINITIONS
# ==========================================
PACKETS_COUNTER = Counter(
    "pcap_packets_total",
    "Total packets processed by protocol",
    ["protocol"]
)

BYTES_COUNTER = Counter(
    "pcap_bytes_total",
    "Total bytes processed by protocol",
    ["protocol"]
)

ELASTIC_WRITES = Counter(
    "pcap_elastic_write_total",
    "Total Elasticsearch bulk write attempts",
    ["status"]
)

PROCESSING_TIME = Gauge(
    "pcap_processing_duration_seconds",
    "Time spent processing the PCAP file"
)

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
            ELASTIC_WRITES.labels(status="success").inc()
            return
        except Exception as e:
            ELASTIC_WRITES.labels(status="fail").inc()
            # Extract the error type and a truncated message to avoid log flooding
            error_type = type(e).__name__
            error_msg = str(e)[:250] + "..." if len(str(e)) > 250 else str(e)
            
            print(f"[-] Write failure (Attempt {attempt}/{max_retries}) | {error_type}: {error_msg}")
            
            if attempt == max_retries:
                print("[-] CRITICAL: Failed to write data after all retries. Exiting.")
                sys.exit(1)
            
            print("[*] Retrying in 2 seconds...")
            time.sleep(2)

def format_timestamp(raw_timestamp):
    """
    Converts a raw epoch timestamp into an ISO 8601 format string required by Elasticsearch.
    """
    milliseconds = int(round((raw_timestamp % 1) * 1000))
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(raw_timestamp)) + f".{milliseconds:03d}Z" 

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
        start_time = time.time() # Start the stopwatch

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
            
            formatted_time = format_timestamp(raw_timestamp)
            
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
            
            # Update Prometheus metrics for this specific packet
            PACKETS_COUNTER.labels(protocol=l4_protocol).inc()
            BYTES_COUNTER.labels(protocol=l4_protocol).inc(packet_length)
            
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
        
        # Stop the stopwatch, calculate duration, and set the new metric
        end_time = time.time()
        duration = end_time - start_time
        PROCESSING_TIME.set(duration)
        print(f"[*] Total processing time: {duration:.2f} seconds.")

        # Keep the script running slightly longer so Prometheus can scrape the final metrics
        metrics_server_timeout_sec = int(os.getenv("METRICS_SERVER_TIMEOUT_SEC", "600"))
        print(f"[*] Analysis complete. Keeping metrics server alive for {metrics_server_timeout_sec} seconds...")
        time.sleep(metrics_server_timeout_sec)

    except Exception as e:
        print(f"[-] An error occurred during analysis: {e}")

if __name__ == "__main__":
    pcap_path = os.getenv("PCAP_PATH", "sample.pcap")
    
    env_max_packets = os.getenv("MAX_PACKETS", "20")
    max_packets_val = int(env_max_packets) if env_max_packets and env_max_packets != "0" else None
    
    # Expose Prometheus metrics server on the specified port
    metrics_port = int(os.getenv("METRICS_PORT", "9100"))
    print(f"[*] Starting Prometheus metrics server on port {metrics_port}")
    start_http_server(metrics_port, addr="0.0.0.0")
    
    analyze_pcap(pcap_path, max_packets=max_packets_val)

