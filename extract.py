from scapy.all import rdpcap, DNSQR # to read pcap files and extract DNS query information
from collections import Counter     # to count occurrences of different protocols
import numpy as np


def extract_features(pcap_file):
    packets={}
    packets = rdpcap(pcap_file)

    if not packets:
        return {}

    sizes = [] # to store packet sizes
    times = [] # to store packet timestamps
    
    start_time = float(packets[0].time) if packets else 0
    bytes_per_sec = []
    size_histogram = [0, 0, 0, 0, 0]

    for p in packets:
        sz = len(p)
        sizes.append(sz) # append packet size to sizes list
        tm = float(p.time)
        times.append(tm) # append packet timestamp to times list

        if sz <= 100: size_histogram[0] += 1
        elif sz <= 500: size_histogram[1] += 1
        elif sz <= 1000: size_histogram[2] += 1
        elif sz <= 1500: size_histogram[3] += 1
        else: size_histogram[4] += 1

        sec_idx = int(tm - start_time)
        while len(bytes_per_sec) <= sec_idx:
            bytes_per_sec.append(0)
        bytes_per_sec[sec_idx] += sz


    inter_arrival = []  # to store inter-arrival times between packets
    
    
    if len(times) > 1: # to check if there are at least two packets for inter-arrival time calculation
        inter_arrival=np.diff(times)  # to calculate inter-arrival times between packets
    else:
        inter_arrival = np.array([0])  # Default to 0 if only one packet or no packets

    
    protocols = [] # to store detected protocols
    ips = set() # to store unique IP addresses
    dns_queries = set() # to store unique DNS queries

    for pkt in packets:
        # IP extraction
        if pkt.haslayer("IP"):
            ips.add(pkt["IP"].dst) # to collect unique destination IP addresses
        elif pkt.haslayer("IPv6"):
            ips.add(pkt["IPv6"].dst)

        # Protocol detection
        if pkt.haslayer("TCP"):
            tcp = pkt["TCP"]
            port = {tcp.sport, tcp.dport}

            # If the packet has a payload (data), label it by its web protocol
            if len(tcp.payload) > 0:
                if 443 in port:  # to check if port 443 is in the packet
                    protocols.append("HTTPS") 
                elif 80 in port:
                    protocols.append("HTTP")
                else:
                    protocols.append("TCP")
            else:
                # If it's an empty control packet (like a TCP ACK or SYN), label it as pure TCP
                protocols.append("TCP") 

        elif pkt.haslayer("UDP"):
            if pkt.haslayer("DNS"):
                protocols.append("DNS")

                if pkt.haslayer(DNSQR):
                    try:
                        qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
                        dns_queries.add(qname)
                    except:
                        pass
            else:
                udp = pkt["UDP"]
                if 443 in {udp.sport, udp.dport}:
                    protocols.append("QUIC/HTTP3")
                else:
                    protocols.append("UDP")

        elif pkt.haslayer("ICMP"):
            protocols.append("ICMP")

        elif pkt.haslayer("ARP"):
            protocols.append("ARP")

    protocol_count = Counter(protocols)    # to count occurrences of each protocol type

    if isinstance(inter_arrival, np.ndarray):
        iat_list = inter_arrival.tolist()   
    else:
        iat_list = list(inter_arrival)

    return {
        "total_packets": len(packets),
        "total_bytes": sum(sizes),
        "packet_sizes": sizes,
        "mean_packet_size": float(np.mean(sizes)) if sizes else 0,
        "max_packet_size": max(sizes) if sizes else 0,
        "min_packet_size": min(sizes) if sizes else 0,
        "unique_ips": list(ips),
        "dns_queries": list(dns_queries),
        "protocol_distribution": dict(protocol_count),
        "inter_arrival_times": iat_list,
        "size_histogram": size_histogram,
        "bytes_per_sec": bytes_per_sec,
    }