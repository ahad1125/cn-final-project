## capture packets related to a specific URL and save them to a pcap file

from scapy.all import sniff, wrpcap
import threading 
import requests 
import time 
import socket 
import urllib.parse
import urllib3 


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 


def get_ip(url): # 
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname if parsed.hostname else url.replace("https://", "").replace("http://", "").split("/")[0]
        
        addr_info = socket.getaddrinfo(hostname, None)
        return list(set([info[4][0] for info in addr_info]))
    except:
        return []


def generate_traffic(url, sniffer_ready):
    try:
        sniffer_ready.wait() 
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        
        
        requests.get(url, timeout=5, headers=headers, verify=False)
        
        
        def fetch_asset(path):
            try:
                requests.get(url.rstrip("/") + path, timeout=4, headers=headers, verify=False)
            except:
                pass

        assets = ["/favicon.ico", "/robots.txt", "/?req=css", "/?req=js", "/?req=img1", "/?req=img2"]
        threads = []
        
        for asset in assets:
            t = threading.Thread(target=fetch_asset, args=(asset,))
            t.start()
            threads.append(t)
            time.sleep(0.3)  # Spread out requests to simulate realistic rendering timeline
            
    except:
        pass
    
    
    
def packet_filter(pkt, target_ips):
    if pkt.haslayer("ARP"): return True
    if pkt.haslayer("UDP") and pkt.haslayer("DNS"): return True
    if pkt.haslayer("IP"):
        return pkt["IP"].dst in target_ips or pkt["IP"].src in target_ips
    if pkt.haslayer("IPv6"):
        return pkt["IPv6"].dst in target_ips or pkt["IPv6"].src in target_ips
    return False


def capture_packets(url, duration=10):
    target_ips = get_ip(url)

    if not target_ips:
        raise Exception("Could not resolve IP")

    sniffer_ready = threading.Event()
    thread = threading.Thread(target=generate_traffic, args=(url, sniffer_ready)) 
    thread.start()

    packets = sniff(lfilter=lambda pkt: packet_filter(pkt, target_ips), timeout=duration, started_callback=sniffer_ready.set)

    filename = f"temp/capture_{int(round(time.time(),5))}.pcap"
    
    wrpcap(filename, packets) # save captured packets to a pcap file

    return filename, target_ips # return the pcap file path and the target IPs for further processing