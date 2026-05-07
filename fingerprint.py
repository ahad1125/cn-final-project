from datetime import datetime
from classify import classify


def normalize_protocols(protocols):
    total = sum(protocols.values())
    if total == 0:
        return protocols

    result = {}

    for k, v in protocols.items():
        percentage = (v / total) * 100
        result[k] = round(percentage, 2)
    
    return result
    

def generate_fingerprint(features, url):
    if not features:
        return {"error": "No packets captured"}

    protocols = normalize_protocols(features.get("protocol_distribution", {}))

    top_protocol=[]

    if protocols:
        top_protocol.append(max(protocols, key=protocols.get))
    else:
        top_protocol.append("Unknown")

    fp = {
        "site_url": url,
        "capture_timestamp": str(datetime.now()),
        "total_packets": features.get("total_packets", 0),
        "total_bytes": features.get("total_bytes", 0),
        "top_protocol": top_protocol,
        "unique_ips": len(features.get("unique_ips", [])),
        "dns_queries": features.get("dns_queries", []),
        "mean_packet_size": round(features.get("mean_packet_size", 0.0), 2),
        "max_packet_size": features.get("max_packet_size", 0),
        "protocol_distribution": protocols,
        "size_histogram": features.get("size_histogram", [0, 0, 0, 0, 0]),
        "bytes_per_sec": features.get("bytes_per_sec", [])
    }

    label, confidence = classify(fp)
    fp["behavior_label"] = {"label": label, "confidence": confidence}

    return fp