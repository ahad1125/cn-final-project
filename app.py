from flask import Flask, request, jsonify, render_template
import os
from capture import capture_packets
from extract import extract_features
from fingerprint import generate_fingerprint

app = Flask(__name__)

os.makedirs("temp", exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.json
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL required"}), 400

    try:
        pcap_file, ip = capture_packets(url, duration=10)
        features = extract_features(pcap_file)
        fingerprint = generate_fingerprint(features, url)
        if "error" in fingerprint:
            return jsonify(fingerprint), 400
        return jsonify(fingerprint)
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/api/compare', methods=['POST'])
def compare():
    data = request.get_json()
    url1 = data.get('url1')
    url2 = data.get('url2')

    if not url1 or not url2:
        return jsonify({"error": "Both urls are required"}), 400

    try:
        pcap1, _ = capture_packets(url1, duration=10)
        features1 = extract_features(pcap1)
        fp1 = generate_fingerprint(features1, url1)

        pcap2, _ = capture_packets(url2, duration=10)
        features2 = extract_features(pcap2)
        fp2 = generate_fingerprint(features2, url2)

        if "error" in fp1:
            return jsonify({"error": f"Error on {url1}: {fp1['error']}"}), 400
        if "error" in fp2:
            return jsonify({"error": f"Error on {url2}: {fp2['error']}"}), 400

        diff = {
            "total_bytes": "url1" if fp1.get("total_bytes", 0) > fp2.get("total_bytes", 0) else "url2",
            "unique_ips": "url1" if fp1.get("unique_ips", 0) > fp2.get("unique_ips", 0) else "url2",
            "mean_packet_size": "url1" if fp1.get("mean_packet_size", 0) > fp2.get("mean_packet_size", 0) else "url2"
        }

        return jsonify({
            "fingerprint1": fp1,
            "fingerprint2": fp2,
            "diff": diff
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, threaded=True)