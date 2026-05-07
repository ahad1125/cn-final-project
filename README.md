# Network Fingerprint Analyzer

A Flask web app that **captures network traffic** for one (or two) target URLs, extracts traffic features from a generated **PCAP**, builds a **fingerprint**, and classifies the observed behavior (e.g., Streaming / Social Media / API-Heavy / etc.). The UI also visualizes results with charts.

> Note: This project actively generates traffic to the target URL(s) and uses packet sniffing. Running it typically requires **appropriate permissions** on your machine.

---

## Features

- Web interface (Flask + HTML) to submit target URL(s)
- Traffic capture for ~10 seconds per URL using **Scapy**
- Feature extraction from the captured PCAP
- Fingerprint creation (protocol distribution, packet/byte statistics, etc.)
- Heuristic classification into one of several behavior labels
- Optional comparison mode for two URLs (fingerprints + a basic diff summary)

---

## How it Works (High Level)

1. **Capture** (`capture.py`)
   - Resolves the target URL to IP addresses.
   - Starts a background thread that generates browsing-like traffic by requesting the target page and some common assets.
   - Sniffs packets matching the target IPs and saves them to a timestamped `temp/*.pcap` file.

2. **Extract Features** (`extract.py`)
   - Reads the PCAP with `scapy.rdpcap`.
   - Computes:
     - total packets / total bytes
     - mean / min / max packet size
     - protocol distribution (HTTP/HTTPS/DNS/UDP/ICMP/etc.)
     - DNS queries (from DNSQR)
     - packet size histogram buckets
     - bytes-per-second timeline
     - inter-arrival times

3. **Generate Fingerprint** (`fingerprint.py`)
   - Normalizes protocol distribution into percentages.
   - Produces a fingerprint JSON object including:
     - `site_url`, `capture_timestamp`
     - stats + protocol distribution + histogram + timeline
   - Adds `behavior_label` using `classify.py`.

4. **Classify Behavior** (`classify.py`)
   - Uses traffic heuristics (bytes, mean packet size, number of unique IPs, packet counts, HTTPS/DNS ratios)
   - Also boosts confidence using URL keywords (e.g., youtube/netflix ⇒ Streaming).
   - Returns `(label, confidence)`.

5. **API + UI**
   - Backend endpoints return JSON fingerprints.
   - Frontend renders stats and charts using **Chart.js**.

---

## Project Structure

- `app.py` — Flask app + API routes
- `capture.py` — traffic generation + packet sniffing + PCAP saving
- `extract.py` — PCAP parsing + feature extraction
- `fingerprint.py` — fingerprint building + behavior label assignment
- `classify.py` — heuristic classifier
- `templates/index.html` — main UI page
- `static/` — CSS + JS for charts and rendering

---

## API Endpoints

### `GET /`

Renders the homepage.

### `POST /api/analyze`

Capture and analyze a single URL.

**Request JSON**:

```json
{ "url": "https://example.com" }
```

**Response JSON** (example fields):

- `site_url`
- `total_packets`, `total_bytes`
- `unique_ips`
- `top_protocol`
- `protocol_distribution` (percentages)
- `size_histogram`
- `bytes_per_sec`
- `behavior_label`: `{ "label": "Streaming", "confidence": 0.87 }`

### `POST /api/compare`

Capture and analyze two URLs, then return both fingerprints and a diff summary.

**Request JSON**:

```json
{ "url1": "https://site1.com", "url2": "https://site2.com" }
```

**Response JSON**:

- `fingerprint1`, `fingerprint2`
- `diff` (simple comparison of `total_bytes`, `unique_ips`, `mean_packet_size`)

---

## Running the Project

1. Install dependencies (you will need at least the packages used by the code, e.g. Flask, Scapy, NumPy, Requests).
2. Start the server:
   ```bash
   python app.py
   ```
3. Open the browser to:
   - `http://127.0.0.1:5000/`
4. Enter a target URL (and optionally enable compare mode).

---

## Notes / Limitations

- The capture window is controlled by `duration=10` in `app.py`.
- Capturing/sniffing may fail if:
  - the program lacks privileges (common with raw packet sniffing)
  - the host blocks or doesn’t respond to automated requests
  - networking conditions don’t produce meaningful traffic in the capture window
- The classification is **heuristic** (rules-based), not a trained ML model.

---

## Security Disclaimer

This tool generates outbound requests to the target URL(s) and performs packet sniffing. Only run it in authorized environments.
