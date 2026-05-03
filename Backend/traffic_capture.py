# =========================
# TRAFFIC CAPTURE + FEATURE EXTRACTOR (CLEAN + VISUAL)
# =========================

from scapy.all import sniff, IP, TCP, UDP
import time
import numpy as np
import requests
import threading
from collections import defaultdict

# =========================
# CONFIG
# =========================
FLASK_API     = "http://127.0.0.1:5000/predict-traffic"
FLOW_TIMEOUT  = 10
CHECK_EVERY   = 5
INTERFACE     = None

# =========================
# LIVE STATS (FOR DEMO)
# =========================
stats = {
    "BENIGN": 0,
    "ATTACK": 0,
    "TOTAL": 0
}

# =========================
# FLOW STORAGE
# =========================
flows = defaultdict(lambda: {
    "start_time": None,
    "last_time": None,
    "fwd_packets": [],
    "bwd_packets": [],
    "fwd_flags": [],
    "bwd_flags": [],
    "src_ip": None,
    "dst_ip": None,
    "src_port": None,
    "dst_port": None,
    "protocol": None,
})

flows_lock = threading.Lock()

# =========================
# FLOW KEY
# =========================
def get_flow_key(pkt):
    if IP not in pkt:
        return None

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto

    sport, dport = 0, 0
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    if src < dst:
        return (src, dst, sport, dport, proto)
    else:
        return (dst, src, dport, sport, proto)

# =========================
# PACKET HANDLER
# =========================
def packet_handler(pkt):
    if IP not in pkt:
        return

    key = get_flow_key(pkt)
    if not key:
        return

    ts = time.time()
    size = len(pkt)

    with flows_lock:
        flow = flows[key]

        if flow["start_time"] is None:
            flow["start_time"] = ts
            flow["src_ip"] = pkt[IP].src
            flow["dst_ip"] = pkt[IP].dst
            flow["protocol"] = pkt[IP].proto

            if TCP in pkt:
                flow["src_port"] = pkt[TCP].sport
                flow["dst_port"] = pkt[TCP].dport
            elif UDP in pkt:
                flow["src_port"] = pkt[UDP].sport
                flow["dst_port"] = pkt[UDP].dport

        flow["last_time"] = ts

        is_forward = (pkt[IP].src == flow["src_ip"])
        flags = int(pkt[TCP].flags) if TCP in pkt else 0

        if is_forward:
            flow["fwd_packets"].append((ts, size))
            flow["fwd_flags"].append(flags)
        else:
            flow["bwd_packets"].append((ts, size))
            flow["bwd_flags"].append(flags)

# =========================
# FEATURE EXTRACTOR
# =========================
def extract_flow_features(flow):
    fwd = flow["fwd_packets"]
    bwd = flow["bwd_packets"]
    all_pkts = fwd + bwd

    duration = max(flow["last_time"] - flow["start_time"], 1e-6)

    fwd_sizes = [s for _, s in fwd]
    bwd_sizes = [s for _, s in bwd]
    all_sizes = fwd_sizes + bwd_sizes

    def safe_mean(x): return float(np.mean(x)) if x else 0.0
    def safe_std(x): return float(np.std(x)) if x else 0.0
    def safe_max(x): return float(max(x)) if x else 0.0
    def safe_min(x): return float(min(x)) if x else 0.0

    total_packets = len(all_pkts)
    total_bytes = sum(all_sizes)

    features = {
        "Flow Duration": duration * 1e6,
        "Total Fwd Packets": len(fwd),
        "Total Backward Packets": len(bwd),
        "Flow Bytes/s": total_bytes / duration,
        "Flow Packets/s": total_packets / duration,
        "Fwd Packet Length Mean": safe_mean(fwd_sizes),
        "Bwd Packet Length Mean": safe_mean(bwd_sizes),
        "Packet Length Mean": safe_mean(all_sizes),
        "Packet Length Std": safe_std(all_sizes),
    }

    return features

# =========================
# SEND TO FLASK + VISUAL OUTPUT
# =========================
def send_to_api(flow_key, features, flow_meta):
    try:
        payload = {
            "features": features,
            "src_ip": flow_meta["src_ip"],
            "dst_ip": flow_meta["dst_ip"],
            "src_port": flow_meta["src_port"],
            "dst_port": flow_meta["dst_port"],
            "protocol": flow_meta["protocol"],
        }

        resp = requests.post(FLASK_API, json=payload, timeout=3)
        data = resp.json()

        label = data.get("prediction", "Unknown")
        prob = data.get("probability", 0)

        # update stats
        stats["TOTAL"] += 1
        if label == "BENIGN":
            stats["BENIGN"] += 1
        else:
            stats["ATTACK"] += 1

        bar = "█" * min(int(prob // 5), 20)

        print("\n" + "=" * 60)
        print(f"FLOW: {flow_meta['src_ip']}:{flow_meta['src_port']} → {flow_meta['dst_ip']}:{flow_meta['dst_port']}")
        print(f"PREDICTION: {label} | Confidence: {prob:.2f}%")
        print(f"[{bar}]")
        print(f"STATS → BENIGN: {stats['BENIGN']} | ATTACK: {stats['ATTACK']} | TOTAL: {stats['TOTAL']}")
        print("=" * 60)

    except Exception as e:
        print("[ERROR]", e)

# =========================
# FLOW CHECKER THREAD
# =========================
def flow_checker():
    while True:
        time.sleep(CHECK_EVERY)
        now = time.time()
        expired = []

        with flows_lock:
            for key, flow in flows.items():
                if flow["last_time"] and (now - flow["last_time"]) > FLOW_TIMEOUT:
                    expired.append(key)

        for key in expired:
            with flows_lock:
                flow = flows.pop(key, None)

            if flow and flow["fwd_packets"]:
                features = extract_flow_features(flow)
                send_to_api(key, features, flow)

# =========================
# LIVE ACTIVITY DISPLAY
# =========================
def show_live_activity():
    while True:
        time.sleep(3)
        print("\nLIVE TRAFFIC")
        print("-" * 40)
        print("BENIGN :", "█" * (stats["BENIGN"] % 30))
        print("ATTACK :", "█" * (stats["ATTACK"] % 30))
        print("TOTAL  :", "█" * (stats["TOTAL"] % 30))
        print("-" * 40)

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    print("=" * 50)
    print("PhishLink - LIVE TRAFFIC DEMO")
    print("=" * 50)

    threading.Thread(target=flow_checker, daemon=True).start()
    threading.Thread(target=show_live_activity, daemon=True).start()

    sniff(
        iface=INTERFACE,
        prn=packet_handler,
        store=False,
        filter="ip"
    )