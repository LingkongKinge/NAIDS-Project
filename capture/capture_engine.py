import sys
import os
import time
import json
import datetime
import numpy as np
import pandas as pd
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP

# Add project root to path so we can import core modules
sys.path.insert(0, '/home/lingkong/NAIDS_Project')

from core.models import analyse_flow
from core.firewall_manager import auto_block_if_critical, is_ip_blocked

# ─── Configuration ────────────────────────────────────────────
ALERTS_FILE   = '/home/lingkong/NAIDS_Project/api/alerts.json'
INTERFACE     = 'wlo1'

# ─── Flow Storage ────────────────────────────────────────────
flows     = defaultdict(list)
alert_log = []

print("=== NAIDS v2.0 — Dual Engine Capture ===")
print("✅ Random Forest + Isolation Forest loaded")
print(f"✅ Monitoring interface: {INTERFACE}")

# ─── Save Alert to File ───────────────────────────────────────
def save_alert(alert):
    """Save detected threat to alerts.json"""
    try:
        with open(ALERTS_FILE, 'r') as f:
            alerts = json.load(f)
        alerts.append(alert)
        if len(alerts) > 1000:
            alerts = alerts[-1000:]
        with open(ALERTS_FILE, 'w') as f:
            json.dump(alerts, f, indent=2)
    except Exception as e:
        print(f"Error saving alert: {e}")

# ─── Feature Columns ─────────────────────────────────────────
FEATURE_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Length of Fwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Bwd IAT Min', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'Average Packet Size',
    'Subflow Fwd Bytes', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Max', 'Idle Min'
]

# ─── Extract Features From Flow ───────────────────────────────
def extract_features(packet_list):
    """Extract 52 features from a group of packets"""
    if len(packet_list) < 2:
        return None

    first_pkt  = packet_list[0]
    src_ip     = first_pkt['src']

    fwd_packets = [p for p in packet_list if p['src'] == src_ip]
    bwd_packets = [p for p in packet_list if p['src'] != src_ip]

    fwd_lengths = [p['length'] for p in fwd_packets]
    bwd_lengths = [p['length'] for p in bwd_packets]
    all_lengths = [p['length'] for p in packet_list]
    timestamps  = [p['time'] for p in packet_list]

    flow_duration = (timestamps[-1] - timestamps[0]) * 1e6
    if flow_duration == 0:
        flow_duration = 1

    iats = [timestamps[i+1] - timestamps[i]
            for i in range(len(timestamps)-1)]
    fwd_times = [p['time'] for p in fwd_packets]
    bwd_times = [p['time'] for p in bwd_packets]
    fwd_iats  = [fwd_times[i+1] - fwd_times[i]
                 for i in range(len(fwd_times)-1)] \
                if len(fwd_times) > 1 else [0]
    bwd_iats  = [bwd_times[i+1] - bwd_times[i]
                 for i in range(len(bwd_times)-1)] \
                if len(bwd_times) > 1 else [0]

    fin_count = sum(1 for p in packet_list if p.get('flags',0) & 0x01)
    psh_count = sum(1 for p in packet_list if p.get('flags',0) & 0x08)
    ack_count = sum(1 for p in packet_list if p.get('flags',0) & 0x10)

    total_bytes  = sum(all_lengths)
    flow_bytes_s = total_bytes / (flow_duration / 1e6)
    flow_pkts_s  = len(packet_list) / (flow_duration / 1e6)

    return {
        'Destination Port': first_pkt.get('dport', 0),
        'Flow Duration': flow_duration,
        'Total Fwd Packets': len(fwd_packets),
        'Total Length of Fwd Packets': sum(fwd_lengths) if fwd_lengths else 0,
        'Fwd Packet Length Max': max(fwd_lengths) if fwd_lengths else 0,
        'Fwd Packet Length Min': min(fwd_lengths) if fwd_lengths else 0,
        'Fwd Packet Length Mean': np.mean(fwd_lengths) if fwd_lengths else 0,
        'Fwd Packet Length Std': np.std(fwd_lengths) if fwd_lengths else 0,
        'Bwd Packet Length Max': max(bwd_lengths) if bwd_lengths else 0,
        'Bwd Packet Length Min': min(bwd_lengths) if bwd_lengths else 0,
        'Bwd Packet Length Mean': np.mean(bwd_lengths) if bwd_lengths else 0,
        'Bwd Packet Length Std': np.std(bwd_lengths) if bwd_lengths else 0,
        'Flow Bytes/s': flow_bytes_s,
        'Flow Packets/s': flow_pkts_s,
        'Flow IAT Mean': np.mean(iats) if iats else 0,
        'Flow IAT Std': np.std(iats) if iats else 0,
        'Flow IAT Max': max(iats) if iats else 0,
        'Flow IAT Min': min(iats) if iats else 0,
        'Fwd IAT Total': sum(fwd_iats),
        'Fwd IAT Mean': np.mean(fwd_iats),
        'Fwd IAT Std': np.std(fwd_iats),
        'Fwd IAT Max': max(fwd_iats),
        'Fwd IAT Min': min(fwd_iats),
        'Bwd IAT Total': sum(bwd_iats),
        'Bwd IAT Mean': np.mean(bwd_iats),
        'Bwd IAT Std': np.std(bwd_iats),
        'Bwd IAT Max': max(bwd_iats),
        'Bwd IAT Min': min(bwd_iats),
        'Fwd Header Length': len(fwd_packets) * 20,
        'Bwd Header Length': len(bwd_packets) * 20,
        'Fwd Packets/s': len(fwd_packets) / (flow_duration / 1e6),
        'Bwd Packets/s': len(bwd_packets) / (flow_duration / 1e6),
        'Min Packet Length': min(all_lengths) if all_lengths else 0,
        'Max Packet Length': max(all_lengths) if all_lengths else 0,
        'Packet Length Mean': np.mean(all_lengths) if all_lengths else 0,
        'Packet Length Std': np.std(all_lengths) if all_lengths else 0,
        'Packet Length Variance': np.var(all_lengths) if all_lengths else 0,
        'FIN Flag Count': fin_count,
        'PSH Flag Count': psh_count,
        'ACK Flag Count': ack_count,
        'Average Packet Size': np.mean(all_lengths) if all_lengths else 0,
        'Subflow Fwd Bytes': sum(fwd_lengths) if fwd_lengths else 0,
        'Init_Win_bytes_forward': first_pkt.get('window', 0),
        'Init_Win_bytes_backward': 0,
        'act_data_pkt_fwd': len([p for p in fwd_packets
                                  if p['length'] > 0]),
        'min_seg_size_forward': min(fwd_lengths) if fwd_lengths else 0,
        'Active Mean': 0, 'Active Max': 0, 'Active Min': 0,
        'Idle Mean': 0,   'Idle Max': 0,   'Idle Min': 0
    }

# ─── Process Each Packet ──────────────────────────────────────
def process_packet(packet):
    """Called automatically for every captured packet"""
    try:
        if not packet.haslayer(IP):
            return

        ip        = packet[IP]
        src       = ip.src
        dst       = ip.dst
        length    = len(packet)
        timestamp = time.time()
        flags     = 0
        dport     = 0
        window    = 0

        if packet.haslayer(TCP):
            flags  = int(packet[TCP].flags)
            dport  = packet[TCP].dport
            window = packet[TCP].window
        elif packet.haslayer(UDP):
            dport  = packet[UDP].dport

        # Skip already blocked IPs
        if is_ip_blocked(src):
            return

        flow_key = f"{src}-{dst}-{dport}"
        flows[flow_key].append({
            'src': src, 'dst': dst,
            'length': length, 'time': timestamp,
            'flags': flags, 'dport': dport,
            'window': window
        })

        # Analyse every 10 packets
        if len(flows[flow_key]) == 10:
            features = extract_features(flows[flow_key])

            if features:
                # ── DUAL ENGINE ANALYSIS ─────────────────────
                result = analyse_flow(features)
                timestamp_str = time.strftime('%H:%M:%S')

                if result['is_threat']:
                    attack_type    = result['attack_type']
                    confidence     = result['confidence']
                    severity       = result['severity']
                    recommendation = result['recommendation']
                    engines        = recommendation.get('engines','RF')
                    action         = recommendation.get('action','')
                    message        = recommendation.get('message','')

                    print(f"🚨 [{timestamp_str}] {attack_type} | "
                          f"{src} → {dst} | "
                          f"Confidence: {confidence:.1f}% | "
                          f"Engine: {engines} | "
                          f"Action: {action}")

                    # Save alert
                    alert = {
                        'time': timestamp_str,
                        'date': datetime.datetime.now().strftime(
                            '%Y-%m-%d'),
                        'type': attack_type,
                        'src': src,
                        'dst': dst,
                        'confidence': round(confidence, 1),
                        'severity': severity,
                        'engines': engines,
                        'action': action,
                        'message': message,
                        'status': 'active',
                        'rf_attack': result['rf_engine']['attack_type'],
                        'if_anomaly': str(result['if_engine']['is_anomaly']),
                        'anomaly_score': result['if_engine']['anomaly_score']
                    }
                    alert_log.append(alert)
                    save_alert(alert)

                    # Auto-block critical threats
                    auto_blocked = auto_block_if_critical(result, src)
                    if auto_blocked:
                        alert['status'] = 'auto_blocked'
                        print(f"🛡️  [{timestamp_str}] AUTO-BLOCKED: {src}")

                else:
                    print(f"✅ [{timestamp_str}] Normal | "
                          f"{src} → {dst} | "
                          f"RF: {result['rf_engine']['confidence']:.1f}%")

            flows[flow_key] = []

    except Exception as e:
        pass

# ─── Start Capture ────────────────────────────────────────────
print(f"\n✅ Starting live capture on: {INTERFACE}")
print("✅ Dual AI engine active")
print("✅ Auto-blocking enabled for critical threats")
print("Press Ctrl+C to stop\n")

try:
    sniff(iface=INTERFACE, prn=process_packet, store=0)
except KeyboardInterrupt:
    print(f"\n=== Capture Stopped ===")
    print(f"Total alerts: {len(alert_log)}")
    threats = [a for a in alert_log if a.get('status') == 'auto_blocked']
    print(f"Auto-blocked: {len(threats)}")