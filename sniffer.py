"""
ThreatShield LIVE NIDS - CSV GUARANTEED VERSION
"""

import joblib
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import numpy as np
import time
from datetime import datetime
import requests
import logging

BOT_TOKEN = "8289559884:AAH4yl_HyZhDo-1zp1lmn6rfuXw-Zt3J8Fk"
CHAT_ID = 8194742029

def send_telegram_alert(text: str):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {"chat_id": CHAT_ID, "text": text}
    try:
        requests.post(url, data=payload, timeout=5)
    except Exception:
        # ignore network errors for now
        pass
# Suppress warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Load model
model = joblib.load("threat_model.pkl")
scaler = joblib.load("scaler.pkl")

# GLOBAL threats list (FIXED!)
threats = []
threat_count = 0
start_time = time.time()
MAX_THREATS = 50
MAX_TIME = 300  # 5 min

def packet_to_features(packet):
    features = np.zeros(41)
    try:
        if IP in packet:
            features[0] = time.time() % 60
            features[1] = packet[IP].proto
            features[4] = len(packet)
            features[5] = len(packet)
            features[22] = 1
            features[23] = 1
            
            if TCP in packet:
                features[2] = 1
                features[3] = 2
                features[32] = packet[TCP].sport
            elif UDP in packet:
                features[2] = 3
    except:
        pass
    return features

def packet_handler(packet):
    global threat_count, start_time
    
    if not IP in packet:
        return
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet[IP].proto
    size = len(packet)
    
    features = packet_to_features(packet)
    features_scaled = scaler.transform([features])
    
    pred = model.predict(features_scaled)[0]
    score = model.decision_function(features_scaled)[0]
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    if pred == -1 and score < -0.05:
        threat_count += 1
        threat_info = {
            'time': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'proto': 'TCP' if proto==6 else 'UDP',
            'size': size,
            'score': f"{score:.3f}",
            'type': 'Suspicious Traffic'
        }
        threats.append(threat_info)  # GLOBAL list!
        
        print(f"🚨 THREAT #{threat_count} | {timestamp}")
        print(f"   IP: {src_ip} → {dst_ip} | Proto: {'TCP' if proto==6 else 'UDP'}")
        print(f"   Size: {size}B | ML Score: {score:.3f}")
        print("-" * 50)

        alert_text = (
        f"ThreatShield Alert #{threat_count}\n"
        f"Time: {timestamp}\n"
        f"Src: {src_ip} → Dst: {dst_ip}\n"
        f"Proto: {'TCP' if proto==6 else 'UDP'} | Size: {size}B\n"
        f"Score: {score:.3f}"
        )
        send_telegram_alert(alert_text)
    # Auto-stop
    if threat_count >= MAX_THREATS:
        print(f"\n🎯 MAX THREATS: {threat_count}")
        save_csv()
        raise KeyboardInterrupt()
    elif (time.time() - start_time) > MAX_TIME:
        print(f"\n⏰ MAX TIME: 5 min")
        save_csv()
        raise KeyboardInterrupt()

def save_csv():
    """FORCE SAVE CSV - Called on EVERY stop"""
    global threats
    if threats:
        df = pd.DataFrame(threats)
        df.to_csv("threats_log.csv", index=False)
        print(f"💾 SAVED {len(threats)} threats → threats_log.csv ✅")
        print(f"📁 File size: {len(threats)} rows")
    else:
        print("ℹ️ No threats - demo CSV created")
        pd.DataFrame([{
            'time': '12:55', 'src_ip': '192.168.1.100', 
            'dst_ip': '8.8.8.8', 'proto': 'TCP', 
            'size': 66, 'score': '-0.057', 'type': 'Demo'
        }]).to_csv("threats_log.csv", index=False)

def start_live_monitoring():
    print("🛡️ ThreatShield LIVE NIDS")
    print("📡 Capturing real traffic...")
    print("⏹️ Auto-stops at 50 threats or 5 min")
    print("=" * 60)
    sniff(prn=packet_handler, filter="tcp or udp", timeout=MAX_TIME, store=0)

if __name__ == "__main__":
    try:
        start_live_monitoring()
    except KeyboardInterrupt:
        pass
    finally:
        # FINAL FORCE SAVE (even on crash!)
        save_csv()
        print("🎉 ThreatShield session complete!")
