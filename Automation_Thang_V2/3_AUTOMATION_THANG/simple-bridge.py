#!/usr/bin/env python3
"""SOC Bridge - Demo end-to-end: Event → AI → Decision → Firewall → ES"""
import time
import requests
from datetime import datetime, timezone

AUTOMATION_URL = "http://127.0.0.1:8000/events"
TOKEN = "demo-automation-token"
ES_URL = "http://localhost:9200"
ES_INDEX = "soc-automation-results"

def send_event(src_ip, event_type, severity, failed_logins, unique_ports):
    event = {
        "event_id": f"demo-{int(time.time()*1000)}",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "test",
        "src_ip": src_ip,
        "dst_ip": "10.0.30.20",
        "severity": severity,
        "event_type": event_type,
        "features": {
            "failed_logins_60s": failed_logins,
            "unique_dst_ports_60s": unique_ports
        }
    }
    
    print(f"[SEND] {src_ip} | {event_type} | sev={severity} | failed={failed_logins} | ports={unique_ports}")
    
    try:
        r = requests.post(AUTOMATION_URL, json=event,
                          headers={"Authorization": f"Bearer {TOKEN}"}, timeout=10)
        
        if r.status_code == 200:
            result = r.json()
            print(f"  → Decision: {result.get('decision')} | Risk: {result.get('risk_score')} | Execution: {result.get('execution')}")
            
            doc = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip": event["src_ip"],
                "event_type": event["event_type"],
                "source": event["source"],
                "decision": result.get("decision"),
                "risk_score": result.get("risk_score"),
                "anomaly_score": result.get("anomaly_score"),
                "execution": result.get("execution"),
                "reason": result.get("reason"),
                "firewall_status": result.get("firewall", {}).get("status") if result.get("firewall") else None,
                "event": event,
                "result": result
            }
            es_r = requests.post(f"{ES_URL}/{ES_INDEX}/_doc", json=doc, timeout=5)
            if es_r.status_code in (200, 201):
                print(f"  → ✅ Saved to ES")
            else:
                print(f"  → ⚠️ ES error: {es_r.status_code}")
        else:
            print(f"  → ❌ HTTP {r.status_code}: {r.text[:100]}")
    except Exception as e:
        print(f"  → ❌ Error: {e}")

if __name__ == "__main__":
    print("=" * 70)
    print(" SOC AUTO DEMO - Simulate Attacks → AI → Decision → Firewall → ES")
    print("=" * 70)
    print()
    
    events = [
        ("198.51.100.23", "brute_force", 12, 30, 1),      # BLOCK
        ("198.51.100.24", "other", 2, 0, 1),               # OBSERVE
        ("198.51.100.25", "port_scan", 12, 0, 100),        # BLOCK
        ("10.10.99.10", "port_scan", 15, 0, 100),          # REVIEW (protected)
        ("10.10.30.20", "brute_force", 15, 50, 1),         # REVIEW (protected)
        ("10.10.40.25", "port_scan", 15, 0, 100),          # REVIEW (internal)
    ]
    
    for i, (ip, etype, sev, fl, up) in enumerate(events, 1):
        print(f"\n[{i}/{len(events)}]")
        send_event(ip, etype, sev, fl, up)
        time.sleep(1.5)
    
    print()
    print("=" * 70)
    print(" ✅ DEMO HOÀN TẤT")
    print("=" * 70)
