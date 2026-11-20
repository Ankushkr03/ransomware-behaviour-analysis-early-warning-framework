#!/usr/bin/env python3
"""
Ransomware Behaviour Analysis and Early Warning Framework
Master Orchestration Runner (Production Implementation)
Chandigarh University - BE CSE Information Security

Starts:
1. All 6 Multi-Vector Behavioral Telemetry Submodules (T2, T3, T4, T5, T6, T7)
2. Weighted Composite Risk Scoring Engine
3. Automated Containment & Incident Response Daemon
4. Prometheus Metrics Exporter on /metrics
5. Centralized SOC Command Center Web Interface on http://127.0.0.1:8000
"""

import os
import sys
import socket
import argparse
import time
import psutil
import uvicorn

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

def is_port_in_use(port: int, host: str = "0.0.0.0") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True

def auto_free_port(port: int):
    """Detects and forcefully frees any stale process currently holding the target port."""
    import subprocess
    try:
        subprocess.run(["fuser", "-k", f"{port}/tcp"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
    except Exception:
        pass

    try:
        for p in psutil.process_iter(['pid', 'name']):
            if p.info['pid'] == os.getpid():
                continue
            try:
                for conn in p.connections(kind='inet'):
                    if conn.laddr and conn.laddr.port == port:
                        print(f"[*] Freeing port {port} currently occupied by PID {p.info['pid']} ({p.info['name']})...")
                        p.kill()
                        p.wait(timeout=1.5)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
    except Exception:
        pass
    time.sleep(0.5)

def print_banner(host: str, port: int):
    banner = f"""
================================================================================
  RANSOMWARE BEHAVIOUR ANALYSIS & EARLY WARNING FRAMEWORK
  Enterprise Multi-Vector Behavioral Telemetry & Automated Containment
================================================================================
  [+] Telemetry T2: Host & Process Ancestry Monitoring (psutil / Win32 API)
  [+] Telemetry T3: File-System Sliding Shannon Entropy (>7.85 bits/byte)
  [+] Telemetry T4: Identity & Authentication Anomalies (Logon 3 vs 10 / LSASS)
  [+] Telemetry T5: Network Lateral Movement & Outbound C2 Beaconing
  [+] Telemetry T6: Defense Evasion & Recovery Inhibition (vssadmin/wmic)
  [+] Telemetry T7: Deception & Tripwire Vault (Sub-second zero-false-positive)
--------------------------------------------------------------------------------
  [*] Centralized SOC Web Command Center: http://127.0.0.1:{port}
  [*] Unified Prometheus Metric Scrape:   http://127.0.0.1:{port}/metrics
  [*] Prometheus Config File:             config/prometheus.yml
  [*] Prometheus Alerting Rules:          config/alert.rules.yml
  [*] Grafana Dashboard JSON:             config/grafana_dashboard.json
  [*] Forensic Incident Reports Path:     reports/
================================================================================
"""
    print(banner)

def main():
    parser = argparse.ArgumentParser(description="Ransomware Early Detection Framework Master Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    args = parser.parse_args()

    # If port is occupied, automatically free it
    if is_port_in_use(args.port, args.host):
        auto_free_port(args.port)
        time.sleep(0.5)

    # If still occupied (e.g. system permission), fall back to next free port
    chosen_port = args.port
    if is_port_in_use(chosen_port, args.host):
        auto_free_port(chosen_port)
        time.sleep(0.5)
        if is_port_in_use(chosen_port, args.host):
            for candidate in [8080, 8081, 8888, 9000]:
                if not is_port_in_use(candidate, args.host):
                    print(f"[!] Notice: Port {chosen_port} busy, switching to free port {candidate}")
                    chosen_port = candidate
                    break

    print_banner(args.host, chosen_port)

    uvicorn.run(
        "dashboard.app:app",
        host=args.host,
        port=chosen_port,
        log_level="info",
        reload=False
    )

if __name__ == "__main__":
    main()
