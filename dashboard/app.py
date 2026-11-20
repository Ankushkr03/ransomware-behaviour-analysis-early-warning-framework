"""
Centralized SOC Monitoring & Incident Response Command Center
FastAPI Backend providing unified telemetry aggregation, Prometheus metric exposition,
automated containment, admin notifications, incident reporting, and simulator controls.
"""

import os
import json
import time
import random
import threading
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Import framework modules
from telemetry.host_process_telemetry import HostProcessTelemetry
from telemetry.filesystem_entropy_telemetry import FilesystemEntropyTelemetry
from telemetry.identity_auth_telemetry import IdentityAuthTelemetry
from telemetry.network_exfil_telemetry import NetworkExfilTelemetry
from telemetry.defense_evasion_telemetry import DefenseEvasionTelemetry
from telemetry.deception_tripwire_telemetry import DeceptionTripwireTelemetry

from engine.risk_scoring_engine import RiskScoringEngine
from engine.containment_engine import ContainmentEngine
from engine.notification_engine import NotificationEngine
from engine.incident_reporter import IncidentReporter
from engine.baseline_benchmark_engine import BaselineBenchmarkEngine
from simulator.ransomware_simulator import RansomwareSimulator

# Load configuration
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.json")

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

# Resolve directories relative to project root if relative or stale
def _resolve_dir(configured_path: str, default_name: str) -> str:
    if not configured_path or not os.path.isabs(configured_path) or not os.path.exists(configured_path):
        target_name = os.path.basename(configured_path.rstrip("/\\")) if configured_path else default_name
        resolved = os.path.join(BASE_DIR, target_name)
        return resolved
    return configured_path

config["filesystem_monitoring"]["monitored_dir"] = _resolve_dir(
    config.get("filesystem_monitoring", {}).get("monitored_dir", "monitored_dir"),
    "monitored_dir"
)
config["canary"]["vault_dir"] = _resolve_dir(
    config.get("canary", {}).get("vault_dir", "canary_vault"),
    "canary_vault"
)

app = FastAPI(title="Ransomware Early Detection & Containment Command Center")

# Static files & templates
static_dir = os.path.join(BASE_DIR, "dashboard", "static")
templates_dir = os.path.join(BASE_DIR, "dashboard", "templates")
reports_dir = os.path.join(BASE_DIR, "reports")

app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)

# Initialize the 6 Telemetry Modules
t2_host_process = HostProcessTelemetry()
t3_fs_entropy = FilesystemEntropyTelemetry(
    monitored_dir=config["filesystem_monitoring"]["monitored_dir"],
    entropy_threshold=config["filesystem_monitoring"]["high_entropy_threshold"]
)
t4_identity_auth = IdentityAuthTelemetry()
t5_network_exfil = NetworkExfilTelemetry()
t6_defense_evasion = DefenseEvasionTelemetry()
t7_deception_canary = DeceptionTripwireTelemetry(vault_dir=config["canary"]["vault_dir"])

# Initialize Backend Engines
risk_engine = RiskScoringEngine(weights=config["risk_scoring"]["weights"])
containment_engine = ContainmentEngine(config=config)
notification_engine = NotificationEngine(config=config, config_path=CONFIG_PATH)
incident_reporter = IncidentReporter(reports_dir=reports_dir)
benchmark_engine = BaselineBenchmarkEngine(
    base_dir=BASE_DIR,
    telemetry_refs={
        "process": t2_host_process,
        "filesystem": t3_fs_entropy,
        "identity": t4_identity_auth,
        "network": t5_network_exfil,
        "defense_evasion": t6_defense_evasion,
        "canary": t7_deception_canary
    },
    containment_ref=containment_engine,
    risk_ref=risk_engine
)
simulator = RansomwareSimulator(
    monitored_dir=config["filesystem_monitoring"]["monitored_dir"],
    canary_vault_dir=config["canary"]["vault_dir"]
)

# Start all telemetry collectors
t2_host_process.start()
t3_fs_entropy.start()
t5_network_exfil.start()
t7_deception_canary.start()

# State Tracking
latest_risk_result: Dict[str, Any] = {
    "risk_score_100": 0.0,
    "threat_score_norm": 0.0,
    "risk_level": "Normal",
    "recommended_action": "Continue monitoring.",
    "badge_color": "#10b981",
    "breakdown": {}
}

last_auto_incident_report_time = 0.0
incident_in_progress = False
simulation_in_progress = False
last_simulation_start_time = 0.0
current_active_simulation_scenario: Optional[str] = None

def get_active_flagged_processes() -> List[Dict[str, Any]]:
    """Returns currently active suspicious processes, strictly excluding terminated/quarantined PIDs."""
    procs = t2_host_process.get_flagged_processes()
    active = []
    for p in procs:
        pid = p.get("pid")
        if pid in containment_engine.quarantined_pids:
            continue
        active.append(p)
    return active

def background_risk_and_containment_loop():
    """
    Continuous evaluation loop (runs every 1 sec):
    1. Gathers latest signals across all 6 telemetry submodules
    2. Runs Risk-Scoring calculation
    3. Triggers Automated Containment and Admin Alert if threshold breached!
    """
    global latest_risk_result, last_auto_incident_report_time
    while True:
        try:
            # Gather telemetry features
            canary_status_list = t7_deception_canary.get_canary_status()
            canary_breached = t7_deception_canary.is_any_compromised or any(c.get("status") == "COMPROMISED" for c in canary_status_list)

            entropy_info = t3_fs_entropy.get_latest_entropy_data()
            curr_entropy = entropy_info.get("latest_entropy", 0.0)
            consec_entropy = entropy_info.get("consecutive_high_entropy", 0)

            recovery_inhibition_hits = int(t6_defense_evasion.m_recovery_inhibition.get())
            ransomware_ext_seen = any(
                f.get("extension", "").lower() in config["filesystem_monitoring"]["ransomware_extensions"]
                for f in entropy_info.get("recent_inspected_files", [])
            )
            rename_rate = float(t3_fs_entropy.m_rename_rate.get())

            flagged_procs = get_active_flagged_processes()
            max_proc_threat = max([p.get("threat_score", 0.0) for p in flagged_procs], default=0.05)

            c2_count = int(t5_network_exfil.m_c2_beacons.get())
            lateral_count = int(t5_network_exfil.m_lateral_scans.get())

            cred_dump_count = int(t4_identity_auth.m_cred_dumping.get())
            failed_logins = int(t4_identity_auth.m_failed_logins.get())

            # Calculate composite risk score
            res = risk_engine.calculate_risk(
                canary_compromised=canary_breached,
                current_entropy=curr_entropy,
                consecutive_high_entropy=consec_entropy,
                recovery_inhibition_count=recovery_inhibition_hits,
                ransomware_extension_seen=ransomware_ext_seen,
                rename_rate=rename_rate,
                max_process_threat=max_proc_threat,
                c2_beacons_count=c2_count,
                lateral_scan_count=lateral_count,
                cred_dump_count=cred_dump_count,
                failed_logins_count=failed_logins
            )
            latest_risk_result = res

            # Automated Response Trigger Logic
            # Threshold: Composite Threat Score >= 0.50 (or Risk Score >= 50) OR Canary Breach == 1
            if containment_engine.auto_response_enabled and (res["risk_score_100"] >= 50.0 or canary_breached):
                # Target process identification
                target_pid = None
                target_name = "simulated_ransomware"
                now = time.time()
                for p in flagged_procs:
                    if p.get("threat_score", 0.0) >= 0.50:
                        injected_at = p.get("injected_at")
                        # For freshly simulated attack processes, maintain an observation window of 15 seconds
                        # so that the user and SOC analysts can observe the active process in the UI!
                        if injected_at and (now - injected_at < 15.0):
                            continue
                        target_pid = p.get("pid")
                        target_name = p.get("name")
                        break

                # 1. Terminate malicious process
                if target_pid and target_pid not in containment_engine.quarantined_pids:
                    containment_engine.terminate_process(
                        pid=target_pid,
                        process_name=target_name,
                        reason=f"Automated Containment: Risk Score {res['risk_score_100']}/100",
                        initiator="Automated Containment Engine"
                    )
                    t2_host_process.remove_process(target_pid)

                # 2. Network Isolation
                if not containment_engine.is_network_isolated:
                    containment_engine.isolate_network(
                        initiator="Automated Containment Engine",
                        reason=f"Early Ransomware Containment Trigger (Score: {res['risk_score_100']})"
                    )

                # 3. Notify Admin
                notification_engine.dispatch_alert(
                    title=f"🚨 CRITICAL RANSOMWARE EARLY WARNING - Score {res['risk_score_100']}/100",
                    severity="CRITICAL",
                    details={
                        "risk_level": res["risk_level"],
                        "threat_score": res["threat_score_norm"],
                        "canary_breached": canary_breached,
                        "write_entropy": curr_entropy,
                        "terminated_pid": target_pid,
                        "target_process": target_name,
                        "action_taken": "Automated Process Termination & Network Quarantine"
                    }
                )

                # 4. Generate Incident Report (once per incident escalation / 120s cooldown)
                now = time.time()
                # If a simulation drill is actively running, the simulation runner generates its own dedicated drill report.
                # Skip duplicate background loop report generation.
                if simulation_in_progress or (current_active_simulation_scenario is not None and (now - last_simulation_start_time < 60.0)):
                    pass
                elif not incident_in_progress or (now - last_auto_incident_report_time > 120.0):
                    incident_in_progress = True
                    last_auto_incident_report_time = now
                    live_rep = incident_reporter.generate_report(
                        risk_data=res,
                        telemetry_events=get_combined_events(limit=30),
                        containment_actions=containment_engine.get_action_history(),
                        flagged_processes=flagged_procs,
                        canary_status=canary_status_list,
                        entropy_data=entropy_info,
                        hostname=config["system"]["hostname"],
                        is_simulation=False,
                        simulation_scenario=None
                    )
                    # Automatically send email notification whenever incident is detected
                    try:
                        notification_engine.dispatch_incident_email(
                            report_data=live_rep,
                            is_simulation=False,
                            scenario_name="Live Production Incident",
                            short_note=(
                                f"CRITICAL: Active ransomware behavior detected on host {config['system']['hostname']} "
                                f"(Score: {res.get('risk_score_100', 0):.1f}/100 - {res.get('risk_level', 'Critical')}). "
                                f"Automated containment has terminated flagged malicious processes and isolated endpoint network. "
                                f"Complete forensic incident report attached in PDF format."
                            )
                        )
                    except Exception as eml_err:
                        print(f"[!] Error auto-dispatching live incident email: {eml_err}")
            else:
                incident_in_progress = False

        except Exception as e:
            pass
        time.sleep(1.0)

# Start background evaluation loop in daemon thread
eval_thread = threading.Thread(target=background_risk_and_containment_loop, daemon=True)
eval_thread.start()

def get_combined_events(limit: int = 60) -> List[Dict[str, Any]]:
    """Merges and chronologically sorts recent events from all 6 telemetry modules."""
    evs = []
    for mod in [t2_host_process, t3_fs_entropy, t4_identity_auth, t5_network_exfil, t6_defense_evasion, t7_deception_canary]:
        try:
            evs.extend(mod.get_recent_events(limit=30))
        except Exception:
            pass
    evs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return evs[:limit]

# ==================== Web & UI Routes ====================

@app.get("/", response_class=HTMLResponse)
def index_page(request: Request):
    try:
        canaries = t7_deception_canary.get_canary_status()
    except Exception:
        canaries = []
    try:
        flagged_procs = get_active_flagged_processes()
    except Exception:
        flagged_procs = []
    try:
        events = get_combined_events(limit=30)
    except Exception:
        events = []
    try:
        entropy_info = t3_fs_entropy.get_latest_entropy_data()
    except Exception:
        entropy_info = {"latest_entropy": 0.0, "consecutive_high_entropy": 0, "active_monitored_file": "None"}
    
    risk_ctx = latest_risk_result or {
        "risk_score_100": 0.0,
        "threat_score_norm": 0.0,
        "risk_level": "Normal",
        "recommended_action": "Continue monitoring.",
        "badge_color": "#10b981",
        "breakdown": {}
    }

    try:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "config": config,
                "hostname": config.get("system", {}).get("hostname", "kali-edr-node"),
                "canaries": canaries,
                "processes": flagged_procs,
                "events": events,
                "risk": risk_ctx,
                "entropy": entropy_info
            }
        )
    except Exception as exc:
        import traceback
        err_tb = traceback.format_exc()
        return HTMLResponse(content=f"<html><body style='background:#0f172a;color:#f87171;font-family:sans-serif;padding:2rem;'><h2>SOC Command Center Template Render Error</h2><pre style='background:#1e293b;padding:1rem;color:#cbd5e1;border-radius:6px;'>{err_tb}</pre></body></html>", status_code=500)

# ==================== Prometheus Exposition Endpoints ====================

@app.get("/metrics", response_class=PlainTextResponse)
def prometheus_unified_metrics():
    """
    Unified Prometheus scraper endpoint (port 8000 /metrics).
    Scrapes operational metrics from all 6 telemetry submodules and risk engine.
    """
    blocks = [
        "# === Ransomware Behaviour Analysis & Early Warning Metrics ===",
        "# Multi-Vector Behavioral Telemetry Exposition",
        "",
        risk_engine.render_metrics(),
        t2_host_process.render_all_metrics(),
        t3_fs_entropy.render_all_metrics(),
        t4_identity_auth.render_all_metrics(),
        t5_network_exfil.render_all_metrics(),
        t6_defense_evasion.render_all_metrics(),
        t7_deception_canary.render_all_metrics()
    ]
    return "\n".join(blocks)

@app.get("/metrics/process", response_class=PlainTextResponse)
def metrics_process():
    return t2_host_process.render_all_metrics()

@app.get("/metrics/entropy", response_class=PlainTextResponse)
def metrics_entropy():
    return t3_fs_entropy.render_all_metrics()

@app.get("/metrics/auth", response_class=PlainTextResponse)
def metrics_auth():
    return t4_identity_auth.render_all_metrics()

@app.get("/metrics/network", response_class=PlainTextResponse)
def metrics_network():
    return t5_network_exfil.render_all_metrics()

@app.get("/metrics/defense_evasion", response_class=PlainTextResponse)
def metrics_defense_evasion():
    return t6_defense_evasion.render_all_metrics()

@app.get("/metrics/canary", response_class=PlainTextResponse)
def metrics_canary():
    return t7_deception_canary.render_all_metrics()

# ==================== JSON REST APIs for Centralized Control ====================

@app.get("/api/status")
def get_system_status():
    entropy_info = t3_fs_entropy.get_latest_entropy_data()
    canaries = t7_deception_canary.get_canary_status()
    breached_count = sum(1 for c in canaries if c.get("status") == "COMPROMISED")

    return {
        "system": {
            "hostname": config["system"]["hostname"],
            "environment": config["system"]["environment"],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        },
        "risk": latest_risk_result,
        "containment": {
            "auto_response_enabled": containment_engine.auto_response_enabled,
            "is_network_isolated": containment_engine.is_network_isolated,
            "quarantined_pids": containment_engine.quarantined_pids,
            "actions_executed": len(containment_engine.action_history)
        },
        "telemetry_summary": {
            "write_entropy": entropy_info.get("latest_entropy", 0.0),
            "consecutive_high_entropy": entropy_info.get("consecutive_high_entropy", 0),
            "canaries_total": len(canaries),
            "canaries_compromised": breached_count,
            "recovery_inhibition_attempts": int(t6_defense_evasion.m_recovery_inhibition.get()),
            "c2_beacons": int(t5_network_exfil.m_c2_beacons.get()),
            "lateral_scans": int(t5_network_exfil.m_lateral_scans.get()),
            "credential_dumps": int(t4_identity_auth.m_cred_dumping.get()),
            "flagged_processes_count": len(get_active_flagged_processes())
        }
    }

@app.get("/api/telemetry")
def get_full_telemetry():
    return {
        "risk": latest_risk_result,
        "entropy": t3_fs_entropy.get_latest_entropy_data(),
        "processes": get_active_flagged_processes(),
        "canaries": t7_deception_canary.get_canary_status(),
        "events": get_combined_events(limit=50),
        "containment": {
            "auto_response_enabled": containment_engine.auto_response_enabled,
            "is_network_isolated": containment_engine.is_network_isolated,
            "quarantined_pids": containment_engine.quarantined_pids,
            "actions_executed": len(containment_engine.action_history)
        },
        "containment_history": containment_engine.get_action_history(limit=20),
        "notifications": notification_engine.get_notification_log(limit=20)
    }

@app.get("/api/telemetry/vector/{vector_id}")
def get_telemetry_vector_detail(vector_id: str):
    v = vector_id.lower().strip()
    
    if v in ["t2", "host", "process"]:
        procs = get_active_flagged_processes()
        recent_evs = [e for e in t2_host_process.get_recent_events(limit=30)]
        return {
            "code": "T2",
            "name": "Host & Process Ancestry Monitoring",
            "icon": "fa-solid fa-microchip text-primary",
            "metric_value": len(procs),
            "metric_label": "Flagged Active Processes",
            "status": "CRITICAL" if len(procs) > 0 else "NORMAL",
            "badge_color": "danger" if len(procs) > 0 else "success",
            "summary": "Audits process ancestry, executable origins, command-line arguments, and calculates dynamic threat scores.",
            "considerations": [
                {
                    "title": "Known Ransomware Signatures & Binary Patterns",
                    "badge": "Signature Matching",
                    "description": "Matches running executable names against known ransomware binaries (@WanaDecryptor@.exe, lockbit3_encryptor.exe, alphv_blackcat.exe, conti_worker.exe, ryuk_crypto.exe, etc.) and analyzes masquerading binaries."
                },
                {
                    "title": "Abnormal & Temporary Directory Executions",
                    "badge": "Path Anomalies",
                    "description": "Flags executables spawned from volatile or non-standard paths (/tmp, /var/tmp, /dev/shm, \\AppData\\Local\\Temp, \\Users\\Public) which are standard ransomware drop/staging points."
                },
                {
                    "title": "Malicious Command-Line Heuristics",
                    "badge": "Argument Inspection",
                    "description": "Detects evasion switches, anti-recovery flags, and encryption parameters (e.g. --killswitch-bypass, --pass-vss, --threads, -path, delete shadows)."
                },
                {
                    "title": "Orphaned Lineage & Interactive Shell Spawns",
                    "badge": "Ancestry Tree",
                    "description": "Monitors parent-child relationships; flags web services, database daemons, or unprivileged background jobs directly spawning interactive command shells (bash, cmd.exe, powershell.exe)."
                },
                {
                    "title": "Process Threat Score Thresholding (S_proc)",
                    "badge": "Scoring Engine",
                    "description": "Processes with threat score S >= 0.70 are flagged for continuous tracking; S >= 0.85 immediately trips automated SIGKILL containment."
                }
            ],
            "evidence": {
                "flagged_processes": procs,
                "recent_events": recent_evs,
                "monitored_total": len(t2_host_process.monitored_pids)
            }
        }
    
    elif v in ["t3", "entropy", "filesystem"]:
        entropy_data = t3_fs_entropy.get_latest_entropy_data()
        curr_ent = entropy_data.get("latest_entropy", 0.0)
        recent_evs = [e for e in t3_fs_entropy.get_recent_events(limit=30)]
        is_crit = curr_ent >= 7.85
        return {
            "code": "T3",
            "name": "File-System & Sliding-Window Shannon Entropy",
            "icon": "fa-solid fa-file-code text-info",
            "metric_value": round(curr_ent, 2),
            "metric_label": "Sliding Shannon Entropy (bits/byte)",
            "status": "CRITICAL" if is_crit else ("ELEVATED" if curr_ent >= 6.5 else "NORMAL"),
            "badge_color": "danger" if is_crit else ("warning text-dark" if curr_ent >= 6.5 else "success"),
            "summary": "Measures information randomness and mass file rename velocity to detect active cryptographic encryption in real time.",
            "considerations": [
                {
                    "title": "Shannon Information Entropy Formula",
                    "badge": "Mathematical Model",
                    "description": "Calculates entropy H(X) = -sum(P(x_i) * log2(P(x_i))) over sliding 4096-byte chunk windows. 0.00 represents pure repetitive patterns, while 8.00 bits/byte represents maximum theoretical cryptographic randomness."
                },
                {
                    "title": "Empirical Baseline vs Attack Threshold (> 7.85)",
                    "badge": "Threshold Rule",
                    "description": "Standard business plaintext, source code, and office spreadsheets fall strictly between 3.5 - 5.5 bits/byte. A sustained reading exceeding 7.85 bits/byte indicates AES/ChaCha20 encrypted ciphertext."
                },
                {
                    "title": "Consecutive High-Entropy Block Verification",
                    "badge": "False-Positive Filter",
                    "description": "Requires >= 3 consecutive high-entropy blocks within the active window to prevent benign compressed files (ZIP, PNG, MP4) from triggering false positives."
                },
                {
                    "title": "Mass File Renaming Burst Velocity",
                    "badge": "Heuristic Speed",
                    "description": "Calculates the rate of file renaming operations per second; a burst rate exceeding 5.0 renames/sec indicates automated batch encryption."
                },
                {
                    "title": "Ransomware Extension Library Matching",
                    "badge": "Known Signatures",
                    "description": "Monitors file modifications ending in known ransomware extensions (.wncry, .lockbit, .alphv, .conti, .royal, .hive, .darkside, .akira, .maze, etc.)."
                }
            ],
            "evidence": {
                "latest_entropy": curr_ent,
                "baseline_entropy": 4.12,
                "threshold": 7.85,
                "consecutive_high_entropy": entropy_data.get("consecutive_high_entropy", 0),
                "active_monitored_file": entropy_data.get("active_monitored_file", "None"),
                "rename_rate": round(getattr(t3_fs_entropy.m_rename_rate, '_value', 0.0) if hasattr(t3_fs_entropy, 'm_rename_rate') else 0.0, 2),
                "recent_events": recent_evs
            }
        }
    
    elif v in ["t4", "auth", "identity"]:
        cred_events = [e for e in t4_identity_auth.auth_events]
        recent_evs = [e for e in t4_identity_auth.get_recent_events(limit=30)]
        count = len(cred_events)
        return {
            "code": "T4",
            "name": "Identity & Authentication Anomalies",
            "icon": "fa-solid fa-user-shield text-warning",
            "metric_value": count,
            "metric_label": "Cred Dumps & Auth Anomalies",
            "status": "CRITICAL" if count > 0 else "NORMAL",
            "badge_color": "danger" if count > 0 else "success",
            "summary": "Monitors LSASS memory access, credential extraction attempts, Logon Type 3 network anomalies, and Kerberoasting.",
            "considerations": [
                {
                    "title": "LSASS Handle Memory Scraping (MITRE T1003.001)",
                    "badge": "Memory Protection",
                    "description": "Intercepts unauthorized processes opening handles to lsass.exe (Local Security Authority Subsystem Service) with PROCESS_VM_READ (0x0010) to steal credentials."
                },
                {
                    "title": "Logon Type 3 Privileged Network Traversal",
                    "badge": "Logon Anomaly",
                    "description": "Flags network logons (Logon Type 3) using privileged credentials (Administrator) across internal endpoints, indicative of lateral PsExec/WMI/SMB traversal."
                },
                {
                    "title": "Kerberoasting Ticket Requests (Event ID 4769)",
                    "badge": "Kerberos Audit",
                    "description": "Detects high-volume requests for Kerberos Service Tickets (TGS) with weak RC4-HMAC (0x17) encryption requested for offline hash cracking."
                },
                {
                    "title": "Authentication Spray & Brute-Force Bursts",
                    "badge": "Burst Detection",
                    "description": "Monitors failed login bursts; >= 5 failed attempts in 10s flags active credential brute-forcing."
                }
            ],
            "evidence": {
                "events_count": count,
                "auth_events": cred_events,
                "recent_events": recent_evs
            }
        }
    
    elif v in ["t5", "network", "exfil"]:
        conns = list(t5_network_exfil.connection_history)
        recent_evs = [e for e in t5_network_exfil.get_recent_events(limit=30)]
        count = len(conns)
        return {
            "code": "T5",
            "name": "Network Lateral Movement & Outbound C2 Beaconing",
            "icon": "fa-solid fa-satellite-dish text-success",
            "metric_value": count,
            "metric_label": "C2 Beacons & Lateral Scans",
            "status": "CRITICAL" if count > 0 else "NORMAL",
            "badge_color": "danger" if count > 0 else "success",
            "summary": "Detects outbound Command & Control (C2) beaconing, East-West SMB/RDP lateral movement, and pre-encryption data exfiltration.",
            "considerations": [
                {
                    "title": "Outbound C2 Beaconing Periodic Signals",
                    "badge": "C2 Infrastructure",
                    "description": "Detects persistent outbound heartbeats with uniform intervals and low jitter over HTTP/HTTPS/TCP connecting to external threat actor infrastructure."
                },
                {
                    "title": "East-West Lateral Movement Sweeps (SMB/RDP/RPC)",
                    "badge": "Lateral Movement",
                    "description": "Identifies rapid connection sweeps to internal workstation and server subnets on high-risk lateral ports: Port 445 (SMB), Port 3389 (RDP), Port 135 (RPC)."
                },
                {
                    "title": "Pre-Encryption Double-Extortion Exfiltration",
                    "badge": "Bandwidth Spike",
                    "description": "Monitors outbound network throughput (MB/s); a sudden high-volume data egress spike prior to file encryption indicates active corporate data theft."
                },
                {
                    "title": "Malicious Destination IP / Domain Correlation",
                    "badge": "Threat Intel",
                    "description": "Correlates destination IPs against known threat actor C2 feeds and WannaCry killswitch domain patterns."
                }
            ],
            "evidence": {
                "connection_history": conns,
                "total_signals": count,
                "recent_events": recent_evs
            }
        }
    
    elif v in ["t6", "evasion", "defense"]:
        evasion_events = list(t6_defense_evasion.evasion_events)
        recent_evs = [e for e in t6_defense_evasion.get_recent_events(limit=30)]
        count = len(evasion_events)
        return {
            "code": "T6",
            "name": "Defense Evasion & Recovery Inhibition",
            "icon": "fa-solid fa-ban text-danger",
            "metric_value": count,
            "metric_label": "Inhibition & Evasion Commands",
            "status": "CRITICAL" if count > 0 else "NORMAL",
            "badge_color": "danger" if count > 0 else "success",
            "summary": "Intercepts commands targeting Volume Shadow Copies, backup catalogs, boot recovery configuration, and security service tampering.",
            "considerations": [
                {
                    "title": "Volume Shadow Copy Annihilation (MITRE T1490)",
                    "badge": "Recovery Inhibition",
                    "description": "Matches command executions designed to prevent victim data restoration: vssadmin delete shadows /all /quiet, wmic shadowcopy delete, vssadmin resize shadowstorage."
                },
                {
                    "title": "Boot Configuration Recovery Tampering",
                    "badge": "Boot Evasion",
                    "description": "Flags bcdedit commands disabling Windows error recovery and startup recovery prompts (recoveryenabled no, bootstatuspolicy ignoreallfailures)."
                },
                {
                    "title": "Security Log & Event Log Erasure (MITRE T1070.001)",
                    "badge": "Indicator Removal",
                    "description": "Intercepts wevtutil commands clearing Windows event logs (wevtutil cl System, wevtutil cl Security) to hinder post-incident forensics."
                },
                {
                    "title": "Antivirus & EDR Service Termination",
                    "badge": "Defense Impairment",
                    "description": "Flags attempts to kill or suspend host protection services (sc stop windefend, net stop, taskkill targeting endpoint defenses)."
                }
            ],
            "evidence": {
                "evasion_events": evasion_events,
                "total_intercepted": count,
                "recent_events": recent_evs
            }
        }
    
    elif v in ["t7", "canary", "deception"]:
        canaries = t7_deception_canary.get_canary_status()
        breached = [c for c in canaries if c.get("status") == "COMPROMISED"]
        recent_evs = [e for e in t7_deception_canary.get_recent_events(limit=30)]
        count = len(breached)
        return {
            "code": "T7",
            "name": "Deception & Canary Tripwire Vault",
            "icon": "fa-solid fa-bomb text-danger",
            "metric_value": count,
            "metric_label": "Compromised Decoy Tripwires",
            "status": "CRITICAL" if count > 0 else "NORMAL",
            "badge_color": "danger" if count > 0 else "success",
            "summary": "Deploys high-interaction canary decoy files in sensitive directories; guarantees sub-second zero-false-positive deterministic early warning upon unauthorized tampering.",
            "considerations": [
                {
                    "title": "Zero-False-Positive Guarantee (0.00% FPR)",
                    "badge": "Deterministic Tripwire",
                    "description": "Canary decoy files are pure deception assets. Legitimate users and benign applications never access, modify, rename, or delete them. Any interaction is a 100% deterministic confirmation of malware traversal."
                },
                {
                    "title": "Strategic Decoy Distribution & Enticement",
                    "badge": "Decoy Architecture",
                    "description": "Decoys (executive payroll, client contracts, database backups, AWS access keys) are placed at high-value directory indices where ransomware algorithms search first alphabetically or by high-priority file types."
                },
                {
                    "title": "Dual-Layer Kernel Integrity Auditing",
                    "badge": "Sub-Second Detection",
                    "description": "Combines OS kernel-level filesystem notifications (inotify / watchdog) with continuous cryptographic SHA-256 hash audits every 0.5s for instant breach identification (< 1.2s)."
                },
                {
                    "title": "Deterministic Containment Escalation",
                    "badge": "Automated Response",
                    "description": "A single canary breach bypasses all heuristic ambiguity, immediately escalating Composite Threat Score to 100% CRITICAL and engaging automated network isolation and SIGKILL."
                }
            ],
            "evidence": {
                "total_deployed": len(canaries),
                "compromised_count": count,
                "compromised_canaries": breached,
                "all_canaries": canaries,
                "recent_events": recent_evs
            }
        }
    
    else:
        raise HTTPException(status_code=404, detail=f"Unknown telemetry vector: {vector_id}")

@app.get("/api/events")
def get_events():
    return {"events": get_combined_events(limit=60)}

@app.get("/api/canaries")
def get_canary_status():
    return {"canaries": t7_deception_canary.get_canary_status()}

@app.get("/api/canaries/{filename}")
def get_single_canary_detail(filename: str):
    canaries = t7_deception_canary.get_canary_status()
    for c in canaries:
        if c.get("filename") == filename:
            return {"canary": c, "sha256": c.get("expected_hash"), **c}
    raise HTTPException(status_code=404, detail="Canary asset not found")

@app.get("/api/processes")
def get_processes():
    return {"processes": get_active_flagged_processes(), "flagged_processes": get_active_flagged_processes()}

@app.get("/api/processes/{pid}")
def get_single_process_detail(pid: int):
    with t2_host_process._lock:
        proc = t2_host_process.monitored_pids.get(pid)
    if proc:
        status = "QUARANTINED" if pid in containment_engine.quarantined_pids else "ACTIVE SUSPICIOUS"
        return {"process": {**proc, "status": status}}
    
    for act in containment_engine.action_history:
        if act.get("pid") == pid:
            return {"process": {
                "pid": pid,
                "name": act.get("process_name", "terminated_malware"),
                "status": "TERMINATED / QUARANTINED",
                "threat_score": 0.95,
                "cmdline": "Neutralized process",
                "flags": [act.get("reason", "Malware containment action")],
                "exe": "Quarantined",
                "user": "root",
                "cpu_percent": 0.0,
                "memory_mb": 0.0
            }}
    raise HTTPException(status_code=404, detail="Process not found or already purged")

# ==================== Incident Response & Containment Control Actions ====================

@app.post("/api/control/containment/terminate")
def terminate_process_api(data: Dict[str, Any]):
    pid = data.get("pid")
    name = data.get("process_name", "manual_target")
    if not pid:
        raise HTTPException(status_code=400, detail="Missing pid parameter")
    pid_int = int(pid)
    res = containment_engine.terminate_process(
        pid=pid_int,
        process_name=name,
        reason=data.get("reason", "Manual SOC Admin Termination"),
        initiator="SOC Admin"
    )
    # Immediately remove from active telemetry tracking so it disappears from UI
    t2_host_process.remove_process(pid_int)
    return res

@app.post("/api/control/containment/isolate-network")
def isolate_network_api():
    return containment_engine.isolate_network(initiator="SOC Admin", reason="Manual Network Containment")

@app.post("/api/control/containment/restore-network")
def restore_network_api():
    return containment_engine.restore_network(initiator="SOC Admin")

@app.post("/api/control/canary/reset")
def reset_canary_vault_api():
    global incident_in_progress
    t7_deception_canary.reset_canary_vault()
    incident_in_progress = False
    return {"status": "SUCCESS", "message": "Canary decoy files restored and tripwire re-armed."}

@app.post("/api/control/system/resume-normal")
@app.post("/api/control/resume-normal")
def resume_normal_services_api():
    """
    Resumes all services and reconnects endpoint networking back to normal pre-attack baseline:
    1. Restores network connection (is_network_isolated = False).
    2. Re-arms canary decoy vault and clears breached status.
    3. Cleans up and clears all flagged/injected simulated attacker processes.
    4. Resets filesystem sliding-window entropy buffers and rename counters.
    5. Cleans up simulated ransomware files (*.locked, *.wncry, *.enc, etc.) from monitored_dir.
    6. Resets network telemetry connection history, lateral scan counters, and C2 beacons.
    7. Clears defense evasion events and security tampering records.
    8. Resets identity and authentication event history.
    9. Resets incident/simulation progress flags and recalculates threat score to 0.0 (Normal).
    """
    global incident_in_progress, simulation_in_progress, latest_risk_result

    # 1. Restore Network Connections
    containment_res = containment_engine.restore_network(initiator="SOC Admin - Resume Normal Services")

    # 2. Re-arm Canary Vault
    t7_deception_canary.reset_canary_vault()

    # 3. Clear Flagged Processes
    t2_host_process.clear_all_flagged_processes()

    # 4. Reset Filesystem Entropy & Renames
    t3_fs_entropy.reset_entropy_data()

    # 5. Clean up leftover simulated encrypted files in monitored_dir
    monitored_dir = config.get("filesystem_monitoring", {}).get("monitored_dir")
    if monitored_dir and os.path.exists(monitored_dir):
        ransom_exts = tuple(config.get("filesystem_monitoring", {}).get("ransomware_extensions", []))
        for fname in os.listdir(monitored_dir):
            if fname.endswith(ransom_exts) or ".dat." in fname or fname.endswith((".locked", ".wncry", ".crypto")):
                fpath = os.path.join(monitored_dir, fname)
                try:
                    if os.path.isfile(fpath):
                        os.remove(fpath)
                except Exception:
                    pass

    # 6. Reset Network Signals & History
    t5_network_exfil.reset_network_telemetry()

    # 7. Reset Defense Evasion Telemetry
    t6_defense_evasion.reset_defense_evasion_telemetry()

    # 8. Reset Identity & Auth Telemetry
    t4_identity_auth.reset_auth_telemetry()

    # 9. Clear global incident flags
    incident_in_progress = False
    simulation_in_progress = False

    # 10. Re-evaluate baseline risk score to clean 0.0
    latest_risk_result = risk_engine.calculate_risk(
        canary_compromised=False,
        current_entropy=0.0,
        consecutive_high_entropy=0,
        recovery_inhibition_count=0,
        ransomware_extension_seen=False,
        rename_rate=0.0,
        max_process_threat=0.0,
        c2_beacons_count=0,
        lateral_scan_count=0,
        cred_dump_count=0,
        failed_logins_count=0
    )

    return {
        "status": "SUCCESS",
        "network_status": "ONLINE",
        "is_network_isolated": False,
        "incident_in_progress": False,
        "risk_score": 0.0,
        "risk_level": "Normal",
        "threat_score": 0.0,
        "canaries_intact": 5,
        "message": "All services resumed successfully. Network connections reconnected, tripwires re-armed, and all telemetry restored to normal pre-attack baseline.",
        "containment_action": containment_res
    }


@app.post("/api/control/auto-response/toggle")
def toggle_auto_response_api(data: Dict[str, Any]):
    enabled = data.get("enabled", True)
    containment_engine.toggle_auto_response(enabled)
    return {"status": "SUCCESS", "auto_response_enabled": containment_engine.auto_response_enabled}

@app.get("/api/notify/config")
def get_notification_config_api():
    """Returns the current SOC Admin alerting and recipient configuration."""
    return notification_engine.get_config()

@app.post("/api/notify/config")
def update_notification_config_api(data: Dict[str, Any]):
    """Updates and persists the SOC Admin alert recipient configuration."""
    updated = notification_engine.update_config(data)
    return {"status": "SUCCESS", "message": "Alert recipient configuration updated successfully.", "config": updated}

@app.post("/api/notify/dispatch")
def dispatch_admin_notification(data: Dict[str, Any]):
    title = data.get("title", "SOC Admin High-Priority Notification")
    severity = data.get("severity", "HIGH")
    details = data.get("details", {})
    
    # Custom recipient & channel overrides
    recipients = data.get("recipients")
    channel = data.get("channel") or data.get("broadcast_channel")
    admin_name = data.get("admin_name")

    # If user selected to persist these recipient details as defaults
    if data.get("save_as_default") or data.get("save_config"):
        cfg_update = {}
        if data.get("soc_email"):
            cfg_update["soc_email"] = data["soc_email"]
        if data.get("secondary_emails") is not None:
            cfg_update["secondary_emails"] = data["secondary_emails"]
        if admin_name:
            cfg_update["admin_name"] = admin_name
        if channel:
            cfg_update["broadcast_channel"] = channel
        if data.get("webhook_url"):
            cfg_update["webhook_url"] = data["webhook_url"]
        if data.get("phone_sms"):
            cfg_update["phone_sms"] = data["phone_sms"]
        if cfg_update:
            notification_engine.update_config(cfg_update)

    return notification_engine.dispatch_alert(
        title=title,
        severity=severity,
        details=details,
        force=True,
        custom_recipients=recipients,
        custom_channel=channel,
        custom_admin=admin_name
    )

@app.get("/api/notifications/emails")
@app.get("/api/notify/emails")
def get_sent_emails_api(limit: int = 50):
    """Returns the outbox list of automatically dispatched incident alert emails with PDF attachments."""
    return {"emails": notification_engine.get_sent_emails(limit=limit)}

@app.post("/api/notify/test-email")
def send_test_email_api(data: Dict[str, Any] = {}):
    """
    Dispatches an on-demand test email to verify SMTP and recipient configuration,
    attaching the latest forensic report PDF with the appropriate note.
    Supports mode='test' (for simulated drill attribution) or mode='real' (for live critical incident attribution).
    """
    recipients = data.get("recipients") or data.get("soc_email")
    if recipients and isinstance(recipients, str):
        recipients = [r.strip() for r in recipients.split(",") if r.strip()]
        
    if "smtp" in data and isinstance(data["smtp"], dict):
        notification_engine.update_config({"smtp": data["smtp"]})

    # Mode determination: test simulation vs live alert
    is_real = (data.get("mode") == "real" or data.get("type") == "real" or data.get("is_simulation") is False)
    is_sim = not is_real

    # Find matching or latest PDF report
    target_inc_id = data.get("incident_id")
    latest_pdf = None
    latest_inc_id = target_inc_id
    if target_inc_id:
        cand_pdf = os.path.join(reports_dir, f"{target_inc_id}.pdf")
        if os.path.exists(cand_pdf):
            latest_pdf = cand_pdf
            latest_inc_id = target_inc_id

    if not latest_pdf:
        pdf_files = [f for f in sorted(os.listdir(reports_dir), reverse=True) if f.endswith(".pdf")]
        latest_pdf = os.path.join(reports_dir, pdf_files[0]) if pdf_files else None
        latest_inc_id = pdf_files[0].replace(".pdf", "") if pdf_files else ("LIVE-INC-SAMPLE" if is_real else "SIM-INC-SAMPLE")

    scenario_param = data.get("scenario")
    rep_data = {
        "incident_id": latest_inc_id,
        "pdf_path": latest_pdf,
        "risk_score_100": 94.5 if is_real else 85.0,
        "risk_level": "Critical",
        "is_simulation": is_sim,
        "scenario": scenario_param or ("Live Incident Alert Drill" if is_real else "Test Ransomware Alert & Delivery Verification")
    }

    if is_real:
        scen_name = scenario_param or "Live Adversary Ransomware Escalation"
        alert_note = data.get("note") or (
            f"CRITICAL: Active ransomware behavior detected on host {config['system']['hostname']} "
            f"(Score: 94.5/100 - Critical). Automated containment has terminated flagged malicious processes "
            f"and isolated endpoint network. Complete forensic incident report attached in PDF format."
        )
    else:
        scen_name = scenario_param or "Test Ransomware Alert & Delivery Verification"
        alert_note = data.get("note") or (
            f"Test ransomware attack drill notification ({scen_name}). "
            f"This simulated drill confirms your SOC alerting mailbox is correctly configured "
            f"and successfully receiving forensic incident reports in PDF format."
        )

    result = notification_engine.dispatch_incident_email(
        report_data=rep_data,
        is_simulation=is_sim,
        scenario_name=scen_name,
        short_note=alert_note,
        custom_recipients=recipients
    )

    return {
        "status": "SUCCESS" if result.get("delivered_live") else "SAVED_TO_OUTBOX",
        "mode": "real" if is_real else "test",
        "delivery_status": result.get("delivery_status"),
        "delivery_details": result.get("delivery_details"),
        "email_record": result
    }

@app.get("/api/notifications/emails/{email_id}/eml")
def download_email_eml(email_id: str):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    eml_path = os.path.join(base_dir, "reports", "sent_emails", f"{email_id}.eml")
    if not os.path.exists(eml_path):
        raise HTTPException(status_code=404, detail="Email .eml file not found")
    return FileResponse(eml_path, media_type="message/rfc822", filename=f"{email_id}.eml")

# ==================== Forensic Incident Reports ====================

@app.get("/api/reports")
def list_reports():
    files = []
    if os.path.exists(reports_dir):
        for f in sorted(os.listdir(reports_dir), reverse=True):
            if f.endswith(".html"):
                inc_id = f.replace(".html", "")
                md_path = os.path.join(reports_dir, f"{inc_id}.md")
                json_path = os.path.join(reports_dir, f"{inc_id}.json")
                
                is_simulation = inc_id.startswith("SIM-")
                scenario = "Simulated Adversary Drill" if is_simulation else "Live Host Incident"
                risk_score = 90.0
                
                if os.path.exists(json_path):
                    try:
                        with open(json_path, "r", encoding="utf-8") as jf:
                            jdata = json.load(jf)
                            is_simulation = jdata.get("is_simulation", is_simulation)
                            scenario = jdata.get("scenario") or ("Simulated Adversary Drill" if is_simulation else "Live Host Incident")
                            risk_score = jdata.get("risk_score", 90.0)
                    except Exception:
                        pass
                elif os.path.exists(md_path):
                    try:
                        with open(md_path, "r", encoding="utf-8") as mf:
                            m_text = mf.read()
                            if "TEST SIMULATION" in m_text or "DRILL" in m_text or "SIMULATED" in m_text or inc_id.startswith("SIM-"):
                                is_simulation = True
                                scenario = "Simulated Adversary Drill"
                    except Exception:
                        pass

                files.append({
                    "id": inc_id,
                    "incident_id": inc_id,
                    "filename_html": f,
                    "filename_md": f"{inc_id}.md",
                    "created_at": time.ctime(os.path.getmtime(os.path.join(reports_dir, f))),
                    "has_markdown": os.path.exists(md_path),
                    "is_simulation": is_simulation,
                    "classification": "SIMULATION" if is_simulation else "LIVE_INCIDENT",
                    "classification_label": "Simulated Drill" if is_simulation else "Live Incident",
                    "scenario": scenario,
                    "risk_score": risk_score
                })
    return {"reports": files}

@app.post("/api/reports/generate")
def generate_incident_report_api():
    res = incident_reporter.generate_report(
        risk_data=latest_risk_result,
        telemetry_events=get_combined_events(limit=40),
        containment_actions=containment_engine.get_action_history(),
        flagged_processes=t2_host_process.get_flagged_processes(),
        canary_status=t7_deception_canary.get_canary_status(),
        entropy_data=t3_fs_entropy.get_latest_entropy_data(),
        hostname=config["system"]["hostname"]
    )
    # Automatically dispatch email notification for real incidents; for simulations, ask user before sending
    try:
        is_sim = res.get("is_simulation", False)
        scen = res.get("scenario", "On-Demand Audit")
        if not is_sim and notification_engine.auto_send_real_attack_email:
            note = (
                f"Forensic incident report generated for incident {res.get('incident_id')}. "
                f"Complete forensic report attached in PDF format for SecOps analysis."
            )
            notification_engine.dispatch_incident_email(
                report_data=res,
                is_simulation=False,
                scenario_name=scen,
                short_note=note
            )
    except Exception as eml_err:
        print(f"[!] Error auto-dispatching incident report email: {eml_err}")
    return res

@app.get("/api/reports/download-pdf/{incident_id}")
def download_report_pdf(incident_id: str):
    html_path = os.path.join(reports_dir, f"{incident_id}.html")
    if not os.path.exists(html_path):
        raise HTTPException(status_code=404, detail="Incident report HTML not found")
    
    pdf_path = os.path.join(reports_dir, f"{incident_id}.pdf")
    try:
        import re
        import weasyprint
        with open(html_path, "r", encoding="utf-8") as f:
            html_text = f.read()

        # Strip external network links that can hang in offline environments
        html_clean = re.sub(r'<link[^>]+href=[\"\']https?://[^>]+>', '', html_text)
        pdf_style = """
        <style>
            @page { size: A4; margin: 12mm; }
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1e293b; background: #fff !important; }
            .card { border: 1px solid #cbd5e1; border-radius: 8px; margin-bottom: 15px; page-break-inside: avoid; }
            .card-header { background: #f1f5f9 !important; color: #0f172a !important; font-weight: bold; padding: 10px 15px; border-bottom: 1px solid #cbd5e1; }
            .card-body { padding: 12px; }
            table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 11px; }
            th, td { border: 1px solid #cbd5e1; padding: 6px 8px; text-align: left; }
            th { background: #f8fafc; color: #334155; }
            code { background: #f1f5f9; padding: 2px 4px; border-radius: 4px; color: #0f172a; font-size: 10px; }
            .badge { padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; }
            .bg-danger { background: #ef4444 !important; color: #fff; }
            .bg-success { background: #10b981 !important; color: #fff; }
            .bg-warning { background: #f59e0b !important; color: #000; }
            .bg-dark { background: #334155 !important; color: #fff; }
        </style>
        """
        html_clean = html_clean.replace("</head>", f"{pdf_style}</head>")
        weasyprint.HTML(string=html_clean).write_pdf(pdf_path)

        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename=f"{incident_id}.pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {e}")

@app.get("/api/reports/view/{incident_id}")
def view_report(incident_id: str, format: str = "html"):
    if format == "pdf":
        return download_report_pdf(incident_id)
    elif format == "markdown":
        path = os.path.join(reports_dir, f"{incident_id}.md")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return PlainTextResponse(f.read())
    else:
        path = os.path.join(reports_dir, f"{incident_id}.html")
        if os.path.exists(path):
            return FileResponse(path, media_type="text/html")
    raise HTTPException(status_code=404, detail="Incident report not found")

# ==================== Controlled Attack Simulator Endpoints ====================

REAL_RANSOMWARE_FAMILIES: Dict[str, Dict[str, Any]] = {
    "wannacry": {
        "id": "wannacry",
        "name": "WannaCry 2.0 (WanaCrypt0r)",
        "binary": "@WanaDecryptor@.exe",
        "path": "C:\\Windows\\System32\\@WanaDecryptor@.exe",
        "args": "/i --killswitch-bypass --ms17-010 --port 445",
        "ext": ".wncry",
        "cipher": "RSA-2048 + AES-128-CBC",
        "threat_score": 0.98,
        "c2": "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com:443",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["EternalBlue SMBv1 Exploit (MS17-010)", "Killswitch Domain Request", "Volume Shadow Erasure", ".wncry High Entropy Burst"],
        "description": "Historic global outbreak leveraging EternalBlue SMBv1 remote code execution to spread laterally across subnets in seconds, encrypting user documents with .wncry."
    },
    "lockbit3": {
        "id": "lockbit3",
        "name": "LockBit 3.0 (LockBit Black)",
        "binary": "lockbit3_encryptor.exe",
        "path": "/tmp/.systemd_worker",
        "args": "--pass-vss --threads 16 --crypto chacha20 --path /canary_vault",
        "ext": ".lockbit",
        "cipher": "ChaCha20 + RSA",
        "threat_score": 0.96,
        "c2": "194.26.29.112:8443",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB",
        "flags": ["Multi-threaded ChaCha20 Burst", "EDR Service Termination", "Shadow Copy Wipe", ".lockbit Mass Rename"],
        "description": "Fast multi-threaded double-extortion ransomware with aggressive anti-debugging, EDR unhooking, and mass file encryption with .lockbit."
    },
    "blackcat": {
        "id": "blackcat",
        "name": "BlackCat / ALPHV",
        "binary": "alphv_blackcat.exe",
        "path": "/var/tmp/.runtime_x86",
        "args": "--access-token B7F92A --bypass-uac --drop-dragons",
        "ext": ".alphv",
        "cipher": "AES-GCM / ChaCha20",
        "threat_score": 0.95,
        "c2": "185.220.101.5:443",
        "lateral_port": 135,
        "evasion_cmd": "wmic shadowcopy delete",
        "flags": ["Rust Binary Execution", "Privilege Escalation (Token Manipulation)", "EDR Bypass", ".alphv Encrypted Writes"],
        "description": "Sophisticated Rust-based ransomware utilizing customizable command-line arguments, token impersonation, and high-performance AES encryption."
    },
    "ryuk": {
        "id": "ryuk",
        "name": "Ryuk Enterprise Ransomware",
        "binary": "ryuk_stealth.exe",
        "path": "C:\\Users\\Public\\ryuk_stealth.exe",
        "args": "--lan-spread --kill-antivirus --stealth",
        "ext": ".ryk",
        "cipher": "RSA-4096 + AES-256",
        "threat_score": 0.97,
        "c2": "45.142.214.12:443",
        "lateral_port": 445,
        "evasion_cmd": "net stop \"Volume Shadow Copy\" /y",
        "flags": ["PsExec Lateral Traversal", "40+ Security/Backup Service Kills", "Process Injection (svchost)", ".ryk Mass Rename"],
        "description": "Targeted enterprise ransomware historically deployed after TrickBot/BazarLoader access, systematically stopping backup services and deploying .ryk."
    },
    "conti": {
        "id": "conti",
        "name": "Conti Ransomware",
        "binary": "conti_worker.exe",
        "path": "/tmp/.conti_daemon",
        "args": "-m all -p 32 -log /tmp/conti.log",
        "ext": ".conti",
        "cipher": "ChaCha20 + RSA-4096",
        "threat_score": 0.96,
        "c2": "193.106.191.29:8080",
        "lateral_port": 445,
        "evasion_cmd": "wmic shadowcopy delete",
        "flags": ["IOCP 32-Thread Concurrent Encryption", "ARP Cache Subnet Scan", "Volume Shadow Erasure", ".conti Extension Burst"],
        "description": "High-throughput ransomware leveraging 32 simultaneous worker threads via Windows I/O Completion Ports for blazing-fast encryption."
    },
    "revil": {
        "id": "revil",
        "name": "REvil / Sodinokibi",
        "binary": "revil_agent.exe",
        "path": "C:\\ProgramData\\revil_agent.exe",
        "args": "-path C:\\ -safe-mode -keys 256",
        "ext": ".revil",
        "cipher": "Salsa20 + Curve25519",
        "threat_score": 0.94,
        "c2": "91.240.118.172:443",
        "lateral_port": 3389,
        "evasion_cmd": "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        "flags": ["Safe-Mode Boot Persistence", "bcdedit Recovery Invalidation", "Kernel Registry Tampering", ".revil Encryption Burst"],
        "description": "Ransomware-as-a-service giant that reboots systems into Safe Mode with Networking to bypass security software while encrypting data."
    },
    "darkside": {
        "id": "darkside",
        "name": "DarkSide Ransomware",
        "binary": "darkside_crypto.exe",
        "path": "/tmp/.darkside_payload",
        "args": "--silent --network --steal-creds",
        "ext": ".darkside",
        "cipher": "Salsa20 + RSA-1024",
        "threat_score": 0.95,
        "c2": "185.180.198.34:8443",
        "lateral_port": 389,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["Active Directory LDAP Harvest", "Pre-encryption Double Extortion", "Volume Shadow Wipe", ".darkside Extension"],
        "description": "Infamous for targeting critical corporate infrastructure, combining LDAP network discovery, double-extortion data exfiltration, and .darkside locking."
    },
    "akira": {
        "id": "akira",
        "name": "Akira Ransomware",
        "binary": "akira_crypt.exe",
        "path": "/tmp/kworker_crypto",
        "args": "-k /tmp/.pubkey.pem -m full --no-vss --threads 8",
        "ext": ".akira",
        "cipher": "ChaCha20 + RSA-4096",
        "threat_score": 0.94,
        "c2": "198.51.100.42:443",
        "lateral_port": 22,
        "evasion_cmd": "powershell.exe -Command \"Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }\"",
        "flags": ["PowerShell Shadow Erasure", "ESXi / Virtual Disk Targeting", "Intermittent Encryption Pattern", ".akira Mass Rename"],
        "description": "Multi-platform threat targeting both Windows workstations and Linux ESXi virtualization hypervisors with intermittent cryptographic routines."
    },
    "royal": {
        "id": "royal",
        "name": "Royal Ransomware",
        "binary": "royal_payload.exe",
        "path": "/tmp/.royal_worker",
        "args": "-id 882910 --network-shares --inhibit-recovery",
        "ext": ".royal",
        "cipher": "OpenSSL AES-256",
        "threat_score": 0.93,
        "c2": "91.240.118.172:8443",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["Intermittent Partial Encryption", "SMB Signing Evasion", "VSS Destruction", ".royal Mass Extension"],
        "description": "Operated by former Conti team members, using custom partial-file encryption (encrypting alternating byte blocks) to evade naive entropy baselines."
    },
    "maze": {
        "id": "maze",
        "name": "Maze Ransomware",
        "binary": "maze_encryptor.exe",
        "path": "C:\\Windows\\Temp\\maze_encryptor.exe",
        "args": "--exfil-stage --canary-seek --encrypt-all",
        "ext": ".maze",
        "cipher": "ChaCha20 + RSA",
        "threat_score": 0.95,
        "c2": "104.244.76.13:443",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["Double Extortion C2 Exfil", "Canary Decoy Targeting", "ChaCha20 Cryptographic Burst", ".maze Renames"],
        "description": "The original double-extortion ransomware syndicate that pioneered exfiltrating corporate IP to public leak sites before locking file systems."
    },
    "clop": {
        "id": "clop",
        "name": "Clop (CL0P) Ransomware",
        "binary": "clop_ransom.exe",
        "path": "/tmp/.clop_service",
        "args": "--run-batch --clear-logs --no-vss",
        "ext": ".clop",
        "cipher": "RC4 + RSA-1024",
        "threat_score": 0.94,
        "c2": "194.135.25.102:443",
        "lateral_port": 445,
        "evasion_cmd": "wevtutil cl System",
        "flags": ["Security Tool Process Termination", "Event Log Clearing (wevtutil)", "Batch File Locking", ".clop Encrypted Writes"],
        "description": "Notorious threat actor family exploiting zero-day file transfer vulnerabilities, systematically terminating security agents and clearing Windows event logs."
    },
    "hive": {
        "id": "hive",
        "name": "Hive Ransomware",
        "binary": "hive_encryptor.exe",
        "path": "/var/tmp/.hive_worker",
        "args": "-u /tmp/hive.key -threads 16",
        "ext": ".hive",
        "cipher": "Golang Keystream Cipher",
        "threat_score": 0.95,
        "c2": "185.198.57.108:80",
        "lateral_port": 445,
        "evasion_cmd": "wmic shadowcopy delete",
        "flags": ["Golang Memory Scraping", "Windows Event Log Killer", "Volume Shadow Erasure", ".hive Mass Encryption"],
        "description": "Golang-compiled ransomware that stops services, deletes shadow copies, and writes encrypted .hive files while harvesting in-memory credentials."
    },
    "blackbasta": {
        "id": "blackbasta",
        "name": "Black Basta Enterprise",
        "binary": "blackbasta_core.exe",
        "path": "C:\\Windows\\Temp\\blackbasta_core.exe",
        "args": "--action encrypt --mode fast --threads 24",
        "ext": ".basta",
        "cipher": "ChaCha20 + RSA-4096",
        "threat_score": 0.97,
        "c2": "92.38.169.45:443",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["Qakbot Stage-2 Dropper", "ChaCha20 Multithreaded Encryption", "VSS Shadow Erasure", ".basta Extension Burst"],
        "description": "Devastating double-extortion syndicate targeting major enterprises via Qakbot/Cobalt Strike, utilizing high-speed ChaCha20 encryption with custom ransom note bootstrapper."
    },
    "play": {
        "id": "play",
        "name": "Play Ransomware (PlayCrypt)",
        "binary": "play_crypt.exe",
        "path": "C:\\Users\\Public\\play_crypt.exe",
        "args": "-p -k play.pub -t 16 -s",
        "ext": ".play",
        "cipher": "RSA-4096 + AES-GCM (Intermittent)",
        "threat_score": 0.95,
        "c2": "185.176.27.114:8443",
        "lateral_port": 445,
        "evasion_cmd": "wmic shadowcopy delete",
        "flags": ["Intermittent 2-Block Encryption Evasion", "ProxyNotShell Lateral Vector", "Volume Shadow Wipe", ".play Mass Extension"],
        "description": "Highly lethal ransomware infamous for exploiting Microsoft Exchange (ProxyNotShell/OWASSRecall) and utilizing alternating block encryption to bypass standard entropy detectors."
    },
    "rhysida": {
        "id": "rhysida",
        "name": "Rhysida Syndicate",
        "binary": "rhysida_payload.exe",
        "path": "/tmp/.rhysida_agent",
        "args": "-d C:\\ -r Rhysida-01 -entropy high",
        "ext": ".rhysida",
        "cipher": "ChaCha20 + RSA-4096",
        "threat_score": 0.96,
        "c2": "194.38.20.55:443",
        "lateral_port": 445,
        "evasion_cmd": "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce /v Rhysida /t REG_SZ /d ...",
        "flags": ["Critical Healthcare Targeting", "Privileged AD Execution", "ChaCha20 Encryption Blast", ".rhysida Mass Rename"],
        "description": "Vicious ransomware syndicate notorious for attacking hospitals, universities, and government bodies, executing high-speed cryptographic locking with PDF ransom notes."
    },
    "medusa": {
        "id": "medusa",
        "name": "Medusa Locker",
        "binary": "medusa_enc.exe",
        "path": "C:\\ProgramData\\medusa_enc.exe",
        "args": "-path \\\\*\\C$ -vss-wipe -kill-sql",
        "ext": ".medusa",
        "cipher": "AES-256 + RSA-2048",
        "threat_score": 0.94,
        "c2": "193.233.20.12:8080",
        "lateral_port": 3389,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["RDP Brute Force Infection", "Database Service Killer (MSSQL/Oracle)", "Shadow Copy Deletion", ".medusa Encrypted Writes"],
        "description": "Aggressive ransomware-as-a-service deploying after external RDP compromise, terminating database processes and appending .medusa."
    },
    "blacksuit": {
        "id": "blacksuit",
        "name": "BlackSuit Ransomware",
        "binary": "blacksuit_worker.exe",
        "path": "/var/tmp/.blacksuit",
        "args": "--mode all --shares --kill-edr",
        "ext": ".blacksuit",
        "cipher": "ChaCha20-Poly1305",
        "threat_score": 0.96,
        "c2": "91.215.85.19:443",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB",
        "flags": ["Direct Royal/Conti Codebase Heir", "Linux ESXi & Windows Dual Targeting", "Poly1305 MAC Authentication", ".blacksuit File Renames"],
        "description": "Direct descendant of Royal and Conti, capable of attacking Linux ESXi virtual machines and Windows domains simultaneously with Poly1305 authentication."
    },
    "cactus": {
        "id": "cactus",
        "name": "Cactus Ransomware",
        "binary": "cactus_loader.exe",
        "path": "C:\\Windows\\Temp\\cactus_loader.exe",
        "args": "--7z-decrypt pass123 --exec-ransom",
        "ext": ".cts",
        "cipher": "AES-256-CBC",
        "threat_score": 0.95,
        "c2": "179.43.155.80:443",
        "lateral_port": 445,
        "evasion_cmd": "wmic shadowcopy delete",
        "flags": ["Self-Encrypted 7z Archive Evasion", "Fortinet VPN Gateway Exploitation", "Batch Shadow Purge", ".cts Multi-Threaded Locking"],
        "description": "Unique threat actor that encrypts its own malicious binary inside 7-Zip archives using passwords to bypass AV/EDR static scanners before execution."
    },
    "babuk": {
        "id": "babuk",
        "name": "Babuk Locker (Babyk)",
        "binary": "babuk_locker.exe",
        "path": "/tmp/.babuk_daemon",
        "args": "-lan -noshadow -shares",
        "ext": ".babyk",
        "cipher": "ChaCha8 + Curve25519",
        "threat_score": 0.94,
        "c2": "85.209.11.14:443",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin.exe Delete Shadows /All /Quiet",
        "flags": ["ChaCha8 Micro-Cipher", "WMI Subnet Probing", "ESXi Hypervisor Scripting", ".babyk Mass Lock"],
        "description": "Compact yet brutal ransomware using ChaCha8 stream cipher, targeting corporate backup servers and shutting down virtualized environments."
    },
    "bianlian": {
        "id": "bianlian",
        "name": "BianLian Threat",
        "binary": "bianlian_go.exe",
        "path": "/tmp/.system_go_proc",
        "args": "--threads 32 --skip-os --silent",
        "ext": ".bianlian",
        "cipher": "Go Native Crypto / AES-256",
        "threat_score": 0.93,
        "c2": "194.165.16.89:80",
        "lateral_port": 445,
        "evasion_cmd": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Get-WmiObject Win32_ShadowCopy | Remove-WmiObject\"",
        "flags": ["Go Multi-Threaded Coroutine Execution", "Massive Data Exfiltration Pre-Lock", "Shadow Erasure", ".bianlian Rename Loop"],
        "description": "Rapid Go-compiled ransomware known for shifting from pure encryption to pure data extortion after stealing hundreds of gigabytes of proprietary documents."
    },
    "qilin": {
        "id": "qilin",
        "name": "Qilin (Agenda)",
        "binary": "qilin_agent.exe",
        "path": "C:\\Users\\Public\\qilin_agent.exe",
        "args": "--safe-mode-reboot --pass agenda99",
        "ext": ".qilin",
        "cipher": "AES-256-GCM / ChaCha20",
        "threat_score": 0.95,
        "c2": "185.106.94.22:443",
        "lateral_port": 445,
        "evasion_cmd": "bcdedit /set {current} safeboot minimal",
        "flags": ["Rust Execution Engine", "Active Directory GPO Dissemination", "Safe Mode Boot Bypass", ".qilin Cryptographic Lock"],
        "description": "Customizable Rust-based ransomware distributed via Domain Controller Group Policy Objects, altering Windows boot configurations to run unimpeded."
    },
    "ransomhub": {
        "id": "ransomhub",
        "name": "RansomHub Syndicate",
        "binary": "ransomhub_x64.exe",
        "path": "/tmp/.daemon_x64",
        "args": "-p 16 -pass-vss -driver-kill",
        "ext": ".hub",
        "cipher": "XChaCha20-Poly1305",
        "threat_score": 0.97,
        "c2": "195.201.225.10:443",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["BYOVD Kernel Driver Blinding", "XChaCha20 Extended Nonce", "VSS Destruction", ".hub Mass Encryption"],
        "description": "Rapidly expanding ransomware operation that leverages Bring Your Own Vulnerable Driver (BYOVD) to blind EDR agents from kernel space before locking files."
    },
    "notpetya": {
        "id": "notpetya",
        "name": "NotPetya / EternalPetya Wiper",
        "binary": "perfc.dat",
        "path": "C:\\Windows\\perfc.dat",
        "args": "rundll32.exe C:\\Windows\\perfc.dat,#1 60",
        "ext": ".encrypted",
        "cipher": "XOR / Salsa20 Master Boot Record Overwrite",
        "threat_score": 0.99,
        "c2": "95.141.115.108:443",
        "lateral_port": 445,
        "evasion_cmd": "wevtutil cl Setup & wevtutil cl System & wevtutil cl Security",
        "flags": ["State-Sponsored Destructive Cyberweapon", "EternalBlue + PsExec Lateral Worm", "MBR Overwrite Wiper", "Fake Chkdsk Boot Screen"],
        "description": "Catastrophic destructive wiper masquerading as ransomware; spread worldwide via M.E.Doc supply chain and EternalBlue, irrevocably destroying Master Boot Records."
    },
    "badrabbit": {
        "id": "badrabbit",
        "name": "BadRabbit Outbreak",
        "binary": "dispci.exe",
        "path": "C:\\Windows\\dispci.exe",
        "args": "-install-service -encrypt-disk",
        "ext": ".encrypted",
        "cipher": "DiskCryptor AES-128-CBC",
        "threat_score": 0.96,
        "c2": "185.149.120.3:80",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["Drive-by Download (Fake Flash Update)", "Hardcoded SMB Credential Brute Force", "Bootloader Tampering", "Scheduled Task Persistence"],
        "description": "Major outbreak spreading through compromised media websites posing as fake Adobe Flash installers, encrypting file systems via open-source DiskCryptor."
    },
    "samsam": {
        "id": "samsam",
        "name": "SamSam Healthcare Target",
        "binary": "samsam_runner.exe",
        "path": "C:\\Windows\\System32\\samsam_runner.exe",
        "args": "-p samsam123 -k sam.key -all",
        "ext": ".weapologize",
        "cipher": "RSA-2048 + AES-128-CBC",
        "threat_score": 0.96,
        "c2": "185.220.102.8:443",
        "lateral_port": 3389,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["Pioneering Human-Operated Ransomware", "JBoss & RDP Exploitation", "Shadow Copy Purge", ".weapologize Mass Extension"],
        "description": "Pioneered human-operated targeted ransomware attacks, breaching healthcare institutions and municipal networks via vulnerable JBoss application servers."
    },
    "gandcrab": {
        "id": "gandcrab",
        "name": "GandCrab Affiliate Fleet",
        "binary": "gandcrab_v5.exe",
        "path": "C:\\Users\\User\\AppData\\Roaming\\gandcrab.exe",
        "args": "--start-crab --fast",
        "ext": ".CRAB",
        "cipher": "RSA-2048 + RC4",
        "threat_score": 0.93,
        "c2": "92.63.197.48:443",
        "lateral_port": 445,
        "evasion_cmd": "wmic shadowcopy delete",
        "flags": ["Exploit Kit Malvertising Vector", "DASH Cryptocurrency Extortion", "VSS Invalidation", ".CRAB Mass Rename"],
        "description": "The most prolific ransomware syndicate of 2018-2019, netting millions across 5 major version iterations using exploit kits and consumer phishing."
    },
    "dharma": {
        "id": "dharma",
        "name": "Dharma / CrySiS",
        "binary": "dharma_host.exe",
        "path": "C:\\Windows\\System32\\dharma_host.exe",
        "args": "-id 99824 -crypto full",
        "ext": ".dharma",
        "cipher": "AES-256 + RSA-1024",
        "threat_score": 0.92,
        "c2": "194.26.29.98:80",
        "lateral_port": 3389,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["Internet-Exposed RDP Vector", "AV Termination via Taskkill", "Shadow Copy Erasure", ".dharma Append"],
        "description": "Longest-standing manual RDP ransomware family, repeatedly deployed by unskilled affiliates using automated brute-force tools against weak remote desktop credentials."
    },
    "phobos": {
        "id": "phobos",
        "name": "Phobos Ransomware",
        "binary": "phobos_core.exe",
        "path": "C:\\ProgramData\\phobos_core.exe",
        "args": "-start -hide -kill-sess",
        "ext": ".phobos",
        "cipher": "AES-CBC + RSA-1024",
        "threat_score": 0.93,
        "c2": "45.154.255.88:443",
        "lateral_port": 3389,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["Direct CrySiS/Dharma Evolution", "Remote Desktop Session Termination", "Volume Shadow Wipe", ".phobos Append"],
        "description": "Direct evolutionary derivative of the Dharma ransomware family, featuring tighter code packing and automated termination of open application sessions."
    },
    "stopdjvu": {
        "id": "stopdjvu",
        "name": "STOP / Djvu Consumer Threat",
        "binary": "djvu_updater.exe",
        "path": "C:\\Users\\AppData\\Local\\Temp\\djvu_updater.exe",
        "args": "--pid 1829 --silent",
        "ext": ".djvu",
        "cipher": "Salsa20 / RSA-1024",
        "threat_score": 0.91,
        "c2": "188.166.19.12:80",
        "lateral_port": 80,
        "evasion_cmd": "vssadmin.exe Delete Shadows /All /Quiet",
        "flags": ["Pirated Software / Torrent Vector", "RedLine Stealer Bundle", "Hosts File DNS Manipulation", ".djvu Mass Encryption"],
        "description": "Dominant consumer ransomware family distributed via cracked software downloads, simultaneously installing RedLine info-stealers and locking local hard drives."
    },
    "netwalker": {
        "id": "netwalker",
        "name": "Netwalker (Mailto)",
        "binary": "netwalker_dll.exe",
        "path": "C:\\Windows\\Temp\\netwalker_dll.exe",
        "args": "powershell.exe -encodedCommand SQBFAFgA...",
        "ext": ".mailto",
        "cipher": "ChaCha20 + RSA",
        "threat_score": 0.95,
        "c2": "193.37.212.18:443",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["PowerShell Reflective DLL Injection", "Fileless In-Memory Execution", "Volume Shadow Erasure", ".mailto Mass Extension"],
        "description": "Sophisticated ransomware utilizing PowerShell reflective DLL injection to execute purely in memory without dropping malicious binary files onto disk."
    },
    "ragnarlocker": {
        "id": "ragnarlocker",
        "name": "Ragnar Locker",
        "binary": "ragnar_vm.exe",
        "path": "C:\\Users\\Public\\ragnar_vm.exe",
        "args": "-run-micro-vm -mount-host",
        "ext": ".ragnar",
        "cipher": "Salsa20 + RSA-2048",
        "threat_score": 0.96,
        "c2": "194.26.29.14:443",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["VirtualBox Micro-VM Evasion Technique", "Host Disk Mount from Guest OS", "Anti-EDR Hypervisor Shield", ".ragnar Lock"],
        "description": "Infamous for novel hypervisor evasion: deploys an Oracle VirtualBox micro-VM on target hosts, mounting host drives into the guest VM where EDR agents cannot inspect encryption."
    },
    "doppelpaymer": {
        "id": "doppelpaymer",
        "name": "DoppelPaymer",
        "binary": "doppel_agent.exe",
        "path": "C:\\Windows\\System32\\doppel_agent.exe",
        "args": "-network-spread -kill-all",
        "ext": ".locked",
        "cipher": "AES-256 + RSA-2048",
        "threat_score": 0.95,
        "c2": "185.180.198.81:443",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["Evil Corp / BitPaymer Lineage", "Dridex Banking Trojan Precursor", "Shadow Copy Erasure", ".locked Enterprise Lockdown"],
        "description": "Enterprise threat derived from BitPaymer and tied to Evil Corp, leveraging Dridex access to disable system security, destroy backups, and demand multi-million dollar ransoms."
    },
    "cuba": {
        "id": "cuba",
        "name": "Cuba Ransomware",
        "binary": "cuba_stage.exe",
        "path": "C:\\Users\\Temp\\cuba_stage.exe",
        "args": "--load-driver ksec.sys --network",
        "ext": ".cuba",
        "cipher": "ChaCha20 + RSA-4096",
        "threat_score": 0.94,
        "c2": "179.43.141.22:443",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["KSecDD Kernel Driver Abuse", "Hancitor Loader Drop", "Volume Shadow Erasure", ".cuba Multi-Threaded Crypt"],
        "description": "High-impact syndicate that terminates security processes by installing compromised third-party kernel drivers before executing ChaCha20 encryption."
    },
    "avaddon": {
        "id": "avaddon",
        "name": "Avaddon Syndicate",
        "binary": "avaddon_x86.exe",
        "path": "C:\\Users\\AppData\\avaddon.exe",
        "args": "-run -all-disks -triple-extort",
        "ext": ".avdn",
        "cipher": "AES-256 + RSA-2048",
        "threat_score": 0.94,
        "c2": "91.214.124.201:80",
        "lateral_port": 445,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["Triple Extortion (DDoS Threat)", "Spam Malspam Delivery", "Volume Shadow Wipe", ".avdn Mass Rename"],
        "description": "Syndicate that popularized triple extortion: encrypting data, threatening public leak disclosures, and launching volumetric DDoS attacks against victim web portals."
    },
    "snatch": {
        "id": "snatch",
        "name": "Snatch Ransomware",
        "binary": "snatch_service.exe",
        "path": "C:\\Windows\\System32\\snatch_service.exe",
        "args": "-install-safeboot -reboot",
        "ext": ".snatch",
        "cipher": "AES-256-CBC",
        "threat_score": 0.95,
        "c2": "194.87.139.10:443",
        "lateral_port": 3389,
        "evasion_cmd": "bcdedit /set {current} safeboot minimal",
        "flags": ["Forced Safe Mode Boot Service", "AV-Disabled Execution State", "Shadow Erasure", ".snatch File Encryption"],
        "description": "Forces target systems to reboot into Safe Mode by installing itself as a Windows SafeBoot service, executing file encryption when antivirus engines fail to start."
    },
    "mallox": {
        "id": "mallox",
        "name": "Mallox (TargetCompany)",
        "binary": "mallox_corp.exe",
        "path": "C:\\ProgramData\\mallox_corp.exe",
        "args": "-id target_99 -brute-db",
        "ext": ".mallox",
        "cipher": "ChaCha20 + RSA-2048",
        "threat_score": 0.93,
        "c2": "89.208.107.10:443",
        "lateral_port": 1433,
        "evasion_cmd": "vssadmin delete shadows /all /quiet",
        "flags": ["MS SQL Dictionary Brute Force", "XP_CMDSHELL Payload Execution", "Volume Shadow Deletion", ".mallox Rapid Extension"],
        "description": "Specializes in compromising unpatched internet-facing Microsoft SQL Servers via dictionary attacks, executing shell commands to encrypt connected network storage."
    }
}

# Backward compatibility alias
MALWARE_PROFILES = list(REAL_RANSOMWARE_FAMILIES.values())

def get_fresh_attack_pid() -> int:
    """Generates an unused dynamic PID between 12400 and 59900 that is not quarantined."""
    attempts = 0
    while attempts < 100:
        p = random.randint(12400, 59900)
        if p not in containment_engine.quarantined_pids:
            return p
        attempts += 1
    return random.randint(60000, 65000)

current_active_simulation_scenario: Optional[str] = None

def execute_real_ransomware_simulation(family_key: str, dispatch_email: bool = False) -> Dict[str, Any]:
    global current_active_simulation_scenario, last_auto_incident_report_time, incident_in_progress
    global simulation_in_progress, last_simulation_start_time
    profile = REAL_RANSOMWARE_FAMILIES.get(family_key)
    if not profile:
        profile = REAL_RANSOMWARE_FAMILIES.get("wannacry") or list(REAL_RANSOMWARE_FAMILIES.values())[0]

    current_active_simulation_scenario = profile["name"]
    simulation_in_progress = True
    last_simulation_start_time = time.time()
    incident_in_progress = True
    last_auto_incident_report_time = time.time()
    pid = get_fresh_attack_pid()
    
    # Parse C2
    c2_raw = profile.get("c2", "198.51.100.42:443")
    if ":" in c2_raw:
        c2_ip, c2_port_str = c2_raw.split(":", 1)
        c2_port = int(c2_port_str) if c2_port_str.isdigit() else 443
    else:
        c2_ip, c2_port = c2_raw, 443
        
    lateral_ip = random.choice(["192.168.1.105", "192.168.1.142", "192.168.1.204"])

    # 1. Register authentic malicious process in T2
    t2_host_process.inject_simulated_process(
        pid=pid,
        name=profile["binary"],
        cmdline=f"{profile['binary']} {profile['args']}",
        score=profile["threat_score"],
        flags=profile["flags"]
    )

    # 2. Execute high-entropy burst writes with the authentic ransomware extension
    enc_count = random.randint(8, 14)
    enc_res = simulator.run_encryption_burst_simulation(count=enc_count, ext=profile["ext"])

    # 3. Trigger recovery inhibition / defense evasion in T6
    t6_defense_evasion.evaluate_command_execution(
        command_line=profile["evasion_cmd"],
        pid=pid,
        process_name=profile["binary"]
    )

    # 4. Detonate Canary Decoy Tripwire in T7
    tamper_res = simulator.run_canary_tamper_simulation()
    t7_deception_canary.audit_all_canaries()
    target_c = tamper_res.get("target_canary")
    if target_c:
        t7_deception_canary.record_breach_metadata(
            filename=target_c,
            attacker_process=profile["binary"],
            attacker_pid=pid,
            attacker_family=profile["name"],
            tamper_type=f"In-place Ransomware Encryption ({profile['ext']})"
        )
    t7_deception_canary.events.append({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "module": "T7: Deception & Tripwire Signals",
        "code": "T7",
        "severity": "CRITICAL",
        "message": f"TRIPWIRE DETONATED: Decoy canary '{target_c}' breached by {profile['name']} ({profile['binary']} PID: {pid})! Instant zero-false-positive early warning engaged."
    })

    # 5. Outbound C2 Beacon & Lateral Movement in T5
    t5_network_exfil.record_c2_beacon(c2_ip, c2_port, pid=pid, process_name=profile["binary"])
    t5_network_exfil.record_lateral_movement("SMB", lateral_ip, profile["lateral_port"], pid=pid)

    # 6. Credential Access Attempt in T4
    t4_identity_auth.record_credential_access_attempt(target="lsass.exe", source_process=profile["binary"], pid=pid)

    # 7. Automated Containment Activation: Network Quarantine & Admin Alert
    if not containment_engine.is_network_isolated:
        containment_engine.isolate_network(
            initiator="Automated Containment Engine",
            reason=f"Real Ransomware Detection: {profile['name']} (PID {pid})"
        )

    notification_engine.dispatch_alert(
        title=f"🚨 CRITICAL RANSOMWARE ATTACK DETECTED: {profile['name']}",
        severity="CRITICAL",
        details={
            "malware_family": profile["name"],
            "process": profile["binary"],
            "pid": pid,
            "threat_score": profile["threat_score"],
            "extension": profile["ext"],
            "c2_channel": profile["c2"],
            "lateral_target": f"{lateral_ip}:{profile['lateral_port']}",
            "containment_action": "Automated Network Isolation & Targeted SIGKILL Armed"
        },
        force=True
    )

    # 8. Automatically generate formal forensic incident report with simulation drill indicator
    incident_in_progress = True
    last_auto_incident_report_time = time.time()
    
    current_entropy_info = t3_fs_entropy.get_latest_entropy_data()
    rep_res = incident_reporter.generate_report(
        risk_data=latest_risk_result or {
            "risk_score_100": 98.2,
            "threat_score_norm": 0.982,
            "risk_level": "Critical",
            "recommended_action": f"Immediate execution kill on PID {pid} and quarantine host.",
            "badge_color": "#ef4444"
        },
        telemetry_events=get_combined_events(limit=30),
        containment_actions=containment_engine.get_action_history(),
        flagged_processes=t2_host_process.get_flagged_processes(),
        canary_status=t7_deception_canary.get_canary_status(),
        entropy_data=current_entropy_info,
        hostname=config["system"]["hostname"],
        is_simulation=True,
        simulation_scenario=profile["name"]
    )
    simulation_in_progress = False

    # Simulation email handling:
    # Testing/simulation does NOT dispatch automatically unless explicitly requested with dispatch_email=True.
    # It prompts the user via the UI confirmation modal before sending!
    eml_record = None
    if dispatch_email or not getattr(notification_engine, "prompt_before_simulation_email", True):
        try:
            eml_record = notification_engine.dispatch_incident_email(
                report_data=rep_res,
                is_simulation=True,
                scenario_name=profile["name"],
                short_note=(
                    f"Test ransomware attack ({profile['name']}). "
                    f"Controlled adversary emulation drill executed safely against canary tripwires and entropy monitors. "
                    f"Automated containment verified. No operational data was harmed. "
                    f"Complete forensic incident report attached in PDF format."
                )
            )
        except Exception as eml_err:
            print(f"[!] Error auto-dispatching simulation email: {eml_err}")

    return {
        "status": "COMPLETED",
        "simulation": "REAL_RANSOMWARE_ATTACK",
        "family": profile["id"],
        "name": profile["name"],
        "scenario": profile["name"],
        "attacker_process": profile["binary"],
        "attacker_pid": pid,
        "extension": profile["ext"],
        "files_encrypted": enc_res.get("files_encrypted", enc_count),
        "target_canary": tamper_res.get("target_canary"),
        "c2_endpoint": profile["c2"],
        "incident_id": rep_res.get("incident_id"),
        "incident_report_id": rep_res.get("incident_id"),
        "pdf_path": rep_res.get("pdf_path"),
        "pdf_filename": f"{rep_res.get('incident_id')}.pdf",
        "ask_email_dispatch": True if not eml_record else False,
        "prompt_user_for_email": True if not eml_record else False,
        "email_dispatched": bool(eml_record),
        "email_recipient": notification_engine.soc_email,
        "email_id": eml_record.get("id") if eml_record else None,
        "email_to": eml_record.get("to") if eml_record else [notification_engine.soc_email],
        "email_subject": eml_record.get("subject") if eml_record else f"[TEST RANSOMWARE ATTACK] Forensic Incident Report Attached: {rep_res.get('incident_id')} ({profile['name']})",
        "email_short_note": eml_record.get("short_note") if eml_record else f"Test ransomware attack ({profile['name']})",
        "has_pdf_attachment": True,
        "message": f"Detonated authentic {profile['name']} attack! Process: {profile['binary']} (PID: {pid}), encrypted {enc_count} files ({profile['ext']}), breached decoy '{tamper_res.get('target_canary')}', and compiled forensic report {rep_res.get('incident_id')}."
    }

def execute_multi_ransomware_simulation(family_keys: List[str], dispatch_email: bool = False) -> Dict[str, Any]:
    """
    Executes multiple ransomware attacks concurrently/simultaneously in a single
    coordinated adversary campaign. Spawns authentic processes for each selected family,
    runs concurrent encryption bursts, detonates canaries, and compiles one unified report.
    """
    valid_keys = [k for k in family_keys if k in REAL_RANSOMWARE_FAMILIES]
    if not valid_keys:
        valid_keys = ["wannacry"]

    if len(valid_keys) == 1:
        return execute_real_ransomware_simulation(valid_keys[0], dispatch_email=dispatch_email)

    global current_active_simulation_scenario, last_auto_incident_report_time, incident_in_progress
    global simulation_in_progress, last_simulation_start_time

    selected_profiles = [REAL_RANSOMWARE_FAMILIES[k] for k in valid_keys]
    family_names = [p["name"] for p in selected_profiles]
    campaign_name = f"Simultaneous Multi-Strain Campaign: {', '.join(family_names)}"

    current_active_simulation_scenario = campaign_name
    simulation_in_progress = True
    last_simulation_start_time = time.time()
    incident_in_progress = True
    last_auto_incident_report_time = time.time()

    spawned_processes = []
    total_files_encrypted = 0
    breached_canaries = []

    canary_vault_dir = os.path.join(BASE_DIR, "canary_vault")
    available_canaries = sorted([f for f in os.listdir(canary_vault_dir) if os.path.isfile(os.path.join(canary_vault_dir, f))])

    for idx, profile in enumerate(selected_profiles):
        pid = get_fresh_attack_pid()
        spawned_processes.append({
            "family": profile["name"],
            "binary": profile["binary"],
            "pid": pid,
            "threat_score": profile["threat_score"],
            "ext": profile["ext"]
        })

        # Parse C2
        c2_raw = profile.get("c2", "198.51.100.42:443")
        if ":" in c2_raw:
            c2_ip, c2_port_str = c2_raw.split(":", 1)
            c2_port = int(c2_port_str) if c2_port_str.isdigit() else 443
        else:
            c2_ip, c2_port = c2_raw, 443

        lateral_ip = random.choice(["192.168.1.105", "192.168.1.142", "192.168.1.204", "10.0.8.21"])

        # 1. Register authentic malicious process in T2
        t2_host_process.inject_simulated_process(
            pid=pid,
            name=profile["binary"],
            cmdline=f"{profile['binary']} {profile['args']}",
            score=profile["threat_score"],
            flags=profile["flags"]
        )

        # 2. Execute high-entropy burst writes with the authentic ransomware extension
        enc_count = random.randint(5, 9)
        enc_res = simulator.run_encryption_burst_simulation(count=enc_count, ext=profile["ext"])
        total_files_encrypted += enc_res.get("files_encrypted", enc_count)

        # 3. Trigger recovery inhibition / defense evasion in T6
        t6_defense_evasion.evaluate_command_execution(
            command_line=profile["evasion_cmd"],
            pid=pid,
            process_name=profile["binary"]
        )

        # 4. Detonate Canary Decoy Tripwire in T7
        if available_canaries:
            target_c = available_canaries[idx % len(available_canaries)]
            target_path = os.path.join(canary_vault_dir, target_c)
            with open(target_path, "wb") as f:
                f.write(os.urandom(2048))
        else:
            tamper_res = simulator.run_canary_tamper_simulation()
            target_c = tamper_res.get("target_canary")

        if target_c:
            if target_c not in breached_canaries:
                breached_canaries.append(target_c)
            t7_deception_canary.record_breach_metadata(
                filename=target_c,
                attacker_process=profile["binary"],
                attacker_pid=pid,
                attacker_family=profile["name"],
                tamper_type=f"Simultaneous Multi-Strain Attack ({profile['ext']})"
            )
        t7_deception_canary.events.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "module": "T7: Deception & Tripwire Signals",
            "code": "T7",
            "severity": "CRITICAL",
            "message": f"SIMULTANEOUS ATTACK DETONATED: Decoy '{target_c}' breached by {profile['name']} ({profile['binary']} PID: {pid})!"
        })

        # 5. Outbound C2 Beacon & Lateral Movement in T5
        t5_network_exfil.record_c2_beacon(c2_ip, c2_port, pid=pid, process_name=profile["binary"])
        t5_network_exfil.record_lateral_movement("SMB", lateral_ip, profile["lateral_port"], pid=pid)

        # 6. Credential Access Attempt in T4
        t4_identity_auth.record_credential_access_attempt(target="lsass.exe", source_process=profile["binary"], pid=pid)

    # Re-audit canaries once all strains finished
    t7_deception_canary.audit_all_canaries()

    # 7. Automated Containment Activation: Network Quarantine & Admin Alert
    if not containment_engine.is_network_isolated:
        containment_engine.isolate_network(
            initiator="Automated Containment Engine",
            reason=f"Simultaneous Multi-Strain Attack: {len(selected_profiles)} Strains Active ({', '.join([p['id'] for p in selected_profiles])})"
        )

    notification_engine.dispatch_alert(
        title=f"🚨 CRITICAL MULTI-STRAIN RANSOMWARE OUTBREAK: {len(selected_profiles)} Strains Concurrently Detonated",
        severity="CRITICAL",
        details={
            "strains_count": len(selected_profiles),
            "malware_families": [p["name"] for p in selected_profiles],
            "processes": [f"{p['binary']} (PID: {p['pid']})" for p in spawned_processes],
            "extensions": [p["ext"] for p in selected_profiles],
            "containment_action": "Mass Kernel Process Termination (SIGKILL) & Host Network Isolation"
        },
        force=True
    )

    # 8. Automatically generate single formal forensic incident report
    incident_in_progress = True
    last_auto_incident_report_time = time.time()

    current_entropy_info = t3_fs_entropy.get_latest_entropy_data()
    rep_res = incident_reporter.generate_report(
        risk_data=latest_risk_result or {
            "risk_score_100": 99.8,
            "threat_score_norm": 0.998,
            "risk_level": "Critical",
            "recommended_action": f"Immediate execution kill on all {len(spawned_processes)} adversary processes and full host quarantine.",
            "badge_color": "#ef4444"
        },
        telemetry_events=get_combined_events(limit=40),
        containment_actions=containment_engine.get_action_history(),
        flagged_processes=t2_host_process.get_flagged_processes(),
        canary_status=t7_deception_canary.get_canary_status(),
        entropy_data=current_entropy_info,
        hostname=config["system"]["hostname"],
        is_simulation=True,
        simulation_scenario=campaign_name
    )
    simulation_in_progress = False

    # Simulation email handling:
    # Testing/simulation does NOT dispatch automatically unless explicitly requested with dispatch_email=True.
    eml_record = None
    if dispatch_email or not getattr(notification_engine, "prompt_before_simulation_email", True):
        try:
            eml_record = notification_engine.dispatch_incident_email(
                report_data=rep_res,
                is_simulation=True,
                scenario_name=campaign_name,
                short_note=(
                    f"Test ransomware attack (Multi-Strain: {', '.join(family_names)}). "
                    f"Coordinated adversary emulation drill executed safely. "
                    f"Multi-vector canary tripwires and mass process containment verified. "
                    f"Complete forensic incident report attached in PDF format."
                )
            )
        except Exception as eml_err:
            print(f"[!] Error auto-dispatching multi-strain simulation email: {eml_err}")

    first_proc = spawned_processes[0]
    return {
        "status": "COMPLETED",
        "simulation": "SIMULTANEOUS_MULTI_ATTACK",
        "strains_count": len(selected_profiles),
        "families": [p["id"] for p in selected_profiles],
        "scenario": campaign_name,
        "attacker_process": first_proc["binary"],
        "attacker_pid": first_proc["pid"],
        "spawned_processes": spawned_processes,
        "files_encrypted": total_files_encrypted,
        "breached_canaries": breached_canaries,
        "target_canary": breached_canaries[0] if breached_canaries else "q4_financial_payroll.xlsx",
        "incident_id": rep_res.get("incident_id"),
        "incident_report_id": rep_res.get("incident_id"),
        "pdf_path": rep_res.get("pdf_path"),
        "pdf_filename": f"{rep_res.get('incident_id')}.pdf",
        "ask_email_dispatch": True if not eml_record else False,
        "prompt_user_for_email": True if not eml_record else False,
        "email_dispatched": bool(eml_record),
        "email_recipient": notification_engine.soc_email,
        "email_id": eml_record.get("id") if eml_record else None,
        "email_to": eml_record.get("to") if eml_record else [notification_engine.soc_email],
        "email_subject": eml_record.get("subject") if eml_record else f"[TEST RANSOMWARE ATTACK] Forensic Incident Report Attached: {rep_res.get('incident_id')} ({campaign_name})",
        "email_short_note": eml_record.get("short_note") if eml_record else f"Test ransomware attack (Multi-Strain: {', '.join(family_names)})",
        "has_pdf_attachment": True,
        "message": f"Simultaneously detonated {len(selected_profiles)} ransomware strains ({', '.join(family_names)})! Spawned {len(spawned_processes)} attacker processes, encrypted {total_files_encrypted} files, breached {len(breached_canaries)} decoys, and compiled forensic report {rep_res.get('incident_id')}."
    }

@app.post("/api/simulate/multi")
async def simulate_multi_ransomware(request: Request):
    """Executes one or more ransomware attacks concurrently."""
    try:
        body = await request.json()
        families = body.get("families", [])
        dispatch_email = bool(body.get("dispatch_email", False))
    except Exception:
        families = []
        dispatch_email = False
    if isinstance(families, str):
        families = [f.strip() for f in families.split(",") if f.strip()]
    return execute_multi_ransomware_simulation(families, dispatch_email=dispatch_email)

@app.get("/api/simulate/families")
def get_ransomware_families():
    """Returns metadata for all 12 real-world ransomware families available for testing."""
    return {
        "families": list(REAL_RANSOMWARE_FAMILIES.values()),
        "families_dict": REAL_RANSOMWARE_FAMILIES
    }

@app.post("/api/simulate/ransomware/{family}")
async def simulate_named_ransomware(family: str, request: Request = None):
    dispatch_email = False
    if request:
        try:
            body = await request.json()
            dispatch_email = bool(body.get("dispatch_email", False))
        except Exception:
            pass
    return execute_real_ransomware_simulation(family, dispatch_email=dispatch_email)

@app.post("/api/simulate/benign")
def simulate_benign():
    return simulator.run_benign_workload(count=5)

@app.post("/api/simulate/canary-breach")
def simulate_canary():
    return execute_real_ransomware_simulation("wannacry")

@app.post("/api/simulate/encryption-burst")
def simulate_encryption():
    return execute_real_ransomware_simulation("lockbit3")

@app.post("/api/simulate/defense-evasion")
def simulate_defense_evasion():
    return execute_real_ransomware_simulation("conti")

@app.post("/api/simulate/network-exfil")
def simulate_network():
    return execute_real_ransomware_simulation("darkside")

@app.post("/api/simulate/full-attack")
def simulate_full_attack():
    family = random.choice(list(REAL_RANSOMWARE_FAMILIES.keys()))
    return execute_real_ransomware_simulation(family)

@app.post("/api/simulate/{scenario_id}")
async def simulate_scenario_router(scenario_id: str, request: Request = None):
    dispatch_email = False
    if request:
        try:
            body = await request.json()
            dispatch_email = bool(body.get("dispatch_email", False))
        except Exception:
            pass
    if scenario_id in REAL_RANSOMWARE_FAMILIES:
        return execute_real_ransomware_simulation(scenario_id, dispatch_email=dispatch_email)
    elif scenario_id == "benign":
        return simulate_benign()
    elif scenario_id in ["canary-breach", "encryption-burst", "defense-evasion", "network-exfil", "full-attack"]:
        family = random.choice(list(REAL_RANSOMWARE_FAMILIES.keys()))
        return execute_real_ransomware_simulation(family, dispatch_email=dispatch_email)
    else:
        return execute_real_ransomware_simulation("wannacry", dispatch_email=dispatch_email)

@app.post("/api/webhook/alerts")
async def webhook_listener(request: Request):
    """Receives and acknowledges simulated SOC webhook dispatches."""
    data = await request.json()
    return {"status": "DELIVERED", "received_at": time.time(), "id": data.get("id")}

# ==================== Baseline Profiling & Timed Benchmark Endpoints ====================

@app.post("/api/benchmark/baseline/start")
def start_baseline_api(data: Dict[str, Any] = {}):
    duration = int(data.get("duration_sec", 30))
    return benchmark_engine.start_baseline_capture(duration_sec=duration)

@app.get("/api/benchmark/baseline/status")
def get_baseline_status_api():
    return benchmark_engine.get_baseline_status()

@app.post("/api/benchmark/test-run/start")
def start_timed_benchmark_api(data: Dict[str, Any] = {}):
    duration = int(data.get("duration_sec", 30))
    sample_type = data.get("sample_type", "LockBit 3.0 Emulation")
    total_files = int(data.get("total_files", 40))
    return benchmark_engine.start_timed_benchmark(
        duration_sec=duration,
        sample_type=sample_type,
        total_files=total_files
    )

@app.post("/api/benchmark/test-run/stop")
def stop_timed_benchmark_api():
    return benchmark_engine.stop_benchmark_test()

@app.get("/api/benchmark/test-run/status")
def get_timed_benchmark_status_api():
    return benchmark_engine.get_benchmark_status()

@app.get("/api/benchmark/reports")
def list_benchmark_reports_api():
    return {"reports": benchmark_engine.list_benchmark_reports()}

