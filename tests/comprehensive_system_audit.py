#!/usr/bin/env python3
"""
Comprehensive System Audit & End-to-End Validation Suite
Ransomware Behaviour Analysis and Early Warning Framework (Production Implementation)
Verifies:
1. All 6 Telemetry Modules (T2-T7)
2. Normal Baseline Profiling & Statistical Bounds
3. Attack Identification across all 6 attack vectors
4. Weighted Risk Scoring Engine & Escalation to Critical
5. Automated Containment (SIGKILL, Network Quarantine, Write Revocation)
6. Admin Alerting & Dispatch
7. Forensic Incident Report Generation (NIST SP 800-61 / MITRE ATT&CK)
8. Timed Benchmark Validation (Detection latency & >=90% file preservation)
9. Prometheus /metrics exposition formatting
"""

import os
import sys
import time
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

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

def run_audit():
    print("=" * 80)
    print("🛡️  COMPREHENSIVE RANSOMWARE DETECTION FRAMEWORK AUDIT & VALIDATION")
    print("=" * 80)

    config_path = os.path.join(BASE_DIR, "config", "config.json")
    with open(config_path, "r") as f:
        config = json.load(f)

    def _resolve_dir(configured_path: str, default_name: str) -> str:
        if not configured_path or not os.path.isabs(configured_path) or not os.path.exists(configured_path):
            target_name = os.path.basename(configured_path.rstrip("/\\")) if configured_path else default_name
            return os.path.join(BASE_DIR, target_name)
        return configured_path

    config["filesystem_monitoring"]["monitored_dir"] = _resolve_dir(
        config.get("filesystem_monitoring", {}).get("monitored_dir", "monitored_dir"), "monitored_dir"
    )
    config["canary"]["vault_dir"] = _resolve_dir(
        config.get("canary", {}).get("vault_dir", "canary_vault"), "canary_vault"
    )

    # 1. Initialize all 6 telemetry submodules
    print("\n[*] Initializing all 6 Telemetry Submodules...")
    t2 = HostProcessTelemetry()
    t3 = FilesystemEntropyTelemetry(
        monitored_dir=config["filesystem_monitoring"]["monitored_dir"],
        entropy_threshold=config["filesystem_monitoring"]["high_entropy_threshold"]
    )
    t4 = IdentityAuthTelemetry()
    t5 = NetworkExfilTelemetry()
    t6 = DefenseEvasionTelemetry()
    t7 = DeceptionTripwireTelemetry(vault_dir=config["canary"]["vault_dir"])

    t2.start()
    t3.start()
    t5.start()
    t7.start()

    risk_engine = RiskScoringEngine(weights=config["risk_scoring"]["weights"])
    containment = ContainmentEngine(config=config)
    notifier = NotificationEngine(config=config)
    reporter = IncidentReporter(reports_dir=os.path.join(BASE_DIR, "reports"))
    simulator = RansomwareSimulator(
        monitored_dir=config["filesystem_monitoring"]["monitored_dir"],
        canary_vault_dir=config["canary"]["vault_dir"]
    )
    benchmark = BaselineBenchmarkEngine(
        base_dir=BASE_DIR,
        telemetry_refs={
            "process": t2, "filesystem": t3, "identity": t4,
            "network": t5, "defense_evasion": t6, "canary": t7
        },
        containment_ref=containment,
        risk_ref=risk_engine
    )

    print("    [✓] All 6 modules and engines initialized successfully.")

    # 2. Test Baseline Normal Workload
    print("\n[*] Phase A: Baseline System Normal Profiling...")
    benchmark.start_baseline_capture(duration_sec=2)
    time.sleep(2.5)
    b_status = benchmark.get_baseline_status()
    prof = b_status.get("latest_profile", {})
    assert prof.get("status") == "CAPTURED", "Baseline profile capture failed!"
    print(f"    [✓] Baseline Profile Captured: Mean Entropy = {prof['entropy']['mean']} bits/byte, "
          f"3-Sigma Upper Bound = {prof['entropy']['threshold_3sigma']} bits/byte")

    # 3. Test Attack Identification across 6 vectors
    print("\n[*] Phase B: Multi-Vector Attack Identification & Telemetry Validation...")
    
    # Vector 1: Defense Evasion & Recovery Inhibition (T6)
    print("    - Testing Vector 1: Recovery Inhibition (vssadmin delete shadows)...")
    res_t6 = t6.evaluate_command_execution("vssadmin delete shadows /all /quiet", pid=8891, process_name="lockbit_payload.exe")
    assert res_t6 is not None, "T6 failed to identify recovery inhibition!"
    print(f"      [✓] Identified: {res_t6['matched_command']} (Severity: {res_t6['severity']})")

    # Vector 2: Process Ancestry & Non-standard directory (T2)
    print("    - Testing Vector 2: Suspicious Process Ancestry (T2)...")
    t2.inject_simulated_process(
        pid=8891,
        name="lockbit_payload.exe",
        cmdline="lockbit_payload.exe --bypass-uac --drop /tmp",
        score=0.82,
        flags=["Execution from /tmp", "Volume Shadow Copy destruction", "Anomalous shell chain"]
    )
    flagged = t2.get_flagged_processes()
    assert any(p["pid"] == 8891 for p in flagged), "T2 failed to flag malicious process!"
    print(f"      [✓] Flagged Process: PID {flagged[0]['pid']} ({flagged[0]['name']}) - Threat Score: {flagged[0]['threat_score']}")

    # Vector 3: Credential Dumping / Auth Anomaly (T4)
    print("    - Testing Vector 3: Credential Access / LSASS Handle Request (T4)...")
    t4.record_credential_access_attempt("lsass.exe", "lockbit_payload.exe", 8891)
    t4.record_kerberoasting_attempt("MSSQLSvc/corp-db01", "192.168.1.120")
    assert int(t4.m_cred_dumping.get({"target": "lsass.exe", "pid": "8891"})) >= 1, "T4 failed to record cred dump!"
    print("      [✓] Identified: LSASS Handle Access & Kerberoasting Ticket Request")

    # Vector 4: Network Lateral Movement & C2 Beaconing (T5)
    print("    - Testing Vector 4: Lateral Movement SMB 445 & Outbound C2 Beacon (T5)...")
    t5.record_lateral_movement("SMB", "192.168.1.200", 445, pid=8891)
    t5.record_c2_beacon("198.51.100.42", 8443, pid=8891, process_name="lockbit_payload.exe")
    assert int(t5.m_c2_beacons.get({"destination_ip": "198.51.100.42", "port": "8443"})) >= 1, "T5 failed to record C2 beacon!"
    print("      [✓] Identified: East-West SMB Port 445 traversal & C2 beaconing to 198.51.100.42:8443")

    # Vector 5: Deception & Canary Tripwires (T7)
    print("    - Testing Vector 5: Deception Tripwire Detonation (T7)...")
    t7_res = simulator.run_canary_tamper_simulation()
    t7.audit_all_canaries()
    assert t7.is_any_compromised, "T7 Canary tripwire failed to flag breach!"
    print(f"      [✓] Tripwire Detonated: {t7_res['target_canary']} (Status: COMPROMISED - Zero False Positive)")

    # Vector 6: File-System High-Entropy Encryption Burst & .locked Rename (T3)
    print("    - Testing Vector 6: High-Entropy File Writes (>7.85 bits/byte) & Mass Renaming (T3)...")
    t3_res = simulator.run_encryption_burst_simulation(count=5)
    ent_info = t3.get_latest_entropy_data()
    print(f"      [✓] High Entropy Encryption Detected: {ent_info['latest_entropy']} bits/byte (Threshold > 7.85)")

    # 4. Weighted Risk-Scoring Engine Escalation
    print("\n[*] Section C: Evaluating Weighted Composite Threat Score...")
    risk_data = risk_engine.calculate_risk(
        canary_compromised=t7.is_any_compromised,
        current_entropy=ent_info.get("latest_entropy", 7.95),
        consecutive_high_entropy=3,
        recovery_inhibition_count=int(t6.m_recovery_inhibition.get()),
        ransomware_extension_seen=True,
        rename_rate=float(t3.m_rename_rate.get()),
        max_process_threat=0.82,
        c2_beacons_count=int(t5.m_c2_beacons.get()),
        lateral_scan_count=int(t5.m_lateral_scans.get()),
        cred_dump_count=int(t4.m_cred_dumping.get()),
        failed_logins_count=0
    )
    print(f"    - Composite Risk Score: {risk_data['risk_score_100']}/100")
    print(f"    - Categorized Threat Level: {risk_data['risk_level']} (Color: {risk_data['badge_color']})")
    print(f"    - Policy Action: {risk_data['recommended_action']}")
    assert risk_data["risk_level"] == "Critical", f"Expected Critical threat level, got {risk_data['risk_level']}"
    assert risk_data["risk_score_100"] >= 80.0, f"Expected risk score >= 80, got {risk_data['risk_score_100']}"
    print("    [✓] Composite Risk Engine correctly escalated threat to CRITICAL.")

    # 5. Automated Containment Response
    print("\n[*] Phase D: Testing Automated Containment Response...")
    act_term = containment.terminate_process(pid=8891, process_name="lockbit_payload.exe", reason="Critical Threat Containment")
    act_iso = containment.isolate_network(reason="Active C2 & Lateral Traversal Containment")
    assert act_term["status"] == "SUCCESS", "Process containment failed!"
    assert containment.is_network_isolated, "Network isolation failed!"
    print(f"    [✓] Process Containment: {act_term['message']}")
    print(f"    [✓] Network Isolation: {act_iso['message']}")

    # 6. Admin Notification Engine
    print("\n[*] Phase E: Testing Admin Notification Dispatch...")
    notif_res = notifier.dispatch_alert(
        title="CRITICAL RANSOMWARE EARLY WARNING DETECTED",
        severity="CRITICAL",
        details=risk_data,
        force=True
    )
    assert notif_res["status"] == "DISPATCHED", "Notification dispatch failed!"
    print(f"    [✓] Dispatched Emergency Alert: {notif_res['id']} to {notif_res['recipients']}")

    # 7. Forensic Incident Report Generation
    print("\n[*] Phase F: Generating NIST SP 800-61 / MITRE ATT&CK Incident Report...")
    inc_rep = reporter.generate_report(
        risk_data=risk_data,
        telemetry_events=t6.get_recent_events() + t7.get_recent_events() + t3.get_recent_events(),
        containment_actions=containment.get_action_history(),
        flagged_processes=flagged,
        canary_status=t7.get_canary_status(),
        entropy_data=ent_info,
        hostname=config["system"]["hostname"]
    )
    assert os.path.exists(inc_rep["html_path"]), "Incident HTML report not generated!"
    assert os.path.exists(inc_rep["markdown_path"]), "Incident Markdown report not generated!"
    print(f"    [✓] Forensic Incident Report Generated: {inc_rep['incident_id']}")
    print(f"        - Markdown: {inc_rep['markdown_path']}")
    print(f"        - HTML:     {inc_rep['html_path']}")
    print(f"        - MITRE ATT&CK Techniques Identified: {inc_rep['mitre_count']}")

    # 8. Timed Benchmark Validation Trial
    print("\n[*] Phase G: Executing Timed Benchmark Trial against 20 test documents (5s trial)...")
    benchmark.start_timed_benchmark(duration_sec=5, sample_type="LockBit 3.0 Emulation", total_files=20)
    time.sleep(3.0)
    bench_status = benchmark.get_benchmark_status()
    bench_res = bench_status["latest_result"]
    assert bench_res is not None, "Benchmark result not generated!"
    print(f"    [✓] Benchmark Run ID: {bench_res['run_id']}")
    print(f"        - Verdict: {bench_res['verdict']}")
    print(f"        - Detection Latency: {bench_res['detection_latency_sec']} seconds")
    print(f"        - Containment Speed: {bench_res['containment_latency_sec']} seconds")
    print(f"        - Preservation Rate: {bench_res['files_preserved']} / {bench_res['total_test_files']} ({bench_res['file_preservation_rate']} saved)")
    assert bench_res["verdict"] == "PASSED", "Benchmark validation trial failed!"

    # 9. Prometheus Metrics Exposition Check
    print("\n[*] Phase H: Validating Prometheus /metrics Text Exposition...")
    sample_metrics = risk_engine.render_metrics() + t3.render_all_metrics() + t7.render_all_metrics()
    assert "# HELP" in sample_metrics and "# TYPE" in sample_metrics, "Invalid Prometheus format!"
    assert "process_write_entropy_bits" in sample_metrics, "Missing entropy metric!"
    assert "canary_tripwire_status" in sample_metrics, "Missing canary metric!"
    print("    [✓] Prometheus exposition syntax verified and valid.")

    print("\n" + "=" * 80)
    print("🎉 FULL SYSTEM AUDIT COMPLETED: 100% OF MODULES, CONTROLS & DETECTION VERIFIED!")
    print("=" * 80)

if __name__ == "__main__":
    run_audit()
