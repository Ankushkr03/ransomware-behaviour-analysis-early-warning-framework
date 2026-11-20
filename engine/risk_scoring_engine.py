"""
Composite Risk Scoring Engine
Implements the Multi-Vector Weighted Risk-Scoring Model:
R100 = ( sum(Wi * Si) / sum(Wi) ) * 100
Evaluates multi-vector telemetry into a normalized risk score (0-100) and risk level.
"""

import time
from typing import Dict, Any, Tuple
from telemetry.common import PrometheusMetric

class RiskScoringEngine:
    def __init__(self, weights: Dict[str, float] = None):
        self.weights = weights or {
            "canary_tripwire_breached": 35.0,
            "high_write_entropy": 25.0,
            "recovery_inhibition_cmd": 20.0,
            "mass_file_renames": 15.0,
            "suspicious_process_spawn": 10.0,
            "network_c2_beaconing": 10.0,
            "auth_anomaly_burst": 10.0
        }
        self.total_weight = sum(self.weights.values())

        # Metrics
        self.m_composite_score = PrometheusMetric(
            "composite_threat_score", "gauge",
            "Normalized multi-vector ransomware threat score (0.0 to 1.0)"
        )
        self.m_risk_score_100 = PrometheusMetric(
            "composite_risk_score_100", "gauge",
            "Normalized multi-vector risk score (0 to 100)"
        )

        self.last_score_100 = 0.0
        self.last_score_norm = 0.0
        self.last_risk_level = "Normal"
        self.last_recommended_action = "Continue monitoring."
        self.last_breakdown: Dict[str, Any] = {}

    def calculate_risk(
        self,
        canary_compromised: bool,
        current_entropy: float,
        consecutive_high_entropy: int,
        recovery_inhibition_count: int,
        ransomware_extension_seen: bool,
        rename_rate: float,
        max_process_threat: float,
        c2_beacons_count: int,
        lateral_scan_count: int,
        cred_dump_count: int,
        failed_logins_count: int
    ) -> Dict[str, Any]:
        """
        Calculates the composite weighted risk score R100 and returns categorization.
        """
        # Calculate Si (normalized severity 0.0 to 1.0) for each vector
        s_canary = 1.0 if canary_compromised else 0.0

        if consecutive_high_entropy >= 3 or current_entropy >= 7.85:
            s_entropy = 1.0
        elif current_entropy >= 7.2:
            s_entropy = 0.70
        elif current_entropy >= 6.0:
            s_entropy = 0.40
        else:
            s_entropy = 0.05

        s_recovery = 1.0 if recovery_inhibition_count > 0 else 0.0

        if ransomware_extension_seen:
            s_rename = 1.0
        elif rename_rate > 3.0:
            s_rename = 0.80
        elif rename_rate > 1.0:
            s_rename = 0.40
        else:
            s_rename = 0.0

        s_process = min(1.0, max(0.05, max_process_threat))

        if c2_beacons_count > 0:
            s_network = 1.0
        elif lateral_scan_count > 0:
            s_network = min(1.0, 0.4 + (lateral_scan_count * 0.15))
        else:
            s_network = 0.05

        if cred_dump_count > 0:
            s_auth = 1.0
        elif failed_logins_count >= 5:
            s_auth = min(1.0, failed_logins_count * 0.1)
        else:
            s_auth = 0.05

        # Weighted calculation
        w_canary = self.weights["canary_tripwire_breached"]
        w_entropy = self.weights["high_write_entropy"]
        w_recovery = self.weights["recovery_inhibition_cmd"]
        w_rename = self.weights["mass_file_renames"]
        w_process = self.weights["suspicious_process_spawn"]
        w_network = self.weights["network_c2_beaconing"]
        w_auth = self.weights["auth_anomaly_burst"]

        pts_canary = round(w_canary * s_canary, 1)
        pts_entropy = round(w_entropy * s_entropy, 1)
        pts_recovery = round(w_recovery * s_recovery, 1)
        pts_rename = round(w_rename * s_rename, 1)
        pts_process = round(w_process * s_process, 1)
        pts_network = round(w_network * s_network, 1)
        pts_auth = round(w_auth * s_auth, 1)

        weighted_sum = (
            pts_canary + pts_entropy + pts_recovery + pts_rename +
            pts_process + pts_network + pts_auth
        )

        r_100 = round((weighted_sum / self.total_weight) * 100.0, 1)
        escalation_rule = None

        # Deception tripwire rule: A breached canary is deterministic zero-false-positive!
        # Automatically escalates to Critical (min 85)
        if canary_compromised and r_100 < 85.0:
            r_100 = 92.5
            escalation_rule = "Canary Decoy Breached (Zero-False-Positive Minimum 92.5 Override)"

        # High Write Entropy Rule with recovery inhibition: instant Critical
        if consecutive_high_entropy >= 3 and s_recovery > 0 and r_100 < 80.0:
            r_100 = 88.0
            escalation_rule = "Cryptographic Write Burst + Recovery Destruction Override"

        r_norm = round(r_100 / 100.0, 3)

        # Map to Risk Categories
        level, action, color = self._categorize_score(r_100)

        self.last_score_100 = r_100
        self.last_score_norm = r_norm
        self.last_risk_level = level
        self.last_recommended_action = action
        self.last_breakdown = {
            "total_weight": self.total_weight,
            "weighted_sum": round(weighted_sum, 1),
            "formula": "R100 = (Σ(Wi * Si) / 125) * 100",
            "escalation_rule": escalation_rule,
            "factors": [
                {
                    "key": "canary",
                    "label": "Canary Decoy Vault (T7)",
                    "weight": w_canary,
                    "severity": s_canary,
                    "points": pts_canary,
                    "max_points": w_canary,
                    "live_val": "COMPROMISED" if canary_compromised else "INTACT (0 Breaches)",
                    "active": canary_compromised,
                    "icon": "fa-file-shield"
                },
                {
                    "key": "entropy",
                    "label": "Sliding Shannon Entropy (T3)",
                    "weight": w_entropy,
                    "severity": s_entropy,
                    "points": pts_entropy,
                    "max_points": w_entropy,
                    "live_val": f"{current_entropy:.2f} bits/byte ({consecutive_high_entropy}/3 consecutive)",
                    "active": current_entropy >= 7.2 or consecutive_high_entropy >= 2,
                    "icon": "fa-chart-area"
                },
                {
                    "key": "recovery",
                    "label": "VSS / Recovery Inhibition (T6)",
                    "weight": w_recovery,
                    "severity": s_recovery,
                    "points": pts_recovery,
                    "max_points": w_recovery,
                    "live_val": f"{recovery_inhibition_count} Shadow Copy Kill commands",
                    "active": recovery_inhibition_count > 0,
                    "icon": "fa-shield-halved"
                },
                {
                    "key": "renames",
                    "label": "Mass File Renames (T3)",
                    "weight": w_rename,
                    "severity": s_rename,
                    "points": pts_rename,
                    "max_points": w_rename,
                    "live_val": "Ransomware Extension Found" if ransomware_extension_seen else f"{rename_rate:.1f} renames/s",
                    "active": ransomware_extension_seen or rename_rate > 1.0,
                    "icon": "fa-file-signature"
                },
                {
                    "key": "process",
                    "label": "Suspicious Process Threat (T2)",
                    "weight": w_process,
                    "severity": s_process,
                    "points": pts_process,
                    "max_points": w_process,
                    "live_val": f"Score {max_process_threat:.2f} / 1.00",
                    "active": max_process_threat >= 0.40,
                    "icon": "fa-microchip"
                },
                {
                    "key": "network",
                    "label": "C2 Beacons & Lateral Scans (T5)",
                    "weight": w_network,
                    "severity": s_network,
                    "points": pts_network,
                    "max_points": w_network,
                    "live_val": f"{c2_beacons_count} C2 hits | {lateral_scan_count} SMB/RDP scans",
                    "active": c2_beacons_count > 0 or lateral_scan_count > 0,
                    "icon": "fa-network-wired"
                },
                {
                    "key": "auth",
                    "label": "Credential Access & Auth Anomaly (T4)",
                    "weight": w_auth,
                    "severity": s_auth,
                    "points": pts_auth,
                    "max_points": w_auth,
                    "live_val": f"{cred_dump_count} LSASS dumps | {failed_logins_count} failed logins",
                    "active": cred_dump_count > 0 or failed_logins_count >= 5,
                    "icon": "fa-user-lock"
                }
            ]
        }

        # Update metrics
        self.m_composite_score.set(r_norm)
        self.m_risk_score_100.set(r_100)

        return {
            "risk_score_100": r_100,
            "threat_score_norm": r_norm,
            "risk_level": level,
            "recommended_action": action,
            "badge_color": color,
            "breakdown": self.last_breakdown,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

    def _categorize_score(self, score: float) -> Tuple[str, str, str]:
        if score <= 19:
            return "Normal", "Continue monitoring.", "#10b981"  # Emerald
        elif score <= 39:
            return "Low", "Record the event and monitor for recurrence.", "#3b82f6"  # Blue
        elif score <= 59:
            return "Medium", "Generate a warning and review relevant telemetry.", "#f59e0b"  # Amber
        elif score <= 79:
            return "High", "Generate a high-priority alert and investigate promptly.", "#f97316"  # Orange
        else:
            return "Critical", "Issue an urgent alert and initiate the approved incident-response procedure.", "#ef4444"  # Red

    def render_metrics(self) -> str:
        return self.m_composite_score.render_prometheus_text() + "\n\n" + self.m_risk_score_100.render_prometheus_text() + "\n"
