"""
Identity and Authentication Anomaly Telemetry Module (T4)
Audits logon types (Logon Type 3 vs Type 10), Kerberos ticket requests (Event ID 4769),
failed authentication bursts, and unauthorized credential dumping patterns.
"""

import time
import os
import threading
from typing import Dict, List, Any, Optional
from telemetry.common import TelemetryModuleBase

class IdentityAuthTelemetry(TelemetryModuleBase):
    def __init__(self):
        super().__init__(
            name="Identity & Authentication",
            code="T4",
            description="Monitors anomalous credential access, failed logon bursts, and Kerberoasting"
        )
        # Register Prometheus metrics
        self.m_failed_logins = self.register_metric(
            "auth_failed_logins_total", "counter",
            "Cumulative failed authentication attempts"
        )
        self.m_suspicious_logons = self.register_metric(
            "auth_suspicious_logon_types_total", "counter",
            "Anomalous logon types observed (e.g., Type 3 network vs Type 10 RDP)"
        )
        self.m_cred_dumping = self.register_metric(
            "credential_dump_attempts_total", "counter",
            "Attempts to access credential storage (lsass.exe, shadow, SAM)"
        )
        self.m_kerberoasting = self.register_metric(
            "kerberoasting_events_total", "counter",
            "Suspicious Kerberos service ticket requests (Event ID 4769)"
        )

        self.auth_events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def record_auth_event(self, event_type: str, username: str, source_ip: str = "127.0.0.1",
                          logon_type: int = 3, success: bool = False, details: Optional[Dict[str, Any]] = None):
        """
        Ingests an authentication event from Windows Event Logs or Linux PAM.
        Logon Type 3: Network logon (e.g. SMB/PsExec lateral movement)
        Logon Type 10: RemoteInteractive (RDP)
        """
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        record = {
            "timestamp": now,
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip,
            "logon_type": logon_type,
            "success": success,
            "details": details or {}
        }

        with self._lock:
            self.auth_events.append(record)
            if len(self.auth_events) > 100:
                self.auth_events.pop(0)

        if not success:
            self.m_failed_logins.inc(1.0, {"source_ip": source_ip, "username": username})
            self.log_event("WARNING", f"Failed authentication burst for user '{username}' from {source_ip}", record)
        else:
            if logon_type in [3, 10]:
                self.m_suspicious_logons.inc(1.0, {"logon_type": str(logon_type), "username": username})
                if logon_type == 3 and "admin" in username.lower():
                    self.log_event("HIGH", f"Type 3 (Network) privileged logon detected for '{username}' from {source_ip} (potential lateral movement)", record)
                else:
                    self.log_event("INFO", f"Logon Type {logon_type} recorded for '{username}'", record)

    def record_credential_access_attempt(self, target: str, source_process: str, pid: int):
        """
        Records unauthorized handle access directed at lsass.exe, sam, or shadow files.
        """
        record = {
            "target": target,
            "source_process": source_process,
            "pid": pid,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        self.m_cred_dumping.inc(1.0, {"target": target, "pid": str(pid)})
        self.log_event(
            "CRITICAL",
            f"Credential Dumping Indicator: Process '{source_process}' (PID {pid}) requested sensitive handle to {target}",
            record
        )

    def record_kerberoasting_attempt(self, service_name: str, client_ip: str, encryption_type: str = "0x17"):
        """
        Records Kerberoasting ticket request (RC4 / 0x17 encryption is high risk).
        """
        record = {
            "service_name": service_name,
            "client_ip": client_ip,
            "encryption_type": encryption_type
        }
        self.m_kerberoasting.inc(1.0)
        self.log_event(
            "HIGH",
            f"Kerberoasting Activity: Kerberos TGS requested for '{service_name}' with weak encryption {encryption_type} from {client_ip}",
            record
        )

    def reset_auth_telemetry(self):
        """Resets authentication events history back to normal baseline."""
        with self._lock:
            self.auth_events.clear()
        self.log_event("INFO", "Identity and authentication telemetry history reset to normal baseline.")

