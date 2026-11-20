"""
Defense Evasion and Recovery Inhibition Telemetry Module (T6)
Identifies recovery-disabling commands (vssadmin, wmic, bcdedit), backup service tampering,
and security-control suppression attempts.
"""

import time
import os
import threading
from typing import Dict, List, Any, Optional
from telemetry.common import TelemetryModuleBase

INHIBITION_SIGNATURES = [
    {"cmd": "vssadmin delete shadows", "category": "shadow_copy_deletion", "severity": "CRITICAL"},
    {"cmd": "vssadmin resize shadowstorage", "category": "shadow_storage_manipulation", "severity": "HIGH"},
    {"cmd": "wmic shadowcopy delete", "category": "shadow_copy_deletion", "severity": "CRITICAL"},
    {"cmd": "wbadmin delete catalog", "category": "backup_catalog_deletion", "severity": "CRITICAL"},
    {"cmd": "bcdedit /set {default} recoveryenabled no", "category": "boot_recovery_inhibition", "severity": "CRITICAL"},
    {"cmd": "bcdedit /set {default} bootstatuspolicy ignoreallfailures", "category": "boot_policy_evasion", "severity": "HIGH"},
    {"cmd": "wevtutil cl", "category": "security_log_clearing", "severity": "CRITICAL"},
    {"cmd": "sc stop windefend", "category": "antivirus_tampering", "severity": "CRITICAL"},
    {"cmd": "net stop", "category": "service_tampering", "severity": "HIGH"},
    {"cmd": "killall -9 auditd", "category": "audit_daemon_tampering", "severity": "CRITICAL"}
]

class DefenseEvasionTelemetry(TelemetryModuleBase):
    def __init__(self):
        super().__init__(
            name="Defense Evasion & Recovery Inhibition",
            code="T6",
            description="Identifies shadow copy deletion, recovery inhibition, and security tool tampering"
        )
        # Register Prometheus metrics
        self.m_recovery_inhibition = self.register_metric(
            "recovery_inhibition_attempts_total", "counter",
            "Attempts to delete Volume Shadow Copies or inhibit system recovery"
        )
        self.m_defense_evasion = self.register_metric(
            "defense_evasion_commands_total", "counter",
            "Commands executed to evade defenses or tamper with security controls"
        )
        self.m_tampering_events = self.register_metric(
            "tampering_events_total", "counter",
            "Tampering events targeting system logs, backups, or security agents"
        )

        self.evasion_events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def evaluate_command_execution(self, command_line: str, pid: int = 0, process_name: str = "unknown") -> Optional[Dict[str, Any]]:
        """
        Inspects process execution arguments against recovery inhibition signatures.
        """
        cmd_clean = command_line.lower().strip()
        for sig in INHIBITION_SIGNATURES:
            if sig["cmd"].lower() in cmd_clean:
                record = {
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "matched_command": sig["cmd"],
                    "full_cmdline": command_line,
                    "category": sig["category"],
                    "severity": sig["severity"],
                    "pid": pid,
                    "process_name": process_name
                }
                with self._lock:
                    self.evasion_events.append(record)
                    if len(self.evasion_events) > 100:
                        self.evasion_events.pop(0)

                if "shadow" in sig["category"] or "recovery" in sig["category"]:
                    self.m_recovery_inhibition.inc(1.0, {"command": sig["cmd"], "pid": str(pid)})
                else:
                    self.m_defense_evasion.inc(1.0, {"category": sig["category"], "pid": str(pid)})
                
                self.m_tampering_events.inc(1.0, {"subsystem": sig["category"]})

                self.log_event(
                    sig["severity"],
                    f"Recovery Inhibition / Defense Evasion Detected: Executed '{sig['cmd']}' by {process_name} (PID: {pid})",
                    record
                )
                return record
        return None

    def record_service_tampering(self, service_name: str, action: str, pid: int = 0):
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "service": service_name,
            "action": action,
            "pid": pid
        }
        self.m_tampering_events.inc(1.0, {"subsystem": "service_control"})
        self.log_event(
            "CRITICAL",
            f"Service Tampering Alert: Service '{service_name}' targeted with action '{action}' by PID {pid}",
            record
        )

    def reset_defense_evasion_telemetry(self):
        """Resets evasion event records and clears defense evasion history back to baseline."""
        with self._lock:
            self.evasion_events.clear()
        self.log_event("INFO", "Defense evasion event logs and counters reset to normal baseline.")

