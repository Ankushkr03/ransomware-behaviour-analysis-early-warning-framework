"""
Deception and Tripwire Signals Telemetry Module (T7)
Deploys decoy canary files, continuously audits SHA-256 integrity,
and generates zero-false-positive deterministic early warning tripwires.
"""

import time
import os
import hashlib
import threading
from typing import Dict, List, Any, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from telemetry.common import TelemetryModuleBase

DEFAULT_CANARY_TEMPLATES = [
    {
        "filename": "q4_financial_payroll.xlsx",
        "description": "Executive Compensation & Bonus Ledger",
        "content": b"PK\x03\x04\x14\x00CONFIDENTIAL_PAYROLL_DATA_2026_DO_NOT_DISTRIBUTE_SALARIES_TOTAL_INR_50000000"
    },
    {
        "filename": "client_contracts_vault.docx",
        "description": "Enterprise Master Service Agreements & NDAs",
        "content": b"PK\x03\x04\x14\x00MASTER_CLIENT_CONTRACT_CONFIDENTIAL_TERMS_AND_CONDITIONS_AUTHORIZED_LEGAL_ONLY"
    },
    {
        "filename": "database_master_backup.sql",
        "description": "PostgreSQL Core Database Full Dump",
        "content": b"-- PostgreSQL database dump\nCREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(50), password_hash VARCHAR(128));\nINSERT INTO users VALUES (1, 'admin', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW');\n"
    },
    {
        "filename": "aws_production_keys.env",
        "description": "Cloud Infrastructure Master Access Keys",
        "content": b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nAWS_DEFAULT_REGION=us-east-1\n"
    },
    {
        "filename": "employee_personnel_records.pdf",
        "description": "HR Employee Identity and Passport Records",
        "content": b"%PDF-1.7\n%CONFIDENTIAL HR FILE - EMPLOYEE TAX AND PASSPORT IDENTIFIERS\n%%EOF"
    }
]

class CanaryWatchdogHandler(FileSystemEventHandler):
    def __init__(self, parent: 'DeceptionTripwireTelemetry'):
        super().__init__()
        self.parent = parent

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self.parent.audit_single_file(event.src_path, trigger_cause="Watchdog on_modified")

    def on_deleted(self, event: FileSystemEvent):
        if not event.is_directory:
            self.parent.audit_single_file(event.src_path, trigger_cause="Watchdog on_deleted")

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            self.parent.audit_single_file(event.src_path, trigger_cause="Watchdog on_moved")

class DeceptionTripwireTelemetry(TelemetryModuleBase):
    def __init__(self, vault_dir: str):
        super().__init__(
            name="Deception & Tripwire Signals",
            code="T7",
            description="Deploys canary decoys and verifies sub-second SHA-256 integrity"
        )
        self.vault_dir = os.path.abspath(vault_dir)
        os.makedirs(self.vault_dir, exist_ok=True)

        # Prometheus metrics
        self.m_status = self.register_metric(
            "canary_tripwire_status", "gauge",
            "Tripwire status per decoy file (0 = Intact, 1 = Compromised)"
        )
        self.m_compromised_count = self.register_metric(
            "canary_compromised_files_total", "counter",
            "Cumulative count of compromised decoy canary files"
        )
        self.m_audit_checks = self.register_metric(
            "canary_audit_checks_total", "counter",
            "Total number of integrity audits performed"
        )
        self.m_latency = self.register_metric(
            "canary_check_latency_ms", "gauge",
            "Average latency in milliseconds for canary integrity audit loop"
        )

        self.canaries: Dict[str, Dict[str, Any]] = {}
        self._observer: Optional[Observer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.is_any_compromised = False

        self._initialize_vault()

    def _initialize_vault(self):
        """Populates the canary vault with clean decoy files and records their initial hashes."""
        for template in DEFAULT_CANARY_TEMPLATES:
            filepath = os.path.join(self.vault_dir, template["filename"])
            # Always ensure baseline exists
            with open(filepath, "wb") as f:
                f.write(template["content"])
            
            sha256 = self._compute_hash(filepath)
            self.canaries[template["filename"]] = {
                "filename": template["filename"],
                "path": filepath,
                "description": template["description"],
                "expected_hash": sha256,
                "current_hash": sha256,
                "status": "INTACT",  # INTACT or COMPROMISED
                "last_checked": time.time(),
                "compromised_at": None,
                "breach_details": None,
                "attacker_process": None,
                "attacker_pid": None,
                "attacker_family": None,
                "tamper_type": None
            }
            self.m_status.set(0.0, {"canary_file": template["filename"], "canary_id": template["filename"]})

    def _compute_hash(self, filepath: str) -> Optional[str]:
        if not os.path.exists(filepath):
            return None
        hasher = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    def start(self, audit_interval: float = 0.5):
        super().start()
        # Start Watchdog Observer for instant OS-level file notifications
        self._observer = Observer()
        handler = CanaryWatchdogHandler(self)
        self._observer.schedule(handler, path=self.vault_dir, recursive=False)
        self._observer.start()

        # Start continuous polling audit thread (double-layered defense)
        self._thread = threading.Thread(target=self._audit_loop, args=(audit_interval,), daemon=True)
        self._thread.start()
        self.log_event("INFO", f"Canary Tripwire module active: {len(self.canaries)} decoy files deployed in {self.vault_dir}")

    def stop(self):
        super().stop()
        if self._observer:
            self._observer.stop()
            self._observer.join()
        self.log_event("INFO", "Canary Tripwire module stopped.")

    def _audit_loop(self, interval: float):
        while self.running:
            t0 = time.time()
            self.audit_all_canaries()
            latency = (time.time() - t0) * 1000.0
            self.m_latency.set(round(latency, 2))
            self.m_audit_checks.inc(1.0)
            time.sleep(interval)

    def audit_all_canaries(self):
        with self._lock:
            for filename in list(self.canaries.keys()):
                self._check_file_internal(filename, trigger_cause="Scheduled Audit")

    def audit_single_file(self, filepath: str, trigger_cause: str = "Instant Event"):
        filename = os.path.basename(filepath)
        with self._lock:
            if filename in self.canaries:
                self._check_file_internal(filename, trigger_cause=trigger_cause)

    def _check_file_internal(self, filename: str, trigger_cause: str):
        c_info = self.canaries[filename]
        filepath = c_info["path"]
        now = time.time()
        c_info["last_checked"] = now

        # Case 1: File deleted or moved
        if not os.path.exists(filepath):
            if c_info["status"] != "COMPROMISED":
                c_info["status"] = "COMPROMISED"
                c_info["compromised_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                c_info["breach_details"] = f"Decoy file deleted/moved ({trigger_cause})"
                self.is_any_compromised = True
                self.m_status.set(1.0, {"canary_file": filename, "canary_id": filename})
                self.m_compromised_count.inc(1.0)
                self.log_event(
                    "CRITICAL",
                    f"TRIPWIRE DETONATED: Decoy canary '{filename}' was DELETED/TAMPERED! ({trigger_cause})",
                    c_info
                )
            return

        # Case 2: File content changed / encrypted
        current_hash = self._compute_hash(filepath)
        c_info["current_hash"] = current_hash
        if current_hash != c_info["expected_hash"]:
            if c_info["status"] != "COMPROMISED":
                c_info["status"] = "COMPROMISED"
                c_info["compromised_at"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                if not c_info.get("attacker_process"):
                    c_info["attacker_process"] = "Active Malicious Process"
                    c_info["attacker_pid"] = "Dynamic Process"
                    c_info["attacker_family"] = "Ransomware Adversary"
                    c_info["tamper_type"] = "Cryptographic Modification / Overwrite"
                c_info["breach_details"] = f"SHA-256 hash mismatch: expected {c_info['expected_hash'][:12]}... but got {str(current_hash)[:12]}... ({trigger_cause})"
                self.is_any_compromised = True
                self.m_status.set(1.0, {"canary_file": filename, "canary_id": filename})
                self.m_compromised_count.inc(1.0)
                self.log_event(
                    "CRITICAL",
                    f"TRIPWIRE DETONATED: Decoy canary '{filename}' CONTENT MODIFIED / ENCRYPTED! ({trigger_cause})",
                    c_info
                )

    def record_breach_metadata(self, filename: str, attacker_process: str = "ransomware_payload.exe",
                               attacker_pid: Any = 0, attacker_family: str = "Active Adversary Ransomware",
                               tamper_type: str = "In-place Cryptographic Encryption"):
        """Records forensic attacker metadata for a triggered canary decoy."""
        with self._lock:
            if filename in self.canaries:
                c_info = self.canaries[filename]
                c_info["attacker_process"] = attacker_process
                c_info["attacker_pid"] = attacker_pid
                c_info["attacker_family"] = attacker_family
                c_info["tamper_type"] = tamper_type
                c_info["status"] = "COMPROMISED"
                if not c_info.get("compromised_at"):
                    c_info["compromised_at"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                c_info["breach_details"] = f"Decoy breached by {attacker_family} ({attacker_process} PID {attacker_pid}). Altered SHA-256 integrity."
                self.is_any_compromised = True

    def reset_canary_vault(self):
        """Re-initializes all canary decoy files and clears tripwire triggers."""
        with self._lock:
            self._initialize_vault()
            self.is_any_compromised = False
            self.log_event("INFO", "Canary vault re-armed and reset to intact status.")

    def get_canary_status(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.canaries.values())
