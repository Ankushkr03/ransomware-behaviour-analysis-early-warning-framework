"""
Controlled Ransomware & Benign Workload Simulation Engine
Used to validate the 6 telemetry modules, test early detection thresholds,
and demonstrate automated containment and incident reporting.
"""

import os
import time
import random
import threading
from typing import Dict, Any, List

class RansomwareSimulator:
    def __init__(self, monitored_dir: str, canary_vault_dir: str):
        self.monitored_dir = os.path.abspath(monitored_dir)
        self.canary_vault_dir = os.path.abspath(canary_vault_dir)
        os.makedirs(self.monitored_dir, exist_ok=True)
        os.makedirs(self.canary_vault_dir, exist_ok=True)

    def run_benign_workload(self, count: int = 5) -> Dict[str, Any]:
        """
        Simulates normal office and user workload (writing text, logs, csv).
        Entropy ~3.5 to 4.5 bits/byte. Should NOT trigger alarms.
        """
        created = []
        for i in range(count):
            filename = f"benign_doc_{int(time.time())}_{i}.txt"
            filepath = os.path.join(self.monitored_dir, filename)
            content = f"Standard system documentation entry {i}.\n" + \
                      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 15 + \
                      f"\nTimestamp: {time.ctime()}\n"
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            created.append(filepath)
            time.sleep(0.1)

        return {
            "status": "COMPLETED",
            "simulation": "BENIGN_WORKLOAD",
            "files_created": len(created),
            "expected_entropy": "~4.0 bits/byte",
            "message": "Benign workload simulation completed. Normal system baseline maintained."
        }

    def run_canary_tamper_simulation(self) -> Dict[str, Any]:
        """
        Tampering with a canary decoy file to trigger sub-second zero-false-positive detection.
        """
        canary_files = [f for f in os.listdir(self.canary_vault_dir) if os.path.isfile(os.path.join(self.canary_vault_dir, f))]
        if not canary_files:
            return {"status": "FAILED", "message": "No canary files found in vault."}

        target_file = random.choice(canary_files)
        target_path = os.path.join(self.canary_vault_dir, target_file)

        # Overwrite with high entropy fake encrypted bytes
        with open(target_path, "wb") as f:
            f.write(os.urandom(2048))

        return {
            "status": "COMPLETED",
            "simulation": "CANARY_TAMPER",
            "target_canary": target_file,
            "target_path": target_path,
            "message": f"Decoy file '{target_file}' tampered! Instant sub-second tripwire trigger dispatched."
        }

    def run_encryption_burst_simulation(self, count: int = 8, ext: str = ".locked") -> Dict[str, Any]:
        """
        Simulates active ransomware encryption: creates high-entropy byte streams (> 7.85 bits/byte)
        and renames files with ransomware extension (e.g. .wncry, .lockbit, .alphv, etc).
        """
        if not ext.startswith("."):
            ext = f".{ext}"
        encrypted_files = []
        for i in range(count):
            base_name = f"critical_database_export_{i}.dat"
            orig_path = os.path.join(self.monitored_dir, base_name)
            
            # Step 1: Write initial data
            with open(orig_path, "wb") as f:
                f.write(f"Normal corporate database table records chunk {i}".encode() * 20)

            time.sleep(0.04)

            # Step 2: Overwrite with cryptographic pseudo-random bytes (Entropy > 7.9)
            enc_data = os.urandom(8192)
            with open(orig_path, "wb") as f:
                f.write(enc_data)

            # Step 3: Rename to target ransomware extension
            locked_path = os.path.join(self.monitored_dir, f"{base_name}{ext}")
            if os.path.exists(locked_path):
                os.remove(locked_path)
            os.rename(orig_path, locked_path)
            encrypted_files.append(locked_path)
            time.sleep(0.05)

        return {
            "status": "COMPLETED",
            "simulation": "HIGH_ENTROPY_ENCRYPTION_BURST",
            "files_encrypted": len(encrypted_files),
            "extension": ext,
            "entropy": "> 7.9 bits/byte",
            "message": f"Simulated {count} high-entropy encrypted file writes with {ext} extension."
        }

    def run_defense_evasion_simulation(self) -> Dict[str, Any]:
        """
        Simulates executing recovery inhibition command (vssadmin delete shadows).
        """
        simulated_command = "vssadmin delete shadows /all /quiet"
        return {
            "status": "COMPLETED",
            "simulation": "DEFENSE_EVASION",
            "command": simulated_command,
            "message": f"Simulated execution of shadow copy destruction: '{simulated_command}'"
        }

    def run_network_exfil_simulation(self) -> Dict[str, Any]:
        """
        Simulates lateral scan and C2 beaconing.
        """
        return {
            "status": "COMPLETED",
            "simulation": "NETWORK_C2_EXFIL",
            "c2_endpoint": "198.51.100.42:8443",
            "lateral_ports": [445, 3389],
            "volume_mb": 15.4,
            "message": "Simulated C2 beaconing and lateral internal scanning bursts."
        }
