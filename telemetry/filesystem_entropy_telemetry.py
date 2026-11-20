"""
File-System and Write Entropy Dynamics Telemetry Module (T3)
Monitors real-time file I/O operations, calculates sliding-window Shannon entropy,
detects mass-renaming, and flags known ransomware file extensions.
"""

import time
import os
import threading
from typing import Dict, List, Any, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from telemetry.common import TelemetryModuleBase, calculate_file_entropy, calculate_shannon_entropy

RANSOM_EXTENSIONS = {
    ".locked", ".crypto", ".enc", ".crypted", ".wncry", 
    ".lockbit", ".blackcat", ".conti", ".royal", ".ransom", 
    ".hive", ".phobos", ".makop", ".mallox"
}

class EntropyHandler(FileSystemEventHandler):
    def __init__(self, parent_module: 'FilesystemEntropyTelemetry'):
        super().__init__()
        self.parent = parent_module

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self.parent.process_file_event("modified", event.src_path)

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self.parent.process_file_event("created", event.src_path)

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            self.parent.process_rename_event(event.src_path, event.dest_path)

class FilesystemEntropyTelemetry(TelemetryModuleBase):
    def __init__(self, monitored_dir: str, entropy_threshold: float = 7.85):
        super().__init__(
            name="File-System & Write Entropy",
            code="T3",
            description="Intercepts file writes, computes sliding-window Shannon entropy, and tracks renaming"
        )
        self.monitored_dir = os.path.abspath(monitored_dir)
        self.entropy_threshold = entropy_threshold
        os.makedirs(self.monitored_dir, exist_ok=True)

        # Prometheus metrics
        self.m_entropy = self.register_metric(
            "process_write_entropy_bits", "gauge",
            "Real-time sliding-window Shannon entropy (0.0 to 8.0 bits/byte)"
        )
        self.m_rename_rate = self.register_metric(
            "file_renames_per_sec", "gauge",
            "Rate of mass file renaming and extension alterations"
        )
        self.m_mod_rate = self.register_metric(
            "file_modifications_rate", "gauge",
            "Rate of file modification events per second"
        )
        self.m_high_entropy_count = self.register_metric(
            "high_entropy_files_total", "counter",
            "Cumulative total count of detected high-entropy file writes (> 7.85 bits/byte)"
        )
        self.m_consecutive_entropy = self.register_metric(
            "consecutive_high_entropy_hits", "gauge",
            "Number of consecutive high-entropy evaluations within active window"
        )

        self._observer: Optional[Observer] = None
        self.consecutive_high_entropy = 0
        self.recent_renames: List[float] = []
        self.recent_mods: List[float] = []
        self.inspected_files: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def start(self):
        super().start()
        self._observer = Observer()
        handler = EntropyHandler(self)
        self._observer.schedule(handler, path=self.monitored_dir, recursive=True)
        self._observer.start()
        self.log_event("INFO", f"Filesystem and Entropy Telemetry monitoring started on directory: {self.monitored_dir}")

    def stop(self):
        super().stop()
        if self._observer:
            self._observer.stop()
            self._observer.join()
        self.log_event("INFO", "Filesystem and Entropy Telemetry stopped.")

    def process_file_event(self, action: str, filepath: str, caller_pid: int = 0, caller_name: str = "system"):
        now = time.time()
        with self._lock:
            self.recent_mods.append(now)
            # Prune events older than 10 seconds
            self.recent_mods = [t for t in self.recent_mods if now - t <= 10.0]
            mod_rate = round(len(self.recent_mods) / 10.0, 2)
            self.m_mod_rate.set(mod_rate, {"pid": str(caller_pid), "process_name": caller_name})

        # Calculate Shannon entropy
        entropy = calculate_file_entropy(filepath)
        filename = os.path.basename(filepath)
        _, ext = os.path.splitext(filename)

        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": action,
            "filepath": filepath,
            "filename": filename,
            "extension": ext,
            "entropy": entropy,
            "pid": caller_pid,
            "process_name": caller_name
        }

        with self._lock:
            self.inspected_files.append(record)
            if len(self.inspected_files) > 100:
                self.inspected_files.pop(0)

        # Update metric
        self.m_entropy.set(entropy, {"pid": str(caller_pid), "process_name": caller_name, "file_path": filename})

        # Rule evaluation: entropy > threshold
        if entropy >= self.entropy_threshold:
            self.consecutive_high_entropy += 1
            self.m_consecutive_entropy.set(self.consecutive_high_entropy)
            self.m_high_entropy_count.inc(1.0, {"pid": str(caller_pid)})
            
            if self.consecutive_high_entropy >= 3:
                self.log_event(
                    "CRITICAL",
                    f"Ransomware Encryption Signature: {self.consecutive_high_entropy} consecutive high-entropy writes (Entropy: {entropy} bits/byte) on {filename}",
                    record
                )
            else:
                self.log_event(
                    "HIGH",
                    f"Elevated write entropy detected ({entropy} bits/byte) on {filename}",
                    record
                )
        else:
            self.consecutive_high_entropy = max(0, self.consecutive_high_entropy - 1)
            self.m_consecutive_entropy.set(self.consecutive_high_entropy)

    def process_rename_event(self, src_path: str, dest_path: str, caller_pid: int = 0, caller_name: str = "system"):
        now = time.time()
        with self._lock:
            self.recent_renames.append(now)
            self.recent_renames = [t for t in self.recent_renames if now - t <= 10.0]
            rename_rate = round(len(self.recent_renames) / 10.0, 2)
            self.m_rename_rate.set(rename_rate, {"pid": str(caller_pid), "process_name": caller_name})

        src_name = os.path.basename(src_path)
        dest_name = os.path.basename(dest_path)
        _, dest_ext = os.path.splitext(dest_name)

        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": "renamed",
            "src": src_name,
            "dest": dest_name,
            "extension": dest_ext,
            "pid": caller_pid,
            "process_name": caller_name
        }

        if dest_ext.lower() in RANSOM_EXTENSIONS:
            self.log_event(
                "CRITICAL",
                f"Ransomware File Extension Append detected: '{src_name}' -> '{dest_name}' (Target ext: {dest_ext})",
                record
            )
        elif rename_rate > 2.0:
            self.log_event(
                "HIGH",
                f"Rapid mass file renaming burst detected ({rename_rate} renames/sec)",
                record
            )
        else:
            self.log_event("INFO", f"File renamed: {src_name} -> {dest_name}", record)

    def get_latest_entropy_data(self) -> Dict[str, Any]:
        with self._lock:
            latest = self.inspected_files[-1] if self.inspected_files else {}
            recent = list(self.inspected_files[-15:])
            return {
                "latest_entropy": latest.get("entropy", 0.0),
                "consecutive_high_entropy": self.consecutive_high_entropy,
                "recent_inspected_files": recent,
                "entropy_threshold": self.entropy_threshold
            }

    def reset_entropy_data(self):
        """Resets entropy sliding windows, consecutive high entropy counts, and inspected files back to baseline."""
        with self._lock:
            self.inspected_files.clear()
            self.consecutive_high_entropy = 0
            self.recent_renames.clear()
            self.recent_mods.clear()
        self.m_entropy.set(0.0)
        self.m_rename_rate.set(0.0)
        self.m_mod_rate.set(0.0)
        self.m_consecutive_entropy.set(0)
        self.log_event("INFO", "Filesystem entropy sliding window and rename meters reset to normal baseline.")

