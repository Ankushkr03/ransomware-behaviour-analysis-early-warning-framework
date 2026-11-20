"""
Host and Process Telemetry Module (T2)
Monitors running processes, parent-child relationships, command-line arguments,
non-standard directory executions, and computes process threat indicators.
"""

import time
import os
import threading
import psutil
from typing import Dict, List, Any, Optional
from telemetry.common import TelemetryModuleBase

SUSPICIOUS_PATHS = [
    "/tmp", "/var/tmp", "/dev/shm",
    "\\AppData\\Local\\Temp\\", "\\Users\\Public\\", "\\Windows\\Temp\\"
]

SUSPICIOUS_SHELL_NAMES = ["bash", "sh", "zsh", "cmd.exe", "powershell.exe", "pwsh.exe"]

SUSPICIOUS_KEYWORDS = [
    "vssadmin", "wmic", "bcdedit", "wbadmin", "wevtutil",
    "cipher", "encrypt", "ransom", "shadowcopy", "taskkill", "certutil"
]

class HostProcessTelemetry(TelemetryModuleBase):
    def __init__(self):
        super().__init__(
            name="Host & Process Telemetry",
            code="T2",
            description="Tracks process ancestry, suspicious execution directories, and shell spawns"
        )
        # Register Prometheus metrics
        self.m_threat_score = self.register_metric(
            "process_threat_score", "gauge",
            "Dynamic composite process risk score (0.0 to 1.0)"
        )
        self.m_suspicious_spawns = self.register_metric(
            "suspicious_process_spawns_total", "counter",
            "Cumulative count of policy violations in process ancestry"
        )
        self.m_process_cpu = self.register_metric(
            "process_cpu_percent", "gauge",
            "CPU utilization percent per monitored process"
        )
        self.m_process_mem = self.register_metric(
            "process_memory_mb", "gauge",
            "Resident memory usage in MB per monitored process"
        )
        self.m_active_count = self.register_metric(
            "monitored_processes_count", "gauge",
            "Total number of active processes inspected by telemetry agent"
        )

        self._thread: Optional[threading.Thread] = None
        self.monitored_pids: Dict[int, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def start(self, poll_interval: float = 2.0):
        super().start()
        self._thread = threading.Thread(target=self._monitor_loop, args=(poll_interval,), daemon=True)
        self._thread.start()
        self.log_event("INFO", "Host and Process Telemetry collector initialized and active.")

    def _monitor_loop(self, interval: float):
        while self.running:
            try:
                self.inspect_system_processes()
            except Exception as e:
                self.log_event("WARNING", f"Error during process inspection: {str(e)}")
            time.sleep(interval)

    def inspect_system_processes(self) -> List[Dict[str, Any]]:
        findings = []
        count = 0
        current_time = time.time()

        current_pid = os.getpid()
        parent_pid = os.getppid()
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe', 'ppid', 'username', 'cpu_percent', 'memory_info']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                if pid == current_pid or pid == parent_pid or pid <= 1:
                    continue
                name = pinfo['name'] or ""
                cmdline_list = pinfo.get('cmdline') or []
                cmdline = " ".join(cmdline_list)
                exe = pinfo.get('exe') or ""
                ppid = pinfo.get('ppid')
                user = pinfo.get('username') or "unknown"
                count += 1

                # Calculate process specific risk score
                score = 0.05  # baseline normal process score
                flags = []

                # Check non-standard or temp directory execution
                for sp in SUSPICIOUS_PATHS:
                    if sp.lower() in exe.lower():
                        score += 0.35
                        flags.append(f"Exec from suspicious path: {exe}")
                        break

                # Check suspicious command line keywords
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw.lower() in cmdline.lower():
                        score += 0.45
                        flags.append(f"Suspicious command argument: {kw}")
                        break

                # Check suspicious shell spawning
                parent_name = "unknown"
                if ppid:
                    try:
                        parent = psutil.Process(ppid)
                        parent_name = parent.name()
                        if name.lower() in SUSPICIOUS_SHELL_NAMES and parent_name.lower() not in ["bash", "sh", "systemd", "login", "sshd", "gnome-terminal"]:
                            score += 0.30
                            flags.append(f"Unusual shell parent: {parent_name} -> {name}")
                            self.m_suspicious_spawns.inc(1.0, {"parent": parent_name, "child": name, "pid": str(pid)})
                    except Exception:
                        pass

                # Cap score at 1.0
                score = min(round(score, 3), 1.0)
                mem_mb = round((pinfo['memory_info'].rss / (1024 * 1024)), 2) if pinfo.get('memory_info') else 0.0
                cpu = pinfo.get('cpu_percent') or 0.0

                proc_data = {
                    "pid": pid,
                    "name": name,
                    "parent_name": parent_name,
                    "ppid": ppid,
                    "cmdline": cmdline[:180],
                    "exe": exe,
                    "user": user,
                    "threat_score": score,
                    "flags": flags,
                    "cpu_percent": cpu,
                    "memory_mb": mem_mb,
                    "last_seen": current_time
                }

                if score >= 0.40:
                    with self._lock:
                        self.monitored_pids[pid] = proc_data
                    findings.append(proc_data)
                    self.m_threat_score.set(score, {"pid": str(pid), "process_name": name, "user": user})
                    self.m_process_cpu.set(cpu, {"pid": str(pid), "process_name": name})
                    self.m_process_mem.set(mem_mb, {"pid": str(pid), "process_name": name})

                    if score >= 0.75:
                        self.log_event("CRITICAL", f"High threat process detected: {name} (PID: {pid}) - Score {score}", proc_data)
                    elif score >= 0.50:
                        self.log_event("WARNING", f"Suspicious process detected: {name} (PID: {pid}) - Score {score}", proc_data)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self.m_active_count.set(count)
        return findings

    def inject_simulated_process(self, pid: int, name: str, cmdline: str, score: float, flags: List[str]):
        """Helper to inject or update a monitored process (for testing or simulated malware)."""
        proc_data = {
            "pid": pid,
            "name": name,
            "parent_name": "cmd_runner",
            "ppid": 9999,
            "cmdline": cmdline,
            "exe": f"/tmp/{name}",
            "user": "root",
            "threat_score": score,
            "flags": flags,
            "cpu_percent": 12.5,
            "memory_mb": 45.2,
            "last_seen": time.time(),
            "injected_at": time.time()
        }
        with self._lock:
            self.monitored_pids[pid] = proc_data
        self.m_threat_score.set(score, {"pid": str(pid), "process_name": name, "user": "root"})
        self.m_suspicious_spawns.inc(1.0, {"parent": "cmd_runner", "child": name, "pid": str(pid)})
        self.log_event("CRITICAL" if score >= 0.75 else "WARNING",
                       f"Injected telemetry for suspicious process: {name} (PID {pid})", proc_data)

    def remove_process(self, pid: int):
        with self._lock:
            if pid in self.monitored_pids:
                del self.monitored_pids[pid]

    def get_flagged_processes(self) -> List[Dict[str, Any]]:
        with self._lock:
            # Sort by threat_score descending
            return sorted(self.monitored_pids.values(), key=lambda x: x["threat_score"], reverse=True)

    def clear_all_flagged_processes(self):
        """Clears all monitored and injected flagged processes back to normal baseline."""
        with self._lock:
            self.monitored_pids.clear()
        self.m_active_count.set(0)
        self.log_event("INFO", "All flagged and simulated processes cleared. Host process baseline restored.")

