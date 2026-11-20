"""
Network and Exfiltration Signals Telemetry Module (T5)
Monitors network sockets, internal lateral movement channels (SMB 445, RPC 135, RDP 3389),
outbound C2 beaconing, and suspicious exfiltration data-transfer spikes.
"""

import time
import threading
import psutil
from typing import Dict, List, Any, Optional
from telemetry.common import TelemetryModuleBase

LATERAL_PORTS = {445: "SMB", 135: "RPC", 3389: "RDP", 22: "SSH", 5985: "WinRM"}

class NetworkExfilTelemetry(TelemetryModuleBase):
    def __init__(self):
        super().__init__(
            name="Network & Exfiltration Signals",
            code="T5",
            description="Tracks lateral movement (SMB/RPC/RDP), outbound C2 beacons, and bandwidth spikes"
        )
        # Register Prometheus metrics
        self.m_outbound_bytes = self.register_metric(
            "network_outbound_bytes_total", "counter",
            "Cumulative outbound network bytes transmitted"
        )
        self.m_c2_beacons = self.register_metric(
            "network_c2_beacons_total", "counter",
            "Outbound Command & Control (C2) beaconing signals flagged"
        )
        self.m_lateral_scans = self.register_metric(
            "network_lateral_scan_attempts_total", "counter",
            "Internal network lateral movement attempts across ports 445, 135, 3389"
        )
        self.m_active_conn = self.register_metric(
            "network_active_connections", "gauge",
            "Number of active established TCP/UDP network connections"
        )
        self.m_bandwidth_rate = self.register_metric(
            "network_bandwidth_out_mb_rate", "gauge",
            "Current outbound throughput rate in MB/s"
        )

        self._thread: Optional[threading.Thread] = None
        self.last_net_bytes = 0
        self.last_sample_time = time.time()
        self.connection_history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def start(self, poll_interval: float = 2.0):
        super().start()
        try:
            io_counters = psutil.net_io_counters()
            self.last_net_bytes = io_counters.bytes_sent
        except Exception:
            self.last_net_bytes = 0
        self.last_sample_time = time.time()

        self._thread = threading.Thread(target=self._monitor_loop, args=(poll_interval,), daemon=True)
        self._thread.start()
        self.log_event("INFO", "Network and Exfiltration Telemetry collector started.")

    def _monitor_loop(self, interval: float):
        while self.running:
            try:
                self.inspect_network_state()
            except Exception as e:
                self.log_event("WARNING", f"Error during network inspection: {str(e)}")
            time.sleep(interval)

    def inspect_network_state(self):
        now = time.time()
        # Bandwidth calculation
        try:
            io_counters = psutil.net_io_counters()
            current_sent = io_counters.bytes_sent
            elapsed = max(0.1, now - self.last_sample_time)
            diff_mb = (current_sent - self.last_net_bytes) / (1024 * 1024)
            rate_mb_s = round(diff_mb / elapsed, 2)
            self.last_net_bytes = current_sent
            self.last_sample_time = now
            self.m_bandwidth_rate.set(rate_mb_s)
        except Exception:
            pass

        # Inspect connections
        try:
            conns = psutil.net_connections(kind='inet')
            self.m_active_conn.set(len(conns), {"protocol": "tcp"})

            for c in conns:
                if c.raddr:
                    r_ip = c.raddr.ip
                    r_port = c.raddr.port
                    l_port = c.laddr.port if c.laddr else 0
                    pid = c.pid or 0

                    if r_port in LATERAL_PORTS:
                        service = LATERAL_PORTS[r_port]
                        self.record_lateral_movement(service, r_ip, r_port, pid)
        except Exception:
            pass

    def record_lateral_movement(self, service: str, target_ip: str, port: int, pid: int = 0):
        record = {
            "service": service,
            "target_ip": target_ip,
            "port": port,
            "pid": pid,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        with self._lock:
            self.connection_history.append(record)
            if len(self.connection_history) > 100:
                self.connection_history.pop(0)

        self.m_lateral_scans.inc(1.0, {"port": str(port), "destination_subnet": target_ip})
        self.log_event(
            "HIGH",
            f"Lateral Movement Traffic: Internal connection to {service} (Port {port}) on {target_ip} by PID {pid}",
            record
        )

    def record_c2_beacon(self, destination_ip: str, port: int, pid: int = 0, process_name: str = "unknown"):
        record = {
            "destination_ip": destination_ip,
            "port": port,
            "pid": pid,
            "process_name": process_name,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        with self._lock:
            self.connection_history.append(record)
        self.m_c2_beacons.inc(1.0, {"destination_ip": destination_ip, "port": str(port)})
        self.log_event(
            "CRITICAL",
            f"Outbound C2 Beaconing Detected: Process '{process_name}' (PID {pid}) communicating with C2 node {destination_ip}:{port}",
            record
        )

    def record_exfiltration_burst(self, destination: str, size_mb: float, pid: int = 0):
        bytes_sent = size_mb * 1024 * 1024
        self.m_outbound_bytes.inc(bytes_sent, {"pid": str(pid), "destination": destination})
        self.log_event(
            "HIGH",
            f"Outbound Data Exfiltration Spike: {size_mb} MB transferred to {destination} by PID {pid}",
            {"destination": destination, "size_mb": size_mb, "pid": pid}
        )

    def reset_network_telemetry(self):
        """Resets network connections history, metrics, and gauges back to normal baseline."""
        with self._lock:
            self.connection_history.clear()
        self.m_bandwidth_rate.set(0.0)
        self.log_event("INFO", "Network telemetry counters and connection history reset to normal baseline.")

