"""
Common utilities, Shannon Entropy calculation, and Prometheus Metrics exposition
for the Ransomware Behaviour Analysis and Early Warning Framework.
"""

import math
import time
import os
import threading
from typing import Dict, List, Any, Optional

def calculate_shannon_entropy(data: bytes) -> float:
    """
    Computes Shannon Entropy in bits per byte (0.0 to 8.0).
    Ransomware encrypted blocks typically exhibit entropy > 7.85 bits/byte.
    """
    if not data:
        return 0.0
    length = len(data)
    frequencies = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1
    
    entropy = 0.0
    for count in frequencies.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)

def calculate_file_entropy(filepath: str, sample_size: int = 65536) -> float:
    """
    Computes Shannon Entropy for a file using sliding-window sample chunks.
    """
    if not os.path.exists(filepath) or os.path.isdir(filepath):
        return 0.0
    try:
        size = os.path.getsize(filepath)
        if size == 0:
            return 0.0
        with open(filepath, 'rb') as f:
            if size <= sample_size:
                data = f.read()
                return calculate_shannon_entropy(data)
            else:
                # Sample head, middle, and tail for sliding-window representation
                f.seek(0)
                head = f.read(sample_size // 3)
                f.seek(max(0, size // 2 - sample_size // 6))
                mid = f.read(sample_size // 3)
                f.seek(max(0, size - sample_size // 3))
                tail = f.read(sample_size // 3)
                return calculate_shannon_entropy(head + mid + tail)
    except Exception:
        return 0.0

class PrometheusMetric:
    """
    Represents an individual Prometheus metric (Gauge or Counter) with labels.
    """
    def __init__(self, name: str, mtype: str, help_text: str):
        self.name = name
        self.mtype = mtype.lower()  # 'gauge' or 'counter'
        self.help_text = help_text
        self.samples: Dict[str, tuple[float, Dict[str, str]]] = {}
        self._lock = threading.Lock()

    def set(self, value: float, labels: Optional[Dict[str, str]] = None):
        labels = labels or {}
        key = self._format_key(labels)
        with self._lock:
            self.samples[key] = (float(value), labels)

    def inc(self, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        labels = labels or {}
        key = self._format_key(labels)
        with self._lock:
            current_val, _ = self.samples.get(key, (0.0, labels))
            self.samples[key] = (current_val + float(value), labels)

    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        labels = labels or {}
        key = self._format_key(labels)
        with self._lock:
            val, _ = self.samples.get(key, (0.0, labels))
            return val

    def _format_key(self, labels: Dict[str, str]) -> str:
        return ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))

    def render_prometheus_text(self) -> str:
        with self._lock:
            lines = [
                f"# HELP {self.name} {self.help_text}",
                f"# TYPE {self.name} {self.mtype}"
            ]
            if not self.samples:
                lines.append(f"{self.name} 0")
            else:
                for key, (val, labels) in self.samples.items():
                    if labels:
                        lbl_str = "{" + key + "}"
                        lines.append(f"{self.name}{lbl_str} {val}")
                    else:
                        lines.append(f"{self.name} {val}")
            return "\n".join(lines)

class TelemetryModuleBase:
    """
    Abstract base class for each of the 6 telemetry modules.
    """
    def __init__(self, name: str, code: str, description: str):
        self.name = name
        self.code = code  # e.g., T2, T3, T4, T5, T6, T7
        self.description = description
        self.running = False
        self.metrics: Dict[str, PrometheusMetric] = {}
        self.events: List[Dict[str, Any]] = []
        self._events_lock = threading.Lock()
        self.max_events = 200

    def register_metric(self, name: str, mtype: str, help_text: str) -> PrometheusMetric:
        metric = PrometheusMetric(name, mtype, help_text)
        self.metrics[name] = metric
        return metric

    def log_event(self, severity: str, message: str, details: Optional[Dict[str, Any]] = None):
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "module": self.name,
            "code": self.code,
            "severity": severity.upper(),  # INFO, WARNING, HIGH, CRITICAL
            "message": message,
            "details": details or {}
        }
        with self._events_lock:
            self.events.append(event)
            if len(self.events) > self.max_events:
                self.events.pop(0)

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._events_lock:
            return list(self.events[-limit:])

    def render_all_metrics(self) -> str:
        blocks = []
        for metric in self.metrics.values():
            blocks.append(metric.render_prometheus_text())
        return "\n\n".join(blocks) + "\n"

    def start(self):
        self.running = True

    def stop(self):
        self.running = False
