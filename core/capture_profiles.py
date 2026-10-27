from dataclasses import dataclass
from typing import Dict

@dataclass
class CaptureProfile:
    name: str
    description: str
    raw_buffer_size: int
    max_flows: int
    flow_timeout: float
    ml_enabled: bool
    stats_interval: float
    deep_inspection: bool
    packet_table_batch_ms: int

PROFILES: Dict[str, CaptureProfile] = {
    "Lightweight": CaptureProfile(
        name="Lightweight",
        description="Basic packet statistics, minimal packet details, lower processing overhead, reduced packet-history retention.",
        raw_buffer_size=500,
        max_flows=2000,
        flow_timeout=60.0,
        ml_enabled=False,
        stats_interval=1.5,
        deep_inspection=False,
        packet_table_batch_ms=250
    ),
    "Balanced": CaptureProfile(
        name="Balanced",
        description="Standard packet inspection, normal anomaly detection, existing dashboard functionality.",
        raw_buffer_size=2000,
        max_flows=10000,
        flow_timeout=120.0,
        ml_enabled=True,
        stats_interval=1.0,
        deep_inspection=True,
        packet_table_batch_ms=100
    ),
    "Deep Analysis": CaptureProfile(
        name="Deep Analysis",
        description="Detailed connection tracking, additional anomaly detection, richer metadata, longer configurable history.",
        raw_buffer_size=10000,
        max_flows=50000,
        flow_timeout=300.0,
        ml_enabled=True,
        stats_interval=0.5,
        deep_inspection=True,
        packet_table_batch_ms=50
    ),
}

DEFAULT_PROFILE = "Balanced"

def get_profile(name: str) -> CaptureProfile:
    return PROFILES.get(name, PROFILES[DEFAULT_PROFILE])
