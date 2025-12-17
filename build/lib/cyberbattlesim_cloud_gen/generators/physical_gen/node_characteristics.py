
"""
Physical Topology Generator
===========================
Generates realistic physical node topology:
- Physical nodes with characteristics (CPU, Memory, etc.)
- Maps services/pods to nodes based on affinity
- Simulates network partitioning and zones
- Assigns IP addresses and security groups
"""

from typing import Dict
from dataclasses import dataclass, asdict


@dataclass
class NodeCharacteristics:
    """Physical characteristics of a node"""
    cpu_cores: int
    memory_gb: int
    disk_gb: int
    network_bandwidth_gbps: float
    has_gpu: bool = False
    gpu_count: int = 0
    
    def to_dict(self) -> Dict:
        return asdict(self)

