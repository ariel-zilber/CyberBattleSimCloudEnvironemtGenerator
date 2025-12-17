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


# ======================================================================
# Node Configuration and Types
# ======================================================================


@dataclass
class IPAllocation:
    """IP address allocation for a node"""

    ipv4: str
    subnet: str
    gateway: str
    cidr: str

    def to_dict(self) -> Dict:
        return asdict(self)
