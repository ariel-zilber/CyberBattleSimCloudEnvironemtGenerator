"""
Physical Topology Generator
===========================
Generates realistic physical node topology:
- Physical nodes with characteristics (CPU, Memory, etc.)
- Maps services/pods to nodes based on affinity
- Simulates network partitioning and zones
- Assigns IP addresses and security groups
"""

from typing import Dict, List
from dataclasses import dataclass, field


@dataclass
class NodeConnection:
    """Represents a network connection between nodes"""

    from_node: str
    to_node: str
    from_ip: str
    to_ip: str
    latency_ms: float
    bandwidth_gbps: float
    packet_loss: float
    is_firewalled: bool = False
    firewall_rules: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "from": self.from_node,
            "to": self.to_node,
            "from_ip": self.from_ip,
            "to_ip": self.to_ip,
            "latency_ms": round(self.latency_ms, 2),
            "bandwidth_gbps": round(self.bandwidth_gbps, 2),
            "packet_loss": round(self.packet_loss, 4),
            "is_firewalled": self.is_firewalled,
            "firewall_rules": self.firewall_rules,
            "allowed_ports": self.allowed_ports,
        }
