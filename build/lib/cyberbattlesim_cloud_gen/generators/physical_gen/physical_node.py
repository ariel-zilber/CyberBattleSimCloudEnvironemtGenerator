"""
Physical Topology Generator
===========================
Generates realistic physical node topology:
- Physical nodes with characteristics (CPU, Memory, etc.)
- Maps services/pods to nodes based on affinity
- Simulates network partitioning and zones
- Assigns IP addresses and security groups
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass, field

from cyberbattlesim_cloud_gen.generators.physical_gen.ip_allocation import IPAllocation
from cyberbattlesim_cloud_gen.generators.physical_gen.node_characteristics import (
    NodeCharacteristics,
)

"""
Physical Topology Generator
===========================
Generates realistic physical node topology:
- Physical nodes with characteristics (CPU, Memory, etc.)
- Maps services/pods to nodes based on affinity
- Simulates network partitioning and zones
- Assigns IP addresses and security groups
"""




# physical_node
@dataclass
class PhysicalNode:
    """Represents a physical node in the cluster"""

    node_id: str
    node_type: str
    zone: str
    ip_allocation: IPAllocation
    characteristics: NodeCharacteristics
    assigned_pods: List[Tuple[str, int]] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    properties: List[str] = field(default_factory=list)
    is_healthy: bool = True
    cpu_utilization: float = 0.0
    memory_utilization: float = 0.0
    security_groups: List[str] = field(default_factory=list)
    firewall: Dict = field(default_factory=dict)

    # NEW: Store the calculated asset value (reward) here
    value: int = 0

    def to_dict(self) -> Dict:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value
            if hasattr(self.node_type, "value")
            else str(self.node_type),
            "zone": self.zone,
            "ip_allocation": self.ip_allocation.to_dict(),
            "characteristics": self.characteristics.to_dict(),
            "assigned_pods": [
                {"service": svc, "instance": inst} for svc, inst in self.assigned_pods
            ],
            "labels": self.labels,
            "properties": self.properties,
            "is_healthy": self.is_healthy,
            "cpu_utilization": round(self.cpu_utilization, 2),
            "memory_utilization": round(self.memory_utilization, 2),
            "pod_count": len(self.assigned_pods),
            "security_groups": self.security_groups,
            "firewall": self.firewall,
            "value": self.value,  # Export the value
        }
