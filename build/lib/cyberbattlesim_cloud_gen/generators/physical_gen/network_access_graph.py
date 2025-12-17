from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict, field

# 

@dataclass
class NetworkAccessGraph:
    """Represents network accessibility between nodes"""
    source_node: str
    destination_node: str
    source_ip: str
    destination_ip: str
    accessible: bool
    allowed_ports: List[int]
    blocked_ports: List[int]
    path_latency: float
    firewall_rules_applied: List[str]
    
    def to_dict(self) -> Dict:
        return {
            "source_node": self.source_node,
            "destination_node": self.destination_node,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "accessible": self.accessible,
            "allowed_ports": self.allowed_ports,
            "blocked_ports": self.blocked_ports,
            "path_latency": round(self.path_latency, 2),
            "firewall_rules_applied": self.firewall_rules_applied
        }

