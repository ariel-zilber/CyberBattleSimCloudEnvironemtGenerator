from dataclasses import dataclass, asdict, field
from typing import Dict, List, Set, Tuple, Optional


@dataclass
class SecurityGroupRule:
    """Network security group rule"""
    rule_id: str
    direction: str  # "ingress" or "egress"
    protocol: str   # "tcp", "udp", "icmp", "all"
    port_range: Optional[Tuple[int, int]]
    source_cidr: str
    destination_cidr: str
    action: str  # "allow" or "deny"
    description: str
    
    def to_dict(self) -> Dict:
        return {
            "rule_id": self.rule_id,
            "direction": self.direction,
            "protocol": self.protocol,
            "port_range": self.port_range,
            "source_cidr": self.source_cidr,
            "destination_cidr": self.destination_cidr,
            "action": self.action,
            "description": self.description
        }

