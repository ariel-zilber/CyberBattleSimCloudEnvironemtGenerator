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
from dataclasses import dataclass

from cyberbattlesim_cloud_gen.generators.physical_gen.security_group_rule import (
    SecurityGroupRule,
)


@dataclass
class SecurityGroup:
    """Network security group for a zone"""

    group_id: str
    zone: str
    name: str
    rules: List[SecurityGroupRule]

    def to_dict(self) -> Dict:
        return {
            "group_id": self.group_id,
            "zone": self.zone,
            "name": self.name,
            "rules": [rule.to_dict() for rule in self.rules],
        }
