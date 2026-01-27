from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict

from cyberbattlesim_network_gen.network_generators.cloud.network_topology_generator import (
    CredentialGrant,
)


class GraphType(Enum):
    """Types of connectivity graphs"""

    KNOWS_CONNECTIVITY = "knows_connectivity"
    KNOWS_REACHABILITY = "knows_reachability"
    ACCESS_CONNECTIVITY = "access_connectivity"
    ACCESS_REACHABILITY = "access_reachability"


@dataclass
class ServiceNode:
    """Represents a service node in the network"""

    name: str
    category: str
    instance_count: int
    port: int
    protocol: str = "TCP"
    is_public: bool = False
    has_authentication: bool = True
    vulnerability_level: float = 0.0
    vulnerabilities: List[Dict] = field(default_factory=list)


@dataclass
class NetworkEdge:
    """Represents a connection between services"""

    source: str
    target: str
    protocol: str
    port: int
    bidirectional: bool = False
    requires_auth: bool = True
    firewall_allowed: bool = True


@dataclass
class NetworkTopology:
    """Complete network topology with all graph types"""

    services: Dict[str, ServiceNode]
    knows_connectivity: List[NetworkEdge]
    knows_reachability: List[str]
    access_connectivity: List[NetworkEdge]
    access_reachability: List[str]
    credential_flow: List[CredentialGrant]
    metadata: Dict
