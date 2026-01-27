"""
CyberBattleSim Attack Scenario Generator
========================================
Extends NetworkGenerator to create CyberBattleSim attack scenarios from cluster.json.
Includes comprehensive attack path analysis and visualization.

Author: Based on Microsoft CyberBattleSim
Date: 2025-11-09
"""

from typing import Dict, FrozenSet, Set, Tuple, Optional
import matplotlib
from dataclasses import dataclass

from cyberbattle.simulation.vulenrabilites import *

IS_DEBUG = False
# Use non-interactive backend for saving files
matplotlib.use("Agg")
from cyberbattle.simulation.nodes import LeakedCredentials, LeakedNodesId, NodeInfo


@dataclass(frozen=True)
class AttackState:
    """
    Immutable state representation for attack path search.
    Uses frozen sets to allow hashing for visited state tracking.
    """

    owned_nodes: FrozenSet[str]
    known_nodes: FrozenSet[str]
    credentials: FrozenSet[Tuple[str, str, str]]  # (node_id, port/service, credential)
    discovered_properties: FrozenSet[
        Tuple[str, FrozenSet[str]]
    ]  # (node_id, properties)
    current_source: str
    current_destination: str

    def get_owned_total_value(self, non_target_nodes: Set[str]) -> int:
        """Count owned nodes excluding non-targets (like attacker node)"""
        return sum([n.value for n in self.owned_nodes if n not in non_target_nodes])

    def get_owned(self, non_target_nodes: Set[str]) -> int:
        return [n for n in self.owned_nodes if n not in non_target_nodes]

    def get_owned_count(self, non_target_nodes: Set[str]) -> int:
        """Count owned nodes excluding non-targets (like attacker node)"""
        return len([n for n in self.owned_nodes if n not in non_target_nodes])

    def get_properties_dict(self) -> Dict[str, Set[str]]:
        """Convert frozen property data to mutable dict"""
        return {node: set(props) for node, props in self.discovered_properties}

    def has_credential_for_service(
        self,
        node_id: str,
        port: str,
        service_name: str,
        protocol: Optional[str],
        allowed_creds: Set[str],
    ) -> bool:
        """Check if we have valid credentials for a service"""
        if not allowed_creds:
            return True

        for cred in allowed_creds:
            if (
                (node_id, str(port), cred) in self.credentials
                or (node_id, service_name, cred) in self.credentials
                or (protocol and (node_id, protocol, cred) in self.credentials)
                or (node_id, "ALL", cred) in self.credentials
            ):
                return True
        return False

    @classmethod
    def create_initial(
        cls, attacker_node: str, nodes: Dict[str, NodeInfo]
    ) -> "AttackState":
        """Factory method to create initial attack state"""
        owned_nodes = frozenset({attacker_node})
        known_nodes = frozenset({attacker_node})
        credentials = frozenset()

        discovered_properties = frozenset()
        if attacker_node in nodes:
            props = frozenset(nodes[attacker_node].properties)
            discovered_properties = frozenset({(attacker_node, props)})

        return cls(
            owned_nodes=owned_nodes,
            known_nodes=known_nodes,
            credentials=credentials,
            discovered_properties=discovered_properties,
            current_source=attacker_node,
            current_destination=attacker_node,
        )

    def apply_movement(
        self, new_source: Optional[str] = None, new_destination: Optional[str] = None
    ) -> "AttackState":
        """Create new state with updated source/destination"""
        return AttackState(
            owned_nodes=self.owned_nodes,
            known_nodes=self.known_nodes,
            credentials=self.credentials,
            discovered_properties=self.discovered_properties,
            current_source=new_source if new_source else self.current_source,
            current_destination=new_destination
            if new_destination
            else self.current_destination,
        )

    def apply_outcome(
        self, target_node: str, outcome, nodes: Dict[str, NodeInfo]
    ) -> "AttackState":
        """Create new state by applying vulnerability outcome"""
        new_owned = set(self.owned_nodes)
        new_known = set(self.known_nodes)
        new_creds = set(self.credentials)
        props_dict = self.get_properties_dict()

        if isinstance(outcome, LeakedNodesId):
            # Discover new nodes
            new_known.update(outcome.nodes)

        elif isinstance(outcome, LeakedCredentials):
            for c in outcome.credentials:
                if c.node in nodes:
                    new_known.add(c.node)

                new_creds.add((c.node, str(c.port), c.credential))
                new_creds.add((c.node, "ALL", c.credential))

        elif isinstance(
            outcome,
            (
                SystemEscalation,
                AdminEscalation,
                PrivilegeEscalation,
                CustomerData,
                LateralMove,
            ),
        ):
            # Successfully compromised the target
            new_owned.add(target_node)
            new_known.add(target_node)

            # Harvest credentials from newly owned node
            if target_node in nodes:
                for service in nodes[target_node].services:
                    if service.allowedCredentials:
                        for cred in service.allowedCredentials:
                            new_creds.add((target_node, str(service.name), cred))
                            new_creds.add((target_node, service.name, cred))
                            if hasattr(service, "protocol"):
                                new_creds.add((target_node, service.name, cred))

                # Discover credentials point to other nodes
                for n_id, _, _ in new_creds:
                    if n_id in nodes:
                        new_known.add(n_id)

                # Get actual properties
                props_dict[target_node] = set(nodes[target_node].properties)

        return AttackState(
            owned_nodes=frozenset(new_owned),
            known_nodes=frozenset(new_known),
            credentials=frozenset(new_creds),
            discovered_properties=frozenset(
                (n, frozenset(p)) for n, p in props_dict.items()
            ),
            current_source=self.current_source,
            current_destination=self.current_destination,
        )

    def to_dict(self) -> Dict:
        """Convert state to dictionary for output"""
        return {
            "discovered": sorted(list(self.known_nodes)),
            "owned": sorted(list(self.owned_nodes)),
            "creds_count": len(self.credentials),
            "props": {n: list(p) for n, p in self.discovered_properties},
            "current_source": self.current_source,
            "current_destination": self.current_destination,
        }
