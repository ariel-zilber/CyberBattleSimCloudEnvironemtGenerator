"""
Interactive Attack Path Solver with Web UI Export

This module provides an interactive solver that exports simulation state
to JSON format for use with a web-based visualization interface.
"""

import ipaddress
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum

# These imports would come from your existing codebase
# from cyberbattle.simulation.firewall import RulePermission
# from cyberbattle.simulation.nodes import NodeInfo
# from cyberbattle.simulation.vulenrabilites import (
#     LateralMove,
#     VulnerabilityInfo,
#     VulnerabilityType,
# )
# from cyberbattlesim_cloud_gen.attack_path.attack_state import AttackState

# For standalone demo, we'll define minimal versions:


class RulePermission(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass
class FirewallRule:
    permission: RulePermission
    subnet: str
    port: str


@dataclass
class Firewall:
    incoming: List[FirewallRule] = field(default_factory=list)
    outgoing: List[FirewallRule] = field(default_factory=list)


@dataclass
class NetworkInfo:
    ip_address: str


@dataclass
class Service:
    name: str
    allowedCredentials: List[str] = field(default_factory=list)
    protocol: Optional[str] = None


class VulnerabilityType(Enum):
    LOCAL = "LOCAL"
    REMOTE = "REMOTE"


@dataclass
class VulnerabilityOutcome:
    """Represents the outcome of exploiting a vulnerability"""

    nodes_discovered: List[str] = field(default_factory=list)
    credentials_discovered: List[Dict[str, Any]] = field(default_factory=list)
    lateral_move: bool = False


@dataclass
class VulnerabilityInfo:
    name: str
    type: VulnerabilityType
    outcome: Optional[VulnerabilityOutcome]
    cost: float = 1.0
    description: str = ""


# @dataclass
# class NodeInfo:
#     id: str
#     vulnerabilities: Dict[str, VulnerabilityInfo] = field(default_factory=dict)
#     services: List[Service] = field(default_factory=list)
#     network_info: List[NetworkInfo] = field(default_factory=list)
#     firewall: Firewall = field(default_factory=Firewall)
#     properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackState:
    """Represents the current state of an attack simulation"""

    current_source: str
    current_destination: str
    owned_nodes: frozenset
    known_nodes: frozenset
    credentials: frozenset

    def __hash__(self):
        return hash(
            (
                self.current_source,
                self.current_destination,
                self.owned_nodes,
                self.known_nodes,
                self.credentials,
            )
        )

    def __eq__(self, other):
        if not isinstance(other, AttackState):
            return False
        return (
            self.current_source == other.current_source
            and self.current_destination == other.current_destination
            and self.owned_nodes == other.owned_nodes
            and self.known_nodes == other.known_nodes
            and self.credentials == other.credentials
        )

    @classmethod
    def create_initial(
        cls, attacker_node: str, nodes: Dict[str, NodeInfo]
    ) -> "AttackState":
        """Create initial attack state"""
        return cls(
            current_source=attacker_node,
            current_destination=attacker_node,
            owned_nodes=frozenset({attacker_node}),
            known_nodes=frozenset({attacker_node}),
            credentials=frozenset(),
        )

    def get_owned_count(self, exclude_nodes: set) -> int:
        """Get count of owned nodes excluding specified nodes"""
        return len(self.owned_nodes - exclude_nodes)

    def has_credential_for_service(
        self,
        target_node: str,
        service_name: str,
        port: str,
        protocol: Optional[str],
        allowed_creds: set,
    ) -> bool:
        """Check if we have credentials for a service"""
        for cred in self.credentials:
            if isinstance(cred, tuple) and len(cred) >= 2:
                cred_name = cred[0]
                if cred_name in allowed_creds:
                    return True
        return False

    def apply_movement(
        self, new_source: str = None, new_destination: str = None
    ) -> "AttackState":
        """Apply movement action and return new state"""
        return AttackState(
            current_source=new_source if new_source else self.current_source,
            current_destination=new_destination
            if new_destination
            else self.current_destination,
            owned_nodes=self.owned_nodes,
            known_nodes=self.known_nodes,
            credentials=self.credentials,
        )

    def apply_outcome(
        self,
        target_node: str,
        outcome: VulnerabilityOutcome,
        nodes: Dict[str, NodeInfo],
    ) -> "AttackState":
        """Apply vulnerability outcome and return new state"""
        new_owned = set(self.owned_nodes)
        new_known = set(self.known_nodes)
        new_creds = set(self.credentials)

        if outcome.lateral_move:
            new_owned.add(target_node)
            new_known.add(target_node)

        if outcome.nodes_discovered:
            for node in outcome.nodes_discovered:
                new_known.add(node)

        if outcome.credentials_discovered:
            for cred in outcome.credentials_discovered:
                cred_tuple = (cred.get("name", ""), cred.get("type", ""))
                new_creds.add(cred_tuple)

        return AttackState(
            current_source=self.current_source,
            current_destination=self.current_destination,
            owned_nodes=frozenset(new_owned),
            known_nodes=frozenset(new_known),
            credentials=frozenset(new_creds),
        )

    def to_dict(self) -> Dict:
        """Convert state to dictionary"""
        return {
            "current_source": self.current_source,
            "current_destination": self.current_destination,
            "owned_nodes": list(self.owned_nodes),
            "known_nodes": list(self.known_nodes),
            "credentials": [
                list(c) if isinstance(c, tuple) else c for c in self.credentials
            ],
        }


@dataclass
class ActionInfo:
    """Represents an available action in the simulation"""

    action_id: str
    action_type: str
    source_node: str
    target_node: str
    name: str
    description: str
    vuln_info: Optional[VulnerabilityInfo]
    service_name: Optional[str]
    cost: float

    def to_dict(self) -> Dict:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "source_node": self.source_node,
            "target_node": self.target_node,
            "name": self.name,
            "description": self.description,
            "cost": self.cost,
            "service_name": self.service_name,
        }


@dataclass
class HistoryEntry:
    """Represents a single step in the attack history"""

    step: int
    action: ActionInfo
    state_before: Dict
    state_after: Dict
    timestamp: float


class InteractiveAttackPathSolver:
    """
    Interactive attack path solver with web UI export capabilities.

    This solver allows users to manually explore attack paths through
    a web-based interface, choosing actions step by step.
    """

    def __init__(self, nodes: Dict[str, NodeInfo], attacker_node: str):
        self.nodes = nodes
        self.attacker_node = attacker_node
        self.non_target_nodes = {attacker_node}
        self.current_state: Optional[AttackState] = None
        self.history: List[HistoryEntry] = []
        self.step_count = 0
        self.start_time = time.time()

        # Initialize state
        self.reset()

    def reset(self):
        """Reset the simulation to initial state"""
        self.current_state = AttackState.create_initial(self.attacker_node, self.nodes)
        self.history = []
        self.step_count = 0
        self.start_time = time.time()

    def _check_firewall_access(
        self, source_node: str, target_node: str, port: str
    ) -> bool:
        """Check if firewall rules allow access from source to target on given port"""
        if source_node not in self.nodes or target_node not in self.nodes:
            return False
        if source_node == target_node:
            return True

        source_info = self.nodes[source_node]
        target_info = self.nodes[target_node]

        # Get IP addresses
        source_ip = "0.0.0.0"
        if source_info.network_info and len(source_info.network_info) > 0:
            source_ip = source_info.network_info[0].ip_address

        target_ip = "0.0.0.0"
        if target_info.network_info and len(target_info.network_info) > 0:
            target_ip = target_info.network_info[0].ip_address

        # Check outgoing rules
        outgoing_allowed = False
        for rule in source_info.firewall.outgoing:
            if rule.permission == RulePermission.ALLOW:
                if str(rule.subnet) in ["0.0.0.0/0", "*"]:
                    if str(rule.port) in ["*", str(port)]:
                        outgoing_allowed = True
                        break
                try:
                    rule_subnet = (
                        str(rule.subnet)
                        if "/" in str(rule.subnet)
                        else f"{rule.subnet}/32"
                    )
                    if target_ip == "0.0.0.0" or ipaddress.ip_address(
                        target_ip
                    ) in ipaddress.ip_network(rule_subnet, strict=False):
                        if str(rule.port) in ["*", str(port)]:
                            outgoing_allowed = True
                            break
                except:
                    continue
        if not outgoing_allowed:
            return False

        # Check incoming rules
        incoming_allowed = False
        for rule in target_info.firewall.incoming:
            if rule.permission == RulePermission.ALLOW:
                if str(rule.subnet) in ["0.0.0.0/0", "*"]:
                    if str(rule.port) in ["*", str(port)]:
                        incoming_allowed = True
                        break
                try:
                    rule_subnet = (
                        str(rule.subnet)
                        if "/" in str(rule.subnet)
                        else f"{rule.subnet}/32"
                    )
                    if source_ip == "0.0.0.0" or ipaddress.ip_address(
                        source_ip
                    ) in ipaddress.ip_network(rule_subnet, strict=False):
                        if str(rule.port) in ["*", str(port)]:
                            incoming_allowed = True
                            break
                except:
                    continue
        return outgoing_allowed and incoming_allowed

    def get_available_actions(self) -> List[ActionInfo]:
        """Get all available actions from current state"""
        if not self.current_state:
            return []

        state = self.current_state
        actions = []
        action_id = 0

        # Attack actions from current source
        if state.current_source in self.nodes:
            # Local exploits
            for v_name, v_info in self.nodes[
                state.current_source
            ].vulnerabilities.items():
                if v_info.type == VulnerabilityType.LOCAL:
                    actions.append(
                        ActionInfo(
                            action_id=f"action_{action_id}",
                            action_type="local_exploit",
                            source_node=state.current_source,
                            target_node=state.current_source,
                            name=v_name,
                            description=f"Execute local exploit '{v_name}' on {state.current_source}",
                            vuln_info=v_info,
                            service_name=None,
                            cost=v_info.cost,
                        )
                    )
                    action_id += 1

            # Remote exploits and connections
            if (
                state.current_source != state.current_destination
                and state.current_destination in self.nodes
            ):
                target_info = self.nodes[state.current_destination]

                # Remote exploits
                for v_name, v_info in target_info.vulnerabilities.items():
                    if v_info.type == VulnerabilityType.REMOTE:
                        if self._check_firewall_access(
                            state.current_source, state.current_destination, "*"
                        ):
                            actions.append(
                                ActionInfo(
                                    action_id=f"action_{action_id}",
                                    action_type="remote_exploit",
                                    source_node=state.current_source,
                                    target_node=state.current_destination,
                                    name=v_name,
                                    description=f"Execute remote exploit '{v_name}' on {state.current_destination} from {state.current_source}",
                                    vuln_info=v_info,
                                    service_name=None,
                                    cost=v_info.cost,
                                )
                            )
                            action_id += 1

                # Service connections
                if state.current_destination not in state.owned_nodes:
                    for service in target_info.services:
                        if self._check_firewall_access(
                            state.current_source,
                            state.current_destination,
                            service.name,
                        ):
                            allowed_creds = (
                                set(service.allowedCredentials)
                                if service.allowedCredentials
                                else set()
                            )
                            protocol = getattr(service, "protocol", None)
                            if state.has_credential_for_service(
                                state.current_destination,
                                str(service.name),
                                service.name,
                                protocol,
                                allowed_creds,
                            ):
                                actions.append(
                                    ActionInfo(
                                        action_id=f"action_{action_id}",
                                        action_type="connect",
                                        source_node=state.current_source,
                                        target_node=state.current_destination,
                                        name=f"Connect_{service.name}",
                                        description=f"Connect to {state.current_destination} via {service.name}",
                                        vuln_info=VulnerabilityInfo(
                                            f"Connect {service.name}",
                                            VulnerabilityType.REMOTE,
                                            VulnerabilityOutcome(lateral_move=True),
                                            1.0,
                                            f"Connected {state.current_destination}",
                                        ),
                                        service_name=service.name,
                                        cost=1.0,
                                    )
                                )
                                action_id += 1

        # Movement actions
        for n in state.owned_nodes:
            if n != state.current_source:
                actions.append(
                    ActionInfo(
                        action_id=f"action_{action_id}",
                        action_type="change_source",
                        source_node=state.current_source,
                        target_node=n,
                        name=f"Move to {n}",
                        description=f"Change attack source from {state.current_source} to {n}",
                        vuln_info=None,
                        service_name=None,
                        cost=0.1,
                    )
                )
                action_id += 1

        for n in state.known_nodes:
            if n != state.current_destination:
                actions.append(
                    ActionInfo(
                        action_id=f"action_{action_id}",
                        action_type="change_destination",
                        source_node=state.current_destination,
                        target_node=n,
                        name=f"Target {n}",
                        description=f"Change attack target from {state.current_destination} to {n}",
                        vuln_info=None,
                        service_name=None,
                        cost=0.1,
                    )
                )
                action_id += 1

        return actions

    def apply_action(self, action_id: str) -> Tuple[bool, str]:
        """
        Apply an action by its ID.

        Returns:
            Tuple of (success, message)
        """
        actions = self.get_available_actions()
        action = next((a for a in actions if a.action_id == action_id), None)

        if not action:
            return False, f"Invalid action ID: {action_id}"

        state_before = self.current_state.to_dict()

        if action.action_type == "change_source":
            self.current_state = self.current_state.apply_movement(
                new_source=action.target_node
            )
        elif action.action_type == "change_destination":
            self.current_state = self.current_state.apply_movement(
                new_destination=action.target_node
            )
        elif action.vuln_info and action.vuln_info.outcome:
            self.current_state = self.current_state.apply_outcome(
                action.target_node, action.vuln_info.outcome, self.nodes
            )

        state_after = self.current_state.to_dict()

        # Record history
        self.step_count += 1
        self.history.append(
            HistoryEntry(
                step=self.step_count,
                action=action,
                state_before=state_before,
                state_after=state_after,
                timestamp=time.time() - self.start_time,
            )
        )

        return True, f"Successfully executed: {action.description}"

    def undo_last_action(self) -> Tuple[bool, str]:
        """Undo the last action"""
        if not self.history:
            return False, "No actions to undo"

        # Pop last history entry
        last_entry = self.history.pop()
        self.step_count -= 1

        # Restore previous state
        self.current_state = AttackState(
            current_source=last_entry.state_before["current_source"],
            current_destination=last_entry.state_before["current_destination"],
            owned_nodes=frozenset(last_entry.state_before["owned_nodes"]),
            known_nodes=frozenset(last_entry.state_before["known_nodes"]),
            credentials=frozenset(
                tuple(c) if isinstance(c, list) else c
                for c in last_entry.state_before["credentials"]
            ),
        )

        return True, f"Undone: {last_entry.action.description}"

    def get_current_status(self) -> Dict:
        """Get current simulation status"""
        total_nodes = len(self.nodes) - len(self.non_target_nodes)
        owned = self.current_state.get_owned_count(self.non_target_nodes)

        return {
            "step": self.step_count,
            "owned_nodes": owned,
            "total_target_nodes": total_nodes,
            "completion_percentage": (owned / total_nodes * 100)
            if total_nodes > 0
            else 0,
            "known_nodes": len(self.current_state.known_nodes),
            "credentials": len(self.current_state.credentials),
            "current_source": self.current_state.current_source,
            "current_destination": self.current_state.current_destination,
            "elapsed_time": time.time() - self.start_time,
        }

    def export_to_json(self, filename: str = "attack_simulation.json"):
        """Export the entire simulation state to JSON for the web UI"""

        # Build nodes data with connections
        nodes_data = []
        edges_data = []
        edge_set = set()

        for node_id, node_info in self.nodes.items():
            node_data = {
                "id": node_id,
                "ip_address": node_info.network_info[0].ip_address
                if node_info.network_info
                else "0.0.0.0",
                "vulnerabilities": [
                    {
                        "name": v_name,
                        "type": v_info.type.value,
                        "cost": v_info.cost,
                        "description": v_info.description,
                    }
                    for v_name, v_info in node_info.vulnerabilities.items()
                ],
                "services": [
                    {
                        "name": s.name,
                        "allowed_credentials": s.allowedCredentials,
                        "protocol": s.protocol,
                    }
                    for s in node_info.services
                ],
                "properties": node_info.properties,
                "is_attacker": node_id == self.attacker_node,
            }
            nodes_data.append(node_data)

            # Generate edges based on firewall rules (simplified)
            for other_id in self.nodes:
                if other_id != node_id:
                    edge_key = tuple(sorted([node_id, other_id]))
                    if edge_key not in edge_set:
                        # Check if there's any connectivity
                        has_connection = self._check_firewall_access(
                            node_id, other_id, "*"
                        )
                        if has_connection:
                            edges_data.append(
                                {
                                    "source": node_id,
                                    "target": other_id,
                                    "accessible": True,
                                }
                            )
                            edge_set.add(edge_key)

        # Build history data
        history_data = []
        for entry in self.history:
            history_data.append(
                {
                    "step": entry.step,
                    "action": entry.action.to_dict(),
                    "state_before": entry.state_before,
                    "state_after": entry.state_after,
                    "timestamp": entry.timestamp,
                }
            )

        # Build available actions
        available_actions = [a.to_dict() for a in self.get_available_actions()]

        export_data = {
            "metadata": {
                "title": "Attack Path Simulation",
                "description": f"Interactive attack path from {self.attacker_node}",
                "attacker_node": self.attacker_node,
                "total_nodes": len(self.nodes),
                "target_nodes": len(self.nodes) - len(self.non_target_nodes),
                "export_time": time.time(),
            },
            "nodes": nodes_data,
            "edges": edges_data,
            "current_state": self.current_state.to_dict(),
            "status": self.get_current_status(),
            "available_actions": available_actions,
            "history": history_data,
        }

        with open(filename, "w") as f:
            json.dump(export_data, f, indent=2)

        return export_data


def create_demo_network() -> Tuple[Dict[str, NodeInfo], str]:
    """Create a demo network for testing"""

    # Create firewall rules
    allow_all = Firewall(
        incoming=[FirewallRule(RulePermission.ALLOW, "0.0.0.0/0", "*")],
        outgoing=[FirewallRule(RulePermission.ALLOW, "0.0.0.0/0", "*")],
    )

    nodes = {
        "attacker": NodeInfo(
            id="attacker",
            network_info=[NetworkInfo("10.0.0.1")],
            firewall=allow_all,
            vulnerabilities={
                "local_scan": VulnerabilityInfo(
                    "Network Scanner",
                    VulnerabilityType.LOCAL,
                    VulnerabilityOutcome(nodes_discovered=["webserver", "database"]),
                    0.5,
                    "Scan network for hosts",
                )
            },
            properties={"role": "attacker_machine"},
        ),
        "webserver": NodeInfo(
            id="webserver",
            network_info=[NetworkInfo("10.0.0.10")],
            firewall=allow_all,
            vulnerabilities={
                "CVE-2021-44228": VulnerabilityInfo(
                    "Log4Shell",
                    VulnerabilityType.REMOTE,
                    VulnerabilityOutcome(
                        lateral_move=True,
                        credentials_discovered=[
                            {"name": "db_admin", "type": "password"}
                        ],
                    ),
                    1.0,
                    "Remote code execution via Log4j",
                ),
                "ssh_enum": VulnerabilityInfo(
                    "SSH Enumeration",
                    VulnerabilityType.REMOTE,
                    VulnerabilityOutcome(nodes_discovered=["internal_server"]),
                    0.3,
                    "Enumerate SSH keys",
                ),
            },
            services=[Service("http", ["web_token"]), Service("ssh", ["ssh_key"])],
            properties={"role": "web_server", "os": "linux"},
        ),
        "database": NodeInfo(
            id="database",
            network_info=[NetworkInfo("10.0.0.20")],
            firewall=allow_all,
            vulnerabilities={
                "sql_injection": VulnerabilityInfo(
                    "SQL Injection",
                    VulnerabilityType.REMOTE,
                    VulnerabilityOutcome(
                        credentials_discovered=[
                            {"name": "admin_cred", "type": "password"},
                            {"name": "backup_key", "type": "api_key"},
                        ]
                    ),
                    0.8,
                    "Extract credentials via SQL injection",
                )
            },
            services=[Service("mysql", ["db_admin"]), Service("ssh", ["backup_key"])],
            properties={"role": "database", "os": "linux"},
        ),
        "internal_server": NodeInfo(
            id="internal_server",
            network_info=[NetworkInfo("10.0.0.30")],
            firewall=allow_all,
            vulnerabilities={
                "priv_escalation": VulnerabilityInfo(
                    "Privilege Escalation",
                    VulnerabilityType.LOCAL,
                    VulnerabilityOutcome(
                        credentials_discovered=[{"name": "root_access", "type": "sudo"}]
                    ),
                    1.5,
                    "Escalate to root",
                ),
                "smb_vuln": VulnerabilityInfo(
                    "EternalBlue",
                    VulnerabilityType.REMOTE,
                    VulnerabilityOutcome(lateral_move=True),
                    2.0,
                    "SMB vulnerability for lateral movement",
                ),
            },
            services=[Service("smb", ["admin_cred"])],
            properties={"role": "file_server", "os": "windows"},
        ),
        "crown_jewel": NodeInfo(
            id="crown_jewel",
            network_info=[NetworkInfo("10.0.0.100")],
            firewall=allow_all,
            vulnerabilities={
                "final_exploit": VulnerabilityInfo(
                    "Zero Day",
                    VulnerabilityType.REMOTE,
                    VulnerabilityOutcome(lateral_move=True),
                    5.0,
                    "Critical system compromise",
                )
            },
            services=[Service("admin_panel", ["root_access"])],
            properties={"role": "crown_jewel", "os": "linux", "critical": True},
        ),
    }

    return nodes, "attacker"


if __name__ == "__main__":
    # Demo usage
    nodes, attacker = create_demo_network()
    solver = InteractiveAttackPathSolver(nodes, attacker)

    print("Interactive Attack Path Solver - Demo")
    print("=" * 50)
    print(f"Starting node: {attacker}")
    print(f"Total nodes: {len(nodes)}")
    print(f"Target nodes: {len(nodes) - 1}")
    print()

    # Export initial state
    solver.export_to_json("attack_simulation.json")
    print("Exported initial state to attack_simulation.json")
