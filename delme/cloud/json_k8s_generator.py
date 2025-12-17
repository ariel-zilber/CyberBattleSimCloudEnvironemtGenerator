"""
CyberBattleSim Attack Scenario Generator
========================================
Extends NetworkGenerator to create CyberBattleSim attack scenarios from cluster.json.
Includes comprehensive attack path analysis and visualization.

Author: Based on Microsoft CyberBattleSim
Date: 2025-11-09
"""

import json
import argparse
import logging
import os
import sys
import heapq
import time
from typing import Dict, List, Set, Tuple, Optional, Iterator, cast
import ipaddress
import matplotlib.pyplot as plt
import networkx as nx
import matplotlib

# Use non-interactive backend for saving files
matplotlib.use('Agg')

# CyberBattleSim imports
from cyberbattle.simulation.nodes import NodeInfo
from cyberbattle.simulation.firewall import FirewallRule, RulePermission, FirewallConfiguration
from cyberbattle.simulation.vulenrabilites import (
    VulnerabilityInfo, VulnerabilityType, LeakedNodesId, LeakedCredentials, 
    CachedCredential, PrivilegeEscalation, AdminEscalation, SystemEscalation,
    CustomerData, LateralMove, PrivilegeLevel
)
from cyberbattle.simulation.nodes_types import NodeID
from cyberbattle.simulation.services import ListeningService
from cyberbattle.simulation.network import NodeNetworkInfo, Subnet, NetworkInterfaces
from cyberbattle.simulation.identifiers import Identifiers
from cyberbattle.simulation.nodes_network import infer_constants_from_nodes

# Import NetworkGenerator base class
from cyberbattlesim_network_gen.generators.network_generator import NetworkGenerator
from cyberbattlesim_network_gen.generators.file_utils import save_yaml
from cyberbattlesim_network_gen.generators.utils import cli_default

# Service to port mappings for common services
SERVICE_PORTS = {
    "etcd": [2379, 2380],
    "kube-state-metrics": [8080, 8081],
    "metrics-server": [443, 4443],
    "postgresql": [5432],
    "mysql": [3306],
    "mongodb": [27017],
    "redis": [6379],
    "valkey": [6379],
    "elasticsearch": [9200, 9300],
    "clickhouse": [8123, 9000],
    "cassandra": [7000, 7001, 9042],
    "spark": [7077, 8080, 8081],
    "flink": [6123, 8081],
    "airflow": [8080],
    "mlflow": [5000],
    "jupyterhub": [8000, 8080],
    "kafka": [9092, 9093],
    "rabbitmq": [5672, 15672],
    "zookeeper": [2181, 2888, 3888],
    "minio": [9000, 9001],
    "nginx": [80, 443],
    "prometheus": [9090],
    "grafana": [3000],
    "jaeger": [6831, 6832, 14268, 16686],
    "loki": [3100],
    "tempo": [3200, 9095]
}

import ipaddress
import time
import collections
import sys
from typing import Dict, Set, Tuple, List, Any

# Set a higher recursion depth limit for deep searches
sys.setrecursionlimit(5000) 

class SearchTimeoutError(Exception):
    """Raised when the search time limit is exceeded."""
    pass

class SearchStateLimitError(Exception):
    """Raised when the visited state limit is exceeded."""
    pass

class AttackPathSolver:
    """
    Computes the maximal achievable state by exploring reachable attack paths
    using a DFS limited by depth, time, and total states visited.
    
    Enhanced to include explicit source and destination node selection.
    """
    
    def __init__(self, nodes: Dict[str, NodeInfo]):
        self.nodes = nodes
        self.attacker_node = "attacker"
        
        # --- Search-global state attributes ---
        self.best_state_found = None
        self.prev_map = {}
        self.visited_states_count = 0
        self.total_nodes = 0
        
    def _get_initial_state(self):
        """Initial state: only own attacker node, no knowledge, no credentials, no properties"""
        owned_nodes = {self.attacker_node}
        known_nodes = {self.attacker_node}
        credentials = set()
        discovered_properties = {self.attacker_node: set(self.nodes[self.attacker_node].properties)} if self.attacker_node in self.nodes else {}
        
        # Initial source and destination are both the attacker node
        current_source = self.attacker_node
        current_destination = self.attacker_node
        
        return (frozenset(owned_nodes), frozenset(known_nodes), frozenset(credentials), 
                frozenset((node, frozenset(props)) for node, props in discovered_properties.items()),
                current_source, current_destination)
    
    def _check_firewall_access(self, source_node: str, target_node: str, port: str) -> bool:
        """Check if source node can access target node on specified port through firewall"""
        if source_node not in self.nodes or target_node not in self.nodes:
            return False
            
        source_info = self.nodes[source_node]
        target_info = self.nodes[target_node]
        
        # Get IP addresses - handle missing network info gracefully
        source_ip = "0.0.0.0"
        if source_info.network_info and len(source_info.network_info) > 0:
            source_ip = source_info.network_info[0].ip_address
        
        target_ip = "0.0.0.0"  
        if target_info.network_info and len(target_info.network_info) > 0:
            target_ip = target_info.network_info[0].ip_address
        
        # Debug logging
        # print(f"  Firewall check: {source_node}({source_ip}) -> {target_node}({target_ip}):{port}")
        
        # Check outgoing rules from source
        outgoing_allowed = False
        for rule in source_info.firewall.outgoing:
            if rule.permission == RulePermission.ALLOW:
                try:
                    # Convert rule subnet to network object
                    rule_subnet = str(rule.subnet)
                    if '/' not in rule_subnet:
                        # Assume single IP if no prefix
                        rule_subnet = f"{rule_subnet}/32"
                    
                    rule_network = ipaddress.ip_network(rule_subnet, strict=False)
                    
                    # Check if target IP is in the allowed subnet
                    if ipaddress.ip_address(target_ip) in rule_network:
                        # Check port - rule.port can be string or int, convert to string for comparison
                        rule_port = str(rule.port) if rule.port != "*" else "*"
                        if rule_port == "*" or rule_port == str(port):
                            outgoing_allowed = True
                            # print(f"    OUTGOING ALLOWED by rule: {rule_subnet}:{rule_port}")
                            break
                except (ValueError, AttributeError) as e:
                    # print(f"    Error parsing outgoing rule: {e}")
                    continue
        
        # If outgoing is blocked, no need to check incoming
        if not outgoing_allowed:
            # print(f"    OUTGOING BLOCKED")
            return False
        
        # Check incoming rules to target
        incoming_allowed = False
        for rule in target_info.firewall.incoming:
            if rule.permission == RulePermission.ALLOW:
                try:
                    # Convert rule subnet to network object
                    rule_subnet = str(rule.subnet)
                    if '/' not in rule_subnet:
                        rule_subnet = f"{rule_subnet}/32"
                    
                    rule_network = ipaddress.ip_network(rule_subnet, strict=False)
                    
                    # Check if source IP is in the allowed subnet
                    if ipaddress.ip_address(source_ip) in rule_network:
                        # Check port
                        rule_port = str(rule.port) if rule.port != "*" else "*"
                        if rule_port == "*" or rule_port == str(port):
                            incoming_allowed = True
                            # print(f"    INCOMING ALLOWED by rule: {rule_subnet}:{rule_port}")
                            break
                except (ValueError, AttributeError) as e:
                    # print(f"    Error parsing incoming rule: {e}")
                    continue
        
        # print(f"    FINAL RESULT: {outgoing_allowed and incoming_allowed}")
        return outgoing_allowed and incoming_allowed 
    
    def _get_all_credentials_from_node(self, node_id: str) -> Set[Tuple[str, str, str]]:
        credentials = set()
        if node_id not in self.nodes:
            return credentials
        node_info = self.nodes[node_id]
        for service in node_info.services:
            for credential in service.allowedCredentials:
                credentials.add((node_id, service.port, credential))
        return credentials
    
    def _get_all_properties_from_node(self, node_id: str) -> Set[str]:
        if node_id in self.nodes:
            return set(self.nodes[node_id].properties)
        return set()
    
    def _get_available_actions(self, state):
        """Get all available actions including source/destination changes"""
        owned_nodes, known_nodes, credentials, properties, current_source, current_destination = state
        actions = []
        properties_dict = {node: set(props) for node, props in properties}
        
        # Action type 1: Change source node (from owned nodes)
        for new_source in owned_nodes:
            if new_source != current_source:
                actions.append(("change_source", current_source, new_source, f"Change source to {new_source}", None, None))
        
        # Action type 2: Change destination node (from known nodes)
        for new_destination in known_nodes:
            if new_destination != current_destination:
                actions.append(("change_destination", current_destination, new_destination, f"Change destination to {new_destination}", None, None))
        
        # Action type 3: Local exploits (on current source)
        if current_source in self.nodes:
            source_info = self.nodes[current_source]
            for vuln_name, vuln_info in source_info.vulnerabilities.items():
                if vuln_info.type == VulnerabilityType.LOCAL:
                    actions.append(("local_exploit", current_source, current_source, vuln_name, vuln_info, None))
        
        # Action type 4: Remote exploits (from current source to current destination)
        if current_source != current_destination and current_destination in self.nodes:
            target_info = self.nodes[current_destination]
            for vuln_name, vuln_info in target_info.vulnerabilities.items():
                if vuln_info.type == VulnerabilityType.REMOTE:
                    actions.append(("remote_exploit", current_source, current_destination, vuln_name, vuln_info, None))
        
        # Action type 5: Connect to service (from current source to current destination)
        if current_source != current_destination and current_destination in self.nodes:
            target_info = self.nodes[current_destination]
            for service in target_info.services:
                if not self._check_firewall_access(current_source, current_destination, service.port):
                    continue
                has_credentials = not service.allowedCredentials or any(
                    (current_destination, service.port, cred) in credentials for cred in service.allowedCredentials
                )
                
                if has_credentials:
                    
                    connect_vuln = VulnerabilityInfo(
                        description=f"Connect to {service.name} on {current_destination}",
                        type=VulnerabilityType.REMOTE,
                        cost=1.0, 
                        outcome=LateralMove(), 
                        reward_string=f"Connected to {current_destination} via {service.name}"
                    )
                    actions.append(("connect", current_source, current_destination, f"Connect_{service.name}", connect_vuln, service.port))
        return actions 
            
    def _apply_action(self, state, action):
        """Apply action and return new state"""
        action_type, source_node, target_node, vuln_name, vuln_info, port = action
        owned_nodes, known_nodes, credentials, properties, current_source, current_destination = state
        
        new_owned = set(owned_nodes)
        new_known = set(known_nodes)
        new_creds = set(credentials)
        properties_dict = {node: set(props) for node, props in properties}
        new_source = current_source
        new_destination = current_destination
        
        # Default cost for non-exploit actions
        cost = 1.0
        
        if action_type == "change_source":
            new_source = target_node  # target_node is the new source in this context
            cost = 0.1  # Small cost for switching source
            
        elif action_type == "change_destination":
            new_destination = target_node  # target_node is the new destination in this context
            cost = 0.1  # Small cost for switching destination
            
        elif action_type in ["local_exploit", "remote_exploit", "connect"]:
            cost = vuln_info.cost if vuln_info else 1.0
            outcome = vuln_info.outcome if vuln_info else None
            
            if outcome:
                if isinstance(outcome, LeakedNodesId):
                    new_known.update(outcome.nodes)
                    for node_id in outcome.nodes:
                        if node_id not in properties_dict:
                            properties_dict[node_id] = {"kubernetes"}
                        
                elif isinstance(outcome, LeakedCredentials):
                    for cred in outcome.credentials:
                        new_creds.add((cred.node, cred.port, cred.credential))
                        
                elif isinstance(outcome, (SystemEscalation, AdminEscalation, PrivilegeEscalation, CustomerData, LateralMove)):
                    new_owned.add(target_node)
                    new_known.add(target_node)
                    
                    all_node_creds = self._get_all_credentials_from_node(target_node)
                    new_creds.update(all_node_creds)
                    
                    all_node_props = self._get_all_properties_from_node(target_node)
                    properties_dict[target_node] = all_node_props
        
        new_properties = frozenset((node, frozenset(props)) for node, props in properties_dict.items())
        
        return (frozenset(new_owned), frozenset(new_known), frozenset(new_creds), 
                new_properties, new_source, new_destination), cost    
    
    def solve(self, max_depth=25, timeout_sec=3, max_visited_states=1_000_000):
        """
        Find the maximal achievable state (most nodes owned) using a
        Depth-First Search (DFS) with a maximum depth, time, and state limit.
        """
        print(f"\n👟 Computing maximal achievable state (DFS: max_depth={max_depth}, timeout={timeout_sec}s, max_states={max_visited_states})...")
        
        initial_state = self._get_initial_state()
        self.total_nodes = len([n for n in self.nodes if "attacker" not in self.nodes[n].properties])
        
        # --- Reset search-global state ---
        self.best_state_found = initial_state
        self.prev_map = {initial_state: (None, "Initial State")}
        visited = set() 
        self.visited_states_count = 0
        
        start_time = time.time()
        
        # Start the recursive exploration
        try:
            self._dfs_explore(initial_state, 0, visited, max_depth, 
                              start_time, timeout_sec, max_visited_states)
            
        except SearchTimeoutError:
            print(f"  SEARCH HALTED: Time limit ({timeout_sec}s) exceeded.")
        except SearchStateLimitError:
            print(f"  SEARCH HALTED: Visited state limit ({max_visited_states}) exceeded.")
        except RecursionError:
            print(f"  ERROR: Maximum recursion depth reached. Try a smaller max_depth or increase sys.setrecursionlimit().")

        end_time = time.time()
        
        print(f"  Search complete. Visited {self.visited_states_count} states in {end_time - start_time:.2f} seconds.")

        # Reconstruct the path to the best state found
        path_result = self._reconstruct_path_to_state(self.prev_map, self.best_state_found, end_time - start_time)
        return path_result

    def _dfs_explore(self, current_state, current_depth, visited, max_depth, 
                     start_time, timeout_sec, max_visited_states):
        
        # --- 1. Check stopping conditions ---
        time_elapsed = time.time() - start_time
        if time_elapsed > timeout_sec:
            raise SearchTimeoutError("Search time limit reached")
            
        if self.visited_states_count >= max_visited_states:
            raise SearchStateLimitError("Visited state limit reached")
        
        if current_depth >= max_depth:
            return # Stop exploring this branch (base case)

        # Mark this state as visited
        visited.add(current_state)
        self.visited_states_count += 1
        
        # 2. Check if this state is better than the current best
        self.best_state_found = self._get_better_state(current_state, self.best_state_found)
        
        # 3. User print log
        if self.visited_states_count % 100 == 0:
            best_owned = self._get_owned_count(self.best_state_found)
            owned, known, creds, props, source, dest = current_state
            print(f"  Visited {self.visited_states_count}, depth {current_depth}, best {best_owned}/{self.total_nodes} nodes, src={source}, dest={dest} [Time: {time_elapsed:.2f}s / {timeout_sec}s]")
        
        # 4. Get actions and recurse
        actions = self._get_available_actions(current_state)

        for action in actions:
            new_state, cost = self._apply_action(current_state, action)
            
            if new_state not in visited:
                action_type, source, target, vuln_name, _, port = action
                
                # Create descriptive action label
                if action_type == "change_source":
                    action_label = f"Change source from {source} to {target}"
                elif action_type == "change_destination":
                    action_label = f"Change destination from {source} to {target}"
                elif action_type == "local_exploit":
                    action_label = f"Local exploit {vuln_name} on {target}"
                elif action_type == "remote_exploit":
                    action_label = f"Remote exploit {vuln_name} from {source} to {target}"
                elif action_type == "connect":
                    action_label = f"Connect from {source} to {target} on port {port}"
                else:
                    action_label = f"{action_type}: {vuln_name}"
                
                self.prev_map[new_state] = (current_state, action_label)
                
                # --- RECURSIVE CALL ---
                self._dfs_explore(new_state, current_depth + 1, visited, max_depth, 
                                  start_time, timeout_sec, max_visited_states) 

    def _get_owned_count(self, state) -> int:
        """Helper to get non-attacker owned nodes from a state."""
        owned_nodes, _, _, _, _, _ = state
        return len([n for n in owned_nodes if "attacker" not in self.nodes[n].properties])
        
    def _get_better_state(self, state1, state2):
        """
        Compares two states and returns the "better" one.
        Better = more owned nodes, then more known, then more creds.
        """
        owned1 = self._get_owned_count(state1)
        owned2 = self._get_owned_count(state2)
        
        if owned1 > owned2:
            return state1
        if owned1 < owned2:
            return state2
        
        # Tie-breaker 1: Known nodes
        known1 = len(state1[1])
        known2 = len(state2[1])
        
        if known1 > known2:
            return state1
        if known1 < known2:
            return state2
            
        # Tie-breaker 2: Credentials
        creds1 = len(state1[2])
        creds2 = len(state2[2])
        
        if creds1 > creds2:
            return state1
        if creds1 < creds2:
            return state2
            
        return state2

    def _reconstruct_path_to_state(self, prev, best_state, time_taken):
        """Reconstructs the single path to the best state found."""
        
        path = []
        current = best_state
        
        while current in prev and prev[current][0] is not None:
            parent, action = prev[current]
            path.append(action)
            current = parent
            
        path.reverse() 
        
        nodes_owned_count = self._get_owned_count(best_state)
        owned_nodes, discovered, creds, props, source, dest = best_state
        
        result = {
            "maximal_achievement": {
                "path": path,
                "nodes_owned": nodes_owned_count,
                "computation_time": f"{time_taken:.2f}s",
                "best_state": {
                    'discovered': [n for n in discovered],
                    'owned': [n for n in owned_nodes],
                    'creds': [n for n in creds],
                    'props': {n[0]: list(n[1]) for n in props},
                    'current_source': source,
                    'current_destination': dest
                }
            }
        }
        
        return result

class AttackVisualizer:
    """Visualizes attack paths and analysis results"""
    
    def __init__(self, output_dir: str):
        self.output_dir = os.path.join(output_dir, "graphs")
        os.makedirs(self.output_dir, exist_ok=True)
    
    def visualize_attack_paths(self, nodes: Dict[str, NodeInfo], attack_paths: Dict):
        """Create visualization of attack paths"""
        print("🎨 Generating attack path visualizations...")
        
        # Create network graph
        G = nx.DiGraph()
        
        # Add nodes
        for node_id, node_info in nodes.items():
            is_attacker = "attacker" in node_info.properties
            node_type = "attacker" if is_attacker else "target"
            G.add_node(node_id, 
                      type=node_type,
                      value=node_info.value,
                      services=len(node_info.services),
                      vulnerabilities=len(node_info.vulnerabilities))
        
        # Add edges based on firewall rules and vulnerabilities
        for source_id, source_info in nodes.items():
            for target_id, target_info in nodes.items():
                if source_id == target_id:
                    continue
                
                # Check if there's any service access
                for service in target_info.services:
                    # Simplified access check
                    has_access = any(
                        rule.permission == RulePermission.ALLOW 
                        for rule in source_info.firewall.outgoing
                    )
                    
                    if has_access:
                        G.add_edge(source_id, target_id, 
                                  type="network_access",
                                  port=service.port)
                        break
        
        # Visualize different aspects
        self._create_network_overview(G, nodes)
        self._create_vulnerability_heatmap(G, nodes)
        self._create_attack_path_diagram(G, attack_paths)
        self._create_property_discovery_chart(attack_paths)
    
    def _create_network_overview(self, G: nx.DiGraph, nodes: Dict[str, NodeInfo]):
        """Create network overview visualization"""
        plt.figure(figsize=(16, 12))
        
        pos = nx.spring_layout(G, k=1, iterations=50, seed=42)
        
        # Color nodes by type
        node_colors = []
        for node in G.nodes():
            if "attacker" in nodes[node].properties:
                node_colors.append("red")
            elif "control_plane" in nodes[node].properties:
                node_colors.append("orange")
            else:
                node_colors.append("lightblue")
        
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=800, alpha=0.9)
        nx.draw_networkx_edges(G, pos, alpha=0.3, arrows=True, arrowstyle='->', arrowsize=10)
        nx.draw_networkx_labels(G, pos, font_size=8, font_weight="bold")
        
        plt.title("Network Overview - Attack Surface", fontsize=16)
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "network_overview.png"), dpi=150, bbox_inches='tight')
        plt.close()
    
    def _create_vulnerability_heatmap(self, G: nx.DiGraph, nodes: Dict[str, NodeInfo]):
        """Create vulnerability heatmap visualization"""
        plt.figure(figsize=(14, 10))
        
        pos = nx.spring_layout(G, k=1, iterations=50, seed=42)
        
        # Color nodes by vulnerability count
        vuln_counts = [len(nodes[node].vulnerabilities) for node in G.nodes()]
        
        nodes_draw = nx.draw_networkx_nodes(G, pos, node_color=vuln_counts, 
                                           node_size=800, alpha=0.9, cmap='Reds')
        nx.draw_networkx_edges(G, pos, alpha=0.2, arrows=False)
        nx.draw_networkx_labels(G, pos, font_size=8, font_weight="bold")
        
        plt.colorbar(nodes_draw, label='Vulnerability Count')
        plt.title("Vulnerability Heatmap", fontsize=16)
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "vulnerability_heatmap.png"), dpi=150, bbox_inches='tight')
        plt.close()
    
    def _create_attack_path_diagram(self, G: nx.DiGraph, attack_paths: Dict):
        """Create attack path visualization"""
        if not attack_paths:
            return
            
        plt.figure(figsize=(18, 14))
        
        pos = nx.spring_layout(G, k=1, iterations=50, seed=42)
        
        # Draw base network
        nx.draw_networkx_nodes(G, pos, node_color='lightgray', node_size=600, alpha=0.7)
        nx.draw_networkx_edges(G, pos, alpha=0.1, arrows=False)
        nx.draw_networkx_labels(G, pos, font_size=7)
        
        # Highlight optimal path if available
        if "maximal_achievement" in attack_paths:
            path_info = attack_paths["maximal_achievement"]
            path_nodes = self._extract_path_nodes(path_info["path"])
            
            # Highlight path nodes
            nx.draw_networkx_nodes(G, pos, nodelist=path_nodes, 
                                 node_color='green', node_size=800, alpha=0.9)
            
            # Highlight path edges
            path_edges = []
            for i in range(len(path_nodes)-1):
                if G.has_edge(path_nodes[i], path_nodes[i+1]):
                    path_edges.append((path_nodes[i], path_nodes[i+1]))
            
            nx.draw_networkx_edges(G, pos, edgelist=path_edges, 
                                 edge_color='green', width=2, alpha=0.8, arrows=True)
        
        plt.title("Optimal Attack Path", fontsize=16)
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "optimal_attack_path.png"), dpi=150, bbox_inches='tight')
        plt.close()
    
    def _create_property_discovery_chart(self, attack_paths: Dict):
        """Create property discovery progression chart"""
        if not attack_paths:
            return
            
        plt.figure(figsize=(12, 8))
        
        # Track property discovery over time for the optimal path
        if "maximal_achievement" in attack_paths:
            path_info = attack_paths["maximal_achievement"]
            
            # Simplified property progression (in real implementation, track state sequence)
            steps = list(range(len(path_info["path"])))
            owned_progression = []
            
            # Reconstruct owned nodes progression (simplified)
            current_owned = 1  # Start with attacker
            for i, action in enumerate(path_info["path"]):
                if any(keyword in action for keyword in ["exploit", "connect", "LateralMove"]):
                    current_owned += 1
                owned_progression.append(current_owned)
            
            plt.plot(steps, owned_progression, 'g-', label='Nodes Owned', linewidth=2)
            plt.xlabel('Attack Step')
            plt.ylabel('Nodes Owned')
            plt.title('Attack Progression - Nodes Compromised')
            plt.legend()
            plt.grid(True, alpha=0.3)
            
            plt.tight_layout()
            plt.savefig(os.path.join(self.output_dir, "attack_progression.png"), dpi=150, bbox_inches='tight')
            plt.close()
    
    def _extract_path_nodes(self, path):
        """Extract node sequence from attack path"""
        nodes = ["attacker"]  # Always start from attacker
        
        for action in path:
            # Parse node names from action descriptions
            if "from" in action and "to" in action:
                # Handle format: "Action from X to Y"
                parts = action.split(" from ")
                if len(parts) > 1:
                    subparts = parts[1].split(" to ")
                    if len(subparts) > 1:
                        source = subparts[0].strip()
                        target = subparts[1].split(" ")[0].strip()
                        if source not in nodes:
                            nodes.append(source)
                        if target not in nodes:
                            nodes.append(target)
            elif "Change source" in action:
                parts = action.split(" to ")
                if len(parts) > 1:
                    new_source = parts[1].strip()
                    if new_source not in nodes:
                        nodes.append(new_source)
            elif "Change destination" in action:
                parts = action.split(" to ")
                if len(parts) > 1:
                    new_dest = parts[1].strip()
                    if new_dest not in nodes:
                        nodes.append(new_dest)
        
        return nodes

# ... [Rest of the ClusterAttackGenerator class remains the same as in the original code]

class ClusterAttackGenerator(NetworkGenerator):
    """
    Generates CyberBattleSim attack scenario from cluster.json
    Extends NetworkGenerator for compatibility with cyberbattlesim_network_gen framework
    """
    
    def __init__(self,
                 config_file: str,
                 out_dir: str,
                 log_level: str = "INFO",
                 **kwargs):
        """
        Initialize the generator.

        :param config_file: Path to the JSON file containing the cluster plan.
        :param out_dir: The output directory (passed by cli_default).
        """
        super().__init__(output_dir=out_dir, **kwargs)
        
        self.output_dir = out_dir
        
        logging.basicConfig(level=getattr(logging, log_level.upper()))

        try:
            with open(config_file, 'r') as f:
                self.cluster_config = json.load(f)
            print(f"✅ Successfully loaded cluster configuration from {config_file}")
        except Exception as e:
            print(f"❌ Error: Could not load or parse config file {config_file}. {e}")
            raise

        self.nodes: Dict[str, NodeInfo] = {}
        self.attack_edges: List[Dict] = []

        # Validate required sections
        if "physical_topology" not in self.cluster_config:
            print("❌ Error: cluster.json must contain 'physical_topology' section")
            print("   Run physical_node_generator.py first to generate physical topology")
            raise ValueError("Missing physical_topology in cluster config")
    
    def _get_service_port(self, service_name: str) -> int:
        """Get default port for a service"""
        return SERVICE_PORTS.get(service_name, [80])[0]
    
    def _map_outcome_string_to_class(self, outcome_string: str, **kwargs):
        """Maps the 'outcome_type' string from the JSON to a CyberBattleSim class with correct parameters."""
        outcome_map = {
            "SystemEscalation": SystemEscalation(),
            "AdminEscalation": AdminEscalation(),
            "PrivilegeEscalation": PrivilegeEscalation(level=PrivilegeLevel.LocalUser),
            "CustomerData": CustomerData(),
            "LateralMove": LateralMove(),
            "LeakedNodesId": LeakedNodesId(nodes=kwargs.get('nodes', [])),
            "LeakedCredentials": LeakedCredentials(credentials=kwargs.get('credentials', [])),
        }
        return outcome_map.get(outcome_string, LeakedNodesId(nodes=[]))
    
    def _create_cyberbattle_node(self, physical_node: Dict) -> NodeInfo:
        """Convert physical node to CyberBattleSim node"""
        node_id = physical_node["node_id"]
        zone = physical_node["zone"]
        ip_allocation = physical_node.get("ip_allocation", {})
        ip_address = ip_allocation.get("ipv4", "10.0.0.1")
        subnet_cidr = ip_allocation.get("cidr", "10.0.0.0/24")
        
        # Get services from assigned pods
        services = []
        vulnerabilities = {}
        
        for pod_assignment in physical_node["assigned_pods"]:
            service_name = pod_assignment["service"]
            instance_id = pod_assignment["instance"]
            
            # Create listening service
            port = self._get_service_port(service_name)
            service_instance_name = f"{service_name}-{instance_id}"
            credential = f"{service_name}_{instance_id}_creds"
            
            service = ListeningService(
                name=service_instance_name,
                port=str(port),
                allowedCredentials=[credential]
            )
            services.append(service)
            
            # Create exploit vulnerability
            vuln_name = f"Exploit_{service_name}_{instance_id}"
            vulnerabilities[vuln_name] = VulnerabilityInfo(
                description=f"Exploit {service_name} service on {node_id}",
                type=VulnerabilityType.REMOTE,
                cost=5.0,
                outcome=LeakedCredentials(credentials=[
                    CachedCredential(
                        node=node_id,
                        port=str(port),
                        credential=credential
                    )
                ]),
                reward_string=f"Gained access to {service_name} on {node_id}"
            )
            
            # Add CVE vulnerabilities if present in cluster config
            if "network_topology" in self.cluster_config:
                network_services = self.cluster_config["network_topology"].get("services", {})
                if service_name in network_services and "vulnerabilities" in network_services[service_name]:
                    for cve in network_services[service_name]["vulnerabilities"]:
                        cve_id = cve["cve_id"]
                        cve_vuln_name = f"{cve_id}_{instance_id}"
                        
                        # Get outcome type and create appropriate outcome object
                        outcome_type = cve.get("outcome_type", "LeakedCredentials")
                        
                        # Handle different outcome types with correct parameters
                        if outcome_type == "LeakedNodesId":
                            # For node discovery outcomes, discover related nodes
                            discovered_nodes = self._find_related_nodes(service_name)
                            outcome = self._map_outcome_string_to_class(outcome_type, nodes=discovered_nodes)
                        elif outcome_type == "LeakedCredentials":
                            # For credential leaks, create appropriate credentials
                            target_service = cve.get("target_service", service_name)
                            target_port = self._get_service_port(target_service)
                            credential_name = f"{service_name}_to_{target_service}_creds"
                            
                            # Find target nodes for this credential
                            target_nodes = self._find_nodes_with_service(target_service)
                            if target_nodes:
                                credentials = [
                                    CachedCredential(
                                        node=target_nodes[0],  # Use first target node
                                        port=str(target_port),
                                        credential=credential_name
                                    )
                                ]
                                outcome = self._map_outcome_string_to_class(outcome_type, credentials=credentials)
                            else:
                                outcome = self._map_outcome_string_to_class(outcome_type)
                        else:
                            # For escalation and other outcomes
                            outcome = self._map_outcome_string_to_class(outcome_type)
                    
                        vulnerabilities[cve_vuln_name] = VulnerabilityInfo(
                            description=cve.get("description", "Unknown CVE"),
                            type=VulnerabilityType.REMOTE,
                            cost=cve.get("exploitability", 0.5) * 10,
                            outcome=outcome,
                            reward_string=f"Exploited {cve_id} on {node_id}"
                        )
        
        # Create firewall configuration based on node connections
        firewall_rules = self._create_firewall_rules(physical_node)
        
        # Determine node value based on type and services
        node_value = 50  # Default value
        if physical_node["node_type"] == "control_plane":
            node_value = 150
        elif physical_node["node_type"] in ["gpu", "compute"]:
            node_value = 100
        
        # Add value for critical services
        critical_services = ["etcd", "kafka", "postgresql", "mysql", "elasticsearch"]
        for pod in physical_node["assigned_pods"]:
            if pod["service"] in critical_services:
                node_value += 25
        
        # Create properties list
        properties = [
            "kubernetes",
            physical_node["node_type"],
            zone,
            f"ip_{ip_address.replace('.', '_')}"
        ]
        
        # Add service properties
        for pod in physical_node["assigned_pods"]:
            properties.append(f"service_{pod['service']}")
            properties.append(f"running_{pod['service']}")
        
        # Add zone and network properties
        properties.append(f"zone_{zone}")
        properties.append(f"subnet_{subnet_cidr.replace('/', '_')}")
        
        return NodeInfo(
            network_info=[
                NodeNetworkInfo(
                    interface=NetworkInterfaces.ETH1,
                    ip_address=ip_address,
                    subnet=Subnet(subnet_cidr)
                )
            ],
            services=services,
            vulnerabilities=vulnerabilities,
            properties=properties,
            value=node_value,
            firewall=firewall_rules,
            reimagable=False
        )
    
    def _find_related_nodes(self, service_name: str) -> List[str]:
        """Find nodes related to a service for discovery outcomes"""
        related_nodes = set()
        
        # Find nodes running the same service
        same_service_nodes = self._find_nodes_with_service(service_name)
        related_nodes.update(same_service_nodes)
        
        # Find nodes that communicate with this service
        if "network_topology" in self.cluster_config:
            access_connectivity = self.cluster_config["network_topology"].get("access_connectivity", [])
            for conn in access_connectivity:
                if conn["source"] == service_name:
                    target_nodes = self._find_nodes_with_service(conn["target"])
                    related_nodes.update(target_nodes)
                elif conn["target"] == service_name:
                    source_nodes = self._find_nodes_with_service(conn["source"])
                    related_nodes.update(source_nodes)
        
        return list(related_nodes)
    
    def _create_firewall_rules(self, physical_node: Dict) -> FirewallConfiguration:
        """Create firewall rules based on physical topology connections"""
        incoming_rules = []
        outgoing_rules = []
        
        node_id = physical_node["node_id"]
        node_ip = physical_node.get("ip_allocation", {}).get("ipv4", "10.0.0.1")
        
        # Check if we have node connections in physical topology
        if "node_connections" in self.cluster_config.get("physical_topology", {}):
            for conn in self.cluster_config["physical_topology"]["node_connections"]:
                if conn["to"] == node_id:
                    # Create rule based on firewall status
                    permission = RulePermission.ALLOW if not conn["is_firewalled"] else RulePermission.BLOCK
                    
                    incoming_rules.append(
                        FirewallRule(
                            port="*",
                            permission=permission,
                            subnet=Subnet(f"{conn['from_ip']}/32"),
                            reason=f"Connection from {conn['from']}"
                        )
                    )
                
                if conn["from"] == node_id:
                    permission = RulePermission.ALLOW if not conn["is_firewalled"] else RulePermission.BLOCK
                    
                    outgoing_rules.append(
                        FirewallRule(
                            port="*",
                            permission=permission,
                            subnet=Subnet(f"{conn['to_ip']}/32"),
                            reason=f"Connection to {conn['to']}"
                        )
                    )
        
        # Add default rules - deny incoming, allow outgoing
        incoming_rules.append(FirewallRule(port="*", permission=RulePermission.BLOCK, reason="Default deny"))
        outgoing_rules.append(FirewallRule(port="*", permission=RulePermission.ALLOW, reason="Default allow"))
        
        return FirewallConfiguration(
            incoming=incoming_rules,
            outgoing=outgoing_rules
        )
    
    def _create_attacker_nodes(self) -> None:
        """Create attacker entry points"""
        public_nodes = self._find_public_nodes()
        
        # Main attacker node
        self.nodes["attacker"] = NodeInfo(
            network_info=[
                NodeNetworkInfo(
                    interface=NetworkInterfaces.ETH1,
                    ip_address="192.168.1.100",
                    subnet=Subnet("192.168.1.0/24")
                )
            ],
            services=[],
            vulnerabilities={
                "InitialScan": VulnerabilityInfo(
                    description="Initial network reconnaissance",
                    type=VulnerabilityType.LOCAL,
                    outcome=LeakedNodesId(nodes=list(public_nodes)),
                    cost=1.0,
                    reward_string="Discovered public-facing nodes"
                ),
                "PortScan": VulnerabilityInfo(
                    description="Detailed port scanning",
                    type=VulnerabilityType.LOCAL,
                    outcome=LeakedNodesId(nodes=list(public_nodes)),
                    cost=2.0,
                    reward_string="Detailed port scan completed"
                )
            },
            properties=["attacker", "external", "reconnaissance"],
            value=0,
            agent_installed=True,
            reimagable=False
        )
    
    def _find_public_nodes(self) -> List[str]:
        """Find nodes with public-facing services"""
        public_nodes = set()
        
        # Check network topology for public services
        if "network_topology" in self.cluster_config:
            for service_name, service_config in self.cluster_config["network_topology"].get("services", {}).items():
                if service_config.get("is_public", False):
                    # Find nodes running this service
                    if "physical_topology" in self.cluster_config:
                        for node in self.cluster_config["physical_topology"]["nodes"]:
                            for pod in node["assigned_pods"]:
                                if pod["service"] == service_name:
                                    public_nodes.add(node["node_id"])
        
        # If no public services found, use control plane nodes as entry points
        if not public_nodes and "physical_topology" in self.cluster_config:
            for node in self.cluster_config["physical_topology"]["nodes"]:
                if node["node_type"] == "control_plane":
                    public_nodes.add(node["node_id"])
        
        # Fallback: use first few worker nodes
        if not public_nodes and "physical_topology" in self.cluster_config:
            worker_nodes = [node["node_id"] for node in self.cluster_config["physical_topology"]["nodes"] 
                          if node["node_type"] == "worker"]
            public_nodes.update(worker_nodes[:3])
        
        return list(public_nodes)
    
    def _build_credential_flows(self) -> None:
        """Build credential flow vulnerabilities based on cluster configuration"""
        if "network_topology" not in self.cluster_config:
            return
            
        credential_flows = self.cluster_config["network_topology"].get("credential_flow", [])
        
        for flow in credential_flows:
            source_service = flow["source"]
            target_service = flow["target"]
            
            # Find nodes running these services
            source_nodes = self._find_nodes_with_service(source_service)
            target_nodes = self._find_nodes_with_service(target_service)
            
            if not source_nodes or not target_nodes:
                continue
                
            # Create credential leak vulnerability
            for source_node in source_nodes:
                if source_node not in self.nodes:
                    continue
                    
                vuln_name = f"CredentialLeak_{source_service}_to_{target_service}"
                credential = f"{source_service}_to_{target_service}_key"
                target_port = str(self._get_service_port(target_service))
                
                # Add vulnerability to source node
                self.nodes[source_node].vulnerabilities[vuln_name] = VulnerabilityInfo(
                    description=f"Stored credentials for {target_service}",
                    type=VulnerabilityType.LOCAL,
                    cost=3.0,
                    outcome=LeakedCredentials(credentials=[
                        CachedCredential(
                            node=target_nodes[0],  # Use first target node
                            port=target_port,
                            credential=credential
                        )
                    ]),
                    reward_string=f"Found credentials for {target_service}"
                )
                
                # Add credential to target service
                for target_node in target_nodes:
                    if target_node in self.nodes:
                        for service in self.nodes[target_node].services:
                            if target_service in service.name and service.port == target_port:
                                if credential not in service.allowedCredentials:
                                    service.allowedCredentials.append(credential)
    
    def _find_nodes_with_service(self, service_name: str) -> List[str]:
        """Find nodes running a specific service"""
        nodes_with_service = []
        
        if "physical_topology" in self.cluster_config:
            for node in self.cluster_config["physical_topology"]["nodes"]:
                for pod in node["assigned_pods"]:
                    if pod["service"] == service_name:
                        nodes_with_service.append(node["node_id"])
                        break
        
        return nodes_with_service
    
    def _perform_attack_analysis(self):
        """Perform comprehensive attack analysis"""
        print("\n🔍 Performing comprehensive attack analysis...")
        
        # Create attack path attack_path
        solver = AttackPathSolver(self.nodes)
        attack_paths = solver.solve()
        
        # Create visualizations
        visualizer = AttackVisualizer(self.output_dir)
        visualizer.visualize_attack_paths(self.nodes, attack_paths)
        
        # Save attack analysis results
        self._save_attack_analysis(attack_paths)
        
        return attack_paths
    
    def _save_attack_analysis(self, attack_paths: Dict):
        """Save attack analysis results to files"""
        analysis_dir = os.path.join(self.output_dir, "analysis")
        os.makedirs(analysis_dir, exist_ok=True)
        
        # Save attack paths as JSON
        paths_data = {}
        for path_name, path_info in attack_paths.items():
            paths_data[path_name] = {
                "best_state": path_info.get("best_state"),
                "nodes_owned": path_info.get("nodes_owned"),
                "computation_time": path_info.get("computation_time"),
                "steps": path_info["path"]
            }
        
        with open(os.path.join(analysis_dir, "attack_paths.json"), 'w') as f:
            json.dump(paths_data, f, indent=2)
        
        # Generate analysis report
        self._generate_analysis_report(attack_paths, analysis_dir)
    
    def _generate_analysis_report(self, attack_paths: Dict, analysis_dir: str):
        """Generate comprehensive analysis report"""
        report_path = os.path.join(analysis_dir, "attack_analysis_report.txt")
        
        with open(report_path, 'w') as f:
            f.write("CYBERBATTLESIM ATTACK ANALYSIS REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            # Basic statistics
            total_nodes = len([n for n in self.nodes if "attacker" not in self.nodes[n].properties])
            total_vulns = sum(len(node.vulnerabilities) for node in self.nodes.values())
            total_properties = sum(len(node.properties) for node in self.nodes.values())
            
            f.write("BASIC STATISTICS:\n")
            f.write(f"Total target nodes: {total_nodes}\n")
            f.write(f"Total vulnerabilities: {total_vulns}\n")
            f.write(f"Total properties: {total_properties}\n")
            f.write(f"Attacker entry points: {len([n for n in self.nodes if 'attacker' in self.nodes[n].properties])}\n\n")
            
            # Attack path results
            f.write("ATTACK PATH ANALYSIS:\n")
            f.write("-" * 30 + "\n")
            
            if "maximal_achievement" in attack_paths:
                optimal = attack_paths["maximal_achievement"]
                f.write(f"Maximal achievement: {optimal['nodes_owned']}/{total_nodes} nodes owned\n")
                f.write(f"Steps required: {len(optimal['path'])}\n")
                f.write(f"Computation time: {optimal['computation_time']}\n\n")
                
                f.write("ATTACK PATH:\n")
                for i, action in enumerate(optimal["path"]):
                    f.write(f"  {i+1}. {action}\n")
                
                # Analyze action types
                action_counts = {}
                for action in optimal["path"]:
                    action_type = action.split(" ")[0] if " " in action else action
                    action_counts[action_type] = action_counts.get(action_type, 0) + 1
                
                f.write(f"\nACTION BREAKDOWN:\n")
                for action_type, count in action_counts.items():
                    f.write(f"  {action_type}: {count} actions\n")
            else:
                f.write("❌ No attack path found\n\n")
            
            # Property analysis
            f.write("\nPROPERTY ANALYSIS:\n")
            f.write("-" * 30 + "\n")
            
            # Count properties by type
            property_counts = {}
            for node in self.nodes.values():
                for prop in node.properties:
                    prop_type = prop.split('_')[0] if '_' in prop else prop
                    property_counts[prop_type] = property_counts.get(prop_type, 0) + 1
            
            for prop_type, count in sorted(property_counts.items()):
                f.write(f"{prop_type}: {count} properties\n")
            
            # Critical nodes analysis
            f.write("\nCRITICAL NODES:\n")
            f.write("-" * 30 + "\n")
            
            critical_nodes = []
            for node_id, node in self.nodes.items():
                if "attacker" not in node.properties:
                    if node.value >= 100 or "control_plane" in node.properties:
                        critical_nodes.append((node_id, node.value, len(node.properties)))
            
            for node_id, value, prop_count in sorted(critical_nodes, key=lambda x: x[1], reverse=True):
                f.write(f"{node_id}: value {value}, properties {prop_count}\n")
        
        print(f"✅ Attack analysis report saved to {report_path}")

    # --- NetworkGenerator Interface Methods ---

    def get_nodes(self) -> Dict[str, NodeInfo]:
        """
        Generate the complete dictionary of nodes for the simulation.
        """
        print("🔄 Generating CyberBattleSim attack scenario from cluster.json...")
        
        # Create nodes from physical topology (only healthy nodes)
        if "physical_topology" in self.cluster_config:
            for physical_node in self.cluster_config["physical_topology"]["nodes"]:
                if physical_node["is_healthy"]:
                    cyber_node = self._create_cyberbattle_node(physical_node)
                    self.nodes[physical_node["node_id"]] = cyber_node
        
        # Create attacker nodes
        self._create_attacker_nodes()
        
        # Build credential flows
        self._build_credential_flows()
        
        print(f"✅ Created {len(self.nodes)} nodes for CyberBattleSim")
        
        return self.nodes

    def get_identifiers(self) -> Identifiers:
        """Get identifiers for CyberBattleSim"""
        return infer_constants_from_nodes(
            cast(Iterator[Tuple[NodeID, NodeInfo]], list(self.nodes.items())),
            {}
        )

    def get_vulnerability_library(self):
        """Get vulnerability library (empty for now)"""
        return dict([])

    def generate(self):
        """
        Overrides the base generate() method to create the attack scenario.
        """
        generated_data = super().generate()
        
        # Perform comprehensive attack analysis
        attack_paths = self._perform_attack_analysis()
        
        # Print final summary
        attacker_nodes = sum(1 for node in self.nodes.values() if "attacker" in node.properties)
        target_nodes = len(self.nodes) - attacker_nodes
        
        print(f"\n🎯 CyberBattleSim Attack Scenario Generation Complete!")
        print(f"   Total nodes: {len(self.nodes)}")
        print(f"   Attacker nodes: {attacker_nodes}")
        print(f"   Target nodes: {target_nodes}")
        print(f"   Output directory: {self.output_dir}")
        
        # Print attack analysis summary
        if "maximal_achievement" in attack_paths:
            optimal = attack_paths["maximal_achievement"]
            print(f"   ✅ Maximal achievement: {optimal['nodes_owned']}/{target_nodes} nodes owned")
            print(f"   ⚡ Attack steps: {len(optimal['path'])}")
        
        return generated_data


# --- CLI Interface ---

def main():
    parser = argparse.ArgumentParser(
        description="Generate CyberBattleSim attack scenario from cluster.json"
    )
    
    parser.add_argument(
        'out_dir',
        type=str,
        help='Directory to write the generated environment files'
    )
    
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    )
    
    # Custom argument for cluster config file
    parser.add_argument(
        "--config-file",
        type=str,
        required=True,
        help="Path to the cluster.json configuration file with physical topology"
    )
    
    print("🚀 Running ClusterAttackGenerator...")
    cli_default(ClusterAttackGenerator, parser)
    
    print(f"\n✅ Successfully generated CyberBattleSim attack scenario!")


if __name__ == "__main__":
    main()