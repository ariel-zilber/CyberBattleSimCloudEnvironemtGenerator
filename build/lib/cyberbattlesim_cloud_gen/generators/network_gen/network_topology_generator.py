"""
Network Topology Generator
==========================
Generates the logical network layer:
- Defines connectivity between services (who talks to whom)
- Generates credential graphs (who has access to whom)
- Applies firewall rules and network segmentation
- Calculates graph metrics (reachability, attack paths)
"""

import random
import networkx as nx
from cyberbattlesim_cloud_gen.config.config_loader import ConfigLoader
from cyberbattlesim_cloud_gen.generators.network_gen.credential import (
    CredentialGrant,
    CredentialLevel,
)
from cyberbattlesim_cloud_gen.generators.network_gen.graph_model import (
    NetworkEdge,
    NetworkTopology,
    ServiceNode,
)
import numpy as np
from typing import Dict, List, Set
from dataclasses import asdict


class NetworkTopologyGenerator:
    """Generate realistic network topologies for Kubernetes service collections"""

    def __init__(
        self,
        services: List[str],
        service_instances: Dict[str, int] = None,
        seed: int = None,
        vulnerability_assigner=None,
        config_loader_instance: ConfigLoader = None,
    ):
        self.services = services
        self.service_instances = service_instances or {s: 1 for s in services}
        self.service_nodes: Dict[str, ServiceNode] = {}
        self.vulnerability_assigner = vulnerability_assigner
        self.config_loader_instance = (
            config_loader_instance or ConfigLoader.get_instance()
        )

        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)

    def _assign_vulnerability(self, service: str, rules: Dict) -> float:
        base_vuln = 0.1
        if rules.get("is_public", False):
            base_vuln += 0.3
        if not rules.get("requires_auth", True):
            base_vuln += 0.2
        if rules.get("is_critical", False):
            base_vuln -= 0.1
        base_vuln += random.uniform(-0.1, 0.1)
        return max(0.0, min(1.0, base_vuln))

    def _create_service_nodes(self) -> Dict[str, ServiceNode]:
        nodes = {}
        connectivity_rules = self.config_loader_instance.get_connectivity_rules()
        default_connectivity = connectivity_rules.get("default", {})

        for service in self.services:
            # Default to default connectivity
            rules = default_connectivity

            # 1. Try exact match
            if service in connectivity_rules:
                rules = connectivity_rules[service]
            else:
                # 2. Try partial match (e.g., "my-nginx" matches "nginx")
                # Sort keys by length desc to match "nginx-ingress" before "nginx"
                for key in sorted(connectivity_rules.keys(), key=len, reverse=True):
                    if key in service and key != "default":
                        rules = connectivity_rules[key]
                        break

            port = random.randint(*rules.get("port_range", (8000, 9000)))
            category = self.config_loader_instance.get_service_category(service)
            vulnerability = self._assign_vulnerability(service, rules)

            # Try to assign specific CVEs if assigner is provided
            vulnerabilities = []
            if self.vulnerability_assigner:
                try:
                    vuln_list = self.vulnerability_assigner.assign_vulnerabilities(
                        service
                    )
                    vulnerabilities = (
                        [asdict(v) for v in vuln_list]
                        if hasattr(vuln_list[0], "to_dict")
                        else vuln_list
                    )
                except Exception as e:
                    print(
                        f"Warning: Could not assign vulnerabilities to {service}: {e}"
                    )

            nodes[service] = ServiceNode(
                name=service,
                category=category,
                instance_count=self.service_instances.get(service, 1),
                port=port,
                protocol="TCP",
                is_public=rules.get("is_public", False),
                has_authentication=rules.get("requires_auth", True),
                vulnerability_level=vulnerability,
                vulnerabilities=vulnerabilities,
            )
        return nodes

    def _generate_base_connectivity(self) -> List[NetworkEdge]:
        edges = []
        connectivity_rules = self.config_loader_instance.get_connectivity_rules()
        default_connectivity = connectivity_rules.get("default", {})

        for service in self.services:
            rules = connectivity_rules.get(service, default_connectivity)
            for target in rules.get("connects_to", []):
                if target in self.services:
                    if random.random() < rules.get("connectivity_probability", 0.5):
                        target_node = self.service_nodes[target]
                        edge = NetworkEdge(
                            source=service,
                            target=target,
                            protocol="TCP",
                            port=target_node.port,
                            bidirectional=False,
                            requires_auth=target_node.has_authentication,
                            firewall_allowed=True,
                        )
                        edges.append(edge)
        return edges

    def _add_implicit_connections(self, edges: List[NetworkEdge]) -> List[NetworkEdge]:
        new_edges = edges.copy()

        # Prometheus Pull
        if "prometheus" in self.services:
            for service in self.services:
                if service != "prometheus" and random.random() < 0.7:
                    edge = NetworkEdge(
                        source="prometheus",
                        target=service,
                        protocol="TCP",
                        port=self.service_nodes[service].port,
                        bidirectional=False,
                        requires_auth=False,
                        firewall_allowed=True,
                    )
                    new_edges.append(edge)

        # Logging Push
        logger = (
            "fluent-bit"
            if "fluent-bit" in self.services
            else ("fluentd" if "fluentd" in self.services else None)
        )
        if logger:
            for service in self.services:
                if service != logger and random.random() < 0.5:
                    edge = NetworkEdge(
                        source=service,
                        target=logger,
                        protocol="TCP",
                        port=self.service_nodes[logger].port,
                        bidirectional=False,
                        requires_auth=False,
                        firewall_allowed=True,
                    )
                    new_edges.append(edge)
        return new_edges

    def _apply_firewall_rules(
        self, edges: List[NetworkEdge], firewall_probability: float
    ) -> List[NetworkEdge]:
        filtered_edges = []
        connectivity_rules = self.config_loader_instance.get_connectivity_rules()

        for edge in edges:
            is_critical = connectivity_rules.get(edge.source, {}).get(
                "is_critical", False
            ) or connectivity_rules.get(edge.target, {}).get("is_critical", False)
            block_prob = firewall_probability * (0.3 if is_critical else 1.0)
            edge.firewall_allowed = random.random() > block_prob
            filtered_edges.append(edge)
        return filtered_edges

    def _compute_reachability(
        self, edges: List[NetworkEdge], entry_points: List[str]
    ) -> Set[str]:
        graph = {service: [] for service in self.services}
        for edge in edges:
            if edge.firewall_allowed:
                graph[edge.source].append(edge.target)

        reachable = set()
        queue = list(entry_points)
        visited = set(entry_points)

        while queue:
            current = queue.pop(0)
            reachable.add(current)
            for neighbor in graph.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        return reachable

    def _get_entry_points(self) -> List[str]:
        entry_points = []
        for service, node in self.service_nodes.items():
            if node.is_public:
                entry_points.append(service)

        if not entry_points:
            for service in self.services:
                if "ingress" in service or "nginx" in service or "kong" in service:
                    entry_points.append(service)

        if not entry_points and self.services:
            entry_points.append(random.choice(self.services))
        return entry_points

    def _generate_credential_flow(
        self, access_edges: List[NetworkEdge]
    ) -> List[CredentialGrant]:
        credentials = []
        credential_access_patterns = (
            self.config_loader_instance.get_credential_access_patterns()
        )
        shared_credential_patterns = (
            self.config_loader_instance.get_shared_credential_patterns()
        )
        credential_caching_services = (
            self.config_loader_instance.get_credential_caching_services()
        )

        for service in self.services:
            # Find matching pattern
            matched_pattern_key = None
            if service in credential_access_patterns:
                matched_pattern_key = service
            else:
                # Heuristic match
                for key in credential_access_patterns.keys():
                    if key in service:
                        matched_pattern_key = key
                        break

            if not matched_pattern_key:
                continue

            patterns = credential_access_patterns[matched_pattern_key]

            for target, (level_val, cred_type, tags) in patterns.items():
                # Find the actual target service name in self.services
                # that matches the 'target' key (e.g. find "postgresql-prod" for key "postgresql")
                actual_targets = [s for s in self.services if target in s]

                for actual_target in actual_targets:
                    # Check for network access
                    has_access = any(
                        e.source == service
                        and e.target == actual_target
                        and e.firewall_allowed
                        for e in access_edges
                    )
                    is_operator = "operator" in service
                    level = CredentialLevel(level_val)
                    is_system = level == CredentialLevel.System

                    if has_access or is_operator or is_system:
                        is_shared = False
                        # Use the pattern key 'target' to check shared status
                        for (
                            pattern_name,
                            services_list,
                        ) in shared_credential_patterns.items():
                            if service in services_list and target in pattern_name:
                                is_shared = True

                        credentials.append(
                            CredentialGrant(
                                source=service,
                                target=actual_target,
                                credential_level=level,
                                credential_type=cred_type,
                                is_cached=(
                                    matched_pattern_key in credential_caching_services
                                ),
                                is_shared=is_shared,
                                can_pivot=(
                                    level
                                    in [CredentialLevel.Admin, CredentialLevel.System]
                                ),
                            )
                        )
        return credentials

    def _compute_graph_metrics(self, edges: List[NetworkEdge]) -> Dict:
        if not edges:
            return {"avg_degree": 0.0, "is_connected": False}

        G = nx.DiGraph()
        for s in self.services:
            G.add_node(s)
        for e in edges:
            G.add_edge(e.source, e.target)

        n = len(self.services)
        m = len(edges)
        return {
            "avg_degree": (2 * m / n) if n > 0 else 0.0,
            "density": m / (n * (n - 1)) if n > 1 else 0.0,
            "is_connected": nx.is_weakly_connected(G) if n > 0 else False,
            "num_components": nx.number_weakly_connected_components(G),
        }

    def generate(
        self, firewall_probability: float = 0.2, knowledge_completeness: float = 0.7
    ) -> NetworkTopology:
        self.service_nodes = self._create_service_nodes()
        base_edges = self._generate_base_connectivity()
        all_edges = self._add_implicit_connections(base_edges)
        filtered_edges = self._apply_firewall_rules(all_edges, firewall_probability)

        # Knowledge graph (what attacker sees)
        known_edges = [
            e for e in filtered_edges if random.random() < knowledge_completeness
        ]

        # Access graph (what actually works)
        access_edges = [e for e in filtered_edges if e.firewall_allowed]

        entry_points = self._get_entry_points()
        credential_flow = self._generate_credential_flow(access_edges)

        access_reachability = list(
            self._compute_reachability(access_edges, entry_points)
        )

        # Build node set for known reachability
        known_nodes = set(entry_points)
        for e in known_edges:
            known_nodes.add(e.source)
            known_nodes.add(e.target)

        metadata = {
            "total_services": len(self.services),
            "total_edges": len(all_edges),
            "entry_points": entry_points,
            "connectivity_metrics": self._compute_graph_metrics(access_edges),
        }

        return NetworkTopology(
            services=self.service_nodes,
            knows_connectivity=known_edges,
            knows_reachability=list(known_nodes),
            access_connectivity=access_edges,
            access_reachability=access_reachability,
            credential_flow=credential_flow,
            metadata=metadata,
        )
