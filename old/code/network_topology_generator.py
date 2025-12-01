"""
Network Topology Generator for Kubernetes Services
===================================================
Generates realistic network connectivity graphs for Kubernetes service collections.

Produces four types of graphs:
1. knows_connectivity: What network connections the attacker knows about
2. knows_reachability: What nodes the attacker knows are reachable
3. access_connectivity: What connections the attacker can actually use
4. access_reachability: What nodes the attacker can actually reach

Author: Auto-generated
Date: 2025-11-07
"""

import json
import random
import networkx as nx
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import numpy as np


# ======================================================================
# Graph Type Definitions
# ======================================================================

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
    vulnerability_level: float = 0.0  # 0.0 = secure, 1.0 = highly vulnerable


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
    metadata: Dict


# ======================================================================
# Service Connectivity Rules
# ======================================================================

# Define which services commonly connect to which other services
SERVICE_CONNECTIVITY_RULES = {
    # Control plane services
    "etcd": {
        "connects_to": ["kube-state-metrics", "metrics-server"],
        "connectivity_probability": 0.9,
        "port_range": (2379, 2380),
        "requires_auth": True,
        "is_critical": True
    },
    
    # Observability
    "prometheus": {
        "connects_to": ["node-exporter", "kube-state-metrics", "cadvisor", "grafana"],
        "connectivity_probability": 0.95,
        "port_range": (9090, 9090),
        "requires_auth": False,
        "is_critical": False
    },
    
    "grafana": {
        "connects_to": ["prometheus", "grafana-loki", "grafana-tempo", "grafana-mimir"],
        "connectivity_probability": 0.9,
        "port_range": (3000, 3000),
        "requires_auth": True,
        "is_critical": False
    },
    
    "grafana-loki": {
        "connects_to": ["fluent-bit", "fluentd", "grafana"],
        "connectivity_probability": 0.85,
        "port_range": (3100, 3100),
        "requires_auth": False,
        "is_critical": False
    },
    
    # Databases - These are servers, not clients. Their connections are defined by their clients.
    "postgresql": {
        "connects_to": [],  # PostgreSQL is a server - clients connect to it
        "connectivity_probability": 1.0,
        "port_range": (5432, 5432),
        "requires_auth": True,
        "is_critical": True
    },
    
    "redis": {
        "connects_to": [],  # Redis is a server - clients connect to it
        "connectivity_probability": 1.0,
        "port_range": (6379, 6379),
        "requires_auth": True,
        "is_critical": True
    },
    
    "mongodb": {
        "connects_to": [],  # MongoDB is a server - clients connect to it
        "connectivity_probability": 1.0,
        "port_range": (27017, 27017),
        "requires_auth": True,
        "is_critical": True
    },
    
    # Messaging
    "kafka": {
        "connects_to": ["zookeeper", "schema-registry", "flink", "spark"],
        "connectivity_probability": 0.9,
        "port_range": (9092, 9092),
        "requires_auth": True,
        "is_critical": True
    },
    
    "zookeeper": {
        "connects_to": [],  # Zookeeper is a server - Kafka connects to it
        "connectivity_probability": 1.0,
        "port_range": (2181, 2181),
        "requires_auth": False,
        "is_critical": True
    },
    
    "rabbitmq": {
        "connects_to": ["airflow"],
        "connectivity_probability": 0.7,
        "port_range": (5672, 5672),
        "requires_auth": True,
        "is_critical": False
    },
    
    # Networking/Ingress
    "nginx-ingress-controller": {
        "connects_to": ["nginx", "wordpress", "ghost", "grafana"],
        "connectivity_probability": 0.85,
        "port_range": (80, 443),
        "requires_auth": False,
        "is_critical": True,
        "is_public": True
    },
    
    "kong": {
        "connects_to": ["postgresql"],
        "connectivity_probability": 0.9,
        "port_range": (8000, 8443),
        "requires_auth": True,
        "is_critical": True,
        "is_public": True
    },
    
    # Storage
    "minio": {
        "connects_to": ["mlflow", "thanos", "grafana-mimir", "spark", "airflow"],
        "connectivity_probability": 0.8,
        "port_range": (9000, 9000),
        "requires_auth": True,
        "is_critical": False
    },
    
    # Security
    "vault": {
        "connects_to": ["keycloak", "postgresql"],
        "connectivity_probability": 0.7,
        "port_range": (8200, 8200),
        "requires_auth": True,
        "is_critical": True
    },
    
    "keycloak": {
        "connects_to": ["postgresql"],
        "connectivity_probability": 0.95,
        "port_range": (8080, 8080),
        "requires_auth": True,
        "is_critical": True
    },
    
    # CI/CD
    "harbor": {
        "connects_to": ["postgresql", "redis"],
        "connectivity_probability": 0.9,
        "port_range": (443, 443),
        "requires_auth": True,
        "is_critical": False
    },
    
    "argo-cd": {
        "connects_to": [],
        "connectivity_probability": 0.7,
        "port_range": (8080, 8080),
        "requires_auth": True,
        "is_critical": False
    },
    
    # ML/AI
    "mlflow": {
        "connects_to": ["postgresql", "minio"],
        "connectivity_probability": 0.85,
        "port_range": (5000, 5000),
        "requires_auth": False,
        "is_critical": False
    },
    
    "jupyterhub": {
        "connects_to": ["postgresql"],
        "connectivity_probability": 0.7,
        "port_range": (8000, 8000),
        "requires_auth": True,
        "is_critical": False
    }
}

# Default connectivity for services not explicitly defined
DEFAULT_CONNECTIVITY = {
    "connects_to": [],
    "connectivity_probability": 0.5,
    "port_range": (8000, 9000),
    "requires_auth": True,
    "is_critical": False,
    "is_public": False
}


# ======================================================================
# Network Topology Generator
# ======================================================================

class NetworkTopologyGenerator:
    """Generate realistic network topologies for Kubernetes service collections"""
    
    def __init__(self, services: List[str], service_instances: Dict[str, int] = None, seed: int = None):
        """
        Initialize the topology generator
        
        Args:
            services: List of service names
            service_instances: Dictionary of service -> instance count
            seed: Random seed for reproducibility
        """
        self.services = services
        self.service_instances = service_instances or {s: 1 for s in services}
        self.service_nodes: Dict[str, ServiceNode] = {}
        
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)
    
    def _create_service_nodes(self) -> Dict[str, ServiceNode]:
        """Create ServiceNode objects for all services"""
        nodes = {}
        
        for service in self.services:
            rules = SERVICE_CONNECTIVITY_RULES.get(service, DEFAULT_CONNECTIVITY)
            port = random.randint(*rules["port_range"])
            
            # Determine category (simplified)
            category = self._infer_category(service)
            
            # Assign vulnerability based on service type
            vulnerability = self._assign_vulnerability(service, rules)
            
            node = ServiceNode(
                name=service,
                category=category,
                instance_count=self.service_instances.get(service, 1),
                port=port,
                protocol="TCP",
                is_public=rules.get("is_public", False),
                has_authentication=rules.get("requires_auth", True),
                vulnerability_level=vulnerability
            )
            nodes[service] = node
        
        return nodes
    
    def _infer_category(self, service: str) -> str:
        """Infer service category from name"""
        if any(x in service for x in ["prometheus", "grafana", "loki", "tempo", "jaeger"]):
            return "observability"
        elif any(x in service for x in ["postgresql", "mysql", "mongodb", "redis", "cassandra"]):
            return "database"
        elif any(x in service for x in ["kafka", "rabbitmq", "nats", "zookeeper"]):
            return "messaging"
        elif any(x in service for x in ["nginx", "kong", "apisix", "haproxy"]):
            return "networking"
        elif any(x in service for x in ["vault", "keycloak", "cert-manager"]):
            return "security"
        elif any(x in service for x in ["harbor", "argo", "jenkins", "gitlab"]):
            return "cicd"
        elif any(x in service for x in ["minio", "seaweedfs"]):
            return "storage"
        elif "etcd" in service or "kube-" in service or "metrics-server" in service:
            return "control_plane"
        else:
            return "application"
    
    def _assign_vulnerability(self, service: str, rules: Dict) -> float:
        """Assign vulnerability level based on service characteristics"""
        base_vuln = 0.1
        
        # Public services are more vulnerable
        if rules.get("is_public", False):
            base_vuln += 0.3
        
        # Services without auth are more vulnerable
        if not rules.get("requires_auth", True):
            base_vuln += 0.2
        
        # Critical services have lower vulnerability (better maintained)
        if rules.get("is_critical", False):
            base_vuln -= 0.1
        
        # Add some randomness
        base_vuln += random.uniform(-0.1, 0.1)
        
        return max(0.0, min(1.0, base_vuln))
    
    def _generate_base_connectivity(self) -> List[NetworkEdge]:
        """Generate base connectivity graph based on service rules"""
        edges = []
        
        for service in self.services:
            rules = SERVICE_CONNECTIVITY_RULES.get(service, DEFAULT_CONNECTIVITY)
            source_node = self.service_nodes[service]
            
            # Connect to defined targets
            for target in rules["connects_to"]:
                if target in self.services:
                    # Probabilistic connection
                    if random.random() < rules["connectivity_probability"]:
                        target_node = self.service_nodes[target]
                        edge = NetworkEdge(
                            source=service,
                            target=target,
                            protocol="TCP",
                            port=target_node.port,
                            bidirectional=False,
                            requires_auth=target_node.has_authentication,
                            firewall_allowed=True
                        )
                        edges.append(edge)
        
        return edges
    
    def _add_implicit_connections(self, edges: List[NetworkEdge]) -> List[NetworkEdge]:
        """Add implicit connections (monitoring, logging, etc.)"""
        new_edges = edges.copy()
        
        # Prometheus scrapes all services for metrics (PULL model)
        if "prometheus" in self.services:
            for service in self.services:
                if service != "prometheus" and random.random() < 0.7:
                    # Prometheus initiates the connection to scrape metrics
                    edge = NetworkEdge(
                        source="prometheus",
                        target=service,
                        protocol="TCP",
                        port=self.service_nodes[service].port,
                        bidirectional=False,
                        requires_auth=False,
                        firewall_allowed=True
                    )
                    new_edges.append(edge)
        
        # Logging connections (PUSH model - correct as-is)
        if "fluent-bit" in self.services or "fluentd" in self.services:
            logger = "fluent-bit" if "fluent-bit" in self.services else "fluentd"
            for service in self.services:
                if service != logger and random.random() < 0.5:
                    # Services push logs to the logger
                    edge = NetworkEdge(
                        source=service,
                        target=logger,
                        protocol="TCP",
                        port=self.service_nodes[logger].port,
                        bidirectional=False,
                        requires_auth=False,
                        firewall_allowed=True
                    )
                    new_edges.append(edge)
        
        return new_edges
    
    def _apply_firewall_rules(self, edges: List[NetworkEdge], 
                             firewall_probability: float = 0.3) -> List[NetworkEdge]:
        """Randomly apply firewall rules to block some connections"""
        filtered_edges = []
        
        for edge in edges:
            # Critical connections are less likely to be blocked
            source_node = self.service_nodes[edge.source]
            target_node = self.service_nodes[edge.target]
            
            is_critical = (
                SERVICE_CONNECTIVITY_RULES.get(edge.source, {}).get("is_critical", False) or
                SERVICE_CONNECTIVITY_RULES.get(edge.target, {}).get("is_critical", False)
            )
            
            block_prob = firewall_probability * (0.3 if is_critical else 1.0)
            
            if random.random() > block_prob:
                edge.firewall_allowed = True
                filtered_edges.append(edge)
            else:
                edge.firewall_allowed = False
                # Still add to list but marked as blocked
                filtered_edges.append(edge)
        
        return filtered_edges
    
    def _compute_reachability(self, edges: List[NetworkEdge], 
                             entry_points: List[str]) -> Set[str]:
        """Compute which nodes are reachable from entry points"""
        # Build adjacency list
        graph = {service: [] for service in self.services}
        for edge in edges:
            if edge.firewall_allowed:
                graph[edge.source].append(edge.target)
        
        # BFS from each entry point
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
        """Identify services that are publicly accessible"""
        entry_points = []
        
        for service, node in self.service_nodes.items():
            if node.is_public:
                entry_points.append(service)
        
        # If no public services, add ingress controllers by default
        if not entry_points:
            for service in self.services:
                if "ingress" in service or "nginx" in service or "kong" in service:
                    entry_points.append(service)
        
        # Always have at least one entry point
        if not entry_points and self.services:
            entry_points.append(random.choice(self.services))
        
        return entry_points
    
    def generate(self, 
                 firewall_probability: float = 0.2,
                 knowledge_completeness: float = 0.7) -> NetworkTopology:
        """
        Generate complete network topology with all four graph types
        
        Args:
            firewall_probability: Probability that a connection is blocked by firewall
            knowledge_completeness: How much of the network the attacker knows (0-1)
        
        Returns:
            NetworkTopology object with all graphs
        """
        # Create service nodes
        self.service_nodes = self._create_service_nodes()
        
        # Generate base connectivity
        base_edges = self._generate_base_connectivity()
        
        # Add implicit connections
        all_edges = self._add_implicit_connections(base_edges)
        
        # Apply firewall rules
        filtered_edges = self._apply_firewall_rules(all_edges, firewall_probability)
        
        # Determine what the attacker knows
        # knows_connectivity: subset of all edges based on knowledge_completeness
        known_edges = []
        for edge in filtered_edges:
            if random.random() < knowledge_completeness:
                known_edges.append(edge)
        
        # access_connectivity: only edges that are firewall allowed
        access_edges = [e for e in filtered_edges if e.firewall_allowed]
        
        # Identify entry points
        entry_points = self._get_entry_points()
        
        # knows_reachability: nodes the attacker knows about
        all_nodes_in_known_edges = set()
        for edge in known_edges:
            all_nodes_in_known_edges.add(edge.source)
            all_nodes_in_known_edges.add(edge.target)
        knows_reachability = list(all_nodes_in_known_edges | set(entry_points))
        
        # access_reachability: nodes actually reachable through firewall
        access_reachability = list(self._compute_reachability(access_edges, entry_points))
        
        # Build metadata
        metadata = {
            "total_services": len(self.services),
            "total_edges": len(all_edges),
            "firewall_blocked_edges": len([e for e in filtered_edges if not e.firewall_allowed]),
            "entry_points": entry_points,
            "knowledge_completeness": knowledge_completeness,
            "firewall_probability": firewall_probability,
            "knows_reachability_count": len(knows_reachability),
            "access_reachability_count": len(access_reachability),
            "connectivity_metrics": self._compute_graph_metrics(access_edges)
        }
        
        return NetworkTopology(
            services=self.service_nodes,
            knows_connectivity=known_edges,
            knows_reachability=knows_reachability,
            access_connectivity=access_edges,
            access_reachability=access_reachability,
            metadata=metadata
        )
    
    def _compute_graph_metrics(self, edges: List[NetworkEdge]) -> Dict:
        """Compute graph theory metrics"""
        if not edges:
            return {
                "avg_degree": 0.0,
                "density": 0.0,
                "is_connected": False
            }
        
        # Build networkx graph
        G = nx.DiGraph()
        for service in self.services:
            G.add_node(service)
        for edge in edges:
            G.add_edge(edge.source, edge.target)
        
        n = len(self.services)
        m = len(edges)
        
        return {
            "avg_degree": (2 * m / n) if n > 0 else 0.0,
            "density": m / (n * (n - 1)) if n > 1 else 0.0,
            "is_connected": nx.is_weakly_connected(G) if n > 0 else False,
            "num_components": nx.number_weakly_connected_components(G)
        }


# ======================================================================
# Export Functions
# ======================================================================

def topology_to_dict(topology: NetworkTopology) -> Dict:
    """Convert NetworkTopology to dictionary format"""
    return {
        "services": {name: asdict(node) for name, node in topology.services.items()},
        "knows_connectivity": [asdict(edge) for edge in topology.knows_connectivity],
        "knows_reachability": topology.knows_reachability,
        "access_connectivity": [asdict(edge) for edge in topology.access_connectivity],
        "access_reachability": topology.access_reachability,
        "metadata": topology.metadata
    }


def topology_to_networkx(topology: NetworkTopology, graph_type: GraphType) -> nx.DiGraph:
    """Convert topology to NetworkX graph for a specific graph type"""
    G = nx.DiGraph()
    
    # Add all service nodes
    for service_name, node in topology.services.items():
        G.add_node(service_name, **asdict(node))
    
    # Add edges based on graph type
    if graph_type == GraphType.KNOWS_CONNECTIVITY:
        edges = topology.knows_connectivity
    elif graph_type == GraphType.ACCESS_CONNECTIVITY:
        edges = topology.access_connectivity
    else:
        # For reachability graphs, create edges from entry points
        edges = topology.access_connectivity
    
    for edge in edges:
        G.add_edge(edge.source, edge.target, **asdict(edge))
    
    return G


def topology_to_adjacency_matrix(topology: NetworkTopology, graph_type: GraphType) -> np.ndarray:
    """Convert topology to adjacency matrix"""
    services = list(topology.services.keys())
    n = len(services)
    matrix = np.zeros((n, n), dtype=int)
    
    service_idx = {service: i for i, service in enumerate(services)}
    
    # Get edges based on graph type
    if graph_type == GraphType.KNOWS_CONNECTIVITY:
        edges = topology.knows_connectivity
    elif graph_type == GraphType.ACCESS_CONNECTIVITY:
        edges = topology.access_connectivity
    else:
        edges = topology.access_connectivity
    
    for edge in edges:
        i = service_idx[edge.source]
        j = service_idx[edge.target]
        matrix[i][j] = 1
    
    return matrix


def export_topology_to_json(topology: NetworkTopology, filepath: str):
    """Export topology to JSON file"""
    with open(filepath, 'w') as f:
        json.dump(topology_to_dict(topology), f, indent=2)


def export_topology_to_graphml(topology: NetworkTopology, filepath: str, 
                               graph_type: GraphType = GraphType.ACCESS_CONNECTIVITY):
    """Export topology to GraphML format for visualization"""
    G = topology_to_networkx(topology, graph_type)
    nx.write_graphml(G, filepath)


# ======================================================================
# CLI and Examples
# ======================================================================

def main():
    """Demo usage"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python network_topology_generator.py <cluster_config.json>")
        print("\nGenerates network topology graphs from cluster configuration")
        sys.exit(1)
    
    # Load cluster configuration
    with open(sys.argv[1], 'r') as f:
        cluster_config = json.load(f)
    
    services = cluster_config.get("services", [])
    service_instances = cluster_config.get("service_instances", {})
    
    print(f"Generating network topology for {len(services)} services...")
    
    # Generate topology
    generator = NetworkTopologyGenerator(services, service_instances, seed=42)
    topology = generator.generate(
        firewall_probability=0.2,
        knowledge_completeness=0.7
    )
    
    # Print summary
    print(f"\n{'='*80}")
    print("NETWORK TOPOLOGY SUMMARY")
    print(f"{'='*80}")
    print(f"Total Services: {topology.metadata['total_services']}")
    print(f"Total Edges: {topology.metadata['total_edges']}")
    print(f"Firewall Blocked: {topology.metadata['firewall_blocked_edges']}")
    print(f"Entry Points: {', '.join(topology.metadata['entry_points'])}")
    print(f"\nKnows Reachability: {topology.metadata['knows_reachability_count']} nodes")
    print(f"Access Reachability: {topology.metadata['access_reachability_count']} nodes")
    print(f"\nGraph Metrics:")
    for key, value in topology.metadata['connectivity_metrics'].items():
        print(f"  {key}: {value}")
    
    # Export
    output_base = sys.argv[1].replace('.json', '')
    export_topology_to_json(topology, f"{output_base}_topology.json")
    print(f"\n✅ Topology exported to {output_base}_topology.json")
    
    # Export GraphML for each graph type
    for graph_type in GraphType:
        export_topology_to_graphml(
            topology, 
            f"{output_base}_{graph_type.value}.graphml",
            graph_type
        )
        print(f"✅ {graph_type.value} graph exported to {output_base}_{graph_type.value}.graphml")


if __name__ == "__main__":
    main()
