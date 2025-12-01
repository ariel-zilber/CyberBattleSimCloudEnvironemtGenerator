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
import numpy as np
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum

# ======================================================================
# Constants & Rules
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
    "kube-state-metrics": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": False,
        "is_critical": False
    },
    "metrics-server": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (4443, 4443),
        "requires_auth": True,
        "is_critical": False
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
    # Databases
    "postgresql": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (5432, 5432),
        "requires_auth": True,
        "is_critical": True
    },
    "redis": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (6379, 6379),
        "requires_auth": True,
        "is_critical": True
    },
    "mongodb": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (27017, 27017),
        "requires_auth": True,
        "is_critical": True
    },
    # Messaging
    "kafka": {
        "connects_to": ["zookeeper", "schema-registry"],
        "connectivity_probability": 0.9,
        "port_range": (9092, 9092),
        "requires_auth": True,
        "is_critical": True
    },
    "zookeeper": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (2181, 2181),
        "requires_auth": False,
        "is_critical": True
    },
    # Web/Ingress
    "nginx-ingress-controller": {
        "connects_to": ["nginx", "wordpress", "ghost", "grafana"],
        "connectivity_probability": 0.85,
        "port_range": (80, 443),
        "requires_auth": False,
        "is_critical": True,
        "is_public": True
    },
    "nginx": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (80, 80),
        "requires_auth": False,
        "is_critical": False
    },
    # Storage
    "minio": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (9000, 9000),
        "requires_auth": True,
        "is_critical": False
    },
    # Default fallback
    "default": {
        "connects_to": [],
        "connectivity_probability": 0.5,
        "port_range": (8000, 9000),
        "requires_auth": True,
        "is_critical": False,
        "is_public": False
    }
}

DEFAULT_CONNECTIVITY = SERVICE_CONNECTIVITY_RULES["default"]

# Define what credential level each service typically needs to access others
CREDENTIAL_ACCESS_PATTERNS = {
    "harbor": {
        "postgresql": (1, "password", ["database_credentials"]), # 1=LocalUser
        "redis": (1, "password", ["cache_credentials"])
    },
    "keycloak": {
        "postgresql": (1, "password", ["database_credentials"])
    },
    "airflow": {
        "postgresql": (1, "password", ["database_credentials"]),
        "redis": (1, "password", ["celery_broker"]),
        "rabbitmq": (1, "password", ["message_queue"])
    },
    "mlflow": {
        "postgresql": (1, "password", ["database_credentials"]),
        "minio": (1, "access_key", ["s3_credentials"])
    },
    "vault": {
        "postgresql": (2, "password", ["database_admin"]), # 2=Admin
        "etcd": (2, "certificate", ["etcd_root"])
    },
    "grafana": {
        "prometheus": (1, "token", ["readonly"]),
        "grafana-loki": (1, "token", ["readonly"])
    },
    "jenkins": {
        "postgresql": (1, "password", ["database_credentials"])
    },
    "argo-cd": {
        "redis": (1, "password", ["cache_credentials"])
    },
    "kafka": {
        "zookeeper": (2, "password", ["cluster_coordination"])
    },
    "spark": {
        "minio": (1, "access_key", ["s3_credentials"]),
        "kafka": (1, "password", ["consumer_credentials"])
    }
}

CREDENTIAL_CACHING_SERVICES = [
    "jenkins", "harbor", "argo-cd", "gitlab-runner",
    "airflow", "spark", "flink", "wordpress"
]

SHARED_CREDENTIAL_PATTERNS = {
    "prometheus_readonly": ["grafana", "superset", "jupyterhub"],
    "minio_data_pipeline": ["spark", "flink", "mlflow", "airflow"],
    "kafka_consumer": ["spark", "flink"],
    "postgresql_readonly": ["superset", "metabase", "redash"]
}

# ======================================================================
# Data Models
# ======================================================================

class CredentialLevel(Enum):
    """Privilege levels for service access"""
    NoAccess = 0
    LocalUser = 1
    Admin = 2
    System = 3
    MAXIMUM = 3

@dataclass
class CredentialGrant:
    """Represents a credential that one service has for accessing another"""
    source: str
    target: str
    credential_level: CredentialLevel
    credential_type: str
    is_cached: bool = False
    is_shared: bool = False
    can_pivot: bool = True

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

# ======================================================================
# Generator Logic
# ======================================================================

class NetworkTopologyGenerator:
    """Generate realistic network topologies for Kubernetes service collections"""
    
    def __init__(self, services: List[str], service_instances: Dict[str, int] = None, 
                 seed: int = None, vulnerability_assigner=None):
        self.services = services
        self.service_instances = service_instances or {s: 1 for s in services}
        self.service_nodes: Dict[str, ServiceNode] = {}
        self.vulnerability_assigner = vulnerability_assigner
        
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)
    
    def _infer_category(self, service: str) -> str:
        """Simple heuristic to categorize services"""
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
        base_vuln = 0.1
        if rules.get("is_public", False): base_vuln += 0.3
        if not rules.get("requires_auth", True): base_vuln += 0.2
        if rules.get("is_critical", False): base_vuln -= 0.1
        base_vuln += random.uniform(-0.1, 0.1)
        return max(0.0, min(1.0, base_vuln))

    def _create_service_nodes(self) -> Dict[str, ServiceNode]:
        nodes = {}
        for service in self.services:
            rules = SERVICE_CONNECTIVITY_RULES.get(service, DEFAULT_CONNECTIVITY)
            port = random.randint(*rules["port_range"])
            category = self._infer_category(service)
            vulnerability = self._assign_vulnerability(service, rules)
            
            # Try to assign specific CVEs if assigner is provided
            vulnerabilities = []
            if self.vulnerability_assigner:
                try:
                    vuln_list = self.vulnerability_assigner.assign_vulnerabilities(service)
                    # Assuming local helper or simple conversion
                    vulnerabilities = [asdict(v) for v in vuln_list] if hasattr(vuln_list[0], 'to_dict') else vuln_list
                except Exception as e:
                    print(f"Warning: Could not assign vulnerabilities to {service}: {e}")
            
            nodes[service] = ServiceNode(
                name=service,
                category=category,
                instance_count=self.service_instances.get(service, 1),
                port=port,
                protocol="TCP",
                is_public=rules.get("is_public", False),
                has_authentication=rules.get("requires_auth", True),
                vulnerability_level=vulnerability,
                vulnerabilities=vulnerabilities
            )
        return nodes

    def _generate_base_connectivity(self) -> List[NetworkEdge]:
        edges = []
        for service in self.services:
            rules = SERVICE_CONNECTIVITY_RULES.get(service, DEFAULT_CONNECTIVITY)
            for target in rules["connects_to"]:
                if target in self.services:
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
                        firewall_allowed=True
                    )
                    new_edges.append(edge)
        
        # Logging Push
        logger = "fluent-bit" if "fluent-bit" in self.services else ("fluentd" if "fluentd" in self.services else None)
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
                        firewall_allowed=True
                    )
                    new_edges.append(edge)
        return new_edges

    def _apply_firewall_rules(self, edges: List[NetworkEdge], firewall_probability: float) -> List[NetworkEdge]:
        filtered_edges = []
        for edge in edges:
            is_critical = (
                SERVICE_CONNECTIVITY_RULES.get(edge.source, {}).get("is_critical", False) or
                SERVICE_CONNECTIVITY_RULES.get(edge.target, {}).get("is_critical", False)
            )
            block_prob = firewall_probability * (0.3 if is_critical else 1.0)
            
            edge.firewall_allowed = random.random() > block_prob
            filtered_edges.append(edge)
        return filtered_edges

    def _compute_reachability(self, edges: List[NetworkEdge], entry_points: List[str]) -> Set[str]:
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

    def _generate_credential_flow(self, access_edges: List[NetworkEdge]) -> List[CredentialGrant]:
        credentials = []
        granted_credentials = {}
        
        for service in self.services:
            if service not in CREDENTIAL_ACCESS_PATTERNS:
                continue
            
            patterns = CREDENTIAL_ACCESS_PATTERNS[service]
            for target, (level_val, cred_type, tags) in patterns.items():
                if target not in self.services:
                    continue
                
                # Check for network access
                has_access = any(e.source == service and e.target == target and e.firewall_allowed for e in access_edges)
                is_operator = "operator" in service
                level = CredentialLevel(level_val)
                is_system = level == CredentialLevel.System
                
                if has_access or is_operator or is_system:
                    is_shared = False
                    for pattern_name, services_list in SHARED_CREDENTIAL_PATTERNS.items():
                        if service in services_list and target in pattern_name:
                            is_shared = True
                    
                    credentials.append(CredentialGrant(
                        source=service,
                        target=target,
                        credential_level=level,
                        credential_type=cred_type,
                        is_cached=(service in CREDENTIAL_CACHING_SERVICES),
                        is_shared=is_shared,
                        can_pivot=(level in [CredentialLevel.Admin, CredentialLevel.System])
                    ))
        return credentials

    def _compute_graph_metrics(self, edges: List[NetworkEdge]) -> Dict:
        if not edges:
            return {"avg_degree": 0.0, "is_connected": False}
        
        G = nx.DiGraph()
        for s in self.services: G.add_node(s)
        for e in edges: G.add_edge(e.source, e.target)
        
        n = len(self.services)
        m = len(edges)
        return {
            "avg_degree": (2 * m / n) if n > 0 else 0.0,
            "density": m / (n * (n - 1)) if n > 1 else 0.0,
            "is_connected": nx.is_weakly_connected(G) if n > 0 else False,
            "num_components": nx.number_weakly_connected_components(G)
        }

    def generate(self, firewall_probability: float = 0.2, knowledge_completeness: float = 0.7) -> NetworkTopology:
        self.service_nodes = self._create_service_nodes()
        base_edges = self._generate_base_connectivity()
        all_edges = self._add_implicit_connections(base_edges)
        filtered_edges = self._apply_firewall_rules(all_edges, firewall_probability)
        
        # Knowledge graph (what attacker sees)
        known_edges = [e for e in filtered_edges if random.random() < knowledge_completeness]
        
        # Access graph (what actually works)
        access_edges = [e for e in filtered_edges if e.firewall_allowed]
        
        entry_points = self._get_entry_points()
        credential_flow = self._generate_credential_flow(access_edges)
        
        access_reachability = list(self._compute_reachability(access_edges, entry_points))
        
        # Build node set for known reachability
        known_nodes = set(entry_points)
        for e in known_edges:
            known_nodes.add(e.source)
            known_nodes.add(e.target)
            
        metadata = {
            "total_services": len(self.services),
            "total_edges": len(all_edges),
            "entry_points": entry_points,
            "connectivity_metrics": self._compute_graph_metrics(access_edges)
        }
        
        return NetworkTopology(
            services=self.service_nodes,
            knows_connectivity=known_edges,
            knows_reachability=list(known_nodes),
            access_connectivity=access_edges,
            access_reachability=access_reachability,
            credential_flow=credential_flow,
            metadata=metadata
        )

# ======================================================================
# Export Helpers
# ======================================================================

def topology_to_dict(topology: NetworkTopology) -> Dict:
    """Convert NetworkTopology to dictionary format"""
    return {
        "services": {name: asdict(node) for name, node in topology.services.items()},
        "knows_connectivity": [asdict(edge) for edge in topology.knows_connectivity],
        "knows_reachability": topology.knows_reachability,
        "access_connectivity": [asdict(edge) for edge in topology.access_connectivity],
        "access_reachability": topology.access_reachability,
        "credential_flow": [
            {
                **asdict(cred),
                "credential_level": cred.credential_level.name
            }
            for cred in topology.credential_flow
        ],
        "metadata": topology.metadata
    }