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
# Credential Level Definitions
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
    source: str  # Service that possesses the credential
    target: str  # Service the credential grants access to
    credential_level: CredentialLevel
    credential_type: str  # e.g., "password", "token", "certificate", "service_account"
    is_cached: bool = False  # Whether credential is cached in memory
    is_shared: bool = False  # Whether multiple services share this credential
    can_pivot: bool = True  # Whether this can be used for lateral movement


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
    vulnerabilities: List[Dict] = None  # NEW: Assigned CVE vulnerabilities
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []


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
    credential_flow: List[CredentialGrant]  # NEW: Credential access graph
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
        "port_range": (2379, 2380),  # Standard etcd client/peer ports
        "requires_auth": True,
        "is_critical": True
    },
    
    "kube-state-metrics": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),  # Metrics port
        "requires_auth": False,
        "is_critical": False
    },
    
    "metrics-server": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (4443, 4443),  # Secure metrics port
        "requires_auth": True,
        "is_critical": False
    },
    
    "external-dns": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (7979, 7979),  # Metrics port
        "requires_auth": False,
        "is_critical": False
    },
    
    "common": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": False,
        "is_critical": False
    },
    
    # Observability - Metrics
    "prometheus": {
        "connects_to": ["node-exporter", "kube-state-metrics", "cadvisor", "grafana"],
        "connectivity_probability": 0.95,
        "port_range": (9090, 9090),  # Standard Prometheus port
        "requires_auth": False,
        "is_critical": False
    },
    
    "grafana": {
        "connects_to": ["prometheus", "grafana-loki", "grafana-tempo", "grafana-mimir"],
        "connectivity_probability": 0.9,
        "port_range": (3000, 3000),  # Standard Grafana port
        "requires_auth": True,
        "is_critical": False
    },
    
    "grafana-mimir": {
        "connects_to": ["minio"],
        "connectivity_probability": 0.8,
        "port_range": (8080, 8080),  # HTTP port
        "requires_auth": False,
        "is_critical": False
    },
    
    "thanos": {
        "connects_to": ["prometheus", "minio"],
        "connectivity_probability": 0.85,
        "port_range": (10902, 10902),  # gRPC port
        "requires_auth": False,
        "is_critical": False
    },
    
    "victoriametrics": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8428, 8428),  # HTTP port
        "requires_auth": False,
        "is_critical": False
    },
    
    "cadvisor": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": False,
        "is_critical": False
    },
    
    "node-exporter": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (9100, 9100),  # Standard node-exporter port
        "requires_auth": False,
        "is_critical": False
    },
    
    "kube-prometheus": {
        "connects_to": ["prometheus"],
        "connectivity_probability": 1.0,
        "port_range": (9090, 9090),
        "requires_auth": False,
        "is_critical": False
    },
    
    # Observability - Logging
    "grafana-loki": {
        "connects_to": ["fluent-bit", "fluentd", "grafana"],
        "connectivity_probability": 0.85,
        "port_range": (3100, 3100),  # HTTP port
        "requires_auth": False,
        "is_critical": False
    },
    
    "fluent-bit": {
        "connects_to": ["grafana-loki", "elasticsearch"],
        "connectivity_probability": 0.8,
        "port_range": (2020, 2020),  # HTTP port
        "requires_auth": False,
        "is_critical": False
    },
    
    "fluentd": {
        "connects_to": ["grafana-loki", "elasticsearch"],
        "connectivity_probability": 0.8,
        "port_range": (24224, 24224),  # Forward port
        "requires_auth": False,
        "is_critical": False
    },
    
    "elasticsearch": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (9200, 9200),  # HTTP API port
        "requires_auth": True,
        "is_critical": True
    },
    
    "opensearch": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (9200, 9200),  # HTTP API port
        "requires_auth": True,
        "is_critical": True
    },
    
    "logstash": {
        "connects_to": ["elasticsearch", "opensearch"],
        "connectivity_probability": 0.9,
        "port_range": (5044, 5044),  # Beats input port
        "requires_auth": False,
        "is_critical": False
    },
    
    "kibana": {
        "connects_to": ["elasticsearch", "opensearch"],
        "connectivity_probability": 0.95,
        "port_range": (5601, 5601),  # Standard Kibana port
        "requires_auth": True,
        "is_critical": False
    },
    
    "solr": {
        "connects_to": ["zookeeper"],
        "connectivity_probability": 0.8,
        "port_range": (8983, 8983),  # Standard Solr port
        "requires_auth": True,
        "is_critical": False
    },
    
    # Observability - Tracing
    "grafana-tempo": {
        "connects_to": ["minio"],
        "connectivity_probability": 0.8,
        "port_range": (3200, 3200),  # HTTP port
        "requires_auth": False,
        "is_critical": False
    },
    
    "jaeger": {
        "connects_to": ["elasticsearch", "cassandra"],
        "connectivity_probability": 0.7,
        "port_range": (16686, 16686),  # UI port
        "requires_auth": False,
        "is_critical": False
    },
    
    "zipkin": {
        "connects_to": ["elasticsearch", "cassandra"],
        "connectivity_probability": 0.6,
        "port_range": (9411, 9411),  # HTTP port
        "requires_auth": False,
        "is_critical": False
    },
    
    "grafana-alloy": {
        "connects_to": ["grafana-loki", "grafana-tempo", "prometheus"],
        "connectivity_probability": 0.7,
        "port_range": (12345, 12345),  # HTTP port
        "requires_auth": False,
        "is_critical": False
    },
    
    "grafana-operator": {
        "connects_to": ["grafana"],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": False,
        "is_critical": False
    },
    
    "grafana-k6-operator": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": False,
        "is_critical": False
    },
    
    "kubernetes-event-exporter": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (2112, 2112),
        "requires_auth": False,
        "is_critical": False
    },
    
    # Databases - SQL
    "postgresql": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (5432, 5432),  # Standard PostgreSQL port
        "requires_auth": True,
        "is_critical": True
    },
    
    "postgresql-ha": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (5432, 5432),
        "requires_auth": True,
        "is_critical": True
    },
    
    "cloudnative-pg": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (5432, 5432),
        "requires_auth": True,
        "is_critical": True
    },
    
    "mysql": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (3306, 3306),  # Standard MySQL port
        "requires_auth": True,
        "is_critical": True
    },
    
    "mariadb": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (3306, 3306),  # Standard MariaDB port
        "requires_auth": True,
        "is_critical": True
    },
    
    "mariadb-galera": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (3306, 3306),
        "requires_auth": True,
        "is_critical": True
    },
    
    "clickhouse": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8123, 8123),  # HTTP interface
        "requires_auth": True,
        "is_critical": True
    },
    
    "clickhouse-operator": {
        "connects_to": ["clickhouse"],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": False,
        "is_critical": False
    },
    
    # Databases - NoSQL
    "redis": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (6379, 6379),  # Standard Redis port
        "requires_auth": True,
        "is_critical": True
    },
    
    "redis-cluster": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (6379, 6379),
        "requires_auth": True,
        "is_critical": True
    },
    
    "valkey": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (6379, 6379),  # Redis-compatible port
        "requires_auth": True,
        "is_critical": True
    },
    
    "valkey-cluster": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (6379, 6379),
        "requires_auth": True,
        "is_critical": True
    },
    
    "keydb": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (6379, 6379),  # Redis-compatible port
        "requires_auth": True,
        "is_critical": True
    },
    
    "memcached": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (11211, 11211),  # Standard Memcached port
        "requires_auth": False,
        "is_critical": True
    },
    
    "mongodb": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (27017, 27017),  # Standard MongoDB port
        "requires_auth": True,
        "is_critical": True
    },
    
    "mongodb-sharded": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (27017, 27017),
        "requires_auth": True,
        "is_critical": True
    },
    
    "cassandra": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (9042, 9042),  # CQL native transport port
        "requires_auth": True,
        "is_critical": True
    },
    
    "scylladb": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (9042, 9042),  # Cassandra-compatible port
        "requires_auth": True,
        "is_critical": True
    },
    
    "influxdb": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8086, 8086),  # HTTP API port
        "requires_auth": True,
        "is_critical": True
    },
    
    "neo4j": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (7474, 7474),  # HTTP port
        "requires_auth": True,
        "is_critical": True
    },
    
    "janusgraph": {
        "connects_to": ["cassandra", "elasticsearch"],
        "connectivity_probability": 0.8,
        "port_range": (8182, 8182),  # Gremlin server port
        "requires_auth": True,
        "is_critical": False
    },
    
    "milvus": {
        "connects_to": ["etcd", "minio"],
        "connectivity_probability": 0.8,
        "port_range": (19530, 19530),  # gRPC port
        "requires_auth": True,
        "is_critical": False
    },
    
    "kube-arangodb": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8529, 8529),  # HTTP API port
        "requires_auth": True,
        "is_critical": True
    },
    
    # Messaging & Queuing
    "kafka": {
        "connects_to": ["zookeeper", "schema-registry"],
        "connectivity_probability": 0.9,
        "port_range": (9092, 9092),  # Standard Kafka port
        "requires_auth": True,
        "is_critical": True
    },
    
    "zookeeper": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (2181, 2181),  # Client port
        "requires_auth": False,
        "is_critical": True
    },
    
    "schema-registry": {
        "connects_to": ["kafka"],
        "connectivity_probability": 0.9,
        "port_range": (8081, 8081),  # REST API port
        "requires_auth": True,
        "is_critical": False
    },
    
    "rabbitmq": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (5672, 5672),  # AMQP port
        "requires_auth": True,
        "is_critical": True
    },
    
    "rabbitmq-cluster-operator": {
        "connects_to": ["rabbitmq"],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": False,
        "is_critical": False
    },
    
    "nats": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (4222, 4222),  # Client port
        "requires_auth": True,
        "is_critical": True
    },
    
    # Networking/Ingress
    "nginx-ingress-controller": {
        "connects_to": ["nginx", "wordpress", "ghost", "grafana"],
        "connectivity_probability": 0.85,
        "port_range": (80, 443),  # HTTP/HTTPS
        "requires_auth": False,
        "is_critical": True,
        "is_public": True
    },
    
    "nginx": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (80, 80),  # HTTP port
        "requires_auth": False,
        "is_critical": False
    },
    
    "apache": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (80, 80),  # HTTP port
        "requires_auth": False,
        "is_critical": False
    },
    
    "kong": {
        "connects_to": ["postgresql"],
        "connectivity_probability": 0.9,
        "port_range": (8000, 8443),  # Proxy port range
        "requires_auth": True,
        "is_critical": True,
        "is_public": True
    },
    
    "apisix": {
        "connects_to": ["etcd"],
        "connectivity_probability": 0.9,
        "port_range": (9080, 9080),  # Admin API port
        "requires_auth": True,
        "is_critical": True,
        "is_public": True
    },
    
    "contour": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8000, 8001),  # HTTP/HTTPS
        "requires_auth": False,
        "is_critical": True,
        "is_public": True
    },
    
    "envoy-gateway": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8443),
        "requires_auth": False,
        "is_critical": True,
        "is_public": True
    },
    
    "haproxy": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (80, 443),  # HTTP/HTTPS
        "requires_auth": False,
        "is_critical": True,
        "is_public": True
    },
    
    "cilium": {
        "connects_to": ["etcd"],
        "connectivity_probability": 0.8,
        "port_range": (9090, 9090),  # Metrics port
        "requires_auth": False,
        "is_critical": True
    },
    
    "multus-cni": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": False,
        "is_critical": True
    },
    
    "metallb": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (7472, 7472),  # Metrics port
        "requires_auth": False,
        "is_critical": True
    },
    
    "whereabouts": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": False,
        "is_critical": False
    },
    
    # Storage
    "minio": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (9000, 9000),  # S3 API port
        "requires_auth": True,
        "is_critical": False
    },
    
    "minio-operator": {
        "connects_to": ["minio"],
        "connectivity_probability": 1.0,
        "port_range": (4221, 4221),
        "requires_auth": False,
        "is_critical": False
    },
    
    "seaweedfs": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8333, 8333),  # Master port
        "requires_auth": True,
        "is_critical": False
    },
    
    # Security
    "vault": {
        "connects_to": ["postgresql"],
        "connectivity_probability": 0.7,
        "port_range": (8200, 8200),  # API port
        "requires_auth": True,
        "is_critical": True
    },
    
    "keycloak": {
        "connects_to": ["postgresql"],
        "connectivity_probability": 0.95,
        "port_range": (8080, 8080),  # HTTP port
        "requires_auth": True,
        "is_critical": True
    },
    
    "cert-manager": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (9402, 9402),  # Metrics port
        "requires_auth": False,
        "is_critical": True
    },
    
    "sealed-secrets": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": False,
        "is_critical": True
    },
    
    "oauth2-proxy": {
        "connects_to": ["keycloak"],
        "connectivity_probability": 0.8,
        "port_range": (4180, 4180),  # HTTP port
        "requires_auth": True,
        "is_critical": False
    },
    
    "pinniped": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8443, 8443),
        "requires_auth": True,
        "is_critical": False
    },
    
    "chainloop": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": True,
        "is_critical": False
    },
    
    "kiam": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8181, 8181),
        "requires_auth": False,
        "is_critical": False
    },
    
    # CI/CD
    "harbor": {
        "connects_to": ["postgresql", "redis"],
        "connectivity_probability": 0.9,
        "port_range": (443, 443),  # HTTPS port
        "requires_auth": True,
        "is_critical": False
    },
    
    "argo-cd": {
        "connects_to": ["redis"],
        "connectivity_probability": 0.8,
        "port_range": (8080, 8080),  # Server port
        "requires_auth": True,
        "is_critical": False
    },
    
    "argo-workflows": {
        "connects_to": ["postgresql"],
        "connectivity_probability": 0.7,
        "port_range": (2746, 2746),  # Server port
        "requires_auth": True,
        "is_critical": False
    },
    
    "flux": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": False,
        "is_critical": False
    },
    
    "jenkins": {
        "connects_to": ["postgresql"],
        "connectivity_probability": 0.6,
        "port_range": (8080, 8080),  # HTTP port
        "requires_auth": True,
        "is_critical": False
    },
    
    "concourse": {
        "connects_to": ["postgresql"],
        "connectivity_probability": 0.8,
        "port_range": (8080, 8080),  # Web UI port
        "requires_auth": True,
        "is_critical": False
    },
    
    "gitea": {
        "connects_to": ["postgresql", "mysql"],
        "connectivity_probability": 0.8,
        "port_range": (3000, 3000),  # HTTP port
        "requires_auth": True,
        "is_critical": False
    },
    
    "gitlab-runner": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (9252, 9252),  # Metrics port
        "requires_auth": False,
        "is_critical": False
    },
    
    "sonarqube": {
        "connects_to": ["postgresql"],
        "connectivity_probability": 0.8,
        "port_range": (9000, 9000),  # Web server port
        "requires_auth": True,
        "is_critical": False
    },
    
    # Data Processing
    "spark": {
        "connects_to": ["minio", "kafka"],
        "connectivity_probability": 0.7,
        "port_range": (4040, 4040),  # Web UI port
        "requires_auth": False,
        "is_critical": False
    },
    
    "flink": {
        "connects_to": ["kafka", "minio"],
        "connectivity_probability": 0.8,
        "port_range": (8081, 8081),  # JobManager port
        "requires_auth": False,
        "is_critical": False
    },
    
    "airflow": {
        "connects_to": ["postgresql", "redis", "rabbitmq"],
        "connectivity_probability": 0.8,
        "port_range": (8080, 8080),  # Webserver port
        "requires_auth": True,
        "is_critical": False
    },
    
    "dremio": {
        "connects_to": ["minio"],
        "connectivity_probability": 0.7,
        "port_range": (9047, 9047),  # Web UI port
        "requires_auth": True,
        "is_critical": False
    },
    
    "nessie": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (19120, 19120),  # REST API port
        "requires_auth": True,
        "is_critical": False
    },
    
    # ML/AI
    "mlflow": {
        "connects_to": ["postgresql", "minio"],
        "connectivity_probability": 0.85,
        "port_range": (5000, 5000),  # Server port
        "requires_auth": False,
        "is_critical": False
    },
    
    "jupyterhub": {
        "connects_to": ["postgresql"],
        "connectivity_probability": 0.7,
        "port_range": (8000, 8000),  # Hub port
        "requires_auth": True,
        "is_critical": False
    },
    
    "kuberay": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8265, 8265),  # Dashboard port
        "requires_auth": False,
        "is_critical": False
    },
    
    "pytorch": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": False,
        "is_critical": False
    },
    
    "deepspeed": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),
        "requires_auth": False,
        "is_critical": False
    },
    
    "tensorflow-resnet": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8501, 8501),  # TensorFlow Serving REST API
        "requires_auth": False,
        "is_critical": False
    },
    
    # Web Applications
    "wordpress": {
        "connects_to": ["mysql", "mariadb", "redis"],
        "connectivity_probability": 0.8,
        "port_range": (80, 80),  # HTTP port
        "requires_auth": False,
        "is_critical": False
    },
    
    "drupal": {
        "connects_to": ["postgresql", "mysql", "mariadb"],
        "connectivity_probability": 0.8,
        "port_range": (80, 80),  # HTTP port
        "requires_auth": False,
        "is_critical": False
    },
    
    "ghost": {
        "connects_to": ["mysql", "mariadb"],
        "connectivity_probability": 0.8,
        "port_range": (2368, 2368),  # Default Ghost port
        "requires_auth": True,
        "is_critical": False
    },
    
    "moodle": {
        "connects_to": ["postgresql", "mysql", "mariadb"],
        "connectivity_probability": 0.8,
        "port_range": (80, 80),  # HTTP port
        "requires_auth": True,
        "is_critical": False
    },
    
    "discourse": {
        "connects_to": ["postgresql", "redis"],
        "connectivity_probability": 0.8,
        "port_range": (80, 80),  # HTTP port
        "requires_auth": True,
        "is_critical": False
    },
    
    "mastodon": {
        "connects_to": ["postgresql", "redis"],
        "connectivity_probability": 0.8,
        "port_range": (3000, 3000),  # Web port
        "requires_auth": True,
        "is_critical": False
    },
    
    "matomo": {
        "connects_to": ["mysql", "mariadb"],
        "connectivity_probability": 0.8,
        "port_range": (80, 80),  # HTTP port
        "requires_auth": True,
        "is_critical": False
    },
    
    "phpmyadmin": {
        "connects_to": ["mysql", "mariadb"],
        "connectivity_probability": 0.9,
        "port_range": (80, 80),  # HTTP port
        "requires_auth": True,
        "is_critical": False
    },
    
    "tomcat": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),  # HTTP port
        "requires_auth": True,
        "is_critical": False
    },
    
    "wildfly": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (8080, 8080),  # HTTP port
        "requires_auth": True,
        "is_critical": False
    },
    
    "aspnet-core": {
        "connects_to": [],
        "connectivity_probability": 1.0,
        "port_range": (5000, 5000),  # Default Kestrel port
        "requires_auth": False,
        "is_critical": False
    },
    
    # Enterprise Apps
    "odoo": {
        "connects_to": ["postgresql"],
        "connectivity_probability": 0.9,
        "port_range": (8069, 8069),  # Web client port
        "requires_auth": True,
        "is_critical": False
    },
    
    "redmine": {
        "connects_to": ["postgresql", "mysql", "mariadb"],
        "connectivity_probability": 0.8,
        "port_range": (3000, 3000),  # Web server port
        "requires_auth": True,
        "is_critical": False
    },
    
    "superset": {
        "connects_to": ["postgresql", "redis"],
        "connectivity_probability": 0.8,
        "port_range": (8088, 8088),  # Web server port
        "requires_auth": True,
        "is_critical": False
    },
    
    "appsmith": {
        "connects_to": ["mongodb", "redis"],
        "connectivity_probability": 0.8,
        "port_range": (80, 80),  # HTTP port
        "requires_auth": True,
        "is_critical": False
    },
    
    "parse": {
        "connects_to": ["mongodb"],
        "connectivity_probability": 0.9,
        "port_range": (1337, 1337),  # API server port
        "requires_auth": True,
        "is_critical": False
    },
    
    "ejbca": {
        "connects_to": ["postgresql", "mariadb"],
        "connectivity_probability": 0.8,
        "port_range": (8443, 8443),  # HTTPS port
        "requires_auth": True,
        "is_critical": True
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
# Credential Access Patterns
# ======================================================================

# Define what credential level each service typically needs to access others
CREDENTIAL_ACCESS_PATTERNS = {
    # Applications accessing databases - typically get dedicated user accounts
    "harbor": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "redis": (CredentialLevel.LocalUser, "password", ["cache_credentials"])
    },
    
    "keycloak": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    "airflow": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "redis": (CredentialLevel.LocalUser, "password", ["celery_broker"]),
        "rabbitmq": (CredentialLevel.LocalUser, "password", ["message_queue"])
    },
    
    "mlflow": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "minio": (CredentialLevel.LocalUser, "access_key", ["s3_credentials"])
    },
    
    "jupyterhub": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    "discourse": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "redis": (CredentialLevel.LocalUser, "password", ["cache_credentials"])
    },
    
    "mastodon": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "redis": (CredentialLevel.LocalUser, "password", ["cache_credentials"])
    },
    
    "superset": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "redis": (CredentialLevel.LocalUser, "password", ["cache_credentials"])
    },
    
    "wordpress": {
        "mysql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "mariadb": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "redis": (CredentialLevel.LocalUser, "password", ["cache_credentials"])
    },
    
    "drupal": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "mysql": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    "ghost": {
        "mysql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "mariadb": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    "gitea": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "mysql": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    "odoo": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    "redmine": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "mysql": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    "sonarqube": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    "appsmith": {
        "mongodb": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "redis": (CredentialLevel.LocalUser, "password", ["cache_credentials"])
    },
    
    "parse": {
        "mongodb": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    # API Gateways - often have admin credentials to backends
    "kong": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    # Security services - typically need elevated access
    "vault": {
        "postgresql": (CredentialLevel.Admin, "password", ["database_admin"]),
        "etcd": (CredentialLevel.Admin, "certificate", ["etcd_root"])
    },
    
    # Monitoring - typically read-only but to many services
    "grafana": {
        "prometheus": (CredentialLevel.LocalUser, "token", ["readonly"]),
        "grafana-loki": (CredentialLevel.LocalUser, "token", ["readonly"]),
        "grafana-tempo": (CredentialLevel.LocalUser, "token", ["readonly"]),
        "grafana-mimir": (CredentialLevel.LocalUser, "token", ["readonly"])
    },
    
    # CI/CD - often has high privileges
    "jenkins": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    "argo-cd": {
        "redis": (CredentialLevel.LocalUser, "password", ["cache_credentials"])
    },
    
    "argo-workflows": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    "concourse": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    # Messaging dependencies
    "kafka": {
        "zookeeper": (CredentialLevel.Admin, "password", ["cluster_coordination"])
    },
    
    "schema-registry": {
        "kafka": (CredentialLevel.LocalUser, "password", ["schema_management"])
    },
    
    # Storage clients
    "thanos": {
        "prometheus": (CredentialLevel.LocalUser, "service_account", ["metrics_reader"]),
        "minio": (CredentialLevel.LocalUser, "access_key", ["s3_credentials"])
    },
    
    "grafana-mimir": {
        "minio": (CredentialLevel.LocalUser, "access_key", ["s3_credentials"])
    },
    
    "grafana-tempo": {
        "minio": (CredentialLevel.LocalUser, "access_key", ["s3_credentials"])
    },
    
    # Data processing
    "spark": {
        "minio": (CredentialLevel.LocalUser, "access_key", ["s3_credentials"]),
        "kafka": (CredentialLevel.LocalUser, "password", ["consumer_credentials"])
    },
    
    "flink": {
        "kafka": (CredentialLevel.LocalUser, "password", ["consumer_credentials"]),
        "minio": (CredentialLevel.LocalUser, "access_key", ["s3_credentials"])
    },
    
    # Logging pipeline
    "logstash": {
        "elasticsearch": (CredentialLevel.LocalUser, "password", ["ingest_credentials"]),
        "opensearch": (CredentialLevel.LocalUser, "password", ["ingest_credentials"])
    },
    
    "fluent-bit": {
        "grafana-loki": (CredentialLevel.LocalUser, "token", ["write_logs"]),
        "elasticsearch": (CredentialLevel.LocalUser, "password", ["write_logs"])
    },
    
    "fluentd": {
        "grafana-loki": (CredentialLevel.LocalUser, "token", ["write_logs"]),
        "elasticsearch": (CredentialLevel.LocalUser, "password", ["write_logs"])
    },
    
    # Tracing
    "jaeger": {
        "elasticsearch": (CredentialLevel.LocalUser, "password", ["trace_storage"]),
        "cassandra": (CredentialLevel.LocalUser, "password", ["trace_storage"])
    },
    
    "zipkin": {
        "elasticsearch": (CredentialLevel.LocalUser, "password", ["trace_storage"]),
        "cassandra": (CredentialLevel.LocalUser, "password", ["trace_storage"])
    },
    
    # Graph databases with backends
    "janusgraph": {
        "cassandra": (CredentialLevel.LocalUser, "password", ["graph_storage"]),
        "elasticsearch": (CredentialLevel.LocalUser, "password", ["graph_index"])
    },
    
    "milvus": {
        "etcd": (CredentialLevel.LocalUser, "password", ["metadata_storage"]),
        "minio": (CredentialLevel.LocalUser, "access_key", ["vector_storage"])
    },
    
    # Search
    "kibana": {
        "elasticsearch": (CredentialLevel.Admin, "password", ["kibana_system"]),
        "opensearch": (CredentialLevel.Admin, "password", ["kibana_system"])
    },
    
    "solr": {
        "zookeeper": (CredentialLevel.LocalUser, "password", ["cluster_coordination"])
    },
    
    # Operators - typically need admin/system access
    "clickhouse-operator": {
        "clickhouse": (CredentialLevel.Admin, "password", ["operator_admin"])
    },
    
    "minio-operator": {
        "minio": (CredentialLevel.Admin, "access_key", ["operator_admin"])
    },
    
    "rabbitmq-cluster-operator": {
        "rabbitmq": (CredentialLevel.Admin, "password", ["operator_admin"])
    },
    
    "grafana-operator": {
        "grafana": (CredentialLevel.Admin, "token", ["operator_admin"])
    },
    
    # CNI and networking - system level
    "cilium": {
        "etcd": (CredentialLevel.System, "certificate", ["cluster_networking"])
    },
    
    "apisix": {
        "etcd": (CredentialLevel.LocalUser, "password", ["config_storage"])
    },
    
    # Auth proxy
    "oauth2-proxy": {
        "keycloak": (CredentialLevel.LocalUser, "client_secret", ["oidc_client"])
    },
    
    # Monitoring operators
    "kube-prometheus": {
        "prometheus": (CredentialLevel.Admin, "service_account", ["prometheus_operator"])
    },
    
    # Web management
    "phpmyadmin": {
        "mysql": (CredentialLevel.Admin, "password", ["admin_user"]),
        "mariadb": (CredentialLevel.Admin, "password", ["admin_user"])
    },
    
    "matomo": {
        "mysql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "mariadb": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    "moodle": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "mysql": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    },
    
    # Data lake
    "dremio": {
        "minio": (CredentialLevel.LocalUser, "access_key", ["data_lake_access"])
    },
    
    # PKI
    "ejbca": {
        "postgresql": (CredentialLevel.LocalUser, "password", ["database_credentials"]),
        "mariadb": (CredentialLevel.LocalUser, "password", ["database_credentials"])
    }
}

# Services that commonly cache credentials in memory
CREDENTIAL_CACHING_SERVICES = [
    "jenkins", "harbor", "argo-cd", "gitlab-runner",
    "airflow", "spark", "flink",
    "wordpress", "drupal", "ghost"
]

# Credentials that are commonly shared across multiple services
SHARED_CREDENTIAL_PATTERNS = {
    # Read-only monitoring credentials often shared
    "prometheus_readonly": ["grafana", "superset", "jupyterhub"],
    
    # S3/MinIO credentials often shared for data pipelines
    "minio_data_pipeline": ["spark", "flink", "mlflow", "airflow"],
    
    # Kafka consumer groups may share credentials
    "kafka_consumer": ["spark", "flink"],
    
    # Common database user for read-only analytics
    "postgresql_readonly": ["superset", "metabase", "redash"]
}


# ======================================================================
# Network Topology Generator
# ======================================================================

class NetworkTopologyGenerator:
    """Generate realistic network topologies for Kubernetes service collections"""
    
    def __init__(self, services: List[str], service_instances: Dict[str, int] = None, 
                 seed: int = None, vulnerability_assigner=None):
        """
        Initialize the topology generator
        
        Args:
            services: List of service names
            service_instances: Dictionary of service -> instance count
            seed: Random seed for reproducibility
            vulnerability_assigner: Optional VulnerabilityAssigner instance
        """
        self.services = services
        self.service_instances = service_instances or {s: 1 for s in services}
        self.service_nodes: Dict[str, ServiceNode] = {}
        self.vulnerability_assigner = vulnerability_assigner
        
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
            
            # Assign CVE vulnerabilities if assigner available
            vulnerabilities = []
            if self.vulnerability_assigner:
                try:
                    vuln_list = self.vulnerability_assigner.assign_vulnerabilities(service)
                    # Convert to dict format
                    from vulnerability_assigner import vulnerabilities_to_dict
                    vulnerabilities = vulnerabilities_to_dict(vuln_list)
                except Exception as e:
                    print(f"Warning: Could not assign vulnerabilities to {service}: {e}")
            
            node = ServiceNode(
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
        Generate complete network topology with all graph types including credential flow
        
        Args:
            firewall_probability: Probability that a connection is blocked by firewall
            knowledge_completeness: How much of the network the attacker knows (0-1)
        
        Returns:
            NetworkTopology object with all graphs including credential flow
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
        known_edges = []
        for edge in filtered_edges:
            if random.random() < knowledge_completeness:
                known_edges.append(edge)
        
        # access_connectivity: only edges that are firewall allowed
        access_edges = [e for e in filtered_edges if e.firewall_allowed]
        
        # Generate credential flow based on access connectivity
        credential_flow = self._generate_credential_flow(access_edges)
        
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
        
        # Compute credential metrics
        credential_metrics = self._compute_credential_metrics(credential_flow)
        
        # Compute vulnerability metrics
        vulnerability_stats = self._compute_vulnerability_stats()
        
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
            "connectivity_metrics": self._compute_graph_metrics(access_edges),
            "credential_metrics": credential_metrics,
            "vulnerability_stats": vulnerability_stats
        }
        
        return NetworkTopology(
            services=self.service_nodes,
            knows_connectivity=known_edges,
            knows_reachability=knows_reachability,
            access_connectivity=access_edges,
            access_reachability=access_reachability,
            credential_flow=credential_flow,
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
    
    def _generate_credential_flow(self, access_edges: List[NetworkEdge]) -> List[CredentialGrant]:
        """
        Generate credential flow graph showing what credentials services have
        
        This models:
        - Application credentials to databases
        - Service account tokens
        - API keys and access tokens
        - Cached credentials
        - Shared credentials
        """
        credentials = []
        granted_credentials = {}  # Track what's been granted to detect sharing
        
        # Generate credentials based on access patterns
        for service in self.services:
            if service not in CREDENTIAL_ACCESS_PATTERNS:
                continue
            
            patterns = CREDENTIAL_ACCESS_PATTERNS[service]
            
            for target, (level, cred_type, tags) in patterns.items():
                # Check if target service exists in cluster
                if target not in self.services:
                    continue
                
                # Check if there's a network connection
                has_network_access = any(
                    e.source == service and e.target == target and e.firewall_allowed
                    for e in access_edges
                )
                
                # Only grant credential if network access exists
                # Exception: Operators and system services can have credentials without direct network access
                is_operator = "operator" in service
                is_system = level == CredentialLevel.System
                
                if has_network_access or is_operator or is_system:
                    # Check if this credential should be shared
                    is_shared = False
                    for pattern_name, services_list in SHARED_CREDENTIAL_PATTERNS.items():
                        if service in services_list and target in pattern_name:
                            credential_key = f"{target}_{pattern_name}"
                            if credential_key in granted_credentials:
                                is_shared = True
                            granted_credentials[credential_key] = service
                    
                    # Check if service caches credentials
                    is_cached = service in CREDENTIAL_CACHING_SERVICES
                    
                    # Determine if credential can be used for pivoting
                    # System and Admin credentials are more useful for lateral movement
                    can_pivot = level in [CredentialLevel.Admin, CredentialLevel.System]
                    
                    credential = CredentialGrant(
                        source=service,
                        target=target,
                        credential_level=level,
                        credential_type=cred_type,
                        is_cached=is_cached,
                        is_shared=is_shared,
                        can_pivot=can_pivot
                    )
                    credentials.append(credential)
        
        # Add Prometheus scraping credentials (implicit service account)
        # Prometheus typically uses service accounts with read access
        if "prometheus" in self.services:
            for service in self.services:
                if service != "prometheus":
                    # Check if prometheus can reach this service
                    has_access = any(
                        e.source == "prometheus" and e.target == service and e.firewall_allowed
                        for e in access_edges
                    )
                    
                    if has_access:
                        credential = CredentialGrant(
                            source="prometheus",
                            target=service,
                            credential_level=CredentialLevel.LocalUser,
                            credential_type="service_account",
                            is_cached=False,
                            is_shared=False,
                            can_pivot=False
                        )
                        credentials.append(credential)
        
        # Add etcd access for control plane components
        # etcd typically uses certificate-based auth at system level
        if "etcd" in self.services:
            control_plane_services = [
                "kube-state-metrics", "metrics-server", "cilium", "apisix"
            ]
            for service in control_plane_services:
                if service in self.services:
                    has_access = any(
                        e.target == "etcd" and e.firewall_allowed
                        for e in access_edges if e.source == service
                    )
                    
                    if has_access:
                        credential = CredentialGrant(
                            source=service,
                            target="etcd",
                            credential_level=CredentialLevel.System if service == "cilium" else CredentialLevel.LocalUser,
                            credential_type="certificate",
                            is_cached=True,
                            is_shared=False,
                            can_pivot=True
                        )
                        credentials.append(credential)
        
        return credentials
    
    def _compute_credential_metrics(self, credentials: List[CredentialGrant]) -> Dict:
        """Compute metrics about credential distribution"""
        if not credentials:
            return {
                "total_credentials": 0,
                "cached_credentials": 0,
                "shared_credentials": 0,
                "pivot_credentials": 0,
                "by_level": {},
                "by_type": {}
            }
        
        by_level = {}
        by_type = {}
        
        for cred in credentials:
            level_name = cred.credential_level.name
            by_level[level_name] = by_level.get(level_name, 0) + 1
            by_type[cred.credential_type] = by_type.get(cred.credential_type, 0) + 1
        
        return {
            "total_credentials": len(credentials),
            "cached_credentials": sum(1 for c in credentials if c.is_cached),
            "shared_credentials": sum(1 for c in credentials if c.is_shared),
            "pivot_credentials": sum(1 for c in credentials if c.can_pivot),
            "by_level": by_level,
            "by_type": by_type,
            "admin_or_system": sum(1 for c in credentials if c.credential_level in [CredentialLevel.Admin, CredentialLevel.System])
        }
    
    def _compute_vulnerability_stats(self) -> Dict:
        """Compute vulnerability statistics across all services"""
        total_vulns = 0
        by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        services_with_vulns = 0
        total_cvss = []
        total_exploitability = []
        
        for service_name, node in self.service_nodes.items():
            if node.vulnerabilities:
                services_with_vulns += 1
                total_vulns += len(node.vulnerabilities)
                
                for vuln in node.vulnerabilities:
                    severity = vuln.get("severity", "UNKNOWN")
                    if severity in by_severity:
                        by_severity[severity] += 1
                    
                    if vuln.get("cvss_score"):
                        total_cvss.append(vuln["cvss_score"])
                    
                    if vuln.get("exploitability"):
                        total_exploitability.append(vuln["exploitability"])
        
        return {
            "total_vulnerabilities": total_vulns,
            "services_with_vulnerabilities": services_with_vulns,
            "services_without_vulnerabilities": len(self.services) - services_with_vulns,
            "by_severity": by_severity,
            "total_critical": by_severity["CRITICAL"],
            "total_high": by_severity["HIGH"],
            "avg_cvss_score": sum(total_cvss) / len(total_cvss) if total_cvss else 0.0,
            "max_cvss_score": max(total_cvss) if total_cvss else 0.0,
            "avg_exploitability": sum(total_exploitability) / len(total_exploitability) if total_exploitability else 0.0,
            "avg_vulnerabilities_per_service": total_vulns / len(self.services) if self.services else 0.0
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
        "credential_flow": [
            {
                **asdict(cred),
                "credential_level": cred.credential_level.name  # Convert enum to string
            }
            for cred in topology.credential_flow
        ],
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
