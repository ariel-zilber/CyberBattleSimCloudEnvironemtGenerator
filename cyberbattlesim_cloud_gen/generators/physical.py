"""
Physical Topology Generator
===========================
Generates realistic physical node topology:
- Physical nodes with characteristics (CPU, Memory, etc.)
- Maps services/pods to nodes based on affinity
- Simulates network partitioning and zones
- Assigns IP addresses and security groups
"""

import random
import ipaddress
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum

# Relative imports from the config package
from ..config.enums import ClusterSize, UseCase
from ..config.models import ServiceProfile
from ..config.catalogs import SERVICE_CATALOG

# ======================================================================
# Node Configuration and Types
# ======================================================================

class NodeType(Enum):
    """Types of physical nodes in a Kubernetes cluster"""
    CONTROL_PLANE = "control_plane"  # Master nodes
    WORKER = "worker"                # General workload nodes
    COMPUTE_OPTIMIZED = "compute"    # High CPU nodes
    MEMORY_OPTIMIZED = "memory"      # High memory nodes
    STORAGE_OPTIMIZED = "storage"    # High disk I/O nodes
    GPU = "gpu"                      # GPU-enabled nodes
    EDGE = "edge"                    # Edge computing nodes


class NodeZone:
    """Dynamic zone representation that supports unlimited zones"""
    
    @staticmethod
    def get_zones(count: int) -> List[str]:
        """Generate zone names for the specified count"""
        if count <= 0:
            return ["zone-a"]
        
        if count <= 26:
            return [f"zone-{chr(65 + i)}".lower() for i in range(count)]
        else:
            return [f"zone-{i+1}" for i in range(count)]


@dataclass
class IPAllocation:
    """IP address allocation for a node"""
    ipv4: str
    subnet: str
    gateway: str
    cidr: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


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
            "rules": [rule.to_dict() for rule in self.rules]
        }


@dataclass
class NodeCharacteristics:
    """Physical characteristics of a node"""
    cpu_cores: int
    memory_gb: int
    disk_gb: int
    network_bandwidth_gbps: float
    has_gpu: bool = False
    gpu_count: int = 0
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class PhysicalNode:
    """Represents a physical node in the cluster"""
    node_id: str
    node_type: NodeType
    zone: str
    ip_allocation: IPAllocation
    characteristics: NodeCharacteristics
    assigned_pods: List[Tuple[str, int]] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    is_healthy: bool = True
    cpu_utilization: float = 0.0
    memory_utilization: float = 0.0
    security_groups: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "zone": self.zone,
            "ip_allocation": self.ip_allocation.to_dict(),
            "characteristics": self.characteristics.to_dict(),
            "assigned_pods": [{"service": svc, "instance": inst} for svc, inst in self.assigned_pods],
            "labels": self.labels,
            "is_healthy": self.is_healthy,
            "cpu_utilization": round(self.cpu_utilization, 2),
            "memory_utilization": round(self.memory_utilization, 2),
            "pod_count": len(self.assigned_pods),
            "security_groups": self.security_groups
        }


@dataclass
class NodeConnection:
    """Represents a network connection between nodes"""
    from_node: str
    to_node: str
    from_ip: str
    to_ip: str
    latency_ms: float
    bandwidth_gbps: float
    packet_loss: float
    is_firewalled: bool = False
    firewall_rules: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "from": self.from_node,
            "to": self.to_node,
            "from_ip": self.from_ip,
            "to_ip": self.to_ip,
            "latency_ms": round(self.latency_ms, 2),
            "bandwidth_gbps": round(self.bandwidth_gbps, 2),
            "packet_loss": round(self.packet_loss, 4),
            "is_firewalled": self.is_firewalled,
            "firewall_rules": self.firewall_rules,
            "allowed_ports": self.allowed_ports
        }


@dataclass
class NetworkAccessGraph:
    """Represents network accessibility between nodes"""
    source_node: str
    destination_node: str
    source_ip: str
    destination_ip: str
    accessible: bool
    allowed_ports: List[int]
    blocked_ports: List[int]
    path_latency: float
    firewall_rules_applied: List[str]
    
    def to_dict(self) -> Dict:
        return {
            "source_node": self.source_node,
            "destination_node": self.destination_node,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "accessible": self.accessible,
            "allowed_ports": self.allowed_ports,
            "blocked_ports": self.blocked_ports,
            "path_latency": round(self.path_latency, 2),
            "firewall_rules_applied": self.firewall_rules_applied
        }


# ======================================================================
# Node Type Profiles
# ======================================================================

NODE_TYPE_PROFILES = {
    NodeType.CONTROL_PLANE: {
        "cpu_range": (4, 8),
        "memory_range": (16, 32),
        "disk_range": (100, 200),
        "bandwidth": 10.0,
        "min_count": 3,  # Always odd number for quorum
        "ha_required": True
    },
    NodeType.WORKER: {
        "cpu_range": (4, 16),
        "memory_range": (16, 64),
        "disk_range": (100, 500),
        "bandwidth": 10.0,
        "min_count": 2,
        "ha_required": False
    },
    NodeType.COMPUTE_OPTIMIZED: {
        "cpu_range": (16, 64),
        "memory_range": (32, 128),
        "disk_range": (200, 1000),
        "bandwidth": 25.0,
        "min_count": 0,
        "ha_required": False
    },
    NodeType.MEMORY_OPTIMIZED: {
        "cpu_range": (8, 32),
        "memory_range": (128, 512),
        "disk_range": (200, 1000),
        "bandwidth": 25.0,
        "min_count": 0,
        "ha_required": False
    },
    NodeType.STORAGE_OPTIMIZED: {
        "cpu_range": (8, 16),
        "memory_range": (32, 128),
        "disk_range": (1000, 10000),
        "bandwidth": 10.0,
        "min_count": 0,
        "ha_required": False
    },
    NodeType.GPU: {
        "cpu_range": (16, 32),
        "memory_range": (64, 256),
        "disk_range": (500, 2000),
        "bandwidth": 25.0,
        "min_count": 0,
        "ha_required": False,
        "gpu_count_range": (1, 8)
    },
    NodeType.EDGE: {
        "cpu_range": (2, 8),
        "memory_range": (8, 32),
        "disk_range": (50, 200),
        "bandwidth": 1.0,
        "min_count": 0,
        "ha_required": False
    }
}


# Service to port mappings for firewall rules
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


# Service affinity rules - which services prefer which node types
SERVICE_NODE_AFFINITY = {
    # Control plane services
    "etcd": [NodeType.CONTROL_PLANE],
    "kube-state-metrics": [NodeType.CONTROL_PLANE, NodeType.WORKER],
    "metrics-server": [NodeType.CONTROL_PLANE, NodeType.WORKER],
    
    # Data services prefer memory/storage optimized
    "postgresql": [NodeType.MEMORY_OPTIMIZED, NodeType.STORAGE_OPTIMIZED, NodeType.WORKER],
    "mysql": [NodeType.MEMORY_OPTIMIZED, NodeType.STORAGE_OPTIMIZED, NodeType.WORKER],
    "mongodb": [NodeType.MEMORY_OPTIMIZED, NodeType.STORAGE_OPTIMIZED, NodeType.WORKER],
    "redis": [NodeType.MEMORY_OPTIMIZED, NodeType.WORKER],
    "valkey": [NodeType.MEMORY_OPTIMIZED, NodeType.WORKER],
    "elasticsearch": [NodeType.MEMORY_OPTIMIZED, NodeType.STORAGE_OPTIMIZED],
    "clickhouse": [NodeType.MEMORY_OPTIMIZED, NodeType.STORAGE_OPTIMIZED],
    "cassandra": [NodeType.STORAGE_OPTIMIZED, NodeType.MEMORY_OPTIMIZED],
    
    # Big data / ML prefer compute or GPU
    "spark": [NodeType.COMPUTE_OPTIMIZED, NodeType.GPU, NodeType.WORKER],
    "flink": [NodeType.COMPUTE_OPTIMIZED, NodeType.WORKER],
    "airflow": [NodeType.COMPUTE_OPTIMIZED, NodeType.WORKER],
    "mlflow": [NodeType.GPU, NodeType.COMPUTE_OPTIMIZED, NodeType.WORKER],
    "jupyterhub": [NodeType.GPU, NodeType.COMPUTE_OPTIMIZED, NodeType.WORKER],
    
    # Messaging systems
    "kafka": [NodeType.STORAGE_OPTIMIZED, NodeType.MEMORY_OPTIMIZED, NodeType.WORKER],
    "rabbitmq": [NodeType.MEMORY_OPTIMIZED, NodeType.WORKER],
    "zookeeper": [NodeType.MEMORY_OPTIMIZED, NodeType.WORKER],
    
    # Object storage
    "minio": [NodeType.STORAGE_OPTIMIZED, NodeType.WORKER],
    
    # Default for everything else
    "default": [NodeType.WORKER, NodeType.COMPUTE_OPTIMIZED]
}


# ======================================================================
# Physical Node Topology Generator
# ======================================================================

class PhysicalNodeGenerator:
    """Generate physical node topology for a Kubernetes cluster"""
    
    def __init__(self, cluster_config: Dict, num_nodes: Optional[int] = None, 
                 num_zones: Optional[int] = None, zone_distribution: str = "balanced",
                 seed: Optional[int] = None):
        self.cluster_config = cluster_config
        # Allow overriding num_nodes from the config
        self.num_nodes = num_nodes if num_nodes is not None else cluster_config["cluster_metadata"]["num_nodes"]
        # Recalculate cluster size if num_nodes was overridden
        if num_nodes is not None:
            self.cluster_size = self._determine_cluster_size(num_nodes)
        else:
            self.cluster_size = ClusterSize[cluster_config["cluster_metadata"]["cluster_size"]]
        self.use_case = UseCase(cluster_config["cluster_metadata"]["use_case"])
        self.services = cluster_config["services"]
        self.service_instances = cluster_config["service_instances"]
        
        # Zone configuration - unlimited zones support
        if num_zones is not None:
            self.num_zones = max(1, num_zones)  # At least 1 zone
        else:
            self.num_zones = self._auto_determine_zones()
        self.zone_distribution = zone_distribution
        
        self.nodes: List[PhysicalNode] = []
        self.node_connections: List[NodeConnection] = []
        self.security_groups: Dict[str, SecurityGroup] = {}
        self.network_access_graph: List[NetworkAccessGraph] = []
        
        # IP allocation tracking
        self.zone_subnets: Dict[str, ipaddress.IPv4Network] = {}
        self.zone_ip_allocations: Dict[str, Set[str]] = {}
        
        if seed is not None:
            random.seed(seed)
    
    def _auto_determine_zones(self) -> int:
        """Automatically determine number of zones based on cluster size"""
        if self.cluster_size == ClusterSize.TINY:
            return 1
        elif self.cluster_size == ClusterSize.SMALL:
            return 2
        elif self.cluster_size == ClusterSize.MEDIUM:
            return 3
        elif self.cluster_size == ClusterSize.LARGE:
            return 4
        else:  # XLARGE and beyond
            return 6
    
    @staticmethod
    def _determine_cluster_size(num_nodes: int) -> ClusterSize:
        """Determine cluster size category from node count"""
        for size in ClusterSize:
            min_nodes, max_nodes = size.value
            if min_nodes <= num_nodes <= max_nodes:
                return size
        return ClusterSize.XLARGE
    
    def _initialize_network_subnets(self):
        """Initialize IP subnets for each zone"""
        base_network = ipaddress.ip_network("10.0.0.0/8")
        
        # Calculate subnet size based on number of zones and expected nodes per zone
        if self.num_zones <= 256:
            subnet_prefix = 16
        else:
            subnet_prefix = 24
        
        # Create subnets for each zone
        zone_subnets = list(base_network.subnets(new_prefix=subnet_prefix))
        available_zones = NodeZone.get_zones(self.num_zones)
        
        for i, zone in enumerate(available_zones):
            if i < len(zone_subnets):
                self.zone_subnets[zone] = zone_subnets[i]
                self.zone_ip_allocations[zone] = set()
            else:
                # Fallback
                fallback_subnet = ipaddress.ip_network(f"10.{i}.0.0/{subnet_prefix}")
                self.zone_subnets[zone] = fallback_subnet
                self.zone_ip_allocations[zone] = set()
    
    def _allocate_ip_for_node(self, zone: str, node_index: int) -> IPAllocation:
        """Allocate IP address for a node in a specific zone"""
        if zone not in self.zone_subnets:
            fallback_index = len(self.zone_subnets)
            self.zone_subnets[zone] = ipaddress.ip_network(f"10.{fallback_index}.0.0/24")
            self.zone_ip_allocations[zone] = set()
        
        subnet = self.zone_subnets[zone]
        
        # Calculate IP based on node index (skip network, gateway)
        ip_index = (node_index % (subnet.num_addresses - 3)) + 2 
        ip_address = str(subnet[ip_index])
        
        while ip_address in self.zone_ip_allocations[zone]:
            ip_index = (ip_index + 1) % (subnet.num_addresses - 3) + 2
            ip_address = str(subnet[ip_index])
        
        self.zone_ip_allocations[zone].add(ip_address)
        gateway = str(subnet[1])
        cidr = str(subnet)
        
        return IPAllocation(
            ipv4=ip_address,
            subnet=str(subnet.netmask),
            gateway=gateway,
            cidr=cidr
        )
    
    def _create_security_groups(self):
        """Create security groups for each zone with appropriate rules"""
        for zone in self.zone_subnets.keys():
            group_id = f"sg-{zone}-{random.randint(1000, 9999)}"
            rules = []
            
            # Base rules
            base_rules = [
                SecurityGroupRule(
                    rule_id=f"{group_id}-ingress-ssh",
                    direction="ingress",
                    protocol="tcp",
                    port_range=(22, 22),
                    source_cidr="10.0.0.0/8",
                    destination_cidr=self.zone_subnets[zone].with_prefixlen,
                    action="allow",
                    description="SSH access within VPC"
                ),
                SecurityGroupRule(
                    rule_id=f"{group_id}-ingress-internal",
                    direction="ingress",
                    protocol="all",
                    port_range=None,
                    source_cidr=self.zone_subnets[zone].with_prefixlen,
                    destination_cidr=self.zone_subnets[zone].with_prefixlen,
                    action="allow",
                    description="Allow all traffic within zone"
                ),
                SecurityGroupRule(
                    rule_id=f"{group_id}-ingress-k8s-api",
                    direction="ingress",
                    protocol="tcp",
                    port_range=(6443, 6443),
                    source_cidr="10.0.0.0/8",
                    destination_cidr=self.zone_subnets[zone].with_prefixlen,
                    action="allow",
                    description="Kubernetes API server"
                )
            ]
            rules.extend(base_rules)
            
            # Cross-zone rules
            if self.zone_distribution == "balanced":
                for other_zone, other_subnet in self.zone_subnets.items():
                    if other_zone != zone:
                        rules.append(
                            SecurityGroupRule(
                                rule_id=f"{group_id}-ingress-{other_zone}",
                                direction="ingress",
                                protocol="all",
                                port_range=None,
                                source_cidr=other_subnet.with_prefixlen,
                                destination_cidr=self.zone_subnets[zone].with_prefixlen,
                                action="allow",
                                description=f"Allow traffic from {other_zone}"
                            )
                        )
            elif self.zone_distribution == "primary-backup" and zone != "zone-a":
                primary_subnet = self.zone_subnets.get("zone-a")
                if primary_subnet:
                    rules.append(
                        SecurityGroupRule(
                            rule_id=f"{group_id}-ingress-primary",
                            direction="ingress",
                            protocol="all",
                            port_range=None,
                            source_cidr=primary_subnet.with_prefixlen,
                            destination_cidr=self.zone_subnets[zone].with_prefixlen,
                            action="allow",
                            description="Allow traffic from primary zone"
                        )
                    )
            
            # Egress rules
            rules.append(
                SecurityGroupRule(
                    rule_id=f"{group_id}-egress-all",
                    direction="egress",
                    protocol="all",
                    port_range=None,
                    source_cidr=self.zone_subnets[zone].with_prefixlen,
                    destination_cidr="0.0.0.0/0",
                    action="allow",
                    description="Allow all outbound traffic"
                )
            )
            
            self.security_groups[zone] = SecurityGroup(
                group_id=group_id,
                zone=zone,
                name=f"security-group-{zone}",
                rules=rules
            )
    
    def _determine_node_type_distribution(self) -> Dict[NodeType, int]:
        """Determine how many nodes of each type to create"""
        distribution = {}
        
        if self.num_nodes >= 3:
            distribution[NodeType.CONTROL_PLANE] = 3
        elif self.num_nodes == 2:
            distribution[NodeType.CONTROL_PLANE] = 1
        else:
            distribution[NodeType.CONTROL_PLANE] = 1
        
        remaining = self.num_nodes - distribution[NodeType.CONTROL_PLANE]
        
        if self.use_case in [UseCase.ML_PLATFORM, UseCase.DATA_ANALYTICS]:
            if remaining >= 4 and self.cluster_size.value[0] >= 10:
                gpu_count = max(1, remaining // 10)
                distribution[NodeType.GPU] = gpu_count
                remaining -= gpu_count
            
            if remaining >= 4:
                compute_count = max(2, remaining // 5)
                distribution[NodeType.COMPUTE_OPTIMIZED] = compute_count
                remaining -= compute_count
        
        if self.use_case in [UseCase.DATA_ANALYTICS, UseCase.IOT_PLATFORM]:
            if remaining >= 4:
                storage_count = max(2, remaining // 8)
                distribution[NodeType.STORAGE_OPTIMIZED] = storage_count
                remaining -= storage_count
        
        has_heavy_db = any(svc in self.services for svc in 
                          ["elasticsearch", "mongodb", "cassandra", "clickhouse"])
        if has_heavy_db and remaining >= 4:
            memory_count = max(2, remaining // 6)
            distribution[NodeType.MEMORY_OPTIMIZED] = memory_count
            remaining -= memory_count
        
        if self.use_case == UseCase.IOT_PLATFORM and remaining >= 2:
            edge_count = max(1, remaining // 10)
            distribution[NodeType.EDGE] = edge_count
            remaining -= edge_count
        
        distribution[NodeType.WORKER] = max(1, remaining)
        
        return distribution
    
    def _create_node(self, node_type: NodeType, node_index: int, zone: str) -> PhysicalNode:
        """Create a single physical node with characteristics"""
        profile = NODE_TYPE_PROFILES[node_type]
        
        cpu_min, cpu_max = profile["cpu_range"]
        mem_min, mem_max = profile["memory_range"]
        disk_min, disk_max = profile["disk_range"]
        
        characteristics = NodeCharacteristics(
            cpu_cores=random.choice([cpu_min, (cpu_min + cpu_max) // 2, cpu_max]),
            memory_gb=random.choice([mem_min, (mem_min + mem_max) // 2, mem_max]),
            disk_gb=random.randint(disk_min, disk_max),
            network_bandwidth_gbps=profile["bandwidth"],
            has_gpu=node_type == NodeType.GPU,
            gpu_count=random.randint(*profile.get("gpu_count_range", (0, 0))) if node_type == NodeType.GPU else 0
        )
        
        ip_allocation = self._allocate_ip_for_node(zone, node_index)
        
        labels = {
            "node-type": node_type.value,
            "zone": zone,
            "kubernetes.io/hostname": f"node-{node_type.value}-{node_index:03d}",
            "ipv4": ip_allocation.ipv4
        }
        
        if node_type == NodeType.GPU:
            labels["nvidia.com/gpu"] = str(characteristics.gpu_count)
        
        node = PhysicalNode(
            node_id=f"node-{node_type.value}-{node_index:03d}",
            node_type=node_type,
            zone=zone,
            ip_allocation=ip_allocation,
            characteristics=characteristics,
            labels=labels,
            security_groups=[f"sg-{zone}"]
        )
        
        return node
    
    def _generate_nodes(self) -> List[PhysicalNode]:
        """Generate all physical nodes"""
        self._initialize_network_subnets()
        distribution = self._determine_node_type_distribution()
        nodes = []
        available_zones = NodeZone.get_zones(self.num_zones)
        
        global_index = 0
        for node_type, count in distribution.items():
            for i in range(count):
                zone = self._assign_zone(global_index, available_zones)
                node = self._create_node(node_type, i, zone)
                nodes.append(node)
                global_index += 1
        
        return nodes
    
    def _assign_zone(self, node_index: int, available_zones: List[str]) -> str:
        """Assign a zone to a node based on the distribution strategy"""
        if not available_zones:
            return "zone-a"
        
        if self.zone_distribution == "balanced":
            return available_zones[node_index % len(available_zones)]
        elif self.zone_distribution == "unbalanced":
            return random.choice(available_zones)
        elif self.zone_distribution == "primary-backup":
            if len(available_zones) == 1:
                return available_zones[0]
            elif random.random() < 0.8:
                return available_zones[0]
            else:
                return random.choice(available_zones[1:])
        else:
            return available_zones[node_index % len(available_zones)]
    
    def _get_node_affinity(self, service_name: str) -> List[NodeType]:
        """Get preferred node types for a service"""
        if service_name in SERVICE_NODE_AFFINITY:
            return SERVICE_NODE_AFFINITY[service_name]
        return SERVICE_NODE_AFFINITY["default"]
    
    def _calculate_pod_resource_requirements(self, service_name: str) -> Tuple[int, int]:
        """Estimate CPU and memory requirements for a pod"""
        if service_name not in SERVICE_CATALOG:
            return (1, 2)
        
        weight = SERVICE_CATALOG[service_name].resource_weight
        
        if weight <= 2:
            return (1, 2)
        elif weight <= 4:
            return (2, 4)
        elif weight <= 6:
            return (4, 8)
        elif weight <= 8:
            return (8, 16)
        else:
            return (16, 32)
    
    def _assign_pods_to_nodes(self):
        """Assign service pods to physical nodes"""
        pods_to_assign = []
        for service_name, instance_count in self.service_instances.items():
            for instance_id in range(instance_count):
                pods_to_assign.append((service_name, instance_id))
        
        pods_to_assign.sort(key=lambda p: SERVICE_CATALOG.get(p[0], ServiceProfile(
            name=p[0], category="unknown", resource_weight=1, requires_ha=False,
            dependencies=[], conflicts_with=[], probability_by_use_case={},
            min_cluster_size=ClusterSize.TINY
        )).resource_weight, reverse=True)
        
        for service_name, instance_id in pods_to_assign:
            preferred_node_types = self._get_node_affinity(service_name)
            cpu_req, mem_req = self._calculate_pod_resource_requirements(service_name)
            
            best_node = None
            best_score = -1
            
            for node in self.nodes:
                if node.node_type not in preferred_node_types:
                    continue
                
                available_cpu = node.characteristics.cpu_cores * (1 - node.cpu_utilization)
                available_mem = node.characteristics.memory_gb * (1 - node.memory_utilization)
                
                if available_cpu < cpu_req or available_mem < mem_req:
                    continue
                
                score = available_cpu + available_mem
                
                if SERVICE_CATALOG.get(service_name, None) and SERVICE_CATALOG[service_name].requires_ha:
                    existing_zones = set()
                    for other_node in self.nodes:
                        for svc, _ in other_node.assigned_pods:
                            if svc == service_name:
                                existing_zones.add(other_node.zone)
                    
                    if node.zone not in existing_zones:
                        score += 100
                
                if score > best_score:
                    best_score = score
                    best_node = node
            
            if best_node is None:
                for node in self.nodes:
                    if node.node_type == NodeType.CONTROL_PLANE:
                        continue
                    available_cpu = node.characteristics.cpu_cores * (1 - node.cpu_utilization)
                    available_mem = node.characteristics.memory_gb * (1 - node.memory_utilization)
                    if available_cpu >= cpu_req and available_mem >= mem_req:
                        best_node = node
                        break
            
            if best_node is None:
                workers = [n for n in self.nodes if n.node_type == NodeType.WORKER]
                if workers:
                    best_node = min(workers, key=lambda n: n.cpu_utilization + n.memory_utilization)
            
            if best_node:
                best_node.assigned_pods.append((service_name, instance_id))
                best_node.cpu_utilization += cpu_req / best_node.characteristics.cpu_cores
                best_node.memory_utilization += mem_req / best_node.characteristics.memory_gb
    
    def _get_services_on_node(self, node: PhysicalNode) -> List[str]:
        """Get unique services running on a node"""
        return list(set([pod[0] for pod in node.assigned_pods]))
    
    def _get_ports_for_services(self, services: List[str]) -> List[int]:
        """Get all ports used by given services"""
        ports = []
        for service in services:
            if service in SERVICE_PORTS:
                ports.extend(SERVICE_PORTS[service])
        return list(set(ports))
    
    def _generate_node_network_topology(self, firewall_probability: float = 0.1, 
                                       firewall_cross_zone_only: bool = False):
        """Generate network connections between nodes"""
        connections = []
        
        for i, node1 in enumerate(self.nodes):
            for node2 in self.nodes[i+1:]:
                same_zone = (node1.zone == node2.zone)
                
                if same_zone:
                    base_latency = random.uniform(0.1, 0.5)
                else:
                    base_latency = random.uniform(1.0, 5.0)
                
                latency = base_latency * random.uniform(0.8, 1.2)
                bandwidth = min(node1.characteristics.network_bandwidth_gbps,
                              node2.characteristics.network_bandwidth_gbps)
                packet_loss = random.uniform(0.0001, 0.001)
                
                node1_services = self._get_services_on_node(node1)
                node2_services = self._get_services_on_node(node2)
                node1_ports = self._get_ports_for_services(node1_services)
                node2_ports = self._get_ports_for_services(node2_services)
                
                common_ports = [22, 6443, 2379, 2380, 10250, 10255, 10256]
                allowed_ports = list(set(common_ports + node1_ports + node2_ports))
                
                is_firewalled = False
                firewall_rules = []
                
                if firewall_cross_zone_only:
                    if not same_zone:
                        is_firewalled = random.random() < firewall_probability
                else:
                    is_firewalled = random.random() < firewall_probability
                
                if is_firewalled:
                    if node2_services:
                        blocked_service = random.choice(node2_services)
                        if blocked_service in SERVICE_PORTS:
                            blocked_ports = SERVICE_PORTS[blocked_service]
                            for port in blocked_ports[:2]:
                                firewall_rules.append(f"DENY tcp:{port} from {node1.ip_allocation.ipv4} to {node2.ip_allocation.ipv4}")
                    
                    if random.random() < 0.3:
                        common_blocked = random.choice([80, 443, 8080, 9090])
                        firewall_rules.append(f"DENY tcp:{common_blocked} from {node1.ip_allocation.ipv4} to {node2.ip_allocation.ipv4}")
                
                connections.append(NodeConnection(
                    from_node=node1.node_id,
                    to_node=node2.node_id,
                    from_ip=node1.ip_allocation.ipv4,
                    to_ip=node2.ip_allocation.ipv4,
                    latency_ms=latency,
                    bandwidth_gbps=bandwidth,
                    packet_loss=packet_loss,
                    is_firewalled=is_firewalled,
                    firewall_rules=firewall_rules,
                    allowed_ports=allowed_ports
                ))
                
                connections.append(NodeConnection(
                    from_node=node2.node_id,
                    to_node=node1.node_id,
                    from_ip=node2.ip_allocation.ipv4,
                    to_ip=node1.ip_allocation.ipv4,
                    latency_ms=latency,
                    bandwidth_gbps=bandwidth,
                    packet_loss=packet_loss,
                    is_firewalled=is_firewalled,
                    firewall_rules=firewall_rules,
                    allowed_ports=allowed_ports
                ))
        
        return connections
    
    def _generate_network_access_graph(self):
        """Generate network accessibility graph"""
        access_graph = []
        
        for i, node1 in enumerate(self.nodes):
            for node2 in self.nodes:
                if node1.node_id == node2.node_id:
                    continue
                
                connection = None
                for conn in self.node_connections:
                    if conn.from_node == node1.node_id and conn.to_node == node2.node_id:
                        connection = conn
                        break
                
                if connection:
                    accessible = (node1.is_healthy and node2.is_healthy and 
                                not connection.is_firewalled)
                    
                    if connection.is_firewalled:
                        allowed_ports = [port for port in connection.allowed_ports 
                                       if not any(f"DENY tcp:{port}" in rule for rule in connection.firewall_rules)]
                        blocked_ports = [port for port in connection.allowed_ports 
                                       if any(f"DENY tcp:{port}" in rule for rule in connection.firewall_rules)]
                    else:
                        allowed_ports = connection.allowed_ports
                        blocked_ports = []
                    
                    access_entry = NetworkAccessGraph(
                        source_node=node1.node_id,
                        destination_node=node2.node_id,
                        source_ip=node1.ip_allocation.ipv4,
                        destination_ip=node2.ip_allocation.ipv4,
                        accessible=accessible,
                        allowed_ports=allowed_ports,
                        blocked_ports=blocked_ports,
                        path_latency=connection.latency_ms,
                        firewall_rules_applied=connection.firewall_rules if connection.is_firewalled else []
                    )
                    
                    access_graph.append(access_entry)
        
        return access_graph
    
    def _simulate_node_failures(self, failure_probability: float = 0.05):
        """Simulate random node failures"""
        for node in self.nodes:
            if node.node_type == NodeType.CONTROL_PLANE:
                prob = failure_probability * 0.2
            else:
                prob = failure_probability
            
            if random.random() < prob:
                node.is_healthy = False
    
    def _generate_statistics(self) -> Dict:
        """Generate statistics about the physical topology"""
        total_pods = sum(len(node.assigned_pods) for node in self.nodes)
        healthy_nodes = sum(1 for node in self.nodes if node.is_healthy)
        
        by_type = {}
        by_zone = {}
        
        for node in self.nodes:
            node_type = node.node_type.value
            if node_type not in by_type:
                by_type[node_type] = {"count": 0, "pods": 0, "healthy": 0}
            by_type[node_type]["count"] += 1
            by_type[node_type]["pods"] += len(node.assigned_pods)
            if node.is_healthy:
                by_type[node_type]["healthy"] += 1
            
            zone = node.zone
            if zone not in by_zone:
                by_zone[zone] = {"count": 0, "pods": 0, "healthy": 0}
            by_zone[zone]["count"] += 1
            by_zone[zone]["pods"] += len(node.assigned_pods)
            if node.is_healthy:
                by_zone[zone]["healthy"] += 1
        
        total_cpu = sum(n.characteristics.cpu_cores for n in self.nodes)
        total_memory = sum(n.characteristics.memory_gb for n in self.nodes)
        
        avg_cpu_util = sum(n.cpu_utilization for n in self.nodes) / len(self.nodes)
        avg_mem_util = sum(n.memory_utilization for n in self.nodes) / len(self.nodes)
        
        total_connections = len(self.node_connections)
        firewalled_connections = sum(1 for c in self.node_connections if c.is_firewalled)
        avg_latency = sum(c.latency_ms for c in self.node_connections) / len(self.node_connections) if self.node_connections else 0
        
        return {
            "total_nodes": len(self.nodes),
            "healthy_nodes": healthy_nodes,
            "total_pods": total_pods,
            "avg_pods_per_node": round(total_pods / len(self.nodes), 2),
            "nodes_by_type": by_type,
            "nodes_by_zone": by_zone,
            "total_resources": {
                "cpu_cores": total_cpu,
                "memory_gb": total_memory
            },
            "resource_utilization": {
                "avg_cpu_utilization": round(avg_cpu_util * 100, 2),
                "avg_memory_utilization": round(avg_mem_util * 100, 2)
            },
            "network_statistics": {
                "total_connections": total_connections,
                "firewalled_connections": firewalled_connections,
                "avg_latency_ms": round(avg_latency, 2)
            }
        }
    
    def _generate_service_mapping(self) -> Dict[str, List[str]]:
        """Generate mapping of services to nodes"""
        mapping = {}
        for node in self.nodes:
            for service_name, instance_id in node.assigned_pods:
                pod_id = f"{service_name}-{instance_id}"
                if service_name not in mapping:
                    mapping[service_name] = []
                mapping[service_name].append({
                    "pod_id": pod_id,
                    "node_id": node.node_id,
                    "zone": node.zone,
                    "node_ip": node.ip_allocation.ipv4,
                    "services_ports": SERVICE_PORTS.get(service_name, [])
                })
        return mapping

    def generate(self, 
                firewall_probability: float = 0.1,
                firewall_cross_zone_only: bool = False,
                node_failure_probability: float = 0.05) -> Dict:
        """Generate complete physical node topology"""
        
        self.nodes = self._generate_nodes()
        self._create_security_groups()
        self._assign_pods_to_nodes()
        
        self.node_connections = self._generate_node_network_topology(
            firewall_probability, 
            firewall_cross_zone_only
        )
        
        self.network_access_graph = self._generate_network_access_graph()
        self._simulate_node_failures(node_failure_probability)
        
        topology = {
            "metadata": {
                "generator": "PhysicalNodeGenerator",
                "version": "2.0",
                "num_physical_nodes": self.num_nodes,
                "num_zones": self.num_zones,
                "zone_distribution": self.zone_distribution,
                "cluster_size": self.cluster_size.name,
                "use_case": self.use_case.value,
                "statistics": self._generate_statistics()
            },
            "network_configuration": {
                "zone_subnets": {zone: str(subnet) for zone, subnet in self.zone_subnets.items()},
                "ip_allocations": {
                    zone: list(ips) for zone, ips in self.zone_ip_allocations.items()
                }
            },
            "security_groups": {sg_id: sg.to_dict() for sg_id, sg in self.security_groups.items()},
            "nodes": [node.to_dict() for node in self.nodes],
            "node_connections": [conn.to_dict() for conn in self.node_connections],
            "network_access_graph": [entry.to_dict() for entry in self.network_access_graph],
            "node_to_service_mapping": self._generate_service_mapping()
        }
        
        return topology