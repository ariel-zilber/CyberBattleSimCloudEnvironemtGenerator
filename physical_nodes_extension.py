"""
Physical Nodes Extension for Kubernetes Cluster Generator
==========================================================
This module extends the k8s_cluster_generator.py with:
- Physical node generation with different node types
- Service-to-node placement engine
- Node-level network topology graphs
- Resource utilization tracking

Usage:
    from k8s_cluster_generator import K8sClusterGenerator, UseCase
    from physical_nodes_extension import extend_with_physical_nodes
    
    # Generate base cluster
    generator = K8sClusterGenerator(num_nodes=10, use_case=UseCase.MICROSERVICES, seed=42)
    cluster = generator.generate()
    
    # Extend with physical nodes
    extended_cluster = extend_with_physical_nodes(cluster, seed=42)

Author: Auto-generated
Date: 2025-11-08
"""

import random
import json
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum


# ======================================================================
# Node Types and Profiles
# ======================================================================

class NodeType(Enum):
    """Types of Kubernetes nodes with different characteristics"""
    CONTROL_PLANE = "control_plane"
    WORKER_GENERAL = "worker_general"
    WORKER_COMPUTE = "worker_compute"
    WORKER_MEMORY = "worker_memory"
    WORKER_STORAGE = "worker_storage"
    WORKER_GPU = "worker_gpu"
    EDGE = "edge"


@dataclass
class NodeProfile:
    """Resource profile for a physical node"""
    node_type: NodeType
    cpu_cores: int
    memory_gb: int
    storage_gb: int
    gpu_count: int = 0
    network_bandwidth_gbps: int = 10
    cost_per_hour: float = 0.0


# Node specifications
NODE_SPECS = {
    NodeType.CONTROL_PLANE: NodeProfile(
        node_type=NodeType.CONTROL_PLANE,
        cpu_cores=4, memory_gb=16, storage_gb=100,
        network_bandwidth_gbps=10, cost_per_hour=0.5
    ),
    NodeType.WORKER_GENERAL: NodeProfile(
        node_type=NodeType.WORKER_GENERAL,
        cpu_cores=8, memory_gb=32, storage_gb=200,
        network_bandwidth_gbps=10, cost_per_hour=1.0
    ),
    NodeType.WORKER_COMPUTE: NodeProfile(
        node_type=NodeType.WORKER_COMPUTE,
        cpu_cores=32, memory_gb=64, storage_gb=200,
        network_bandwidth_gbps=25, cost_per_hour=2.5
    ),
    NodeType.WORKER_MEMORY: NodeProfile(
        node_type=NodeType.WORKER_MEMORY,
        cpu_cores=16, memory_gb=256, storage_gb=500,
        network_bandwidth_gbps=25, cost_per_hour=3.0
    ),
    NodeType.WORKER_STORAGE: NodeProfile(
        node_type=NodeType.WORKER_STORAGE,
        cpu_cores=8, memory_gb=64, storage_gb=2000,
        network_bandwidth_gbps=10, cost_per_hour=1.5
    ),
    NodeType.WORKER_GPU: NodeProfile(
        node_type=NodeType.WORKER_GPU,
        cpu_cores=16, memory_gb=128, storage_gb=500, gpu_count=4,
        network_bandwidth_gbps=100, cost_per_hour=8.0
    ),
    NodeType.EDGE: NodeProfile(
        node_type=NodeType.EDGE,
        cpu_cores=4, memory_gb=8, storage_gb=50,
        network_bandwidth_gbps=1, cost_per_hour=0.3
    ),
}


# Resource requirements for each service category
SERVICE_RESOURCE_PROFILES = {
    "control_plane_core": {"cpu": 1.0, "memory": 2.0, "storage": 20.0, "preferred_types": [NodeType.CONTROL_PLANE, NodeType.WORKER_GENERAL]},
    "control_plane_security": {"cpu": 0.5, "memory": 1.0, "storage": 10.0, "preferred_types": [NodeType.WORKER_GENERAL]},
    "control_plane_networking": {"cpu": 1.0, "memory": 2.0, "storage": 10.0, "preferred_types": [NodeType.WORKER_GENERAL, NodeType.WORKER_COMPUTE]},
    "observability_metrics": {"cpu": 2.0, "memory": 8.0, "storage": 100.0, "preferred_types": [NodeType.WORKER_MEMORY, NodeType.WORKER_STORAGE]},
    "observability_logging": {"cpu": 2.0, "memory": 8.0, "storage": 200.0, "preferred_types": [NodeType.WORKER_MEMORY, NodeType.WORKER_STORAGE]},
    "observability_tracing": {"cpu": 1.5, "memory": 4.0, "storage": 100.0, "preferred_types": [NodeType.WORKER_MEMORY]},
    "ci_cd": {"cpu": 1.5, "memory": 3.0, "storage": 50.0, "preferred_types": [NodeType.WORKER_GENERAL, NodeType.WORKER_COMPUTE]},
    "data_sql": {"cpu": 2.0, "memory": 8.0, "storage": 200.0, "preferred_types": [NodeType.WORKER_MEMORY, NodeType.WORKER_STORAGE]},
    "data_nosql": {"cpu": 2.0, "memory": 8.0, "storage": 200.0, "preferred_types": [NodeType.WORKER_MEMORY, NodeType.WORKER_STORAGE]},
    "data_analytics": {"cpu": 8.0, "memory": 32.0, "storage": 1000.0, "preferred_types": [NodeType.WORKER_COMPUTE, NodeType.WORKER_MEMORY, NodeType.WORKER_STORAGE]},
    "data_caching": {"cpu": 1.0, "memory": 4.0, "storage": 20.0, "preferred_types": [NodeType.WORKER_MEMORY]},
    "data_messaging": {"cpu": 2.0, "memory": 8.0, "storage": 500.0, "preferred_types": [NodeType.WORKER_MEMORY, NodeType.WORKER_STORAGE]},
    "data_storage": {"cpu": 2.0, "memory": 8.0, "storage": 1000.0, "preferred_types": [NodeType.WORKER_STORAGE]},
    "data_processing": {"cpu": 8.0, "memory": 32.0, "storage": 200.0, "preferred_types": [NodeType.WORKER_COMPUTE, NodeType.WORKER_MEMORY]},
    "data_orchestration": {"cpu": 2.0, "memory": 4.0, "storage": 50.0, "preferred_types": [NodeType.WORKER_GENERAL, NodeType.WORKER_COMPUTE]},
    "ml_platform": {"cpu": 4.0, "memory": 16.0, "storage": 100.0, "preferred_types": [NodeType.WORKER_GPU, NodeType.WORKER_COMPUTE, NodeType.WORKER_MEMORY]},
    "web_servers": {"cpu": 0.5, "memory": 1.0, "storage": 10.0, "preferred_types": [NodeType.WORKER_GENERAL]},
    "web_cms": {"cpu": 1.0, "memory": 2.0, "storage": 20.0, "preferred_types": [NodeType.WORKER_GENERAL]},
}


@dataclass
class PhysicalNode:
    """Represents a physical Kubernetes node"""
    node_id: str
    node_type: NodeType
    zone: str
    rack: str
    profile: NodeProfile
    labels: Dict[str, str] = field(default_factory=dict)
    taints: List[str] = field(default_factory=list)
    allocated_cpu: float = 0.0
    allocated_memory: float = 0.0
    allocated_storage: float = 0.0
    running_pods: List[str] = field(default_factory=list)
    
    def available_cpu(self) -> float:
        return self.profile.cpu_cores - self.allocated_cpu
    
    def available_memory(self) -> float:
        return self.profile.memory_gb - self.allocated_memory
    
    def available_storage(self) -> float:
        return self.profile.storage_gb - self.allocated_storage
    
    def cpu_utilization(self) -> float:
        return (self.allocated_cpu / self.profile.cpu_cores) * 100 if self.profile.cpu_cores > 0 else 0
    
    def memory_utilization(self) -> float:
        return (self.allocated_memory / self.profile.memory_gb) * 100 if self.profile.memory_gb > 0 else 0


@dataclass
class PodPlacement:
    """Represents a pod placement on a node"""
    pod_id: str
    service_name: str
    node_id: str
    cpu_request: float
    memory_request: float
    storage_request: float


# ======================================================================
# Physical Node Generator
# ======================================================================

class PhysicalNodeGenerator:
    """Generate physical nodes based on cluster requirements"""
    
    def __init__(self, num_nodes: int, use_case: str, seed: int = None):
        self.num_nodes = num_nodes
        self.use_case = use_case
        self.nodes: List[PhysicalNode] = []
        
        if seed is not None:
            random.seed(seed)
    
    def generate_nodes(self) -> List[PhysicalNode]:
        """Generate physical nodes with appropriate distribution"""
        distribution = self._calculate_node_distribution()
        
        # Generate zones for multi-AZ setup
        num_zones = min(3, max(1, self.num_nodes // 10))
        zones = [f"zone-{chr(97+i)}" for i in range(num_zones)]
        
        node_id_counter = 0
        
        # Generate control plane nodes
        num_control_plane = distribution.get(NodeType.CONTROL_PLANE, 1)
        for i in range(num_control_plane):
            zone = zones[i % len(zones)]
            rack = f"rack-{i // 10 + 1}"
            node = PhysicalNode(
                node_id=f"control-plane-{node_id_counter}",
                node_type=NodeType.CONTROL_PLANE,
                zone=zone,
                rack=rack,
                profile=NODE_SPECS[NodeType.CONTROL_PLANE],
                labels={"node-role": "control-plane", "zone": zone, "rack": rack},
                taints=["NoSchedule"]
            )
            self.nodes.append(node)
            node_id_counter += 1
        
        # Generate worker nodes
        for node_type, count in distribution.items():
            if node_type == NodeType.CONTROL_PLANE:
                continue
                
            for i in range(count):
                zone = zones[node_id_counter % len(zones)]
                rack = f"rack-{node_id_counter // 10 + 1}"
                
                labels = {"node-type": node_type.value, "zone": zone, "rack": rack}
                
                if node_type == NodeType.WORKER_GPU:
                    labels["gpu"] = "true"
                elif node_type == NodeType.WORKER_MEMORY:
                    labels["memory-optimized"] = "true"
                elif node_type == NodeType.WORKER_COMPUTE:
                    labels["compute-optimized"] = "true"
                elif node_type == NodeType.WORKER_STORAGE:
                    labels["storage-optimized"] = "true"
                
                node = PhysicalNode(
                    node_id=f"{node_type.value}-{node_id_counter}",
                    node_type=node_type,
                    zone=zone,
                    rack=rack,
                    profile=NODE_SPECS[node_type],
                    labels=labels,
                    taints=[]
                )
                self.nodes.append(node)
                node_id_counter += 1
        
        return self.nodes
    
    def _calculate_node_distribution(self) -> Dict[NodeType, int]:
        """Calculate how many nodes of each type to create"""
        distribution = {}
        
        # Determine cluster size category
        if self.num_nodes <= 3:
            cluster_size = "TINY"
        elif self.num_nodes <= 10:
            cluster_size = "SMALL"
        elif self.num_nodes <= 50:
            cluster_size = "MEDIUM"
        elif self.num_nodes <= 200:
            cluster_size = "LARGE"
        else:
            cluster_size = "XLARGE"
        
        # Control plane sizing
        if cluster_size == "TINY":
            distribution[NodeType.CONTROL_PLANE] = 1
        elif cluster_size == "SMALL":
            distribution[NodeType.CONTROL_PLANE] = 3
        else:
            distribution[NodeType.CONTROL_PLANE] = 5
        
        remaining_nodes = self.num_nodes - distribution[NodeType.CONTROL_PLANE]
        
        # Use case specific distributions
        if self.use_case in ["ml_platform", "data_analytics"]:
            distribution[NodeType.WORKER_GPU] = max(0, int(remaining_nodes * 0.2))
            distribution[NodeType.WORKER_MEMORY] = max(0, int(remaining_nodes * 0.3))
            distribution[NodeType.WORKER_COMPUTE] = max(0, int(remaining_nodes * 0.2))
            distribution[NodeType.WORKER_STORAGE] = max(0, int(remaining_nodes * 0.15))
            distribution[NodeType.WORKER_GENERAL] = remaining_nodes - sum([
                distribution.get(NodeType.WORKER_GPU, 0),
                distribution.get(NodeType.WORKER_MEMORY, 0),
                distribution.get(NodeType.WORKER_COMPUTE, 0),
                distribution.get(NodeType.WORKER_STORAGE, 0)
            ])
        elif self.use_case == "iot_platform":
            distribution[NodeType.EDGE] = max(0, int(remaining_nodes * 0.3))
            distribution[NodeType.WORKER_MEMORY] = max(0, int(remaining_nodes * 0.2))
            distribution[NodeType.WORKER_GENERAL] = remaining_nodes - sum([
                distribution.get(NodeType.EDGE, 0),
                distribution.get(NodeType.WORKER_MEMORY, 0)
            ])
        elif self.use_case in ["ecommerce", "saas_platform"]:
            distribution[NodeType.WORKER_COMPUTE] = max(0, int(remaining_nodes * 0.3))
            distribution[NodeType.WORKER_MEMORY] = max(0, int(remaining_nodes * 0.25))
            distribution[NodeType.WORKER_STORAGE] = max(0, int(remaining_nodes * 0.1))
            distribution[NodeType.WORKER_GENERAL] = remaining_nodes - sum([
                distribution.get(NodeType.WORKER_COMPUTE, 0),
                distribution.get(NodeType.WORKER_MEMORY, 0),
                distribution.get(NodeType.WORKER_STORAGE, 0)
            ])
        else:
            distribution[NodeType.WORKER_MEMORY] = max(0, int(remaining_nodes * 0.2))
            distribution[NodeType.WORKER_COMPUTE] = max(0, int(remaining_nodes * 0.15))
            distribution[NodeType.WORKER_GENERAL] = remaining_nodes - sum([
                distribution.get(NodeType.WORKER_MEMORY, 0),
                distribution.get(NodeType.WORKER_COMPUTE, 0)
            ])
        
        return distribution


# ======================================================================
# Service Placement Engine
# ======================================================================

class ServicePlacementEngine:
    """Place service pods onto physical nodes"""
    
    def __init__(self, nodes: List[PhysicalNode], cluster_config: Dict, seed: int = None):
        self.nodes = nodes
        self.cluster_config = cluster_config
        self.placements: List[PodPlacement] = []
        
        if seed is not None:
            random.seed(seed)
    
    def place_services(self) -> List[PodPlacement]:
        """Place all service pods onto nodes"""
        services = self.cluster_config.get("services", [])
        service_instances = self.cluster_config.get("service_instances", {})
        services_by_category = self.cluster_config.get("services_by_category", {})
        
        # Create a reverse mapping of service to category
        service_to_category = {}
        for category, service_list in services_by_category.items():
            for service in service_list:
                service_to_category[service] = category
        
        # Sort services by resource requirements (heaviest first)
        sorted_services = sorted(services, key=lambda s: len(s), reverse=True)
        
        for service_name in sorted_services:
            category = service_to_category.get(service_name, "web_servers")
            resource_profile = SERVICE_RESOURCE_PROFILES.get(category, SERVICE_RESOURCE_PROFILES["web_servers"])
            num_instances = service_instances.get(service_name, 1)
            
            # Place each instance
            for instance_idx in range(num_instances):
                pod_id = f"{service_name}-{instance_idx}"
                
                best_node = self._find_best_node(resource_profile, service_name, instance_idx, num_instances)
                
                if best_node:
                    placement = PodPlacement(
                        pod_id=pod_id,
                        service_name=service_name,
                        node_id=best_node.node_id,
                        cpu_request=resource_profile["cpu"],
                        memory_request=resource_profile["memory"],
                        storage_request=resource_profile["storage"]
                    )
                    
                    best_node.allocated_cpu += resource_profile["cpu"]
                    best_node.allocated_memory += resource_profile["memory"]
                    best_node.allocated_storage += resource_profile["storage"]
                    best_node.running_pods.append(pod_id)
                    
                    self.placements.append(placement)
        
        return self.placements
    
    def _find_best_node(self, resource_profile: Dict, service_name: str, 
                       instance_idx: int, total_instances: int) -> Optional[PhysicalNode]:
        """Find the best node to place a pod"""
        candidate_nodes = []
        
        for node in self.nodes:
            # Skip control plane unless needed
            if node.node_type == NodeType.CONTROL_PLANE and "control_plane" not in service_name:
                continue
            
            if "NoSchedule" in node.taints and node.node_type != NodeType.CONTROL_PLANE:
                continue
            
            # Check resources
            if (node.available_cpu() < resource_profile["cpu"] or
                node.available_memory() < resource_profile["memory"] or
                node.available_storage() < resource_profile["storage"]):
                continue
            
            # Score based on node type preference
            score = 1.0
            if node.node_type in resource_profile.get("preferred_types", []):
                score = 2.0
            
            candidate_nodes.append((node, score))
        
        if not candidate_nodes:
            # Fallback: any node with resources
            for node in self.nodes:
                if (node.available_cpu() >= resource_profile["cpu"] and
                    node.available_memory() >= resource_profile["memory"]):
                    candidate_nodes.append((node, 0.1))
        
        if not candidate_nodes:
            return None
        
        # For HA, spread across zones
        if total_instances > 1:
            used_zones = set()
            for p in self.placements:
                if p.service_name == service_name:
                    for n in self.nodes:
                        if n.node_id == p.node_id:
                            used_zones.add(n.zone)
            
            candidates_by_zone = [(node, score * 2.0) for node, score in candidate_nodes
                                 if node.zone not in used_zones]
            if candidates_by_zone:
                candidate_nodes = candidates_by_zone
        
        # Score by utilization
        scored_nodes = []
        for node, base_score in candidate_nodes:
            util_score = 1.0 - (node.cpu_utilization() / 100.0)
            total_score = base_score * util_score
            scored_nodes.append((node, total_score))
        
        scored_nodes.sort(key=lambda x: x[1], reverse=True)
        return scored_nodes[0][0] if scored_nodes else None


# ======================================================================
# Node Graph Generator
# ======================================================================

class NodeGraphGenerator:
    """Generate network topology graphs for physical nodes"""
    
    def __init__(self, nodes: List[PhysicalNode], placements: List[PodPlacement], 
                 cluster_config: Dict, seed: int = None):
        self.nodes = nodes
        self.placements = placements
        self.cluster_config = cluster_config
        self.node_connections: Dict[str, Set[str]] = {}
        
        if seed is not None:
            random.seed(seed)
    
    def generate_topology(self) -> Dict:
        """Generate node-to-node connectivity"""
        # Initialize connections
        for node in self.nodes:
            self.node_connections[node.node_id] = set()
        
        # 1. Control plane connects to all workers
        cp_nodes = [n for n in self.nodes if n.node_type == NodeType.CONTROL_PLANE]
        worker_nodes = [n for n in self.nodes if n.node_type != NodeType.CONTROL_PLANE]
        
        for cp in cp_nodes:
            for worker in worker_nodes:
                self.node_connections[cp.node_id].add(worker.node_id)
                self.node_connections[worker.node_id].add(cp.node_id)
        
        # 2. Full mesh within zones
        nodes_by_zone: Dict[str, List[PhysicalNode]] = {}
        for node in self.nodes:
            if node.zone not in nodes_by_zone:
                nodes_by_zone[node.zone] = []
            nodes_by_zone[node.zone].append(node)
        
        for zone_nodes in nodes_by_zone.values():
            for i, n1 in enumerate(zone_nodes):
                for n2 in zone_nodes[i+1:]:
                    if n1.node_type != NodeType.CONTROL_PLANE and n2.node_type != NodeType.CONTROL_PLANE:
                        self.node_connections[n1.node_id].add(n2.node_id)
                        self.node_connections[n2.node_id].add(n1.node_id)
        
        # 3. Connect nodes running related services (based on dependencies)
        service_to_nodes: Dict[str, Set[str]] = {}
        for p in self.placements:
            if p.service_name not in service_to_nodes:
                service_to_nodes[p.service_name] = set()
            service_to_nodes[p.service_name].add(p.node_id)
        
        # Simple heuristic: connect nodes of different services that likely communicate
        service_list = list(service_to_nodes.keys())
        for i, svc1 in enumerate(service_list):
            for svc2 in service_list[i+1:]:
                # Connect with some probability (simulating service mesh)
                if random.random() < 0.3:
                    for n1 in service_to_nodes[svc1]:
                        for n2 in service_to_nodes[svc2]:
                            self.node_connections[n1].add(n2)
                            self.node_connections[n2].add(n1)
        
        # 4. Add random cross-zone connections
        num_cross_zone = min(len(worker_nodes) * 2, len(worker_nodes) * len(worker_nodes) // 10)
        for _ in range(num_cross_zone):
            if len(worker_nodes) >= 2:
                n1 = random.choice(worker_nodes)
                n2 = random.choice(worker_nodes)
                if n1.node_id != n2.node_id and n1.zone != n2.zone:
                    self.node_connections[n1.node_id].add(n2.node_id)
                    self.node_connections[n2.node_id].add(n1.node_id)
        
        return self._build_topology_dict()
    
    def _build_topology_dict(self) -> Dict:
        """Build dictionary representation of topology"""
        edges = []
        for source_id, targets in self.node_connections.items():
            for target_id in targets:
                if source_id < target_id:  # Avoid duplicates
                    source_node = next((n for n in self.nodes if n.node_id == source_id), None)
                    target_node = next((n for n in self.nodes if n.node_id == target_id), None)
                    
                    if source_node and target_node:
                        edge_type = "intra_zone" if source_node.zone == target_node.zone else "inter_zone"
                        latency_ms = random.uniform(0.1, 1.0) if edge_type == "intra_zone" else random.uniform(2.0, 10.0)
                        
                        edges.append({
                            "source": source_id,
                            "target": target_id,
                            "edge_type": edge_type,
                            "latency_ms": round(latency_ms, 2),
                            "bandwidth_gbps": min(source_node.profile.network_bandwidth_gbps,
                                                target_node.profile.network_bandwidth_gbps)
                        })
        
        return {
            "nodes": [
                {
                    "node_id": node.node_id,
                    "node_type": node.node_type.value,
                    "zone": node.zone,
                    "rack": node.rack,
                    "pod_count": len(node.running_pods)
                }
                for node in self.nodes
            ],
            "edges": edges,
            "topology_stats": {
                "total_nodes": len(self.nodes),
                "total_edges": len(edges),
                "avg_degree": round(2 * len(edges) / len(self.nodes), 2) if len(self.nodes) > 0 else 0,
                "zones": len(set(n.zone for n in self.nodes)),
                "control_plane_nodes": len([n for n in self.nodes if n.node_type == NodeType.CONTROL_PLANE]),
                "worker_nodes": len([n for n in self.nodes if n.node_type != NodeType.CONTROL_PLANE])
            }
        }


# ======================================================================
# Main Extension Function
# ======================================================================

def extend_with_physical_nodes(cluster_config: Dict, seed: int = None) -> Dict:
    """
    Extend a cluster configuration with physical nodes and placement.
    
    Args:
        cluster_config: Output from K8sClusterGenerator.generate()
        seed: Random seed for reproducibility
        
    Returns:
        Extended cluster configuration with physical nodes, placements, and node topology
    """
    if seed is not None:
        random.seed(seed)
    
    # Extract metadata
    metadata = cluster_config["cluster_metadata"]
    num_nodes = metadata["num_nodes"]
    use_case = metadata["use_case"]
    
    # Generate physical nodes
    node_gen = PhysicalNodeGenerator(num_nodes, use_case, seed)
    physical_nodes = node_gen.generate_nodes()
    
    # Place services on nodes
    placement_engine = ServicePlacementEngine(physical_nodes, cluster_config, seed)
    placements = placement_engine.place_services()
    
    # Generate node topology
    graph_gen = NodeGraphGenerator(physical_nodes, placements, cluster_config, seed)
    node_topology = graph_gen.generate_topology()
    
    # Calculate statistics
    total_cpu = sum(n.profile.cpu_cores for n in physical_nodes)
    total_memory = sum(n.profile.memory_gb for n in physical_nodes)
    total_storage = sum(n.profile.storage_gb for n in physical_nodes)
    allocated_cpu = sum(n.allocated_cpu for n in physical_nodes)
    allocated_memory = sum(n.allocated_memory for n in physical_nodes)
    allocated_storage = sum(n.allocated_storage for n in physical_nodes)
    
    # Add extensions to cluster config
    extended_config = cluster_config.copy()
    extended_config["physical_nodes"] = [
        {
            "node_id": n.node_id,
            "node_type": n.node_type.value,
            "zone": n.zone,
            "rack": n.rack,
            "cpu_cores": n.profile.cpu_cores,
            "memory_gb": n.profile.memory_gb,
            "storage_gb": n.profile.storage_gb,
            "gpu_count": n.profile.gpu_count,
            "network_bandwidth_gbps": n.profile.network_bandwidth_gbps,
            "allocated_cpu": round(n.allocated_cpu, 2),
            "allocated_memory": round(n.allocated_memory, 2),
            "allocated_storage": round(n.allocated_storage, 2),
            "cpu_utilization_pct": round(n.cpu_utilization(), 2),
            "memory_utilization_pct": round(n.memory_utilization(), 2),
            "running_pods": n.running_pods,
            "pod_count": len(n.running_pods),
            "labels": n.labels,
            "taints": n.taints
        }
        for n in physical_nodes
    ]
    
    extended_config["pod_placements"] = [
        {
            "pod_id": p.pod_id,
            "service_name": p.service_name,
            "node_id": p.node_id,
            "cpu_request": p.cpu_request,
            "memory_request": p.memory_request,
            "storage_request": p.storage_request
        }
        for p in placements
    ]
    
    extended_config["node_topology"] = node_topology
    
    extended_config["node_utilization"] = {
        "total_capacity": {
            "cpu_cores": total_cpu,
            "memory_gb": total_memory,
            "storage_gb": total_storage
        },
        "total_allocated": {
            "cpu_cores": round(allocated_cpu, 2),
            "memory_gb": round(allocated_memory, 2),
            "storage_gb": round(allocated_storage, 2)
        },
        "utilization_pct": {
            "cpu": round((allocated_cpu / total_cpu * 100) if total_cpu > 0 else 0, 2),
            "memory": round((allocated_memory / total_memory * 100) if total_memory > 0 else 0, 2),
            "storage": round((allocated_storage / total_storage * 100) if total_storage > 0 else 0, 2)
        },
        "nodes_by_type": {
            node_type.value: len([n for n in physical_nodes if n.node_type == node_type])
            for node_type in NodeType
        }
    }
    
    # Update metadata
    extended_config["cluster_metadata"]["placed_pods"] = len(placements)
    extended_config["cluster_metadata"]["unplaced_pods"] = metadata["total_pods"] - len(placements)
    
    return extended_config


# ======================================================================
# Utility Functions
# ======================================================================

def export_node_graph_to_graphviz(extended_config: Dict, output_file: str = "node_graph.dot") -> None:
    """Export node topology to Graphviz DOT format"""
    node_colors = {
        "control_plane": "lightblue",
        "worker_general": "lightgreen",
        "worker_compute": "orange",
        "worker_memory": "yellow",
        "worker_storage": "pink",
        "worker_gpu": "purple",
        "edge": "gray"
    }
    
    with open(output_file, 'w') as f:
        f.write("graph NodeTopology {\n")
        f.write("  layout=fdp;\n")
        f.write("  node [shape=box, style=filled];\n\n")
        
        # Write nodes
        for node in extended_config['physical_nodes']:
            color = node_colors.get(node['node_type'], "white")
            label = f"{node['node_id']}\\n{node['pod_count']} pods\\n{node['cpu_utilization_pct']:.0f}% CPU"
            f.write(f'  "{node["node_id"]}" [label="{label}", fillcolor="{color}"];\n')
        
        f.write("\n")
        
        # Write edges
        for edge in extended_config['node_topology']['edges']:
            style = "solid" if edge['edge_type'] == "intra_zone" else "dashed"
            label = f"{edge['latency_ms']}ms"
            f.write(f'  "{edge["source"]}" -- "{edge["target"]}" '
                   f'[label="{label}", style="{style}"];\n')
        
        f.write("}\n")
    
    print(f"✅ Node graph exported to {output_file}")


def print_cluster_summary(extended_config: Dict) -> None:
    """Print a summary of the extended cluster"""
    print("\n" + "="*80)
    print("EXTENDED CLUSTER SUMMARY")
    print("="*80)
    
    metadata = extended_config["cluster_metadata"]
    print(f"\n📊 Cluster: {metadata['num_nodes']} nodes, {metadata['use_case']}")
    print(f"   Services: {metadata['total_services']}, Pods: {metadata['placed_pods']}/{metadata['total_pods']}")
    
    util = extended_config["node_utilization"]
    print(f"\n💻 Resources:")
    print(f"   CPU: {util['total_allocated']['cpu_cores']}/{util['total_capacity']['cpu_cores']} cores ({util['utilization_pct']['cpu']}%)")
    print(f"   Memory: {util['total_allocated']['memory_gb']}/{util['total_capacity']['memory_gb']} GB ({util['utilization_pct']['memory']}%)")
    print(f"   Storage: {util['total_allocated']['storage_gb']}/{util['total_capacity']['storage_gb']} GB ({util['utilization_pct']['storage']}%)")
    
    print(f"\n🏗️  Node Types:")
    for node_type, count in util['nodes_by_type'].items():
        if count > 0:
            print(f"   {node_type:25s} {count:3d} nodes")
    
    topo = extended_config['node_topology']['topology_stats']
    print(f"\n🌐 Topology: {topo['total_edges']} connections, {topo['zones']} zones, avg degree {topo['avg_degree']}")


if __name__ == "__main__":
    print("Physical Nodes Extension Module")
    print("="*80)
    print("\nThis module extends k8s_cluster_generator.py")
    print("\nUsage:")
    print("  from k8s_cluster_generator import K8sClusterGenerator, UseCase")
    print("  from physical_nodes_extension import extend_with_physical_nodes")
    print("\n  generator = K8sClusterGenerator(num_nodes=10, use_case=UseCase.MICROSERVICES, seed=42)")
    print("  cluster = generator.generate()")
    print("  extended_cluster = extend_with_physical_nodes(cluster, seed=42)")
