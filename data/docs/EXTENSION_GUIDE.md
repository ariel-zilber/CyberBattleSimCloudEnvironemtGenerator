# Kubernetes Cluster Generator - Extension Guide

## Extension Overview

This guide shows how to extend your existing `k8s_cluster_generator.py` with:
1. **Physical Node Generation** - Create realistic K8s nodes with different types
2. **Service-to-Node Placement** - Intelligently place pods on nodes
3. **Node-Level Network Graphs** - Generate network topology between nodes

## Step 1: Add Node Type Definitions

Add these enums and dataclasses after the existing `UseCase` enum:

```python
class NodeType(Enum):
    """Types of Kubernetes nodes"""
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

NODE_SPECS = {
    NodeType.CONTROL_PLANE: NodeProfile(NodeType.CONTROL_PLANE, 4, 16, 100, 0, 10, 0.5),
    NodeType.WORKER_GENERAL: NodeProfile(NodeType.WORKER_GENERAL, 8, 32, 200, 0, 10, 1.0),
    NodeType.WORKER_COMPUTE: NodeProfile(NodeType.WORKER_COMPUTE, 32, 64, 200, 0, 25, 2.5),
    NodeType.WORKER_MEMORY: NodeProfile(NodeType.WORKER_MEMORY, 16, 256, 500, 0, 25, 3.0),
    NodeType.WORKER_STORAGE: NodeProfile(NodeType.WORKER_STORAGE, 8, 64, 2000, 0, 10, 1.5),
    NodeType.WORKER_GPU: NodeProfile(NodeType.WORKER_GPU, 16, 128, 500, 4, 100, 8.0),
    NodeType.EDGE: NodeProfile(NodeType.EDGE, 4, 8, 50, 0, 1, 0.3),
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
    
    def cpu_utilization(self) -> float:
        return (self.allocated_cpu / self.profile.cpu_cores) * 100 if self.profile.cpu_cores > 0 else 0

@dataclass
class PodPlacement:
    """Represents a pod placement on a node"""
    pod_id: str
    service_name: str
    node_id: str
    cpu_request: float
    memory_request: float
    storage_request: float
```

## Step 2: Extend ServiceProfile

Add these fields to your existing `ServiceProfile` dataclass:

```python
@dataclass
class ServiceProfile:
    # ... existing fields ...
    
    # NEW FIELDS:
    cpu_per_pod: float = 0.5
    memory_per_pod: float = 1.0
    storage_per_pod: float = 10.0
    preferred_node_types: List[NodeType] = field(default_factory=list)
    node_affinity_labels: Dict[str, str] = field(default_factory=dict)
    requires_gpu: bool = False
```

Then update your SERVICE_CATALOG entries. Example for PostgreSQL:

```python
"postgresql": ServiceProfile(
    # ... existing fields ...
    cpu_per_pod=2.0,
    memory_per_pod=8.0,
    storage_per_pod=200.0,
    preferred_node_types=[NodeType.WORKER_MEMORY, NodeType.WORKER_STORAGE]
),
```

## Step 3: Add PhysicalNodeGenerator

```python
class PhysicalNodeGenerator:
    """Generate physical nodes based on cluster requirements"""
    
    def __init__(self, num_nodes: int, cluster_size: ClusterSize, use_case: UseCase, seed: int = None):
        self.num_nodes = num_nodes
        self.cluster_size = cluster_size
        self.use_case = use_case
        self.nodes: List[PhysicalNode] = []
        
        if seed is not None:
            random.seed(seed)
    
    def generate_nodes(self) -> List[PhysicalNode]:
        """Generate physical nodes with appropriate distribution"""
        distribution = self._calculate_node_distribution()
        
        # Generate zones and racks
        num_zones = min(3, max(1, self.num_nodes // 10))
        zones = [f"zone-{chr(97+i)}" for i in range(num_zones)]
        
        node_id_counter = 0
        
        # Generate control plane nodes
        num_control_plane = distribution[NodeType.CONTROL_PLANE]
        for i in range(num_control_plane):
            zone = zones[i % len(zones)]
            rack = f"rack-{i // 10 + 1}"
            node = PhysicalNode(
                node_id=f"control-plane-{node_id_counter}",
                node_type=NodeType.CONTROL_PLANE,
                zone=zone,
                rack=rack,
                profile=NODE_SPECS[NodeType.CONTROL_PLANE],
                labels={"node-role": "control-plane", "zone": zone},
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
                
                labels = {"node-type": node_type.value, "zone": zone}
                if node_type == NodeType.WORKER_GPU:
                    labels["gpu"] = "true"
                
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
        
        # Control plane: 1, 3, or 5 based on cluster size
        if self.cluster_size == ClusterSize.TINY:
            distribution[NodeType.CONTROL_PLANE] = 1
        elif self.cluster_size == ClusterSize.SMALL:
            distribution[NodeType.CONTROL_PLANE] = 3
        else:
            distribution[NodeType.CONTROL_PLANE] = 5
        
        remaining_nodes = self.num_nodes - distribution[NodeType.CONTROL_PLANE]
        
        # Use case specific distributions
        if self.use_case in [UseCase.ML_PLATFORM, UseCase.DATA_ANALYTICS]:
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
        elif self.use_case == UseCase.IOT_PLATFORM:
            distribution[NodeType.EDGE] = max(0, int(remaining_nodes * 0.3))
            distribution[NodeType.WORKER_MEMORY] = max(0, int(remaining_nodes * 0.2))
            distribution[NodeType.WORKER_GENERAL] = remaining_nodes - sum([
                distribution.get(NodeType.EDGE, 0),
                distribution.get(NodeType.WORKER_MEMORY, 0)
            ])
        else:
            # Default: mostly general purpose
            distribution[NodeType.WORKER_MEMORY] = max(0, int(remaining_nodes * 0.2))
            distribution[NodeType.WORKER_COMPUTE] = max(0, int(remaining_nodes * 0.15))
            distribution[NodeType.WORKER_GENERAL] = remaining_nodes - sum([
                distribution.get(NodeType.WORKER_MEMORY, 0),
                distribution.get(NodeType.WORKER_COMPUTE, 0)
            ])
        
        return distribution
```

## Step 4: Add ServicePlacementEngine

```python
class ServicePlacementEngine:
    """Place service pods onto physical nodes"""
    
    def __init__(self, nodes: List[PhysicalNode], services: Set[str], 
                 service_instances: Dict[str, int], seed: int = None):
        self.nodes = nodes
        self.services = services
        self.service_instances = service_instances
        self.placements: List[PodPlacement] = []
        
        if seed is not None:
            random.seed(seed)
    
    def place_services(self) -> List[PodPlacement]:
        """Place all service pods onto nodes"""
        # Sort services by resource weight (heaviest first)
        sorted_services = sorted(
            self.services,
            key=lambda s: SERVICE_CATALOG.get(s, ServiceProfile(
                name=s, category="unknown", resource_weight=1, requires_ha=False,
                dependencies=[], conflicts_with=[], probability_by_use_case={},
                min_cluster_size=ClusterSize.TINY
            )).resource_weight,
            reverse=True
        )
        
        for service_name in sorted_services:
            if service_name not in SERVICE_CATALOG:
                continue
            
            profile = SERVICE_CATALOG[service_name]
            num_instances = self.service_instances.get(service_name, 1)
            
            for instance_idx in range(num_instances):
                pod_id = f"{service_name}-{instance_idx}"
                best_node = self._find_best_node(profile, instance_idx, num_instances)
                
                if best_node:
                    placement = PodPlacement(
                        pod_id=pod_id,
                        service_name=service_name,
                        node_id=best_node.node_id,
                        cpu_request=profile.cpu_per_pod,
                        memory_request=profile.memory_per_pod,
                        storage_request=profile.storage_per_pod
                    )
                    
                    # Update node allocation
                    best_node.allocated_cpu += profile.cpu_per_pod
                    best_node.allocated_memory += profile.memory_per_pod
                    best_node.allocated_storage += profile.storage_per_pod
                    best_node.running_pods.append(pod_id)
                    
                    self.placements.append(placement)
        
        return self.placements
    
    def _find_best_node(self, profile: ServiceProfile, instance_idx: int, 
                       total_instances: int) -> Optional[PhysicalNode]:
        """Find the best node to place a pod"""
        candidate_nodes = []
        
        for node in self.nodes:
            # Skip control plane unless specifically needed
            if node.node_type == NodeType.CONTROL_PLANE:
                if profile.preferred_node_types and NodeType.CONTROL_PLANE in profile.preferred_node_types:
                    pass
                else:
                    continue
            
            # Check resource availability
            if (node.available_cpu() < profile.cpu_per_pod or
                node.available_memory() < profile.memory_per_pod or
                node.available_storage() < profile.storage_per_pod):
                continue
            
            # Check GPU requirement
            if profile.requires_gpu and node.profile.gpu_count == 0:
                continue
            
            # Score based on node type preference
            if profile.preferred_node_types:
                if node.node_type in profile.preferred_node_types:
                    candidate_nodes.append((node, 1.0))
                else:
                    candidate_nodes.append((node, 0.5))
            else:
                candidate_nodes.append((node, 1.0))
        
        if not candidate_nodes:
            return None
        
        # For HA services, spread across zones
        if profile.requires_ha and total_instances > 1:
            used_zones = set()
            for placement in self.placements:
                if placement.service_name == profile.name:
                    for node in self.nodes:
                        if node.node_id == placement.node_id:
                            used_zones.add(node.zone)
            
            candidates_by_zone = [
                (node, score * 2.0) for node, score in candidate_nodes
                if node.zone not in used_zones
            ]
            
            if candidates_by_zone:
                candidate_nodes = candidates_by_zone
        
        # Score based on utilization (prefer less utilized)
        scored_nodes = []
        for node, base_score in candidate_nodes:
            utilization_score = 1.0 - (node.cpu_utilization() / 100.0)
            total_score = base_score * utilization_score
            scored_nodes.append((node, total_score))
        
        scored_nodes.sort(key=lambda x: x[1], reverse=True)
        return scored_nodes[0][0] if scored_nodes else None
```

## Step 5: Add NodeGraphGenerator

```python
class NodeGraphGenerator:
    """Generate network topology graphs for physical nodes"""
    
    def __init__(self, nodes: List[PhysicalNode], placements: List[PodPlacement], seed: int = None):
        self.nodes = nodes
        self.placements = placements
        self.node_connections: Dict[str, Set[str]] = {}
        
        if seed is not None:
            random.seed(seed)
    
    def generate_topology(self) -> Dict[str, Set[str]]:
        """Generate node-to-node connectivity"""
        # Initialize
        for node in self.nodes:
            self.node_connections[node.node_id] = set()
        
        # 1. Control plane to all workers
        control_plane_nodes = [n for n in self.nodes if n.node_type == NodeType.CONTROL_PLANE]
        worker_nodes = [n for n in self.nodes if n.node_type != NodeType.CONTROL_PLANE]
        
        for cp_node in control_plane_nodes:
            for worker_node in worker_nodes:
                self.node_connections[cp_node.node_id].add(worker_node.node_id)
                self.node_connections[worker_node.node_id].add(cp_node.node_id)
        
        # 2. Full mesh within zones
        nodes_by_zone: Dict[str, List[PhysicalNode]] = {}
        for node in self.nodes:
            if node.zone not in nodes_by_zone:
                nodes_by_zone[node.zone] = []
            nodes_by_zone[node.zone].append(node)
        
        for zone, zone_nodes in nodes_by_zone.items():
            for i, node1 in enumerate(zone_nodes):
                for node2 in zone_nodes[i+1:]:
                    if node1.node_type != NodeType.CONTROL_PLANE and node2.node_type != NodeType.CONTROL_PLANE:
                        self.node_connections[node1.node_id].add(node2.node_id)
                        self.node_connections[node2.node_id].add(node1.node_id)
        
        # 3. Service dependency connections
        service_to_nodes: Dict[str, Set[str]] = {}
        for placement in self.placements:
            if placement.service_name not in service_to_nodes:
                service_to_nodes[placement.service_name] = set()
            service_to_nodes[placement.service_name].add(placement.node_id)
        
        for service_name in service_to_nodes.keys():
            if service_name not in SERVICE_CATALOG:
                continue
            
            profile = SERVICE_CATALOG[service_name]
            service_nodes = service_to_nodes[service_name]
            
            for dep_service in profile.dependencies:
                if dep_service in service_to_nodes:
                    dep_nodes = service_to_nodes[dep_service]
                    for service_node in service_nodes:
                        for dep_node in dep_nodes:
                            self.node_connections[service_node].add(dep_node)
                            self.node_connections[dep_node].add(service_node)
        
        # 4. Cross-zone partial mesh
        all_worker_nodes = [n for n in self.nodes if n.node_type != NodeType.CONTROL_PLANE]
        num_cross_zone = min(len(all_worker_nodes) * 2, len(all_worker_nodes) * len(all_worker_nodes) // 10)
        
        for _ in range(num_cross_zone):
            node1 = random.choice(all_worker_nodes)
            node2 = random.choice(all_worker_nodes)
            if node1.node_id != node2.node_id and node1.zone != node2.zone:
                self.node_connections[node1.node_id].add(node2.node_id)
                self.node_connections[node2.node_id].add(node1.node_id)
        
        return self.node_connections
    
    def generate_physical_topology_dict(self) -> Dict:
        """Generate dictionary representation of physical network topology"""
        edges = []
        for source_node_id, targets in self.node_connections.items():
            for target_node_id in targets:
                if source_node_id < target_node_id:  # Avoid duplicates
                    source_node = next((n for n in self.nodes if n.node_id == source_node_id), None)
                    target_node = next((n for n in self.nodes if n.node_id == target_node_id), None)
                    
                    if source_node and target_node:
                        edge_type = "intra_zone" if source_node.zone == target_node.zone else "inter_zone"
                        latency_ms = random.uniform(0.1, 1.0) if edge_type == "intra_zone" else random.uniform(2.0, 10.0)
                        
                        edges.append({
                            "source": source_node_id,
                            "target": target_node_id,
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
```

## Step 6: Extend K8sClusterGenerator

Add to the `__init__` method:

```python
def __init__(self, num_nodes: int, use_case: UseCase, seed: int = None):
    # ... existing code ...
    self.physical_nodes: List[PhysicalNode] = []
    self.placements: List[PodPlacement] = []
```

Update the `generate()` method:

```python
def generate(self) -> Dict:
    """Generate a realistic cluster configuration with physical nodes"""
    # Phase 1: Select services (existing code)
    for service_name, profile in SERVICE_CATALOG.items():
        probability = profile.probability_by_use_case.get(self.use_case.value, 0)
        if random.random() < probability:
            self._add_service_with_dependencies(service_name)
    
    # Phase 2: Generate physical nodes (NEW)
    node_generator = PhysicalNodeGenerator(
        self.num_nodes, 
        self.cluster_size, 
        self.use_case, 
        self.seed
    )
    self.physical_nodes = node_generator.generate_nodes()
    
    # Phase 3: Place services on nodes (NEW)
    placement_engine = ServicePlacementEngine(
        self.physical_nodes,
        self.selected_services,
        self.service_instances,
        self.seed
    )
    self.placements = placement_engine.place_services()
    
    # Phase 4: Generate node topology (NEW)
    graph_generator = NodeGraphGenerator(
        self.physical_nodes,
        self.placements,
        self.seed
    )
    node_topology = graph_generator.generate_topology()
    physical_topology_dict = graph_generator.generate_physical_topology_dict()
    
    # Phase 5: Build cluster config (extend existing)
    total_pods = sum(self.service_instances.values())
    successfully_placed_pods = len(self.placements)
    
    cluster_config = {
        "cluster_metadata": {
            # ... existing fields ...
            "placed_pods": successfully_placed_pods,
            "unplaced_pods": total_pods - successfully_placed_pods,
        },
        "services": sorted(list(self.selected_services)),
        "service_instances": {k: v for k, v in sorted(self.service_instances.items())},
        "services_by_category": self._group_by_category(),
        "deployment_stats": self._generate_stats(),
        
        # NEW FIELDS:
        "physical_nodes": self._nodes_to_dict(),
        "node_topology": physical_topology_dict,
        "pod_placements": self._placements_to_dict(),
        "node_utilization": self._calculate_node_utilization()
    }
    
    return cluster_config
```

Add helper methods:

```python
def _nodes_to_dict(self) -> List[Dict]:
    """Convert physical nodes to dictionary format"""
    return [
        {
            "node_id": node.node_id,
            "node_type": node.node_type.value,
            "zone": node.zone,
            "rack": node.rack,
            "cpu_cores": node.profile.cpu_cores,
            "memory_gb": node.profile.memory_gb,
            "storage_gb": node.profile.storage_gb,
            "gpu_count": node.profile.gpu_count,
            "allocated_cpu": round(node.allocated_cpu, 2),
            "allocated_memory": round(node.allocated_memory, 2),
            "allocated_storage": round(node.allocated_storage, 2),
            "cpu_utilization_pct": round(node.cpu_utilization(), 2),
            "memory_utilization_pct": round(node.memory_utilization() if hasattr(node, 'memory_utilization') else 
                                           (node.allocated_memory / node.profile.memory_gb * 100), 2),
            "running_pods": node.running_pods,
            "pod_count": len(node.running_pods),
            "labels": node.labels,
            "taints": node.taints
        }
        for node in self.physical_nodes
    ]

def _placements_to_dict(self) -> List[Dict]:
    """Convert pod placements to dictionary format"""
    return [
        {
            "pod_id": p.pod_id,
            "service_name": p.service_name,
            "node_id": p.node_id,
            "cpu_request": p.cpu_request,
            "memory_request": p.memory_request,
            "storage_request": p.storage_request
        }
        for p in self.placements
    ]

def _calculate_node_utilization(self) -> Dict:
    """Calculate overall node utilization statistics"""
    if not self.physical_nodes:
        return {}
    
    total_cpu = sum(n.profile.cpu_cores for n in self.physical_nodes)
    total_memory = sum(n.profile.memory_gb for n in self.physical_nodes)
    total_storage = sum(n.profile.storage_gb for n in self.physical_nodes)
    
    allocated_cpu = sum(n.allocated_cpu for n in self.physical_nodes)
    allocated_memory = sum(n.allocated_memory for n in self.physical_nodes)
    allocated_storage = sum(n.allocated_storage for n in self.physical_nodes)
    
    return {
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
            node_type.value: len([n for n in self.physical_nodes if n.node_type == node_type])
            for node_type in NodeType
        }
    }
```

## Summary

This extension adds:
- ✅ 7 node types with realistic resource profiles
- ✅ Physical node generation with zone/rack awareness
- ✅ Intelligent pod-to-node placement algorithm
- ✅ Node-level network topology generation
- ✅ Resource utilization tracking
- ✅ All existing functionality preserved

The extension is **additive** - all your original code continues to work, with new capabilities available when needed.
