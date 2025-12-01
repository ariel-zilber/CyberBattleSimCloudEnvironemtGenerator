"""
Logical Cluster Generator
=========================
Generates the abstract Kubernetes cluster state:
- Determines cluster size and resource capacity.
- Selects services based on UseCase probabilities or explicit configuration.
- Assigns services to logical subnets.
- Generates high-level firewall and OSINT configurations.
"""

import random
from typing import List, Dict, Set, Tuple, Optional, Union
from dataclasses import dataclass, field,asdict

# Relative imports
from ..config.enums import ClusterSize, UseCase
from ..config.models import ServiceProfile
from ..config.catalogs import SERVICE_CATALOG

# ======================================================================
# Dynamic Configuration Structures
# ======================================================================

@dataclass
class SubnetConfig:
    """Configuration for network subnets in the cluster"""
    subnet_ranges: List[Union[int, Tuple[int, int]]]  # e.g., [1, (1,4), (1,6)]
    address_space_bounds: Tuple[int, int]  # (max_subnets, max_hosts_per_subnet)
    subnet_labels: Optional[Dict[int, str]] = None
    sensitive_subnet_probabilities: Optional[Dict[int, float]] = None
    
    def __post_init__(self):
        if self.subnet_labels is None:
            self.subnet_labels = {}
        if self.sensitive_subnet_probabilities is None:
            self.sensitive_subnet_probabilities = {}

@dataclass
class NetworkTopologyConfig:
    """Configuration for network topology between subnets"""
    topology_matrix: Optional[List[List[int]]] = None  # Adjacency matrix
    topology_type: str = "mesh"  # mesh, star, hub_spoke, random
    connectivity_probability: float = 0.3  # For random topology
    
    def generate_topology(self, num_subnets: int) -> List[List[int]]:
        """Generate topology matrix based on configuration"""
        if self.topology_matrix:
            return self.topology_matrix
        
        if self.topology_type == "mesh":
            return [[1 if i != j else 0 for j in range(num_subnets)] for i in range(num_subnets)]
        
        elif self.topology_type == "star":
            matrix = [[0] * num_subnets for _ in range(num_subnets)]
            for i in range(1, num_subnets):
                matrix[0][i] = matrix[i][0] = 1
            return matrix
        
        elif self.topology_type == "hub_spoke":
            matrix = [[0] * num_subnets for _ in range(num_subnets)]
            for i in range(1, num_subnets):
                matrix[0][i] = matrix[i][0] = 1
                if random.random() < 0.2:
                    j = random.randint(1, num_subnets - 1)
                    if i != j:
                        matrix[i][j] = matrix[j][i] = 1
            return matrix
        
        elif self.topology_type == "random":
            matrix = [[0] * num_subnets for _ in range(num_subnets)]
            for i in range(num_subnets):
                for j in range(i + 1, num_subnets):
                    if random.random() < self.connectivity_probability:
                        matrix[i][j] = matrix[j][i] = 1
            return matrix
        
        else:
            raise ValueError(f"Unknown topology type: {self.topology_type}")

@dataclass
class ServiceDistributionConfig:
    """Configuration for how services are distributed across subnets"""
    service_selection_strategy: str = "probability"  # probability, required, graph_theory_random
    service_probabilities: Optional[Dict[str, float]] = None
    required_services: Optional[List[str]] = None
    excluded_services: Optional[List[str]] = None
    subnet_service_affinity: Optional[Dict[int, List[str]]] = None
    
    def __post_init__(self):
        if self.service_probabilities is None:
            self.service_probabilities = {}
        if self.required_services is None:
            self.required_services = []
        if self.excluded_services is None:
            self.excluded_services = []
        if self.subnet_service_affinity is None:
            self.subnet_service_affinity = {}

@dataclass
class FirewallConfig:
    """Configuration for firewall rules"""
    incoming: str = "_subnets"  # _all, _none, _subnets
    incoming_exceptions: List[str] = field(default_factory=list)
    outgoing: str = "_all"  # _all, _none, _subnets
    outgoing_exceptions: List[str] = field(default_factory=list)
    default_block_probability: float = 0.2

@dataclass
class OsintConfig:
    """Configuration for OSINT (Open Source Intelligence) visibility"""
    status: str = "enabled"
    services_strategy: str = "graph_theory_random"
    visible_services: Optional[List[str]] = None
    visibility_probability: float = 0.5
    
    def __post_init__(self):
        if self.visible_services is None:
            self.visible_services = []

@dataclass
class ClusterDynamicConfig:
    """Complete dynamic configuration for cluster generation"""
    num_nodes: int
    use_case: UseCase
    
    # Optional configs
    subnet_config: Optional[SubnetConfig] = None
    network_topology: Optional[NetworkTopologyConfig] = None
    service_distribution: Optional[ServiceDistributionConfig] = None
    firewall_config: Optional[FirewallConfig] = None
    osint_config: Optional[OsintConfig] = None
    os_distribution: Optional[Dict[str, float]] = None
    sensitive_host_probability: float = 0.3
    seed: Optional[int] = None
    
    def __post_init__(self):
        if self.subnet_config is None:
            self.subnet_config = SubnetConfig(
                subnet_ranges=[1, (1, 4), (1, 4), (1, 6)],
                address_space_bounds=(10, 10)
            )
        if self.network_topology is None:
            self.network_topology = NetworkTopologyConfig(topology_type="mesh")
        if self.service_distribution is None:
            self.service_distribution = ServiceDistributionConfig()
        if self.firewall_config is None:
            self.firewall_config = FirewallConfig()
        if self.osint_config is None:
            self.osint_config = OsintConfig()
        if self.os_distribution is None:
            self.os_distribution = {"linux": 0.7, "windows": 0.3}

# ======================================================================
# Main Logical Generator
# ======================================================================

class K8sClusterGenerator:
    """
    Generates the logical structure of a Kubernetes cluster.
    Translates UseCase and Config into specific service selections and instance counts.
    """
    
    def __init__(self, config: ClusterDynamicConfig):
        self.config = config
        self.num_nodes = config.num_nodes
        self.use_case = config.use_case
        self.cluster_size = self._determine_cluster_size(config.num_nodes)
        
        # State
        self.selected_services: Set[str] = set()
        self.service_instances: Dict[str, int] = {}
        self.service_subnet_mapping: Dict[str, List[int]] = {}
        self.subnet_host_counts: Dict[int, int] = {}
        self.subnets: List[int] = []
        self.topology_matrix: List[List[int]] = []
        
        if config.seed is not None:
            random.seed(config.seed)
    
    @staticmethod
    def _determine_cluster_size(num_nodes: int) -> ClusterSize:
        for size in ClusterSize:
            min_nodes, max_nodes = size.value
            if min_nodes <= num_nodes <= max_nodes:
                return size
        return ClusterSize.XLARGE
    
    def _generate_subnets(self) -> List[int]:
        subnets = []
        for range_spec in self.config.subnet_config.subnet_ranges:
            if isinstance(range_spec, int):
                subnets.append(range_spec)
            elif isinstance(range_spec, tuple):
                min_hosts, max_hosts = range_spec
                subnets.append(random.randint(min_hosts, max_hosts))
            else:
                raise ValueError(f"Invalid subnet range specification: {range_spec}")
        return subnets
    
    def _select_services_by_strategy(self) -> Set[str]:
        """Select services based on configured strategy using SERVICE_CATALOG"""
        strategy = self.config.service_distribution.service_selection_strategy
        selected = set()
        available_services = list(SERVICE_CATALOG.keys())
        
        # 1. Always include required services
        for service in self.config.service_distribution.required_services:
            if service in available_services:
                selected.add(service)
        
        # 2. Filter exclusions
        candidates = [
            s for s in available_services 
            if s not in self.config.service_distribution.excluded_services
        ]
        
        # 3. Apply Strategy
        if strategy == "probability":
            # Use predefined probabilities in SERVICE_CATALOG based on UseCase
            for service in candidates:
                profile = SERVICE_CATALOG[service]
                # Default probability based on UseCase
                prob = profile.probability_by_use_case.get(self.use_case.value, 0.0)
                
                # Override with explicit config if provided
                if service in self.config.service_distribution.service_probabilities:
                    prob = self.config.service_distribution.service_probabilities[service]
                
                if random.random() < prob:
                    selected.add(service)
                    
        elif strategy == "required":
            # Only include required services (already added)
            pass
        
        elif strategy == "graph_theory_random":
            # Random selection with a bias towards 30-70% of catalog
            num_to_select = random.randint(
                len(candidates) // 3,
                2 * len(candidates) // 3
            )
            selected.update(random.sample(candidates, num_to_select))
            
        # 4. Resolve Dependencies
        final_selection = set(selected)
        for service in selected:
            profile = SERVICE_CATALOG[service]
            for dep in profile.dependencies:
                if dep in SERVICE_CATALOG:
                    final_selection.add(dep)
                    
        return final_selection
    
    def _assign_services_to_subnets(self):
        """Assign selected services to subnets"""
        for service in self.selected_services:
            assigned_subnets = []
            
            # Check explicit affinity config
            for subnet_id, preferred_services in self.config.service_distribution.subnet_service_affinity.items():
                if service in preferred_services and subnet_id < len(self.subnets):
                    assigned_subnets.append(subnet_id)
            
            # If no affinity, random assignment
            if not assigned_subnets:
                # Most services live in 1 subnet, critical ones might be in multiple
                num_subnets = random.randint(1, min(3, len(self.subnets)))
                assigned_subnets = random.sample(range(len(self.subnets)), num_subnets)
            
            self.service_subnet_mapping[service] = assigned_subnets
    
    def _calculate_instance_count(self, service_name: str) -> int:
        """Calculate number of instances based on profile and cluster size"""
        if service_name not in SERVICE_CATALOG:
            return 1
            
        profile = SERVICE_CATALOG[service_name]
        base_count = profile.base_instance_count
        
        if not profile.scale_with_cluster:
            # Respect HA
            return 2 if profile.requires_ha and base_count < 2 else base_count
            
        # Scale logic
        if self.cluster_size == ClusterSize.TINY:
            instances = base_count
        elif self.cluster_size == ClusterSize.SMALL:
            instances = base_count + 1
        elif self.cluster_size == ClusterSize.MEDIUM:
            instances = base_count + 2
        elif self.cluster_size == ClusterSize.LARGE:
            instances = base_count + 3
        else:
            instances = base_count + 5
            
        # Distribute across assigned subnets
        subnets = self.service_subnet_mapping.get(service_name, [])
        if subnets:
            # Ensure we have at least 1 instance per subnet if HA is required
            if profile.requires_ha:
                instances = max(instances, len(subnets))
        
        return max(instances, 1)
    
    def generate(self) -> Dict:
        """Execute generation pipeline"""
        self.subnets = self._generate_subnets()
        num_subnets = len(self.subnets)
        self.topology_matrix = self.config.network_topology.generate_topology(num_subnets)
        
        self.selected_services = self._select_services_by_strategy()
        self._assign_services_to_subnets()
        
        for service in self.selected_services:
            self.service_instances[service] = self._calculate_instance_count(service)
        
        total_pods = sum(self.service_instances.values())
        
        # Build subnet metadata
        subnet_info = []
        for i, host_count in enumerate(self.subnets):
            subnet_label = self.config.subnet_config.subnet_labels.get(i + 1, f"subnet_{i+1}")
            sensitive_prob = self.config.subnet_config.sensitive_subnet_probabilities.get(i + 1, 0.0)
            
            services_in_subnet = [
                s for s, subnets in self.service_subnet_mapping.items() 
                if i in subnets
            ]
            
            subnet_info.append({
                "id": i + 1,
                "label": subnet_label,
                "host_count": host_count,
                "sensitive_probability": sensitive_prob,
                "services": services_in_subnet,
                "num_services": len(services_in_subnet)
            })
        
        cluster_config = {
            "cluster_metadata": {
                "num_nodes": self.num_nodes,
                "cluster_size": self.cluster_size.name,
                "use_case": self.use_case.value,
                "total_services": len(self.selected_services),
                "total_pods": total_pods,
                "avg_pods_per_node": f"{total_pods / self.num_nodes:.1f}",
                "num_subnets": num_subnets,
                "total_hosts": sum(self.subnets)
            },
            "services": sorted(list(self.selected_services)),
            "service_instances": {k: v for k, v in sorted(self.service_instances.items())},
            "network": {
                "subnets": subnet_info,
                "topology_matrix": self.topology_matrix,
                "address_space_bounds": self.config.subnet_config.address_space_bounds
            },
            "service_distribution": {
                service: {
                    "instances": self.service_instances[service],
                    "subnets": self.service_subnet_mapping[service]
                }
                for service in sorted(self.selected_services)
            },
            "firewall": asdict(self.config.firewall_config),
            "osint": asdict(self.config.osint_config),
            "os_distribution": self.config.os_distribution
        }
        
        return cluster_config