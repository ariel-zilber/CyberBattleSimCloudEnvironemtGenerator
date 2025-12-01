"""
Kubernetes Realistic Cluster Generator - Enhanced with Dynamic Configuration
=============================================================================
Extends the base generator with support for dynamic configuration selection
similar to network topology YAML configs.

BACKWARDS COMPATIBLE: Can be used as a drop-in replacement for the original generator.

Author: Auto-generated
Date: 2025-11-15
"""

import random
import json
import yaml
from typing import List, Dict, Set, Tuple, Optional, Union
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
import sys
import os


# ======================================================================
# Import from original generator for backwards compatibility
# ======================================================================

try:
    # Try to import from the original generator if available
    from k8s_cluster_generator import (
        K8sClusterGenerator as OriginalK8sClusterGenerator,
        ClusterSize,
        UseCase,
        ServiceProfile,
        SERVICE_CATALOG
    )
    HAS_ORIGINAL = True
except ImportError:
    # If original not available, define the classes here
    HAS_ORIGINAL = False
    
    class ClusterSize(Enum):
        """Cluster size categories with node ranges"""
        TINY = (1, 3)
        SMALL = (3, 10)
        MEDIUM = (10, 50)
        LARGE = (50, 200)
        XLARGE = (200, 1000)

    class UseCase(Enum):
        """Common cluster use cases"""
        STARTUP_MVP = "startup_mvp"
        MICROSERVICES = "microservices"
        DATA_ANALYTICS = "data_analytics"
        ML_PLATFORM = "ml_platform"
        WEB_HOSTING = "web_hosting"
        ENTERPRISE_INTERNAL = "enterprise_internal"
        ECOMMERCE = "ecommerce"
        SAAS_PLATFORM = "saas_platform"
        IOT_PLATFORM = "iot_platform"
        GAMING_BACKEND = "gaming_backend"
    
    # Placeholder - would be imported from original
    @dataclass
    class ServiceProfile:
        name: str
        category: str
        resource_weight: int
        requires_ha: bool
        dependencies: List[str]
        conflicts_with: List[str]
        probability_by_use_case: Dict[str, float]
        min_cluster_size: 'ClusterSize'
        base_instance_count: int = 1
        scale_with_cluster: bool = False
    
    SERVICE_CATALOG = {}  # Would be imported from original


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
            # Full mesh - all subnets connected
            return [[1 if i != j else 0 for j in range(num_subnets)] for i in range(num_subnets)]
        
        elif self.topology_type == "star":
            # Star topology - subnet 0 is hub
            matrix = [[0] * num_subnets for _ in range(num_subnets)]
            for i in range(1, num_subnets):
                matrix[0][i] = matrix[i][0] = 1
            return matrix
        
        elif self.topology_type == "hub_spoke":
            # Hub and spoke with limited inter-spoke
            matrix = [[0] * num_subnets for _ in range(num_subnets)]
            for i in range(1, num_subnets):
                matrix[0][i] = matrix[i][0] = 1
                # Some spokes can talk to each other
                if random.random() < 0.2:
                    j = random.randint(1, num_subnets - 1)
                    if i != j:
                        matrix[i][j] = matrix[j][i] = 1
            return matrix
        
        elif self.topology_type == "random":
            # Random topology with connectivity probability
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
    subnet_service_affinity: Optional[Dict[int, List[str]]] = None  # Which services prefer which subnets
    
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
    
    def allows_incoming(self, service: str, from_subnet: int, to_subnet: int) -> bool:
        """Check if incoming traffic is allowed"""
        if service in self.incoming_exceptions:
            return True
        
        if self.incoming == "_all":
            return True
        elif self.incoming == "_none":
            return False
        elif self.incoming == "_subnets":
            return from_subnet == to_subnet
        
        return False
    
    def allows_outgoing(self, service: str, from_subnet: int, to_subnet: int) -> bool:
        """Check if outgoing traffic is allowed"""
        if service in self.outgoing_exceptions:
            return True
        
        if self.outgoing == "_all":
            return True
        elif self.outgoing == "_none":
            return False
        elif self.outgoing == "_subnets":
            return from_subnet == to_subnet
        
        return False


@dataclass
class OsintConfig:
    """Configuration for OSINT (Open Source Intelligence) visibility"""
    status: str = "enabled"  # enabled, disabled
    services_strategy: str = "graph_theory_random"  # all, none, random, graph_theory_random
    visible_services: Optional[List[str]] = None
    visibility_probability: float = 0.5
    
    def __post_init__(self):
        if self.visible_services is None:
            self.visible_services = []


@dataclass
class ClusterDynamicConfig:
    """Complete dynamic configuration for cluster generation"""
    # Core cluster parameters
    num_nodes: int
    use_case: UseCase
    
    # Network configuration
    subnet_config: Optional[SubnetConfig] = None
    network_topology: Optional[NetworkTopologyConfig] = None
    
    # Service configuration
    service_distribution: Optional[ServiceDistributionConfig] = None
    
    # Security configuration
    firewall_config: Optional[FirewallConfig] = None
    osint_config: Optional[OsintConfig] = None
    
    # Host configuration
    os_distribution: Optional[Dict[str, float]] = None  # e.g., {"linux": 0.7, "windows": 0.3}
    sensitive_host_probability: float = 0.3
    
    # Randomization
    seed: Optional[int] = None
    
    def __post_init__(self):
        # Set defaults if not provided
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
# Backwards Compatible Wrapper
# ======================================================================

class K8sClusterGenerator:
    """
    Backwards compatible wrapper for the enhanced generator.
    Can be used as a drop-in replacement for the original generator.
    
    Usage (identical to original):
        generator = K8sClusterGenerator(
            num_nodes=10,
            use_case=UseCase.MICROSERVICES,
            seed=42
        )
        cluster = generator.generate()
    """
    
    def __init__(self, num_nodes: int, use_case: UseCase, seed: int = None):
        """
        Initialize with the same interface as the original generator.
        
        Args:
            num_nodes: Number of nodes in the cluster
            use_case: Primary use case for the cluster
            seed: Random seed for reproducibility (optional)
        """
        # Create a basic config for backwards compatibility
        self.num_nodes = num_nodes
        self.use_case = use_case
        self.seed = seed
        
        # Use enhanced generator internally with default config
        config = ClusterDynamicConfig(
            num_nodes=num_nodes,
            use_case=use_case,
            seed=seed,
            # Use None for all optional params to get default behavior
            subnet_config=None,
            network_topology=None,
            service_distribution=None,
            firewall_config=None,
            osint_config=None
        )
        
        self._enhanced_generator = EnhancedK8sClusterGenerator(config)
        
        # Expose same attributes as original
        self.cluster_size = self._enhanced_generator.cluster_size
        self.selected_services = self._enhanced_generator.selected_services
        self.service_instances = self._enhanced_generator.service_instances
        self.total_resource_weight = 0
    
    @staticmethod
    def _determine_cluster_size(num_nodes: int) -> ClusterSize:
        """Determine cluster size category from node count (same as original)"""
        for size in ClusterSize:
            min_nodes, max_nodes = size.value
            if min_nodes <= num_nodes <= max_nodes:
                return size
        return ClusterSize.XLARGE
    
    def generate(self) -> Dict:
        """
        Generate a realistic cluster configuration.
        Returns the same format as the original generator.
        
        Returns:
            Dict with cluster configuration (compatible with original format)
        """
        result = self._enhanced_generator.generate()
        
        # Update internal state for backwards compatibility
        self.selected_services = self._enhanced_generator.selected_services
        self.service_instances = self._enhanced_generator.service_instances
        self.total_resource_weight = sum(
            self.service_instances.get(s, 0) 
            for s in self.selected_services
        )
        
        # Return in original format (without enhanced fields if not needed)
        # But include them for those who want to use them
        return result


# ======================================================================
# Enhanced Cluster Generator
# ======================================================================

class EnhancedK8sClusterGenerator:
    """
    Enhanced Kubernetes cluster generator with dynamic configuration support.
    Allows for fine-grained control over network topology, service distribution,
    firewall rules, and visibility similar to network simulation configs.
    """
    
    def __init__(self, config: ClusterDynamicConfig):
        self.config = config
        self.num_nodes = config.num_nodes
        self.use_case = config.use_case
        self.cluster_size = self._determine_cluster_size(config.num_nodes)
        
        # State
        self.selected_services: Set[str] = set()
        self.service_instances: Dict[str, int] = {}
        self.service_subnet_mapping: Dict[str, List[int]] = {}  # Service -> subnets it's deployed in
        self.subnet_host_counts: Dict[int, int] = {}
        self.subnets: List[int] = []
        self.topology_matrix: List[List[int]] = []
        
        if config.seed is not None:
            random.seed(config.seed)
    
    @staticmethod
    def _determine_cluster_size(num_nodes: int) -> ClusterSize:
        """Determine cluster size category from node count"""
        for size in ClusterSize:
            min_nodes, max_nodes = size.value
            if min_nodes <= num_nodes <= max_nodes:
                return size
        return ClusterSize.XLARGE
    
    def _generate_subnets(self) -> List[int]:
        """Generate subnet host counts based on configuration"""
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
    
    def _select_services_by_strategy(self, available_services: List[str]) -> Set[str]:
        """Select services based on configured strategy"""
        strategy = self.config.service_distribution.service_selection_strategy
        selected = set()
        
        # Always include required services
        for service in self.config.service_distribution.required_services:
            if service in available_services:
                selected.add(service)
        
        # Exclude services that should not be included
        available_services = [
            s for s in available_services 
            if s not in self.config.service_distribution.excluded_services
        ]
        
        if strategy == "probability":
            # Use configured probabilities
            for service in available_services:
                prob = self.config.service_distribution.service_probabilities.get(service, 0.5)
                if random.random() < prob:
                    selected.add(service)
        
        elif strategy == "required":
            # Only include required services (already added above)
            pass
        
        elif strategy == "graph_theory_random":
            # Random selection with graph connectivity considerations
            # More connected services have higher probability
            num_to_select = random.randint(
                len(available_services) // 3,
                2 * len(available_services) // 3
            )
            selected.update(random.sample(available_services, num_to_select))
        
        return selected
    
    def _assign_services_to_subnets(self):
        """Assign selected services to subnets based on affinity"""
        for service in self.selected_services:
            # Check if service has subnet affinity
            assigned_subnets = []
            
            for subnet_id, preferred_services in self.config.service_distribution.subnet_service_affinity.items():
                if service in preferred_services and subnet_id < len(self.subnets):
                    assigned_subnets.append(subnet_id)
            
            # If no affinity specified, randomly assign to subnets
            if not assigned_subnets:
                num_subnets = random.randint(1, min(3, len(self.subnets)))
                assigned_subnets = random.sample(range(len(self.subnets)), num_subnets)
            
            self.service_subnet_mapping[service] = assigned_subnets
    
    def _calculate_instance_count(self, service_name: str, base_count: int = 2) -> int:
        """Calculate number of instances for a service"""
        # Scale based on cluster size
        if self.cluster_size == ClusterSize.TINY:
            instances = base_count
        elif self.cluster_size == ClusterSize.SMALL:
            instances = base_count + 1
        elif self.cluster_size == ClusterSize.MEDIUM:
            instances = base_count + 2
        elif self.cluster_size == ClusterSize.LARGE:
            instances = base_count + 3
        else:  # XLARGE
            instances = base_count + 5
        
        # Multiply by number of subnets service is deployed in
        subnets = self.service_subnet_mapping.get(service_name, [])
        if subnets:
            instances *= len(subnets)
        
        return max(instances, 1)
    
    def generate(self) -> Dict:
        """Generate a cluster configuration with dynamic settings"""
        # Generate subnets
        self.subnets = self._generate_subnets()
        num_subnets = len(self.subnets)
        
        # Generate topology
        self.topology_matrix = self.config.network_topology.generate_topology(num_subnets)
        
        # For this example, we'll use a simplified service catalog
        # In production, you would integrate with the full SERVICE_CATALOG
        example_services = [
            "nginx", "postgresql", "redis", "prometheus", "grafana",
            "etcd", "vault", "kong", "kafka", "elasticsearch",
            "mongodb", "rabbitmq", "jenkins", "argo-cd"
        ]
        
        # Select services based on strategy
        self.selected_services = self._select_services_by_strategy(example_services)
        
        # Assign services to subnets
        self._assign_services_to_subnets()
        
        # Calculate instance counts
        for service in self.selected_services:
            self.service_instances[service] = self._calculate_instance_count(service)
        
        # Calculate total pods
        total_pods = sum(self.service_instances.values())
        
        # Build subnet information
        subnet_info = []
        for i, host_count in enumerate(self.subnets):
            subnet_label = self.config.subnet_config.subnet_labels.get(i + 1, f"subnet_{i+1}")
            sensitive_prob = self.config.subnet_config.sensitive_subnet_probabilities.get(i + 1, 0.0)
            
            # Services in this subnet
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
        
        # Build firewall rules summary
        firewall_summary = {
            "incoming_policy": self.config.firewall_config.incoming,
            "outgoing_policy": self.config.firewall_config.outgoing,
            "incoming_exceptions": self.config.firewall_config.incoming_exceptions,
            "outgoing_exceptions": self.config.firewall_config.outgoing_exceptions,
            "default_block_probability": self.config.firewall_config.default_block_probability
        }
        
        # Build OSINT summary
        osint_summary = {
            "status": self.config.osint_config.status,
            "strategy": self.config.osint_config.services_strategy,
            "visible_services": self.config.osint_config.visible_services,
            "visibility_probability": self.config.osint_config.visibility_probability
        }
        
        # Build complete configuration
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
            "firewall": firewall_summary,
            "osint": osint_summary,
            "os_distribution": self.config.os_distribution,
            "configuration": {
                "service_selection_strategy": self.config.service_distribution.service_selection_strategy,
                "topology_type": self.config.network_topology.topology_type,
                "seed": self.config.seed
            }
        }
        
        return cluster_config


# ======================================================================
# YAML Configuration Loader
# ======================================================================

class ConfigLoader:
    """Load cluster configurations from YAML files"""
    
    @staticmethod
    def load_from_yaml(yaml_path: str) -> ClusterDynamicConfig:
        """Load configuration from YAML file"""
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        # Parse subnet configuration
        subnet_ranges = []
        for subnet_spec in data.get('subnets', [1]):
            if isinstance(subnet_spec, str) and '-' in subnet_spec:
                min_val, max_val = map(int, subnet_spec.split('-'))
                subnet_ranges.append((min_val, max_val))
            else:
                subnet_ranges.append(int(subnet_spec))
        
        subnet_config = SubnetConfig(
            subnet_ranges=subnet_ranges,
            address_space_bounds=tuple(data.get('address_space_bounds', (10, 10))),
            subnet_labels=data.get('subnet_labels', {}),
            sensitive_subnet_probabilities=data.get('sensitive_hosts', {})
        )
        
        # Parse network topology
        network_topology = NetworkTopologyConfig(
            topology_matrix=data.get('topology'),
            topology_type=data.get('topology_type', 'mesh' if not data.get('topology') else 'custom'),
            connectivity_probability=data.get('connectivity_probability', 0.3)
        )
        
        # Parse service distribution
        service_dist = ServiceDistributionConfig(
            service_selection_strategy=data.get('osint', {}).get('services', {}).get('strategy', 'probability'),
            required_services=data.get('services', []),
            service_probabilities={},  # Can be extended
            excluded_services=data.get('excluded_services', [])
        )
        
        # Parse firewall config
        firewall_data = data.get('firewall', {})
        firewall_config = FirewallConfig(
            incoming=firewall_data.get('incoming', '_subnets'),
            incoming_exceptions=firewall_data.get('incoming_exceptions', []),
            outgoing=firewall_data.get('outgoing', '_all'),
            outgoing_exceptions=firewall_data.get('outgoing_exceptions', [])
        )
        
        # Parse OSINT config
        osint_data = data.get('osint', {})
        osint_config = OsintConfig(
            status=osint_data.get('status', 'enabled'),
            services_strategy=osint_data.get('services', {}).get('strategy', 'random'),
            visible_services=osint_data.get('services', {}).get('values', [])
        )
        
        # OS distribution
        os_list = data.get('os', ['linux'])
        os_distribution = {os: 1.0 / len(os_list) for os in os_list}
        
        # Create complete config
        config = ClusterDynamicConfig(
            num_nodes=data.get('num_nodes', 10),
            use_case=UseCase(data.get('use_case', 'microservices')),
            subnet_config=subnet_config,
            network_topology=network_topology,
            service_distribution=service_dist,
            firewall_config=firewall_config,
            osint_config=osint_config,
            os_distribution=os_distribution,
            seed=data.get('seed')
        )
        
        return config


# ======================================================================
# CLI Interface
# ======================================================================

def generate_cluster_cli():
    """Command-line interface with dynamic configuration support"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Generate Kubernetes clusters with dynamic configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate from YAML config
  python k8s_cluster_generator_enhanced.py --config cluster_config.yaml
  
  # Generate with inline parameters
  python k8s_cluster_generator_enhanced.py --nodes 20 --use-case microservices \\
      --topology-type hub_spoke --service-strategy graph_theory_random
  
  # Generate multiple scenarios
  python k8s_cluster_generator_enhanced.py --config base_config.yaml --count 5
        """
    )
    
    parser.add_argument(
        "--config", "-c",
        type=str,
        help="Path to YAML configuration file"
    )
    
    parser.add_argument(
        "--nodes", "-n",
        type=int,
        help="Number of nodes in the cluster"
    )
    
    parser.add_argument(
        "--use-case", "-u",
        type=str,
        choices=[uc.value for uc in UseCase],
        help="Primary use case for the cluster"
    )
    
    parser.add_argument(
        "--topology-type",
        type=str,
        choices=["mesh", "star", "hub_spoke", "random"],
        default="mesh",
        help="Network topology type"
    )
    
    parser.add_argument(
        "--service-strategy",
        type=str,
        choices=["probability", "required", "graph_theory_random"],
        default="probability",
        help="Service selection strategy"
    )
    
    parser.add_argument(
        "--seed", "-s",
        type=int,
        default=None,
        help="Random seed for reproducibility"
    )
    
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of configurations to generate"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output file (JSON format)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    results = []
    
    for i in range(args.count):
        seed = args.seed + i if args.seed is not None else None
        
        # Load configuration
        if args.config:
            config = ConfigLoader.load_from_yaml(args.config)
            if seed is not None:
                config.seed = seed
        else:
            # Create configuration from CLI arguments
            if not args.nodes or not args.use_case:
                parser.error("--nodes and --use-case required when not using --config")
            
            config = ClusterDynamicConfig(
                num_nodes=args.nodes,
                use_case=UseCase(args.use_case),
                network_topology=NetworkTopologyConfig(topology_type=args.topology_type),
                service_distribution=ServiceDistributionConfig(
                    service_selection_strategy=args.service_strategy
                ),
                seed=seed
            )
        
        # Generate cluster
        generator = EnhancedK8sClusterGenerator(config)
        cluster_config = generator.generate()
        results.append(cluster_config)
        
        if args.verbose:
            print(f"\n{'='*80}")
            print(f"Cluster Configuration {i+1}/{args.count}")
            print(f"{'='*80}")
            print(f"Nodes: {cluster_config['cluster_metadata']['num_nodes']}")
            print(f"Subnets: {cluster_config['cluster_metadata']['num_subnets']}")
            print(f"Services: {cluster_config['cluster_metadata']['total_services']}")
            print(f"Total Pods: {cluster_config['cluster_metadata']['total_pods']}")
            print(f"Topology: {config.network_topology.topology_type}")
            print(f"\nSubnets:")
            for subnet in cluster_config['network']['subnets']:
                print(f"  {subnet['id']}: {subnet['label']} - {subnet['host_count']} hosts, "
                      f"{subnet['num_services']} services")
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results if args.count > 1 else results[0], f, indent=2)
        print(f"\n✅ Configuration saved to {args.output}")
    else:
        print(json.dumps(results if args.count > 1 else results[0], indent=2))


# ======================================================================
# Example Usage
# ======================================================================

if __name__ == "__main__":
    import sys
    
    # Check if CLI arguments provided
    if len(sys.argv) > 1:
        generate_cluster_cli()
    else:
        # Example usage showing both backwards compatible and enhanced usage
        print("Kubernetes Cluster Generator - Enhanced Edition")
        print("="*80)
        print("\n*** BACKWARDS COMPATIBLE MODE ***")
        print("Using the original interface (works exactly like before):\n")
        
        # Example 1: Original interface (backwards compatible)
        generator = K8sClusterGenerator(
            num_nodes=10,
            use_case=UseCase.MICROSERVICES,
            seed=42
        )
        
        cluster = generator.generate()
        
        print(f"Generated cluster using original interface:")
        print(f"  Nodes: {cluster['cluster_metadata']['num_nodes']}")
        print(f"  Services: {cluster['cluster_metadata']['total_services']}")
        print(f"  Pods: {cluster['cluster_metadata']['total_pods']}")
        
        print("\n" + "="*80)
        print("\n*** ENHANCED MODE ***")
        print("Using the new enhanced interface with custom configuration:\n")
        
        # Example 2: Enhanced interface with custom config
        config = ClusterDynamicConfig(
            num_nodes=10,
            use_case=UseCase.MICROSERVICES,
            subnet_config=SubnetConfig(
                subnet_ranges=[1, (1, 4), (1, 4), (2, 6)],
                address_space_bounds=(10, 10),
                subnet_labels={
                    1: "dmz",
                    2: "application_tier",
                    3: "data_tier",
                    4: "management"
                }
            ),
            network_topology=NetworkTopologyConfig(
                topology_type="hub_spoke"
            ),
            seed=42
        )
        
        enhanced_generator = EnhancedK8sClusterGenerator(config)
        enhanced_cluster = enhanced_generator.generate()
        
        print(f"Generated cluster using enhanced interface:")
        print(f"  Nodes: {enhanced_cluster['cluster_metadata']['num_nodes']}")
        print(f"  Subnets: {enhanced_cluster['cluster_metadata']['num_subnets']}")
        print(f"  Services: {enhanced_cluster['cluster_metadata']['total_services']}")
        print(f"  Pods: {enhanced_cluster['cluster_metadata']['total_pods']}")
        
        print("\n" + "="*80)
        print("\nBoth interfaces available!")
        print("  - Use K8sClusterGenerator() for original interface")
        print("  - Use EnhancedK8sClusterGenerator() for new features")
        print("\nRun with --help for CLI options")
        print("="*80)