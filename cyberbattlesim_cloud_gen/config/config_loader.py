import yaml
from pathlib import Path
from enum import Enum
from typing import Dict, List, Any, Set, Tuple, Union

# Default base directory
DEFAULT_CONFIG_DIR = Path(__file__).parent

# Config file names (fixed)
SERVICES_CONFIG_NAME = "services.yaml"
NODES_CONFIG_NAME = "node_type.yaml"
VULN_CONFIG_NAME = "vulnerability.yaml"
TOPOLOGY_CONFIG_NAME = "topology.yaml"
CATALOG_CONFIG_NAME = "catalog.yaml"


class ConfigLoader:
    _instance = None
    _initialized = False

    def __new__(cls, base_dir: Path = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, base_dir: Path = None):
        if ConfigLoader._initialized:
            return
        
        base_dir = Path(base_dir) if base_dir else DEFAULT_CONFIG_DIR
        
        self.services = {}
        self.defaults = {}
        self.shared_credentials = {}
        self.node_profiles_data = {}
        self.value_strategy = {}  # NEW: Stores the reward strategy
        self.vuln_profiles_data = {}
        self.default_vuln_profile = {}
        self.topology_data = {}
        self.catalog_data = {}
        self.cluster_sizes = {}
        self.vuln_scoring_strategy = {} # NEW: Stores the scoring configuration
        
        self._load_yaml(base_dir / SERVICES_CONFIG_NAME, self._parse_services)
        self._load_yaml(base_dir / NODES_CONFIG_NAME, self._parse_nodes)
        self._load_yaml(base_dir / VULN_CONFIG_NAME, self._parse_vuln)
        self._load_yaml(base_dir / TOPOLOGY_CONFIG_NAME, self._parse_topology)
        self._load_yaml(base_dir / CATALOG_CONFIG_NAME, self._parse_catalog)
        
        self.NodeType = self._create_node_type_enum()
        
        ConfigLoader._initialized = True

    @classmethod
    def get_instance(cls, base_dir: Path = None):
        """Get the singleton instance, creating it if necessary."""
        if cls._instance is None:
            cls._instance = cls(base_dir)
        return cls._instance

    @classmethod
    def reset(cls):
        """Reset the singleton (useful for testing)."""
        cls._instance = None
        cls._initialized = False

    def _load_yaml(self, path, parser_func):
        if path.exists():
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
                parser_func(data)
        else:
            print(f"WARNING: Config not found at {path}")

    # --- Parsers ---
    def _parse_services(self, data):
        self.defaults = data.get('defaults', {})
        self.services = data.get('services', {})
        self.shared_credentials = data.get('shared_credentials', {})

    def _parse_nodes(self, data):
        self.node_profiles_data = data.get('node_profiles', {})
        # NEW: Parse the value strategy from the same file
        self.value_strategy = data.get('value_strategy', {})

    def _parse_vuln(self, data):
        self.vuln_profiles_data = data.get('profiles', {})
        self.default_vuln_profile = data.get('default_profile', {})
        self.vuln_scoring_strategy = data.get('scoring_strategy', {})
    
    def _parse_topology(self, data):
        self.topology_data = data

    def _parse_catalog(self, data):
        self.cluster_sizes = data.get('cluster_sizes', {})
        self.catalog_data = data.get('services', {})

    def _create_node_type_enum(self):
        enum_members = {k.upper(): k for k in self.node_profiles_data.keys()}
        # Add Aliases
        if "compute" in self.node_profiles_data: enum_members["COMPUTE_OPTIMIZED"] = "compute"
        if "memory" in self.node_profiles_data: enum_members["MEMORY_OPTIMIZED"] = "memory"
        if "storage" in self.node_profiles_data: enum_members["STORAGE_OPTIMIZED"] = "storage"
        return Enum('NodeType', enum_members)

    # --- NODE CONFIG GETTERS ---

    def get_node_profile_config(self, node_type_name: str) -> Dict[str, Any]:
        """Retrieves the raw dictionary config for a specific node type."""
        # Normalize keys (handle Enum or String)
        key = node_type_name.value if hasattr(node_type_name, 'value') else str(node_type_name)
        # Fallback to 'worker' if type not found to prevent crashes
        return self.node_profiles_data.get(key.lower()) or self.node_profiles_data.get('worker', {})

    def get_value_strategy(self) -> Dict[str, Any]:
        """Retrieves the strategy for calculating node value/reward."""
        return self.value_strategy or {
            "base_value": 50,
            "multipliers": {"node_type": {}},
            "noise_percentage": 0.0
        }

    # --- TOPOLOGY GETTERS ---
    def get_topology_config(self) -> Dict[str, Any]:
        """Returns the full topology configuration"""
        return self.topology_data

    def get_subnet_ranges(self) -> List[Union[int, Tuple[int, int]]]:
        """Converts YAML lists [1, 4] to Python Tuples (1, 4)"""
        raw_ranges = self.topology_data.get('subnets', {}).get('ranges', [])
        processed = []
        for r in raw_ranges:
            if isinstance(r, list):
                processed.append(tuple(r))
            else:
                processed.append(r)
        return processed

    def get_subnet_bounds(self) -> Tuple[int, int]:
        bounds = self.topology_data.get('subnets', {}).get('bounds', {})
        return (bounds.get('max_subnets', 5), bounds.get('max_hosts_per_subnet', 254))

    def get_subnet_labels(self) -> Dict[int, str]:
        """Returns subnet ID to label mapping."""
        return self.topology_data.get('subnet_labels', {})

    def get_sensitive_subnet_probabilities(self) -> Dict[int, float]:
        """Returns subnet ID to sensitivity probability mapping."""
        return self.topology_data.get('sensitive_subnet_probabilities', {})

    def get_address_space_config(self) -> Dict[str, Any]:
        """Returns address space configuration."""
        return self.topology_data.get('address_space', {
            'base_network': '10.0.0.0/8',
            'subnet_prefix': 24
        })

    def get_zones_config(self) -> List[Dict[str, Any]]:
        """Returns zone configurations."""
        return self.topology_data.get('zones', [])

    def get_topology_type(self) -> str:
        """Returns the network topology type."""
        return self.topology_data.get('topology_type', 'mesh')

    def get_firewall_defaults(self) -> Dict[str, Any]:
        """Returns default firewall configuration."""
        return self.topology_data.get('firewall', {
            'default_policy': 'deny',
            'cross_zone_probability': 0.3,
            'same_zone_probability': 0.9
        })

    def get_service_category_map(self) -> Dict[str, str]:
        """Helper to fix _infer_category in generator"""
        cat_map = {}
        for name, cfg in self.services.items():
            cats = cfg.get('category', [])
            if cats:
                cat_map[name] = cats[0]
        return cat_map

    def get_service_category(self, service_name: str) -> str:
        """Returns the category for a specific service."""
        cfg = self.services.get(service_name, {})
        cats = cfg.get('category', [])
        if cats:
            return cats[0]
        # Fallback to catalog data
        catalog_cfg = self.catalog_data.get(service_name, {})
        return catalog_cfg.get('category', 'application')
    
    def get_service_ports(self) -> Dict[str, List[int]]:
        return {name: cfg.get('ports', []) for name, cfg in self.services.items() if 'ports' in cfg}

    def get_service_names(self) -> List[str]:
        """Returns all service names from services.yaml."""
        return list(self.services.keys())

    def get_public_services(self) -> Set[str]:
        return {name for name, cfg in self.services.items() if "public" in cfg.get('tags', []) or cfg.get('is_public', False)}

    def get_control_plane_services(self) -> List[str]:
        return [name for name, cfg in self.services.items() if "control_plane" in cfg.get('tags', [])]

    def get_node_affinity(self) -> Dict[str, List[Enum]]:
        affinity_map = {}
        default_affinity = self.defaults.get('node_affinity', ["WORKER"])
        for name, cfg in self.services.items():
            affinity_strs = cfg.get('node_affinity', default_affinity)
            mapped_types = []
            for a_str in affinity_strs:
                try:
                    member = getattr(self.NodeType, a_str.upper())
                    mapped_types.append(member)
                except AttributeError:
                    try:
                        member = self.NodeType(a_str)
                        mapped_types.append(member)
                    except ValueError: pass
            affinity_map[name] = mapped_types
        return affinity_map

    def get_connectivity_rules(self) -> Dict[str, Any]:
        rules = {}
        for name, cfg in self.services.items():
            conn_cfg = cfg.get('connectivity', {})
            tags = cfg.get('tags', [])
            is_crit = "critical" in tags or self.defaults['is_critical']
            is_pub = "public" in tags or self.defaults['is_public']
            ports = cfg.get('ports', [0])
            port_range = (ports[0], ports[-1]) if ports else (0,0)
            rules[name] = {
                "connects_to": conn_cfg.get('connects_to', []),
                "connectivity_probability": conn_cfg.get('probability', self.defaults['connectivity_probability']),
                "port_range": port_range,
                "requires_auth": conn_cfg.get('requires_auth', self.defaults['requires_auth']),
                "is_critical": is_crit,
                "is_public": is_pub
            }
        rules["default"] = {
            "connects_to": [], "connectivity_probability": 0.5, "port_range": (8000, 9000),
            "requires_auth": True, "is_critical": False, "is_public": False
        }
        return rules

    def get_credential_access_patterns(self) -> Dict[str, Dict[str, Tuple[int, str, List[str]]]]:
        patterns = {}
        for service, cfg in self.services.items():
            cred_access = cfg.get('credential_access', {})
            if not cred_access: continue
            patterns[service] = {}
            for target_svc, details in cred_access.items():
                if isinstance(details, dict):
                    patterns[service][target_svc] = (details.get('level', 1), details.get('type', 'password'), details.get('roles', []))
        return patterns

    def get_credential_caching_services(self) -> List[str]:
        return [name for name, cfg in self.services.items() if "credential_caching" in cfg.get('tags', [])]

    def get_shared_credential_patterns(self) -> Dict[str, List[str]]:
        return self.shared_credentials
        
    def get_node_type_profiles(self) -> Dict[Enum, Dict[str, Any]]:
        profiles = {}
        for key_str, data in self.node_profiles_data.items():
            try:
                enum_member = self.NodeType(key_str)
                profiles[enum_member] = data
            except ValueError: pass
        return profiles
        
    def get_service_vulnerability_profiles(self) -> Dict[str, Any]:
        profiles = {}
        for svc, data in self.vuln_profiles_data.items():
            profile = data.copy()
            if "base_vulnerability_count" in profile:
                profile["base_vulnerability_count"] = tuple(profile["base_vulnerability_count"])
            profiles[svc] = profile
        return profiles

    def get_default_vulnerability_profile(self) -> Dict[str, Any]:
        profile = self.default_vuln_profile.copy()
        if "base_vulnerability_count" in profile:
            profile["base_vulnerability_count"] = tuple(profile["base_vulnerability_count"])
        return profile

    # --- CATALOG GETTERS ---
    def get_cluster_sizes(self) -> Dict[str, Tuple[int, int]]:
        """Returns cluster size definitions as tuples (min, max)."""
        return {name: tuple(bounds) for name, bounds in self.cluster_sizes.items()}

    def get_cluster_size_for_nodes(self, num_nodes: int) -> str:
        """Returns the cluster size category for a given number of nodes."""
        for size_name, bounds in self.cluster_sizes.items():
            min_nodes, max_nodes = bounds
            if min_nodes <= num_nodes <= max_nodes:
                return size_name
        return "XLARGE"  # Default to largest if exceeds all bounds

    def get_catalog_services(self) -> Dict[str, Any]:
        """Returns all service catalog entries."""
        return self.catalog_data

    def get_catalog_service(self, service_name: str) -> Dict[str, Any]:
        """Returns catalog entry for a specific service."""
        return self.catalog_data.get(service_name, {})

    def get_services_by_category(self, category: str) -> List[str]:
        """Returns all services matching a category."""
        return [name for name, cfg in self.catalog_data.items() 
                if cfg.get('category') == category]

    def get_all_categories(self) -> Set[str]:
        """Returns all unique service categories."""
        return {cfg.get('category') for cfg in self.catalog_data.values() if cfg.get('category')}

    def get_service_dependencies(self, service_name: str) -> List[str]:
        """Returns dependencies for a service."""
        return self.catalog_data.get(service_name, {}).get('dependencies', [])

    def get_service_conflicts(self, service_name: str) -> List[str]:
        """Returns services that conflict with the given service."""
        return self.catalog_data.get(service_name, {}).get('conflicts_with', [])

    def get_services_by_min_cluster_size(self, cluster_size: str) -> List[str]:
        """Returns services that require at most the given cluster size."""
        size_order = list(self.cluster_sizes.keys())
        if cluster_size not in size_order:
            return []
        max_index = size_order.index(cluster_size)
        valid_sizes = set(size_order[:max_index + 1])
        return [name for name, cfg in self.catalog_data.items() 
                if cfg.get('min_cluster_size') in valid_sizes]

    def get_service_probability(self, service_name: str, use_case: str) -> float:
        """Returns the probability of a service being used for a given use case."""
        service_cfg = self.catalog_data.get(service_name, {})
        probabilities = service_cfg.get('probability_by_use_case', {})
        return probabilities.get(use_case, 0.0)

    def get_services_for_use_case(self, use_case: str, min_probability: float = 0.0) -> Dict[str, float]:
        """Returns services and their probabilities for a use case, filtered by minimum probability."""
        results = {}
        for name, cfg in self.catalog_data.items():
            prob = cfg.get('probability_by_use_case', {}).get(use_case, 0.0)
            if prob >= min_probability:
                results[name] = prob
        return results

    def get_ha_services(self) -> List[str]:
        """Returns services that require high availability."""
        return [name for name, cfg in self.catalog_data.items() if cfg.get('requires_ha', False)]

    def get_service_base_instance_count(self, service_name: str) -> int:
        """Returns the base instance count for a service."""
        return self.catalog_data.get(service_name, {}).get('base_instance_count', 1)

    def get_scalable_services(self) -> List[str]:
        """Returns services that scale with cluster size."""
        return [name for name, cfg in self.catalog_data.items() if cfg.get('scale_with_cluster', False)]

    def get_service_resource_weight(self, service_name: str) -> int:
        """Returns the resource weight for a service."""
        return self.catalog_data.get(service_name, {}).get('resource_weight', 1)

    def get_all_use_cases(self) -> Set[str]:
        """Returns all unique use cases defined across services."""
        use_cases = set()
        for cfg in self.catalog_data.values():
            use_cases.update(cfg.get('probability_by_use_case', {}).keys())
        return use_cases

    # --- SETTERS ---
    def set_services(self, services: Dict[str, Any]) -> None:
        """Set the services configuration."""
        self.services = services

    def set_defaults(self, defaults: Dict[str, Any]) -> None:
        """Set the defaults configuration."""
        self.defaults = defaults

    def set_shared_credentials(self, shared_credentials: Dict[str, List[str]]) -> None:
        """Set the shared credentials configuration."""
        self.shared_credentials = shared_credentials

    def set_node_profiles(self, node_profiles: Dict[str, Any]) -> None:
        """Set the node profiles and regenerate the NodeType enum."""
        self.node_profiles_data = node_profiles
        self.NodeType = self._create_node_type_enum()
    
    def set_value_strategy(self, strategy: Dict[str, Any]) -> None:
        """Set the value strategy manually (useful for testing)."""
        self.value_strategy = strategy

    def set_vulnerability_profiles(self, vuln_profiles: Dict[str, Any]) -> None:
        """Set the vulnerability profiles configuration."""
        self.vuln_profiles_data = vuln_profiles

    def set_default_vulnerability_profile(self, default_profile: Dict[str, Any]) -> None:
        """Set the default vulnerability profile."""
        self.default_vuln_profile = default_profile

    def set_topology(self, topology: Dict[str, Any]) -> None:
        """Set the topology configuration."""
        self.topology_data = topology

    def set_subnet_ranges(self, ranges: List[Union[int, Tuple[int, int]]]) -> None:
        """Set subnet ranges within the topology configuration."""
        if 'subnets' not in self.topology_data:
            self.topology_data['subnets'] = {}
        # Convert tuples back to lists for YAML compatibility
        self.topology_data['subnets']['ranges'] = [
            list(r) if isinstance(r, tuple) else r for r in ranges
        ]

    def set_subnet_bounds(self, max_subnets: int, max_hosts_per_subnet: int) -> None:
        """Set subnet bounds within the topology configuration."""
        if 'subnets' not in self.topology_data:
            self.topology_data['subnets'] = {}
        if 'bounds' not in self.topology_data['subnets']:
            self.topology_data['subnets']['bounds'] = {}
        self.topology_data['subnets']['bounds']['max_subnets'] = max_subnets
        self.topology_data['subnets']['bounds']['max_hosts_per_subnet'] = max_hosts_per_subnet

    def add_service(self, name: str, config: Dict[str, Any]) -> None:
        """Add or update a single service configuration."""
        self.services[name] = config

    def remove_service(self, name: str) -> bool:
        """Remove a service configuration. Returns True if removed, False if not found."""
        if name in self.services:
            del self.services[name]
            return True
        return False

    def add_node_profile(self, name: str, profile: Dict[str, Any]) -> None:
        """Add or update a node profile and regenerate the NodeType enum."""
        self.node_profiles_data[name] = profile
        self.NodeType = self._create_node_type_enum()

    def remove_node_profile(self, name: str) -> bool:
        """Remove a node profile. Returns True if removed, False if not found."""
        if name in self.node_profiles_data:
            del self.node_profiles_data[name]
            self.NodeType = self._create_node_type_enum()
            return True
        return False

    def add_vulnerability_profile(self, service: str, profile: Dict[str, Any]) -> None:
        """Add or update a vulnerability profile for a service."""
        self.vuln_profiles_data[service] = profile

    def remove_vulnerability_profile(self, service: str) -> bool:
        """Remove a vulnerability profile. Returns True if removed, False if not found."""
        if service in self.vuln_profiles_data:
            del self.vuln_profiles_data[service]
            return True
        return False

    def update_service_connectivity(self, service: str, connects_to: List[str] = None, 
                                     probability: float = None, requires_auth: bool = None) -> None:
        """Update connectivity settings for a service."""
        if service not in self.services:
            self.services[service] = {}
        if 'connectivity' not in self.services[service]:
            self.services[service]['connectivity'] = {}
        
        if connects_to is not None:
            self.services[service]['connectivity']['connects_to'] = connects_to
        if probability is not None:
            self.services[service]['connectivity']['probability'] = probability
        if requires_auth is not None:
            self.services[service]['connectivity']['requires_auth'] = requires_auth

    def update_service_tags(self, service: str, tags: List[str]) -> None:
        """Update tags for a service."""
        if service not in self.services:
            self.services[service] = {}
        self.services[service]['tags'] = tags

    def update_service_ports(self, service: str, ports: List[int]) -> None:
        """Update ports for a service."""
        if service not in self.services:
            self.services[service] = {}
        self.services[service]['ports'] = ports

    # --- CATALOG SETTERS ---
    def set_cluster_sizes(self, cluster_sizes: Dict[str, List[int]]) -> None:
        """Set the cluster size definitions."""
        self.cluster_sizes = cluster_sizes

    def set_catalog_data(self, catalog_data: Dict[str, Any]) -> None:
        """Set the entire service catalog."""
        self.catalog_data = catalog_data

    def add_catalog_service(self, name: str, config: Dict[str, Any]) -> None:
        """Add or update a service in the catalog."""
        self.catalog_data[name] = config

    def remove_catalog_service(self, name: str) -> bool:
        """Remove a service from the catalog. Returns True if removed, False if not found."""
        if name in self.catalog_data:
            del self.catalog_data[name]
            return True
        return False

    def update_service_probability(self, service: str, use_case: str, probability: float) -> None:
        """Update the probability for a service in a specific use case."""
        if service not in self.catalog_data:
            self.catalog_data[service] = {}
        if 'probability_by_use_case' not in self.catalog_data[service]:
            self.catalog_data[service]['probability_by_use_case'] = {}
        self.catalog_data[service]['probability_by_use_case'][use_case] = probability

    def update_service_dependencies(self, service: str, dependencies: List[str]) -> None:
        """Update dependencies for a catalog service."""
        if service not in self.catalog_data:
            self.catalog_data[service] = {}
        self.catalog_data[service]['dependencies'] = dependencies

    def update_service_conflicts(self, service: str, conflicts: List[str]) -> None:
        """Update conflicts for a catalog service."""
        if service not in self.catalog_data:
            self.catalog_data[service] = {}
        self.catalog_data[service]['conflicts_with'] = conflicts


    def get_vulnerability_scoring_strategy(self) -> Dict[str, Any]:
        """
        Retrieves the strategy for calculating vulnerability cost.
        Returns defaults if not configured in YAML.
        """
        defaults = {
            "base_score": 12.0,
            "min_score": 1.0,
            "multipliers": {
                "severity": 2.0,
                "exploitability": 2.0
            },
            "severity_weights": {
                "LOW": 1.0,
                "MEDIUM": 2.0,
                "HIGH": 3.0,
                "CRITICAL": 4.0
            }
        }
        strategy = defaults.copy()
        if self.vuln_scoring_strategy:
            strategy.update(self.vuln_scoring_strategy)
        return strategy