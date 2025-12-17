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
import numpy as np
from typing import Dict, List, Set, Optional, Union

from cyberbattlesim_cloud_gen.config.config_loader import ConfigLoader
from cyberbattlesim_cloud_gen.config.enums import ClusterSize
from cyberbattlesim_cloud_gen.generators.physical_gen.ip_allocation import IPAllocation
from cyberbattlesim_cloud_gen.generators.physical_gen.network_access_graph import (
    NetworkAccessGraph,
)
from cyberbattlesim_cloud_gen.generators.physical_gen.node_characteristics import (
    NodeCharacteristics,
)
from cyberbattlesim_cloud_gen.generators.physical_gen.node_connection import (
    NodeConnection,
)
from cyberbattlesim_cloud_gen.generators.physical_gen.node_zone import NodeZone
from cyberbattlesim_cloud_gen.generators.physical_gen.physical_node import PhysicalNode
from cyberbattlesim_cloud_gen.generators.physical_gen.security_group import (
    SecurityGroup,
)
from cyberbattlesim_cloud_gen.generators.physical_gen.security_group_rule import (
    SecurityGroupRule,
)


class PhysicalNodeGenerator:
    """Generate physical node topology for a Kubernetes cluster"""

    def __init__(
        self,
        cluster_config: Dict,
        num_nodes: Optional[int] = None,
        num_zones: Optional[int] = None,
        zone_distribution: str = "balanced",
        seed: Optional[int] = None,
        config_loader_instance: ConfigLoader = None,
    ):
        self.cluster_config = cluster_config
        self.config_loader_instance = (
            config_loader_instance or ConfigLoader.get_instance()
        )

        # Allow overriding num_nodes from the config
        self.num_nodes = (
            num_nodes
            if num_nodes is not None
            else cluster_config["cluster_metadata"]["num_nodes"]
        )

        if num_nodes is not None:
            self.cluster_size = self._determine_cluster_size(num_nodes)
        else:
            self.cluster_size = ClusterSize[
                cluster_config["cluster_metadata"]["cluster_size"]
            ]

        self.use_case = cluster_config["cluster_metadata"]["use_case"]
        self.services = cluster_config["services"]
        self.service_instances = cluster_config["service_instances"]

        # Zone configuration
        if num_zones is not None:
            self.num_zones = max(1, num_zones)
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
            np.random.seed(seed)

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
        else:
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
        if self.num_zones <= 256:
            subnet_prefix = 16
        else:
            subnet_prefix = 24

        zone_subnets = list(base_network.subnets(new_prefix=subnet_prefix))
        available_zones = NodeZone.get_zones(self.num_zones)

        for i, zone in enumerate(available_zones):
            if i < len(zone_subnets):
                self.zone_subnets[zone] = zone_subnets[i]
            else:
                self.zone_subnets[zone] = ipaddress.ip_network(
                    f"10.{i}.0.0/{subnet_prefix}"
                )
            self.zone_ip_allocations[zone] = set()

    def _allocate_ip_for_node(self, zone: str, node_index: int) -> IPAllocation:
        """Allocate IP address for a node in a specific zone"""
        if zone == "public":
            return IPAllocation(
                ipv4="0.0.0.0", subnet="0.0.0.0", gateway="0.0.0.0", cidr="0.0.0.0/0"
            )

        if zone not in self.zone_subnets:
            fallback_index = len(self.zone_subnets)
            self.zone_subnets[zone] = ipaddress.ip_network(
                f"10.{fallback_index}.0.0/24"
            )
            self.zone_ip_allocations[zone] = set()

        subnet = self.zone_subnets[zone]

        # Calculate IP based on node index
        ip_index = (node_index % (subnet.num_addresses - 3)) + 2
        ip_address = str(subnet[ip_index])

        # Simple collision avoidance
        while ip_address in self.zone_ip_allocations[zone]:
            ip_index = (ip_index + 1) % (subnet.num_addresses - 3) + 2
            ip_address = str(subnet[ip_index])

        self.zone_ip_allocations[zone].add(ip_address)
        gateway = str(subnet[1])
        cidr = str(subnet)

        return IPAllocation(
            ipv4=ip_address, subnet=str(subnet.netmask), gateway=gateway, cidr=cidr
        )

    def _create_security_groups(self):
        """Create security groups for each zone"""
        for zone in self.zone_subnets.keys():
            group_id = f"sg-{zone}-{random.randint(1000, 9999)}"
            rules = [
                SecurityGroupRule(
                    rule_id=f"{group_id}-ingress-internal",
                    direction="ingress",
                    protocol="all",
                    port_range=None,
                    source_cidr=self.zone_subnets[zone].with_prefixlen,
                    destination_cidr=self.zone_subnets[zone].with_prefixlen,
                    action="allow",
                    description="Allow all traffic within zone",
                )
            ]

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
                                description=f"Allow traffic from {other_zone}",
                            )
                        )

            self.security_groups[zone] = SecurityGroup(
                group_id=group_id, zone=zone, name=f"security-group-{zone}", rules=rules
            )

    def _determine_node_type_distribution(self) -> Dict:
        """Determine how many nodes of each type to create based on node profiles"""
        NodeType = self.config_loader_instance.NodeType
        node_profiles = self.config_loader_instance.get_node_type_profiles()

        distribution = {}
        remaining = self.num_nodes

        # 1. Allocate min_count / ha_required
        for node_type, profile in node_profiles.items():
            min_count = profile.get("min_count", 0)
            ha_required = profile.get("ha_required", False)

            count = 0
            if ha_required and self.num_nodes >= 3:
                count = max(min_count, 3)
            elif min_count > 0:
                count = min_count

            if count > 0:
                distribution[node_type] = count
                remaining -= count

        # 2. Ensure control plane
        try:
            cp_type = NodeType.CONTROL_PLANE
            if cp_type not in distribution:
                count = 3 if self.num_nodes >= 3 else 1
                distribution[cp_type] = count
                remaining -= count
        except AttributeError:
            pass

        # 3. Dump remainder into Worker
        try:
            w_type = NodeType.WORKER
            distribution[w_type] = distribution.get(w_type, 0) + max(0, remaining)
        except AttributeError:
            pass

        return distribution

    def _generate_resource_value(
        self, config: Union[Dict, int, float, List]
    ) -> Union[int, float]:
        """
        Generates a resource value based on the new YAML config structure.
        Handles:
          - Dict: {min: 4, max: 8, distribution: 'performance'}
          - List: [4, 8] (Backward compatibility)
          - Scalar: 10
        """
        # 1. Handle List [min, max] (Old format)
        if isinstance(config, list):
            if len(config) == 2:
                return random.choice(
                    [config[0], (config[0] + config[1]) // 2, config[1]]
                )
            return config[0] if config else 0

        # 2. Handle Scalar
        if not isinstance(config, dict):
            return config

        # 3. Handle Dict (New format)
        min_val = config.get("min", 0)
        max_val = config.get("max", 0)
        dist = config.get("distribution", "uniform")

        if min_val == max_val:
            return min_val

        val = min_val
        if dist == "performance":
            # Skew towards max
            val = random.triangular(min_val, max_val, max_val)
        elif dist == "efficiency":
            # Skew towards min
            val = random.triangular(min_val, max_val, min_val)
        elif dist == "log_normal":
            # Log normalish (using Beta for bounded range)
            val = min_val + (max_val - min_val) * np.random.beta(2, 5)
        else:
            # Uniform
            if isinstance(min_val, int) and isinstance(max_val, int):
                val = random.randint(min_val, max_val)
            else:
                val = random.uniform(min_val, max_val)

        return int(val) if isinstance(min_val, int) else round(val, 2)

    def _calculate_node_asset_value(self, node_type: str, services: List[str]) -> int:
        """
        Calculates the CyberBattleSim 'value' (reward) for this node based on strategy.
        This fixes the ValueError by ensuring every node has a value.
        """
        strategy = self.config_loader_instance.get_value_strategy()
        base_value = strategy.get("base_value", 50)

        # 1. Apply Node Type Multiplier
        type_mult = (
            strategy.get("multipliers", {}).get("node_type", {}).get(node_type, 1.0)
        )
        current_value = base_value * type_mult

        # Get multiplier dictionaries
        service_cat_mults = strategy.get("multipliers", {}).get("services", {})
        specific_svc_mults = strategy.get("multipliers", {}).get(
            "specific_services", {}
        )

        # 2. Apply Service Multipliers
        for svc in services:
            boost_multiplier = 1.0

            # Check for exact name match first
            if svc in specific_svc_mults:
                boost_multiplier = specific_svc_mults[svc]
            else:
                # Fallback to category match
                cat = self.config_loader_instance.get_service_category(svc)
                if cat in service_cat_mults:
                    boost_multiplier = service_cat_mults[cat]

            # Apply boost (Additive logic: 1.5 multiplier adds 50% of base value)
            if boost_multiplier > 1.0:
                boost = (boost_multiplier - 1.0) * base_value
                current_value += boost

        # 3. Add Noise
        noise_pct = strategy.get("noise_percentage", 0.0)
        if noise_pct > 0:
            noise = random.uniform(-noise_pct, noise_pct)
            current_value = current_value * (1 + noise)

        return int(max(10, current_value))  # Ensure at least some value

    def _create_node(self, node_type, node_index: int, zone: str) -> PhysicalNode:
        """Create a single physical node with characteristics using new config"""
        NodeType = self.config_loader_instance.NodeType

        # Handle Enum to String conversion for lookup
        type_str = node_type.value if hasattr(node_type, "value") else str(node_type)
        profile = self.config_loader_instance.get_node_profile_config(type_str)

        # Helper to get config with fallback
        def get_cfg(key, default_min, default_max):
            return profile.get(key, {"min": default_min, "max": default_max})

        # Generate Resources using new helper
        characteristics = NodeCharacteristics(
            cpu_cores=self._generate_resource_value(get_cfg("cpu", 2, 4)),
            memory_gb=self._generate_resource_value(get_cfg("memory_gb", 4, 8)),
            disk_gb=self._generate_resource_value(get_cfg("disk_gb", 50, 100)),
            network_bandwidth_gbps=float(profile.get("bandwidth_gbps", 10.0)),
            has_gpu=profile.get("has_gpu", False),
            gpu_count=self._generate_resource_value(profile.get("gpu_count", 0)),
        )

        ip_allocation = self._allocate_ip_for_node(zone, node_index)

        labels = {
            "node-type": type_str,
            "zone": zone,
            "kubernetes.io/hostname": f"node-{type_str}-{node_index:03d}",
            "ipv4": ip_allocation.ipv4,
        }

        # Value is initialized to 0, will be calculated after pod assignment
        node = PhysicalNode(
            node_id=f"node-{type_str}-{node_index:03d}",
            node_type=node_type,
            zone=zone,
            ip_allocation=ip_allocation,
            characteristics=characteristics,
            labels=labels,
            security_groups=[f"sg-{zone}"] if zone != "public" else [],
            value=0,
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
        if not available_zones:
            return "zone-a"
        return available_zones[node_index % len(available_zones)]

    def _get_node_affinity(self, service_name: str) -> List:
        service_node_affinity = self.config_loader_instance.get_node_affinity()
        return service_node_affinity.get(
            service_name, service_node_affinity.get("default", [])
        )

    def _assign_pods_to_nodes(self):
        """Assign service pods to physical nodes based on Node Affinity rules."""
        NodeType = self.config_loader_instance.NodeType

        pods_to_assign = []
        for service_name, instance_count in self.service_instances.items():
            for instance_id in range(instance_count):
                pods_to_assign.append((service_name, instance_id))

        random.shuffle(pods_to_assign)

        for service_name, instance_id in pods_to_assign:
            preferred_types = self._get_node_affinity(service_name)
            eligible_nodes = [n for n in self.nodes if n.node_type in preferred_types]

            if not eligible_nodes:
                try:
                    eligible_nodes = [
                        n for n in self.nodes if n.node_type == NodeType.WORKER
                    ]
                except AttributeError:
                    pass

            if not eligible_nodes:
                try:
                    eligible_nodes = [
                        n for n in self.nodes if n.node_type != NodeType.INTERNET
                    ]
                except AttributeError:
                    eligible_nodes = self.nodes

            if eligible_nodes:
                selected_node = min(eligible_nodes, key=lambda n: len(n.assigned_pods))
                selected_node.assigned_pods.append((service_name, instance_id))

    def _get_services_on_node(self, node: PhysicalNode) -> List[str]:
        return list(set([pod[0] for pod in node.assigned_pods]))

    def _get_ports_for_services(self, services: List[str]) -> List[int]:
        service_ports = self.config_loader_instance.get_service_ports()
        ports = []
        for service in services:
            if service in service_ports:
                ports.extend(service_ports[service])
        return list(set(ports))

    def _generate_node_network_topology(self):
        connections = []
        for i, node1 in enumerate(self.nodes):
            for node2 in self.nodes[i + 1 :]:
                connections.append(
                    NodeConnection(
                        from_node=node1.node_id,
                        to_node=node2.node_id,
                        from_ip=node1.ip_allocation.ipv4,
                        to_ip=node2.ip_allocation.ipv4,
                        latency_ms=random.uniform(0.1, 2.0),
                        bandwidth_gbps=10.0,
                        packet_loss=0.0,
                    )
                )
                connections.append(
                    NodeConnection(
                        from_node=node2.node_id,
                        to_node=node1.node_id,
                        from_ip=node2.ip_allocation.ipv4,
                        to_ip=node1.ip_allocation.ipv4,
                        latency_ms=random.uniform(0.1, 2.0),
                        bandwidth_gbps=10.0,
                        packet_loss=0.0,
                    )
                )
        return connections

    def _generate_network_access_graph(self):
        return []

    def _generate_service_mapping(self) -> Dict[str, List[str]]:
        service_ports = self.config_loader_instance.get_service_ports()
        mapping = {}
        for node in self.nodes:
            for service_name, instance_id in node.assigned_pods:
                pod_id = f"{service_name}-{instance_id}"
                if service_name not in mapping:
                    mapping[service_name] = []
                mapping[service_name].append(
                    {
                        "pod_id": pod_id,
                        "node_id": node.node_id,
                        "zone": node.zone,
                        "node_ip": node.ip_allocation.ipv4,
                        "services_ports": service_ports.get(service_name, []),
                    }
                )
        return mapping

    def _apply_realistic_firewall_rules(self, permissive_level: float):
        NodeType = self.config_loader_instance.NodeType
        public_services = self.config_loader_instance.get_public_services()
        public_services = set(
            self.cluster_config.get("public_services", []) + list(public_services)
        )
        all_cidrs = list([str(subnet) for subnet in self.zone_subnets.values()])
        dmz_zone = "zone-a"

        for node in self.nodes:
            try:
                if node.node_type == NodeType.INTERNET:
                    continue
            except AttributeError:
                pass

            incoming, outgoing = [], []

            for cidr in all_cidrs:
                outgoing.append(
                    {
                        "subnet": cidr,
                        "permission": "ALLOW",
                        "port": "*",
                        "reason": "Internal Routing",
                    }
                )
                if node.zone != "public":
                    incoming.append(
                        {
                            "subnet": cidr,
                            "permission": "ALLOW",
                            "port": "*",
                            "reason": "Internal Trust",
                        }
                    )

            node_services = self._get_services_on_node(node)
            is_public_node = any(s in public_services for s in node_services)

            if is_public_node and node.zone == dmz_zone:
                ports = self._get_ports_for_services(node_services)
                for port in ports:
                    incoming.append(
                        {
                            "subnet": "0.0.0.0/0",
                            "permission": "ALLOW",
                            "port": str(port),
                            "reason": "Public Service Access",
                        }
                    )

            if permissive_level > 0 and random.random() < permissive_level:
                incoming.append(
                    {
                        "subnet": "0.0.0.0/0",
                        "permission": "ALLOW",
                        "port": "22",
                        "reason": "MISCONFIG: SSH Exposed",
                    }
                )

            incoming.append(
                {
                    "subnet": "0.0.0.0/0",
                    "permission": "DENY",
                    "port": "*",
                    "reason": "Default Deny",
                }
            )
            outgoing.append(
                {
                    "subnet": "0.0.0.0/0",
                    "permission": "DENY",
                    "port": "*",
                    "reason": "Default Deny",
                }
            )
            node.firewall = {"incoming": incoming, "outgoing": outgoing}

    def generate(
        self,
        firewall_probability: float = 0.1,
        firewall_cross_zone_only: bool = False,
        node_failure_probability: float = 0.05,
        permissive_level: float = 0.1,
    ) -> Dict:
        """Generate complete physical node topology"""
        NodeType = self.config_loader_instance.NodeType

        self.nodes = self._generate_nodes()
        self._create_security_groups()
        self._assign_pods_to_nodes()

        # --- NEW: Calculate Node Values (Fixing the ValueError) ---
        for node in self.nodes:
            type_str = (
                node.node_type.value
                if hasattr(node.node_type, "value")
                else str(node.node_type)
            )
            services = self._get_services_on_node(node)
            node.value = self._calculate_node_asset_value(type_str, services)
        # -----------------------------------------------------------

        # Add Internet Node
        try:
            internet_node = self._create_node(NodeType.INTERNET, 0, "public")
            internet_node.node_id = "node-internet"
            internet_node.properties = ["attacker", "external", "internet"]
            internet_node.value = 0  # Attacker node has no value
            internet_node.firewall = {
                "incoming": [
                    {
                        "subnet": "0.0.0.0/0",
                        "permission": "ALLOW",
                        "port": "*",
                        "reason": "Internet",
                    }
                ],
                "outgoing": [
                    {
                        "subnet": "0.0.0.0/0",
                        "permission": "ALLOW",
                        "port": "*",
                        "reason": "Internet",
                    }
                ],
            }
            self.nodes.append(internet_node)
        except AttributeError:
            pass

        self._apply_realistic_firewall_rules(permissive_level)
        self.node_connections = self._generate_node_network_topology()
        self.network_access_graph = self._generate_network_access_graph()

        topology = {
            "metadata": {
                "generator": "PhysicalNodeGenerator",
                "version": "2.1-InternetAware",
                "num_physical_nodes": self.num_nodes,
                "num_zones": self.num_zones,
            },
            "network_configuration": {
                "zone_subnets": {
                    zone: str(subnet) for zone, subnet in self.zone_subnets.items()
                },
                "ip_allocations": {
                    zone: list(ips) for zone, ips in self.zone_ip_allocations.items()
                },
            },
            "security_groups": {
                sg_id: sg.to_dict() for sg_id, sg in self.security_groups.items()
            },
            "nodes": [node.to_dict() for node in self.nodes],
            "node_connections": [conn.to_dict() for conn in self.node_connections],
            "network_access_graph": [
                entry.to_dict() for entry in self.network_access_graph
            ],
            "node_to_service_mapping": self._generate_service_mapping(),
        }

        return topology
