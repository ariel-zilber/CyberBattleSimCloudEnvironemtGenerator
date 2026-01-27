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
from typing import List, Dict, Set
from dataclasses import asdict

from cyberbattlesim_cloud_gen.config.config_loader import ConfigLoader
from cyberbattlesim_cloud_gen.config.enums import ClusterSize
from cyberbattlesim_cloud_gen.generators.logical_gen.cluster_dynamic_config import (
    ClusterDynamicConfig,
)


class K8sClusterGenerator:
    """
    Generates the logical structure of a Kubernetes cluster.
    Translates UseCase and Config into specific service selections and instance counts.
    """

    def __init__(
        self, config: ClusterDynamicConfig, config_loader_instance: ConfigLoader
    ):
        self.config = config
        self.num_nodes = config.num_nodes
        self.use_case = config.use_case
        self.cluster_size = self._determine_cluster_size(config.num_nodes)
        self.config_loader_instance = config_loader_instance

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
        available_services = self.config_loader_instance.get_service_names()
        # 1. Always include required services
        for service in self.config.service_distribution.required_services:
            if service in available_services:
                selected.add(service)

        # 2. Filter exclusions
        candidates = [
            s
            for s in available_services
            if s not in self.config.service_distribution.excluded_services
        ]

        # 3. Apply Strategy
        if strategy == "probability":
            # Use predefined probabilities in SERVICE_CATALOG based on UseCase
            for service in candidates:
                prob = self.config_loader_instance.get_service_probability(
                    service, self.use_case
                )
                print(prob)
                # Override with explicit config if provided
                if service in self.config.service_distribution.service_probabilities:
                    prob = self.config.service_distribution.service_probabilities[
                        service
                    ]

                if random.random() < prob:
                    selected.add(service)

        elif strategy == "required":
            # Only include required services (already added)
            pass

        elif strategy == "graph_theory_random":
            # Random selection with a bias towards 30-70% of catalog
            num_to_select = random.randint(
                len(candidates) // 3, 2 * len(candidates) // 3
            )
            selected.update(random.sample(candidates, num_to_select))

        # 4. Resolve Dependencies
        final_selection = set(selected)
        for service in selected:
            for dep in self.config_loader_instance.get_service_dependencies(service):
                if dep in self.config_loader_instance.get_catalog_services():
                    final_selection.add(dep)

        return final_selection

    def _assign_services_to_subnets(self):
        """Assign selected services to subnets"""
        for service in self.selected_services:
            assigned_subnets = []

            # Check explicit affinity config
            for (
                subnet_id,
                preferred_services,
            ) in self.config.service_distribution.subnet_service_affinity.items():
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
        catalog_service = self.config_loader_instance.get_catalog_service(service_name)
        if not catalog_service:
            return 1

        base_count = catalog_service.get("base_instance_count", 1)
        requires_ha = catalog_service.get("requires_ha", False)
        scale_with_cluster = catalog_service.get("scale_with_cluster", False)

        if not scale_with_cluster:
            # Respect HA
            return 2 if requires_ha and base_count < 2 else base_count

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
            if requires_ha:
                instances = max(instances, len(subnets))

        return max(instances, 1)

    def generate(self) -> Dict:
        """Execute generation pipeline"""
        self.subnets = self._generate_subnets()
        num_subnets = len(self.subnets)
        self.topology_matrix = self.config.network_topology.generate_topology(
            num_subnets
        )

        self.selected_services = self._select_services_by_strategy()
        self._assign_services_to_subnets()

        for service in self.selected_services:
            self.service_instances[service] = self._calculate_instance_count(service)

        total_pods = sum(self.service_instances.values())

        # Build subnet metadata
        subnet_info = []
        for i, host_count in enumerate(self.subnets):
            subnet_label = self.config.subnet_config.subnet_labels.get(
                i + 1, f"subnet_{i + 1}"
            )
            sensitive_prob = (
                self.config.subnet_config.sensitive_subnet_probabilities.get(i + 1, 0.0)
            )

            services_in_subnet = [
                s for s, subnets in self.service_subnet_mapping.items() if i in subnets
            ]

            subnet_info.append(
                {
                    "id": i + 1,
                    "label": subnet_label,
                    "host_count": host_count,
                    "sensitive_probability": sensitive_prob,
                    "services": services_in_subnet,
                    "num_services": len(services_in_subnet),
                }
            )

        cluster_config = {
            "cluster_metadata": {
                "num_nodes": self.num_nodes,
                "cluster_size": self.cluster_size.name,
                "use_case": self.use_case,
                "total_services": len(self.selected_services),
                "total_pods": total_pods,
                "avg_pods_per_node": f"{total_pods / self.num_nodes:.1f}",
                "num_subnets": num_subnets,
                "total_hosts": sum(self.subnets),
            },
            "services": sorted(list(self.selected_services)),
            "service_instances": {
                k: v for k, v in sorted(self.service_instances.items())
            },
            "network": {
                "subnets": subnet_info,
                "topology_matrix": self.topology_matrix,
                "address_space_bounds": self.config.subnet_config.address_space_bounds,
            },
            "service_distribution": {
                service: {
                    "instances": self.service_instances[service],
                    "subnets": self.service_subnet_mapping[service],
                }
                for service in sorted(self.selected_services)
            },
            "firewall": asdict(self.config.firewall_config),
            "osint": asdict(self.config.osint_config),
            "os_distribution": self.config.os_distribution,
        }

        return cluster_config


# def enhance_logical_generation(cluster_data: Dict) -> Dict:
#     """
#     Post-process logical cluster to ensure attack surface exists.
#     Call this after K8sClusterGenerator.generate()
#     """

#     selected_services = set(cluster_data.get("services", []))

#     # 1. Ensure Control Plane Services exist
#     # These are critical for targeting the control plane (and often missing in random generation)
#     for cp_svc in CONTROL_PLANE_SERVICES:
#         if cp_svc not in selected_services:
#             selected_services.add(cp_svc)
#             # Add metadata
#             if "service_instances" not in cluster_data:
#                 cluster_data["service_instances"] = {}
#             cluster_data["service_instances"][cp_svc] = 1

#             if "service_distribution" not in cluster_data:
#                 cluster_data["service_distribution"] = {}
#             # Assign to subnet 0 (logical), physical gen will move to Control Plane nodes via affinity
#             cluster_data["service_distribution"][cp_svc] = {
#                 "instances": 1,
#                 "subnets": [0]
#             }

#     # 2. Ensure at least one public service exists
#     has_public = any(svc in self.config_loader.get_public_services() for svc in selected_services)

#     if not has_public:
#         # Force add a common public service
#         public_entry = "nginx"
#         selected_services.add(public_entry)

#         # Add instance count
#         if "service_instances" not in cluster_data:
#             cluster_data["service_instances"] = {}
#         cluster_data["service_instances"][public_entry] = 1

#         # Assign to DMZ subnet (subnet 0)
#         if "service_distribution" not in cluster_data:
#             cluster_data["service_distribution"] = {}
#         cluster_data["service_distribution"][public_entry] = {
#             "instances": 1,
#             "subnets": [0]  # DMZ
#         }

#     # Save back the complete list
#     cluster_data["services"] = sorted(list(selected_services))

#     # 3. Mark public services in metadata
#     cluster_data["public_services"] = [
#         svc for svc in selected_services if svc in PUBLIC_SERVICES
#     ]

#     # 4. Ensure DMZ subnet exists and has public services
#     if "network" in cluster_data and "subnets" in cluster_data["network"]:
#         subnets = cluster_data["network"]["subnets"]
#         if subnets:
#             # Mark first subnet as DMZ
#             subnets[0]["label"] = "dmz"
#             subnets[0]["is_public"] = True

#             # Ensure at least one public service is in DMZ
#             dmz_services = subnets[0].get("services", [])
#             has_public_in_dmz = any(s in PUBLIC_SERVICES for s in dmz_services)

#             if not has_public_in_dmz and cluster_data["public_services"]:
#                 # Move one public service to DMZ
#                 pub_svc = cluster_data["public_services"][0]
#                 if pub_svc not in dmz_services:
#                     dmz_services.append(pub_svc)
#                     subnets[0]["services"] = dmz_services

#                     # Update service distribution
#                     if pub_svc in cluster_data["service_distribution"]:
#                         dist = cluster_data["service_distribution"][pub_svc]
#                         if 0 not in dist["subnets"]:
#                             dist["subnets"].insert(0, 0)

#     return cluster_data
