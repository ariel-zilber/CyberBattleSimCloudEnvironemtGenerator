
from enum import Enum
from cyberbattlesim_network_gen.network_generators.cloud.k8s_cluster_generator.k8s_service_catalog import SERVICE_CATALOG
from cyberbattlesim_network_gen.network_generators.cloud.k8s_cluster_generator.usae_case import UseCase
from cyberbattlesim_network_gen.network_generators.cloud.k8s_cluster_generator.cluster_size import ClusterSize
from cyberbattlesim_network_gen.network_generators.cloud.k8s_cluster_generator.service_profile import ServiceProfile
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import random
import json


class K8sClusterGenerator:
    """Generate realistic Kubernetes cluster configurations"""
    
    def __init__(self, num_nodes: int, use_case: UseCase, seed: int = None):
        self.num_nodes = num_nodes
        self.use_case = use_case
        self.cluster_size = self._determine_cluster_size(num_nodes)
        self.selected_services: Set[str] = set()
        self.service_instances: Dict[str, int] = {}  # Track instance counts
        self.total_resource_weight = 0
        
        if seed is not None:
            random.seed(seed)
    
    @staticmethod
    def _determine_cluster_size(num_nodes: int) -> ClusterSize:
        """Determine cluster size category from node count"""
        for size in ClusterSize:
            min_nodes, max_nodes = size.value
            if min_nodes <= num_nodes <= max_nodes:
                return size
        return ClusterSize.XLARGE
    
    def _calculate_instance_count(self, service_name: str, profile: ServiceProfile) -> int:
        """Calculate the number of instances for a service based on cluster size and HA requirements"""
        base_count = profile.base_instance_count
        
        # If service doesn't scale with cluster, return base count
        if not profile.scale_with_cluster:
            # But apply HA rules if required
            if profile.requires_ha and base_count < 2:
                return 2  # Minimum 2 for HA
            return base_count
        
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
        
        # Apply HA constraints
        if profile.requires_ha:
            # Ensure odd number for quorum-based systems (etcd, zookeeper, etc.)
            if service_name in ["etcd", "zookeeper", "consul"]:
                if instances % 2 == 0:
                    instances += 1
                # Cap at reasonable limits
                instances = min(instances, 7)
            else:
                # For other HA services, ensure at least 2
                instances = max(instances, 2)
                # Cap at reasonable limits
                instances = min(instances, 10)
        
        return instances
    
    def _can_add_service(self, service_name: str, profile: ServiceProfile) -> bool:
        """Check if a service can be added based on constraints"""
        # Check cluster size requirement
        required_min = profile.min_cluster_size.value[0]
        if self.num_nodes < required_min:
            return False
        
        # Check conflicts
        for conflict in profile.conflicts_with:
            if conflict in self.selected_services:
                return False
        
        # Check if we have capacity (rough heuristic)
        estimated_weight = self.total_resource_weight + profile.resource_weight
        max_capacity = self.num_nodes * 10  # Assume ~10 weight units per node
        if estimated_weight > max_capacity:
            return False
        
        return True
    
    def _add_service_with_dependencies(self, service_name: str):
        """Add a service and all its dependencies"""
        if service_name in self.selected_services:
            return
        
        if service_name not in SERVICE_CATALOG:
            return
        
        profile = SERVICE_CATALOG[service_name]
        
        # First add dependencies
        for dep in profile.dependencies:
            self._add_service_with_dependencies(dep)
        
        # Then add the service itself
        if self._can_add_service(service_name, profile):
            self.selected_services.add(service_name)
            # Calculate and store instance count
            instance_count = self._calculate_instance_count(service_name, profile)
            self.service_instances[service_name] = instance_count
            # Multiply resource weight by instance count
            self.total_resource_weight += profile.resource_weight * instance_count
    
    def generate(self) -> Dict:
        """Generate a realistic cluster configuration"""
        # Phase 1: Add services based on probability
        for service_name, profile in SERVICE_CATALOG.items():
            probability = profile.probability_by_use_case.get(self.use_case.value, 0)
            
            # Roll the dice
            if random.random() < probability:
                self._add_service_with_dependencies(service_name)
        
        # Calculate total pods
        total_pods = sum(self.service_instances.values())
        
        # Phase 2: Generate cluster metadata
        cluster_config = {
            "cluster_metadata": {
                "num_nodes": self.num_nodes,
                "cluster_size": self.cluster_size.name,
                "use_case": self.use_case.value,
                "total_services": len(self.selected_services),
                "total_pods": total_pods,
                "avg_pods_per_node": f"{total_pods / self.num_nodes:.1f}",
                "total_resource_weight": self.total_resource_weight,
                "resource_utilization": f"{(self.total_resource_weight / (self.num_nodes * 10)) * 100:.1f}%"
            },
            "services": sorted(list(self.selected_services)),
            "service_instances": {k: v for k, v in sorted(self.service_instances.items())},
            "services_by_category": self._group_by_category(),
            "deployment_stats": self._generate_stats()
        }
        
        return cluster_config
    
    def _group_by_category(self) -> Dict[str, List[str]]:
        """Group selected services by category"""
        by_category = {}
        for service_name in self.selected_services:
            if service_name in SERVICE_CATALOG:
                category = SERVICE_CATALOG[service_name].category
                if category not in by_category:
                    by_category[category] = []
                by_category[category].append(service_name)
        
        return {k: sorted(v) for k, v in sorted(by_category.items())}
    
    def _generate_stats(self) -> Dict:
        """Generate deployment statistics"""
        has_monitoring = bool({"prometheus", "grafana"} & self.selected_services)
        has_logging = bool({"grafana-loki", "elasticsearch", "fluent-bit"} & self.selected_services)
        has_tracing = bool({"jaeger", "grafana-tempo", "zipkin"} & self.selected_services)
        has_gitops = bool({"argo-cd", "flux"} & self.selected_services)
        has_service_mesh = bool({"cilium"} & self.selected_services)
        
        return {
            "observability_stack": {
                "metrics": has_monitoring,
                "logging": has_logging,
                "tracing": has_tracing,
                "completeness_score": sum([has_monitoring, has_logging, has_tracing]) / 3
            },
            "automation": {
                "gitops_enabled": has_gitops,
                "service_mesh": has_service_mesh
            },
            "data_layer": {
                "sql_databases": len([s for s in self.selected_services if s in ["postgresql", "mysql", "mariadb"]]),
                "nosql_databases": len([s for s in self.selected_services if SERVICE_CATALOG.get(s, None) and "nosql" in SERVICE_CATALOG[s].category]),
                "caching": "redis" in self.selected_services or "valkey" in self.selected_services,
                "messaging": "kafka" in self.selected_services or "rabbitmq" in self.selected_services
            }
        }
