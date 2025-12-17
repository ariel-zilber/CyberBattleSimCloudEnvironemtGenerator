
import random
import json
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from cyberbattlesim_network_gen.network_generators.cloud.k8s_cluster_generator.cluster_size import ClusterSize


@dataclass
class ServiceProfile:
    """Metadata about a service"""
    name: str
    category: str
    resource_weight: int  # 1-10, relative resource consumption
    requires_ha: bool  # Needs HA setup in prod
    dependencies: List[str]
    conflicts_with: List[str]
    probability_by_use_case: Dict[str, float]
    min_cluster_size: ClusterSize
    base_instance_count: int = 1  # Base number of instances for small clusters
    scale_with_cluster: bool = False  # Whether to scale instances with cluster size
