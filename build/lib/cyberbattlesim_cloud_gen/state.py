import time
from typing import List, Dict, Any

from cyberbattlesim_cloud_gen.generators.physical_gen.physical_node import PhysicalNode
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

class PhysicalClusterState:
    """
    The Single Source of Truth.
    Aggregates all models from the core sub-modules.
    """
    num_nodes:int
    cluster_size:int
    zone_distribution:str
    use_case:str
    services: any
    service_instances:any
    seed:int
    nodes: List[PhysicalNode] = []
    node_connections: List[NodeConnection] = []
    security_groups: Dict[str, SecurityGroup] = {}
    network_access_graph: List[NetworkAccessGraph] = []

    # IP allocation tracking
    zone_subnets: Dict[str, ipaddress.IPv4Network] = {}
    zone_ip_allocations: Dict[str, Set[str]] = {}
