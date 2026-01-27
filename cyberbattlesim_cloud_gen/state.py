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

