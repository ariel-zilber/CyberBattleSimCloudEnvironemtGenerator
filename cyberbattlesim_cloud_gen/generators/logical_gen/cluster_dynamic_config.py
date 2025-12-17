from dataclasses import dataclass
from typing import Optional

from cyberbattlesim_cloud_gen.generators.logical_gen.subnet_config import SubnetConfig
from cyberbattlesim_cloud_gen.generators.logical_gen.network_topology_config import (
    NetworkTopologyConfig,
)
from cyberbattlesim_cloud_gen.generators.logical_gen.service_distribution_config import (
    ServiceDistributionConfig,
)
from cyberbattlesim_cloud_gen.generators.logical_gen.firewall_config import (
    FirewallConfig,
)
from cyberbattlesim_cloud_gen.generators.logical_gen.osint_config import OsintConfig
from typing import Dict


@dataclass
class ClusterDynamicConfig:
    """Complete dynamic configuration for cluster generation"""

    num_nodes: int
    use_case: str

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
                subnet_ranges=[1, (1, 4), (1, 4), (1, 6)], address_space_bounds=(10, 10)
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
