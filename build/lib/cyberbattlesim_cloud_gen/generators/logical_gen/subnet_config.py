from dataclasses import dataclass
from typing import List, Tuple, Union, Optional, Dict


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
