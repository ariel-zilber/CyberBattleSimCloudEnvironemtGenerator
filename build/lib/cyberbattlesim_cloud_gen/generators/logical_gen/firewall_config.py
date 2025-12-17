
import random
from typing import List, Dict, Set, Tuple, Optional, Union
from dataclasses import dataclass, field, asdict

@dataclass
class FirewallConfig:
    """Configuration for firewall rules"""
    incoming: str = "_subnets"  # _all, _none, _subnets
    incoming_exceptions: List[str] = field(default_factory=list)
    outgoing: str = "_all"  # _all, _none, _subnets
    outgoing_exceptions: List[str] = field(default_factory=list)
    default_block_probability: float = 0.2
