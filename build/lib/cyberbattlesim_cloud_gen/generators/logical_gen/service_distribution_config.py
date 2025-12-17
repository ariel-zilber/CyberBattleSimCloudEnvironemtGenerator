from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional

from cyberbattlesim_cloud_gen.config.config_loader import ConfigLoader


@dataclass
class ServiceDistributionConfig:
    """Enhanced to track public exposure"""
    service_selection_strategy: str = "probability"
    service_probabilities: Dict[str, float] = field(default_factory=dict)
    required_services: List[str] = field(default_factory=list)
    excluded_services: List[str] = field(default_factory=list)
    subnet_service_affinity: Dict[int, List[str]] = field(default_factory=dict)
    
    # NEW: Force at least one public service
    require_public_entry: bool = True
    public_services: Set[str] = field(default_factory=set)
    
    # NEW: DMZ subnet configuration
    dmz_subnet_id: int = 0  # Subnet 0 is DMZ by default
    
    def __post_init__(self):
        """Initialize public_services from ConfigLoader if not provided."""
        if not self.public_services:
            config_loader = ConfigLoader.get_instance()
            self.public_services = config_loader.get_public_services().copy()