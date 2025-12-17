
from typing import List, Optional

from dataclasses import dataclass, field, asdict

@dataclass
class OsintConfig:
    """Configuration for OSINT (Open Source Intelligence) visibility"""
    status: str = "enabled"
    services_strategy: str = "graph_theory_random"
    visible_services: Optional[List[str]] = None
    visibility_probability: float = 0.5
    
    def __post_init__(self):
        if self.visible_services is None:
            self.visible_services = []
