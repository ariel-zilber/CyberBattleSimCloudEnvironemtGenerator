"""
Network Topology Generator
==========================
Generates the logical network layer:
- Defines connectivity between services (who talks to whom)
- Generates credential graphs (who has access to whom)
- Applies firewall rules and network segmentation
- Calculates graph metrics (reachability, attack paths)
"""

from typing import Dict
from dataclasses import  asdict

from cyberbattlesim_cloud_gen.generators.network_gen.graph_model import NetworkTopology

# ======================================================================
# Export Helpers
# ======================================================================

def topology_to_dict(topology: NetworkTopology) -> Dict:
    """Convert NetworkTopology to dictionary format"""
    return {
        "services": {name: asdict(node) for name, node in topology.services.items()},
        "knows_connectivity": [asdict(edge) for edge in topology.knows_connectivity],
        "knows_reachability": topology.knows_reachability,
        "access_connectivity": [asdict(edge) for edge in topology.access_connectivity],
        "access_reachability": topology.access_reachability,
        "credential_flow": [
            {
                **asdict(cred),
                "credential_level": cred.credential_level.name
            }
            for cred in topology.credential_flow
        ],
        "metadata": topology.metadata
    }