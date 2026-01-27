"""
CyberBattleSim Attack Scenario Generator
========================================
Extends NetworkGenerator to create CyberBattleSim attack scenarios from cluster.json.
Includes comprehensive attack path analysis and visualization.

Author: Based on Microsoft CyberBattleSim
Date: 2025-11-09
"""

import sys
import matplotlib

IS_DEBUG = False
# Use non-interactive backend for saving files
matplotlib.use("Agg")

# --- External Dependencies ---
try:
    from cyberbattle.simulation.nodes import NodeInfo
    from cyberbattle.simulation.firewall import (
        FirewallRule,
        RulePermission,
        FirewallConfiguration,
    )
    from cyberbattle.simulation.vulenrabilites import (
        VulnerabilityInfo,
        VulnerabilityType,
        LeakedNodesId,
        LeakedCredentials,
        CachedCredential,
        PrivilegeEscalation,
        AdminEscalation,
        SystemEscalation,
        CustomerData,
        LateralMove,
        PrivilegeLevel,
    )
    from cyberbattle.simulation.nodes_types import NodeID
    from cyberbattle.simulation.services import ListeningService
    from cyberbattle.simulation.network import (
        NodeNetworkInfo,
        Subnet,
        NetworkInterfaces,
    )
    from cyberbattle.simulation.identifiers import Identifiers
    from cyberbattle.simulation.nodes_network import infer_constants_from_nodes

    from cyberbattlesim_network_gen.generators.network_generator import NetworkGenerator
    from cyberbattlesim_network_gen.generators.file_utils import save_yaml
    from cyberbattlesim_network_gen.generators.utils import cli_default
except ImportError as e:
    raise ImportError(f"Missing required CyberBattleSim dependencies: {e}")

# Set a higher recursion depth limit for deep searches
sys.setrecursionlimit(25000)


class SearchTimeoutError(Exception):
    """Raised when the search time limit is exceeded."""

    pass


class SearchStateLimitError(Exception):
    """Raised when the visited state limit is exceeded."""

    pass
