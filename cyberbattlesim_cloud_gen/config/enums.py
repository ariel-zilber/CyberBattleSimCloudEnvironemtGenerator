from enum import Enum


class ClusterSize(Enum):
    """Cluster size categories with node ranges"""

    TINY = (1, 3)  # Dev/testing
    SMALL = (3, 10)  # Small production/startup
    MEDIUM = (10, 50)  # Growing company
    LARGE = (50, 200)  # Enterprise
    XLARGE = (200, 1000)  # Hyperscale
