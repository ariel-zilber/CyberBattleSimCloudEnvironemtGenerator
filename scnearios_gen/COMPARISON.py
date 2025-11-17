"""
Comparison: Original vs Enhanced K8s Cluster Generator
=======================================================
This file shows the key differences and when to use each version.
"""

# ============================================================================
# ORIGINAL GENERATOR - Simple Use Cases
# ============================================================================

"""
The original generator is perfect for:
- Quick cluster generation
- Standard use case patterns
- Automatic service selection
- Default probability-based deployment
"""

# Example with original generator:
from_original = """
from k8s_cluster_generator import K8sClusterGenerator, UseCase

# Simple - just specify nodes and use case
generator = K8sClusterGenerator(
    num_nodes=10,
    use_case=UseCase.MICROSERVICES,
    seed=42
)

cluster = generator.generate()
# Output: Services selected based on use case probabilities
"""


# ============================================================================
# ENHANCED GENERATOR - Advanced Control
# ============================================================================

"""
The enhanced generator adds:
- Custom network topologies
- Subnet configuration with ranges
- Service-subnet affinity
- Firewall rule simulation
- OSINT visibility control
- Sensitive data placement
"""

# Example with enhanced generator:
from_enhanced = """
from k8s_cluster_generator_enhanced import (
    ClusterDynamicConfig,
    SubnetConfig,
    NetworkTopologyConfig,
    ServiceDistributionConfig,
    FirewallConfig,
    EnhancedK8sClusterGenerator,
    UseCase
)

# Advanced - full control over network and deployment
config = ClusterDynamicConfig(
    num_nodes=10,
    use_case=UseCase.MICROSERVICES,
    
    # Define subnets with ranges
    subnet_config=SubnetConfig(
        subnet_ranges=[1, (2,4), (1,3)],  # Can vary
        subnet_labels={
            1: "dmz",
            2: "application",
            3: "database"
        },
        sensitive_subnet_probabilities={
            3: 0.8  # Database tier is sensitive
        }
    ),
    
    # Choose topology
    network_topology=NetworkTopologyConfig(
        topology_type="hub_spoke"
    ),
    
    # Control service placement
    service_distribution=ServiceDistributionConfig(
        service_selection_strategy="graph_theory_random",
        required_services=["nginx", "postgresql"],
        subnet_service_affinity={
            0: ["nginx"],        # DMZ
            2: ["postgresql"]    # Database tier
        }
    ),
    
    # Firewall rules
    firewall_config=FirewallConfig(
        incoming="_subnets",  # Block cross-subnet by default
        incoming_exceptions=["nginx"]  # Except nginx
    ),
    
    seed=42
)

generator = EnhancedK8sClusterGenerator(config)
cluster = generator.generate()
"""


# ============================================================================
# FEATURE COMPARISON TABLE
# ============================================================================

comparison_table = """
┌─────────────────────────────────┬────────────────┬──────────────────┐
│ Feature                         │ Original       │ Enhanced         │
├─────────────────────────────────┼────────────────┼──────────────────┤
│ Basic cluster generation        │ ✓              │ ✓                │
│ Use case patterns               │ ✓              │ ✓                │
│ Service probability             │ ✓              │ ✓                │
│ HA instance scaling             │ ✓              │ ✓                │
│                                 │                │                  │
│ Custom network topology         │ ✗              │ ✓                │
│ Subnet configuration            │ ✗              │ ✓                │
│ Service-subnet affinity         │ ✗              │ ✓                │
│ Firewall rules                  │ ✗              │ ✓                │
│ OSINT visibility                │ ✗              │ ✓                │
│ Sensitive data placement        │ ✗              │ ✓                │
│ Multiple service strategies     │ ✗              │ ✓                │
│ YAML configuration              │ ✗              │ ✓                │
│ Custom topology matrix          │ ✗              │ ✓                │
└─────────────────────────────────┴────────────────┴──────────────────┘
"""


# ============================================================================
# WHEN TO USE WHICH?
# ============================================================================

decision_guide = """
USE ORIGINAL GENERATOR WHEN:
---------------------------
✓ You need a quick, realistic cluster
✓ Default service distribution is fine
✓ You don't need custom network topology
✓ Standard use case patterns work for you
✓ You want simplicity

Example scenarios:
- Testing cluster autoscaling
- Benchmarking pod density
- Quick demos or presentations
- Learning Kubernetes concepts


USE ENHANCED GENERATOR WHEN:
----------------------------
✓ You need specific network topology
✓ Services must be in particular subnets
✓ Simulating security scenarios
✓ Modeling firewall rules
✓ Testing attack/defense scenarios
✓ Need reproducible network configs
✓ Want YAML-based configuration
✓ Multiple scenario generation

Example scenarios:
- Security research and penetration testing
- Network topology optimization
- Compliance testing (DMZ, data tiers)
- Multi-tenant cluster simulation
- Attack graph generation
- Chaos engineering experiments
"""


# ============================================================================
# OUTPUT COMPARISON
# ============================================================================

output_comparison = """
ORIGINAL GENERATOR OUTPUT:
{
  "cluster_metadata": {
    "num_nodes": 10,
    "total_services": 12,
    "total_pods": 35
  },
  "services": ["nginx", "postgresql", "redis", ...],
  "service_instances": {
    "nginx": 4,
    "postgresql": 2
  }
}

ENHANCED GENERATOR OUTPUT:
{
  "cluster_metadata": {
    "num_nodes": 10,
    "total_services": 12,
    "total_pods": 35,
    "num_subnets": 3        ← NEW
  },
  "network": {               ← NEW
    "subnets": [
      {
        "id": 1,
        "label": "dmz",
        "host_count": 1,
        "services": ["nginx"]
      }
    ],
    "topology_matrix": [[0,1,1], [1,0,1], [1,1,0]]
  },
  "service_distribution": {  ← NEW
    "nginx": {
      "instances": 4,
      "subnets": [0]
    }
  },
  "firewall": {              ← NEW
    "incoming_policy": "_subnets",
    "incoming_exceptions": ["nginx"]
  }
}
"""


# ============================================================================
# MIGRATION PATH
# ============================================================================

migration_guide = """
MIGRATING FROM ORIGINAL TO ENHANCED:
====================================

Step 1: Import the enhanced classes
-----------------------------------
# Old:
from k8s_cluster_generator import K8sClusterGenerator, UseCase

# New:
from k8s_cluster_generator_enhanced import (
    EnhancedK8sClusterGenerator,
    ClusterDynamicConfig,
    UseCase
)

Step 2: Convert simple generator calls
--------------------------------------
# Old:
generator = K8sClusterGenerator(num_nodes=10, use_case=UseCase.MICROSERVICES)
cluster = generator.generate()

# New (minimal change):
config = ClusterDynamicConfig(num_nodes=10, use_case=UseCase.MICROSERVICES)
generator = EnhancedK8sClusterGenerator(config)
cluster = generator.generate()

Step 3: Add advanced features as needed
---------------------------------------
# Now you can add subnet config, topology, firewall rules, etc.
config = ClusterDynamicConfig(
    num_nodes=10,
    use_case=UseCase.MICROSERVICES,
    subnet_config=SubnetConfig(...),  # Optional
    network_topology=NetworkTopologyConfig(...),  # Optional
    # etc.
)
"""


# ============================================================================
# EXAMPLES
# ============================================================================

def print_all_comparisons():
    """Print all comparison information"""
    print("="*80)
    print("K8S CLUSTER GENERATOR COMPARISON")
    print("="*80)
    print()
    
    print(comparison_table)
    print()
    
    print(decision_guide)
    print()
    
    print("USAGE EXAMPLES:")
    print("="*80)
    print("\nOriginal Generator:")
    print("-"*80)
    print(from_original)
    print()
    
    print("Enhanced Generator:")
    print("-"*80)
    print(from_enhanced)
    print()
    
    print("OUTPUT COMPARISON:")
    print("="*80)
    print(output_comparison)
    print()
    
    print(migration_guide)


if __name__ == "__main__":
    print_all_comparisons()
