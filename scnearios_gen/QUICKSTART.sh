#!/bin/bash
# Quick Start Guide for Enhanced K8s Cluster Generator
# ======================================================

echo "Enhanced Kubernetes Cluster Generator - Quick Start"
echo "===================================================="
echo ""

# Example 1: Simple generation with CLI
echo "Example 1: Generate a 20-node microservices cluster"
echo "----------------------------------------------------"
cat << 'EOF'
python k8s_cluster_generator_enhanced.py \
  --nodes 20 \
  --use-case microservices \
  --topology-type hub_spoke \
  --service-strategy graph_theory_random \
  --seed 42 \
  --output cluster_simple.json \
  --verbose
EOF
echo ""

# Example 2: Using YAML config
echo "Example 2: Generate from YAML configuration"
echo "--------------------------------------------"
cat << 'EOF'
python k8s_cluster_generator_enhanced.py \
  --config example_cluster_config.yaml \
  --output cluster_from_yaml.json \
  --verbose
EOF
echo ""

# Example 3: Multiple scenarios
echo "Example 3: Generate 5 different scenarios"
echo "------------------------------------------"
cat << 'EOF'
python k8s_cluster_generator_enhanced.py \
  --nodes 15 \
  --use-case microservices \
  --topology-type random \
  --count 5 \
  --seed 100 \
  --output multiple_scenarios.json
EOF
echo ""

# Example 4: Run all usage examples
echo "Example 4: Run comprehensive usage examples"
echo "--------------------------------------------"
cat << 'EOF'
python usage_examples.py
EOF
echo ""

# Example 5: Custom Python script
echo "Example 5: Custom Python script"
echo "--------------------------------"
cat << 'EOF'
from k8s_cluster_generator_enhanced import *

config = ClusterDynamicConfig(
    num_nodes=25,
    use_case=UseCase.ECOMMERCE,
    subnet_config=SubnetConfig(
        subnet_ranges=[1, (2,4), (3,6), (1,3)],
        subnet_labels={
            1: "dmz",
            2: "frontend", 
            3: "backend",
            4: "database"
        },
        sensitive_subnet_probabilities={
            3: 0.5,
            4: 0.9
        }
    ),
    network_topology=NetworkTopologyConfig(
        topology_type="hub_spoke"
    ),
    firewall_config=FirewallConfig(
        incoming="_subnets",
        incoming_exceptions=["nginx", "kong"]
    ),
    seed=42
)

generator = EnhancedK8sClusterGenerator(config)
result = generator.generate()

import json
print(json.dumps(result, indent=2))
EOF
echo ""

echo "Configuration Files"
echo "-------------------"
echo "- example_cluster_config.yaml  : Full YAML configuration example"
echo "- usage_examples.py            : Comprehensive usage examples"
echo "- ENHANCED_README.md           : Complete documentation"
echo ""

echo "Key Configuration Options"
echo "-------------------------"
echo "Topology Types:"
echo "  - mesh      : Fully connected subnets"
echo "  - star      : All connect to central hub"
echo "  - hub_spoke : Hub with limited inter-spoke"
echo "  - random    : Probabilistic connections"
echo ""
echo "Service Strategies:"
echo "  - probability          : Use case-based probabilities"
echo "  - required             : Only required services"
echo "  - graph_theory_random  : Random with connectivity"
echo ""
echo "Firewall Policies:"
echo "  - _all      : Allow all traffic"
echo "  - _none     : Block all traffic"
echo "  - _subnets  : Same-subnet only"
echo ""

echo "Next Steps"
echo "----------"
echo "1. Review example_cluster_config.yaml for YAML structure"
echo "2. Run usage_examples.py to see all features"
echo "3. Read ENHANCED_README.md for detailed documentation"
echo "4. Create your own configuration and generate!"
echo ""

echo "Need Help?"
echo "----------"
echo "Run: python k8s_cluster_generator_enhanced.py --help"
echo ""
