# Enhanced Kubernetes Cluster Generator - Complete Package

## ⚡ **100% BACKWARDS COMPATIBLE** ⚡

**This enhanced version is a drop-in replacement for the original generator.**

```python
# OLD CODE - Works exactly the same!
from k8s_cluster_generator_enhanced import K8sClusterGenerator, UseCase

generator = K8sClusterGenerator(num_nodes=10, use_case=UseCase.MICROSERVICES)
cluster = generator.generate()
```

**Migration: Just change the import. That's it. Everything else stays the same.**

---

## 📦 What's Included

This package provides an enhanced version of the K8s cluster generator with dynamic configuration capabilities similar to network simulation YAML configs.

### Core Files

1. **k8s_cluster_generator_enhanced.py** - Main enhanced generator with all new features
2. **example_cluster_config.yaml** - Example YAML configuration file
3. **usage_examples.py** - Comprehensive usage examples demonstrating all features
4. **TUTORIAL.py** - 5 real-world scenarios with complete implementations
5. **COMPARISON.py** - Side-by-side comparison of original vs enhanced
6. **ENHANCED_README.md** - Complete documentation
7. **QUICKSTART.sh** - Quick reference commands
8. **test_backwards_compatibility.py** - Proves 100% backwards compatibility

## 🔄 Backwards Compatibility

**The enhanced generator maintains 100% backwards compatibility with the original.**

### Original Interface (Still Works!)

```python
from k8s_cluster_generator_enhanced import K8sClusterGenerator, UseCase

# Use exactly like the original - no changes needed
generator = K8sClusterGenerator(
    num_nodes=10,
    use_case=UseCase.MICROSERVICES,
    seed=42
)

cluster = generator.generate()
# Returns same format as original generator
```

### Enhanced Interface (New Features!)

```python
from k8s_cluster_generator_enhanced import (
    EnhancedK8sClusterGenerator,
    ClusterDynamicConfig,
    SubnetConfig,
    NetworkTopologyConfig
)

# Use new features when you need them
config = ClusterDynamicConfig(
    num_nodes=20,
    use_case=UseCase.MICROSERVICES,
    subnet_config=SubnetConfig(
        subnet_ranges=[1, (2,4), (3,6)],
        subnet_labels={1: "dmz", 2: "app", 3: "db"}
    ),
    network_topology=NetworkTopologyConfig(topology_type="hub_spoke")
)

generator = EnhancedK8sClusterGenerator(config)
result = generator.generate()
# Returns enhanced format with network topology, firewall rules, etc.
```

### Verify Compatibility

```bash
# Run backwards compatibility tests
python test_backwards_compatibility.py
```

## 🚀 Quick Start

### Option 1: Original Interface (Backwards Compatible)
```python
from k8s_cluster_generator_enhanced import K8sClusterGenerator, UseCase

# Works exactly like the original!
generator = K8sClusterGenerator(
    num_nodes=10,
    use_case=UseCase.MICROSERVICES,
    seed=42
)
cluster = generator.generate()
```

### Option 2: Command Line (Original Interface)
```bash
python k8s_cluster_generator_enhanced.py \
  --nodes 20 \
  --use-case microservices \
  --output cluster.json
```

### Option 3: YAML Configuration (Enhanced)
```bash
python k8s_cluster_generator_enhanced.py \
  --config example_cluster_config.yaml \
  --output cluster.json
```

### Option 4: Enhanced Interface with Custom Topology
```python
from k8s_cluster_generator_enhanced import *

config = ClusterDynamicConfig(
    num_nodes=20,
    use_case=UseCase.MICROSERVICES,
    subnet_config=SubnetConfig(
        subnet_ranges=[1, (2,4), (3,6)],
        subnet_labels={1: "dmz", 2: "app", 3: "db"}
    ),
    network_topology=NetworkTopologyConfig(
        topology_type="hub_spoke"
    ),
    seed=42
)

generator = EnhancedK8sClusterGenerator(config)
result = generator.generate()
```

## ✨ Key New Features

### 1. Dynamic Subnet Configuration
- Define subnets with ranges: `[1, (1,4), (2,6)]`
- Label subnets for clarity
- Set sensitive data probabilities per subnet

### 2. Network Topology Options
- Predefined: mesh, star, hub_spoke, random
- Custom adjacency matrices
- Control connectivity between subnets

### 3. Service Distribution Control
- Multiple strategies: probability, required, graph_theory_random
- Service-subnet affinity mapping
- Required and excluded service lists

### 4. Firewall Rules
- Policies: _all, _none, _subnets
- Per-service exceptions
- Random blocking simulation

### 5. OSINT Visibility
- Control what attackers can discover
- Service visibility configuration
- Multiple discovery strategies

## 📚 Learning Path

1. **Start Here**: Read ENHANCED_README.md for complete documentation
2. **Quick Examples**: Run `python usage_examples.py`
3. **Real Scenarios**: Study TUTORIAL.py for practical use cases
4. **Compare**: Check COMPARISON.py to understand differences
5. **Experiment**: Modify example_cluster_config.yaml and generate

## 🎯 Use Cases

### When to Use Enhanced Generator

✅ Security research and penetration testing
✅ Network topology optimization  
✅ Compliance testing (DMZ, data tiers)
✅ Multi-tenant cluster simulation
✅ Attack graph generation
✅ Chaos engineering experiments
✅ Need YAML-based configuration
✅ Multiple scenario generation

### Real-World Scenarios Included

1. **Secure E-Commerce** - DMZ, web tier, app tier, database isolation
2. **Data Science Platform** - Ingestion, processing, storage, analytics
3. **Multi-Tenant SaaS** - Tenant isolation with shared services
4. **IoT Edge Platform** - Edge devices, queues, processing, time-series
5. **Gaming Backend** - API gateway, game servers, state management

## 📊 Output Structure

```json
{
  "cluster_metadata": {
    "num_nodes": 20,
    "num_subnets": 4,
    "total_services": 12,
    "total_pods": 48
  },
  "network": {
    "subnets": [...],
    "topology_matrix": [[0,1,1,0], ...]
  },
  "service_distribution": {
    "nginx": {
      "instances": 8,
      "subnets": [0, 1]
    }
  },
  "firewall": {...},
  "osint": {...}
}
```

## 🔧 Configuration Options

### Topology Types
- `mesh` - Fully connected
- `star` - Central hub
- `hub_spoke` - Hub with limited inter-spoke
- `random` - Probabilistic connections

### Service Strategies  
- `probability` - Use case-based probabilities
- `required` - Only specified services
- `graph_theory_random` - Random with connectivity

### Firewall Policies
- `_all` - Allow all traffic
- `_none` - Block all traffic  
- `_subnets` - Same-subnet only

## 📖 Documentation

- **ENHANCED_README.md** - Complete feature documentation
- **COMPARISON.py** - Feature comparison table
- **TUTORIAL.py** - Real-world scenario implementations
- **QUICKSTART.sh** - Quick reference commands

## 🔬 Running Examples

```bash
# Run all usage examples
python usage_examples.py

# Run real-world scenarios
python TUTORIAL.py

# View comparison
python COMPARISON.py

# Quick start guide
bash QUICKSTART.sh
```

## 💡 Tips

1. Always use `--seed` for reproducible configurations
2. Start with example_cluster_config.yaml and modify
3. Use `--verbose` to see detailed generation info
4. Generate multiple scenarios with `--count`
5. Combine with network topology generator for full attack graphs

## 🎓 Examples by Complexity

### Basic
```bash
python k8s_cluster_generator_enhanced.py --nodes 10 --use-case startup_mvp
```

### Intermediate
```bash
python k8s_cluster_generator_enhanced.py \
  --config example_cluster_config.yaml \
  --count 5 \
  --verbose
```

### Advanced
```python
# See usage_examples.py or TUTORIAL.py for complete examples
```

## 🤝 Integration

Works with:
- Original K8s cluster generator
- Network topology generator
- Vulnerability assignment system
- Attack graph tools

## 📝 License

Auto-generated for research purposes.

---

**Questions?** Check the documentation files or run with `--help`
