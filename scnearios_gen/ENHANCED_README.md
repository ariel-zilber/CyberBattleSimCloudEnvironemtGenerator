# Enhanced Kubernetes Cluster Generator with Dynamic Configuration

## Overview

This enhanced version of the K8s cluster generator adds dynamic configuration capabilities similar to network simulation YAML configs. It allows fine-grained control over:

- **Network topology** between subnets
- **Service distribution** across subnets
- **Firewall rules** and policies
- **OSINT visibility** (what attackers can discover)
- **Subnet configuration** with ranges and labels
- **OS distribution** across nodes

## Key Features

### 1. Dynamic Subnet Configuration

Define subnets with either fixed host counts or ranges:

```yaml
# Mix of fixed and range specifications
subnets: [1, 1-4, 1-4, 1-6, 2-9]

# Address space bounds
address_space_bounds: [10, 10]  # (max_subnets, max_hosts_per_subnet)

# Label your subnets
subnet_labels:
  1: dmz
  2: web_tier
  3: application_tier
  4: data_tier
```

### 2. Network Topology Options

Choose from predefined topologies or specify custom ones:

```python
# Option 1: Predefined topology types
topology_type: "hub_spoke"  # mesh, star, hub_spoke, random

# Option 2: Custom adjacency matrix
topology: [
  [0, 1, 1, 0, 0],
  [1, 0, 1, 1, 0],
  [1, 1, 0, 1, 1],
  [0, 1, 1, 0, 0],
  [0, 0, 1, 0, 0],
]
```

**Topology Types:**
- `mesh` - Fully connected subnets
- `star` - All subnets connect to subnet 0
- `hub_spoke` - Hub with limited inter-spoke connectivity
- `random` - Randomly connected based on probability

### 3. Service Distribution Strategies

Control how services are selected and distributed:

```yaml
service_distribution:
  strategy: graph_theory_random  # probability, required, graph_theory_random
  
  required_services:
    - nginx
    - postgresql
    - redis
  
  excluded_services:
    - wordpress
  
  # Define which services prefer which subnets
  subnet_affinity:
    0:  # DMZ
      - nginx
      - kong
    3:  # Data tier
      - postgresql
      - mongodb
```

**Strategies:**
- `probability` - Use service probabilities from use case
- `required` - Only deploy required services
- `graph_theory_random` - Random selection with connectivity awareness

### 4. Firewall Configuration

Define firewall policies and exceptions:

```yaml
firewall:
  incoming: _subnets  # _all, _none, _subnets
  incoming_exceptions:
    - nginx      # Can receive from anywhere
    - grafana
  outgoing: _all
  outgoing_exceptions: []
  default_block_probability: 0.2  # Random blocking rate
```

**Policies:**
- `_all` - Allow all traffic
- `_none` - Block all traffic
- `_subnets` - Only allow within same subnet

### 5. OSINT (Visibility) Configuration

Simulate what external attackers can discover:

```yaml
osint:
  status: enabled
  services:
    strategy: graph_theory_random
    values:  # Explicitly visible services
      - nginx
      - grafana
  visibility_probability: 0.3
```

### 6. Sensitive Data Configuration

Specify probability of sensitive hosts per subnet:

```yaml
sensitive_hosts:
  1: 0.0   # DMZ - no sensitive data
  2: 0.3   # Application tier
  3: 0.8   # Data tier - highly sensitive
  4: 0.5   # Management tier
```

## Usage

### Method 1: YAML Configuration File

Create a YAML config file (see `example_cluster_config.yaml`):

```bash
python k8s_cluster_generator_enhanced.py --config my_config.yaml --output result.json
```

### Method 2: Command Line Arguments

```bash
python k8s_cluster_generator_enhanced.py \
  --nodes 20 \
  --use-case microservices \
  --topology-type hub_spoke \
  --service-strategy graph_theory_random \
  --seed 42 \
  --output cluster.json
```

### Method 3: Programmatic (Python)

```python
from k8s_cluster_generator_enhanced import (
    ClusterDynamicConfig,
    SubnetConfig,
    NetworkTopologyConfig,
    ServiceDistributionConfig,
    FirewallConfig,
    EnhancedK8sClusterGenerator,
    UseCase
)

# Create configuration
config = ClusterDynamicConfig(
    num_nodes=20,
    use_case=UseCase.MICROSERVICES,
    subnet_config=SubnetConfig(
        subnet_ranges=[1, (2, 4), (2, 5), (1, 3)],
        address_space_bounds=(10, 10),
        subnet_labels={
            1: "dmz",
            2: "frontend",
            3: "backend",
            4: "database"
        }
    ),
    network_topology=NetworkTopologyConfig(
        topology_type="hub_spoke"
    ),
    service_distribution=ServiceDistributionConfig(
        service_selection_strategy="graph_theory_random",
        required_services=["nginx", "postgresql", "redis"]
    ),
    seed=42
)

# Generate cluster
generator = EnhancedK8sClusterGenerator(config)
cluster = generator.generate()
```

## Output Format

The generator produces a comprehensive JSON structure:

```json
{
  "cluster_metadata": {
    "num_nodes": 20,
    "cluster_size": "MEDIUM",
    "use_case": "microservices",
    "total_services": 12,
    "total_pods": 48,
    "num_subnets": 4
  },
  "services": ["nginx", "postgresql", "redis", ...],
  "service_instances": {
    "nginx": 8,
    "postgresql": 6,
    "redis": 4
  },
  "network": {
    "subnets": [
      {
        "id": 1,
        "label": "dmz",
        "host_count": 1,
        "services": ["nginx"],
        "num_services": 1
      },
      ...
    ],
    "topology_matrix": [[0,1,1,0], [1,0,1,1], ...],
    "address_space_bounds": [10, 10]
  },
  "service_distribution": {
    "nginx": {
      "instances": 8,
      "subnets": [0, 1]
    },
    ...
  },
  "firewall": {
    "incoming_policy": "_subnets",
    "incoming_exceptions": ["nginx"],
    ...
  },
  "osint": {
    "status": "enabled",
    "strategy": "graph_theory_random",
    ...
  }
}
```

## Examples

### Example 1: E-commerce Platform

```python
config = ClusterDynamicConfig(
    num_nodes=30,
    use_case=UseCase.ECOMMERCE,
    subnet_config=SubnetConfig(
        subnet_ranges=[(2,4), (3,6), (2,5), (1,3)],
        subnet_labels={
            1: "frontend",
            2: "api_gateway", 
            3: "backend_services",
            4: "databases"
        }
    ),
    network_topology=NetworkTopologyConfig(
        topology_type="hub_spoke"  # API gateway as hub
    ),
    firewall_config=FirewallConfig(
        incoming="_subnets",
        incoming_exceptions=["nginx", "kong"],  # Public-facing
        default_block_probability=0.3
    )
)
```

### Example 2: Data Analytics Platform

```python
config = ClusterDynamicConfig(
    num_nodes=50,
    use_case=UseCase.DATA_ANALYTICS,
    subnet_config=SubnetConfig(
        subnet_ranges=[2, (4,8), (6,10), (2,4)],
        subnet_labels={
            1: "edge_ingestion",
            2: "processing_cluster",
            3: "storage_tier",
            4: "analytics_compute"
        }
    ),
    service_distribution=ServiceDistributionConfig(
        required_services=["kafka", "spark", "clickhouse", "minio"],
        subnet_service_affinity={
            0: ["kafka"],  # Ingestion
            1: ["spark", "flink"],  # Processing
            2: ["minio", "clickhouse"],  # Storage
            3: ["jupyterhub", "mlflow"]  # Analytics
        }
    )
)
```

### Example 3: Multi-Scenario Generation

Generate multiple variations for testing:

```bash
python k8s_cluster_generator_enhanced.py \
  --config base_config.yaml \
  --count 10 \
  --output scenarios.json \
  --verbose
```

## Integration with Existing Generator

The enhanced generator extends the original `K8sClusterGenerator`. To use both:

1. Keep original generator for simple use cases
2. Use enhanced generator when you need:
   - Custom network topologies
   - Specific service-subnet placement
   - Firewall rule simulation
   - Multiple scenario generation

## Advanced Features

### Generating Attack Scenarios

Combine with network topology generator:

```bash
python k8s_cluster_generator_enhanced.py \
  --config attack_scenario.yaml \
  --generate-topology \
  --firewall-probability 0.3 \
  --knowledge-completeness 0.7 \
  --cve-json vulnerabilities.json \
  --vuln-db vuln_db.yml
```

### Reproducibility

Always use `--seed` for reproducible configurations:

```bash
# Same seed = identical output
python k8s_cluster_generator_enhanced.py \
  --nodes 20 --use-case microservices --seed 42
```

### Batch Generation

Generate multiple configurations with different seeds:

```bash
for i in {1..10}; do
  python k8s_cluster_generator_enhanced.py \
    --config base.yaml \
    --seed $i \
    --output "scenario_${i}.json"
done
```

## Configuration Reference

### Complete YAML Template

```yaml
# Basic parameters
num_nodes: 15
use_case: microservices
seed: 42

# Network
subnets: [1, 1-4, 2-5, 1-3]
address_space_bounds: [10, 10]
topology_type: hub_spoke
subnet_labels:
  1: subnet_name_1
  2: subnet_name_2

# Security
sensitive_hosts:
  1: 0.0
  2: 0.5

firewall:
  incoming: _subnets
  incoming_exceptions: [nginx]
  outgoing: _all

# Services
services: [nginx, postgresql, redis]
excluded_services: [wordpress]

service_distribution:
  strategy: graph_theory_random
  subnet_affinity:
    0: [nginx]
    3: [postgresql]

# OSINT
osint:
  status: enabled
  services:
    strategy: random
    values: [nginx]
```

## Troubleshooting

**Issue:** Services not appearing in expected subnets
- Check `subnet_service_affinity` configuration
- Verify subnet indices (0-indexed in code, 1-indexed in YAML labels)

**Issue:** Too many/few services selected
- Adjust `service_selection_strategy`
- Use `required_services` for must-have services
- Use `excluded_services` to prevent certain services

**Issue:** Invalid topology matrix
- Ensure matrix is square (N×N for N subnets)
- Matrix should be symmetric for undirected graphs
- Use 0 for no connection, 1 for connection

## Performance Notes

- Large clusters (>100 nodes) may take a few seconds
- Custom topology matrices are faster than random generation
- Service-subnet affinity reduces computation time

## Future Enhancements

- [ ] Support for weighted topology edges (bandwidth/latency)
- [ ] Multi-region cluster support
- [ ] Cost estimation based on service deployment
- [ ] Automatic vulnerability injection
- [ ] Export to Kubernetes YAML manifests
- [ ] Visualization of network topology
- [ ] Integration with chaos engineering tools

## Contributing

To extend the generator:

1. Add new `ServiceProfile` entries to catalog
2. Add new topology types to `NetworkTopologyConfig.generate_topology()`
3. Add new selection strategies to `_select_services_by_strategy()`
4. Update YAML schema for new configuration options

## License

Same as original generator - Auto-generated for research purposes.
