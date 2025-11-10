# 🚀 Physical Nodes Extension - Quick Reference Card

## Installation
```bash
# Ensure both files are in the same directory
ls physical_nodes_extension.py k8s_cluster_generator.py
```

## Basic Usage

### Import
```python
from k8s_cluster_generator import K8sClusterGenerator, UseCase
from physical_nodes_extension import extend_with_physical_nodes
```

### Generate Extended Cluster
```python
# Create base cluster
generator = K8sClusterGenerator(num_nodes=20, use_case=UseCase.MICROSERVICES, seed=42)
cluster = generator.generate()

# Extend with physical nodes
extended = extend_with_physical_nodes(cluster, seed=42)
```

## Key Functions

### Print Summary
```python
from physical_nodes_extension import print_cluster_summary
print_cluster_summary(extended)
```

### Export Graph
```python
from physical_nodes_extension import export_node_graph_to_graphviz
export_node_graph_to_graphviz(extended, "topology.dot")
```

### Render Graph
```bash
dot -Tpng topology.dot -o topology.png
```

## Data Access

### Physical Nodes
```python
for node in extended["physical_nodes"]:
    print(f"{node['node_id']}: {node['cpu_utilization_pct']}% CPU")
```

### Pod Placements
```python
for placement in extended["pod_placements"]:
    print(f"{placement['pod_id']} on {placement['node_id']}")
```

### Network Topology
```python
topology = extended["node_topology"]
print(f"Nodes: {topology['topology_stats']['total_nodes']}")
print(f"Edges: {topology['topology_stats']['total_edges']}")
```

### Resource Utilization
```python
util = extended["node_utilization"]
print(f"CPU: {util['utilization_pct']['cpu']}%")
print(f"Memory: {util['utilization_pct']['memory']}%")
```

## Node Types

| Type | CPU | Memory | Storage | Use Case |
|------|-----|--------|---------|----------|
| control_plane | 4 | 16 GB | 100 GB | Control components |
| worker_general | 8 | 32 GB | 200 GB | General workloads |
| worker_compute | 32 | 64 GB | 200 GB | CPU-intensive |
| worker_memory | 16 | 256 GB | 500 GB | Memory-intensive |
| worker_storage | 8 | 64 GB | 2 TB | Storage-heavy |
| worker_gpu | 16 | 128 GB | 500 GB | ML/AI (4 GPUs) |
| edge | 4 | 8 GB | 50 GB | Edge/IoT |

## Use Cases

- `startup_mvp` - Small setup
- `microservices` - Service architecture
- `data_analytics` - Data processing
- `ml_platform` - Machine learning
- `web_hosting` - Web applications
- `enterprise_internal` - Enterprise apps
- `ecommerce` - E-commerce platform
- `saas_platform` - SaaS infrastructure
- `iot_platform` - IoT/edge computing
- `gaming_backend` - Gaming servers

## Common Analyses

### Find Overutilized Nodes
```python
overutilized = [n for n in extended["physical_nodes"] 
                if n["cpu_utilization_pct"] > 80]
print(f"Overutilized: {len(overutilized)}")
```

### Check High Availability
```python
zones = extended["node_topology"]["topology_stats"]["zones"]
print("✅ Multi-AZ" if zones >= 3 else "⚠️ Single/Dual AZ")
```

### Calculate Total Cost
```python
from physical_nodes_extension import NODE_SPECS, NodeType

total_cost = sum(
    NODE_SPECS[NodeType(n["node_type"])].cost_per_hour 
    for n in extended["physical_nodes"]
)
print(f"Hourly: ${total_cost:.2f}")
```

### Service Distribution
```python
from collections import defaultdict

service_nodes = defaultdict(list)
for p in extended["pod_placements"]:
    service_nodes[p["service_name"]].append(p["node_id"])

for svc, nodes in service_nodes.items():
    print(f"{svc}: {len(nodes)} pods")
```

## Output Files

### Run Demo
```bash
python3 demo_physical_nodes.py
```

### Generated Files
- `extended_cluster_demo.json` - Full configuration
- `node_topology_demo.dot` - Network graph

### Export Custom
```python
import json

# Save JSON
with open("my_cluster.json", 'w') as f:
    json.dump(extended, f, indent=2)

# Export graph
export_node_graph_to_graphviz(extended, "my_topology.dot")
```

## Troubleshooting

### Import Error
```python
# Ensure files are in same directory
import sys
sys.path.append('/path/to/directory')
```

### Unplaced Pods
```python
unplaced = extended["cluster_metadata"]["unplaced_pods"]
if unplaced > 0:
    print(f"⚠️ {unplaced} pods couldn't be placed")
    print("Solution: Add more nodes or check resources")
```

### Over-Utilized Storage
```python
util = extended["node_utilization"]["utilization_pct"]["storage"]
if util > 100:
    print("⚠️ Storage over-allocated")
    print("Solution: Add storage-optimized nodes")
```

## Performance Tips

- Use same seed for reproducibility
- Cache generated clusters
- Batch process for multiple scenarios
- Profile for large clusters (200+ nodes)

## Examples

### Different Cluster Sizes
```python
for size in [10, 20, 50, 100]:
    gen = K8sClusterGenerator(size, UseCase.MICROSERVICES, 42)
    ext = extend_with_physical_nodes(gen.generate(), 42)
    print(f"{size} nodes: {len(ext['physical_nodes'])} physical nodes")
```

### Different Use Cases
```python
use_cases = [UseCase.STARTUP_MVP, UseCase.ML_PLATFORM, UseCase.ECOMMERCE]
for uc in use_cases:
    gen = K8sClusterGenerator(20, uc, 42)
    ext = extend_with_physical_nodes(gen.generate(), 42)
    print(f"{uc.value}: {ext['cluster_metadata']['total_services']} services")
```

### Simulation
```python
# Test zone failure
zone_to_fail = "zone-a"
surviving = [p for p in extended["pod_placements"]
             if all(n["zone"] != zone_to_fail 
                    for n in extended["physical_nodes"] 
                    if n["node_id"] == p["node_id"])]
print(f"After failure: {len(surviving)} pods survive")
```

## Documentation

- **DELIVERY_SUMMARY.md** - Complete delivery overview
- **PHYSICAL_NODES_DOCUMENTATION.md** - Full technical docs
- **README_PHYSICAL_NODES.md** - User guide & architecture
- **demo_physical_nodes.py** - Working example

## Support

- Check documentation for detailed explanations
- Run demo for working examples
- Examine sample outputs for data structure
- Modify source code for customization

---

**Quick Start**: Run `python3 demo_physical_nodes.py` to see everything in action!

**Visualization**: `dot -Tpng node_topology_demo.dot -o topology.png`

**Full Docs**: See PHYSICAL_NODES_DOCUMENTATION.md
