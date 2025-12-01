# Integration Guide

## How to Use the Extended Generator

### Quick Start

```python
from k8s_cluster_generator_extended import K8sClusterGenerator, UseCase

# Create generator
generator = K8sClusterGenerator(
    num_nodes=50,
    use_case=UseCase.MICROSERVICES,
    seed=42  # For reproducibility
)

# Generate complete cluster with physical nodes
cluster = generator.generate()

# Access different parts
services = cluster['services']
nodes = cluster['physical_nodes']
placements = cluster['pod_placements']
topology = cluster['node_topology']
```

### Accessing Physical Nodes

```python
# Iterate through nodes
for node in cluster['physical_nodes']:
    print(f"{node['node_id']}: {node['pod_count']} pods, "
          f"CPU util: {node['cpu_utilization_pct']}%")

# Find high-utilization nodes
overloaded = [n for n in cluster['physical_nodes'] 
              if n['cpu_utilization_pct'] > 80]

# Group by zone
from collections import defaultdict
by_zone = defaultdict(list)
for node in cluster['physical_nodes']:
    by_zone[node['zone']].append(node)
```

### Working with Pod Placements

```python
# Find where a service is running
prometheus_pods = [p for p in cluster['pod_placements'] 
                   if p['service_name'] == 'prometheus']

# Check placement distribution
from collections import Counter
placement_dist = Counter(p['node_id'] for p in cluster['pod_placements'])
print(f"Most loaded node: {placement_dist.most_common(1)}")

# Verify HA services are spread
def check_ha_spread(service_name, placements, nodes):
    service_pods = [p for p in placements if p['service_name'] == service_name]
    zones = set()
    for pod in service_pods:
        node = next(n for n in nodes if n['node_id'] == pod['node_id'])
        zones.add(node['zone'])
    return len(zones) > 1  # True if spread across zones

is_ha = check_ha_spread('postgresql', cluster['pod_placements'], 
                        cluster['physical_nodes'])
```

### Analyzing Network Topology

```python
# Get topology graph
topology = cluster['node_topology']

# Count connections per node
node_degrees = {}
for edge in topology['edges']:
    node_degrees[edge['source']] = node_degrees.get(edge['source'], 0) + 1
    node_degrees[edge['target']] = node_degrees.get(edge['target'], 0) + 1

# Find critical nodes (high degree)
critical_nodes = sorted(node_degrees.items(), key=lambda x: x[1], reverse=True)[:5]

# Calculate average latency
latencies = [e['latency_ms'] for e in topology['edges']]
avg_latency = sum(latencies) / len(latencies)

# Find cross-zone connections
cross_zone = [e for e in topology['edges'] if e['edge_type'] == 'inter_zone']
print(f"Cross-zone links: {len(cross_zone)}/{len(topology['edges'])}")
```

### Resource Utilization Analysis

```python
util = cluster['node_utilization']

# Overall cluster utilization
print(f"Cluster CPU utilization: {util['utilization_pct']['cpu']}%")
print(f"Cluster Memory utilization: {util['utilization_pct']['memory']}%")

# Capacity planning
total_capacity = util['total_capacity']
total_allocated = util['total_allocated']
remaining = {
    'cpu': total_capacity['cpu_cores'] - total_allocated['cpu_cores'],
    'memory': total_capacity['memory_gb'] - total_allocated['memory_gb']
}
print(f"Remaining capacity: {remaining['cpu']} CPU, {remaining['memory']}GB RAM")

# Check if we can fit more services
new_service_needs = {'cpu': 10, 'memory': 20}
can_fit = (remaining['cpu'] >= new_service_needs['cpu'] and 
           remaining['memory'] >= new_service_needs['memory'])
```

### Custom Node Type Selection

```python
# If you want to customize node generation before placing services
from k8s_cluster_generator_extended import PhysicalNodeGenerator, NodeType

# Create custom node distribution
node_gen = PhysicalNodeGenerator(num_nodes=50, cluster_size=ClusterSize.MEDIUM, 
                                   use_case=UseCase.CUSTOM, seed=42)

# Manually specify distribution
custom_dist = {
    NodeType.CONTROL_PLANE: 3,
    NodeType.WORKER_GPU: 10,      # More GPU nodes
    NodeType.WORKER_MEMORY: 20,    # Lots of memory
    NodeType.WORKER_GENERAL: 17
}

# Generate with custom distribution
# (You'd need to modify the generator to accept custom distributions)
```

### Exporting for Visualization

```python
import json

# Export topology for graph visualization tools
with open('topology.json', 'w') as f:
    json.dump(cluster['node_topology'], f, indent=2)

# Export for Kubernetes manifest generation
manifests = {
    'nodes': cluster['physical_nodes'],
    'deployments': {}
}

# Group pods by service
from collections import defaultdict
by_service = defaultdict(list)
for placement in cluster['pod_placements']:
    by_service[placement['service_name']].append(placement)

for service, pods in by_service.items():
    manifests['deployments'][service] = {
        'replicas': len(pods),
        'resource_requests': {
            'cpu': pods[0]['cpu_request'],
            'memory': f"{pods[0]['memory_request']}Gi"
        },
        'node_selector': {}  # Add based on preferred_node_types
    }

with open('k8s_manifests.json', 'w') as f:
    json.dump(manifests, f, indent=2)
```

### Integration with Attack Graph Generator

```python
# If you have an attack graph generator that needs node topology

# Convert to attack graph format
def cluster_to_attack_graph(cluster):
    attack_graph = {
        'nodes': [],
        'edges': []
    }
    
    # Add physical nodes as attack graph nodes
    for node in cluster['physical_nodes']:
        attack_graph['nodes'].append({
            'id': node['node_id'],
            'type': 'physical_node',
            'properties': {
                'node_type': node['node_type'],
                'zone': node['zone'],
                'services': []
            }
        })
    
    # Add services running on each node
    for placement in cluster['pod_placements']:
        node_idx = next(i for i, n in enumerate(attack_graph['nodes']) 
                       if n['id'] == placement['node_id'])
        attack_graph['nodes'][node_idx]['properties']['services'].append({
            'name': placement['service_name'],
            'pod_id': placement['pod_id']
        })
    
    # Add network edges
    for edge in cluster['node_topology']['edges']:
        attack_graph['edges'].append({
            'source': edge['source'],
            'target': edge['target'],
            'latency': edge['latency_ms'],
            'bandwidth': edge['bandwidth_gbps']
        })
    
    return attack_graph

attack_graph = cluster_to_attack_graph(cluster)
```

### Performance Considerations

```python
# For large clusters (>100 nodes), consider:

# 1. Limiting verbosity
cluster = generator.generate()  # Don't use --verbose in CLI

# 2. Streaming output for very large clusters
import ijson  # For streaming JSON parsing

# 3. Parallel generation
from multiprocessing import Pool

def generate_cluster(args):
    num_nodes, use_case, seed = args
    gen = K8sClusterGenerator(num_nodes, use_case, seed)
    return gen.generate()

# Generate multiple clusters in parallel
with Pool(4) as pool:
    clusters = pool.map(generate_cluster, [
        (50, UseCase.MICROSERVICES, 1),
        (100, UseCase.DATA_ANALYTICS, 2),
        (30, UseCase.STARTUP_MVP, 3),
        (200, UseCase.ENTERPRISE_INTERNAL, 4)
    ])
```

## Common Patterns

### Pattern 1: Capacity Planning Simulation

```python
# Simulate adding new services
current_util = cluster['node_utilization']['utilization_pct']
if current_util['cpu'] > 70:
    print("Warning: Need to add more compute nodes")
    needed_nodes = calculate_needed_nodes(cluster)
```

### Pattern 2: Failure Simulation

```python
# Simulate node failure and check service availability
def simulate_node_failure(cluster, failed_node_id):
    affected_services = set()
    for placement in cluster['pod_placements']:
        if placement['node_id'] == failed_node_id:
            affected_services.add(placement['service_name'])
    
    # Check if services still have replicas
    for service in affected_services:
        remaining = [p for p in cluster['pod_placements']
                    if p['service_name'] == service and 
                    p['node_id'] != failed_node_id]
        if not remaining:
            print(f"CRITICAL: {service} has NO remaining replicas!")
```

### Pattern 3: Cost Optimization

```python
# Calculate cluster cost
def calculate_cost(cluster):
    from k8s_cluster_generator_extended import NODE_SPECS
    
    total_cost = 0
    for node in cluster['physical_nodes']:
        node_type = NodeType(node['node_type'])
        hourly_cost = NODE_SPECS[node_type].cost_per_hour
        total_cost += hourly_cost
    
    return {
        'hourly': total_cost,
        'daily': total_cost * 24,
        'monthly': total_cost * 24 * 30
    }
```

## Next Steps

1. Run example generations with different use cases
2. Visualize topologies using graph libraries (networkx, graphviz)
3. Integrate with your attack graph or simulation tools
4. Extend with custom node types or placement strategies
5. Add validation rules for production constraints
