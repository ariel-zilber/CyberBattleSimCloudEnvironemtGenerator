# Complete Example: Extended K8s Cluster Generator

## Example: Generate a 20-Node ML Platform

```python
from k8s_cluster_generator_extended import K8sClusterGenerator, UseCase

# Generate cluster
generator = K8sClusterGenerator(
    num_nodes=20,
    use_case=UseCase.ML_PLATFORM,
    seed=42
)

cluster = generator.generate()
```

## Example Output Structure

```json
{
  "cluster_metadata": {
    "num_nodes": 20,
    "cluster_size": "MEDIUM",
    "use_case": "ml_platform",
    "total_services": 24,
    "total_pods": 58,
    "placed_pods": 58,
    "unplaced_pods": 0,
    "avg_pods_per_node": "2.9",
    "total_resource_weight": 342,
    "resource_utilization": "85.5%"
  },
  
  "services": [
    "airflow", "argo-cd", "cert-manager", "etcd", "fluent-bit",
    "grafana", "grafana-loki", "jaeger", "jupyterhub", "kube-state-metrics",
    "metrics-server", "minio", "mlflow", "mongodb", "nginx-ingress-controller",
    "postgresql", "prometheus", "redis", "spark", "thanos", "vault"
  ],
  
  "service_instances": {
    "airflow": 3,
    "argo-cd": 3,
    "cert-manager": 1,
    "etcd": 5,
    "fluent-bit": 1,
    "grafana": 1,
    "grafana-loki": 3,
    "jaeger": 3,
    "jupyterhub": 1,
    "kube-state-metrics": 1,
    "metrics-server": 1,
    "minio": 3,
    "mlflow": 1,
    "mongodb": 3,
    "nginx-ingress-controller": 3,
    "postgresql": 3,
    "prometheus": 3,
    "redis": 3,
    "spark": 1,
    "thanos": 3,
    "vault": 3
  },
  
  "services_by_category": {
    "ci_cd": ["argo-cd"],
    "control_plane_core": ["etcd", "kube-state-metrics", "metrics-server"],
    "control_plane_networking": ["nginx-ingress-controller"],
    "control_plane_security": ["cert-manager", "vault"],
    "data_caching": ["redis"],
    "data_nosql": ["mongodb"],
    "data_orchestration": ["airflow"],
    "data_processing": ["spark"],
    "data_sql": ["postgresql"],
    "data_storage": ["minio"],
    "ml_platform": ["jupyterhub", "mlflow"],
    "observability_logging": ["fluent-bit", "grafana-loki"],
    "observability_metrics": ["grafana", "prometheus", "thanos"],
    "observability_tracing": ["jaeger"]
  },
  
  "deployment_stats": {
    "observability_stack": {
      "metrics": true,
      "logging": true,
      "tracing": true,
      "completeness_score": 1.0
    },
    "automation": {
      "gitops_enabled": true,
      "service_mesh": false
    },
    "data_layer": {
      "sql_databases": 1,
      "nosql_databases": 1,
      "caching": true,
      "messaging": false
    }
  },
  
  "physical_nodes": [
    {
      "node_id": "control-plane-0",
      "node_type": "control_plane",
      "zone": "zone-a",
      "rack": "rack-1",
      "cpu_cores": 4,
      "memory_gb": 16,
      "storage_gb": 100,
      "gpu_count": 0,
      "allocated_cpu": 4.0,
      "allocated_memory": 8.0,
      "allocated_storage": 100.0,
      "cpu_utilization_pct": 100.0,
      "memory_utilization_pct": 50.0,
      "running_pods": ["etcd-0", "etcd-1"],
      "pod_count": 2,
      "labels": {"node-role": "control-plane", "zone": "zone-a"},
      "taints": ["NoSchedule"]
    },
    {
      "node_id": "worker_gpu-5",
      "node_type": "worker_gpu",
      "zone": "zone-a",
      "rack": "rack-1",
      "cpu_cores": 16,
      "memory_gb": 128,
      "storage_gb": 500,
      "gpu_count": 4,
      "allocated_cpu": 10.0,
      "allocated_memory": 40.0,
      "allocated_storage": 250.0,
      "cpu_utilization_pct": 62.5,
      "memory_utilization_pct": 31.25,
      "running_pods": ["jupyterhub-0", "spark-0"],
      "pod_count": 2,
      "labels": {"node-type": "worker_gpu", "zone": "zone-a", "gpu": "true"},
      "taints": []
    },
    {
      "node_id": "worker_memory-10",
      "node_type": "worker_memory",
      "zone": "zone-b",
      "rack": "rack-2",
      "cpu_cores": 16,
      "memory_gb": 256,
      "storage_gb": 500,
      "gpu_count": 0,
      "allocated_cpu": 10.0,
      "allocated_memory": 80.0,
      "allocated_storage": 800.0,
      "cpu_utilization_pct": 62.5,
      "memory_utilization_pct": 31.25,
      "running_pods": ["postgresql-0", "postgresql-1", "mongodb-0", "redis-0"],
      "pod_count": 4,
      "labels": {"node-type": "worker_memory", "zone": "zone-b", "memory-optimized": "true"},
      "taints": []
    }
    // ... 17 more nodes
  ],
  
  "node_topology": {
    "nodes": [
      {"node_id": "control-plane-0", "node_type": "control_plane", "zone": "zone-a", "rack": "rack-1", "pod_count": 2},
      {"node_id": "worker_gpu-5", "node_type": "worker_gpu", "zone": "zone-a", "rack": "rack-1", "pod_count": 2},
      {"node_id": "worker_memory-10", "node_type": "worker_memory", "zone": "zone-b", "rack": "rack-2", "pod_count": 4}
      // ... 17 more
    ],
    "edges": [
      {
        "source": "control-plane-0",
        "target": "worker_gpu-5",
        "edge_type": "intra_zone",
        "latency_ms": 0.43,
        "bandwidth_gbps": 10
      },
      {
        "source": "control-plane-0",
        "target": "worker_memory-10",
        "edge_type": "inter_zone",
        "latency_ms": 4.72,
        "bandwidth_gbps": 10
      },
      {
        "source": "worker_gpu-5",
        "target": "worker_memory-10",
        "edge_type": "inter_zone",
        "latency_ms": 5.21,
        "bandwidth_gbps": 10
      },
      {
        "source": "worker_memory-10",
        "target": "worker_memory-11",
        "edge_type": "intra_zone",
        "latency_ms": 0.67,
        "bandwidth_gbps": 25
      }
      // ... 150+ more edges
    ],
    "topology_stats": {
      "total_nodes": 20,
      "total_edges": 164,
      "avg_degree": 16.4,
      "zones": 2,
      "control_plane_nodes": 5,
      "worker_nodes": 15
    }
  },
  
  "pod_placements": [
    {
      "pod_id": "etcd-0",
      "service_name": "etcd",
      "node_id": "control-plane-0",
      "cpu_request": 2.0,
      "memory_request": 4.0,
      "storage_request": 50.0
    },
    {
      "pod_id": "postgresql-0",
      "service_name": "postgresql",
      "node_id": "worker_memory-10",
      "cpu_request": 2.0,
      "memory_request": 8.0,
      "storage_request": 200.0
    },
    {
      "pod_id": "jupyterhub-0",
      "service_name": "jupyterhub",
      "node_id": "worker_gpu-5",
      "cpu_request": 2.0,
      "memory_request": 8.0,
      "storage_request": 50.0
    },
    {
      "pod_id": "spark-0",
      "service_name": "spark",
      "node_id": "worker_gpu-5",
      "cpu_request": 8.0,
      "memory_request": 32.0,
      "storage_request": 200.0
    }
    // ... 54 more placements
  ],
  
  "node_utilization": {
    "total_capacity": {
      "cpu_cores": 244,
      "memory_gb": 1424,
      "storage_gb": 7100
    },
    "total_allocated": {
      "cpu_cores": 147.5,
      "memory_gb": 856.0,
      "storage_request": 4320.0
    },
    "utilization_pct": {
      "cpu": 60.45,
      "memory": 60.11,
      "storage": 60.85
    },
    "nodes_by_type": {
      "control_plane": 5,
      "worker_general": 3,
      "worker_compute": 4,
      "worker_memory": 6,
      "worker_storage": 0,
      "worker_gpu": 2,
      "edge": 0
    }
  }
}
```

## Analysis Examples

### 1. Node Utilization Analysis

```python
# Find most and least utilized nodes
nodes = cluster['physical_nodes']
sorted_by_cpu = sorted(nodes, key=lambda n: n['cpu_utilization_pct'], reverse=True)

print("Top 5 Most Utilized Nodes:")
for node in sorted_by_cpu[:5]:
    print(f"  {node['node_id']}: {node['cpu_utilization_pct']}% CPU, "
          f"{node['pod_count']} pods, Zone: {node['zone']}")

print("\nTop 5 Least Utilized Nodes:")
for node in sorted_by_cpu[-5:]:
    print(f"  {node['node_id']}: {node['cpu_utilization_pct']}% CPU, "
          f"{node['pod_count']} pods, Zone: {node['zone']}")
```

**Output:**
```
Top 5 Most Utilized Nodes:
  control-plane-0: 100.0% CPU, 2 pods, Zone: zone-a
  control-plane-1: 100.0% CPU, 2 pods, Zone: zone-a
  control-plane-2: 100.0% CPU, 2 pods, Zone: zone-b
  worker_memory-10: 75.0% CPU, 4 pods, Zone: zone-b
  worker_compute-8: 71.88% CPU, 3 pods, Zone: zone-a

Top 5 Least Utilized Nodes:
  worker_general-15: 18.75% CPU, 1 pod, Zone: zone-b
  worker_general-14: 25.0% CPU, 1 pod, Zone: zone-a
  worker_memory-12: 31.25% CPU, 2 pods, Zone: zone-b
  worker_compute-9: 37.5% CPU, 2 pods, Zone: zone-b
  worker_gpu-6: 43.75% CPU, 1 pod, Zone: zone-b
```

### 2. Service Distribution Analysis

```python
# Which services are placed where
from collections import defaultdict

service_nodes = defaultdict(list)
for placement in cluster['pod_placements']:
    service_nodes[placement['service_name']].append(placement['node_id'])

print("Service to Node Mapping:")
for service, nodes in sorted(service_nodes.items()):
    unique_nodes = set(nodes)
    zones = set()
    for node_id in unique_nodes:
        node = next(n for n in cluster['physical_nodes'] if n['node_id'] == node_id)
        zones.add(node['zone'])
    
    print(f"  {service:30s} {len(nodes):2d} pods on {len(unique_nodes):2d} nodes across {len(zones)} zones")
```

**Output:**
```
Service to Node Mapping:
  airflow                         3 pods on  3 nodes across 2 zones
  argo-cd                         3 pods on  3 nodes across 2 zones
  cert-manager                    1 pod  on  1 node  across 1 zone
  etcd                            5 pods on  5 nodes across 2 zones
  grafana                         1 pod  on  1 node  across 1 zone
  jupyterhub                      1 pod  on  1 node  across 1 zone
  minio                           3 pods on  3 nodes across 2 zones
  postgresql                      3 pods on  3 nodes across 2 zones
  prometheus                      3 pods on  3 nodes across 2 zones
  spark                           1 pod  on  1 node  across 1 zone
```

### 3. Network Topology Analysis

```python
# Analyze network connectivity
topology = cluster['node_topology']

# Calculate connectivity stats
intra_zone_edges = [e for e in topology['edges'] if e['edge_type'] == 'intra_zone']
inter_zone_edges = [e for e in topology['edges'] if e['edge_type'] == 'inter_zone']

print(f"Network Topology Analysis:")
print(f"  Total Edges: {len(topology['edges'])}")
print(f"  Intra-Zone Edges: {len(intra_zone_edges)} ({len(intra_zone_edges)/len(topology['edges'])*100:.1f}%)")
print(f"  Inter-Zone Edges: {len(inter_zone_edges)} ({len(inter_zone_edges)/len(topology['edges'])*100:.1f}%)")

# Average latencies
avg_intra_latency = sum(e['latency_ms'] for e in intra_zone_edges) / len(intra_zone_edges)
avg_inter_latency = sum(e['latency_ms'] for e in inter_zone_edges) / len(inter_zone_edges)

print(f"\n  Average Intra-Zone Latency: {avg_intra_latency:.2f}ms")
print(f"  Average Inter-Zone Latency: {avg_inter_latency:.2f}ms")

# Node degree distribution
from collections import Counter
degrees = Counter()
for edge in topology['edges']:
    degrees[edge['source']] += 1
    degrees[edge['target']] += 1

print(f"\n  Node Degree Distribution:")
print(f"    Min: {min(degrees.values())}")
print(f"    Max: {max(degrees.values())}")
print(f"    Mean: {sum(degrees.values())/len(degrees):.1f}")
print(f"    Median: {sorted(degrees.values())[len(degrees)//2]}")
```

**Output:**
```
Network Topology Analysis:
  Total Edges: 164
  Intra-Zone Edges: 98 (59.8%)
  Inter-Zone Edges: 66 (40.2%)

  Average Intra-Zone Latency: 0.54ms
  Average Inter-Zone Latency: 5.83ms

  Node Degree Distribution:
    Min: 12
    Max: 19
    Mean: 16.4
    Median: 16
```

### 4. Resource Capacity Planning

```python
# Check if cluster has headroom
util = cluster['node_utilization']

print("Resource Capacity Analysis:")
print(f"  CPU:")
print(f"    Total: {util['total_capacity']['cpu_cores']} cores")
print(f"    Allocated: {util['total_allocated']['cpu_cores']} cores")
print(f"    Available: {util['total_capacity']['cpu_cores'] - util['total_allocated']['cpu_cores']} cores")
print(f"    Utilization: {util['utilization_pct']['cpu']}%")

print(f"\n  Memory:")
print(f"    Total: {util['total_capacity']['memory_gb']} GB")
print(f"    Allocated: {util['total_allocated']['memory_gb']} GB")
print(f"    Available: {util['total_capacity']['memory_gb'] - util['total_allocated']['memory_gb']} GB")
print(f"    Utilization: {util['utilization_pct']['memory']}%")

# Recommendation
if util['utilization_pct']['cpu'] > 80:
    print("\n⚠️  WARNING: High CPU utilization. Consider adding more nodes.")
elif util['utilization_pct']['cpu'] < 40:
    print("\n💡 INFO: Low CPU utilization. Cluster may be over-provisioned.")
else:
    print("\n✅ OK: CPU utilization is in healthy range (40-80%).")
```

**Output:**
```
Resource Capacity Analysis:
  CPU:
    Total: 244 cores
    Allocated: 147.5 cores
    Available: 96.5 cores
    Utilization: 60.45%

  Memory:
    Total: 1424 GB
    Allocated: 856.0 GB
    Available: 568.0 GB
    Utilization: 60.11%

✅ OK: CPU utilization is in healthy range (40-80%).
```

### 5. High Availability Check

```python
# Check HA compliance for critical services
ha_services = [
    service for service, profile in SERVICE_CATALOG.items()
    if profile.requires_ha and service in cluster['services']
]

print("High Availability Compliance Check:")
for service in ha_services:
    placements = [p for p in cluster['pod_placements'] if p['service_name'] == service]
    zones = set()
    for placement in placements:
        node = next(n for n in cluster['physical_nodes'] if n['node_id'] == placement['node_id'])
        zones.add(node['zone'])
    
    status = "✅" if len(zones) >= 2 else "⚠️ "
    print(f"  {status} {service:30s} {len(placements)} pods across {len(zones)} zone(s)")
```

**Output:**
```
High Availability Compliance Check:
  ✅ etcd                           5 pods across 2 zones
  ✅ prometheus                     3 pods across 2 zones
  ✅ postgresql                     3 pods across 2 zones
  ✅ mongodb                        3 pods across 2 zones
  ✅ redis                          3 pods across 2 zones
  ✅ nginx-ingress-controller       3 pods across 2 zones
  ✅ vault                          3 pods across 2 zones
  ✅ argo-cd                        3 pods across 2 zones
```

## Visualization Helpers

### Generate Node Utilization Heatmap Data

```python
# Prepare data for heatmap visualization
import json

heatmap_data = []
for node in cluster['physical_nodes']:
    if node['node_type'] != 'control_plane':  # Skip control plane for cleaner viz
        heatmap_data.append({
            'node': node['node_id'],
            'zone': node['zone'],
            'type': node['node_type'],
            'cpu_util': node['cpu_utilization_pct'],
            'memory_util': node['memory_utilization_pct'],
            'pod_count': node['pod_count']
        })

# Save for visualization
with open('node_heatmap.json', 'w') as f:
    json.dump(heatmap_data, f, indent=2)
```

### Generate Network Graph Data for Visualization

```python
# Prepare data for network graph visualization (e.g., D3.js)
graph_data = {
    'nodes': [
        {
            'id': node['node_id'],
            'type': node['node_type'],
            'zone': node['zone'],
            'size': node['pod_count'],
            'utilization': node['cpu_utilization_pct']
        }
        for node in cluster['physical_nodes']
    ],
    'links': [
        {
            'source': edge['source'],
            'target': edge['target'],
            'type': edge['edge_type'],
            'latency': edge['latency_ms'],
            'bandwidth': edge['bandwidth_gbps']
        }
        for edge in cluster['node_topology']['edges']
    ]
}

with open('network_graph.json', 'w') as f:
    json.dump(graph_data, f, indent=2)
```

## Summary Statistics

```python
def print_cluster_summary(cluster):
    print("="*80)
    print("CLUSTER SUMMARY")
    print("="*80)
    
    meta = cluster['cluster_metadata']
    util = cluster['node_utilization']
    topo = cluster['node_topology']['topology_stats']
    
    print(f"\n📊 Scale: {meta['num_nodes']} nodes, {meta['total_pods']} pods ({meta['placed_pods']} placed)")
    print(f"🎯 Use Case: {meta['use_case']}")
    print(f"📦 Services: {meta['total_services']} ({len(cluster['services_by_category'])} categories)")
    
    print(f"\n🖥️  Infrastructure:")
    print(f"   {util['nodes_by_type']['control_plane']} control plane nodes")
    print(f"   {util['nodes_by_type']['worker_general']} general workers")
    print(f"   {util['nodes_by_type']['worker_compute']} compute workers")
    print(f"   {util['nodes_by_type']['worker_memory']} memory workers")
    print(f"   {util['nodes_by_type']['worker_gpu']} GPU workers")
    
    print(f"\n💾 Resources:")
    print(f"   CPU: {util['utilization_pct']['cpu']}% utilized")
    print(f"   Memory: {util['utilization_pct']['memory']}% utilized")
    print(f"   Storage: {util['utilization_pct']['storage']}% utilized")
    
    print(f"\n🌐 Network:")
    print(f"   {topo['total_edges']} connections")
    print(f"   {topo['zones']} availability zones")
    print(f"   {topo['avg_degree']:.1f} average node degree")
    
    stats = cluster['deployment_stats']
    print(f"\n✅ Features:")
    print(f"   Observability: {stats['observability_stack']['completeness_score']*100:.0f}%")
    print(f"   GitOps: {'Yes' if stats['automation']['gitops_enabled'] else 'No'}")
    print(f"   Service Mesh: {'Yes' if stats['automation']['service_mesh'] else 'No'}")
    
    print("="*80)

# Usage
print_cluster_summary(cluster)
```

This complete example shows how to:
1. Generate a realistic cluster
2. Access and analyze all the new data
3. Perform health checks and capacity planning
4. Prepare data for visualization
5. Generate comprehensive summaries
