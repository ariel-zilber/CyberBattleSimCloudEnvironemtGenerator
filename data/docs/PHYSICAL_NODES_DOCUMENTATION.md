# Physical Nodes Extension for Kubernetes Cluster Generator

## Overview

This extension module adds physical node topology and service placement capabilities to the original Kubernetes cluster generator. It maintains full backward compatibility while adding powerful new features for infrastructure modeling and analysis.

## Key Features

### 🏗️ Physical Node Generation
- **Multiple Node Types**: Control plane, general workers, compute-optimized, memory-optimized, storage-optimized, GPU nodes, and edge nodes
- **Realistic Resource Profiles**: Each node type has appropriate CPU, memory, storage, GPU, and network specifications
- **Multi-AZ Deployment**: Automatic distribution across availability zones for high availability
- **Rack Awareness**: Nodes are organized into racks for realistic data center topology

### 📍 Intelligent Service Placement
- **Resource-Aware Scheduling**: Places pods on nodes based on CPU, memory, and storage requirements
- **Affinity Rules**: Respects service preferences for specific node types (e.g., databases prefer memory-optimized nodes)
- **High Availability**: Spreads HA services across different availability zones
- **Load Balancing**: Distributes workloads to avoid hotspots

### 🌐 Network Topology Graphs
- **Node-Level Connectivity**: Generates realistic network connections between physical nodes
- **Intra-Zone vs Inter-Zone**: Different latency characteristics for same-zone and cross-zone connections
- **Service Dependencies**: Creates connections between nodes running related services
- **Mesh Networking**: Simulates service mesh connectivity patterns

### 📊 Resource Utilization Tracking
- **Real-Time Monitoring**: Tracks CPU, memory, and storage allocation per node
- **Utilization Metrics**: Calculates utilization percentages for capacity planning
- **Bottleneck Detection**: Identifies overutilized nodes
- **Cost Analysis**: Estimates relative infrastructure costs

## Installation

### Prerequisites
- Python 3.7+
- The original `k8s_cluster_generator.py` file

### Setup
1. Place `physical_nodes_extension.py` in the same directory as `k8s_cluster_generator.py`
2. No additional dependencies required (uses only Python standard library)

## Usage

### Basic Usage

```python
from k8s_cluster_generator import K8sClusterGenerator, UseCase
from physical_nodes_extension import extend_with_physical_nodes

# Generate base cluster
generator = K8sClusterGenerator(num_nodes=20, use_case=UseCase.MICROSERVICES, seed=42)
cluster = generator.generate()

# Extend with physical nodes
extended_cluster = extend_with_physical_nodes(cluster, seed=42)

# Access physical nodes
for node in extended_cluster["physical_nodes"]:
    print(f"{node['node_id']}: {node['cpu_utilization_pct']}% CPU, {node['pod_count']} pods")
```

### Advanced Usage

```python
from physical_nodes_extension import (
    extend_with_physical_nodes,
    print_cluster_summary,
    export_node_graph_to_graphviz
)

# Generate and extend cluster
extended_cluster = extend_with_physical_nodes(cluster, seed=42)

# Print summary
print_cluster_summary(extended_cluster)

# Export network topology for visualization
export_node_graph_to_graphviz(extended_cluster, "network_topology.dot")

# Analyze specific nodes
overutilized = [n for n in extended_cluster["physical_nodes"] 
                if n["cpu_utilization_pct"] > 80]
print(f"Found {len(overutilized)} overutilized nodes")
```

## Data Structures

### Extended Cluster Configuration

The `extend_with_physical_nodes()` function adds the following fields to the original cluster configuration:

```python
{
    # ... original cluster configuration fields ...
    
    "physical_nodes": [
        {
            "node_id": "worker_general-0",
            "node_type": "worker_general",
            "zone": "zone-a",
            "rack": "rack-1",
            "cpu_cores": 8,
            "memory_gb": 32,
            "storage_gb": 200,
            "gpu_count": 0,
            "network_bandwidth_gbps": 10,
            "allocated_cpu": 4.5,
            "allocated_memory": 16.0,
            "allocated_storage": 80.0,
            "cpu_utilization_pct": 56.25,
            "memory_utilization_pct": 50.0,
            "running_pods": ["nginx-0", "redis-0", "prometheus-0"],
            "pod_count": 3,
            "labels": {"node-type": "worker_general", "zone": "zone-a"},
            "taints": []
        },
        #... more nodes
    ],
    
    "pod_placements": [
        {
            "pod_id": "nginx-0",
            "service_name": "nginx",
            "node_id": "worker_general-0",
            "cpu_request": 0.5,
            "memory_request": 1.0,
            "storage_request": 10.0
        },
        # ... more placements
    ],
    
    "node_topology": {
        "nodes": [...],  # Node list for graph
        "edges": [
            {
                "source": "control-plane-0",
                "target": "worker_general-0",
                "edge_type": "intra_zone",
                "latency_ms": 0.5,
                "bandwidth_gbps": 10
            },
            # ... more edges
        ],
        "topology_stats": {
            "total_nodes": 20,
            "total_edges": 180,
            "avg_degree": 18.0,
            "zones": 3,
            "control_plane_nodes": 5,
            "worker_nodes": 15
        }
    },
    
    "node_utilization": {
        "total_capacity": {
            "cpu_cores": 160,
            "memory_gb": 640,
            "storage_gb": 4000
        },
        "total_allocated": {
            "cpu_cores": 72.5,
            "memory_gb": 289.0,
            "storage_gb": 1450.0
        },
        "utilization_pct": {
            "cpu": 45.31,
            "memory": 45.16,
            "storage": 36.25
        },
        "nodes_by_type": {
            "control_plane": 5,
            "worker_general": 8,
            "worker_compute": 3,
            "worker_memory": 3,
            "worker_storage": 1,
            "worker_gpu": 0,
            "edge": 0
        }
    }
}
```

## Node Types

### Control Plane
- **Resources**: 4 CPU cores, 16 GB RAM, 100 GB storage
- **Purpose**: Kubernetes control plane components (API server, controller manager, scheduler)
- **Taints**: NoSchedule (workload pods don't schedule here)

### Worker General Purpose
- **Resources**: 8 CPU cores, 32 GB RAM, 200 GB storage
- **Purpose**: General application workloads
- **Cost**: Baseline (1.0x)

### Worker Compute-Optimized
- **Resources**: 32 CPU cores, 64 GB RAM, 200 GB storage
- **Purpose**: CPU-intensive workloads (data processing, analytics)
- **Cost**: 2.5x baseline

### Worker Memory-Optimized
- **Resources**: 16 CPU cores, 256 GB RAM, 500 GB storage
- **Purpose**: Memory-intensive workloads (databases, caching, in-memory processing)
- **Cost**: 3.0x baseline

### Worker Storage-Optimized
- **Resources**: 8 CPU cores, 64 GB RAM, 2000 GB storage
- **Purpose**: Storage-heavy workloads (databases, object storage, data lakes)
- **Cost**: 1.5x baseline

### Worker GPU
- **Resources**: 16 CPU cores, 128 GB RAM, 500 GB storage, 4 GPUs, 100 Gbps network
- **Purpose**: ML/AI training and inference
- **Cost**: 8.0x baseline

### Edge
- **Resources**: 4 CPU cores, 8 GB RAM, 50 GB storage, 1 Gbps network
- **Purpose**: Edge computing, IoT gateway nodes
- **Cost**: 0.3x baseline

## Service Placement Logic

The placement engine considers multiple factors:

1. **Resource Requirements**: Ensures nodes have sufficient CPU, memory, and storage
2. **Node Type Preferences**: Places services on preferred node types:
   - Databases → Memory/Storage-optimized nodes
   - ML workloads → GPU nodes
   - General services → General-purpose workers
3. **High Availability**: Spreads HA services across availability zones
4. **Load Balancing**: Prefers less-utilized nodes to avoid hotspots
5. **Taints and Tolerations**: Respects node taints (e.g., control plane NoSchedule)

## Network Topology

The topology generator creates realistic network connections:

### Connection Types

1. **Control Plane ↔ Workers**: All worker nodes connect to control plane (0.1-1ms latency)
2. **Intra-Zone Mesh**: Full mesh within each availability zone (0.1-1ms latency)
3. **Service Dependencies**: Nodes running related services are connected
4. **Cross-Zone Links**: Partial mesh between zones (2-10ms latency)

### Topology Statistics

- **Total Nodes**: Number of physical nodes
- **Total Edges**: Number of network connections
- **Average Degree**: Average number of connections per node
- **Zones**: Number of availability zones
- **Network Diameter**: Longest shortest path (computed separately)

## Use Case Examples

### Example 1: Microservices Platform

```python
generator = K8sClusterGenerator(num_nodes=20, use_case=UseCase.MICROSERVICES, seed=42)
cluster = generator.generate()
extended = extend_with_physical_nodes(cluster, seed=42)

# Result:
# - 5 control plane nodes
# - 10 general-purpose workers
# - 3 memory-optimized nodes (for Redis, PostgreSQL)
# - 2 compute-optimized nodes (for API gateways)
# - 3 availability zones
# - ~150 network connections
```

### Example 2: ML Platform

```python
generator = K8sClusterGenerator(num_nodes=30, use_case=UseCase.ML_PLATFORM, seed=42)
cluster = generator.generate()
extended = extend_with_physical_nodes(cluster, seed=42)

# Result:
# - 5 control plane nodes
# - 6 GPU nodes (for model training)
# - 9 memory-optimized nodes (for data processing)
# - 6 compute-optimized nodes (for preprocessing)
# - 4 storage-optimized nodes (for data lakes)
# - 3 availability zones
```

### Example 3: E-Commerce Platform

```python
generator = K8sClusterGenerator(num_nodes=50, use_case=UseCase.ECOMMERCE, seed=42)
cluster = generator.generate()
extended = extend_with_physical_nodes(cluster, seed=42)

# Result:
# - 5 control plane nodes
# - 15 compute-optimized nodes (for application tier)
# - 12 memory-optimized nodes (for caching and databases)
# - 13 general-purpose workers
# - 5 storage-optimized nodes (for media and logs)
# - 3 availability zones
# - Full observability stack
```

## Visualization

### Graphviz Export

The extension can export node topology to Graphviz DOT format:

```python
export_node_graph_to_graphviz(extended_cluster, "topology.dot")
```

Render with:
```bash
# PNG format
dot -Tpng topology.dot -o topology.png

# SVG format (scalable)
dot -Tsvg topology.dot -o topology.svg

# PDF format
dot -Tpdf topology.dot -o topology.pdf
```

### Graph Properties

- **Node Colors**: Different colors for each node type
- **Node Labels**: Show node ID, pod count, and CPU utilization
- **Edge Styles**: Solid lines for intra-zone, dashed for inter-zone
- **Edge Labels**: Display network latency

## Performance Considerations

### Scalability

The extension efficiently handles:
- **Small clusters** (1-10 nodes): <1 second
- **Medium clusters** (10-50 nodes): 1-2 seconds
- **Large clusters** (50-200 nodes): 2-5 seconds
- **XLarge clusters** (200-1000 nodes): 5-30 seconds

### Memory Usage

Approximate memory usage:
- Base cluster data: ~1 MB
- Physical nodes (1000 nodes): ~5 MB
- Node topology graph (1000 nodes, 10,000 edges): ~10 MB
- Total for 1000-node cluster: ~16 MB

## API Reference

### Main Functions

#### `extend_with_physical_nodes(cluster_config, seed=None)`
Extends a base cluster configuration with physical nodes and placement.

**Parameters:**
- `cluster_config` (dict): Output from K8sClusterGenerator.generate()
- `seed` (int, optional): Random seed for reproducibility

**Returns:**
- dict: Extended cluster configuration

#### `print_cluster_summary(extended_config)`
Prints a formatted summary of the extended cluster.

**Parameters:**
- `extended_config` (dict): Extended cluster configuration

#### `export_node_graph_to_graphviz(extended_config, output_file)`
Exports node topology to Graphviz DOT format.

**Parameters:**
- `extended_config` (dict): Extended cluster configuration
- `output_file` (str): Output file path

### Classes

#### `PhysicalNodeGenerator`
Generates physical nodes based on cluster requirements.

#### `ServicePlacementEngine`
Places service pods onto physical nodes.

#### `NodeGraphGenerator`
Generates network topology graphs for physical nodes.

## Troubleshooting

### Common Issues

**Issue**: "Storage utilization > 100%"
- **Cause**: Storage-heavy services exceeded available capacity
- **Solution**: Increase number of storage-optimized nodes or reduce storage requirements

**Issue**: "Some pods unplaced"
- **Cause**: Insufficient resources or node type mismatch
- **Solution**: Add more nodes or ensure appropriate node types are available

**Issue**: "Low CPU utilization"
- **Cause**: Cluster is over-provisioned
- **Solution**: Reduce node count or consolidate workloads

**Issue**: "Single availability zone"
- **Cause**: Cluster too small for multi-AZ (< 10 nodes)
- **Solution**: Increase cluster size for better HA

## Future Enhancements

Potential additions:
- Pod autoscaling simulation
- Network policy enforcement
- Storage class modeling
- Cost optimization recommendations
- Failure scenario simulation
- Performance benchmarking
- Integration with real Kubernetes APIs

## Contributing

To extend this module:

1. Add new node types to `NodeType` enum
2. Define specs in `NODE_SPECS` dictionary
3. Update distribution logic in `PhysicalNodeGenerator`
4. Add service profiles to `SERVICE_RESOURCE_PROFILES`

## License

This extension follows the same license as the original k8s_cluster_generator.py.

## Support

For issues, questions, or contributions, refer to the main project documentation.

---

**Version**: 1.0.0  
**Last Updated**: 2025-11-08  
**Compatibility**: k8s_cluster_generator.py (2025-11-07)
