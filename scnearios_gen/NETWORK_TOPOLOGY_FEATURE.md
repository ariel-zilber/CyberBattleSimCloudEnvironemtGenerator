# Network Topology Generation Feature

## 🌐 Overview

The Network Topology Generator creates realistic graph representations of service connectivity in Kubernetes clusters. It produces four distinct graph types that model different aspects of network knowledge and accessibility, perfect for security analysis, attack simulation, and network design.

## 📊 Four Graph Types

### 1. **knows_connectivity** 
Edges the attacker is aware of (reconnaissance data)
- Represents what connections the attacker has discovered
- Subset of total connectivity based on `knowledge_completeness` parameter
- Models incomplete network knowledge

### 2. **knows_reachability**
Nodes the attacker knows exist
- All services mentioned in known edges plus entry points
- Represents discovered services (even if not all connections are known)
- Models service discovery phase

### 3. **access_connectivity**
Connections the attacker can actually use
- Only includes edges that pass firewall rules
- Bidirectional connections properly modeled
- Authentication requirements tracked

### 4. **access_reachability**
Nodes actually reachable from entry points
- Computed via graph traversal from public services
- Represents lateral movement possibilities
- Critical for attack path analysis

## 🎯 Key Features

### Realistic Service Connectivity
- **60+ predefined service connection rules** based on real-world architectures
- Database → Application connections (PostgreSQL → Keycloak, Harbor, etc.)
- Observability flows (Prometheus → metrics exporters)
- Storage patterns (MinIO → ML services)
- Message queue topologies (Kafka → Zookeeper)

### Intelligent Entry Points
- Automatically identifies publicly exposed services
- Ingress controllers marked as entry points
- Fallback logic ensures at least one entry point

### Firewall Simulation
- Probabilistic firewall rule application
- Critical services less likely to be blocked
- Configurable blocking probability

### Vulnerability Modeling
- Services assigned vulnerability scores (0.0-1.0)
- Public services more vulnerable
- Unauthenticated services more vulnerable
- Critical services better maintained (lower vulnerability)

## 🚀 Usage

### Basic Usage

```bash
# Generate cluster with network topology
python k8s_cluster_generator.py \
  --nodes 20 \
  --use-case microservices \
  --generate-topology \
  -o cluster.json
```

### Advanced Configuration

```bash
# Control firewall and knowledge parameters
python k8s_cluster_generator.py \
  --nodes 50 \
  --use-case ecommerce \
  --generate-topology \
  --firewall-probability 0.3 \
  --knowledge-completeness 0.8 \
  --seed 42 \
  -o cluster.json
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--generate-topology` | False | Enable topology generation |
| `--firewall-probability` | 0.2 | Probability a connection is blocked (0.0-1.0) |
| `--knowledge-completeness` | 0.7 | How much network the attacker knows (0.0-1.0) |

## 📁 Output Format

### JSON Structure

```json
{
  "cluster_metadata": { ... },
  "services": [ ... ],
  "service_instances": { ... },
  "network_topology": {
    "services": {
      "prometheus": {
        "name": "prometheus",
        "category": "observability",
        "instance_count": 4,
        "port": 9090,
        "protocol": "TCP",
        "is_public": false,
        "has_authentication": false,
        "vulnerability_level": 0.23
      },
      ...
    },
    "knows_connectivity": [
      {
        "source": "grafana",
        "target": "prometheus",
        "protocol": "TCP",
        "port": 9090,
        "bidirectional": false,
        "requires_auth": false,
        "firewall_allowed": true
      },
      ...
    ],
    "knows_reachability": ["nginx", "grafana", "prometheus", ...],
    "access_connectivity": [ ... ],
    "access_reachability": ["nginx", "grafana", ...],
    "metadata": {
      "total_services": 28,
      "total_edges": 67,
      "firewall_blocked_edges": 12,
      "entry_points": ["nginx-ingress-controller"],
      "connectivity_metrics": {
        "avg_degree": 2.39,
        "density": 0.087,
        "is_connected": false,
        "num_components": 3
      }
    }
  }
}
```

## 🔍 Service Connectivity Examples

### Database Connections
```
PostgreSQL connects to:
  → Keycloak (auth management)
  → Harbor (container registry)
  → Airflow (workflow orchestration)
  → MLflow (ML experiment tracking)

Redis connects to:
  → Harbor (cache)
  → WordPress (session store)
  → GitLab Runner (job queue)
```

### Observability Flows
```
Prometheus collects from:
  ← All services (metrics scraping)
  ← Node exporters
  ← Kube-state-metrics

Grafana queries:
  → Prometheus (metrics)
  → Loki (logs)
  → Tempo (traces)
  → Mimir (long-term storage)
```

### Messaging Topology
```
Kafka ecosystem:
  ← Zookeeper (coordination)
  → Schema Registry
  → Flink (stream processing)
  → Spark (batch processing)
```

## 📈 Graph Metrics

### Connectivity Metrics
- **Average Degree**: Average connections per node
- **Density**: Ratio of actual to possible edges
- **Is Connected**: Whether graph is weakly connected
- **Num Components**: Number of disconnected subgraphs

### Typical Values by Use Case

| Use Case | Avg Degree | Density | Components |
|----------|------------|---------|------------|
| Startup MVP | 1.5-2.5 | 0.05-0.15 | 1-2 |
| Microservices | 2.5-4.0 | 0.08-0.18 | 1-3 |
| Data Analytics | 3.0-5.0 | 0.10-0.25 | 1-2 |
| E-commerce | 3.5-5.5 | 0.12-0.28 | 1 |

## 🎮 Use Cases

### 1. Security Analysis
```python
import json

# Load topology
with open('cluster.json', 'r') as f:
    data = json.load(f)

topology = data['network_topology']

# Identify vulnerable entry points
entry_points = topology['metadata']['entry_points']
for ep in entry_points:
    service = topology['services'][ep]
    if service['vulnerability_level'] > 0.5:
        print(f"⚠️ Vulnerable entry point: {ep}")

# Find critical services without auth
for name, service in topology['services'].items():
    if not service['has_authentication'] and service['category'] == 'database':
        print(f"🚨 Unauthenticated database: {name}")
```

### 2. Attack Path Simulation
```python
# Get reachable targets from entry points
entry_points = topology['metadata']['entry_points']
reachable = topology['access_reachability']

print(f"Starting from: {entry_points}")
print(f"Can reach: {len(reachable)} services")

# Identify high-value targets
for service_name in reachable:
    service = topology['services'][service_name]
    if service['category'] in ['database', 'security']:
        print(f"💎 High-value target reachable: {service_name}")
```

### 3. Network Segmentation Analysis
```python
# Check if critical services are isolated
critical_categories = ['database', 'security', 'storage']
metrics = topology['metadata']['connectivity_metrics']

if metrics['num_components'] > 1:
    print(f"✅ Network has {metrics['num_components']} isolated segments")
else:
    print("⚠️ No network segmentation - all services in one component")
```

### 4. Firewall Rule Validation
```python
# Find blocked connections to critical services
for edge in topology['knows_connectivity']:
    if not edge['firewall_allowed']:
        target = topology['services'][edge['target']]
        if target['category'] in ['database', 'security']:
            print(f"🔒 Firewall blocks: {edge['source']} → {edge['target']}")
```

## 🔧 Standalone Usage

The topology generator can also be used independently:

```python
from network_topology_generator import NetworkTopologyGenerator, topology_to_dict

# Define services
services = ['nginx', 'postgresql', 'redis', 'prometheus', 'grafana']
instances = {'nginx': 3, 'postgresql': 3, 'redis': 2, 'prometheus': 2, 'grafana': 1}

# Generate topology
generator = NetworkTopologyGenerator(services, instances, seed=42)
topology = generator.generate(
    firewall_probability=0.2,
    knowledge_completeness=0.7
)

# Export
import json
with open('topology.json', 'w') as f:
    json.dump(topology_to_dict(topology), f, indent=2)
```

## 📊 Export Formats

### GraphML Export
```bash
# Generate topology and export to GraphML for visualization
python network_topology_generator.py cluster.json

# Outputs:
# - cluster_topology.json (full data)
# - cluster_knows_connectivity.graphml
# - cluster_access_connectivity.graphml
# - cluster_knows_reachability.graphml  
# - cluster_access_reachability.graphml
```

### NetworkX Integration
```python
from network_topology_generator import topology_to_networkx, GraphType

# Convert to NetworkX for analysis
G = topology_to_networkx(topology, GraphType.ACCESS_CONNECTIVITY)

# Analyze with NetworkX
import networkx as nx
print(f"Shortest path: {nx.shortest_path(G, 'nginx', 'postgresql')}")
print(f"Betweenness: {nx.betweenness_centrality(G)}")
```

### Adjacency Matrix
```python
from network_topology_generator import topology_to_adjacency_matrix, GraphType

# Get adjacency matrix
matrix = topology_to_adjacency_matrix(topology, GraphType.ACCESS_CONNECTIVITY)

# Use for graph algorithms
print(f"Matrix shape: {matrix.shape}")
print(f"Sparsity: {1.0 - np.count_nonzero(matrix) / matrix.size:.2%}")
```

## 🎯 Real-World Scenarios

### Scenario 1: Penetration Testing Setup
```bash
# Generate test environment with known vulnerabilities
python k8s_cluster_generator.py \
  --nodes 30 \
  --use-case microservices \
  --generate-topology \
  --firewall-probability 0.15 \
  --knowledge-completeness 0.5 \
  -o pentest_env.json
```

### Scenario 2: Network Design Validation
```bash
# Verify proper segmentation in production-like cluster
python k8s_cluster_generator.py \
  --nodes 100 \
  --use-case ecommerce \
  --generate-topology \
  --firewall-probability 0.4 \
  -o production_design.json

# Check if critical services are properly isolated
```

### Scenario 3: Attack Surface Analysis
```bash
# Analyze what an attacker can discover and access
python k8s_cluster_generator.py \
  --nodes 50 \
  --use-case saas_platform \
  --generate-topology \
  --knowledge-completeness 0.3 \
  -o attack_surface.json

# Compare knows_reachability vs access_reachability
```

## 📝 Integration with CyberBattleSim

The topology format is compatible with CyberBattleSim:

```python
# Convert to CyberBattleSim format
def topology_to_cyberbattle(topology):
    nodes = {}
    for name, service in topology['services'].items():
        nodes[name] = {
            'value': 100 if service['category'] in ['database', 'security'] else 50,
            'properties': ['breach_node'],
            'services': [{'name': f"{service['protocol']}/{service['port']}"}],
            'firewall': {'outgoing': [], 'incoming': []}
        }
    
    # Add edges as firewall rules
    for edge in topology['access_connectivity']:
        if edge['firewall_allowed']:
            nodes[edge['source']]['firewall']['outgoing'].append({
                'target': edge['target'],
                'port': edge['port']
            })
    
    return nodes
```

## 🔬 Advanced Features

### Custom Connectivity Rules
Extend SERVICE_CONNECTIVITY_RULES in the generator to add custom service types:

```python
SERVICE_CONNECTIVITY_RULES["my-service"] = {
    "connects_to": ["postgresql", "redis"],
    "connectivity_probability": 0.9,
    "port_range": (8080, 8080),
    "requires_auth": True,
    "is_critical": True,
    "is_public": False
}
```

### Dynamic Port Assignment
Ports are automatically assigned within realistic ranges for each service type.

### Vulnerability Scoring
Configurable vulnerability calculation based on:
- Public exposure (+0.3)
- Authentication requirements (+0.2 if missing)
- Criticality (-0.1 if critical)
- Random variation (±0.1)

## 📚 References

- [NetworkX Documentation](https://networkx.org/)
- [CyberBattleSim](https://github.com/microsoft/CyberBattleSim)
- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

## 🎓 Best Practices

1. **Use seeds for reproducibility** in security testing
2. **Adjust firewall_probability** based on security posture (0.1=permissive, 0.5=strict)
3. **Lower knowledge_completeness** for red team scenarios (0.3-0.5)
4. **Higher knowledge_completeness** for blue team design (0.8-0.9)
5. **Export to GraphML** for visualization in tools like Gephi or Cytoscape

---

**Version:** 1.2
**Date:** November 7, 2025
**Formats:** JSON, GraphML, NetworkX, Adjacency Matrix
