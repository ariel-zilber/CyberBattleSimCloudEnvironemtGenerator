# Instance Count Feature - Update v1.1

## 🆕 What's New

The Kubernetes Cluster Generator now includes **automatic instance count calculation** for all services based on:
- Cluster size (TINY, SMALL, MEDIUM, LARGE, XLARGE)
- High availability requirements
- Service-specific scaling characteristics
- Quorum requirements (for etcd, zookeeper, etc.)

## 📊 Key Additions

### 1. Service Instance Counts

Each service now has configurable instance count parameters:
- **`base_instance_count`**: Base number of replicas (default: 1 or 2 for HA)
- **`scale_with_cluster`**: Whether to scale with cluster size (true/false)

### 2. Intelligent Scaling

**Automatic Scaling Rules:**
- **TINY** (1-3 nodes): Base count
- **SMALL** (3-10 nodes): Base + 1
- **MEDIUM** (10-50 nodes): Base + 2  
- **LARGE** (50-200 nodes): Base + 3
- **XLARGE** (200+ nodes): Base + 5

**High Availability Enforcement:**
- Services with `requires_ha=True` get minimum 2 instances
- Quorum-based services (etcd, zookeeper, consul) always use odd numbers (3, 5, 7)
- Maximum caps prevent over-scaling (7 for quorum services, 10 for others)

### 3. Enhanced Output

#### New Metadata Fields
```json
{
  "cluster_metadata": {
    "total_pods": 86,              // NEW: Total pod count across all services
    "avg_pods_per_node": "0.9"     // NEW: Average pods per node
  }
}
```

#### Service Instance Mapping
```json
{
  "service_instances": {
    "etcd": 5,
    "prometheus": 4,
    "grafana": 1,
    "postgresql": 4,
    "redis": 4,
    ...
  }
}
```

### 4. Updated CLI Verbose Output

```bash
python k8s_cluster_generator.py --nodes 50 --use-case microservices --verbose
```

**Now shows:**
```
Total Services: 28
Total Pods: 95
Avg Pods/Node: 1.9
Resource Utilization: 47.5%

Top 10 Services by Instance Count:
  etcd                             7 instances
  kafka                            5 instances
  postgresql                       5 instances
  redis                            5 instances
  ...
```

### 5. Enhanced CSV Exports

**New CSV file: `clusters_instance_counts.csv`**
```csv
cluster_id,use_case,num_nodes,total_pods,etcd,prometheus,grafana,...
1,microservices,20,95,5,4,1,...
2,data_analytics,100,156,7,6,1,...
```

## 🎯 Examples

### Example 1: Small Startup (10 nodes)

```bash
python k8s_cluster_generator.py --nodes 10 --use-case startup_mvp --seed 42
```

**Instance Counts:**
- etcd: 5 instances (quorum requirement)
- prometheus: 3 instances (HA + scaling)
- postgresql: 3 instances (HA + scaling)
- redis: 3 instances (HA + scaling)
- grafana: 1 instance (no scaling needed)
- cert-manager: 1 instance (no scaling needed)

**Total:** ~24 pods across 14 services

### Example 2: Medium Microservices (50 nodes)

```bash
python k8s_cluster_generator.py --nodes 50 --use-case microservices --seed 42
```

**Instance Counts:**
- etcd: 7 instances (max quorum)
- kafka: 5 instances (large cluster scaling)
- postgresql: 5 instances (HA + large cluster)
- redis: 5 instances (HA + large cluster)
- prometheus: 5 instances (HA + large cluster)
- nginx-ingress: 5 instances (HA + large cluster)

**Total:** ~95 pods across 28 services (~1.9 pods/node)

### Example 3: Large Data Platform (100 nodes)

```bash
python k8s_cluster_generator.py --nodes 100 --use-case data_analytics --seed 42
```

**Instance Counts:**
- etcd: 7 instances (max quorum)
- spark: 8 instances (compute-heavy scaling)
- flink: 7 instances (stream processing scaling)
- clickhouse: 7 instances (analytics scaling)
- kafka: 7 instances (messaging scaling)
- minio: 7 instances (storage scaling)

**Total:** ~156 pods across 35 services (~1.6 pods/node)

## 📈 Scaling Behavior

### Non-Scaling Services
These maintain base count regardless of cluster size:
- cert-manager
- sealed-secrets
- grafana
- kibana
- jupyterhub
- mlflow

### Scaling Services
These increase instances with cluster size:
- etcd (3 → 5 → 7)
- prometheus (2 → 3 → 4 → 5)
- databases (2 → 3 → 4 → 5)
- ingress controllers (2 → 3 → 4 → 5)
- kafka (2 → 3 → 5 → 7)
- data processing (spark, flink)

## 🔧 Resource Impact

**Updated Resource Calculation:**
```python
total_resource_weight = sum(service.resource_weight * service.instance_count)
```

**Example:**
- Before: prometheus (weight=5) = 5 units
- After: prometheus (weight=5, instances=4) = 20 units

This provides more accurate resource utilization estimates.

## 📊 CSV Export Updates

### clusters_summary.csv
**Added columns:**
- `total_pods`: Total pod count
- `avg_pods_per_node`: Average pods per node

### clusters_instance_counts.csv (NEW)
**Full matrix of instance counts:**
- Rows: Clusters
- Columns: Services
- Values: Number of instances (empty if not present)

Perfect for:
- Capacity planning
- Resource estimation
- Comparing cluster densities
- Identifying scaling patterns

## 🎓 Use Cases

### 1. Capacity Planning
```bash
# Generate multiple cluster sizes
for nodes in 10 20 50 100; do
  python k8s_cluster_generator.py --nodes $nodes --use-case microservices -o cluster_${nodes}.json
done

# Export and analyze
python cluster_csv_export.py cluster_*.json
# Review clusters_instance_counts.csv for pod density trends
```

### 2. Resource Estimation
```bash
# Generate cluster
python k8s_cluster_generator.py --nodes 50 --use-case ecommerce -o ecommerce.json

# Examine output
# total_pods * avg_resource_per_pod = total_cluster_resources
```

### 3. Density Analysis
```bash
# Compare pod density across use cases
python k8s_cluster_generator.py --nodes 50 --use-case startup_mvp -o startup.json
python k8s_cluster_generator.py --nodes 50 --use-case data_analytics -o data.json

# startup: ~1.5 pods/node (lightweight)
# data: ~1.8 pods/node (more intensive services)
```

## 🔍 Under the Hood

### Instance Count Calculation Algorithm

```python
def _calculate_instance_count(service, profile, cluster_size):
    base = profile.base_instance_count
    
    if not profile.scale_with_cluster:
        return max(base, 2 if profile.requires_ha else base)
    
    # Scale with cluster size
    scale_factor = {
        TINY: 0,
        SMALL: 1,
        MEDIUM: 2,
        LARGE: 3,
        XLARGE: 5
    }
    
    instances = base + scale_factor[cluster_size]
    
    # Apply quorum rules for distributed systems
    if service in ["etcd", "zookeeper", "consul"]:
        if instances % 2 == 0:
            instances += 1  # Make odd
        instances = min(instances, 7)  # Cap at 7
    elif profile.requires_ha:
        instances = max(instances, 2)
        instances = min(instances, 10)
    
    return instances
```

### Service Profile Example

```python
"postgresql": ServiceProfile(
    name="postgresql",
    resource_weight=6,
    requires_ha=True,
    base_instance_count=2,      # Start with 2 for HA
    scale_with_cluster=True,    # Scale up with cluster
    # ... other fields
)
```

## 📝 Migration Notes

**Backward Compatibility:**
- Old JSON outputs (v1.0) remain valid
- New fields are additive
- CSV exports handle both old and new formats

**Regenerating Old Clusters:**
To get instance counts for existing configurations, regenerate with the same seed:
```bash
# Original generation (v1.0)
python k8s_cluster_generator.py --nodes 20 --use-case microservices --seed 42 -o old.json

# Regenerate with same seed (v1.1)
python k8s_cluster_generator.py --nodes 20 --use-case microservices --seed 42 -o new.json
# Now includes instance counts!
```

## 🎉 Benefits

1. **More Realistic Configurations**: Instance counts reflect real-world deployments
2. **Better Capacity Planning**: Accurate pod density estimates
3. **Resource Estimation**: Calculate actual cluster resource needs
4. **HA Awareness**: Automatic enforcement of HA requirements
5. **Scaling Insights**: Understand how services scale with cluster size

## 📖 Documentation Updates

All documentation has been updated:
- **README.md**: Full technical details
- **QUICKSTART.md**: Updated examples
- **PROJECT_SUMMARY.md**: Feature overview
- **INDEX.md**: Navigation updated

## 🚀 Try It Now

```bash
# Quick test
python k8s_cluster_generator.py --nodes 20 --use-case microservices --verbose

# Look for:
# - Total Pods: X
# - Avg Pods/Node: Y
# - Top 10 Services by Instance Count
# - service_instances in JSON output
```

---

**Version:** 1.1
**Date:** November 7, 2025
**New Fields:** `total_pods`, `avg_pods_per_node`, `service_instances`
**New CSV:** `clusters_instance_counts.csv`
