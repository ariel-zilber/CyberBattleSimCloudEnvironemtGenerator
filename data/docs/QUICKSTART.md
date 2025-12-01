# Quick Start Guide - Kubernetes Cluster Generator

## 🚀 Getting Started in 30 Seconds

### Generate Your First Cluster

```bash
# Generate a 10-node microservices cluster
python k8s_cluster_generator.py --nodes 10 --use-case microservices
```

That's it! You'll get a realistic cluster configuration with ~15-25 services.

## 📋 Common Use Cases

### 1. Startup / MVP (3-10 nodes)
Perfect for: Early-stage startups, MVPs, small production workloads

```bash
python k8s_cluster_generator.py --nodes 5 --use-case startup_mvp --seed 42
```

**What you get:**
- Essential services only (~10-15 services)
- Single database (PostgreSQL)
- Basic observability (Prometheus + Grafana)
- Simple secrets management
- ~80-100% resource utilization

### 2. Microservices Platform (10-50 nodes)
Perfect for: Modern cloud-native applications, API platforms

```bash
python k8s_cluster_generator.py --nodes 20 --use-case microservices --verbose
```

**What you get:**
- Full observability stack (metrics, logs, traces)
- Service mesh (Cilium)
- Multiple databases (SQL, NoSQL, caching)
- GitOps (ArgoCD)
- Container registry (Harbor)
- ~25-35 services

### 3. Data Analytics Platform (50-200 nodes)
Perfect for: Big data processing, data lakes, analytics

```bash
python k8s_cluster_generator.py --nodes 100 --use-case data_analytics -o data_platform.json
```

**What you get:**
- Big data engines (Spark, Flink)
- Analytics databases (ClickHouse)
- Data orchestration (Airflow)
- Object storage (MinIO)
- Streaming (Kafka)
- ~30-40 services

### 4. ML Platform (20-100 nodes)
Perfect for: Machine learning, model training, experimentation

```bash
python k8s_cluster_generator.py --nodes 50 --use-case ml_platform --seed 123
```

**What you get:**
- ML experiment tracking (MLflow)
- Notebooks (JupyterHub)
- Distributed training frameworks
- Vector databases
- Large object storage
- ~20-30 services

### 5. E-commerce (30-100 nodes)
Perfect for: Online stores, marketplaces, high-traffic sites

```bash
python k8s_cluster_generator.py --nodes 50 --use-case ecommerce --verbose
```

**What you get:**
- HA databases with clustering
- Multiple caching layers
- Advanced security (Vault, Keycloak)
- Real-time messaging
- Payment infrastructure ready
- ~25-35 services

## 🎯 Advanced Usage

### Generate Multiple Variations

Compare different configurations:

```bash
# Generate 5 variations of the same cluster size
python k8s_cluster_generator.py --nodes 20 --use-case microservices --count 5 -o variations.json
```

### Reproducible Clusters

Use seeds for consistent results:

```bash
# Always get the same configuration
python k8s_cluster_generator.py --nodes 15 --use-case saas_platform --seed 42
```

### Compare Clusters

```bash
# Generate different sizes
python k8s_cluster_generator.py --nodes 5 --use-case startup_mvp -o small.json
python k8s_cluster_generator.py --nodes 50 --use-case startup_mvp -o large.json

# Compare them
python cluster_comparison.py small.json large.json
```

### Export to CSV

For spreadsheet analysis:

```bash
# Generate several clusters
python k8s_cluster_generator.py --nodes 10 --use-case microservices --count 3 -o micro.json
python k8s_cluster_generator.py --nodes 100 --use-case data_analytics -o data.json

# Export to CSV
python cluster_csv_export.py micro.json data.json
```

This creates:
- `clusters_summary.csv` - Overview of all clusters
- `clusters_services_matrix.csv` - Which services are in which cluster
- `clusters_categories.csv` - Service counts by category

## 📊 Understanding the Output

### Cluster Metadata
```json
{
  "num_nodes": 20,              // Number of worker nodes
  "cluster_size": "MEDIUM",     // Size category
  "use_case": "microservices",  // Primary use case
  "total_services": 28,         // Total deployed services
  "resource_utilization": "56%"  // Estimated resource usage
}
```

### Deployment Stats
```json
{
  "observability_stack": {
    "metrics": true,              // Has Prometheus/Grafana
    "logging": true,              // Has logging stack
    "tracing": true,              // Has distributed tracing
    "completeness_score": 1.0     // 0-1, full obs = 1.0
  },
  "automation": {
    "gitops_enabled": true,       // Has ArgoCD/Flux
    "service_mesh": true          // Has Cilium/Istio
  },
  "data_layer": {
    "sql_databases": 1,           // Number of SQL DBs
    "nosql_databases": 2,         // Number of NoSQL DBs
    "caching": true,              // Has Redis/Valkey
    "messaging": true             // Has Kafka/RabbitMQ
  }
}
```

## 💡 Tips & Best Practices

### Choosing Cluster Size

| Nodes | Best For | Typical Use Cases |
|-------|----------|-------------------|
| 1-5 | Dev/Test | Local development, CI/CD testing |
| 5-15 | Small Prod | Startups, small apps, MVPs |
| 15-50 | Medium Prod | Growing companies, moderate traffic |
| 50-200 | Large Prod | Enterprise, high traffic, data platforms |
| 200+ | Hyperscale | Tech giants, massive scale operations |

### Use Case Selection Guide

**Choose `startup_mvp` if:**
- You're just getting started
- You want minimal complexity
- Budget is tight
- Team is small

**Choose `microservices` if:**
- You have multiple services
- You need full observability
- You practice GitOps
- You want best practices

**Choose `data_analytics` if:**
- You process large datasets
- You need data warehousing
- You run ETL/ELT pipelines
- You do analytics at scale

**Choose `ml_platform` if:**
- You train ML models
- You need experiment tracking
- You use Jupyter notebooks
- You need GPU support

**Choose `ecommerce` if:**
- You have high traffic
- You need low latency
- Payment processing is critical
- You need HA everything

### Seed Usage

Seeds make results reproducible:

```bash
# Same seed = same output
python k8s_cluster_generator.py --nodes 10 --use-case microservices --seed 42
```

Different seeds give you variations while maintaining realistic patterns.

## 🔧 Troubleshooting

### Too Many Services?
Try a smaller cluster or different use case:
```bash
# Instead of this:
python k8s_cluster_generator.py --nodes 5 --use-case data_analytics

# Try this:
python k8s_cluster_generator.py --nodes 5 --use-case startup_mvp
```

### Not Enough Services?
Use a larger cluster or more aggressive use case:
```bash
# Instead of this:
python k8s_cluster_generator.py --nodes 100 --use-case startup_mvp

# Try this:
python k8s_cluster_generator.py --nodes 100 --use-case microservices
```

### Want Specific Services?
The generator is probabilistic. Try different seeds:
```bash
# Try different seeds until you get what you want
for i in {1..10}; do
  python k8s_cluster_generator.py --nodes 20 --use-case microservices --seed $i | grep -q "kafka" && echo "Found in seed $i"
done
```

## 📚 Next Steps

1. **Read the full README.md** for detailed documentation
2. **Run examples.sh** to see all use cases in action
3. **Experiment with different parameters** to find your ideal config
4. **Use comparison tools** to analyze differences
5. **Export to CSV** for spreadsheet analysis

## 🎓 Example Workflow

Complete workflow for evaluating cluster configurations:

```bash
# Step 1: Generate multiple cluster sizes
python k8s_cluster_generator.py --nodes 10 --use-case microservices -o cluster_10n.json
python k8s_cluster_generator.py --nodes 20 --use-case microservices -o cluster_20n.json
python k8s_cluster_generator.py --nodes 50 --use-case microservices -o cluster_50n.json

# Step 2: Compare them
python cluster_comparison.py cluster_*.json

# Step 3: Export for analysis
python cluster_csv_export.py cluster_*.json

# Step 4: Review in spreadsheet
# Open clusters_summary.csv in Excel/Google Sheets

# Step 5: Pick your favorite and iterate
python k8s_cluster_generator.py --nodes 20 --use-case microservices --count 10 -o final_variations.json
```

## 🤝 Need Help?

Check these resources:
- Full documentation: `README.md`
- Example scenarios: `examples.sh`
- Service catalog: `scenario_profiles_complete.py`

---

**Happy cluster generating! 🎉**
