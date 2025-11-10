# Kubernetes Realistic Cluster Generator

A sophisticated tool that generates realistic Kubernetes service deployments based on cluster size, use case patterns, and real-world probability distributions.

## 🎯 Overview

This tool simulates real-world Kubernetes cluster configurations by considering:
- **Cluster size** (1-1000+ nodes)
- **Use case patterns** (10 predefined scenarios)
- **Service dependencies** (automatic dependency resolution)
- **Resource constraints** (weighted capacity planning)
- **Conflict resolution** (mutually exclusive services)
- **Probability distributions** (realistic deployment patterns)

## 🚀 Features

### Service Profiles
Each service includes:
- **Resource weight**: Relative resource consumption (1-10 scale)
- **HA requirements**: Whether service needs high availability setup
- **Dependencies**: Automatically resolved service dependencies
- **Conflicts**: Mutually exclusive services (e.g., redis vs valkey)
- **Probability by use case**: Realistic deployment likelihood per scenario
- **Minimum cluster size**: Required cluster size for service

### Use Cases

The generator supports 10 pre-configured use case patterns:

| Use Case | Description | Typical Services |
|----------|-------------|------------------|
| `startup_mvp` | Minimal viable product for startups | Basic observability, single DB, simple networking |
| `microservices` | Modern microservices architecture | Full observability, service mesh, GitOps, multiple DBs |
| `data_analytics` | Big data processing and analytics | Spark/Flink, data lakes, ClickHouse, Kafka |
| `ml_platform` | Machine learning and AI workloads | MLflow, JupyterHub, GPU support, object storage |
| `web_hosting` | Multi-tenant web hosting | Web servers, CMS platforms, CDN |
| `enterprise_internal` | Internal enterprise applications | ERP, PKI, collaboration tools |
| `ecommerce` | E-commerce platforms | High availability DBs, caching, payment processing |
| `saas_platform` | Software-as-a-Service platform | Multi-tenancy, API gateways, full observability |
| `iot_platform` | IoT data ingestion and processing | Time-series DBs, Kafka, stream processing |
| `gaming_backend` | Gaming backend services | Low-latency caching, real-time messaging |

### Cluster Sizes

| Size | Node Range | Typical Use |
|------|-----------|-------------|
| TINY | 1-3 | Development, testing |
| SMALL | 3-10 | Small production, startups |
| MEDIUM | 10-50 | Growing companies |
| LARGE | 50-200 | Enterprise deployments |
| XLARGE | 200+ | Hyperscale operations |

## 📦 Installation

No installation required! Just Python 3.7+

```bash
# Clone or download the script
python k8s_cluster_generator.py --help
```

## 🔧 Usage

### Basic Usage

```bash
# Generate a 10-node microservices cluster
python k8s_cluster_generator.py --nodes 10 --use-case microservices

# Generate a 5-node startup cluster with seed for reproducibility
python k8s_cluster_generator.py --nodes 5 --use-case startup_mvp --seed 42

# Generate with verbose output
python k8s_cluster_generator.py --nodes 20 --use-case saas_platform --verbose
```

### Output to File

```bash
# Save to JSON file
python k8s_cluster_generator.py --nodes 50 --use-case ecommerce -o cluster.json

# Generate multiple variations
python k8s_cluster_generator.py --nodes 15 --use-case microservices --count 5 -o clusters.json
```

### Command-Line Options

```
--nodes, -n          Number of nodes in the cluster (required)
--use-case, -u       Primary use case (required)
                     Choices: startup_mvp, microservices, data_analytics,
                              ml_platform, web_hosting, enterprise_internal,
                              ecommerce, saas_platform, iot_platform, gaming_backend
--seed, -s           Random seed for reproducibility (optional)
--count, -c          Number of clusters to generate (default: 1)
--output, -o         Output file path (JSON format)
--verbose, -v        Show detailed statistics
--help, -h           Show help message
```

## 📊 Output Format

The generator produces JSON with the following structure:

```json
{
  "cluster_metadata": {
    "num_nodes": 10,
    "cluster_size": "SMALL",
    "use_case": "microservices",
    "total_services": 18,
    "total_resource_weight": 73,
    "resource_utilization": "73.0%"
  },
  "services": [
    "argo-cd",
    "cert-manager",
    "etcd",
    "grafana",
    "prometheus",
    ...
  ],
  "services_by_category": {
    "control_plane_core": ["etcd", "kube-state-metrics", "metrics-server"],
    "observability_metrics": ["prometheus", "grafana"],
    ...
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
      "service_mesh": true
    },
    "data_layer": {
      "sql_databases": 1,
      "nosql_databases": 1,
      "caching": true,
      "messaging": true
    }
  }
}
```

## 🎲 Examples

### Example 1: Startup MVP (5 nodes)

```bash
python k8s_cluster_generator.py --nodes 5 --use-case startup_mvp --seed 100
```

**Output**: 14 services including essentials:
- Core: etcd, metrics-server, kube-state-metrics
- Networking: nginx-ingress-controller
- Security: cert-manager, sealed-secrets
- Observability: prometheus, grafana, loki
- Data: postgresql, redis
- GitOps: argo-cd

### Example 2: Microservices Platform (20 nodes)

```bash
python k8s_cluster_generator.py --nodes 20 --use-case microservices --seed 200
```

**Output**: 25+ services including:
- Full observability stack (metrics, logging, tracing)
- Service mesh (Cilium)
- Multiple databases (PostgreSQL, MongoDB, Redis)
- Message queuing (Kafka or RabbitMQ)
- Container registry (Harbor)
- Advanced networking (API gateway)

### Example 3: Data Analytics Platform (100 nodes)

```bash
python k8s_cluster_generator.py --nodes 100 --use-case data_analytics --seed 300 --verbose
```

**Output**: 30+ services including:
- Big data processing (Spark, Flink)
- Analytics databases (ClickHouse)
- Data lakes (Minio, Dremio)
- Workflow orchestration (Airflow)
- ML platform (MLflow, JupyterHub)
- Streaming (Kafka)

### Example 4: E-commerce Platform (50 nodes)

```bash
python k8s_cluster_generator.py --nodes 50 --use-case ecommerce --seed 400 -o ecommerce.json
```

**Output**: High-availability stack with:
- HA databases (PostgreSQL-HA, Redis Cluster)
- Caching layers (Redis, Memcached)
- Full observability
- Advanced security (Vault, Keycloak)
- CDN and edge caching

## 🔬 Technical Details

### Dependency Resolution

The generator automatically resolves service dependencies. For example:
- If **Harbor** is selected, it automatically includes **PostgreSQL** and **Redis**
- If **Kafka** is selected, it automatically includes **Zookeeper**
- If **Keycloak** is selected, it automatically includes **PostgreSQL**

### Conflict Management

Mutually exclusive services are handled intelligently:
- **Redis** conflicts with **Valkey** and **KeyDB** (choose one caching solution)
- **Vault** conflicts with **Sealed-Secrets** (choose one secrets management)
- **Prometheus** conflicts with **VictoriaMetrics** (choose one metrics backend)
- Ingress controllers are mutually exclusive

### Resource Capacity Planning

Each service has a resource weight (1-10), and the generator ensures:
- Total resource weight doesn't exceed `num_nodes × 10`
- Heavier services (like Cassandra, Spark) are only added to larger clusters
- Resource utilization is reported in the output

### Probability Distributions

Services have use-case-specific probabilities:
- **Core services** (etcd, metrics-server): 95-100% probability
- **Common services** (prometheus, grafana): 80-95% probability
- **Specialized services** (Spark, Cassandra): 5-60% probability depending on use case

## 📈 Use Cases in Detail

### Startup MVP
**Philosophy**: Minimize complexity, maximize velocity
- Minimal observability (Prometheus + Grafana)
- Single database (PostgreSQL or MySQL)
- Simple secrets management (Sealed Secrets)
- Basic CI/CD (ArgoCD or Jenkins)

### Microservices
**Philosophy**: Full observability, resilience, automation
- Complete observability stack (metrics, logs, traces)
- Service mesh for traffic management
- Multiple data stores (SQL, NoSQL, caching)
- GitOps workflows
- Container registry

### Data Analytics
**Philosophy**: Big data processing at scale
- Distributed processing (Spark, Flink)
- Analytics databases (ClickHouse)
- Data lakes (MinIO, Dremio)
- Workflow orchestration (Airflow)
- Time-series and search engines

### ML Platform
**Philosophy**: End-to-end ML lifecycle
- Experiment tracking (MLflow)
- Notebook environments (JupyterHub)
- Distributed training (Ray, PyTorch)
- Model serving infrastructure
- Large object storage

### E-commerce
**Philosophy**: High availability, low latency, security
- HA databases with clustering
- Multi-layer caching
- Advanced security (Vault, Keycloak)
- Real-time inventory systems
- Payment processing infrastructure

## 🛠️ Programmatic Usage

You can also use the generator as a Python library:

```python
from k8s_cluster_generator import K8sClusterGenerator, UseCase

# Create generator
generator = K8sClusterGenerator(
    num_nodes=20,
    use_case=UseCase.MICROSERVICES,
    seed=42  # Optional: for reproducibility
)

# Generate cluster
cluster = generator.generate()

# Access results
print(f"Services: {cluster['services']}")
print(f"Resource utilization: {cluster['cluster_metadata']['resource_utilization']}")

# Get services by category
for category, services in cluster['services_by_category'].items():
    print(f"{category}: {', '.join(services)}")
```

## 🎯 Advanced Scenarios

### Generate Multiple Variations

Generate 10 different variations of a 15-node microservices cluster:

```bash
for i in {1..10}; do
  python k8s_cluster_generator.py \
    --nodes 15 \
    --use-case microservices \
    --seed $i \
    -o "cluster_${i}.json"
done
```

### Compare Cluster Sizes

Generate the same use case across different cluster sizes:

```bash
for size in 5 10 20 50 100; do
  python k8s_cluster_generator.py \
    --nodes $size \
    --use-case saas_platform \
    --seed 1000 \
    -o "saas_${size}nodes.json" \
    --verbose
done
```

### Batch Generation

Generate multiple use cases at once:

```bash
for use_case in startup_mvp microservices data_analytics ml_platform; do
  python k8s_cluster_generator.py \
    --nodes 20 \
    --use-case $use_case \
    --seed 5000 \
    -o "${use_case}_cluster.json"
done
```

## 📋 Service Catalog

The generator includes 60+ Kubernetes services across categories:

- **Control Plane** (10): etcd, cert-manager, vault, cilium, nginx-ingress, etc.
- **Observability** (14): prometheus, grafana, loki, tempo, jaeger, etc.
- **Databases - SQL** (8): postgresql, mysql, mariadb, clickhouse, etc.
- **Databases - NoSQL** (12): mongodb, elasticsearch, cassandra, redis, etc.
- **Messaging** (6): kafka, rabbitmq, nats, zookeeper
- **Data Processing** (5): spark, flink, airflow, dremio
- **ML/AI** (6): mlflow, jupyterhub, kuberay, pytorch, tensorflow
- **Web & Apps** (10+): nginx, wordpress, drupal, ghost, etc.

## 🔍 Validation & Testing

The generator implements several validation mechanisms:

1. **Dependency validation**: Ensures all dependencies are met
2. **Conflict detection**: Prevents incompatible services
3. **Resource constraints**: Respects cluster capacity limits
4. **Minimum cluster size**: Enforces size requirements per service

## 🤝 Contributing

To add new services to the catalog:

1. Add service profile to `SERVICE_CATALOG` dictionary
2. Set appropriate probabilities for each use case
3. Define dependencies and conflicts
4. Set resource weight and HA requirements

Example:

```python
"my-service": ServiceProfile(
    name="my-service",
    category="data_processing",
    resource_weight=7,
    requires_ha=True,
    dependencies=["postgresql"],
    conflicts_with=["other-service"],
    probability_by_use_case={
        UseCase.STARTUP_MVP.value: 0.1,
        UseCase.MICROSERVICES.value: 0.3,
        # ... other use cases
    },
    min_cluster_size=ClusterSize.MEDIUM
)
```

## 📝 License

This tool is provided as-is for generating realistic Kubernetes test scenarios.

## 🙏 Acknowledgments

Based on real-world Kubernetes deployment patterns and best practices from:
- Cloud Native Computing Foundation (CNCF)
- Kubernetes production deployment surveys
- Enterprise architecture patterns
- SaaS and platform engineering teams

---

**Generated configurations are for testing and simulation purposes.**
**Always validate configurations against your specific requirements and constraints.**
