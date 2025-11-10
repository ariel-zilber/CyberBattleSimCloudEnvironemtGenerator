"""
Comprehensive Kubernetes Deployment Scenario Profiles
======================================================
This configuration organizes 140+ Kubernetes services into logical deployment scenarios
that represent real-world cluster architectures and use cases.
"""

SCENARIO_PROFILES = {
    # ======================================================================
    # CATEGORY: K8s Control Plane & Core Services
    # ======================================================================
    
    "control_plane_core": {
        "description": "Essential services required for a Kubernetes cluster to function and manage itself.",
        "criticality": "critical",
        "services": [
            "etcd",
            "kube-state-metrics",
            "metrics-server",
            "external-dns",
            "common"  # Common libraries/charts
        ]
    },
    
    "control_plane_security": {
        "description": "Security, identity, and secrets management services. The 'crown jewels' of the control plane.",
        "criticality": "critical",
        "services": [
            "vault",
            "keycloak",
            "oauth2-proxy",
            "pinniped",
            "cert-manager",
            "sealed-secrets",
            "chainloop"  # Software supply chain security
        ]
    },

    "control_plane_networking": {
        "description": "Ingress, CNI, and service mesh components that manage north-south and east-west traffic.",
        "criticality": "critical",
        "services": [
            "cilium",
            "multus-cni",
            "nginx-ingress-controller",
            "apisix",
            "contour",
            "envoy-gateway",
            "haproxy",
            "kong",
            "metallb",
            "whereabouts"  # IP Address Management (IPAM) CNI plugin
        ]
    },

    # ======================================================================
    # CATEGORY: DevOps & GitOps
    # ======================================================================

    "ci_cd_pipeline": {
        "description": "Complete GitOps & CI/CD pipeline for building, testing, and deploying applications.",
        "criticality": "high",
        "services": [
            "gitea",
            "gitlab-runner",
            "jenkins",
            "concourse",
            "argo-cd",
            "argo-workflows",
            "flux",
            "harbor",
            "sonarqube",  # Code quality and security
            "chainloop"   # Supply chain security
        ]
    },

    # ======================================================================
    # CATEGORY: Observability Stack
    # ======================================================================

    "observability_metrics": {
        "description": "Metrics collection, storage, and visualization stack.",
        "criticality": "high",
        "services": [
            "prometheus",
            "grafana",
            "grafana-mimir",
            "thanos",
            "victoriametrics",
            "cadvisor",
            "node-exporter",
            "kube-prometheus"
        ]
    },

    "observability_logging": {
        "description": "Centralized logging collection, aggregation, and analysis.",
        "criticality": "high",
        "services": [
            "grafana-loki",
            "fluent-bit",
            "fluentd",
            "elasticsearch",
            "opensearch",
            "logstash",
            "kibana"
        ]
    },

    "observability_tracing": {
        "description": "Distributed tracing for microservices observability.",
        "criticality": "medium",
        "services": [
            "grafana-tempo",
            "jaeger",
            "zipkin",
            "grafana-alloy"  # OpenTelemetry collector
        ]
    },
    
    "observability_operators": {
        "description": "Specialized operators for managing observability components.",
        "criticality": "medium",
        "services": [
            "grafana-operator",
            "grafana-k6-operator",
            "kubernetes-event-exporter"
        ]
    },

    # ======================================================================
    # CATEGORY: Data & Storage - SQL Databases
    # ======================================================================

    "data_sql_standard": {
        "description": "Standard single-instance SQL databases for small to medium workloads.",
        "criticality": "high",
        "services": [
            "postgresql",
            "mysql",
            "mariadb"
        ]
    },

    "data_sql_ha_clustered": {
        "description": "High-availability and clustered SQL databases for production workloads.",
        "criticality": "high",
        "services": [
            "postgresql-ha",
            "cloudnative-pg",
            "mariadb-galera"
        ]
    },
    
    "data_sql_analytics": {
        "description": "Column-oriented SQL databases optimized for OLAP and analytics.",
        "criticality": "medium",
        "services": [
            "clickhouse",
            "clickhouse-operator"
        ]
    },

    # ======================================================================
    # CATEGORY: Data & Storage - NoSQL Databases
    # ======================================================================

    "data_nosql_document": {
        "description": "Document-oriented NoSQL databases for flexible schema applications.",
        "criticality": "high",
        "services": [
            "mongodb",
            "mongodb-sharded"
        ]
    },

    "data_nosql_search": {
        "description": "Full-text search and analytics engines (ELK/OpenSearch stacks).",
        "criticality": "high",
        "services": [
            "elasticsearch",
            "opensearch",
            "logstash",
            "kibana",
            "solr"  # Apache Solr search platform
        ]
    },

    "data_nosql_wide_column": {
        "description": "Wide-column stores for massive scale and high-throughput workloads.",
        "criticality": "medium",
        "services": [
            "cassandra",
            "scylladb"
        ]
    },

    "data_nosql_graph": {
        "description": "Graph databases for relationship-heavy data modeling.",
        "criticality": "medium",
        "services": [
            "neo4j",
            "janusgraph",
            "kube-arangodb"  # Multi-model (includes graph)
        ]
    },

    "data_nosql_timeseries": {
        "description": "Time-series databases for IoT, metrics, and monitoring data.",
        "criticality": "medium",
        "services": [
            "influxdb",
            "victoriametrics"
        ]
    },

    "data_nosql_vector": {
        "description": "Vector databases for AI/ML embeddings and similarity search.",
        "criticality": "medium",
        "services": [
            "milvus"
        ]
    },

    # ======================================================================
    # CATEGORY: Data & Storage - Caching & Messaging
    # ======================================================================

    "data_caching_inmemory": {
        "description": "In-memory key-value stores and caches for performance optimization.",
        "criticality": "high",
        "services": [
            "redis",
            "redis-cluster",
            "valkey",
            "valkey-cluster",
            "keydb",
            "memcached"
        ]
    },

    "data_messaging_streaming": {
        "description": "Event streaming platforms for real-time data pipelines.",
        "criticality": "high",
        "services": [
            "kafka",
            "schema-registry",
            "zookeeper"
        ]
    },

    "data_messaging_queuing": {
        "description": "Message queuing systems for asynchronous communication.",
        "criticality": "high",
        "services": [
            "rabbitmq",
            "rabbitmq-cluster-operator",
            "nats"
        ]
    },

    # ======================================================================
    # CATEGORY: Data & Storage - Object Storage & Filesystems
    # ======================================================================

    "data_storage_object": {
        "description": "Object storage and distributed file systems for unstructured data.",
        "criticality": "medium",
        "services": [
            "minio",
            "minio-operator",
            "seaweedfs"
        ]
    },

    # ======================================================================
    # CATEGORY: Data Processing & Analytics
    # ======================================================================

    "data_big_data_batch": {
        "description": "Batch processing engines for big data analytics.",
        "criticality": "medium",
        "services": [
            "spark"
        ]
    },

    "data_big_data_streaming": {
        "description": "Stream processing engines for real-time analytics.",
        "criticality": "medium",
        "services": [
            "flink"
        ]
    },

    "data_lakehouse": {
        "description": "Data lakehouse and query engines for unified analytics.",
        "criticality": "medium",
        "services": [
            "dremio",
            "nessie"  # Data version control for data lakes
        ]
    },

    "data_workflow_orchestration": {
        "description": "Workflow orchestration and data pipeline management.",
        "criticality": "medium",
        "services": [
            "airflow"
        ]
    },

    # ======================================================================
    # CATEGORY: AI/ML & Data Science
    # ======================================================================

    "ai_ml_platform": {
        "description": "Complete ML platforms for experiment tracking and model management.",
        "criticality": "medium",
        "services": [
            "mlflow",
            "jupyterhub",
            "kuberay"
        ]
    },

    "ai_ml_training": {
        "description": "Deep learning frameworks and distributed training systems.",
        "criticality": "medium",
        "services": [
            "pytorch",
            "tensorflow-resnet",
            "deepspeed"
        ]
    },

    "ai_ml_inference": {
        "description": "Model serving and inference platforms.",
        "criticality": "medium",
        "services": [
            "kuberay"  # Ray Serve for model serving
        ]
    },

    # ======================================================================
    # CATEGORY: Web Applications - Public Facing
    # ======================================================================

    "web_servers_static": {
        "description": "General-purpose web servers for static and dynamic content.",
        "criticality": "high",
        "services": [
            "nginx",
            "apache",
            "tomcat",
            "wildfly"
        ]
    },

    "web_cms_blogs": {
        "description": "Content Management Systems and blogging platforms.",
        "criticality": "medium",
        "services": [
            "wordpress",
            "drupal",
            "ghost",
            "moodle"
        ]
    },

    "web_social_community": {
        "description": "Social media and community platforms.",
        "criticality": "medium",
        "services": [
            "mastodon",
            "discourse"
        ]
    },

    # ======================================================================
    # CATEGORY: Web Applications - Internal Tools
    # ======================================================================

    "web_admin_tools": {
        "description": "Database administration and management tools.",
        "criticality": "low",
        "services": [
            "phpmyadmin"
        ]
    },

    "web_analytics_bi": {
        "description": "Business intelligence and analytics platforms.",
        "criticality": "medium",
        "services": [
            "superset",
            "matomo"
        ]
    },

    "web_low_code_platforms": {
        "description": "Low-code/no-code application development platforms.",
        "criticality": "medium",
        "services": [
            "appsmith"
        ]
    },

    # ======================================================================
    # CATEGORY: Enterprise Applications
    # ======================================================================

    "enterprise_erp": {
        "description": "Enterprise Resource Planning systems.",
        "criticality": "high",
        "services": [
            "odoo"
        ]
    },

    "enterprise_project_management": {
        "description": "Project management and issue tracking systems.",
        "criticality": "medium",
        "services": [
            "redmine"
        ]
    },

    "enterprise_pki": {
        "description": "Public Key Infrastructure and certificate management.",
        "criticality": "high",
        "services": [
            "ejbca"
        ]
    },

    # ======================================================================
    # CATEGORY: Backend Services & APIs
    # ======================================================================

    "backend_baas": {
        "description": "Backend-as-a-Service platforms for mobile/web apps.",
        "criticality": "medium",
        "services": [
            "parse"
        ]
    },

    "backend_aspnet": {
        "description": "ASP.NET Core application hosting.",
        "criticality": "medium",
        "services": [
            "aspnet-core"
        ]
    },

    # ======================================================================
    # CATEGORY: Complete Stack Scenarios (Pre-composed)
    # ======================================================================

    "scenario_startup_minimal": {
        "description": "Minimal viable production cluster for a startup (core services only).",
        "criticality": "varies",
        "includes_profiles": [
            "control_plane_core",
            "control_plane_security",
            "control_plane_networking",
            "observability_metrics",
            "data_sql_standard",
            "data_caching_inmemory"
        ]
    },

    "scenario_microservices_platform": {
        "description": "Complete platform for running microservices with full observability.",
        "criticality": "varies",
        "includes_profiles": [
            "control_plane_core",
            "control_plane_security",
            "control_plane_networking",
            "ci_cd_pipeline",
            "observability_metrics",
            "observability_logging",
            "observability_tracing",
            "data_sql_ha_clustered",
            "data_nosql_document",
            "data_caching_inmemory",
            "data_messaging_streaming"
        ]
    },

    "scenario_data_platform": {
        "description": "Comprehensive data platform with analytics, ML, and data lake capabilities.",
        "criticality": "varies",
        "includes_profiles": [
            "control_plane_core",
            "control_plane_security",
            "data_sql_analytics",
            "data_nosql_search",
            "data_big_data_batch",
            "data_big_data_streaming",
            "data_lakehouse",
            "data_workflow_orchestration",
            "data_storage_object",
            "ai_ml_platform",
            "web_analytics_bi"
        ]
    },

    "scenario_ml_training_platform": {
        "description": "Platform optimized for machine learning training and experimentation.",
        "criticality": "varies",
        "includes_profiles": [
            "control_plane_core",
            "ai_ml_platform",
            "ai_ml_training",
            "data_storage_object",
            "data_nosql_vector",
            "observability_metrics"
        ]
    },

    "scenario_web_hosting_platform": {
        "description": "Multi-tenant web hosting platform with CMS support.",
        "criticality": "varies",
        "includes_profiles": [
            "control_plane_core",
            "control_plane_security",
            "control_plane_networking",
            "web_servers_static",
            "web_cms_blogs",
            "data_sql_ha_clustered",
            "data_caching_inmemory",
            "observability_metrics",
            "observability_logging"
        ]
    },

    "scenario_enterprise_intranet": {
        "description": "Internal enterprise applications and collaboration platform.",
        "criticality": "varies",
        "includes_profiles": [
            "control_plane_core",
            "control_plane_security",
            "enterprise_erp",
            "enterprise_project_management",
            "enterprise_pki",
            "web_social_community",
            "data_sql_ha_clustered",
            "observability_metrics"
        ]
    },

    "scenario_observability_central": {
        "description": "Centralized observability platform for monitoring multiple clusters.",
        "criticality": "varies",
        "includes_profiles": [
            "control_plane_core",
            "observability_metrics",
            "observability_logging",
            "observability_tracing",
            "observability_operators",
            "data_nosql_search",
            "data_nosql_timeseries"
        ]
    }
}


# ======================================================================
# Helper Functions
# ======================================================================

def get_all_services_in_profile(profile_name):
    """Get all services in a profile, including nested profile references."""
    profile = SCENARIO_PROFILES.get(profile_name)
    if not profile:
        return []
    
    services = set(profile.get("services", []))
    
    # Handle nested profiles
    for nested_profile in profile.get("includes_profiles", []):
        services.update(get_all_services_in_profile(nested_profile))
    
    return sorted(list(services))


def list_profiles_by_category():
    """Organize profiles by their category prefix."""
    categories = {}
    for profile_name in SCENARIO_PROFILES.keys():
        category = profile_name.split('_')[0]
        if category not in categories:
            categories[category] = []
        categories[category].append(profile_name)
    return categories


def get_service_usage_count():
    """Count how many profiles each service appears in."""
    service_counts = {}
    for profile_name, profile_data in SCENARIO_PROFILES.items():
        for service in get_all_services_in_profile(profile_name):
            service_counts[service] = service_counts.get(service, 0) + 1
    return dict(sorted(service_counts.items(), key=lambda x: x[1], reverse=True))


# ======================================================================
# Usage Examples
# ======================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("KUBERNETES DEPLOYMENT SCENARIO PROFILES")
    print("=" * 80)
    
    # Example 1: Get all services for microservices platform
    print("\n📦 Services in 'scenario_microservices_platform':")
    services = get_all_services_in_profile("scenario_microservices_platform")
    print(f"Total services: {len(services)}")
    for service in services[:10]:  # Show first 10
        print(f"  - {service}")
    print(f"  ... and {len(services) - 10} more")
    
    # Example 2: List profiles by category
    print("\n📂 Profiles by Category:")
    categories = list_profiles_by_category()
    for category, profiles in sorted(categories.items()):
        print(f"\n  {category.upper()}:")
        for profile in profiles[:3]:  # Show first 3 per category
            desc = SCENARIO_PROFILES[profile].get("description", "")[:60]
            print(f"    - {profile}: {desc}...")
    
    # Example 3: Most commonly used services
    print("\n⭐ Top 10 Most Used Services Across All Profiles:")
    service_counts = get_service_usage_count()
    for service, count in list(service_counts.items())[:10]:
        print(f"  - {service}: used in {count} profiles")
