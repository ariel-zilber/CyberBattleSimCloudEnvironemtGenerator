"""
Kubernetes Realistic Cluster Generator
=======================================
Generates realistic Kubernetes service deployments based on:
- Cluster size (number of nodes)
- Use case patterns (startup, enterprise, data platform, etc.)
- Resource constraints and dependencies
- Real-world deployment probability distributions

Author: Auto-generated
Date: 2025-11-07
"""

import random
import json
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum


# ======================================================================
# Configuration and Constants
# ======================================================================

class ClusterSize(Enum):
    """Cluster size categories with node ranges"""
    TINY = (1, 3)           # Dev/testing
    SMALL = (3, 10)         # Small production/startup
    MEDIUM = (10, 50)       # Growing company
    LARGE = (50, 200)       # Enterprise
    XLARGE = (200, 1000)    # Hyperscale


class UseCase(Enum):
    """Common cluster use cases"""
    STARTUP_MVP = "startup_mvp"
    MICROSERVICES = "microservices"
    DATA_ANALYTICS = "data_analytics"
    ML_PLATFORM = "ml_platform"
    WEB_HOSTING = "web_hosting"
    ENTERPRISE_INTERNAL = "enterprise_internal"
    ECOMMERCE = "ecommerce"
    SAAS_PLATFORM = "saas_platform"
    IOT_PLATFORM = "iot_platform"
    GAMING_BACKEND = "gaming_backend"


@dataclass
class ServiceProfile:
    """Metadata about a service"""
    name: str
    category: str
    resource_weight: int  # 1-10, relative resource consumption
    requires_ha: bool  # Needs HA setup in prod
    dependencies: List[str]
    conflicts_with: List[str]
    probability_by_use_case: Dict[str, float]
    min_cluster_size: ClusterSize
    base_instance_count: int = 1  # Base number of instances for small clusters
    scale_with_cluster: bool = False  # Whether to scale instances with cluster size


# ======================================================================
# Service Catalog with Realistic Profiles
# ======================================================================

SERVICE_CATALOG = {
    # Control Plane - Always present or very high probability
    "etcd": ServiceProfile(
        name="etcd",
        category="control_plane_core",
        resource_weight=5,
        requires_ha=True,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 1.0,
            UseCase.MICROSERVICES.value: 1.0,
            UseCase.DATA_ANALYTICS.value: 1.0,
            UseCase.ML_PLATFORM.value: 1.0,
            UseCase.WEB_HOSTING.value: 1.0,
            UseCase.ENTERPRISE_INTERNAL.value: 1.0,
            UseCase.ECOMMERCE.value: 1.0,
            UseCase.SAAS_PLATFORM.value: 1.0,
            UseCase.IOT_PLATFORM.value: 1.0,
            UseCase.GAMING_BACKEND.value: 1.0,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=3,  # etcd always runs 3 or 5 nodes for HA
        scale_with_cluster=True  # Scale to 5 for larger clusters
    ),
    
    "kube-state-metrics": ServiceProfile(
        name="kube-state-metrics",
        category="control_plane_core",
        resource_weight=2,
        requires_ha=False,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.9,
            UseCase.MICROSERVICES.value: 0.95,
            UseCase.DATA_ANALYTICS.value: 0.9,
            UseCase.ML_PLATFORM.value: 0.85,
            UseCase.WEB_HOSTING.value: 0.9,
            UseCase.ENTERPRISE_INTERNAL.value: 0.95,
            UseCase.ECOMMERCE.value: 0.95,
            UseCase.SAAS_PLATFORM.value: 0.95,
            UseCase.IOT_PLATFORM.value: 0.9,
            UseCase.GAMING_BACKEND.value: 0.9,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=1,
        scale_with_cluster=False
    ),
    
    "metrics-server": ServiceProfile(
        name="metrics-server",
        category="control_plane_core",
        resource_weight=2,
        requires_ha=False,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.95,
            UseCase.MICROSERVICES.value: 0.98,
            UseCase.DATA_ANALYTICS.value: 0.95,
            UseCase.ML_PLATFORM.value: 0.9,
            UseCase.WEB_HOSTING.value: 0.95,
            UseCase.ENTERPRISE_INTERNAL.value: 0.98,
            UseCase.ECOMMERCE.value: 0.98,
            UseCase.SAAS_PLATFORM.value: 0.98,
            UseCase.IOT_PLATFORM.value: 0.95,
            UseCase.GAMING_BACKEND.value: 0.95,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=1,
        scale_with_cluster=False
    ),
    
    "cert-manager": ServiceProfile(
        name="cert-manager",
        category="control_plane_security",
        resource_weight=3,
        requires_ha=False,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.7,
            UseCase.MICROSERVICES.value: 0.9,
            UseCase.DATA_ANALYTICS.value: 0.6,
            UseCase.ML_PLATFORM.value: 0.5,
            UseCase.WEB_HOSTING.value: 0.95,
            UseCase.ENTERPRISE_INTERNAL.value: 0.9,
            UseCase.ECOMMERCE.value: 0.98,
            UseCase.SAAS_PLATFORM.value: 0.95,
            UseCase.IOT_PLATFORM.value: 0.7,
            UseCase.GAMING_BACKEND.value: 0.8,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=1,
        scale_with_cluster=False
    ),
    
    "vault": ServiceProfile(
        name="vault",
        category="control_plane_security",
        resource_weight=4,
        requires_ha=True,
        dependencies=[],
        conflicts_with=["sealed-secrets"],  # Often choose one or the other
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.2,
            UseCase.MICROSERVICES.value: 0.5,
            UseCase.DATA_ANALYTICS.value: 0.3,
            UseCase.ML_PLATFORM.value: 0.3,
            UseCase.WEB_HOSTING.value: 0.4,
            UseCase.ENTERPRISE_INTERNAL.value: 0.7,
            UseCase.ECOMMERCE.value: 0.8,
            UseCase.SAAS_PLATFORM.value: 0.7,
            UseCase.IOT_PLATFORM.value: 0.5,
            UseCase.GAMING_BACKEND.value: 0.6,
        },
        min_cluster_size=ClusterSize.SMALL,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "sealed-secrets": ServiceProfile(
        name="sealed-secrets",
        category="control_plane_security",
        resource_weight=2,
        requires_ha=False,
        dependencies=[],
        conflicts_with=["vault"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.5,
            UseCase.MICROSERVICES.value: 0.3,
            UseCase.DATA_ANALYTICS.value: 0.4,
            UseCase.ML_PLATFORM.value: 0.4,
            UseCase.WEB_HOSTING.value: 0.3,
            UseCase.ENTERPRISE_INTERNAL.value: 0.2,
            UseCase.ECOMMERCE.value: 0.1,
            UseCase.SAAS_PLATFORM.value: 0.2,
            UseCase.IOT_PLATFORM.value: 0.3,
            UseCase.GAMING_BACKEND.value: 0.2,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=1,
        scale_with_cluster=False
    ),
    
    "keycloak": ServiceProfile(
        name="keycloak",
        category="control_plane_security",
        resource_weight=5,
        requires_ha=True,
        dependencies=["postgresql"],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.1,
            UseCase.MICROSERVICES.value: 0.4,
            UseCase.DATA_ANALYTICS.value: 0.2,
            UseCase.ML_PLATFORM.value: 0.3,
            UseCase.WEB_HOSTING.value: 0.3,
            UseCase.ENTERPRISE_INTERNAL.value: 0.7,
            UseCase.ECOMMERCE.value: 0.6,
            UseCase.SAAS_PLATFORM.value: 0.8,
            UseCase.IOT_PLATFORM.value: 0.4,
            UseCase.GAMING_BACKEND.value: 0.5,
        },
        min_cluster_size=ClusterSize.SMALL,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    # Networking
    "nginx-ingress-controller": ServiceProfile(
        name="nginx-ingress-controller",
        category="control_plane_networking",
        resource_weight=3,
        requires_ha=True,
        dependencies=[],
        conflicts_with=["kong", "apisix", "contour", "haproxy"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.8,
            UseCase.MICROSERVICES.value: 0.7,
            UseCase.DATA_ANALYTICS.value: 0.5,
            UseCase.ML_PLATFORM.value: 0.4,
            UseCase.WEB_HOSTING.value: 0.9,
            UseCase.ENTERPRISE_INTERNAL.value: 0.6,
            UseCase.ECOMMERCE.value: 0.7,
            UseCase.SAAS_PLATFORM.value: 0.6,
            UseCase.IOT_PLATFORM.value: 0.5,
            UseCase.GAMING_BACKEND.value: 0.6,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "kong": ServiceProfile(
        name="kong",
        category="control_plane_networking",
        resource_weight=4,
        requires_ha=True,
        dependencies=["postgresql"],
        conflicts_with=["nginx-ingress-controller", "apisix"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.1,
            UseCase.MICROSERVICES.value: 0.25,
            UseCase.DATA_ANALYTICS.value: 0.1,
            UseCase.ML_PLATFORM.value: 0.2,
            UseCase.WEB_HOSTING.value: 0.1,
            UseCase.ENTERPRISE_INTERNAL.value: 0.2,
            UseCase.ECOMMERCE.value: 0.3,
            UseCase.SAAS_PLATFORM.value: 0.35,
            UseCase.IOT_PLATFORM.value: 0.3,
            UseCase.GAMING_BACKEND.value: 0.25,
        },
        min_cluster_size=ClusterSize.SMALL,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "cilium": ServiceProfile(
        name="cilium",
        category="control_plane_networking",
        resource_weight=4,
        requires_ha=False,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.1,
            UseCase.MICROSERVICES.value: 0.3,
            UseCase.DATA_ANALYTICS.value: 0.2,
            UseCase.ML_PLATFORM.value: 0.2,
            UseCase.WEB_HOSTING.value: 0.2,
            UseCase.ENTERPRISE_INTERNAL.value: 0.4,
            UseCase.ECOMMERCE.value: 0.35,
            UseCase.SAAS_PLATFORM.value: 0.4,
            UseCase.IOT_PLATFORM.value: 0.25,
            UseCase.GAMING_BACKEND.value: 0.3,
        },
        min_cluster_size=ClusterSize.MEDIUM,
        base_instance_count=1,
        scale_with_cluster=False
    ),
    
    # Observability - Metrics
    "prometheus": ServiceProfile(
        name="prometheus",
        category="observability_metrics",
        resource_weight=5,
        requires_ha=True,
        dependencies=[],
        conflicts_with=["victoriametrics"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.85,
            UseCase.MICROSERVICES.value: 0.95,
            UseCase.DATA_ANALYTICS.value: 0.8,
            UseCase.ML_PLATFORM.value: 0.8,
            UseCase.WEB_HOSTING.value: 0.9,
            UseCase.ENTERPRISE_INTERNAL.value: 0.9,
            UseCase.ECOMMERCE.value: 0.95,
            UseCase.SAAS_PLATFORM.value: 0.95,
            UseCase.IOT_PLATFORM.value: 0.85,
            UseCase.GAMING_BACKEND.value: 0.9,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "grafana": ServiceProfile(
        name="grafana",
        category="observability_metrics",
        resource_weight=3,
        requires_ha=False,
        dependencies=["prometheus"],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.9,
            UseCase.MICROSERVICES.value: 0.95,
            UseCase.DATA_ANALYTICS.value: 0.9,
            UseCase.ML_PLATFORM.value: 0.85,
            UseCase.WEB_HOSTING.value: 0.9,
            UseCase.ENTERPRISE_INTERNAL.value: 0.95,
            UseCase.ECOMMERCE.value: 0.98,
            UseCase.SAAS_PLATFORM.value: 0.98,
            UseCase.IOT_PLATFORM.value: 0.9,
            UseCase.GAMING_BACKEND.value: 0.95,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=1,
        scale_with_cluster=False
    ),
    
    "thanos": ServiceProfile(
        name="thanos",
        category="observability_metrics",
        resource_weight=6,
        requires_ha=True,
        dependencies=["prometheus", "minio"],
        conflicts_with=["victoriametrics"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.05,
            UseCase.MICROSERVICES.value: 0.3,
            UseCase.DATA_ANALYTICS.value: 0.2,
            UseCase.ML_PLATFORM.value: 0.15,
            UseCase.WEB_HOSTING.value: 0.2,
            UseCase.ENTERPRISE_INTERNAL.value: 0.5,
            UseCase.ECOMMERCE.value: 0.4,
            UseCase.SAAS_PLATFORM.value: 0.45,
            UseCase.IOT_PLATFORM.value: 0.3,
            UseCase.GAMING_BACKEND.value: 0.35,
        },
        min_cluster_size=ClusterSize.MEDIUM,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    # Observability - Logging
    "grafana-loki": ServiceProfile(
        name="grafana-loki",
        category="observability_logging",
        resource_weight=5,
        requires_ha=True,
        dependencies=[],
        conflicts_with=["elasticsearch"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.6,
            UseCase.MICROSERVICES.value: 0.7,
            UseCase.DATA_ANALYTICS.value: 0.5,
            UseCase.ML_PLATFORM.value: 0.5,
            UseCase.WEB_HOSTING.value: 0.65,
            UseCase.ENTERPRISE_INTERNAL.value: 0.5,
            UseCase.ECOMMERCE.value: 0.6,
            UseCase.SAAS_PLATFORM.value: 0.65,
            UseCase.IOT_PLATFORM.value: 0.55,
            UseCase.GAMING_BACKEND.value: 0.6,
        },
        min_cluster_size=ClusterSize.SMALL,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "fluent-bit": ServiceProfile(
        name="fluent-bit",
        category="observability_logging",
        resource_weight=2,
        requires_ha=False,
        dependencies=[],
        conflicts_with=["fluentd"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.7,
            UseCase.MICROSERVICES.value: 0.8,
            UseCase.DATA_ANALYTICS.value: 0.7,
            UseCase.ML_PLATFORM.value: 0.65,
            UseCase.WEB_HOSTING.value: 0.75,
            UseCase.ENTERPRISE_INTERNAL.value: 0.7,
            UseCase.ECOMMERCE.value: 0.8,
            UseCase.SAAS_PLATFORM.value: 0.8,
            UseCase.IOT_PLATFORM.value: 0.75,
            UseCase.GAMING_BACKEND.value: 0.75,
        },
        min_cluster_size=ClusterSize.SMALL,
        base_instance_count=1,
        scale_with_cluster=False
    ),
    
    "elasticsearch": ServiceProfile(
        name="elasticsearch",
        category="observability_logging",
        resource_weight=8,
        requires_ha=True,
        dependencies=[],
        conflicts_with=["grafana-loki", "opensearch"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.2,
            UseCase.MICROSERVICES.value: 0.3,
            UseCase.DATA_ANALYTICS.value: 0.4,
            UseCase.ML_PLATFORM.value: 0.3,
            UseCase.WEB_HOSTING.value: 0.25,
            UseCase.ENTERPRISE_INTERNAL.value: 0.45,
            UseCase.ECOMMERCE.value: 0.5,
            UseCase.SAAS_PLATFORM.value: 0.4,
            UseCase.IOT_PLATFORM.value: 0.35,
            UseCase.GAMING_BACKEND.value: 0.35,
        },
        min_cluster_size=ClusterSize.MEDIUM,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "kibana": ServiceProfile(
        name="kibana",
        category="observability_logging",
        resource_weight=3,
        requires_ha=False,
        dependencies=["elasticsearch"],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.95,
            UseCase.MICROSERVICES.value: 0.95,
            UseCase.DATA_ANALYTICS.value: 0.95,
            UseCase.ML_PLATFORM.value: 0.9,
            UseCase.WEB_HOSTING.value: 0.95,
            UseCase.ENTERPRISE_INTERNAL.value: 0.98,
            UseCase.ECOMMERCE.value: 0.98,
            UseCase.SAAS_PLATFORM.value: 0.98,
            UseCase.IOT_PLATFORM.value: 0.95,
            UseCase.GAMING_BACKEND.value: 0.95,
        },
        min_cluster_size=ClusterSize.MEDIUM,
        base_instance_count=1,
        scale_with_cluster=False
    ),
    
    # Observability - Tracing
    "jaeger": ServiceProfile(
        name="jaeger",
        category="observability_tracing",
        resource_weight=4,
        requires_ha=True,
        dependencies=[],
        conflicts_with=["zipkin", "grafana-tempo"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.15,
            UseCase.MICROSERVICES.value: 0.6,
            UseCase.DATA_ANALYTICS.value: 0.2,
            UseCase.ML_PLATFORM.value: 0.25,
            UseCase.WEB_HOSTING.value: 0.3,
            UseCase.ENTERPRISE_INTERNAL.value: 0.4,
            UseCase.ECOMMERCE.value: 0.7,
            UseCase.SAAS_PLATFORM.value: 0.65,
            UseCase.IOT_PLATFORM.value: 0.4,
            UseCase.GAMING_BACKEND.value: 0.5,
        },
        min_cluster_size=ClusterSize.SMALL,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "grafana-tempo": ServiceProfile(
        name="grafana-tempo",
        category="observability_tracing",
        resource_weight=5,
        requires_ha=True,
        dependencies=["grafana"],
        conflicts_with=["jaeger", "zipkin"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.1,
            UseCase.MICROSERVICES.value: 0.3,
            UseCase.DATA_ANALYTICS.value: 0.15,
            UseCase.ML_PLATFORM.value: 0.15,
            UseCase.WEB_HOSTING.value: 0.2,
            UseCase.ENTERPRISE_INTERNAL.value: 0.25,
            UseCase.ECOMMERCE.value: 0.35,
            UseCase.SAAS_PLATFORM.value: 0.35,
            UseCase.IOT_PLATFORM.value: 0.25,
            UseCase.GAMING_BACKEND.value: 0.3,
        },
        min_cluster_size=ClusterSize.SMALL,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    # CI/CD
    "argo-cd": ServiceProfile(
        name="argo-cd",
        category="ci_cd",
        resource_weight=3,
        requires_ha=True,
        dependencies=[],
        conflicts_with=["flux"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.5,
            UseCase.MICROSERVICES.value: 0.7,
            UseCase.DATA_ANALYTICS.value: 0.4,
            UseCase.ML_PLATFORM.value: 0.5,
            UseCase.WEB_HOSTING.value: 0.6,
            UseCase.ENTERPRISE_INTERNAL.value: 0.65,
            UseCase.ECOMMERCE.value: 0.7,
            UseCase.SAAS_PLATFORM.value: 0.75,
            UseCase.IOT_PLATFORM.value: 0.55,
            UseCase.GAMING_BACKEND.value: 0.65,
        },
        min_cluster_size=ClusterSize.SMALL,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "jenkins": ServiceProfile(
        name="jenkins",
        category="ci_cd",
        resource_weight=5,
        requires_ha=False,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.3,
            UseCase.MICROSERVICES.value: 0.4,
            UseCase.DATA_ANALYTICS.value: 0.3,
            UseCase.ML_PLATFORM.value: 0.35,
            UseCase.WEB_HOSTING.value: 0.35,
            UseCase.ENTERPRISE_INTERNAL.value: 0.6,
            UseCase.ECOMMERCE.value: 0.45,
            UseCase.SAAS_PLATFORM.value: 0.5,
            UseCase.IOT_PLATFORM.value: 0.4,
            UseCase.GAMING_BACKEND.value: 0.45,
        },
        min_cluster_size=ClusterSize.SMALL,
        base_instance_count=1,
        scale_with_cluster=False
    ),
    
    "harbor": ServiceProfile(
        name="harbor",
        category="ci_cd",
        resource_weight=6,
        requires_ha=True,
        dependencies=["postgresql", "redis"],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.2,
            UseCase.MICROSERVICES.value: 0.5,
            UseCase.DATA_ANALYTICS.value: 0.3,
            UseCase.ML_PLATFORM.value: 0.4,
            UseCase.WEB_HOSTING.value: 0.35,
            UseCase.ENTERPRISE_INTERNAL.value: 0.6,
            UseCase.ECOMMERCE.value: 0.55,
            UseCase.SAAS_PLATFORM.value: 0.65,
            UseCase.IOT_PLATFORM.value: 0.45,
            UseCase.GAMING_BACKEND.value: 0.5,
        },
        min_cluster_size=ClusterSize.MEDIUM,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    # Databases - SQL
    "postgresql": ServiceProfile(
        name="postgresql",
        category="data_sql",
        resource_weight=6,
        requires_ha=True,
        dependencies=[],
        conflicts_with=["mysql", "mariadb"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.7,
            UseCase.MICROSERVICES.value: 0.75,
            UseCase.DATA_ANALYTICS.value: 0.6,
            UseCase.ML_PLATFORM.value: 0.5,
            UseCase.WEB_HOSTING.value: 0.65,
            UseCase.ENTERPRISE_INTERNAL.value: 0.7,
            UseCase.ECOMMERCE.value: 0.8,
            UseCase.SAAS_PLATFORM.value: 0.85,
            UseCase.IOT_PLATFORM.value: 0.6,
            UseCase.GAMING_BACKEND.value: 0.7,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "mysql": ServiceProfile(
        name="mysql",
        category="data_sql",
        resource_weight=6,
        requires_ha=True,
        dependencies=[],
        conflicts_with=["postgresql", "mariadb"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.2,
            UseCase.MICROSERVICES.value: 0.15,
            UseCase.DATA_ANALYTICS.value: 0.2,
            UseCase.ML_PLATFORM.value: 0.2,
            UseCase.WEB_HOSTING.value: 0.3,
            UseCase.ENTERPRISE_INTERNAL.value: 0.2,
            UseCase.ECOMMERCE.value: 0.15,
            UseCase.SAAS_PLATFORM.value: 0.1,
            UseCase.IOT_PLATFORM.value: 0.2,
            UseCase.GAMING_BACKEND.value: 0.2,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "clickhouse": ServiceProfile(
        name="clickhouse",
        category="data_analytics",
        resource_weight=8,
        requires_ha=True,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.05,
            UseCase.MICROSERVICES.value: 0.15,
            UseCase.DATA_ANALYTICS.value: 0.6,
            UseCase.ML_PLATFORM.value: 0.3,
            UseCase.WEB_HOSTING.value: 0.1,
            UseCase.ENTERPRISE_INTERNAL.value: 0.3,
            UseCase.ECOMMERCE.value: 0.4,
            UseCase.SAAS_PLATFORM.value: 0.35,
            UseCase.IOT_PLATFORM.value: 0.5,
            UseCase.GAMING_BACKEND.value: 0.3,
        },
        min_cluster_size=ClusterSize.MEDIUM,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    # Databases - NoSQL
    "mongodb": ServiceProfile(
        name="mongodb",
        category="data_nosql",
        resource_weight=7,
        requires_ha=True,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.4,
            UseCase.MICROSERVICES.value: 0.5,
            UseCase.DATA_ANALYTICS.value: 0.3,
            UseCase.ML_PLATFORM.value: 0.4,
            UseCase.WEB_HOSTING.value: 0.45,
            UseCase.ENTERPRISE_INTERNAL.value: 0.4,
            UseCase.ECOMMERCE.value: 0.6,
            UseCase.SAAS_PLATFORM.value: 0.65,
            UseCase.IOT_PLATFORM.value: 0.7,
            UseCase.GAMING_BACKEND.value: 0.7,
        },
        min_cluster_size=ClusterSize.SMALL,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "cassandra": ServiceProfile(
        name="cassandra",
        category="data_nosql",
        resource_weight=9,
        requires_ha=True,
        dependencies=[],
        conflicts_with=["scylladb"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.02,
            UseCase.MICROSERVICES.value: 0.1,
            UseCase.DATA_ANALYTICS.value: 0.15,
            UseCase.ML_PLATFORM.value: 0.1,
            UseCase.WEB_HOSTING.value: 0.05,
            UseCase.ENTERPRISE_INTERNAL.value: 0.15,
            UseCase.ECOMMERCE.value: 0.2,
            UseCase.SAAS_PLATFORM.value: 0.25,
            UseCase.IOT_PLATFORM.value: 0.4,
            UseCase.GAMING_BACKEND.value: 0.3,
        },
        min_cluster_size=ClusterSize.LARGE,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    # Caching
    "redis": ServiceProfile(
        name="redis",
        category="data_caching",
        resource_weight=4,
        requires_ha=True,
        dependencies=[],
        conflicts_with=["valkey", "keydb"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.6,
            UseCase.MICROSERVICES.value: 0.85,
            UseCase.DATA_ANALYTICS.value: 0.5,
            UseCase.ML_PLATFORM.value: 0.6,
            UseCase.WEB_HOSTING.value: 0.7,
            UseCase.ENTERPRISE_INTERNAL.value: 0.75,
            UseCase.ECOMMERCE.value: 0.95,
            UseCase.SAAS_PLATFORM.value: 0.9,
            UseCase.IOT_PLATFORM.value: 0.7,
            UseCase.GAMING_BACKEND.value: 0.9,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "valkey": ServiceProfile(
        name="valkey",
        category="data_caching",
        resource_weight=4,
        requires_ha=True,
        dependencies=[],
        conflicts_with=["redis", "keydb"],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.15,
            UseCase.MICROSERVICES.value: 0.1,
            UseCase.DATA_ANALYTICS.value: 0.1,
            UseCase.ML_PLATFORM.value: 0.1,
            UseCase.WEB_HOSTING.value: 0.1,
            UseCase.ENTERPRISE_INTERNAL.value: 0.1,
            UseCase.ECOMMERCE.value: 0.05,
            UseCase.SAAS_PLATFORM.value: 0.08,
            UseCase.IOT_PLATFORM.value: 0.1,
            UseCase.GAMING_BACKEND.value: 0.08,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    # Messaging
    "kafka": ServiceProfile(
        name="kafka",
        category="data_messaging",
        resource_weight=8,
        requires_ha=True,
        dependencies=["zookeeper"],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.1,
            UseCase.MICROSERVICES.value: 0.5,
            UseCase.DATA_ANALYTICS.value: 0.7,
            UseCase.ML_PLATFORM.value: 0.5,
            UseCase.WEB_HOSTING.value: 0.2,
            UseCase.ENTERPRISE_INTERNAL.value: 0.5,
            UseCase.ECOMMERCE.value: 0.6,
            UseCase.SAAS_PLATFORM.value: 0.65,
            UseCase.IOT_PLATFORM.value: 0.8,
            UseCase.GAMING_BACKEND.value: 0.5,
        },
        min_cluster_size=ClusterSize.MEDIUM,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "zookeeper": ServiceProfile(
        name="zookeeper",
        category="data_messaging",
        resource_weight=3,
        requires_ha=True,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.1,
            UseCase.MICROSERVICES.value: 0.5,
            UseCase.DATA_ANALYTICS.value: 0.7,
            UseCase.ML_PLATFORM.value: 0.5,
            UseCase.WEB_HOSTING.value: 0.2,
            UseCase.ENTERPRISE_INTERNAL.value: 0.5,
            UseCase.ECOMMERCE.value: 0.6,
            UseCase.SAAS_PLATFORM.value: 0.65,
            UseCase.IOT_PLATFORM.value: 0.8,
            UseCase.GAMING_BACKEND.value: 0.5,
        },
        min_cluster_size=ClusterSize.MEDIUM,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "rabbitmq": ServiceProfile(
        name="rabbitmq",
        category="data_messaging",
        resource_weight=5,
        requires_ha=True,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.3,
            UseCase.MICROSERVICES.value: 0.4,
            UseCase.DATA_ANALYTICS.value: 0.3,
            UseCase.ML_PLATFORM.value: 0.35,
            UseCase.WEB_HOSTING.value: 0.3,
            UseCase.ENTERPRISE_INTERNAL.value: 0.45,
            UseCase.ECOMMERCE.value: 0.5,
            UseCase.SAAS_PLATFORM.value: 0.45,
            UseCase.IOT_PLATFORM.value: 0.4,
            UseCase.GAMING_BACKEND.value: 0.4,
        },
        min_cluster_size=ClusterSize.SMALL,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    # Object Storage
    "minio": ServiceProfile(
        name="minio",
        category="data_storage",
        resource_weight=6,
        requires_ha=True,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.2,
            UseCase.MICROSERVICES.value: 0.4,
            UseCase.DATA_ANALYTICS.value: 0.7,
            UseCase.ML_PLATFORM.value: 0.8,
            UseCase.WEB_HOSTING.value: 0.35,
            UseCase.ENTERPRISE_INTERNAL.value: 0.5,
            UseCase.ECOMMERCE.value: 0.5,
            UseCase.SAAS_PLATFORM.value: 0.55,
            UseCase.IOT_PLATFORM.value: 0.6,
            UseCase.GAMING_BACKEND.value: 0.45,
        },
        min_cluster_size=ClusterSize.SMALL,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    # Big Data
    "spark": ServiceProfile(
        name="spark",
        category="data_processing",
        resource_weight=9,
        requires_ha=False,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.01,
            UseCase.MICROSERVICES.value: 0.05,
            UseCase.DATA_ANALYTICS.value: 0.6,
            UseCase.ML_PLATFORM.value: 0.7,
            UseCase.WEB_HOSTING.value: 0.02,
            UseCase.ENTERPRISE_INTERNAL.value: 0.3,
            UseCase.ECOMMERCE.value: 0.2,
            UseCase.SAAS_PLATFORM.value: 0.15,
            UseCase.IOT_PLATFORM.value: 0.4,
            UseCase.GAMING_BACKEND.value: 0.1,
        },
        min_cluster_size=ClusterSize.LARGE,
        base_instance_count=1,
        scale_with_cluster=False
    ),
    
    "flink": ServiceProfile(
        name="flink",
        category="data_processing",
        resource_weight=8,
        requires_ha=True,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.01,
            UseCase.MICROSERVICES.value: 0.05,
            UseCase.DATA_ANALYTICS.value: 0.4,
            UseCase.ML_PLATFORM.value: 0.3,
            UseCase.WEB_HOSTING.value: 0.02,
            UseCase.ENTERPRISE_INTERNAL.value: 0.2,
            UseCase.ECOMMERCE.value: 0.15,
            UseCase.SAAS_PLATFORM.value: 0.15,
            UseCase.IOT_PLATFORM.value: 0.5,
            UseCase.GAMING_BACKEND.value: 0.2,
        },
        min_cluster_size=ClusterSize.LARGE,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "airflow": ServiceProfile(
        name="airflow",
        category="data_orchestration",
        resource_weight=6,
        requires_ha=True,
        dependencies=["postgresql"],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.05,
            UseCase.MICROSERVICES.value: 0.15,
            UseCase.DATA_ANALYTICS.value: 0.7,
            UseCase.ML_PLATFORM.value: 0.75,
            UseCase.WEB_HOSTING.value: 0.1,
            UseCase.ENTERPRISE_INTERNAL.value: 0.4,
            UseCase.ECOMMERCE.value: 0.3,
            UseCase.SAAS_PLATFORM.value: 0.35,
            UseCase.IOT_PLATFORM.value: 0.5,
            UseCase.GAMING_BACKEND.value: 0.2,
        },
        min_cluster_size=ClusterSize.MEDIUM,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    # ML/AI
    "mlflow": ServiceProfile(
        name="mlflow",
        category="ml_platform",
        resource_weight=5,
        requires_ha=False,
        dependencies=["postgresql", "minio"],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.02,
            UseCase.MICROSERVICES.value: 0.05,
            UseCase.DATA_ANALYTICS.value: 0.3,
            UseCase.ML_PLATFORM.value: 0.8,
            UseCase.WEB_HOSTING.value: 0.02,
            UseCase.ENTERPRISE_INTERNAL.value: 0.2,
            UseCase.ECOMMERCE.value: 0.15,
            UseCase.SAAS_PLATFORM.value: 0.2,
            UseCase.IOT_PLATFORM.value: 0.25,
            UseCase.GAMING_BACKEND.value: 0.1,
        },
        min_cluster_size=ClusterSize.MEDIUM,
        base_instance_count=1,
        scale_with_cluster=False
    ),
    
    "jupyterhub": ServiceProfile(
        name="jupyterhub",
        category="ml_platform",
        resource_weight=5,
        requires_ha=False,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.05,
            UseCase.MICROSERVICES.value: 0.1,
            UseCase.DATA_ANALYTICS.value: 0.6,
            UseCase.ML_PLATFORM.value: 0.9,
            UseCase.WEB_HOSTING.value: 0.05,
            UseCase.ENTERPRISE_INTERNAL.value: 0.3,
            UseCase.ECOMMERCE.value: 0.2,
            UseCase.SAAS_PLATFORM.value: 0.2,
            UseCase.IOT_PLATFORM.value: 0.3,
            UseCase.GAMING_BACKEND.value: 0.1,
        },
        min_cluster_size=ClusterSize.MEDIUM,
        base_instance_count=1,
        scale_with_cluster=False
    ),
    
    # Web Applications
    "nginx": ServiceProfile(
        name="nginx",
        category="web_servers",
        resource_weight=2,
        requires_ha=True,
        dependencies=[],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.5,
            UseCase.MICROSERVICES.value: 0.4,
            UseCase.DATA_ANALYTICS.value: 0.2,
            UseCase.ML_PLATFORM.value: 0.2,
            UseCase.WEB_HOSTING.value: 0.9,
            UseCase.ENTERPRISE_INTERNAL.value: 0.5,
            UseCase.ECOMMERCE.value: 0.6,
            UseCase.SAAS_PLATFORM.value: 0.5,
            UseCase.IOT_PLATFORM.value: 0.3,
            UseCase.GAMING_BACKEND.value: 0.4,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=2,
        scale_with_cluster=True
    ),
    
    "wordpress": ServiceProfile(
        name="wordpress",
        category="web_cms",
        resource_weight=3,
        requires_ha=False,
        dependencies=["mysql", "redis"],
        conflicts_with=[],
        probability_by_use_case={
            UseCase.STARTUP_MVP.value: 0.2,
            UseCase.MICROSERVICES.value: 0.05,
            UseCase.DATA_ANALYTICS.value: 0.02,
            UseCase.ML_PLATFORM.value: 0.02,
            UseCase.WEB_HOSTING.value: 0.7,
            UseCase.ENTERPRISE_INTERNAL.value: 0.15,
            UseCase.ECOMMERCE.value: 0.1,
            UseCase.SAAS_PLATFORM.value: 0.05,
            UseCase.IOT_PLATFORM.value: 0.05,
            UseCase.GAMING_BACKEND.value: 0.05,
        },
        min_cluster_size=ClusterSize.TINY,
        base_instance_count=1,
        scale_with_cluster=False
    ),
}


# ======================================================================
# Cluster Generator
# ======================================================================

class K8sClusterGenerator:
    """Generate realistic Kubernetes cluster configurations"""
    
    def __init__(self, num_nodes: int, use_case: UseCase, seed: int = None):
        self.num_nodes = num_nodes
        self.use_case = use_case
        self.cluster_size = self._determine_cluster_size(num_nodes)
        self.selected_services: Set[str] = set()
        self.service_instances: Dict[str, int] = {}  # Track instance counts
        self.total_resource_weight = 0
        
        if seed is not None:
            random.seed(seed)
    
    @staticmethod
    def _determine_cluster_size(num_nodes: int) -> ClusterSize:
        """Determine cluster size category from node count"""
        for size in ClusterSize:
            min_nodes, max_nodes = size.value
            if min_nodes <= num_nodes <= max_nodes:
                return size
        return ClusterSize.XLARGE
    
    def _calculate_instance_count(self, service_name: str, profile: ServiceProfile) -> int:
        """Calculate the number of instances for a service based on cluster size and HA requirements"""
        base_count = profile.base_instance_count
        
        # If service doesn't scale with cluster, return base count
        if not profile.scale_with_cluster:
            # But apply HA rules if required
            if profile.requires_ha and base_count < 2:
                return 2  # Minimum 2 for HA
            return base_count
        
        # Scale based on cluster size
        if self.cluster_size == ClusterSize.TINY:
            instances = base_count
        elif self.cluster_size == ClusterSize.SMALL:
            instances = base_count + 1
        elif self.cluster_size == ClusterSize.MEDIUM:
            instances = base_count + 2
        elif self.cluster_size == ClusterSize.LARGE:
            instances = base_count + 3
        else:  # XLARGE
            instances = base_count + 5
        
        # Apply HA constraints
        if profile.requires_ha:
            # Ensure odd number for quorum-based systems (etcd, zookeeper, etc.)
            if service_name in ["etcd", "zookeeper", "consul"]:
                if instances % 2 == 0:
                    instances += 1
                # Cap at reasonable limits
                instances = min(instances, 7)
            else:
                # For other HA services, ensure at least 2
                instances = max(instances, 2)
                # Cap at reasonable limits
                instances = min(instances, 10)
        
        return instances
    
    def _can_add_service(self, service_name: str, profile: ServiceProfile) -> bool:
        """Check if a service can be added based on constraints"""
        # Check cluster size requirement
        required_min = profile.min_cluster_size.value[0]
        if self.num_nodes < required_min:
            return False
        
        # Check conflicts
        for conflict in profile.conflicts_with:
            if conflict in self.selected_services:
                return False
        
        # Check if we have capacity (rough heuristic)
        estimated_weight = self.total_resource_weight + profile.resource_weight
        max_capacity = self.num_nodes * 10  # Assume ~10 weight units per node
        if estimated_weight > max_capacity:
            return False
        
        return True
    
    def _add_service_with_dependencies(self, service_name: str):
        """Add a service and all its dependencies"""
        if service_name in self.selected_services:
            return
        
        if service_name not in SERVICE_CATALOG:
            return
        
        profile = SERVICE_CATALOG[service_name]
        
        # First add dependencies
        for dep in profile.dependencies:
            self._add_service_with_dependencies(dep)
        
        # Then add the service itself
        if self._can_add_service(service_name, profile):
            self.selected_services.add(service_name)
            # Calculate and store instance count
            instance_count = self._calculate_instance_count(service_name, profile)
            self.service_instances[service_name] = instance_count
            # Multiply resource weight by instance count
            self.total_resource_weight += profile.resource_weight * instance_count
    
    def generate(self) -> Dict:
        """Generate a realistic cluster configuration"""
        # Phase 1: Add services based on probability
        for service_name, profile in SERVICE_CATALOG.items():
            probability = profile.probability_by_use_case.get(self.use_case.value, 0)
            
            # Roll the dice
            if random.random() < probability:
                self._add_service_with_dependencies(service_name)
        
        # Calculate total pods
        total_pods = sum(self.service_instances.values())
        
        # Phase 2: Generate cluster metadata
        cluster_config = {
            "cluster_metadata": {
                "num_nodes": self.num_nodes,
                "cluster_size": self.cluster_size.name,
                "use_case": self.use_case.value,
                "total_services": len(self.selected_services),
                "total_pods": total_pods,
                "avg_pods_per_node": f"{total_pods / self.num_nodes:.1f}",
                "total_resource_weight": self.total_resource_weight,
                "resource_utilization": f"{(self.total_resource_weight / (self.num_nodes * 10)) * 100:.1f}%"
            },
            "services": sorted(list(self.selected_services)),
            "service_instances": {k: v for k, v in sorted(self.service_instances.items())},
            "services_by_category": self._group_by_category(),
            "deployment_stats": self._generate_stats()
        }
        
        return cluster_config
    
    def _group_by_category(self) -> Dict[str, List[str]]:
        """Group selected services by category"""
        by_category = {}
        for service_name in self.selected_services:
            if service_name in SERVICE_CATALOG:
                category = SERVICE_CATALOG[service_name].category
                if category not in by_category:
                    by_category[category] = []
                by_category[category].append(service_name)
        
        return {k: sorted(v) for k, v in sorted(by_category.items())}
    
    def _generate_stats(self) -> Dict:
        """Generate deployment statistics"""
        has_monitoring = bool({"prometheus", "grafana"} & self.selected_services)
        has_logging = bool({"grafana-loki", "elasticsearch", "fluent-bit"} & self.selected_services)
        has_tracing = bool({"jaeger", "grafana-tempo", "zipkin"} & self.selected_services)
        has_gitops = bool({"argo-cd", "flux"} & self.selected_services)
        has_service_mesh = bool({"cilium"} & self.selected_services)
        
        return {
            "observability_stack": {
                "metrics": has_monitoring,
                "logging": has_logging,
                "tracing": has_tracing,
                "completeness_score": sum([has_monitoring, has_logging, has_tracing]) / 3
            },
            "automation": {
                "gitops_enabled": has_gitops,
                "service_mesh": has_service_mesh
            },
            "data_layer": {
                "sql_databases": len([s for s in self.selected_services if s in ["postgresql", "mysql", "mariadb"]]),
                "nosql_databases": len([s for s in self.selected_services if SERVICE_CATALOG.get(s, None) and "nosql" in SERVICE_CATALOG[s].category]),
                "caching": "redis" in self.selected_services or "valkey" in self.selected_services,
                "messaging": "kafka" in self.selected_services or "rabbitmq" in self.selected_services
            }
        }


# ======================================================================
# CLI Interface
# ======================================================================

def generate_cluster_cli():
    """Command-line interface for cluster generation"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Generate realistic Kubernetes cluster configurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a 5-node microservices cluster
  python k8s_cluster_generator.py --nodes 5 --use-case microservices
  
  # Generate a 100-node data analytics cluster
  python k8s_cluster_generator.py --nodes 100 --use-case data_analytics
  
  # Generate with specific seed for reproducibility
  python k8s_cluster_generator.py --nodes 20 --use-case saas_platform --seed 42
  
  # Generate multiple clusters
  python k8s_cluster_generator.py --nodes 10 --use-case startup_mvp --count 3
        """
    )
    
    parser.add_argument(
        "--nodes", "-n",
        type=int,
        required=True,
        help="Number of nodes in the cluster"
    )
    
    parser.add_argument(
        "--use-case", "-u",
        type=str,
        required=True,
        choices=[uc.value for uc in UseCase],
        help="Primary use case for the cluster"
    )
    
    parser.add_argument(
        "--seed", "-s",
        type=int,
        default=None,
        help="Random seed for reproducibility"
    )
    
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=1,
        help="Number of clusters to generate"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output file (JSON format). If not specified, prints to stdout"
    )
    
    parser.add_argument(
        "--generate-topology",
        action="store_true",
        help="Generate network topology graphs for the cluster"
    )
    
    parser.add_argument(
        "--firewall-probability",
        type=float,
        default=0.2,
        help="Probability that a connection is blocked by firewall (0.0-1.0)"
    )
    
    parser.add_argument(
        "--knowledge-completeness",
        type=float,
        default=0.7,
        help="How much of the network the attacker knows (0.0-1.0)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output with statistics"
    )
    
    args = parser.parse_args()
    
    use_case = UseCase(args.use_case)
    results = []
    
    for i in range(args.count):
        seed = args.seed + i if args.seed is not None else None
        generator = K8sClusterGenerator(args.nodes, use_case, seed)
        cluster_config = generator.generate()
        
        # Generate network topology if requested
        if args.generate_topology:
            try:
                # Import here to avoid dependency if not needed
                from network_topology_generator import NetworkTopologyGenerator, topology_to_dict
                
                topo_generator = NetworkTopologyGenerator(
                    services=cluster_config["services"],
                    service_instances=cluster_config["service_instances"],
                    seed=seed
                )
                
                topology = topo_generator.generate(
                    firewall_probability=args.firewall_probability,
                    knowledge_completeness=args.knowledge_completeness
                )
                
                # Add topology to cluster config
                cluster_config["network_topology"] = topology_to_dict(topology)
                
            except ImportError:
                print("⚠️  Warning: network_topology_generator.py not found. Skipping topology generation.")
        
        results.append(cluster_config)
        
        if args.verbose:
            print(f"\n{'='*80}")
            print(f"Cluster {i+1}/{args.count}")
            print(f"{'='*80}")
            print(f"Nodes: {cluster_config['cluster_metadata']['num_nodes']}")
            print(f"Size Category: {cluster_config['cluster_metadata']['cluster_size']}")
            print(f"Use Case: {cluster_config['cluster_metadata']['use_case']}")
            print(f"Total Services: {cluster_config['cluster_metadata']['total_services']}")
            print(f"Total Pods: {cluster_config['cluster_metadata']['total_pods']}")
            print(f"Avg Pods/Node: {cluster_config['cluster_metadata']['avg_pods_per_node']}")
            print(f"Resource Utilization: {cluster_config['cluster_metadata']['resource_utilization']}")
            print(f"\nServices by Category:")
            for category, services in cluster_config['services_by_category'].items():
                print(f"  {category}: {len(services)} services")
            print(f"\nTop 10 Services by Instance Count:")
            sorted_instances = sorted(
                cluster_config['service_instances'].items(),
                key=lambda x: x[1],
                reverse=True
            )
            for service, count in sorted_instances[:10]:
                print(f"  {service:30s} {count:3d} instances")
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results if args.count > 1 else results[0], f, indent=2)
        print(f"\n✅ Configuration saved to {args.output}")
    else:
        print(json.dumps(results if args.count > 1 else results[0], indent=2))


if __name__ == "__main__":
    import sys
    
    # Check if CLI arguments provided
    if len(sys.argv) > 1:
        generate_cluster_cli()
    else:
        # Example usage if run directly without arguments
        print("Kubernetes Realistic Cluster Generator")
        print("="*80)
        print("\nExample: Generate a 10-node microservices cluster\n")
        
        generator = K8sClusterGenerator(
            num_nodes=10,
            use_case=UseCase.MICROSERVICES,
            seed=42
        )
        
        cluster = generator.generate()
        
        print(json.dumps(cluster, indent=2))
        print("\n" + "="*80)
        print("Run with --help for CLI options")
