"""
Kubernetes Manifest Generator
=============================
Translates CyberBattleSim cloud topology into real Kubernetes manifests.

This generates deployable K8s resources that mirror the simulated network:
- Namespaces for network segmentation (zones/subnets)
- Deployments for service instances
- Services for network exposure
- NetworkPolicies for firewall rules
- Secrets for credentials
- Ingress for public entry points

Author: Generated for CyberBattleSim Integration
"""

import os
import yaml
import base64
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class K8sManifestConfig:
    """Configuration for K8s manifest generation"""

    namespace_prefix: str = "cybersim"
    use_network_policies: bool = True
    create_ingress: bool = True
    ingress_class: str = "nginx"
    default_image_registry: str = ""
    default_resource_limits: Dict = field(
        default_factory=lambda: {"cpu": "100m", "memory": "128Mi"}
    )
    default_resource_requests: Dict = field(
        default_factory=lambda: {"cpu": "50m", "memory": "64Mi"}
    )
    # Map service names to real container images
    service_image_map: Dict[str, str] = field(default_factory=dict)
    # Labels to add to all resources
    common_labels: Dict[str, str] = field(
        default_factory=lambda: {
            "app.kubernetes.io/managed-by": "cyberbattlesim",
            "cybersim/generated": "true",
        }
    )


class K8sManifestGenerator:
    """
    Generates Kubernetes manifests from CyberBattleSim cluster configuration.

    Maps the simulated topology to real K8s resources:
    - Zones → Namespaces
    - Services → Deployments + Services
    - Firewall rules → NetworkPolicies
    - Credentials → Secrets
    - Public services → Ingress
    """

    # Default image mappings for common services
    DEFAULT_IMAGES = {
        # Web/Proxy
        "nginx": "nginx:1.25-alpine",
        "nginx-ingress": "nginx:1.25-alpine",
        "kong": "kong:3.4",
        "traefik": "traefik:v2.10",
        "haproxy": "haproxy:2.8-alpine",
        "envoy": "envoyproxy/envoy:v1.28-latest",
        "apisix": "apache/apisix:3.8.0-debian",  # Added
        "ambassador": "emissaryingress/emissary:v3.9.0",  # Added
        # Databases
        "postgresql": "postgres:15-alpine",
        "mysql": "mysql:8.0",
        "mongodb": "mongo:7.0",
        "redis": "redis:7-alpine",
        "elasticsearch": "elasticsearch:8.11.0",
        "cassandra": "cassandra:4.1",
        "mariadb": "mariadb:11",
        "clickhouse": "clickhouse/clickhouse-server:24.3",  # Added
        "valkey": "valkey/valkey:8.0",  # Added - Redis fork
        # Message Queues
        "rabbitmq": "rabbitmq:3.12-management-alpine",
        "kafka": "confluentinc/cp-kafka:7.5.0",
        "nats": "nats:2.10-alpine",
        "activemq": "apache/activemq-artemis:2.31.0",
        "zookeeper": "confluentinc/cp-zookeeper:7.5.0",  # Added
        # Kubernetes Components
        "etcd": "quay.io/coreos/etcd:v3.5.9",
        "kube-apiserver": "registry.k8s.io/kube-apiserver:v1.28.0",
        "kube-scheduler": "registry.k8s.io/kube-scheduler:v1.28.0",
        "kube-controller-manager": "registry.k8s.io/kube-controller-manager:v1.28.0",
        "coredns": "coredns/coredns:1.11.1",
        "kube-state-metrics": "k8s.gcr.io/kube-state-metrics/kube-state-metrics:v2.10.0",  # Added
        "metrics-server": "k8s.gcr.io/metrics-server/metrics-server:v0.6.4",  # Added
        # Monitoring
        "prometheus": "prom/prometheus:v2.47.0",
        "grafana": "grafana/grafana:10.2.0",
        "alertmanager": "prom/alertmanager:v0.26.0",
        "jaeger": "jaegertracing/all-in-one:1.51",
        "tempo": "grafana/tempo:2.3.0",  # Added
        "grafana-loki": "grafana/loki:2.9.0",  # Added (duplicate of "loki")
        "node-exporter": "prom/node-exporter:v1.7.0",  # Added
        # Logging
        "fluent-bit": "fluent/fluent-bit:2.2",
        "fluentd": "fluent/fluentd:v1.16-1",
        "loki": "grafana/loki:2.9.0",
        # Security
        "vault": "hashicorp/vault:1.15",
        "cert-manager": "quay.io/jetstack/cert-manager-controller:v1.13.0",
        "keycloak": "quay.io/keycloak/keycloak:24.0.0",  # Added
        # Service Mesh
        "istio-proxy": "istio/proxyv2:1.20.0",
        "linkerd-proxy": "ghcr.io/linkerd/proxy:stable-2.14.0",
        # CI/CD
        "jenkins": "jenkins/jenkins:lts-jdk17",
        "gitlab": "gitlab/gitlab-ce:16.5.0-ce.0",
        "argocd": "quay.io/argoproj/argocd:v2.9.0",
        "gitlab-runner": "gitlab/gitlab-runner:alpine-v16.5.0",  # Added
        "argo-cd": "quay.io/argoproj/argocd:v2.9.0",  # Added (duplicate of "argocd")
        # Storage
        "minio": "minio/minio:RELEASE.2023-11-01T01-57-10Z",
        "seaweedfs": "chrislusf/seaweedfs:3.64",  # Added
        # Big Data / ML
        "spark": "apache/spark:3.5.0",  # Added
        "flink": "apache/flink:1.18.0",  # Added
        "airflow": "apache/airflow:2.7.3-python3.11",  # Added
        "mlflow": "mlflow/mlflow:v2.10.0",  # Added
        "jupyterhub": "jupyterhub/jupyterhub:3.1.1",  # Added
        # Application Services
        "wordpress": "wordpress:6.4-apache",  # Added
        "superset": "apache/superset:3.0.0",  # Added
        "metabase": "metabase/metabase:v0.49.0",  # Added
        "redash": "redash/redash:11.0.0",  # Added
        "frontend": "nginx:1.25-alpine",  # Added (generic frontend)
        "web": "nginx:1.25-alpine",  # Added (generic web)
        "api-gateway": "kong:3.4",  # Added (using Kong)
        # Registry
        "harbor": "goharbor/harbor-core:v2.9.0",  # Added
        # Generic fallback
        "default": "busybox:1.36",
        # SSH/RDP (typically handled by OS, not containers)
        "ssh": "alpine:3.19",  # Added (minimal SSH server)
        "rdp": "alpine:3.19",  # Added (placeholder)
        # Schema Registry (for Kafka ecosystem)
        "schema-registry": "confluentinc/cp-schema-registry:7.5.0",  # Added
        # Additional Observability
        "cadvisor": "gcr.io/cadvisor/cadvisor:v0.47.2",  # Added
        "kibana": "docker.elastic.co/kibana/kibana:8.11.0",  # Added
        # Additional Networking
        "frontend": "nginx:1.25-alpine",  # Added
        "web": "nginx:1.25-alpine",
    }

    def __init__(
        self, cluster_config: Dict, config: Optional[K8sManifestConfig] = None
    ):
        self.cluster_config = cluster_config
        self.config = config or K8sManifestConfig()

        # Merge default images with user-provided mappings
        self.image_map = {**self.DEFAULT_IMAGES, **self.config.service_image_map}

        # Generated manifests storage
        self.manifests: Dict[str, List[Dict]] = {
            "namespaces": [],
            "deployments": [],
            "services": [],
            "network_policies": [],
            "secrets": [],
            "configmaps": [],
            "ingresses": [],
            "service_accounts": [],
        }

        # Tracking
        self.zone_to_namespace: Dict[str, str] = {}
        self.service_to_namespace: Dict[str, str] = {}

    def _get_image_for_service(self, service_name: str) -> str:
        """Get container image for a service"""
        # Exact match
        if service_name in self.image_map:
            return self.image_map[service_name]

        # Partial match (e.g., "my-nginx" matches "nginx")
        for key, image in self.image_map.items():
            if key in service_name.lower():
                return image

        # Default fallback
        return self.image_map.get("default", "busybox:1.36")

    def _sanitize_name(self, name: str) -> str:
        """Sanitize name for K8s (lowercase, alphanumeric, dashes)"""
        sanitized = name.lower().replace("_", "-").replace(".", "-")
        # Remove invalid characters
        sanitized = "".join(c if c.isalnum() or c == "-" else "-" for c in sanitized)
        # Remove leading/trailing dashes
        sanitized = sanitized.strip("-")
        # Ensure it doesn't start with a number
        if sanitized and sanitized[0].isdigit():
            sanitized = "svc-" + sanitized
        # Truncate to 63 chars (K8s limit)
        return sanitized[:63]

    def _generate_labels(
        self, service_name: str, component: str = None, extra_labels: Dict = None
    ) -> Dict[str, str]:
        """Generate standard labels for resources"""
        labels = {
            **self.config.common_labels,
            "app.kubernetes.io/name": self._sanitize_name(service_name),
            "app.kubernetes.io/instance": self._sanitize_name(
                f"{service_name}-instance"
            ),
        }
        if component:
            labels["app.kubernetes.io/component"] = component
        if extra_labels:
            labels.update(extra_labels)
        return labels

    def _get_service_port(self, service_name: str) -> int:
        """Get port for a service from network topology"""
        network_topology = self.cluster_config.get("network_topology", {})
        services = network_topology.get("services", {})

        if service_name in services:
            return services[service_name].get("port", 8080)

        # Default ports for known services
        default_ports = {
            "nginx": 80,
            "kong": 8000,
            "traefik": 80,
            "postgresql": 5432,
            "mysql": 3306,
            "mongodb": 27017,
            "redis": 6379,
            "elasticsearch": 9200,
            "rabbitmq": 5672,
            "kafka": 9092,
            "prometheus": 9090,
            "grafana": 3000,
            "etcd": 2379,
            "vault": 8200,
            "jenkins": 8080,
        }

        for key, port in default_ports.items():
            if key in service_name.lower():
                return port

        return 8080  # Default

    def _is_public_service(self, service_name: str) -> bool:
        """Check if service should be publicly exposed"""
        network_topology = self.cluster_config.get("network_topology", {})
        services = network_topology.get("services", {})

        if service_name in services:
            return services[service_name].get("is_public", False)

        # Public service patterns
        public_patterns = [
            "nginx",
            "ingress",
            "kong",
            "traefik",
            "gateway",
            "api-gateway",
        ]
        return any(p in service_name.lower() for p in public_patterns)

    def generate_namespaces(self) -> List[Dict]:
        """Generate namespace manifests for zones"""
        namespaces = []

        # Get zones from physical topology
        physical = self.cluster_config.get("physical_topology", {})
        network_config = physical.get("network_configuration", {})
        zone_subnets = network_config.get("zone_subnets", {})

        # Also create namespace for each subnet from logical layer
        network = self.cluster_config.get("network", {})
        subnets = network.get("subnets", [])

        # Create namespace for each zone
        for zone_name, cidr in zone_subnets.items():
            if zone_name == "public":
                continue  # Skip public/internet zone

            ns_name = f"{self.config.namespace_prefix}-{self._sanitize_name(zone_name)}"
            self.zone_to_namespace[zone_name] = ns_name

            namespace = {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": ns_name,
                    "labels": {
                        **self.config.common_labels,
                        "cybersim/zone": zone_name,
                        "cybersim/cidr": cidr,
                    },
                    "annotations": {
                        "cybersim/description": f"Zone {zone_name} with CIDR {cidr}",
                    },
                },
            }
            namespaces.append(namespace)

        # Create namespace for each logical subnet
        for subnet in subnets:
            subnet_id = subnet.get("id", 0)
            subnet_label = subnet.get("label", f"subnet-{subnet_id}")
            ns_name = (
                f"{self.config.namespace_prefix}-{self._sanitize_name(subnet_label)}"
            )

            if ns_name not in [ns["metadata"]["name"] for ns in namespaces]:
                namespace = {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {
                        "name": ns_name,
                        "labels": {
                            **self.config.common_labels,
                            "cybersim/subnet-id": str(subnet_id),
                            "cybersim/subnet-label": subnet_label,
                        },
                    },
                }
                namespaces.append(namespace)

        # Default namespace if none created
        if not namespaces:
            namespaces.append(
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {
                        "name": f"{self.config.namespace_prefix}-default",
                        "labels": self.config.common_labels,
                    },
                }
            )

        self.manifests["namespaces"] = namespaces
        return namespaces

    def generate_deployments(self) -> List[Dict]:
        """Generate deployment manifests for services"""
        deployments = []

        service_instances = self.cluster_config.get("service_instances", {})
        service_distribution = self.cluster_config.get("service_distribution", {})

        for service_name, instance_count in service_instances.items():
            # Determine namespace
            dist = service_distribution.get(service_name, {})
            subnets = dist.get("subnets", [0])

            # Map to namespace
            namespace = self._get_namespace_for_service(service_name, subnets)
            self.service_to_namespace[service_name] = namespace

            # Get service details
            port = self._get_service_port(service_name)
            image = self._get_image_for_service(service_name)

            deployment = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": self._sanitize_name(service_name),
                    "namespace": namespace,
                    "labels": self._generate_labels(service_name, "server"),
                },
                "spec": {
                    "replicas": instance_count,
                    "selector": {
                        "matchLabels": {
                            "app.kubernetes.io/name": self._sanitize_name(service_name),
                        }
                    },
                    "template": {
                        "metadata": {
                            "labels": self._generate_labels(service_name, "server"),
                            "annotations": {
                                "cybersim/service": service_name,
                                "cybersim/port": str(port),
                            },
                        },
                        "spec": {
                            "containers": [
                                {
                                    "name": self._sanitize_name(service_name),
                                    "image": image,
                                    "ports": [
                                        {
                                            "containerPort": port,
                                            "name": "main",
                                            "protocol": "TCP",
                                        }
                                    ],
                                    "resources": {
                                        "limits": self.config.default_resource_limits,
                                        "requests": self.config.default_resource_requests,
                                    },
                                    "livenessProbe": {
                                        "tcpSocket": {"port": port},
                                        "initialDelaySeconds": 30,
                                        "periodSeconds": 10,
                                    },
                                    "readinessProbe": {
                                        "tcpSocket": {"port": port},
                                        "initialDelaySeconds": 5,
                                        "periodSeconds": 5,
                                    },
                                }
                            ],
                            "securityContext": {
                                "runAsNonRoot": True,
                                "runAsUser": 1000,
                                "fsGroup": 1000,
                            },
                        },
                    },
                },
            }

            # Add environment variables from vulnerabilities (simulated misconfigs)
            self._add_vulnerability_env_vars(deployment, service_name)

            deployments.append(deployment)

        self.manifests["deployments"] = deployments
        return deployments

    def _get_namespace_for_service(self, service_name: str, subnets: List[int]) -> str:
        """Determine namespace for a service based on subnet assignment"""
        # Get subnet info
        network = self.cluster_config.get("network", {})
        subnet_list = network.get("subnets", [])

        if subnets and subnet_list:
            subnet_id = subnets[0]  # Primary subnet
            for s in subnet_list:
                if s.get("id") == subnet_id:
                    label = s.get("label", f"subnet-{subnet_id}")
                    return (
                        f"{self.config.namespace_prefix}-{self._sanitize_name(label)}"
                    )

        # Check zone mapping from physical topology
        physical = self.cluster_config.get("physical_topology", {})
        node_mapping = physical.get("node_to_service_mapping", {})

        if service_name in node_mapping:
            instances = node_mapping[service_name]
            if instances:
                zone = instances[0].get("zone", "zone-a")
                if zone in self.zone_to_namespace:
                    return self.zone_to_namespace[zone]

        # Default namespace
        if self.manifests["namespaces"]:
            return self.manifests["namespaces"][0]["metadata"]["name"]
        return f"{self.config.namespace_prefix}-default"

    def _add_vulnerability_env_vars(self, deployment: Dict, service_name: str):
        """Add environment variables that simulate vulnerabilities"""
        network_topology = self.cluster_config.get("network_topology", {})
        services = network_topology.get("services", {})

        env_vars = []

        if service_name in services:
            svc_info = services[service_name]
            vulns = svc_info.get("vulnerabilities", [])

            for vuln in vulns:
                # Simulate misconfiguration based on vulnerability type
                if vuln.get("outcome_type") == "LeakedCredentials":
                    env_vars.append({"name": "DEBUG_MODE", "value": "true"})
                elif vuln.get("vulnerability_type") == "REMOTE":
                    env_vars.append({"name": "ALLOW_REMOTE_DEBUG", "value": "true"})

        if env_vars:
            deployment["spec"]["template"]["spec"]["containers"][0]["env"] = env_vars

    def generate_services(self) -> List[Dict]:
        """Generate service manifests for network exposure"""
        services = []

        service_instances = self.cluster_config.get("service_instances", {})

        for service_name in service_instances.keys():
            namespace = self.service_to_namespace.get(
                service_name, f"{self.config.namespace_prefix}-default"
            )
            port = self._get_service_port(service_name)
            is_public = self._is_public_service(service_name)

            service = {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "name": self._sanitize_name(service_name),
                    "namespace": namespace,
                    "labels": self._generate_labels(service_name, "service"),
                },
                "spec": {
                    "selector": {
                        "app.kubernetes.io/name": self._sanitize_name(service_name),
                    },
                    "ports": [
                        {
                            "name": "main",
                            "port": port,
                            "targetPort": port,
                            "protocol": "TCP",
                        }
                    ],
                    "type": "LoadBalancer" if is_public else "ClusterIP",
                },
            }

            services.append(service)

        self.manifests["services"] = services
        return services

    def generate_network_policies(self) -> List[Dict]:
        """Generate NetworkPolicy manifests from firewall rules"""
        if not self.config.use_network_policies:
            return []

        policies = []

        # Get firewall configuration
        firewall_config = self.cluster_config.get("firewall", {})
        physical = self.cluster_config.get("physical_topology", {})
        nodes = physical.get("nodes", [])

        # Generate policies per namespace
        for namespace_manifest in self.manifests["namespaces"]:
            ns_name = namespace_manifest["metadata"]["name"]

            # Default deny all ingress policy
            deny_policy = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": "default-deny-ingress",
                    "namespace": ns_name,
                    "labels": self.config.common_labels,
                },
                "spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": []},
            }
            policies.append(deny_policy)

            # Allow internal namespace traffic
            allow_internal = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": "allow-same-namespace",
                    "namespace": ns_name,
                    "labels": self.config.common_labels,
                },
                "spec": {
                    "podSelector": {},
                    "policyTypes": ["Ingress"],
                    "ingress": [{"from": [{"podSelector": {}}]}],
                },
            }
            policies.append(allow_internal)

        # Generate service-specific policies from access_connectivity
        network_topology = self.cluster_config.get("network_topology", {})
        access_edges = network_topology.get("access_connectivity", [])

        for edge in access_edges:
            if not edge.get("firewall_allowed", True):
                continue

            source = edge.get("source", "")
            target = edge.get("target", "")
            port = edge.get("port", 8080)

            source_ns = self.service_to_namespace.get(source)
            target_ns = self.service_to_namespace.get(target)

            if not source_ns or not target_ns:
                continue

            policy = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": f"allow-{self._sanitize_name(source)}-to-{self._sanitize_name(target)}"[
                        :63
                    ],
                    "namespace": target_ns,
                    "labels": self.config.common_labels,
                },
                "spec": {
                    "podSelector": {
                        "matchLabels": {
                            "app.kubernetes.io/name": self._sanitize_name(target),
                        }
                    },
                    "policyTypes": ["Ingress"],
                    "ingress": [
                        {
                            "from": [
                                {
                                    "namespaceSelector": {
                                        "matchLabels": {
                                            "kubernetes.io/metadata.name": source_ns
                                        }
                                    },
                                    "podSelector": {
                                        "matchLabels": {
                                            "app.kubernetes.io/name": self._sanitize_name(
                                                source
                                            ),
                                        }
                                    },
                                }
                            ],
                            "ports": [{"protocol": "TCP", "port": port}],
                        }
                    ],
                },
            }
            policies.append(policy)

        self.manifests["network_policies"] = policies
        return policies

    def generate_secrets(self) -> List[Dict]:
        """Generate secrets from credential flow"""
        secrets = []

        network_topology = self.cluster_config.get("network_topology", {})
        credential_flow = network_topology.get("credential_flow", [])

        # Group credentials by source service
        creds_by_source: Dict[str, List[Dict]] = {}

        for cred in credential_flow:
            source = cred.get("source", "")
            target = cred.get("target", "")
            cred_type = cred.get("credential_type", "password")
            cred_level = cred.get("credential_level", "LocalUser")

            if source not in creds_by_source:
                creds_by_source[source] = []

            creds_by_source[source].append(
                {"target": target, "type": cred_type, "level": cred_level}
            )

        # Create secrets
        for source, creds in creds_by_source.items():
            namespace = self.service_to_namespace.get(
                source, f"{self.config.namespace_prefix}-default"
            )

            secret_data = {}
            for cred in creds:
                # Generate pseudo-credential
                key = f"{self._sanitize_name(cred['target'])}-{cred['type']}"
                # In real deployment, these would be real credentials
                value = base64.b64encode(
                    f"simulated-{cred['type']}-for-{cred['target']}".encode()
                ).decode()
                secret_data[key] = value

            secret = {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": f"{self._sanitize_name(source)}-credentials",
                    "namespace": namespace,
                    "labels": self._generate_labels(source, "credentials"),
                },
                "type": "Opaque",
                "data": secret_data,
            }
            secrets.append(secret)

        self.manifests["secrets"] = secrets
        return secrets

    def generate_ingresses(self) -> List[Dict]:
        """Generate ingress manifests for public services"""
        if not self.config.create_ingress:
            return []

        ingresses = []

        network_topology = self.cluster_config.get("network_topology", {})
        services_info = network_topology.get("services", {})
        service_instances = self.cluster_config.get("service_instances", {})

        for service_name in service_instances.keys():
            if not self._is_public_service(service_name):
                continue

            namespace = self.service_to_namespace.get(
                service_name, f"{self.config.namespace_prefix}-default"
            )
            port = self._get_service_port(service_name)

            ingress = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {
                    "name": f"{self._sanitize_name(service_name)}-ingress",
                    "namespace": namespace,
                    "labels": self._generate_labels(service_name, "ingress"),
                    "annotations": {
                        "kubernetes.io/ingress.class": self.config.ingress_class,
                    },
                },
                "spec": {
                    "rules": [
                        {
                            "host": f"{self._sanitize_name(service_name)}.local",
                            "http": {
                                "paths": [
                                    {
                                        "path": "/",
                                        "pathType": "Prefix",
                                        "backend": {
                                            "service": {
                                                "name": self._sanitize_name(
                                                    service_name
                                                ),
                                                "port": {"number": port},
                                            }
                                        },
                                    }
                                ]
                            },
                        }
                    ]
                },
            }
            ingresses.append(ingress)

        self.manifests["ingresses"] = ingresses
        return ingresses

    def generate_configmaps(self) -> List[Dict]:
        """Generate configmaps with topology metadata"""
        configmaps = []

        # Create a configmap with cluster metadata
        cluster_meta = self.cluster_config.get("cluster_metadata", {})

        for namespace_manifest in self.manifests["namespaces"]:
            ns_name = namespace_manifest["metadata"]["name"]

            configmap = {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "cybersim-metadata",
                    "namespace": ns_name,
                    "labels": self.config.common_labels,
                },
                "data": {
                    "cluster-size": str(cluster_meta.get("cluster_size", "UNKNOWN")),
                    "use-case": str(cluster_meta.get("use_case", "unknown")),
                    "total-services": str(cluster_meta.get("total_services", 0)),
                    "generator": "CyberBattleSim",
                },
            }
            configmaps.append(configmap)

        self.manifests["configmaps"] = configmaps
        return configmaps

    def generate_all(self) -> Dict[str, List[Dict]]:
        """Generate all manifests"""
        self.generate_namespaces()
        self.generate_deployments()
        self.generate_services()
        self.generate_network_policies()
        self.generate_secrets()
        self.generate_ingresses()
        self.generate_configmaps()

        return self.manifests

    def save_manifests(self, output_dir: str, single_file: bool = False):
        """
        Save manifests to files

        Args:
            output_dir: Directory to save files
            single_file: If True, save all manifests to one file
        """
        os.makedirs(output_dir, exist_ok=True)

        if single_file:
            # Save everything to one file with document separators
            all_manifests = []
            for resource_type, manifests in self.manifests.items():
                all_manifests.extend(manifests)

            output_path = os.path.join(output_dir, "all-manifests.yaml")
            with open(output_path, "w") as f:
                yaml.dump_all(all_manifests, f, default_flow_style=False)
            print(f"  Saved all manifests to {output_path}")
        else:
            # Save each resource type to separate files
            for resource_type, manifests in self.manifests.items():
                if not manifests:
                    continue

                # Create subdirectory for resource type
                type_dir = os.path.join(output_dir, resource_type)
                os.makedirs(type_dir, exist_ok=True)

                for manifest in manifests:
                    name = manifest["metadata"]["name"]
                    namespace = manifest["metadata"].get("namespace", "default")
                    filename = f"{namespace}-{name}.yaml"

                    output_path = os.path.join(type_dir, filename)
                    with open(output_path, "w") as f:
                        yaml.dump(manifest, f, default_flow_style=False)

                print(f"  Saved {len(manifests)} {resource_type} to {type_dir}/")

        # Generate kustomization.yaml for easy deployment
        self._generate_kustomization(output_dir)

    def _generate_kustomization(self, output_dir: str):
        """Generate kustomization.yaml for kubectl apply -k"""
        resources = []

        for resource_type, manifests in self.manifests.items():
            for manifest in manifests:
                name = manifest["metadata"]["name"]
                namespace = manifest["metadata"].get("namespace", "default")
                resources.append(f"{resource_type}/{namespace}-{name}.yaml")

        kustomization = {
            "apiVersion": "kustomize.config.k8s.io/v1beta1",
            "kind": "Kustomization",
            "resources": resources,
            "commonLabels": self.config.common_labels,
        }

        output_path = os.path.join(output_dir, "kustomization.yaml")
        with open(output_path, "w") as f:
            yaml.dump(kustomization, f, default_flow_style=False)
        print("  Generated kustomization.yaml")

    def generate_helm_chart(
        self, output_dir: str, chart_name: str = "cybersim-cluster"
    ):
        """Generate a Helm chart from the manifests"""
        chart_dir = os.path.join(output_dir, chart_name)
        templates_dir = os.path.join(chart_dir, "templates")
        os.makedirs(templates_dir, exist_ok=True)

        # Chart.yaml
        chart_yaml = {
            "apiVersion": "v2",
            "name": chart_name,
            "description": "CyberBattleSim generated cluster topology",
            "type": "application",
            "version": "0.1.0",
            "appVersion": "1.0.0",
        }
        with open(os.path.join(chart_dir, "Chart.yaml"), "w") as f:
            yaml.dump(chart_yaml, f, default_flow_style=False)

        # values.yaml
        values = {
            "replicaCount": 1,
            "image": {
                "pullPolicy": "IfNotPresent",
            },
            "resources": {
                "limits": self.config.default_resource_limits,
                "requests": self.config.default_resource_requests,
            },
            "networkPolicies": {
                "enabled": self.config.use_network_policies,
            },
            "ingress": {
                "enabled": self.config.create_ingress,
                "className": self.config.ingress_class,
            },
        }
        with open(os.path.join(chart_dir, "values.yaml"), "w") as f:
            yaml.dump(values, f, default_flow_style=False)

        # Templates
        for resource_type, manifests in self.manifests.items():
            if not manifests:
                continue

            output_path = os.path.join(templates_dir, f"{resource_type}.yaml")
            with open(output_path, "w") as f:
                yaml.dump_all(manifests, f, default_flow_style=False)

        print(f"  Generated Helm chart at {chart_dir}/")


def generate_k8s_manifests(
    cluster_config: Dict, output_dir: str, config: Optional[K8sManifestConfig] = None
) -> Dict[str, List[Dict]]:
    """
    Convenience function to generate K8s manifests from cluster configuration

    Args:
        cluster_config: The cluster configuration dictionary from the generator pipeline
        output_dir: Directory to save the manifests
        config: Optional configuration for manifest generation

    Returns:
        Dictionary of generated manifests by resource type
    """
    generator = K8sManifestGenerator(cluster_config, config)
    manifests = generator.generate_all()
    generator.save_manifests(output_dir)

    return manifests
