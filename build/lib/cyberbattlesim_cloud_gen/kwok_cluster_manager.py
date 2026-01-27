"""
KWOK Cluster Manager for Kubernetes CyberBattle Simulator - FIXED VERSION

This module provides integration with KWOK (Kubernetes WithOut Kubelet) to create
lightweight, simulated Kubernetes clusters for attack simulation.
"""

import os
import time
import logging
import subprocess
import shutil
from typing import Dict, List, Optional
import yaml
import requests
import platform
import random

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException

    K8S_CLIENT_AVAILABLE = True
except ImportError:
    K8S_CLIENT_AVAILABLE = False
    logging.warning("Kubernetes client not available")

LOGGER = logging.getLogger(__name__)


class KWOKClusterManager:
    """Manager for KWOK-based Kubernetes clusters"""

    KWOK_VERSION = "v0.7.0"
    KWOK_REPO = "kubernetes-sigs/kwok"

    def __init__(
        self,
        cluster_name: str = "cyberbattle",
        kwok_binary_path: Optional[str] = None,
        kwokctl_binary_path: Optional[str] = None,
        kubeconfig_path: Optional[str] = None,
        auto_install: bool = True,
        verbose: bool = False,
    ):
        self.cluster_name = cluster_name
        self.verbose = verbose
        if verbose:
            LOGGER.setLevel(logging.DEBUG)

        self.kwok_binary = kwok_binary_path or self._find_binary("kwok")
        self.kwokctl_binary = kwokctl_binary_path or self._find_binary("kwokctl")

        if auto_install and (not self.kwok_binary or not self.kwokctl_binary):
            LOGGER.info("KWOK binaries not found. Installing...")
            self.install_kwok()
            self.kwok_binary = self._find_binary("kwok")
            self.kwokctl_binary = self._find_binary("kwokctl")

        if kubeconfig_path:
            self.kubeconfig_path = kubeconfig_path
        else:
            kwok_dir = os.path.expanduser("~/.kwok")
            self.kubeconfig_path = os.path.join(
                kwok_dir, "clusters", cluster_name, "kubeconfig.yaml"
            )

        self.k8s_core_api = None
        self.k8s_apps_api = None
        self.k8s_rbac_api = None
        self.cluster_running = False
        self.simulated_nodes = {}
        self.simulated_pods = {}

        LOGGER.info(f"KWOK Cluster Manager initialized for cluster: {cluster_name}")

    def _find_binary(self, binary_name: str) -> Optional[str]:
        binary_path = shutil.which(binary_name)
        if binary_path:
            return binary_path
        common_locations = [
            f"/usr/local/bin/{binary_name}",
            f"/usr/bin/{binary_name}",
            os.path.expanduser(f"~/.local/bin/{binary_name}"),
            os.path.expanduser(f"~/bin/{binary_name}"),
        ]
        for location in common_locations:
            if os.path.exists(location) and os.access(location, os.X_OK):
                return location
        return None

    def install_kwok(self, install_dir: Optional[str] = None) -> bool:
        if not install_dir:
            install_dir = os.path.expanduser("~/.local/bin")
        os.makedirs(install_dir, exist_ok=True)

        os_name = platform.system().lower()
        machine = platform.machine().lower()
        arch_map = {
            "x86_64": "amd64",
            "amd64": "amd64",
            "arm64": "arm64",
            "aarch64": "arm64",
        }
        arch = arch_map.get(machine, "amd64")

        if os_name == "darwin":
            os_name = "darwin"
        elif os_name == "linux":
            os_name = "linux"
        else:
            LOGGER.error(f"Unsupported OS: {os_name}")
            return False

        kwok_url = f"https://github.com/{self.KWOK_REPO}/releases/download/{self.KWOK_VERSION}/kwok-{os_name}-{arch}"
        kwokctl_url = f"https://github.com/{self.KWOK_REPO}/releases/download/{self.KWOK_VERSION}/kwokctl-{os_name}-{arch}"

        for binary_name, url in [("kwok", kwok_url), ("kwokctl", kwokctl_url)]:
            target_path = os.path.join(install_dir, binary_name)
            try:
                LOGGER.info(f"Downloading {binary_name} from {url}")
                response = requests.get(url, stream=True, timeout=300)
                response.raise_for_status()
                with open(target_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                os.chmod(target_path, 0o755)
            except Exception as e:
                LOGGER.error(f"Failed to install {binary_name}: {e}")
                return False
        return True

    def create_cluster(
        self,
        k8s_version: str = "v1.28.0",
        runtime: str = "binary",
        wait_ready: bool = True,
        extra_args: Optional[List[str]] = None,
    ) -> bool:
        if not self.kwokctl_binary:
            return False

        LOGGER.info(
            f"Creating KWOK cluster '{self.cluster_name}' with K8s {k8s_version}"
        )

        os_name = platform.system().lower()
        machine = platform.machine().lower()
        arch_map = {
            "x86_64": "amd64",
            "amd64": "amd64",
            "arm64": "arm64",
            "aarch64": "arm64",
        }
        arch = arch_map.get(machine, "amd64")

        env = os.environ.copy()
        env["KWOK_KUBE_VERSION"] = k8s_version

        cmd = [
            self.kwokctl_binary,
            "create",
            "cluster",
            "--name",
            self.cluster_name,
            "--runtime",
            runtime,
        ]

        if runtime == "binary":
            kube_binary_prefix = (
                f"https://dl.k8s.io/release/{k8s_version}/bin/{os_name}/{arch}"
            )
            cmd.extend(
                [
                    "--kube-apiserver-binary",
                    f"{kube_binary_prefix}/kube-apiserver",
                    "--kube-controller-manager-binary",
                    f"{kube_binary_prefix}/kube-controller-manager",
                    "--kube-scheduler-binary",
                    f"{kube_binary_prefix}/kube-scheduler",
                ]
            )

        if wait_ready:
            cmd.extend(["--wait", "30s"])
        if extra_args:
            cmd.extend(extra_args)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120, env=env
            )
            if result.returncode == 0:
                self.cluster_running = True
                time.sleep(2)
                self._init_k8s_client()
                return True
            else:
                LOGGER.error(f"Failed to create cluster: {result.stderr}")
                return False
        except Exception as e:
            LOGGER.error(f"Error creating cluster: {e}")
            return False

    def delete_cluster(self) -> bool:
        if not self.kwokctl_binary:
            return False
        try:
            subprocess.run(
                [self.kwokctl_binary, "delete", "cluster", "--name", self.cluster_name],
                capture_output=True,
                timeout=60,
            )
            self.cluster_running = False
            return True
        except Exception:
            return False

    def _init_k8s_client(self) -> bool:
        if not K8S_CLIENT_AVAILABLE:
            return False
        try:
            config.load_kube_config(config_file=self.kubeconfig_path)
            self.k8s_core_api = client.CoreV1Api()
            self.k8s_apps_api = client.AppsV1Api()
            self.k8s_rbac_api = client.RbacAuthorizationV1Api()
            return True
        except Exception as e:
            LOGGER.error(f"Failed to init K8s client: {e}")
            return False

    def _force_pod_to_running(self, namespace: str, name: str) -> bool:
        """Manually patch the Pod status to Running/Ready for KWOK simulation."""
        if not self.k8s_core_api:
            LOGGER.error("K8s client not initialized for status patch.")
            return False

        patch_body = {
            "status": {
                "phase": "Running",
                "conditions": [{"type": "Ready", "status": "True"}],
                "containerStatuses": [
                    {
                        "name": "main",  # Generic name
                        "ready": True,
                        "state": {
                            "running": {
                                "startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ")
                            }
                        },
                        "image": "fake-kwok-image",
                        "imageID": "fake-kwok-id",
                        "containerID": "fake-kwok-container-id",
                        "restartCount": 0,
                    }
                ],
            }
        }

        try:
            self.k8s_core_api.patch_namespaced_pod_status(name, namespace, patch_body)
            LOGGER.info(f"✓ Manually patched Pod status to Running: {namespace}/{name}")
            return True
        except ApiException as e:
            LOGGER.error(f"Failed to patch pod status {namespace}/{name}: {e}")
            return False

    def create_vulnerable_cluster(
        self, cluster_config: Dict, create_cluster_first: bool = True
    ) -> bool:
        """
        Create a full vulnerable Kubernetes cluster based on configuration

        Order: Namespaces -> Secrets -> RBAC -> Nodes -> Workloads (Pods/Deployments)
        """
        if create_cluster_first:
            k8s_version = cluster_config.get("k8s_version", "v1.28.0")
            if not self.create_cluster(k8s_version=k8s_version):
                return False

        # 1. Namespaces
        if "namespaces" in cluster_config:
            for ns_config in cluster_config["namespaces"]:
                self._create_namespace(ns_config)

        # 2. Secrets
        if "secrets" in cluster_config:
            for secret_config in cluster_config["secrets"]:
                self._create_secret(secret_config)

        # 3. RBAC (ServiceAccounts, Roles, Bindings)
        if "rbac" in cluster_config:
            self._create_rbac_resources(cluster_config["rbac"])

        # 4. Nodes
        if "nodes" in cluster_config:
            for node_config in cluster_config["nodes"]:
                self.create_simulated_node(
                    node_name=node_config["name"],
                    labels=node_config.get("labels", {}),
                    taints=node_config.get("taints", []),
                    capacity=node_config.get("capacity", None),
                )

        # 5. Workloads (Pods/Deployments)
        if "workloads" in cluster_config:
            for workload_config in cluster_config["workloads"]:
                self._create_workload(workload_config)

        # 6. FIX: Force ALL Pods to Running state (not just initial pod)
        time.sleep(2)  # Give pods time to be created
        for workload_config in cluster_config.get("workloads", []):
            if workload_config.get("type") == "Pod":
                namespace = workload_config.get("namespace", "default")
                name = workload_config["name"]
                self._force_pod_to_running(namespace, name)

        LOGGER.info("✓ Vulnerable cluster setup complete")
        return True

    def create_simulated_node(
        self,
        node_name: str,
        labels: dict = None,
        taints: list = None,
        capacity: dict = None,
        node_ip: str = None,
    ) -> bool:
        if not self.k8s_core_api:
            return False
        labels = labels or {}
        capacity = capacity or {"cpu": "4", "memory": "8Gi", "pods": "110"}
        if not node_ip:
            node_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"

        labels.update({"type": "kwok", "kwok.x-k8s.io/node": "fake"})

        node = client.V1Node(
            metadata=client.V1ObjectMeta(name=node_name, labels=labels),
            spec=client.V1NodeSpec(taints=taints or []),
            status=client.V1NodeStatus(
                capacity=capacity,
                allocatable=capacity,
                addresses=[client.V1NodeAddress(type="InternalIP", address=node_ip)],
                conditions=[
                    client.V1NodeCondition(
                        type="Ready",
                        status="True",
                        reason="KubeletReady",
                        message="kubelet is posting ready status",
                    )
                ],
            ),
        )
        try:
            self.k8s_core_api.create_node(node)
            LOGGER.info(f"✓ Created simulated node: {node_name}")
            return True
        except ApiException as e:
            if e.status != 409:
                LOGGER.error(f"Failed to create node: {e}")
            return e.status == 409  # Return True if already exists

    def _create_namespace(self, ns_config: Dict):
        ns = client.V1Namespace(
            metadata=client.V1ObjectMeta(
                name=ns_config["name"], labels=ns_config.get("labels", {})
            )
        )
        try:
            self.k8s_core_api.create_namespace(ns)
            LOGGER.info(f"✓ Created namespace: {ns_config['name']}")
        except ApiException as e:
            if e.status != 409:
                LOGGER.error(f"Failed to create namespace: {e}")

    def _create_workload(self, workload_config: Dict):
        if workload_config.get("type") == "Pod":
            self._create_pod(workload_config)
        elif workload_config.get("type") == "Deployment":
            self._create_deployment(workload_config)

    def _create_pod(self, pod_config: Dict):
        name = pod_config["name"]
        namespace = pod_config.get("namespace", "default")
        containers = []
        for c in pod_config.get("containers", [{"name": "main", "image": "nginx"}]):
            sec_ctx = client.V1SecurityContext(
                privileged=pod_config.get("privileged", False),
                capabilities=client.V1Capabilities(
                    add=pod_config.get("capabilities", [])
                )
                if pod_config.get("capabilities")
                else None,
            )
            containers.append(
                client.V1Container(
                    name=c.get("name", "main"),
                    image=c.get("image", "nginx"),
                    security_context=sec_ctx,
                    command=c.get(
                        "command", None
                    ),  # FIX: Support command specification
                )
            )

        pod = client.V1Pod(
            metadata=client.V1ObjectMeta(
                name=name,
                namespace=namespace,
                labels=pod_config.get("labels", {}),
                annotations=pod_config.get("annotations", {}),
            ),
            spec=client.V1PodSpec(
                containers=containers,
                service_account_name=pod_config.get("service_account", "default"),
                host_network=pod_config.get("host_network", False),
                host_pid=pod_config.get("host_pid", False),
                node_selector=pod_config.get(
                    "nodeSelector", None
                ),  # FIX: Add nodeSelector support
            ),
        )
        try:
            self.k8s_core_api.create_namespaced_pod(namespace, pod)
            LOGGER.info(f"✓ Created pod: {namespace}/{name}")
        except ApiException as e:
            if e.status != 409:
                LOGGER.error(f"Failed to create pod: {e}")

    def _create_deployment(self, deploy_config: Dict):
        name = deploy_config["name"]
        namespace = deploy_config.get("namespace", "default")
        deployment = client.V1Deployment(
            metadata=client.V1ObjectMeta(
                name=name, namespace=namespace, labels=deploy_config.get("labels", {})
            ),
            spec=client.V1DeploymentSpec(
                replicas=deploy_config.get("replicas", 1),
                selector=client.V1LabelSelector(match_labels={"app": name}),
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(labels={"app": name}),
                    spec=client.V1PodSpec(
                        containers=[
                            client.V1Container(
                                name="main", image=deploy_config.get("image", "nginx")
                            )
                        ]
                    ),
                ),
            ),
        )
        try:
            self.k8s_apps_api.create_namespaced_deployment(namespace, deployment)
            LOGGER.info(f"✓ Created deployment: {namespace}/{name}")
        except ApiException as e:
            if e.status != 409:
                LOGGER.error(f"Failed to create deployment: {e}")

    def _create_secret(self, secret_config: Dict):
        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=secret_config["name"],
                namespace=secret_config.get("namespace", "default"),
            ),
            string_data=secret_config.get("data", {}),
        )
        try:
            self.k8s_core_api.create_namespaced_secret(
                secret_config.get("namespace", "default"), secret
            )
            LOGGER.info(f"✓ Created secret: {secret_config['name']}")
        except ApiException as e:
            if e.status != 409:
                LOGGER.error(f"Failed to create secret: {e}")

    def _create_rbac_resources(self, rbac_config: Dict):
        if isinstance(rbac_config, dict):
            for sa in rbac_config.get("service_accounts", []):
                self._create_service_account(sa)
            for role in rbac_config.get("roles", []):
                self._create_role(role)
            for cr in rbac_config.get("cluster_roles", []):  # ADD
                self._create_cluster_role(cr)
            for binding in rbac_config.get("role_bindings", []):
                self._create_role_binding(binding)
            for crb in rbac_config.get("cluster_role_bindings", []):  # ADD
                self._create_cluster_role_binding(crb)

    def _create_cluster_role(self, cr_config: Dict):
        cr_body = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": cr_config["name"]},
            "rules": cr_config.get("rules", []),
        }
        try:
            self.k8s_rbac_api.create_cluster_role(body=cr_body)
            LOGGER.info(f"✓ Created cluster role: {cr_config['name']}")
        except ApiException as e:
            if e.status != 409:
                LOGGER.error(f"Failed to create cluster role: {e}")

    def _create_cluster_role_binding(self, crb_config: Dict):
        subjects = []
        for s in crb_config.get("subjects", []):
            subject = {
                "kind": s.get("kind", "ServiceAccount"),
                "name": s["name"],
                "namespace": s.get("namespace", "default"),
            }
            if subject["kind"] != "ServiceAccount":
                subject["apiGroup"] = s.get("apiGroup", "rbac.authorization.k8s.io")
            subjects.append(subject)

        crb_body = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": crb_config["name"]},
            "subjects": subjects,
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": crb_config["roleRef"]["name"],
            },
        }
        try:
            self.k8s_rbac_api.create_cluster_role_binding(body=crb_body)
            LOGGER.info(f"✓ Created cluster role binding: {crb_config['name']}")
        except ApiException as e:
            if e.status != 409:
                LOGGER.error(f"Failed to create cluster role binding: {e}")

    def _create_service_account(self, sa_config: Dict):
        sa = client.V1ServiceAccount(
            metadata=client.V1ObjectMeta(
                name=sa_config["name"], namespace=sa_config.get("namespace", "default")
            )
        )
        try:
            self.k8s_core_api.create_namespaced_service_account(
                sa_config.get("namespace", "default"), sa
            )
            LOGGER.info(f"✓ Created service account: {sa_config['name']}")
        except ApiException as e:
            if e.status != 409:
                LOGGER.error(f"Failed to create SA: {e}")

    def _create_role(self, role_config: Dict):
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {
                "name": role_config["name"],
                "namespace": role_config.get("namespace", "default"),
            },
            "rules": role_config.get("rules", []),
        }
        try:
            self.k8s_rbac_api.create_namespaced_role(
                role_config.get("namespace", "default"), body=role
            )
            LOGGER.info(f"✓ Created role: {role_config['name']}")
        except ApiException as e:
            if e.status != 409:
                LOGGER.error(f"Failed to create role: {e}")

    def _create_role_binding(self, binding_config: Dict):
        """FIX: Corrected apiGroup handling for ServiceAccount subjects"""
        namespace = binding_config.get("namespace", "default")

        # Build subjects correctly
        subjects = []
        for s in binding_config.get("subjects", []):
            subject = {
                "kind": s.get("kind", "ServiceAccount"),
                "name": s["name"],
                "namespace": s.get("namespace", namespace),
            }
            # FIX: ServiceAccount subjects should NOT have apiGroup field
            if subject["kind"] != "ServiceAccount":
                subject["apiGroup"] = s.get("apiGroup", "rbac.authorization.k8s.io")
            subjects.append(subject)

        binding_body = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": binding_config["name"], "namespace": namespace},
            "subjects": subjects,
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": binding_config.get("roleRef", {}).get("kind", "Role"),
                "name": binding_config.get("roleRef", {})["name"],
            },
        }

        try:
            self.k8s_rbac_api.create_namespaced_role_binding(
                namespace, body=binding_body
            )
            LOGGER.info(f"✓ Created role binding: {binding_config['name']}")
        except ApiException as e:
            if e.status != 409:
                LOGGER.error(
                    f"Failed to create role binding {binding_config['name']}: {e}"
                )

    def get_cluster_info(self) -> Dict:
        """Get information about the KWOK cluster"""
        if not self.k8s_core_api:
            return {"error": "K8s client not initialized"}

        try:
            return {
                "cluster_name": self.cluster_name,
                "nodes": len(self.k8s_core_api.list_node().items),
                "pods": len(self.k8s_core_api.list_pod_for_all_namespaces().items),
                "namespaces": len(self.k8s_core_api.list_namespace().items),
                "running": self.cluster_running,
                "kubeconfig_path": self.kubeconfig_path,
            }
        except Exception as e:
            return {"error": str(e)}

    def cleanup(self):
        """Cleanup the cluster"""
        self.delete_cluster()
        LOGGER.info(f"✓ Cluster '{self.cluster_name}' cleaned up")


# Helper function to create a sample vulnerable cluster config for KWOK
def create_kwok_cluster_config(output_path: str):
    """Create a sample KWOK cluster configuration"""
    config = {
        "k8s_version": "v1.28.0",
        "namespaces": [
            {"name": "default"},
            {"name": "kube-system", "labels": {"critical": "true"}},
            {"name": "production", "labels": {"env": "prod"}},
            {"name": "dev", "labels": {"env": "dev"}},
        ],
        "nodes": [
            {
                "name": "master-node",
                "labels": {
                    "node-role.kubernetes.io/master": "true",
                    "kubernetes.io/hostname": "master-node",
                },
                "capacity": {"cpu": "4", "memory": "8Gi", "pods": "110"},
            },
            {
                "name": "worker-1",
                "labels": {
                    "node-role.kubernetes.io/worker": "true",
                    "kubernetes.io/hostname": "worker-1",
                },
                "capacity": {"cpu": "8", "memory": "16Gi", "pods": "110"},
            },
            {
                "name": "worker-2",
                "labels": {
                    "node-role.kubernetes.io/worker": "true",
                    "kubernetes.io/hostname": "worker-2",
                },
                "capacity": {"cpu": "8", "memory": "16Gi", "pods": "110"},
            },
        ],
        "workloads": [
            {
                "type": "Pod",
                "name": "web-frontend",
                "namespace": "default",
                "service_account": "default",
                "containers": [{"name": "nginx", "image": "nginx:latest"}],
                "labels": {"app": "web", "tier": "frontend"},
                "annotations": {"cyberbattle.io/initial-access": "true"},
                "vulnerabilities": ["ExposedPort"],
            },
            {
                "type": "Pod",
                "name": "privileged-admin",
                "namespace": "kube-system",
                "service_account": "admin-sa",
                "privileged": True,
                "host_network": True,
                "host_pid": True,
                "capabilities": ["SYS_ADMIN", "NET_ADMIN"],
                "containers": [{"name": "admin", "image": "alpine:latest"}],
                "labels": {"app": "admin"},
            },
            {
                "type": "Deployment",
                "name": "api-backend",
                "namespace": "production",
                "replicas": 3,
                "image": "nginx:latest",
                "labels": {"app": "api", "tier": "backend"},
            },
        ],
        "secrets": [
            {
                "name": "database-credentials",
                "namespace": "production",
                "data": {
                    "username": "admin",
                    "password": "super-secret-password-123",
                    "connection-string": "postgresql://admin:super-secret-password-123@db:5432/prod",
                },
            },
            {
                "name": "api-keys",
                "namespace": "default",
                "data": {
                    "stripe-key": "sk_test_51234567890",
                    "aws-access-key": "AKIAIOSFODNN7EXAMPLE",
                },
            },
        ],
        "rbac": {
            "service_accounts": [
                {"name": "admin-sa", "namespace": "kube-system"},
                {"name": "api-sa", "namespace": "production"},
            ],
            "roles": [
                {
                    "name": "secret-reader",
                    "namespace": "production",
                    "rules": [
                        {
                            "apiGroups": [""],
                            "resources": ["secrets"],
                            "verbs": ["get", "list"],
                        }
                    ],
                },
                {
                    "name": "admin-role",
                    "namespace": "kube-system",
                    "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
                },
            ],
            "role_bindings": [
                {
                    "name": "admin-binding",
                    "namespace": "kube-system",
                    "subjects": [{"kind": "ServiceAccount", "name": "admin-sa"}],
                    "roleRef": {"kind": "Role", "name": "admin-role"},
                }
            ],
        },
    }

    with open(output_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"✓ KWOK cluster config created: {output_path}")


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    print("\n" + "=" * 70)
    print("  KWOK Cluster Manager - Test")
    print("=" * 70 + "\n")

    manager = KWOKClusterManager(
        cluster_name="cyberbattle-test", auto_install=True, verbose=True
    )

    config_path = "kwok_cluster_config.yaml"
    create_kwok_cluster_config(config_path)

    with open(config_path, "r") as f:
        cluster_config = yaml.safe_load(f)

    if manager.create_vulnerable_cluster(cluster_config):
        print("\n✓ Cluster created successfully!")

        info = manager.get_cluster_info()
        print("\n3. Cluster Information:")
        print(f"   Nodes: {info.get('nodes')}")
        print(f"   Pods:  {info.get('pods')}")
        print(f"   Config Path: {info.get('kubeconfig_path')}")

        print("\n4. Cluster is ready for testing!")
        print(
            f"   To connect manually: export KUBECONFIG={info.get('kubeconfig_path')}"
        )
        print("   Then run: kubectl get pods -A")

        input("\nPress Enter to delete the cluster and exit...")

        print("\n5. Cleaning up...")
        manager.cleanup()
        print("✓ Done!")
    else:
        print("\n✗ Failed to create cluster")
