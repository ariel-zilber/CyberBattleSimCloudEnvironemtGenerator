"""
KWOK Integration for CyberBattleSim K8s Manifest Generator - FIXED
===================================================================
Preserves original node names from physical_topology.

Key Fix: Uses node_id from cluster_data['physical_topology']['nodes']
instead of generating generic names like 'master-node', 'worker-zone-a'.
"""

import os
import yaml
import json
import logging
import base64
from typing import Dict, List, Optional
from dataclasses import dataclass

LOGGER = logging.getLogger(__name__)


@dataclass
class KWOKDeploymentConfig:
    """Configuration for KWOK deployment"""

    cluster_name: str = "cyberbattle-sim"
    k8s_version: str = "v1.28.0"
    runtime: str = "binary"

    simulate_node_ips: bool = True
    node_ip_base: str = "10.0.0"

    force_pods_running: bool = True
    wait_for_ready: bool = True
    ready_timeout_seconds: int = 30

    inject_vulnerabilities: bool = True
    add_attack_annotations: bool = True

    add_kwok_labels: bool = True
    kwok_node_label: str = "kwok.x-k8s.io/node"


class ManifestToKWOKConverter:
    """
    Converts standard K8s manifests to KWOK cluster config format.

    FIXED: Now accepts cluster_data to extract original node names
    from physical_topology instead of generating generic names.
    """

    def __init__(
        self,
        config: Optional[KWOKDeploymentConfig] = None,
        cluster_data: Optional[Dict] = None,
    ):
        self.config = config or KWOKDeploymentConfig()
        self.cluster_data = cluster_data
        self.node_ip_counter = 1

    def convert_manifests(self, manifests: Dict[str, List[Dict]]) -> Dict:
        """
        Convert K8s manifests dictionary to KWOK cluster config format.
        """
        kwok_config = {
            "k8s_version": self.config.k8s_version,
            "namespaces": [],
            "nodes": [],
            "workloads": [],
            "secrets": [],
            "rbac": {
                "service_accounts": [],
                "roles": [],
                "cluster_roles": [],
                "role_bindings": [],
                "cluster_role_bindings": [],
            },
        }

        # Convert namespaces
        for ns in manifests.get("namespaces", []):
            kwok_config["namespaces"].append(self._convert_namespace(ns))

        # Ensure essential namespaces exist
        ns_names = [ns["name"] for ns in kwok_config["namespaces"]]
        if "default" not in ns_names:
            kwok_config["namespaces"].insert(0, {"name": "default", "labels": {}})
        if "kube-system" not in ns_names:
            kwok_config["namespaces"].append({"name": "kube-system", "labels": {}})

        # Convert deployments
        for deployment in manifests.get("deployments", []):
            kwok_config["workloads"].append(self._convert_deployment(deployment))

        # Convert secrets
        for secret in manifests.get("secrets", []):
            kwok_config["secrets"].append(self._convert_secret(secret))

        # =========================================================
        # CRITICAL FIX: Extract ORIGINAL nodes from cluster_data
        # =========================================================
        if self.cluster_data:
            kwok_config["nodes"] = self._extract_nodes_from_cluster_data()
        else:
            # Fallback to generic node generation
            LOGGER.warning("No cluster_data provided - using generic node names")
            kwok_config["nodes"] = self._generate_fallback_nodes(
                kwok_config["workloads"], manifests.get("namespaces", [])
            )

        return kwok_config

    def _extract_nodes_from_cluster_data(self) -> List[Dict]:
        """
        Extract ORIGINAL node definitions from cluster_data.

        This preserves the exact node names like:
        - node-worker-000
        - node-control_plane-001
        - node-internet

        Instead of generic names like:
        - master-node
        - worker-zone-a
        """
        nodes = []

        physical_topology = self.cluster_data.get("physical_topology", {})
        physical_nodes = physical_topology.get("nodes", [])

        if not physical_nodes:
            LOGGER.warning("No nodes in physical_topology, using fallback")
            return []

        LOGGER.info(f"Extracting {len(physical_nodes)} nodes from physical_topology")

        for node_data in physical_nodes:
            # Get original node ID - THIS IS THE KEY FIX
            node_id = node_data.get("node_id", "unknown")
            node_type = node_data.get("node_type", "worker")
            zone = node_data.get("zone", "zone-a")
            properties = node_data.get("properties", [])
            original_labels = node_data.get("labels", {})

            # Get IP from ip_allocation
            ip_allocation = node_data.get("ip_allocation", {})
            node_ip = ip_allocation.get("ipv4", "10.0.0.1")

            # Get capacity from characteristics
            characteristics = node_data.get("characteristics", {})
            capacity = {
                "cpu": str(characteristics.get("cpu_cores", 4)),
                "memory": f"{characteristics.get('memory_gb', 8)}Gi",
                "pods": "110",
            }

            # Build node labels - preserve original + add standard K8s labels
            labels = {
                "kubernetes.io/hostname": node_id,  # Use original node_id
                "topology.kubernetes.io/zone": zone,
                "cybersim/node-type": node_type,
                "cybersim/original-id": node_id,
            }

            # Add role labels based on node type
            if node_type in ["control_plane", "master"]:
                labels["node-role.kubernetes.io/control-plane"] = "true"
                labels["node-role.kubernetes.io/master"] = "true"
            elif node_type == "worker":
                labels["node-role.kubernetes.io/worker"] = "true"
            elif node_type == "internet":
                labels["cybersim/role"] = "attacker"
                labels["node-role.kubernetes.io/attacker"] = "true"

            # Handle special properties
            for prop in properties:
                if prop == "attacker":
                    labels["cybersim/role"] = "attacker"
                    labels["node-role.kubernetes.io/attacker"] = "true"
                elif prop == "control_plane":
                    labels["node-role.kubernetes.io/control-plane"] = "true"
                elif prop == "external":
                    labels["cybersim/external"] = "true"
                elif prop == "internet":
                    labels["cybersim/internet"] = "true"

            # Merge with original labels (original takes precedence)
            labels.update(original_labels)

            # Build taints for special nodes
            taints = None
            if "attacker" in properties or node_type == "internet":
                taints = [
                    {
                        "key": "cybersim/attacker",
                        "value": "true",
                        "effect": "NoSchedule",
                    }
                ]

            node_config = {
                "name": node_id,  # CRITICAL: Use original node_id as name
                "labels": labels,
                "capacity": capacity,
                "node_ip": node_ip,
            }

            if taints:
                node_config["taints"] = taints

            nodes.append(node_config)
            LOGGER.debug(f"  -> {node_id} (type={node_type}, zone={zone})")

        return nodes

    def _generate_fallback_nodes(
        self, workloads: List[Dict], namespaces: List[Dict]
    ) -> List[Dict]:
        """Fallback node generation when cluster_data is not available."""
        nodes = []
        zones_seen = set()

        for ns in namespaces:
            labels = ns.get("labels", {})
            zone = labels.get("cybersim/zone")
            if zone:
                zones_seen.add(zone)

        if not zones_seen:
            zones_seen = {"zone-a", "zone-b", "zone-c"}

        # Create control plane node
        nodes.append(
            {
                "name": "node-control_plane-000",
                "labels": {
                    "node-role.kubernetes.io/control-plane": "true",
                    "node-role.kubernetes.io/master": "true",
                    "kubernetes.io/hostname": "node-control_plane-000",
                },
                "capacity": {"cpu": "4", "memory": "8Gi", "pods": "110"},
                "node_ip": f"{self.config.node_ip_base}.1",
            }
        )

        # Create worker nodes per zone
        for i, zone in enumerate(sorted(zones_seen)):
            node_name = f"node-worker-{i:03d}"
            nodes.append(
                {
                    "name": node_name,
                    "labels": {
                        "node-role.kubernetes.io/worker": "true",
                        "kubernetes.io/hostname": node_name,
                        "topology.kubernetes.io/zone": zone,
                        "cybersim/zone": zone,
                    },
                    "capacity": {"cpu": "8", "memory": "16Gi", "pods": "110"},
                    "node_ip": f"{self.config.node_ip_base}.{10 + i}",
                }
            )

        # Add attacker/internet node
        nodes.append(
            {
                "name": "node-internet",
                "labels": {
                    "node-role.kubernetes.io/attacker": "true",
                    "kubernetes.io/hostname": "node-internet",
                    "cybersim/role": "attacker",
                },
                "capacity": {"cpu": "2", "memory": "4Gi", "pods": "10"},
                "node_ip": "192.168.1.100",
                "taints": [
                    {
                        "key": "cybersim/attacker",
                        "value": "true",
                        "effect": "NoSchedule",
                    }
                ],
            }
        )

        return nodes

    def _convert_namespace(self, ns_manifest: Dict) -> Dict:
        """Convert K8s Namespace manifest to KWOK format"""
        metadata = ns_manifest.get("metadata", {})
        return {
            "name": metadata.get("name", "default"),
            "labels": metadata.get("labels", {}),
        }

    def _convert_deployment(self, deploy_manifest: Dict) -> Dict:
        """Convert K8s Deployment manifest to KWOK workload format"""
        metadata = deploy_manifest.get("metadata", {})
        spec = deploy_manifest.get("spec", {})
        pod_spec = spec.get("template", {}).get("spec", {})

        containers = []
        for container in pod_spec.get("containers", []):
            containers.append(
                {
                    "name": container.get("name", "main"),
                    "image": container.get("image", "busybox"),
                }
            )

        workload = {
            "type": "Deployment",
            "name": metadata.get("name", "unknown"),
            "namespace": metadata.get("namespace", "default"),
            "replicas": spec.get("replicas", 1),
            "labels": metadata.get("labels", {}),
            "annotations": metadata.get("annotations", {}),
            "containers": containers,
            "image": containers[0]["image"] if containers else "busybox",
            "service_account": pod_spec.get("serviceAccountName", "default"),
            "host_network": pod_spec.get("hostNetwork", False),
            "host_pid": pod_spec.get("hostPID", False),
        }

        # Check security context
        if pod_spec.get("containers"):
            sec_ctx = pod_spec["containers"][0].get("securityContext", {})
            workload["privileged"] = sec_ctx.get("privileged", False)
            if sec_ctx.get("capabilities"):
                workload["capabilities"] = sec_ctx["capabilities"].get("add", [])

        return workload

    def _convert_secret(self, secret_manifest: Dict) -> Dict:
        """Convert K8s Secret manifest to KWOK format"""
        metadata = secret_manifest.get("metadata", {})

        secret_data = secret_manifest.get("stringData", {})
        if not secret_data:
            for key, value in secret_manifest.get("data", {}).items():
                try:
                    secret_data[key] = base64.b64decode(value).decode("utf-8")
                except:
                    secret_data[key] = value

        return {
            "name": metadata.get("name", "unknown"),
            "namespace": metadata.get("namespace", "default"),
            "data": secret_data,
        }


class KWOKDeployer:
    """
    Deploys CyberBattleSim topology to a KWOK cluster.

    FIXED: Now passes cluster_data to converter for original node names.
    """

    def __init__(self, kwok_manager, config: Optional[KWOKDeploymentConfig] = None):
        self.kwok = kwok_manager
        self.config = config or KWOKDeploymentConfig()
        self.cluster_data = None  # Will be set when deploying
        self.deployed_resources = {
            "namespaces": [],
            "nodes": [],
            "workloads": [],
            "secrets": [],
        }

    def deploy_from_manifests(
        self,
        manifests: Dict[str, List[Dict]],
        create_cluster: bool = True,
        cluster_data: Optional[Dict] = None,
    ) -> bool:
        """
        Deploy K8s manifests to KWOK cluster.

        Args:
            manifests: Dict with keys like 'namespaces', 'deployments', etc.
            create_cluster: Whether to create a new KWOK cluster
            cluster_data: Original cluster_data for preserving node names
        """
        self.cluster_data = cluster_data

        # Create converter WITH cluster_data for original node names
        converter = ManifestToKWOKConverter(self.config, cluster_data)
        kwok_config = converter.convert_manifests(manifests)

        LOGGER.info("Converted to KWOK config:")
        LOGGER.info(f"  Namespaces: {len(kwok_config['namespaces'])}")
        LOGGER.info(f"  Nodes: {len(kwok_config['nodes'])}")
        LOGGER.info(f"  Workloads: {len(kwok_config['workloads'])}")
        LOGGER.info(f"  Secrets: {len(kwok_config['secrets'])}")

        # Show node names for verification
        print("\n🖥️  Nodes to create (original names):")
        for node in kwok_config["nodes"]:
            node_type = node["labels"].get(
                "cybersim/node-type",
                node["labels"].get("node-role.kubernetes.io/control-plane", "worker"),
            )
            zone = node["labels"].get("topology.kubernetes.io/zone", "N/A")
            print(f"   - {node['name']:30s} type={node_type:15s} zone={zone}")

        if create_cluster:
            LOGGER.info(f"Creating KWOK cluster: {self.config.cluster_name}")
            success = self.kwok.create_vulnerable_cluster(
                kwok_config, create_cluster_first=True
            )
        else:
            success = self.kwok.create_vulnerable_cluster(
                kwok_config, create_cluster_first=False
            )

        if success:
            self._record_deployment(kwok_config)
            self._verify_deployment()

        return success

    def deploy_from_cluster_data(
        self, cluster_data: Dict, create_cluster: bool = True
    ) -> bool:
        """
        Deploy directly from cluster_data JSON.
        Generates K8s manifests and deploys them.
        """
        try:
            from k8s_manifest_generator import K8sManifestGenerator, K8sManifestConfig
        except ImportError:
            LOGGER.error("k8s_manifest_generator not found")
            return False

        LOGGER.info("Generating K8s manifests from cluster_data...")

        k8s_config = K8sManifestConfig(
            namespace_prefix=self.config.cluster_name,
            use_network_policies=False,
            create_ingress=False,
        )

        generator = K8sManifestGenerator(cluster_data, k8s_config)
        manifests = generator.generate_all()

        # Pass cluster_data to preserve node names
        return self.deploy_from_manifests(manifests, create_cluster, cluster_data)

    def deploy_from_directory(
        self,
        manifest_dir: str,
        create_cluster: bool = True,
        cluster_data: Optional[Dict] = None,
    ) -> bool:
        """
        Deploy from a directory of K8s manifest files.

        Args:
            manifest_dir: Path to directory containing YAML files
            create_cluster: Whether to create a new KWOK cluster
            cluster_data: Original cluster_data for node names (optional)
        """
        LOGGER.info(f"Loading manifests from: {manifest_dir}")

        manifests = {
            "namespaces": [],
            "deployments": [],
            "services": [],
            "secrets": [],
            "configmaps": [],
            "network_policies": [],
        }

        for root, dirs, files in os.walk(manifest_dir):
            for filename in files:
                if not filename.endswith((".yaml", ".yml")):
                    continue

                filepath = os.path.join(root, filename)
                with open(filepath, "r") as f:
                    for doc in yaml.safe_load_all(f):
                        if not doc:
                            continue

                        kind = doc.get("kind", "").lower()

                        if kind == "namespace":
                            manifests["namespaces"].append(doc)
                        elif kind == "deployment":
                            manifests["deployments"].append(doc)
                        elif kind == "secret":
                            manifests["secrets"].append(doc)
                        elif kind == "service":
                            manifests["services"].append(doc)
                        elif kind == "configmap":
                            manifests["configmaps"].append(doc)
                        elif kind == "networkpolicy":
                            manifests["network_policies"].append(doc)

        LOGGER.info(f"Loaded: {sum(len(v) for v in manifests.values())} resources")

        return self.deploy_from_manifests(manifests, create_cluster, cluster_data)

    def _record_deployment(self, kwok_config: Dict):
        """Record what was deployed for later reference"""
        self.deployed_resources = {
            "namespaces": [ns["name"] for ns in kwok_config.get("namespaces", [])],
            "nodes": [n["name"] for n in kwok_config.get("nodes", [])],
            "workloads": [
                (w["namespace"], w["name"]) for w in kwok_config.get("workloads", [])
            ],
            "secrets": [
                (s["namespace"], s["name"]) for s in kwok_config.get("secrets", [])
            ],
        }

    def _verify_deployment(self) -> bool:
        """Verify that deployment was successful"""
        if not self.config.wait_for_ready:
            return True

        LOGGER.info("Verifying deployment...")

        try:
            info = self.kwok.get_cluster_info()

            expected_nodes = len(self.deployed_resources["nodes"])
            actual_nodes = info.get("nodes", 0)

            if actual_nodes < expected_nodes:
                LOGGER.warning(f"Expected {expected_nodes} nodes, got {actual_nodes}")
                return False

            LOGGER.info(
                f"✓ Deployment verified: {actual_nodes} nodes, {info.get('pods', 0)} pods"
            )
            return True

        except Exception as e:
            LOGGER.error(f"Verification failed: {e}")
            return False

    def get_attack_surface(self) -> Dict:
        """Get the attack surface of the deployed cluster."""
        if not self.kwok.k8s_core_api:
            return {"error": "K8s client not initialized"}

        attack_surface = {
            "entry_points": [],
            "privileged_pods": [],
            "secrets_accessible": [],
            "service_accounts": [],
            "nodes": [],
        }

        try:
            # Get pods with initial-access annotation
            pods = self.kwok.k8s_core_api.list_pod_for_all_namespaces()
            for pod in pods.items:
                annotations = pod.metadata.annotations or {}

                if annotations.get("cyberbattle.io/initial-access") == "true":
                    attack_surface["entry_points"].append(
                        {
                            "name": pod.metadata.name,
                            "namespace": pod.metadata.namespace,
                            "node": pod.spec.node_name,
                        }
                    )

                # Check for privileged containers
                for container in pod.spec.containers:
                    if (
                        container.security_context
                        and container.security_context.privileged
                    ):
                        attack_surface["privileged_pods"].append(
                            {
                                "name": pod.metadata.name,
                                "namespace": pod.metadata.namespace,
                                "container": container.name,
                            }
                        )

            # Get nodes
            nodes = self.kwok.k8s_core_api.list_node()
            for node in nodes.items:
                labels = node.metadata.labels or {}
                attack_surface["nodes"].append(
                    {
                        "name": node.metadata.name,
                        "role": labels.get(
                            "cybersim/role",
                            "control-plane"
                            if "node-role.kubernetes.io/control-plane" in labels
                            else "worker",
                        ),
                        "zone": labels.get("topology.kubernetes.io/zone", "unknown"),
                    }
                )

            # Get secrets
            secrets = self.kwok.k8s_core_api.list_secret_for_all_namespaces()
            for secret in secrets.items:
                if "service-account" not in secret.metadata.name:
                    attack_surface["secrets_accessible"].append(
                        {
                            "name": secret.metadata.name,
                            "namespace": secret.metadata.namespace,
                            "keys": list(secret.data.keys()) if secret.data else [],
                        }
                    )

        except Exception as e:
            LOGGER.error(f"Failed to get attack surface: {e}")

        return attack_surface


def deploy_to_kwok(
    cluster_data: Dict,
    cluster_name: str = "cyberbattle-sim",
    k8s_version: str = "v1.28.0",
    auto_install: bool = True,
) -> Optional[KWOKDeployer]:
    """
    Main entry point for deploying cluster_data to KWOK.

    Args:
        cluster_data: The full cluster_data dictionary from the generator
        cluster_name: Name for the KWOK cluster
        k8s_version: Kubernetes version to simulate
        auto_install: Whether to auto-install KWOK if not present

    Returns:
        KWOKDeployer instance if successful, None otherwise
    """
    try:
        from kwok_cluster_manager import KWOKClusterManager
    except ImportError:
        LOGGER.error("KWOKClusterManager not found")
        return None

    config = KWOKDeploymentConfig(cluster_name=cluster_name, k8s_version=k8s_version)

    kwok_manager = KWOKClusterManager(
        cluster_name=cluster_name, auto_install=auto_install, verbose=True
    )

    deployer = KWOKDeployer(kwok_manager, config)

    success = deployer.deploy_from_cluster_data(cluster_data, create_cluster=True)

    if success:
        return deployer
    return None


# =============================================================================
# CLI for standalone usage
# =============================================================================


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Deploy CyberBattleSim topology to KWOK (preserves original node names)"
    )

    parser.add_argument(
        "--cluster-json",
        "-c",
        type=str,
        required=True,
        help="Path to cluster_full.json (REQUIRED for correct node names)",
    )
    parser.add_argument(
        "--manifest-dir",
        "-m",
        type=str,
        help="Path to directory containing K8s manifests (optional)",
    )
    parser.add_argument(
        "--cluster-name",
        "-n",
        type=str,
        default="cyberbattle-sim",
        help="Name for the KWOK cluster",
    )
    parser.add_argument(
        "--k8s-version",
        type=str,
        default="v1.28.0",
        help="Kubernetes version to simulate",
    )
    parser.add_argument(
        "--output-config",
        "-o",
        type=str,
        help="Save KWOK config to file without deploying",
    )
    parser.add_argument(
        "--show-attack-surface",
        action="store_true",
        help="Show attack surface after deployment",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Load cluster_data
    with open(args.cluster_json, "r") as f:
        cluster_data = json.load(f)
    print(f"✓ Loaded cluster data from: {args.cluster_json}")

    # If manifest directory provided, load manifests from there
    manifests = None
    if args.manifest_dir:
        manifests = load_manifests_from_directory(args.manifest_dir)

    # Convert to KWOK config
    config = KWOKDeploymentConfig(
        cluster_name=args.cluster_name, k8s_version=args.k8s_version
    )
    converter = ManifestToKWOKConverter(config, cluster_data)

    if manifests:
        kwok_config = converter.convert_manifests(manifests)
    else:
        # Generate manifests from cluster_data
        try:
            from k8s_manifest_generator import K8sManifestGenerator, K8sManifestConfig

            k8s_config = K8sManifestConfig(
                namespace_prefix=args.cluster_name,
                use_network_policies=False,
            )
            generator = K8sManifestGenerator(cluster_data, k8s_config)
            manifests = generator.generate_all()
            kwok_config = converter.convert_manifests(manifests)
        except ImportError:
            print("ERROR: k8s_manifest_generator not found")
            return 1

    # Print summary
    print("\n📋 Configuration Summary:")
    print(f"   Namespaces: {len(kwok_config['namespaces'])}")
    print(f"   Nodes:      {len(kwok_config['nodes'])}")
    print(f"   Workloads:  {len(kwok_config['workloads'])}")
    print(f"   Secrets:    {len(kwok_config['secrets'])}")

    print("\n🖥️  Nodes (ORIGINAL names from physical_topology):")
    for node in kwok_config["nodes"]:
        node_type = node["labels"].get("cybersim/node-type", "unknown")
        zone = node["labels"].get("topology.kubernetes.io/zone", "N/A")
        ip = node.get("node_ip", "N/A")
        print(f"   - {node['name']:30s} type={node_type:15s} zone={zone:10s} ip={ip}")

    # Save config if requested
    if args.output_config:
        with open(args.output_config, "w") as f:
            yaml.dump(kwok_config, f, default_flow_style=False, sort_keys=False)
        print(f"\n✓ KWOK config saved to: {args.output_config}")
        return 0

    # Deploy to KWOK
    try:
        from kwok_cluster_manager import KWOKClusterManager
    except ImportError:
        print("ERROR: KWOKClusterManager not found")
        return 1

    print(f"\n🚀 Creating KWOK cluster: {args.cluster_name}")

    manager = KWOKClusterManager(
        cluster_name=args.cluster_name, auto_install=True, verbose=args.verbose
    )

    success = manager.create_vulnerable_cluster(kwok_config, create_cluster_first=True)

    if success:
        info = manager.get_cluster_info()
        print("\n✅ KWOK cluster created successfully!")
        print("\n📊 Cluster Info:")
        print(f"   Name:   {info.get('cluster_name')}")
        print(f"   Nodes:  {info.get('nodes')}")
        print(f"   Pods:   {info.get('pods')}")
        print("\n🔗 To connect:")
        print(f"   export KUBECONFIG={info.get('kubeconfig_path')}")
        print("   kubectl get nodes")
        print("   kubectl get pods -A -o wide")

        if args.show_attack_surface:
            deployer = KWOKDeployer(manager, config)
            deployer.cluster_data = cluster_data
            surface = deployer.get_attack_surface()
            print("\n⚔️  Attack Surface:")
            print(f"   Entry points: {len(surface.get('entry_points', []))}")
            print(f"   Privileged pods: {len(surface.get('privileged_pods', []))}")
            print(
                f"   Accessible secrets: {len(surface.get('secrets_accessible', []))}"
            )
            print("   Nodes:")
            for node in surface.get("nodes", []):
                print(f"      - {node['name']} ({node['role']})")

        return 0
    else:
        print("❌ Failed to create KWOK cluster")
        return 1


def load_manifests_from_directory(manifest_dir: str) -> Dict[str, List]:
    """Load all K8s manifests from a directory structure."""
    manifests = {
        "namespaces": [],
        "deployments": [],
        "services": [],
        "secrets": [],
        "configmaps": [],
        "network_policies": [],
    }

    if not os.path.exists(manifest_dir):
        LOGGER.error(f"Directory not found: {manifest_dir}")
        return manifests

    for root, dirs, files in os.walk(manifest_dir):
        for filename in files:
            if not filename.endswith((".yaml", ".yml")):
                continue

            filepath = os.path.join(root, filename)
            try:
                with open(filepath, "r") as f:
                    for doc in yaml.safe_load_all(f):
                        if not doc:
                            continue

                        kind = doc.get("kind", "").lower()

                        if kind == "namespace":
                            manifests["namespaces"].append(doc)
                        elif kind == "deployment":
                            manifests["deployments"].append(doc)
                        elif kind == "service":
                            manifests["services"].append(doc)
                        elif kind == "secret":
                            manifests["secrets"].append(doc)
                        elif kind == "configmap":
                            manifests["configmaps"].append(doc)
                        elif kind == "networkpolicy":
                            manifests["network_policies"].append(doc)
            except Exception as e:
                LOGGER.warning(f"Failed to parse {filepath}: {e}")

    total = sum(len(v) for v in manifests.values())
    LOGGER.info(f"Loaded {total} manifests from {manifest_dir}")
    return manifests


if __name__ == "__main__":
    exit(main())
