"""
Full Stack Cloud Generator with Kubernetes Deployment
======================================================
Generates cloud environments for CyberBattleSim with optional K8s manifests.

Usage:
    python main.py                          # Uses default config.yaml
    python main.py --config my_config.yaml  # Uses custom config
    python main.py --config config.yaml --override core.nodes=100
"""

import argparse
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import yaml

# --- Internal Imports ---
from cyberbattlesim_cloud_gen.generators.file_utils import save_yaml
from cyberbattlesim_cloud_gen.generators.logical_gen.k8s_cluster_generator import (
    K8sClusterGenerator,
)
from cyberbattlesim_cloud_gen.generators.logical_gen.cluster_dynamic_config import (
    ClusterDynamicConfig,
)
from cyberbattlesim_cloud_gen.generators.logical_gen.subnet_config import SubnetConfig
from cyberbattlesim_cloud_gen.generators.logical_gen.network_topology_config import (
    NetworkTopologyConfig,
)
from cyberbattlesim_cloud_gen.generators.logical_gen.firewall_config import (
    FirewallConfig,
)
from cyberbattlesim_cloud_gen.generators.network_gen.network_topology_generator import (
    NetworkTopologyGenerator,
)
from cyberbattlesim_cloud_gen.generators.network_gen.topology_to_dict import (
    topology_to_dict,
)
from cyberbattlesim_cloud_gen.generators.physical_gen.physical_node_generator import (
    PhysicalNodeGenerator,
)
from cyberbattlesim_cloud_gen.generators.cyberbattle import ClusterAttackGenerator
from cyberbattlesim_cloud_gen.visualization.logical_viz import visualize_graph_from_data
from cyberbattlesim_cloud_gen.visualization.physical_viz import (
    visualize_physical_from_data,
)
from cyberbattlesim_network_gen.generators.file_utils import *
from cyberbattlesim_network_gen.generators.view_utils import *
from cyberbattlesim_cloud_gen.generators.vulnerability_gen.vulnerability_assigner import (
    VulnerabilityAssigner,
)
from cyberbattlesim_cloud_gen.config.config_loader import ConfigLoader

# --- Optional K8s Generator ---
try:
    from k8s_manifest_generator import K8sManifestGenerator, K8sManifestConfig
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False


# =============================================================================
# Configuration Dataclass
# =============================================================================

@dataclass
class PipelineConfig:
    """Unified configuration for the generation pipeline."""
    
    # Core
    nodes: int = 50
    use_case: str = "microservices"
    zones: int = 3
    seed: int = 42
    
    # Network
    topology_type: str = "mesh"
    firewall_probability: float = 0.2
    knowledge_completeness: float = 0.7
    
    # Vulnerabilities
    vuln_enabled: bool = False
    cve_json_path: Optional[str] = None
    vuln_db_path: Optional[str] = None
    
    # Output
    base_dir: str = "./outputs"
    intermediate_json: str = "cluster_full.json"
    sim_output_dir: str = "generated_env"
    visualize: bool = True
    
    # Kubernetes
    k8s_enabled: bool = False
    k8s_output_dir: Optional[str] = None
    k8s_namespace_prefix: str = "cybersim"
    k8s_network_policies: bool = True
    k8s_ingress: bool = True
    k8s_ingress_class: str = "nginx"
    k8s_single_file: bool = False
    k8s_helm_enabled: bool = False
    k8s_helm_name: str = "cybersim-cluster"
    k8s_cpu_limit: str = "100m"
    k8s_memory_limit: str = "128Mi"
    k8s_cpu_request: str = "50m"
    k8s_memory_request: str = "64Mi"
    
    # Config loader
    config_loader_dir: Optional[str] = None

    @classmethod
    def from_yaml(cls, yaml_path: str) -> "PipelineConfig":
        """Load configuration from YAML file."""
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)
        
        return cls(
            # Core
            nodes=data.get("core", {}).get("nodes", 50),
            use_case=data.get("core", {}).get("use_case", "microservices"),
            zones=data.get("core", {}).get("zones", 3),
            seed=data.get("core", {}).get("seed", 42),
            
            # Network
            topology_type=data.get("network", {}).get("topology_type", "mesh"),
            firewall_probability=data.get("network", {}).get("firewall_probability", 0.2),
            knowledge_completeness=data.get("network", {}).get("knowledge_completeness", 0.7),
            
            # Vulnerabilities
            vuln_enabled=data.get("vulnerabilities", {}).get("enabled", False),
            cve_json_path=data.get("vulnerabilities", {}).get("cve_json_path"),
            vuln_db_path=data.get("vulnerabilities", {}).get("vuln_db_path"),
            
            # Output
            base_dir=data.get("output", {}).get("base_dir", "./outputs"),
            intermediate_json=data.get("output", {}).get("intermediate_json", "cluster_full.json"),
            sim_output_dir=data.get("output", {}).get("sim_output_dir", "generated_env"),
            visualize=data.get("output", {}).get("visualize", True),
            
            # Kubernetes
            k8s_enabled=data.get("kubernetes", {}).get("enabled", False),
            k8s_output_dir=data.get("kubernetes", {}).get("output_dir"),
            k8s_namespace_prefix=data.get("kubernetes", {}).get("namespace_prefix", "cybersim"),
            k8s_network_policies=data.get("kubernetes", {}).get("generate_network_policies", True),
            k8s_ingress=data.get("kubernetes", {}).get("generate_ingress", True),
            k8s_ingress_class=data.get("kubernetes", {}).get("ingress_class", "nginx"),
            k8s_single_file=data.get("kubernetes", {}).get("single_file", False),
            k8s_helm_enabled=data.get("kubernetes", {}).get("helm", {}).get("enabled", False),
            k8s_helm_name=data.get("kubernetes", {}).get("helm", {}).get("chart_name", "cybersim-cluster"),
            k8s_cpu_limit=data.get("kubernetes", {}).get("resources", {}).get("limits", {}).get("cpu", "100m"),
            k8s_memory_limit=data.get("kubernetes", {}).get("resources", {}).get("limits", {}).get("memory", "128Mi"),
            k8s_cpu_request=data.get("kubernetes", {}).get("resources", {}).get("requests", {}).get("cpu", "50m"),
            k8s_memory_request=data.get("kubernetes", {}).get("resources", {}).get("requests", {}).get("memory", "64Mi"),
            
            # Config loader
            config_loader_dir=data.get("config_loader", {}).get("base_dir"),
        )

    def apply_overrides(self, overrides: list) -> None:
        """Apply CLI overrides in format 'key.subkey=value'."""
        for override in overrides:
            if "=" not in override:
                continue
            key_path, value = override.split("=", 1)
            
            # Map dotted paths to flat attributes
            key_map = {
                "core.nodes": "nodes",
                "core.use_case": "use_case",
                "core.zones": "zones",
                "core.seed": "seed",
                "network.topology_type": "topology_type",
                "network.firewall_probability": "firewall_probability",
                "network.knowledge_completeness": "knowledge_completeness",
                "kubernetes.enabled": "k8s_enabled",
                "output.visualize": "visualize",
            }
            
            attr_name = key_map.get(key_path, key_path.replace(".", "_"))
            
            if hasattr(self, attr_name):
                current_val = getattr(self, attr_name)
                # Type conversion
                if isinstance(current_val, bool):
                    value = value.lower() in ("true", "1", "yes")
                elif isinstance(current_val, int):
                    value = int(value)
                elif isinstance(current_val, float):
                    value = float(value)
                setattr(self, attr_name, value)

    @property
    def output_json_path(self) -> str:
        return os.path.join(self.base_dir, self.intermediate_json)

    @property
    def sim_output_path(self) -> str:
        return os.path.join(self.base_dir, self.sim_output_dir)

    @property
    def k8s_output_path(self) -> str:
        if self.k8s_output_dir:
            return self.k8s_output_dir
        return os.path.join(self.sim_output_path, "kubernetes")


# =============================================================================
# Pipeline Functions
# =============================================================================

def load_vulnerability_assigner(config: PipelineConfig) -> Optional[VulnerabilityAssigner]:
    """Load vulnerability assigner if enabled and paths provided."""
    if not config.vuln_enabled or not config.cve_json_path or not config.vuln_db_path:
        return None
    
    try:
        print("🔒 Loading Vulnerability Database...")
        return VulnerabilityAssigner(
            config.cve_json_path, 
            config.vuln_db_path, 
            seed=config.seed
        )
    except Exception as e:
        print(f"⚠️  Warning: Failed to load vulnerability data: {e}")
        return None


def generate_logical_cluster(config: PipelineConfig, config_loader: ConfigLoader) -> Dict:
    """Step 1: Generate logical cluster topology."""
    print(f"1. Generating Logical Cluster ({config.nodes} nodes, {config.use_case})...")
    
    # Subnet Configuration
    subnet_config = SubnetConfig(
        subnet_ranges=config_loader.get_subnet_ranges(),
        address_space_bounds=config_loader.get_subnet_bounds(),
        subnet_labels=config_loader.get_subnet_labels(),
        sensitive_subnet_probabilities=config_loader.get_sensitive_subnet_probabilities(),
    )
    
    # Network Topology Configuration
    raw_topo_config = config_loader.get_topology_config()
    topology_type = config.topology_type or config_loader.get_topology_type()
    
    net_topo_config = NetworkTopologyConfig(
        topology_type=topology_type,
        connectivity_probability=raw_topo_config.get("connectivity_probability", 0.3),
        topology_matrix=raw_topo_config.get("topology_matrix"),
    )
    
    # Firewall Configuration
    firewall_data = raw_topo_config.get("firewall", {})
    valid_keys = {"incoming", "incoming_exceptions", "outgoing", "outgoing_exceptions", "default_block_probability"}
    filtered_fw = {k: v for k, v in firewall_data.items() if k in valid_keys}
    firewall_config = FirewallConfig(**filtered_fw) if filtered_fw else None
    
    # Create and run generator
    logical_config = ClusterDynamicConfig(
        num_nodes=config.nodes,
        use_case=config.use_case,
        seed=config.seed,
        subnet_config=subnet_config,
        network_topology=net_topo_config,
        firewall_config=firewall_config,
    )
    
    generator = K8sClusterGenerator(logical_config, config_loader_instance=config_loader)
    return generator.generate()


def generate_network_topology(config: PipelineConfig, config_loader: ConfigLoader, 
                               cluster_data: Dict, vuln_assigner: Optional[VulnerabilityAssigner]) -> Dict:
    """Step 2: Generate network topology with vulnerabilities."""
    print("2. Generating Network Topology...")
    
    net_gen = NetworkTopologyGenerator(
        config_loader_instance=config_loader,
        services=cluster_data["services"],
        service_instances=cluster_data["service_instances"],
        seed=config.seed,
        vulnerability_assigner=vuln_assigner,
    )
    
    network_topology = net_gen.generate(
        firewall_probability=config.firewall_probability,
        knowledge_completeness=config.knowledge_completeness,
    )
    
    cluster_data["network_topology"] = topology_to_dict(network_topology)
    
    # Report vulnerability stats
    if vuln_assigner and "metadata" in cluster_data["network_topology"]:
        stats = cluster_data["network_topology"]["metadata"].get("vulnerability_stats", {})
        count = stats.get("total_vulnerabilities", 0)
        if count > 0:
            print(f"   -> Assigned {count} specific vulnerabilities")
    
    return cluster_data


def generate_physical_topology(config: PipelineConfig, config_loader: ConfigLoader, 
                                cluster_data: Dict) -> Dict:
    """Step 3: Generate physical infrastructure."""
    print("3. Generating Physical Infrastructure...")
    
    phys_gen = PhysicalNodeGenerator(
        config_loader_instance=config_loader,
        cluster_config=cluster_data,
        num_nodes=config.nodes,
        num_zones=config.zones,
        seed=config.seed,
    )
    
    cluster_data["physical_topology"] = phys_gen.generate(
        firewall_probability=0.0,
        firewall_cross_zone_only=False,
    )
    
    return cluster_data


def save_outputs(config: PipelineConfig, cluster_data: Dict) -> None:
    """Step 4: Save intermediate data and visualizations."""
    print(f"4. Saving Intermediate Data to {config.output_json_path}...")
    
    os.makedirs(os.path.dirname(os.path.abspath(config.output_json_path)), exist_ok=True)
    
    with open(config.output_json_path, "w") as f:
        json.dump(cluster_data, f, indent=2)
    
    if config.visualize:
        print("   Generating Visualizations...")
        visualize_graph_from_data(cluster_data, config.output_json_path)
        visualize_physical_from_data(cluster_data, config.output_json_path)


def generate_cyberbattlesim(config: PipelineConfig, cluster_data: Dict) -> Dict:
    """Step 5: Convert to CyberBattleSim environment."""
    print("5. Converting to CyberBattleSim Environment...")
    
    cbs_gen = ClusterAttackGenerator(
        config_file=config.output_json_path,
        cluster_config=cluster_data,
        out_dir=config.sim_output_path,
    )
    generated = cbs_gen.generate()
    
    # Create output directories
    for subdir in ["nodes", "identifiers", "vulnerability_library", "graphs"]:
        os.makedirs(os.path.join(config.sim_output_path, subdir), exist_ok=True)
    
    # Save artifacts
    print("   Saving CyberBattleSim artifacts...")
    
    for name, node in generated["nodes"].items():
        save_yaml(node.to_dict(), os.path.join(config.sim_output_path, "nodes", f"{name}.yaml"))
    
    save_yaml(
        generated["identifiers"].to_dict(),
        os.path.join(config.sim_output_path, "identifiers", "identifiers.yaml"),
    )
    
    save_yaml(
        generated["vulnerability_library"],
        os.path.join(config.sim_output_path, "vulnerability_library", "vulnerability_library.yaml"),
    )
    
    # Plot network
    try:
        plot_ip_network(generated["nodes"], os.path.join(config.sim_output_path, "graphs", "network"))
    except Exception as e:
        print(f"⚠️  Warning: Failed to plot network: {e}")
    
    return generated


def generate_kubernetes_manifests(config: PipelineConfig, cluster_data: Dict) -> Optional[Dict]:
    """Step 6: Generate Kubernetes manifests."""
    if not config.k8s_enabled:
        return None
    
    if not K8S_AVAILABLE:
        print("⚠️  Warning: k8s_manifest_generator not available. Skipping K8s generation.")
        return None
    
    print("\n6. Generating Kubernetes Manifests...")
    
    k8s_config = K8sManifestConfig(
        namespace_prefix=config.k8s_namespace_prefix,
        use_network_policies=config.k8s_network_policies,
        create_ingress=config.k8s_ingress,
        ingress_class=config.k8s_ingress_class,
        default_resource_limits={"cpu": config.k8s_cpu_limit, "memory": config.k8s_memory_limit},
        default_resource_requests={"cpu": config.k8s_cpu_request, "memory": config.k8s_memory_request},
    )
    
    generator = K8sManifestGenerator(cluster_data, k8s_config)
    manifests = generator.generate_all()
    
    # Save manifests
    generator.save_manifests(config.k8s_output_path, single_file=config.k8s_single_file)
    
    # Generate Helm chart if enabled
    if config.k8s_helm_enabled:
        helm_dir = os.path.join(config.k8s_output_path, "helm")
        generator.generate_helm_chart(helm_dir, chart_name=config.k8s_helm_name)
    
    # Print summary
    print("\n   📦 Kubernetes Manifests Generated:")
    print(f"      - Namespaces:      {len(manifests['namespaces'])}")
    print(f"      - Deployments:     {len(manifests['deployments'])}")
    print(f"      - Services:        {len(manifests['services'])}")
    print(f"      - NetworkPolicies: {len(manifests['network_policies'])}")
    print(f"      - Secrets:         {len(manifests['secrets'])}")
    print(f"      - Ingresses:       {len(manifests['ingresses'])}")
    print(f"      - ConfigMaps:      {len(manifests['configmaps'])}")
    print(f"\n   📁 Output: {config.k8s_output_path}")
    
    if config.k8s_helm_enabled:
        print(f"   📊 Helm chart: {os.path.join(config.k8s_output_path, 'helm', config.k8s_helm_name)}")
    
    print(f"\n   🚀 Deploy: kubectl apply -k {config.k8s_output_path}")
    
    return manifests


def run_pipeline(config: PipelineConfig) -> Dict[str, Any]:
    """Execute the full generation pipeline."""
    print("🚀 Starting Cloud Environment Generation Pipeline...")
    print(f"   K8s Generation: {'ENABLED' if config.k8s_enabled else 'DISABLED'}")
    
    # Initialize config loader
    config_loader = ConfigLoader.get_instance(base_dir=config.config_loader_dir)
    
    # Load vulnerability assigner
    vuln_assigner = load_vulnerability_assigner(config)
    
    # Run pipeline steps
    cluster_data = generate_logical_cluster(config, config_loader)
    cluster_data = generate_network_topology(config, config_loader, cluster_data, vuln_assigner)
    cluster_data = generate_physical_topology(config, config_loader, cluster_data)
    save_outputs(config, cluster_data)
    generated = generate_cyberbattlesim(config, cluster_data)
    manifests = generate_kubernetes_manifests(config, cluster_data)
    
    print("\n✅ Pipeline Complete.")
    
    return {
        "cluster_data": cluster_data,
        "cyberbattle_nodes": generated["nodes"],
        "k8s_manifests": manifests,
    }


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Full Stack Cloud Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                    # Use default config.yaml
  python main.py --config prod_config.yaml          # Use custom config
  python main.py --override core.nodes=100          # Override specific values
  python main.py --override kubernetes.enabled=true # Enable K8s generation
""",
    )
    
    parser.add_argument(
        "--config", "-c",
        type=str,
        default="config.yaml",
        help="Path to YAML configuration file (default: config.yaml)",
    )
    
    parser.add_argument(
        "--override", "-o",
        type=str,
        action="append",
        default=[],
        help="Override config values (format: key.subkey=value)",
    )
    
    args = parser.parse_args()
    
    # Load configuration
    if not os.path.exists(args.config):
        print(f"❌ Config file not found: {args.config}")
        print("   Create one or specify path with --config")
        return
    
    config = PipelineConfig.from_yaml(args.config)
    config.apply_overrides(args.override)
    
    # Run pipeline
    run_pipeline(config)


if __name__ == "__main__":
    main()