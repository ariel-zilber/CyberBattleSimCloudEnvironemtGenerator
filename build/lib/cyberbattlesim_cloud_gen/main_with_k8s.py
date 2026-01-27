"""
Full Stack Cloud Generator with Kubernetes Deployment
======================================================
Extended pipeline that generates:
1. Logical cluster topology
2. Network connectivity graph
3. Physical node infrastructure
4. CyberBattleSim simulation environment
5. **Real Kubernetes manifests for deployment**

The K8s manifests mirror the simulated topology, allowing you to:
- Deploy a real cluster matching your simulation
- Test security tools against the same topology
- Validate attack paths in real infrastructure
"""

import argparse
import json
import os

# --- Internal Imports ---
from cyberbattlesim_cloud_gen.generators.file_utils import save_yaml
from cyberbattlesim_cloud_gen.generators.logical_gen.k8s_cluster_generator import (
    K8sClusterGenerator,
)
from cyberbattlesim_cloud_gen.generators.logical_gen.cluster_dynamic_config import (
    ClusterDynamicConfig,
)

# --- Configuration Imports ---
from cyberbattlesim_cloud_gen.generators.logical_gen.subnet_config import SubnetConfig
from cyberbattlesim_cloud_gen.generators.logical_gen.network_topology_config import (
    NetworkTopologyConfig,
)
from cyberbattlesim_cloud_gen.generators.logical_gen.firewall_config import (
    FirewallConfig,
)

# -----------------------------
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

# --- NEW: Kubernetes Manifest Generator ---
from k8s_manifest_generator import (
    K8sManifestGenerator,
    K8sManifestConfig,
)


def load_vulnerability_assigner(cve_json_path: str, vuln_db_path: str, seed: int):
    """
    Helper to load the VulnerabilityAssigner if the external module exists
    and paths are provided.
    """
    if not cve_json_path or not vuln_db_path:
        return None

    try:
        print("🔑 Loading Vulnerability Database...")
        return VulnerabilityAssigner(cve_json_path, vuln_db_path, seed=seed)
    except ImportError:
        print(
            "⚠️  Warning: 'generators.vulnerability' module not found. Skipping CVE assignment."
        )
        return None
    except Exception as e:
        print(f"⚠️  Warning: Failed to load vulnerability data: {e}")
        return None


def run_pipeline(args):
    print("🚀 Starting Cloud Environment Generation Pipeline...")
    print(
        f"   Mode: {'WITH' if args.generate_k8s else 'WITHOUT'} Kubernetes manifest generation"
    )

    # ---------------------------------------------------------
    # PRE-STEP: Initialize ConfigLoader
    # ---------------------------------------------------------
    print(f"   Loading configuration from: {args.config_dir or 'default location'}")
    config_loader_instance = ConfigLoader.get_instance(base_dir=args.config_dir)

    # ---------------------------------------------------------
    # PRE-STEP: Load Vulnerability Data (If provided)
    # ---------------------------------------------------------
    vuln_assigner = load_vulnerability_assigner(args.cve_json, args.vuln_db, args.seed)

    # ---------------------------------------------------------
    # STEP 1: Logical Generation
    # ---------------------------------------------------------
    print(f"1. Generating Logical Cluster ({args.nodes} nodes, {args.use_case})...")

    # --- LOAD TOPOLOGY FROM YAML ---

    # 1. Subnet Configuration
    subnet_config = SubnetConfig(
        subnet_ranges=config_loader_instance.get_subnet_ranges(),
        address_space_bounds=config_loader_instance.get_subnet_bounds(),
        subnet_labels=config_loader_instance.get_subnet_labels(),
        sensitive_subnet_probabilities=config_loader_instance.get_sensitive_subnet_probabilities(),
    )

    # 2. Network Topology Configuration (Explicit Matrix or Type)
    raw_topo_config = config_loader_instance.get_topology_config()

    # CLI argument overrides yaml config for topology type
    topology_type = (
        args.topology_type
        if args.topology_type
        else config_loader_instance.get_topology_type()
    )

    net_topo_config = NetworkTopologyConfig(
        topology_type=topology_type,
        connectivity_probability=raw_topo_config.get("connectivity_probability", 0.3),
        topology_matrix=raw_topo_config.get("topology_matrix", None),
    )

    # 3. Firewall Configuration
    firewall_data = raw_topo_config.get("firewall", {})
    valid_fw_keys = {
        "incoming",
        "incoming_exceptions",
        "outgoing",
        "outgoing_exceptions",
        "default_block_probability",
    }
    filtered_fw_data = {k: v for k, v in firewall_data.items() if k in valid_fw_keys}
    firewall_config = FirewallConfig(**filtered_fw_data) if filtered_fw_data else None

    # Create Logical Config
    logical_config = ClusterDynamicConfig(
        num_nodes=args.nodes,
        use_case=args.use_case,
        seed=args.seed,
        subnet_config=subnet_config,
        network_topology=net_topo_config,
        firewall_config=firewall_config,
    )

    logical_gen = K8sClusterGenerator(
        logical_config, config_loader_instance=config_loader_instance
    )
    cluster_data = logical_gen.generate()

    # ---------------------------------------------------------
    # STEP 2: Network Layer (With Vulnerabilities)
    # ---------------------------------------------------------
    print("2. Generating Network Topology...")

    net_gen = NetworkTopologyGenerator(
        config_loader_instance=config_loader_instance,
        services=cluster_data["services"],
        service_instances=cluster_data["service_instances"],
        seed=args.seed,
        vulnerability_assigner=vuln_assigner,
    )

    network_topology = net_gen.generate(
        firewall_probability=args.firewall_prob, knowledge_completeness=args.knowledge
    )

    cluster_data["network_topology"] = topology_to_dict(network_topology)

    if vuln_assigner and "metadata" in cluster_data["network_topology"]:
        stats = cluster_data["network_topology"]["metadata"].get(
            "vulnerability_stats", {}
        )
        count = stats.get("total_vulnerabilities", 0)
        if count > 0:
            print(f"   -> Assigned {count} specific vulnerabilities")

    # ---------------------------------------------------------
    # STEP 3: Physical Layer
    # ---------------------------------------------------------
    print("3. Generating Physical Infrastructure...")

    phys_gen = PhysicalNodeGenerator(
        config_loader_instance=config_loader_instance,
        cluster_config=cluster_data,
        num_nodes=args.nodes,
        num_zones=args.zones,
        seed=args.seed,
    )

    physical_topology = phys_gen.generate(
        firewall_probability=0.0, firewall_cross_zone_only=False
    )

    cluster_data["physical_topology"] = physical_topology

    # ---------------------------------------------------------
    # STEP 4: Export & Visualization
    # ---------------------------------------------------------
    print(f"4. Saving Intermediate Data to {args.output}...")
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

    with open(args.output, "w") as f:
        json.dump(cluster_data, f, indent=2)

    if args.visualize:
        print("   Generating Visualizations...")
        visualize_graph_from_data(cluster_data, args.output)
        visualize_physical_from_data(cluster_data, args.output)

    # ---------------------------------------------------------
    # STEP 5: CyberBattleSim Conversion
    # ---------------------------------------------------------
    print("5. Converting to CyberBattleSim Environment...")

    cbs_gen = ClusterAttackGenerator(
        config_file=args.output,
        cluster_config=cluster_data,
        out_dir=args.sim_output_dir,
    )
    generated = cbs_gen.generate()

    # Ensure all output directories exist
    for file_path in [
        args.sim_output_dir + "/nodes/",
        args.sim_output_dir + "/identifiers",
        args.sim_output_dir + "/vulnerability_library",
        args.sim_output_dir + "/graphs",
    ]:
        if not os.path.exists(file_path):
            os.makedirs(file_path)

    # --- SAVE GENERATED ARTIFACTS ---
    print("   Saving CyberBattleSim artifacts...")

    # 1. Save Nodes
    for k, v in generated["nodes"].items():
        save_yaml(v.to_dict(), args.sim_output_dir + "/nodes/" + k + ".yaml")

    # 2. Save Identifiers
    save_yaml(
        generated["identifiers"].to_dict(),
        os.path.join(args.sim_output_dir, "identifiers", "identifiers.yaml"),
    )

    # 3. Save Vulnerability Library
    save_yaml(
        generated["vulnerability_library"],
        os.path.join(
            args.sim_output_dir, "vulnerability_library", "vulnerability_library.yaml"
        ),
    )

    # 4. Plot IP Network
    try:
        plot_ip_network(generated["nodes"], args.sim_output_dir + "/graphs/network")
    except NameError:
        print("⚠️  Warning: plot_ip_network function not found. Skipping network plot.")
    except Exception as e:
        print(f"⚠️  Warning: Failed to plot network: {e}")

    # ---------------------------------------------------------
    # STEP 6: Kubernetes Manifest Generation (NEW!)
    # ---------------------------------------------------------
    if args.generate_k8s:
        print("\n6. Generating Kubernetes Manifests...")

        k8s_output_dir = args.k8s_output_dir or os.path.join(
            args.sim_output_dir, "kubernetes"
        )

        # Configure K8s manifest generation
        k8s_config = K8sManifestConfig(
            namespace_prefix=args.k8s_namespace_prefix,
            use_network_policies=args.k8s_network_policies,
            create_ingress=args.k8s_ingress,
            ingress_class=args.k8s_ingress_class,
            default_resource_limits={
                "cpu": args.k8s_cpu_limit,
                "memory": args.k8s_memory_limit,
            },
            default_resource_requests={
                "cpu": args.k8s_cpu_request,
                "memory": args.k8s_memory_request,
            },
        )

        # Generate manifests
        generator = K8sManifestGenerator(cluster_data, k8s_config)
        manifests = generator.generate_all()

        # Save manifests
        generator.save_manifests(k8s_output_dir, single_file=args.k8s_single_file)

        # Optionally generate Helm chart
        if args.k8s_helm:
            helm_dir = os.path.join(k8s_output_dir, "helm")
            generator.generate_helm_chart(helm_dir, chart_name=args.k8s_helm_name)

        # Print summary
        print("\n   📦 Kubernetes Manifests Generated:")
        print(f"      - Namespaces:      {len(manifests['namespaces'])}")
        print(f"      - Deployments:     {len(manifests['deployments'])}")
        print(f"      - Services:        {len(manifests['services'])}")
        print(f"      - NetworkPolicies: {len(manifests['network_policies'])}")
        print(f"      - Secrets:         {len(manifests['secrets'])}")
        print(f"      - Ingresses:       {len(manifests['ingresses'])}")
        print(f"      - ConfigMaps:      {len(manifests['configmaps'])}")
        print(f"\n   📁 Output directory: {k8s_output_dir}")

        if args.k8s_helm:
            print(
                f"   📊 Helm chart: {os.path.join(k8s_output_dir, 'helm', args.k8s_helm_name)}"
            )

        print("\n   🚀 Deploy with:")
        print(f"      kubectl apply -k {k8s_output_dir}")
        if args.k8s_helm:
            print(
                f"      helm install {args.k8s_helm_name} {os.path.join(k8s_output_dir, 'helm', args.k8s_helm_name)}"
            )

    print("\n✅ Pipeline Complete.")

    # Return for programmatic use
    return {
        "cluster_data": cluster_data,
        "cyberbattle_nodes": generated["nodes"],
        "k8s_manifests": manifests if args.generate_k8s else None,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Full Stack Cloud Generator with Kubernetes Deployment Support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic generation (simulation only)
  python main.py --nodes 20 --use-case microservices

  # Generate with Kubernetes manifests
  python main.py --nodes 20 --use-case microservices --generate-k8s

  # Full generation with Helm chart and custom namespace
  python main.py --nodes 50 --use-case ml_platform \\
      --generate-k8s --k8s-helm --k8s-namespace-prefix myapp

  # Generate with network policies disabled (permissive)
  python main.py --nodes 30 --generate-k8s --no-k8s-network-policies
""",
    )

    # Config Args
    parser.add_argument(
        "--config-dir",
        type=str,
        default=None,
        help="Base directory containing config YAML files",
    )

    # Core Args
    parser.add_argument("--nodes", type=int, default=50, help="Number of nodes")
    parser.add_argument(
        "--use-case",
        type=str,
        default="microservices",
        help="Cluster use case (microservices, ml_platform, data_pipeline, etc.)",
    )
    parser.add_argument(
        "--zones", type=int, default=3, help="Number of availability zones"
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for reproducibility"
    )

    # Topology & Network Args
    parser.add_argument(
        "--topology-type",
        type=str,
        default=None,
        choices=["mesh", "star", "hub_spoke", "random", "exact"],
        help="Network topology type",
    )
    parser.add_argument(
        "--firewall-prob",
        type=float,
        default=0.2,
        help="Internal firewall block probability",
    )
    parser.add_argument(
        "--knowledge",
        type=float,
        default=0.7,
        help="Attacker knowledge completeness (0.0-1.0)",
    )

    # Vulnerability Args
    parser.add_argument(
        "--cve-json", type=str, help="Path to final.json with CVE lists per service"
    )
    parser.add_argument(
        "--vuln-db", type=str, help="Path to vulnerability_db.yml with CVE details"
    )

    # Output Args
    parser.add_argument(
        "--output",
        type=str,
        default="./outputs/cluster_full.json",
        help="Intermediate JSON output path",
    )
    parser.add_argument(
        "--sim-output-dir",
        type=str,
        default="./outputs/generated_env",
        help="CyberBattleSim output directory",
    )
    parser.add_argument(
        "--visualize", action="store_true", help="Generate PNG visualization graphs"
    )

    # =========================================================================
    # NEW: Kubernetes Generation Arguments
    # =========================================================================
    k8s_group = parser.add_argument_group(
        "Kubernetes Generation", "Options for generating real K8s manifests"
    )

    k8s_group.add_argument(
        "--generate-k8s",
        action="store_true",
        help="Generate Kubernetes manifests from the topology",
    )
    k8s_group.add_argument(
        "--k8s-output-dir",
        type=str,
        default=None,
        help="Output directory for K8s manifests (default: <sim-output-dir>/kubernetes)",
    )
    k8s_group.add_argument(
        "--k8s-namespace-prefix",
        type=str,
        default="cybersim",
        help="Prefix for generated Kubernetes namespaces",
    )
    k8s_group.add_argument(
        "--k8s-network-policies",
        action="store_true",
        default=True,
        help="Generate NetworkPolicies (default: True)",
    )
    k8s_group.add_argument(
        "--no-k8s-network-policies",
        action="store_false",
        dest="k8s_network_policies",
        help="Skip NetworkPolicy generation (permissive cluster)",
    )
    k8s_group.add_argument(
        "--k8s-ingress",
        action="store_true",
        default=True,
        help="Generate Ingress resources for public services",
    )
    k8s_group.add_argument(
        "--no-k8s-ingress",
        action="store_false",
        dest="k8s_ingress",
        help="Skip Ingress generation",
    )
    k8s_group.add_argument(
        "--k8s-ingress-class",
        type=str,
        default="nginx",
        help="Ingress class to use (nginx, traefik, etc.)",
    )
    k8s_group.add_argument(
        "--k8s-single-file",
        action="store_true",
        help="Output all manifests to a single YAML file",
    )

    # Helm Chart Options
    k8s_group.add_argument(
        "--k8s-helm", action="store_true", help="Also generate a Helm chart"
    )
    k8s_group.add_argument(
        "--k8s-helm-name",
        type=str,
        default="cybersim-cluster",
        help="Name for the generated Helm chart",
    )

    # Resource Limits
    k8s_group.add_argument(
        "--k8s-cpu-limit",
        type=str,
        default="100m",
        help="Default CPU limit for containers",
    )
    k8s_group.add_argument(
        "--k8s-memory-limit",
        type=str,
        default="128Mi",
        help="Default memory limit for containers",
    )
    k8s_group.add_argument(
        "--k8s-cpu-request",
        type=str,
        default="50m",
        help="Default CPU request for containers",
    )
    k8s_group.add_argument(
        "--k8s-memory-request",
        type=str,
        default="64Mi",
        help="Default memory request for containers",
    )

    args = parser.parse_args()


    run_pipeline(args)
