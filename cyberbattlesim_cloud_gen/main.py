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
from cyberbattlesim_network_gen.generators.view_utils import *  # Includes plot_ip_network
from cyberbattlesim_cloud_gen.generators.vulnerability_gen.vulnerability_assigner import (
    VulnerabilityAssigner,
)
from cyberbattlesim_cloud_gen.config.config_loader import ConfigLoader


def load_vulnerability_assigner(cve_json_path: str, vuln_db_path: str, seed: int):
    """
    Helper to load the VulnerabilityAssigner if the external module exists
    and paths are provided.
    """
    if not cve_json_path or not vuln_db_path:
        return None

    try:
        print("🔒 Loading Vulnerability Database...")
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
        topology_matrix=raw_topo_config.get(
            "topology_matrix", None
        ),  # Loads exact matrix if defined
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

    print("\n✅ Pipeline Complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Full Stack Cloud Generator")

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
        "--use-case", type=str, default="microservices", help="Cluster use case"
    )
    parser.add_argument(
        "--zones", type=int, default=3, help="Number of availability zones"
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed")

    # Topology & Network Args
    parser.add_argument(
        "--topology-type",
        type=str,
        default=None,
        choices=["mesh", "star", "hub_spoke", "random", "exact"],
        help="Network topology type. If 'exact', requires topology_matrix in topology.yaml",
    )

    parser.add_argument(
        "--firewall-prob",
        type=float,
        default=0.2,
        help="Internal firewall block probability",
    )
    parser.add_argument(
        "--knowledge", type=float, default=0.7, help="Attacker knowledge completeness"
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
        help="Intermediate JSON output",
    )
    parser.add_argument(
        "--sim-output-dir",
        type=str,
        default="./outputs/generated_env",
        help="CyberBattleSim output directory",
    )
    parser.add_argument("--visualize", action="store_true", help="Generate PNG graphs")

    args = parser.parse_args()
    run_pipeline(args)
