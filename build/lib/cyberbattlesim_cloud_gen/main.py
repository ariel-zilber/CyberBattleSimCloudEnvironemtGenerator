import argparse
import json
import os
import sys
from typing import Dict, Optional

# --- Internal Imports ---
from .config.enums import UseCase
from .generators.logical import K8sClusterGenerator, ClusterDynamicConfig
from .generators.network import NetworkTopologyGenerator, topology_to_dict
from .generators.physical import PhysicalNodeGenerator
from .generators.cyberbattle import ClusterAttackGenerator
from .visualization.logical_viz import visualize_graph_from_data
from .visualization.physical_viz import visualize_physical_from_data
from cyberbattlesim_network_gen.generators.file_utils import *
from cyberbattlesim_network_gen.generators.view_utils import *

def load_vulnerability_assigner(cve_json_path: str, vuln_db_path: str, seed: int):
    """
    Helper to load the VulnerabilityAssigner if the external module exists
    and paths are provided.
    """
    if not cve_json_path or not vuln_db_path:
        return None

    try:
        # Import from the new location in the generators package
        from .generators.vulnerability import VulnerabilityAssigner
        
        print(f"🔒 Loading Vulnerability Database...")
        return VulnerabilityAssigner(cve_json_path, vuln_db_path, seed=seed)
    except ImportError:
        print("⚠️  Warning: 'generators.vulnerability' module not found. Skipping CVE assignment.")
        return None
    except Exception as e:
        print(f"⚠️  Warning: Failed to load vulnerability data: {e}")
        return None

def run_pipeline(args):
    print(f"🚀 Starting Cloud Environment Generation Pipeline...")
    
    # ---------------------------------------------------------
    # PRE-STEP: Load Vulnerability Data (If provided)
    # ---------------------------------------------------------
    vuln_assigner = load_vulnerability_assigner(args.cve_json, args.vuln_db, args.seed)

    # ---------------------------------------------------------
    # STEP 1: Logical Generation
    # ---------------------------------------------------------
    print(f"1. Generating Logical Cluster ({args.nodes} nodes, {args.use_case})...")
    
    logical_config = ClusterDynamicConfig(
        num_nodes=args.nodes,
        use_case=UseCase(args.use_case),
        seed=args.seed
    )
    logical_gen = K8sClusterGenerator(logical_config)
    cluster_data = logical_gen.generate()

    # ---------------------------------------------------------
    # STEP 2: Network Layer (With Vulnerabilities)
    # ---------------------------------------------------------
    print("2. Generating Network Topology...")
    
    net_gen = NetworkTopologyGenerator(
        services=cluster_data["services"],
        service_instances=cluster_data["service_instances"],
        seed=args.seed,
        vulnerability_assigner=vuln_assigner
    )
    
    network_topology = net_gen.generate(
        firewall_probability=args.firewall_prob,
        knowledge_completeness=args.knowledge
    )
    
    cluster_data["network_topology"] = topology_to_dict(network_topology)
    
    # Log vulnerability stats if we used the assigner
    if vuln_assigner and "metadata" in cluster_data["network_topology"]:
        stats = cluster_data["network_topology"]["metadata"].get("vulnerability_stats", {})
        count = stats.get('total_vulnerabilities', 0)
        if count > 0:
            print(f"   -> Assigned {count} specific vulnerabilities")

    # ---------------------------------------------------------
    # STEP 3: Physical Layer
    # ---------------------------------------------------------
    print("3. Generating Physical Infrastructure...")
    
    phys_gen = PhysicalNodeGenerator(
        cluster_config=cluster_data,
        num_nodes=args.nodes,
        num_zones=args.zones,
        seed=args.seed
    )
    
    physical_topology = phys_gen.generate(
        firewall_probability=0.0, # Internal node-to-node firewall default
        firewall_cross_zone_only=False
    )
    
    cluster_data["physical_topology"] = physical_topology

    # ---------------------------------------------------------
    # STEP 4: Export & Visualization
    # ---------------------------------------------------------
    print(f"4. Saving Intermediate Data to {args.output}...")
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    
    with open(args.output, 'w') as f:
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
        out_dir=args.sim_output_dir
    )
    generated=cbs_gen.generate()
    for file_path in [args.sim_output_dir+"/nodes/",
                    args.sim_output_dir+"/identifiers",
                    args.sim_output_dir+"/vulnerability_library",
                    args.sim_output_dir+"/graphs"
                    ]:
        if not os.path.exists(file_path):
            os.makedirs(file_path)

    for k,v in generated['nodes'].items():
        save_yaml(v.to_dict(),args.sim_output_dir+"/nodes/"+k+'.yaml')

    
    print("\n✅ Pipeline Complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Full Stack Cloud Generator")
    
    # Core Args
    parser.add_argument("--nodes", type=int, default=50, help="Number of nodes")
    parser.add_argument("--use-case", type=str, default="microservices", help="Cluster use case")
    parser.add_argument("--zones", type=int, default=3, help="Number of availability zones")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    
    # Network Args
    parser.add_argument("--firewall-prob", type=float, default=0.2, help="Internal firewall block probability")
    parser.add_argument("--knowledge", type=float, default=0.7, help="Attacker knowledge completeness")
    
    # Vulnerability Args
    parser.add_argument("--cve-json", type=str, help="Path to final.json with CVE lists per service")
    parser.add_argument("--vuln-db", type=str, help="Path to vulnerability_db.yml with CVE details")
    
    # Output Args
    parser.add_argument("--output", type=str, default="./outputs/cluster_full.json", help="Intermediate JSON output")
    parser.add_argument("--sim-output-dir", type=str, default="./outputs/generated_env", help="CyberBattleSim output directory")
    parser.add_argument("--visualize", action="store_true", help="Generate PNG graphs")
    
    args = parser.parse_args()
    run_pipeline(args)