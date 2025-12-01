import os
import json
from cyberbattlesim_cloud_gen.config.enums import UseCase
from cyberbattlesim_cloud_gen.generators.logical import K8sClusterGenerator, ClusterDynamicConfig
from cyberbattlesim_cloud_gen.generators.network import NetworkTopologyGenerator, topology_to_dict
from cyberbattlesim_cloud_gen.generators.physical import PhysicalNodeGenerator
from cyberbattlesim_cloud_gen.generators.cyberbattle import CyberBattleExporter
from cyberbattlesim_cloud_gen.visualization.logical_viz import visualize_graph_from_data
from cyberbattlesim_cloud_gen.visualization.physical_viz import visualize_physical_from_data

def main():
    # Configuration
    OUTPUT_DIR = "./demo_output"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    print("🚀 Starting Cloud Generation Demo...")

    # ---------------------------------------------------------
    # 1. Logical Layer (Abstract Services)
    # ---------------------------------------------------------
    print("\n[1/4] Generating Logical Cluster...")
    logical_config = ClusterDynamicConfig(
        num_nodes=50,
        use_case=UseCase.MICROSERVICES,
        seed=42
    )
    logical_gen = K8sClusterGenerator(logical_config)
    cluster_data = logical_gen.generate()
    print(f"      -> Generated {len(cluster_data['services'])} services")

    # ---------------------------------------------------------
    # 2. Network Layer (Connectivity & Creds)
    # ---------------------------------------------------------
    print("\n[2/4] Generating Logical Network Topology...")
    net_gen = NetworkTopologyGenerator(
        services=cluster_data["services"],
        service_instances=cluster_data["service_instances"],
        seed=42
    )
    network_topology = net_gen.generate(firewall_probability=0.2)
    
    # Merge into main data structure
    cluster_data["network_topology"] = topology_to_dict(network_topology)

    # ---------------------------------------------------------
    # 3. Physical Layer (Nodes & IPs)
    # ---------------------------------------------------------
    print("\n[3/4] Generating Physical Infrastructure...")
    phys_gen = PhysicalNodeGenerator(
        cluster_config=cluster_data,
        num_zones=3,
        seed=42
    )
    physical_topology = phys_gen.generate()
    
    # Merge into main data structure
    cluster_data["physical_topology"] = physical_topology

    # Save intermediate JSON (Snapshot of the full environment)
    json_path = os.path.join(OUTPUT_DIR, "environment.json")
    with open(json_path, 'w') as f:
        json.dump(cluster_data, f, indent=2)
    print(f"      -> Saved config to {json_path}")

    # Generate Visualizations
    print("      -> Generating graphs...")
    visualize_graph_from_data(cluster_data, json_path)
    visualize_physical_from_data(cluster_data, json_path)

    # ---------------------------------------------------------
    # 4. CyberBattleSim Export
    # ---------------------------------------------------------
    print("\n[4/4] Exporting to CyberBattleSim...")
    sim_dir = os.path.join(OUTPUT_DIR, "cyberbattle_env")
    
    cbs_exporter = CyberBattleExporter(
        out_dir=sim_dir,
        cluster_config=cluster_data  # Pass the dict directly!
    )
    cbs_exporter.generate()
    
    print("\n✨ Done! Environment is ready for simulation.")

if __name__ == "__main__":
    main()