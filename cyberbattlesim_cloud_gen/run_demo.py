"""
Updated Demo Runner with Firewall Fixes

Changes:
1. Calls enhance_logical_generation() after logical layer
2. Calls fix_physical_topology() after physical layer
3. Ensures public entry points exist
"""

import os
import json
from cyberbattlesim_cloud_gen.generators.cyberbattle import ClusterAttackGenerator
from cyberbattlesim_cloud_gen.visualization.logical_viz import visualize_graph_from_data
from cyberbattlesim_cloud_gen.visualization.physical_viz import visualize_physical_from_data
from cyberbattlesim_network_gen.generators.file_utils import *
from cyberbattlesim_network_gen.generators.view_utils import *
from interactive_attack_solver import  run_interactive_server
from cyberbattlesim_network_gen.generators.logical_gen.k8s_cluster_generator import K8sClusterGenerator
from cyberbattlesim_network_gen.generators.logical_gen. cluster_dynamic_config import ClusterDynamicConfig
from cyberbattlesim_network_gen.generators.network_gen.network_topology_generator import NetworkTopologyGenerator
from cyberbattlesim_cloud_gen.generators.physical_gen.physical_node_generator import PhysicalNodeGenerator
from cyberbattlesim_cloud_gen.generators.network_gen.topology_to_dict import topology_to_dict

# Import fixes


def main():
    # Configuration
    OUTPUT_DIR = "./demo_output"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    print("🚀 Starting Cloud Generation Demo (WITH FIREWALL FIXES)...")

    # ---------------------------------------------------------
    # 1. Logical Layer (Abstract Services)
    # ---------------------------------------------------------
    print("\n[1/4] Generating Logical Cluster...")
    logical_config = ClusterDynamicConfig(
        num_nodes=5,  # Increased for more realistic scenario
        use_case=UseCase.ML_PLATFORM,
        seed=42
    )
    logical_gen = K8sClusterGenerator(logical_config)
    cluster_data = logical_gen.generate()
    
    # *** FIX 1: Ensure public services exist ***
    # cluster_data = enhance_logical_generation(cluster_data)
    
    print(f"      -> Generated {len(cluster_data['services'])} services")
    print(f"      -> Public services: {cluster_data.get('public_services', [])}")

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
    
#     # *** FIX 2: Fix firewall rules to allow attacks ***
#     physical_topology = fix_physical_topology(
#     physical_topology, 
#     cluster_data, 
#     permissive_level=0.2  # 20% chance of a misconfiguration per node
# )
    
    # Merge into main data structure
    cluster_data["physical_topology"] = physical_topology

    # Save intermediate JSON (Snapshot of the full environment)
    json_path = os.path.join(OUTPUT_DIR, "environment.json")
    with open(json_path, 'w') as f:
        json.dump(cluster_data, f, indent=2)
    print(f"      -> Saved config to {json_path}")

    # Generate Visualizations
    print("      -> Generating graphs...")
    try:
        visualize_graph_from_data(cluster_data, json_path)
        visualize_physical_from_data(cluster_data, json_path)
    except Exception as e:
        print(f"      Warning: Visualization failed: {e}")

    # ---------------------------------------------------------
    # 4. CyberBattleSim Export
    # ---------------------------------------------------------
    print("\n[4/4] Exporting to CyberBattleSim...")
    sim_dir = os.path.join(OUTPUT_DIR, "cyberbattle_env")
    
    cbs_exporter = ClusterAttackGenerator(
        out_dir=sim_dir,
        cluster_config=cluster_data
    )
    generated = cbs_exporter.generate()
    # solver = InteractiveAttackPathSolver(generated['nodes'], "attacker")
    # app = create_web_server(solver)
    # app.run(port=5000)
    # Create output directories
    for file_path in [
        OUTPUT_DIR + "/nodes/",
        OUTPUT_DIR + "/identifiers",
        OUTPUT_DIR + "/vulnerability_library",
        OUTPUT_DIR + "/graphs"
    ]:
        if not os.path.exists(file_path):
            os.makedirs(file_path)

    # Save node YAMLs
    for k, v in generated['nodes'].items():
        save_yaml(v.to_dict(), OUTPUT_DIR + "/nodes/" + k + '.yaml')
    
    save_yaml(generated['identifiers'].to_dict(), OUTPUT_DIR + "/identifiers/identifiers.yaml")
    save_yaml(generated['vulnerability_library'], OUTPUT_DIR + "/vulnerability_library/vulnerability_library.yaml")
        # Save other generated files

    # *** VALIDATION: Check if attack is possible ***
    print("\n🔍 Attack Surface Validation:")
    validate_attack_surface(generated['nodes'])

    print("\n✨ Done! Environment is ready for simulation.")


def validate_attack_surface(nodes: dict):
    """
    Validate that the generated scenario is actually attackable.
    """
    from cyberbattle.simulation.firewall import RulePermission
    
    # Find attacker node
    attacker_id = None
    for node_id, node_info in nodes.items():
        if "attacker" in node_info.properties:
            attacker_id = node_id
            break
    
    if not attacker_id:
        print("   ❌ No attacker node found!")
        return
    
    print(f"   ✓ Attacker node: {attacker_id}")
    
    # Find nodes attacker can reach
    reachable = []
    public_nodes = []
    
    attacker = nodes[attacker_id]
    
    for target_id, target_info in nodes.items():
        if target_id == attacker_id:
            continue
        
        # Check if target has public IP (0.0.0.0/0 incoming rule)
        for rule in target_info.firewall.incoming:
            if rule.permission == RulePermission.ALLOW:
                if str(rule.subnet) in ["*", "0.0.0.0/0"]:
                    public_nodes.append(target_id)
                    reachable.append(target_id)
                    break
        
        # Check if attacker's outgoing rules allow this target
        if target_info.network_info:
            target_ip = target_info.network_info[0].ip_address
            for rule in attacker.firewall.outgoing:
                if rule.permission == RulePermission.ALLOW:
                    try:
                        if str(rule.subnet) in ["*", "0.0.0.0/0"]:
                            if target_id not in reachable:
                                reachable.append(target_id)
                            break
                        network = ipaddress.ip_network(str(rule.subnet), strict=False)
                        if ipaddress.ip_address(target_ip) in network:
                            if target_id not in reachable:
                                reachable.append(target_id)
                            break
                    except:
                        continue
    
    print(f"   ✓ Public nodes (0.0.0.0/0 allow): {len(public_nodes)}")
    for node_id in public_nodes:
        services = [s.name for s in nodes[node_id].services]
        print(f"      - {node_id}: {services}")
    
    print(f"   ✓ Nodes reachable from attacker: {len(reachable)}")
    
    if not reachable:
        print("   ❌ WARNING: Attacker cannot reach ANY nodes!")
        print("      This scenario is NOT solvable!")
    else:
        print("   ✓ Scenario appears to be attackable")
    
    # Check for vulnerabilities on reachable nodes
    vuln_count = 0
    for node_id in reachable:
        vuln_count += len(nodes[node_id].vulnerabilities)
    
    print(f"   ✓ Vulnerabilities on reachable nodes: {vuln_count}")
    
    if vuln_count == 0:
        print("   ⚠️  WARNING: No vulnerabilities on reachable nodes!")


if __name__ == "__main__":
    import ipaddress  # Import needed for validation
    main()