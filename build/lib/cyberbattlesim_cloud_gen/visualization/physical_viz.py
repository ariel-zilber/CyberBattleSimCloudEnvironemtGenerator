"""
Physical Topology Visualizer
==================================
Generates visualizations for the Physical Layer:
1. Node-to-node network graph (latency, firewalls)
2. Node-to-service mapping (pod placement)
3. Zone distribution charts
"""

import json
import sys
import networkx as nx
import matplotlib.pyplot as plt
from typing import Dict, List, Tuple
from collections import defaultdict

def load_physical_topology(filepath: str) -> Dict:
    """Load physical topology from a cluster JSON file"""
    try:
        with open(filepath, 'r') as f:
            cluster_config = json.load(f)
        
        if "physical_topology" not in cluster_config:
            print(f"Error: 'physical_topology' key not found in {filepath}", file=sys.stderr)
            return {}
            
        return cluster_config["physical_topology"]
        
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}", file=sys.stderr)
        return {}
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {filepath}", file=sys.stderr)
        return {}

def build_node_network_graph(topology: Dict) -> nx.DiGraph:
    """Build a NetworkX graph showing node-to-node connections"""
    G = nx.DiGraph()
    
    # Add nodes (physical nodes)
    if "nodes" not in topology:
        print("Error: No 'nodes' found in topology data", file=sys.stderr)
        return G
    
    for node_data in topology["nodes"]:
        node_id = node_data["node_id"]
        G.add_node(node_id,
                   node_type=node_data["node_type"],
                   zone=node_data["zone"],
                   is_healthy=node_data["is_healthy"],
                   cpu_util=node_data["cpu_utilization"],
                   mem_util=node_data["memory_utilization"],
                   pod_count=node_data["pod_count"],
                   cpu_cores=node_data["characteristics"]["cpu_cores"],
                   memory_gb=node_data["characteristics"]["memory_gb"])
    
    # Add edges (node connections)
    if "node_connections" not in topology:
        print("Warning: No 'node_connections' found. Graph will have no edges.", file=sys.stderr)
        return G
    
    for conn in topology["node_connections"]:
        if G.has_node(conn["from"]) and G.has_node(conn["to"]):
            G.add_edge(conn["from"], conn["to"],
                       latency_ms=conn["latency_ms"],
                       bandwidth_gbps=conn["bandwidth_gbps"],
                       packet_loss=conn["packet_loss"],
                       is_firewalled=conn["is_firewalled"],
                       firewall_rules=conn.get("firewall_rules", []))
    
    return G

def build_node_service_graph(topology: Dict) -> nx.Graph:
    """Build a bipartite graph showing nodes and their assigned services"""
    G = nx.Graph()
    
    # Add node nodes
    if "nodes" not in topology:
        print("Error: No 'nodes' found in topology data", file=sys.stderr)
        return G
    
    for node_data in topology["nodes"]:
        node_id = node_data["node_id"]
        G.add_node(node_id,
                   bipartite=0,  # Nodes are in set 0
                   node_type=node_data["node_type"],
                   zone=node_data["zone"],
                   is_healthy=node_data["is_healthy"],
                   cpu_util=node_data["cpu_utilization"],
                   mem_util=node_data["memory_utilization"])
        
        # Add service nodes and edges
        for pod in node_data["assigned_pods"]:
            service_name = pod["service"]
            pod_id = f"{service_name}-{pod['instance']}"
            
            # Add service node if not exists
            if not G.has_node(service_name):
                G.add_node(service_name, bipartite=1)  # Services are in set 1
            
            # Add edge from node to service
            G.add_edge(node_id, service_name, pod_id=pod_id)
    
    return G

def get_node_color_by_type(node_type: str) -> str:
    """Get color for a node based on its type"""
    colors = {
        "control_plane": "#e63946",  # Red
        "worker": "#457b9d",          # Blue
        "compute": "#f77f00",         # Orange
        "memory": "#06d6a0",          # Green
        "storage": "#8338ec",         # Purple
        "gpu": "#ff006e",             # Pink
        "edge": "#fb5607"             # Orange-red
    }
    return colors.get(node_type, "#adb5bd")  # Gray default

def get_node_color_by_zone(zone: str) -> str:
    """Get color for a node based on its zone"""
    colors = {
        "zone-a": "#0077b6",  # Blue
        "zone-b": "#00b4d8",  # Light blue
        "zone-c": "#90e0ef",  # Lighter blue
        "zone-d": "#caf0f8"   # Lightest blue
    }
    return colors.get(zone, "#adb5bd")  # Gray default

def visualize_node_network(G: nx.DiGraph, output_file: str, color_by: str = "type"):
    """Generate and save a visualization of the node network graph"""
    if G.number_of_nodes() == 0:
        print("Cannot visualize an empty graph.", file=sys.stderr)
        return
    
    fig, ax = plt.subplots(figsize=(28, 28))
    pos = nx.spring_layout(G, k=2.0, iterations=50, seed=42)
    
    # --- Node Colors ---
    node_colors = []
    node_labels = {}
    for node in G.nodes:
        node_data = G.nodes[node]
        
        if color_by == "type":
            color = get_node_color_by_type(node_data.get("node_type", "unknown"))
        else:  # color by zone
            color = get_node_color_by_zone(node_data.get("zone", "unknown"))
        
        if not node_data.get("is_healthy", True):
            node_colors.append(color + "80")  # Semi-transparent if unhealthy
        else:
            node_colors.append(color)
        
        pod_count = node_data.get("pod_count", 0)
        cpu_util = node_data.get("cpu_util", 0)
        mem_util = node_data.get("mem_util", 0)
        node_type = node_data.get("node_type", "?")[:4]
        zone = node_data.get("zone", "?").split("-")[-1].upper()
        
        label = f"{node}\n{node_type}|Z{zone}\nP:{pod_count} C:{cpu_util:.0f}% M:{mem_util:.0f}%"
        node_labels[node] = label
    
    # --- Node Sizes ---
    node_sizes = []
    for node in G.nodes:
        node_data = G.nodes[node]
        cpu = node_data.get("cpu_cores", 4)
        mem = node_data.get("memory_gb", 16)
        size = 1000 + (cpu * 50) + (mem * 10)
        node_sizes.append(size)
    
    # --- Edges ---
    normal_edges = []
    firewalled_edges = []
    high_latency_edges = []
    edge_labels = {}
    
    for u, v, data in G.edges(data=True):
        latency = data.get("latency_ms", 0)
        is_firewalled = data.get("is_firewalled", False)
        
        if is_firewalled:
            firewalled_edges.append((u, v))
            edge_labels[(u, v)] = f"🚫 {latency:.1f}ms"
        elif latency > 3.0:
            high_latency_edges.append((u, v))
            edge_labels[(u, v)] = f"⚠️ {latency:.1f}ms"
        else:
            normal_edges.append((u, v))
            edge_labels[(u, v)] = f"{latency:.1f}ms"
    
    # --- Draw ---
    nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color=node_colors, 
                          alpha=0.9, edgecolors="black", linewidths=2)
    nx.draw_networkx_labels(G, pos, labels=node_labels, font_size=7, 
                           font_weight="bold", font_family="monospace")
    
    if normal_edges:
        nx.draw_networkx_edges(G, pos, edgelist=normal_edges, width=1.0, alpha=0.3, 
                              edge_color="#06d6a0", arrows=True, arrowstyle="->", connectionstyle="arc3,rad=0.05")
    if high_latency_edges:
        nx.draw_networkx_edges(G, pos, edgelist=high_latency_edges, width=1.5, alpha=0.5, 
                              edge_color="#f77f00", arrows=True, arrowstyle="->", connectionstyle="arc3,rad=0.05")
    if firewalled_edges:
        nx.draw_networkx_edges(G, pos, edgelist=firewalled_edges, width=2.0, alpha=0.6, 
                              edge_color="#e63946", style="dashed", arrows=True, connectionstyle="arc3,rad=0.05")
    
    important_edges = {k: v for k, v in edge_labels.items() if k in firewalled_edges or k in high_latency_edges}
    if important_edges and len(important_edges) < 100:
        nx.draw_networkx_edge_labels(G, pos, edge_labels=important_edges, font_size=6, 
                                    font_color="#212529", bbox=dict(facecolor='white', alpha=0.7, pad=1, edgecolor='none'))
    
    plt.title(f"Physical Node Network Topology (Colored by {color_by})", fontsize=20, fontweight='bold')
    plt.axis("off")
    
    try:
        plt.savefig(output_file, format="PNG", dpi=150, bbox_inches="tight")
        print(f"✅ Node network graph saved to {output_file}")
    except Exception as e:
        print(f"Error saving graph image: {e}", file=sys.stderr)
    plt.close()

def visualize_node_service_mapping(G: nx.Graph, output_file: str, topology: Dict):
    """Generate and save a visualization of the node-to-service mapping"""
    if G.number_of_nodes() == 0:
        return
    
    fig, ax = plt.subplots(figsize=(32, 24))
    physical_nodes = [n for n, d in G.nodes(data=True) if d.get("bipartite") == 0]
    service_nodes = [n for n, d in G.nodes(data=True) if d.get("bipartite") == 1]
    
    pos = {}
    y_spacing = 1.0
    for i, node in enumerate(physical_nodes):
        pos[node] = (0, i * y_spacing)
    
    y_spacing_services = len(physical_nodes) * y_spacing / max(len(service_nodes), 1)
    for i, service in enumerate(service_nodes):
        pos[service] = (3, i * y_spacing_services)
    
    node_colors = []
    node_sizes = []
    labels = {}
    
    for node in G.nodes:
        if node in physical_nodes:
            node_data = G.nodes[node]
            color = get_node_color_by_type(node_data.get("node_type", "unknown"))
            if not node_data.get("is_healthy", True):
                color = color + "80"
            node_colors.append(color)
            node_sizes.append(2000)
            
            pod_count = len([e for e in G.edges(node)])
            zone = node_data.get("zone", "?").split("-")[-1].upper()
            labels[node] = f"{node}\nZ{zone}\nPods:{pod_count}"
        else:
            node_colors.append("#ffd60a")
            instance_count = len([e for e in G.edges(node)])
            node_sizes.append(500 + instance_count * 100)
            labels[node] = f"{node}\n({instance_count})"
    
    nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color=node_colors, alpha=0.9, edgecolors="black", linewidths=2)
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=8, font_weight="bold", font_family="monospace")
    nx.draw_networkx_edges(G, pos, width=0.5, alpha=0.3, edge_color="#495057", arrows=False)
    
    plt.title("Node-to-Service Mapping", fontsize=20, fontweight='bold')
    plt.axis("off")
    
    try:
        plt.savefig(output_file, format="PNG", dpi=150, bbox_inches="tight")
        print(f"✅ Node-service mapping graph saved to {output_file}")
    except Exception as e:
        print(f"Error saving graph image: {e}", file=sys.stderr)
    plt.close()

def visualize_zone_distribution(topology: Dict, output_file: str):
    """Generate a visualization showing zone distribution"""
    if "nodes" not in topology:
        return
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(20, 10))
    zones = defaultdict(lambda: {"nodes": 0, "pods": 0})
    
    for node in topology["nodes"]:
        zone = node["zone"]
        zones[zone]["nodes"] += 1
        zones[zone]["pods"] += node["pod_count"]
    
    zone_names = list(zones.keys())
    node_counts = [zones[z]["nodes"] for z in zone_names]
    pod_counts = [zones[z]["pods"] for z in zone_names]
    colors = [get_node_color_by_zone(z) for z in zone_names]
    
    ax1.bar(zone_names, node_counts, color=colors, alpha=0.8, edgecolor='black')
    ax1.set_title("Nodes per Zone", fontsize=16)
    
    ax2.bar(zone_names, pod_counts, color=colors, alpha=0.8, edgecolor='black')
    ax2.set_title("Pods per Zone", fontsize=16)
    
    plt.suptitle("Availability Zone Distribution", fontsize=20, fontweight='bold')
    plt.tight_layout()
    
    try:
        plt.savefig(output_file, format="PNG", dpi=150, bbox_inches="tight")
        print(f"✅ Zone distribution graph saved to {output_file}")
    except Exception as e:
        print(f"Error saving graph image: {e}", file=sys.stderr)
    plt.close()

# --- Integration Helpers ---

def visualize_physical_from_data(cluster_data: Dict, output_base_path: str):
    """
    Main entry point for pipeline integration.
    Accepts the full cluster dictionary and generates visualizations.
    """
    if "physical_topology" not in cluster_data:
        print("⚠️ Cannot visualize: 'physical_topology' missing from cluster data.")
        return

    topology = cluster_data["physical_topology"]
    base_output = output_base_path.replace(".json", "")
    
    print("🕸️  Building physical graphs...")
    node_network_graph = build_node_network_graph(topology)
    node_service_graph = build_node_service_graph(topology)
    
    print("🎨 Generating physical visualizations...")
    visualize_node_network(node_network_graph, f"{base_output}_nodes_by_type.png", color_by="type")
    visualize_node_network(node_network_graph, f"{base_output}_nodes_by_zone.png", color_by="zone")
    visualize_node_service_mapping(node_service_graph, f"{base_output}_mapping.png", topology)
    visualize_zone_distribution(topology, f"{base_output}_zones.png")

if __name__ == "__main__":
    # Standalone CLI usage
    if len(sys.argv) < 2:
        print("Usage: python physical_viz.py <cluster_config_with_nodes.json>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_base = input_file.replace(".json", "")
    
    print(f"📂 Loading physical topology from {input_file}...")
    topology = load_physical_topology(input_file)
    
    if topology:
        print("🕸️  Building graphs...")
        node_network_graph = build_node_network_graph(topology)
        node_service_graph = build_node_service_graph(topology)
        
        print("🎨 Generating visualizations...")
        visualize_node_network(node_network_graph, f"{output_base}_nodes_by_type.png", color_by="type")
        visualize_node_network(node_network_graph, f"{output_base}_nodes_by_zone.png", color_by="zone")
        visualize_node_service_mapping(node_service_graph, f"{output_base}_mapping.png", topology)
        visualize_zone_distribution(topology, f"{output_base}_zones.png")