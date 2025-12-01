#!/usr/bin/env python3
"""
Physical Node Topology Visualizer
==================================
Loads a cluster.json file containing physical node topology data
and generates PNG visualizations of:
1. Node-to-node network graph
2. Node-to-service mapping graph

This version displays:
- Nodes colored by type and zone
- Network connections with latency and firewall status
- Pod assignments to nodes
- Resource utilization

Requires: networkx, matplotlib
Install with: pip install networkx matplotlib
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
            sys.exit(1)
            
        return cluster_config["physical_topology"]
        
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {filepath}", file=sys.stderr)
        sys.exit(1)

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
    
    # Use spring layout for initial positioning
    pos = nx.spring_layout(G, k=2.0, iterations=50, seed=42)
    
    # --- Node Colors ---
    node_colors = []
    node_labels = {}
    for node in G.nodes:
        node_data = G.nodes[node]
        
        # Color by type or zone
        if color_by == "type":
            color = get_node_color_by_type(node_data.get("node_type", "unknown"))
        else:  # color by zone
            color = get_node_color_by_zone(node_data.get("zone", "unknown"))
        
        # Fade if unhealthy
        if not node_data.get("is_healthy", True):
            # Make unhealthy nodes semi-transparent
            node_colors.append(color + "80")  # Add alpha
        else:
            node_colors.append(color)
        
        # Create label with utilization info
        pod_count = node_data.get("pod_count", 0)
        cpu_util = node_data.get("cpu_util", 0)
        mem_util = node_data.get("mem_util", 0)
        node_type = node_data.get("node_type", "?")[:4]  # Abbreviated
        zone = node_data.get("zone", "?").split("-")[-1].upper()
        
        label = f"{node}\n{node_type}|Z{zone}\nP:{pod_count} C:{cpu_util:.0f}% M:{mem_util:.0f}%"
        node_labels[node] = label
    
    # --- Node Sizes (based on resource capacity) ---
    node_sizes = []
    for node in G.nodes:
        node_data = G.nodes[node]
        cpu = node_data.get("cpu_cores", 4)
        mem = node_data.get("memory_gb", 16)
        # Size proportional to resources
        size = 1000 + (cpu * 50) + (mem * 10)
        node_sizes.append(size)
    
    # --- Separate Edges by Type ---
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
        elif latency > 3.0:  # High latency (cross-zone)
            high_latency_edges.append((u, v))
            edge_labels[(u, v)] = f"⚠️ {latency:.1f}ms"
        else:
            normal_edges.append((u, v))
            edge_labels[(u, v)] = f"{latency:.1f}ms"
    
    # --- Draw Graph Components ---
    
    # Draw nodes
    nx.draw_networkx_nodes(G, pos, 
                          node_size=node_sizes, 
                          node_color=node_colors, 
                          alpha=0.9, 
                          edgecolors="black", 
                          linewidths=2)
    
    # Draw labels
    nx.draw_networkx_labels(G, pos, 
                           labels=node_labels,
                           font_size=7, 
                           font_weight="bold",
                           font_family="monospace")
    
    # Draw normal edges (solid green)
    if normal_edges:
        nx.draw_networkx_edges(G, pos,
                              edgelist=normal_edges,
                              width=1.0,
                              alpha=0.3,
                              edge_color="#06d6a0",
                              arrows=True,
                              arrowstyle="->",
                              arrowsize=10,
                              connectionstyle="arc3,rad=0.05")
    
    # Draw high latency edges (solid orange)
    if high_latency_edges:
        nx.draw_networkx_edges(G, pos,
                              edgelist=high_latency_edges,
                              width=1.5,
                              alpha=0.5,
                              edge_color="#f77f00",
                              arrows=True,
                              arrowstyle="->",
                              arrowsize=10,
                              connectionstyle="arc3,rad=0.05")
    
    # Draw firewalled edges (dashed red)
    if firewalled_edges:
        nx.draw_networkx_edges(G, pos,
                              edgelist=firewalled_edges,
                              width=2.0,
                              alpha=0.6,
                              edge_color="#e63946",
                              style="dashed",
                              arrows=True,
                              arrowstyle="->",
                              arrowsize=10,
                              connectionstyle="arc3,rad=0.05")
    
    # Draw edge labels (sample only for readability)
    # Only show labels for interesting edges
    important_edges = {k: v for k, v in edge_labels.items() 
                      if k in firewalled_edges or k in high_latency_edges}
    
    if important_edges and len(important_edges) < 100:  # Don't overcrowd
        nx.draw_networkx_edge_labels(G, pos,
                                     edge_labels=important_edges,
                                     font_size=6,
                                     font_color="#212529",
                                     bbox=dict(facecolor='white', alpha=0.7, 
                                             pad=1, edgecolor='none'))
    
    # --- Legend ---
    legend_elements = [
        plt.Line2D([0], [0], marker='o', color='w', 
                  markerfacecolor=get_node_color_by_type("control_plane"), 
                  markersize=15, label='Control Plane'),
        plt.Line2D([0], [0], marker='o', color='w', 
                  markerfacecolor=get_node_color_by_type("worker"), 
                  markersize=15, label='Worker'),
        plt.Line2D([0], [0], marker='o', color='w', 
                  markerfacecolor=get_node_color_by_type("compute"), 
                  markersize=15, label='Compute-Optimized'),
        plt.Line2D([0], [0], marker='o', color='w', 
                  markerfacecolor=get_node_color_by_type("memory"), 
                  markersize=15, label='Memory-Optimized'),
        plt.Line2D([0], [0], marker='o', color='w', 
                  markerfacecolor=get_node_color_by_type("storage"), 
                  markersize=15, label='Storage-Optimized'),
        plt.Line2D([0], [0], marker='o', color='w', 
                  markerfacecolor=get_node_color_by_type("gpu"), 
                  markersize=15, label='GPU'),
        plt.Line2D([0], [0], color='#06d6a0', linewidth=2, label='Normal Latency'),
        plt.Line2D([0], [0], color='#f77f00', linewidth=2, label='High Latency'),
        plt.Line2D([0], [0], color='#e63946', linewidth=2, 
                  linestyle='--', label='Firewalled')
    ]
    
    ax.legend(handles=legend_elements, loc='upper left', fontsize=12)
    
    color_by_text = "Type" if color_by == "type" else "Zone"
    plt.title(f"Physical Node Network Topology (Colored by {color_by_text})\n"
             f"Green=Low Latency, Orange=High Latency, Red=Firewalled",
             fontsize=20, fontweight='bold')
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
        print("Cannot visualize an empty graph.", file=sys.stderr)
        return
    
    fig, ax = plt.subplots(figsize=(32, 24))
    
    # Separate nodes by bipartite sets
    physical_nodes = [n for n, d in G.nodes(data=True) if d.get("bipartite") == 0]
    service_nodes = [n for n, d in G.nodes(data=True) if d.get("bipartite") == 1]
    
    # Create a layout with physical nodes on left, services on right
    pos = {}
    
    # Position physical nodes on the left
    y_spacing = 1.0
    for i, node in enumerate(physical_nodes):
        pos[node] = (0, i * y_spacing)
    
    # Position service nodes on the right
    y_spacing_services = len(physical_nodes) * y_spacing / max(len(service_nodes), 1)
    for i, service in enumerate(service_nodes):
        pos[service] = (3, i * y_spacing_services)
    
    # --- Node Colors ---
    node_colors = []
    node_sizes = []
    
    for node in G.nodes:
        if node in physical_nodes:
            node_data = G.nodes[node]
            node_type = node_data.get("node_type", "unknown")
            color = get_node_color_by_type(node_type)
            
            if not node_data.get("is_healthy", True):
                color = color + "80"  # Add alpha for unhealthy
            
            node_colors.append(color)
            node_sizes.append(2000)
        else:  # Service node
            node_colors.append("#ffd60a")  # Yellow for services
            # Size based on number of instances
            instance_count = len([e for e in G.edges(node)])
            node_sizes.append(500 + instance_count * 100)
    
    # --- Draw Graph Components ---
    
    # Draw nodes
    nx.draw_networkx_nodes(G, pos,
                          node_size=node_sizes,
                          node_color=node_colors,
                          alpha=0.9,
                          edgecolors="black",
                          linewidths=2)
    
    # Create better labels
    labels = {}
    for node in G.nodes:
        if node in physical_nodes:
            node_data = G.nodes[node]
            pod_count = len([e for e in G.edges(node)])
            cpu_util = node_data.get("cpu_util", 0)
            mem_util = node_data.get("mem_util", 0)
            zone = node_data.get("zone", "?").split("-")[-1].upper()
            health = "✓" if node_data.get("is_healthy", True) else "✗"
            labels[node] = f"{node}\nZ{zone} {health}\nPods:{pod_count}\nC:{cpu_util:.0f}% M:{mem_util:.0f}%"
        else:
            # Count instances
            instance_count = len([e for e in G.edges(node)])
            labels[node] = f"{node}\n({instance_count} pods)"
    
    # Draw labels
    nx.draw_networkx_labels(G, pos,
                           labels=labels,
                           font_size=8,
                           font_weight="bold",
                           font_family="monospace")
    
    # Draw edges
    nx.draw_networkx_edges(G, pos,
                          width=0.5,
                          alpha=0.3,
                          edge_color="#495057",
                          arrows=False)
    
    # --- Statistics Box ---
    stats = topology.get("metadata", {}).get("statistics", {})
    stats_text = f"""
Statistics:
  Total Nodes: {stats.get('total_nodes', 0)}
  Healthy Nodes: {stats.get('healthy_nodes', 0)}
  Total Pods: {stats.get('total_pods', 0)}
  Avg Pods/Node: {stats.get('avg_pods_per_node', 0)}
  
Resource Utilization:
  Avg CPU: {stats.get('resource_utilization', {}).get('avg_cpu_utilization', 0)}%
  Avg Memory: {stats.get('resource_utilization', {}).get('avg_memory_utilization', 0)}%
"""
    
    ax.text(0.02, 0.98, stats_text,
           transform=ax.transAxes,
           fontsize=10,
           verticalalignment='top',
           bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8),
           fontfamily='monospace')
    
    # --- Legend ---
    legend_elements = [
        plt.Line2D([0], [0], marker='o', color='w',
                  markerfacecolor=get_node_color_by_type("control_plane"),
                  markersize=15, label='Control Plane'),
        plt.Line2D([0], [0], marker='o', color='w',
                  markerfacecolor=get_node_color_by_type("worker"),
                  markersize=15, label='Worker'),
        plt.Line2D([0], [0], marker='o', color='w',
                  markerfacecolor=get_node_color_by_type("compute"),
                  markersize=15, label='Compute'),
        plt.Line2D([0], [0], marker='o', color='w',
                  markerfacecolor=get_node_color_by_type("memory"),
                  markersize=15, label='Memory'),
        plt.Line2D([0], [0], marker='o', color='w',
                  markerfacecolor=get_node_color_by_type("storage"),
                  markersize=15, label='Storage'),
        plt.Line2D([0], [0], marker='o', color='w',
                  markerfacecolor="#ffd60a",
                  markersize=15, label='Service/Pod')
    ]
    
    ax.legend(handles=legend_elements, loc='upper right', fontsize=12)
    
    plt.title("Node-to-Service Mapping\nPhysical Nodes (Left) → Services (Right)",
             fontsize=20, fontweight='bold')
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
    
    # Collect data
    zones = defaultdict(lambda: {"nodes": 0, "pods": 0, "types": defaultdict(int)})
    
    for node in topology["nodes"]:
        zone = node["zone"]
        node_type = node["node_type"]
        pod_count = node["pod_count"]
        
        zones[zone]["nodes"] += 1
        zones[zone]["pods"] += pod_count
        zones[zone]["types"][node_type] += 1
    
    # Plot 1: Nodes per zone
    zone_names = list(zones.keys())
    node_counts = [zones[z]["nodes"] for z in zone_names]
    colors = [get_node_color_by_zone(z) for z in zone_names]
    
    ax1.bar(zone_names, node_counts, color=colors, alpha=0.8, edgecolor='black')
    ax1.set_title("Nodes per Availability Zone", fontsize=16, fontweight='bold')
    ax1.set_xlabel("Zone", fontsize=12)
    ax1.set_ylabel("Number of Nodes", fontsize=12)
    ax1.grid(axis='y', alpha=0.3)
    
    # Add value labels on bars
    for i, (zone, count) in enumerate(zip(zone_names, node_counts)):
        ax1.text(i, count + 0.5, str(count), ha='center', fontweight='bold')
    
    # Plot 2: Pods per zone
    pod_counts = [zones[z]["pods"] for z in zone_names]
    
    ax2.bar(zone_names, pod_counts, color=colors, alpha=0.8, edgecolor='black')
    ax2.set_title("Pods per Availability Zone", fontsize=16, fontweight='bold')
    ax2.set_xlabel("Zone", fontsize=12)
    ax2.set_ylabel("Number of Pods", fontsize=12)
    ax2.grid(axis='y', alpha=0.3)
    
    # Add value labels on bars
    for i, (zone, count) in enumerate(zip(zone_names, pod_counts)):
        ax2.text(i, count + 1, str(count), ha='center', fontweight='bold')
    
    plt.suptitle("Availability Zone Distribution", fontsize=20, fontweight='bold', y=0.98)
    plt.tight_layout()
    
    try:
        plt.savefig(output_file, format="PNG", dpi=150, bbox_inches="tight")
        print(f"✅ Zone distribution graph saved to {output_file}")
    except Exception as e:
        print(f"Error saving graph image: {e}", file=sys.stderr)
    
    plt.close()

def main():
    """Main CLI interface"""
    if len(sys.argv) < 2:
        print("Usage: python visualize_physical_topology.py <cluster_config_with_nodes.json>")
        print("\nExample: python visualize_physical_topology.py cluster_with_nodes.json")
        print("\nGenerates three visualizations:")
        print("  1. Node network topology (colored by type)")
        print("  2. Node network topology (colored by zone)")
        print("  3. Node-to-service mapping")
        print("  4. Zone distribution charts")
        sys.exit(1)
    
    input_file = sys.argv[1]
    base_output = input_file.replace(".json", "")
    
    # Load data
    print(f"📂 Loading physical topology from {input_file}...")
    topology = load_physical_topology(input_file)
    
    print(f"   Found {len(topology.get('nodes', []))} nodes")
    print(f"   Found {len(topology.get('node_connections', []))} connections")
    
    # Build graphs
    print("🕸️  Building node network graph...")
    node_network_graph = build_node_network_graph(topology)
    
    print("🕸️  Building node-service mapping graph...")
    node_service_graph = build_node_service_graph(topology)
    
    # Generate visualizations
    print("🎨 Generating visualizations...")
    
    # 1. Node network colored by type
    output1 = f"{base_output}_nodes_by_type.png"
    visualize_node_network(node_network_graph, output1, color_by="type")
    
    # 2. Node network colored by zone
    output2 = f"{base_output}_nodes_by_zone.png"
    visualize_node_network(node_network_graph, output2, color_by="zone")
    
    # 3. Node-to-service mapping
    output3 = f"{base_output}_node_service_mapping.png"
    visualize_node_service_mapping(node_service_graph, output3, topology)
    
    # 4. Zone distribution
    output4 = f"{base_output}_zone_distribution.png"
    visualize_zone_distribution(topology, output4)
    
    print(f"\n{'='*80}")
    print("✅ All visualizations generated successfully!")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()