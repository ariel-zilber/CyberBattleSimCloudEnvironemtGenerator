#!/usr/bin/env python3
"""
Network Topology Visualizer
===========================
Loads a cluster.json file containing network topology data
and generates a PNG visualization of the service graph.

This version displays all known connections, coloring them based
on whether they are allowed, blocked, or require authentication.

Requires: networkx, matplotlib
Install with: pip install networkx matplotlib
"""

import json
import sys
import networkx as nx
import matplotlib.pyplot as plt
from typing import Dict, List

def load_topology(filepath: str) -> Dict:
    """Load network topology from a cluster JSON file"""
    try:
        with open(filepath, 'r') as f:
            cluster_config = json.load(f)
        
        if "network_topology" not in cluster_config:
            print(f"Error: 'network_topology' key not found in {filepath}", file=sys.stderr)
            sys.exit(1)
            
        return cluster_config["network_topology"]
        
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {filepath}", file=sys.stderr)
        sys.exit(1)

def build_graph(topology: Dict) -> nx.DiGraph:
    """Build a NetworkX graph from topology data"""
    G = nx.DiGraph()
    
    # Add nodes (services)
    if "services" not in topology:
        print("Error: No 'services' found in topology data", file=sys.stderr)
        return G
        
    for service_name, service_data in topology["services"].items():
        G.add_node(service_name, 
                   category=service_data.get("category", "unknown"),
                   is_public=service_data.get("is_public", False),
                   vulnerability=service_data.get("vulnerability_level", 0))
    
    # Add edges (using 'knows_connectivity' to get ALL connections)
    if "knows_connectivity" not in topology:
        print("Warning: No 'knows_connectivity' found. Graph will have no edges.", file=sys.stderr)
        return G

    for edge in topology["knows_connectivity"]:
        if G.has_node(edge["source"]) and G.has_node(edge["target"]):
            G.add_edge(edge["source"], edge["target"], 
                       port=edge.get("port", 0),
                       firewall_allowed=edge.get("firewall_allowed", False),
                       requires_auth=edge.get("requires_auth", True)) # Added auth data
            
    return G

def visualize_graph(G: nx.DiGraph, output_file: str, entry_points: List[str]):
    """Generate and save a visualization of the graph"""
    if G.number_of_nodes() == 0:
        print("Cannot visualize an empty graph.", file=sys.stderr)
        return

    plt.figure(figsize=(24, 24)) # Made figure even larger for clarity
    
    # Use a spring layout
    pos = nx.spring_layout(G, k=0.7, iterations=50, seed=42)
    
    # --- 1. Define Node Colors ---
    node_colors = []
    for node in G.nodes:
        if node in entry_points:
            node_colors.append("#e63946")  # Bright Red for entry points
        elif G.nodes[node].get("category") == "database":
            node_colors.append("#52b788")  # Green for databases
        elif G.nodes[node].get("category") == "security":
            node_colors.append("#0077b6")  # Blue for security
        else:
            node_colors.append("#ffb703")  # Yellow/Orange for others
    
    # --- 2. Separate Edges by Type ---
    allowed_auth_edges = []
    allowed_no_auth_edges = []
    blocked_edges = []
    
    auth_labels = {}
    no_auth_labels = {}

    for u, v, data in G.edges(data=True):
        if data.get("firewall_allowed", False):
            if data.get("requires_auth", True):
                allowed_auth_edges.append((u, v))
                auth_labels[(u, v)] = f"🔒 {data.get('port', 0)}" # Add lock icon
            else:
                allowed_no_auth_edges.append((u, v))
                no_auth_labels[(u, v)] = f"❗ {data.get('port', 0)}" # Add warning icon
        else:
            blocked_edges.append((u, v))

    # --- 3. Draw Graph Components ---
            
    # Draw Nodes
    nx.draw_networkx_nodes(G, pos, node_size=3000, node_color=node_colors, alpha=0.9, edgecolors="black", linewidths=0.5)
    
    # Draw Labels
    nx.draw_networkx_labels(G, pos, font_size=10, font_weight="bold")
    
    # Draw Allowed + Auth Edges (Solid Blue)
    nx.draw_networkx_edges(G, pos, 
                           edgelist=allowed_auth_edges,
                           width=1.5, 
                           alpha=0.7, 
                           edge_color="#0077b6", # Blue
                           arrows=True, 
                           arrowstyle="->", 
                           arrowsize=20,
                           connectionstyle="arc3,rad=0.1")
    
    # Draw Allowed + NO Auth Edges (Solid Orange)
    nx.draw_networkx_edges(G, pos, 
                           edgelist=allowed_no_auth_edges,
                           width=2.0,  # Make these stand out
                           alpha=0.8, 
                           edge_color="#fb8500", # Orange
                           arrows=True, 
                           arrowstyle="->", 
                           arrowsize=20,
                           connectionstyle="arc3,rad=0.1")
    
    # Draw Blocked Edges (Dashed Red)
    nx.draw_networkx_edges(G, pos, 
                           edgelist=blocked_edges,
                           width=1.0, 
                           alpha=0.4, 
                           edge_color="#e63946", # Red
                           style="dashed", 
                           arrows=False,
                           connectionstyle="arc3,rad=0.1")

    # --- 4. Draw Edge Labels (Ports) ---
    nx.draw_networkx_edge_labels(G, pos,
                                 edge_labels=auth_labels,
                                 font_color="#003049",
                                 font_size=9,
                                 bbox=dict(facecolor='white', alpha=0.5, pad=0.1, edgecolor='none'))
    
    nx.draw_networkx_edge_labels(G, pos,
                                 edge_labels=no_auth_labels,
                                 font_color="#c9184a",
                                 font_weight="bold",
                                 font_size=9,
                                 bbox=dict(facecolor='white', alpha=0.5, pad=0.1, edgecolor='none'))

    
    plt.title("Cluster Service Graph (Blue=Auth, Orange=No-Auth, Red=Blocked)", fontsize=24)
    plt.axis("off")
    
    try:
        plt.savefig(output_file, format="PNG", dpi=100, bbox_inches="tight")
        print(f"\n✅ Graph visualization saved to {output_file}")
    except Exception as e:
        print(f"Error saving graph image: {e}", file=sys.stderr)

def main():
    """Main CLI interface"""
    if len(sys.argv) < 2:
        print("Usage: python visualize_topology.py <cluster_config.json>")
        print("\nExample: python visualize_topology.py test_with_topology.json")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = input_file.replace(".json", "_graph.png")
    
    # Load data
    print(f"📂 Loading topology from {input_file}...")
    topology = load_topology(input_file)
    
    # Build graph
    print("🕸️  Building graph from 'knows_connectivity' to show all connection types...")
    G = build_graph(topology)
    
    # Visualize
    print(f"🎨 Generating visualization...")
    entry_points = topology.get("metadata", {}).get("entry_points", [])
    visualize_graph(G, output_file, entry_points)

if __name__ == "__main__":
    main()