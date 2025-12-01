"""
CyberBattleSim Attack Scenario Generator
========================================
Extends NetworkGenerator to create CyberBattleSim attack scenarios from cluster.json.
Includes comprehensive attack path analysis and visualization.

Author: Based on Microsoft CyberBattleSim
Date: 2025-11-09
"""

import json
import argparse
import logging
import os
import sys
import heapq
import time
from typing import Dict, FrozenSet, List, Set, Tuple, Optional, Iterator, cast
import ipaddress
import matplotlib.pyplot as plt
import networkx as nx
import matplotlib
from dataclasses import dataclass, field

# Use non-interactive backend for saving files
matplotlib.use('Agg')

# --- External Dependencies ---
try:
    from cyberbattle.simulation.nodes import NodeInfo
    from cyberbattle.simulation.firewall import FirewallRule, RulePermission, FirewallConfiguration
    from cyberbattle.simulation.vulenrabilites import (
        VulnerabilityInfo, VulnerabilityType, LeakedNodesId, LeakedCredentials, 
        CachedCredential, PrivilegeEscalation, AdminEscalation, SystemEscalation,
        CustomerData, LateralMove, PrivilegeLevel
    )
    from cyberbattle.simulation.nodes_types import NodeID
    from cyberbattle.simulation.services import ListeningService
    from cyberbattle.simulation.network import NodeNetworkInfo, Subnet, NetworkInterfaces
    from cyberbattle.simulation.identifiers import Identifiers
    from cyberbattle.simulation.nodes_network import infer_constants_from_nodes

    from cyberbattlesim_network_gen.generators.network_generator import NetworkGenerator
    from cyberbattlesim_network_gen.generators.file_utils import save_yaml
    from cyberbattlesim_network_gen.generators.utils import cli_default
except ImportError as e:
    raise ImportError(f"Missing required CyberBattleSim dependencies: {e}")


class AttackVisualizer:
    """
    Robust Visualizer:
    - Fixed Discovery Tree parsing (case-insensitive, aggressive matching)
    - Fixed Optimal Path crash (filters nodes against graph existence)
    - Debug prints to show exactly what is being parsed
    """
    
    def __init__(self, output_dir: str):
        self.output_dir = os.path.join(output_dir, "graphs")
        os.makedirs(self.output_dir, exist_ok=True)
    
    def visualize_attack_paths(self, nodes: Dict[str, NodeInfo], attack_paths: Dict):
        print(f"\n🎨 Generating attack path visualizations...")
        
        # 1. Build Base Network Graph (Strict Firewall Rules)
        G = nx.DiGraph()
        node_ips = {nid: n.network_info[0].ip_address for nid, n in nodes.items() if n.network_info}

        # Add Nodes
        for nid, n in nodes.items():
            G.add_node(nid, type="attacker" if "attacker" in n.properties else "target")
            
        # Add Edges (Strict Firewall Check)
        for src_id, src_info in nodes.items():
            for tgt_id, tgt_info in nodes.items():
                if src_id == tgt_id: continue
                tgt_ip = node_ips.get(tgt_id)
                if not tgt_ip: continue
                for rule in src_info.firewall.outgoing:
                    if rule.permission == RulePermission.ALLOW:
                        try:
                            if str(rule.subnet) in ["*", "0.0.0.0/0"]:
                                G.add_edge(src_id, tgt_id, type="network_access"); break
                            if ipaddress.ip_address(tgt_ip) in ipaddress.ip_network(str(rule.subnet), strict=False):
                                G.add_edge(src_id, tgt_id, type="network_access"); break
                        except: continue

        # Run Generators
        self._create_network_overview(G, nodes)
        self._create_vulnerability_heatmap(G, nodes)
        self._create_attack_path_diagram(G, attack_paths)
        self._create_discovery_tree(attack_paths)
        self._create_property_discovery_chart(attack_paths)

    def _create_attack_path_diagram(self, G: nx.DiGraph, attack_paths: Dict):
        """Numbered Attack Path Sequence"""
        if not attack_paths or "maximal_achievement" not in attack_paths: return
        
        path_info = attack_paths["maximal_achievement"]
        raw_nodes = self._extract_path_nodes(path_info)
        
        # --- CRITICAL FIX: Filter nodes that don't exist in the graph ---
        valid_nodes = [n for n in raw_nodes if n in G.nodes()]
        
        if not valid_nodes:
            print("   ! No valid path nodes found in graph to draw.")
            return

        print(f"   > Drawing Optimal Path with {len(valid_nodes)} nodes...")

        plt.figure(figsize=(22, 16))
        node_order = {node: i for i, node in enumerate(valid_nodes)}
        
        # Layout
        try: pos = nx.spring_layout(G, k=2.0, iterations=100, seed=42)
        except: pos = nx.shell_layout(G)
        
        # Background (Non-path nodes)
        non_path = [n for n in G.nodes() if n not in valid_nodes]
        nx.draw_networkx_nodes(G, pos, nodelist=non_path, node_color='#f0f0f0', node_size=300, alpha=0.4)
        nx.draw_networkx_edges(G, pos, alpha=0.05, edge_color='gray')

        # Path Edges
        path_edges = []
        for i in range(len(valid_nodes)-1):
            path_edges.append((valid_nodes[i], valid_nodes[i+1]))
            
        nx.draw_networkx_edges(G, pos, edgelist=path_edges, edge_color='#ff4444', width=2.5, 
                             arrowstyle='-|>', arrowsize=20, connectionstyle='arc3,rad=0.1')

        # Path Nodes
        # Draw Start
        if valid_nodes[0] in pos:
            nx.draw_networkx_nodes(G, pos, nodelist=[valid_nodes[0]], node_color='#32CD32', node_size=1200, node_shape='s')
        
        # Draw Intermediates
        if len(valid_nodes) > 2:
            intermediates = valid_nodes[1:-1]
            # Filter intermediates again just to be safe for drawing
            intermediates = [n for n in intermediates if n in pos]
            if intermediates:
                nx.draw_networkx_nodes(G, pos, nodelist=intermediates, node_color='#FFD700', node_size=1000)
            
        # Draw Target
        if len(valid_nodes) > 1 and valid_nodes[-1] in pos:
            nx.draw_networkx_nodes(G, pos, nodelist=[valid_nodes[-1]], node_color='#FF4500', node_size=1200, node_shape='D')

        # Labels & Numbers
        # Only label valid nodes
        labels = {n: f"{n.split('_')[-1]}" for n in valid_nodes if n in pos}
        nx.draw_networkx_labels(G, pos, labels=labels, font_size=9, font_weight="bold")

        for node, order_id in node_order.items():
            if node in pos:
                x, y = pos[node]
                plt.text(x, y+0.04, f"#{order_id}", fontsize=12, color='darkblue', fontweight='bold', 
                        horizontalalignment='center', bbox=dict(facecolor='white', alpha=0.7, edgecolor='none'))

        plt.title(f"Optimal Attack Path Sequence", fontsize=20)
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "optimal_attack_path.png"), dpi=150)
        plt.close()
        print(f"   - Saved optimal_attack_path.png")

    def _create_discovery_tree(self, attack_paths: Dict):
        """Discovery Provenance Tree (Pivots and Routers)"""
        if not attack_paths or "maximal_achievement" not in attack_paths: return
        
        path_info = attack_paths["maximal_achievement"]
        path = path_info.get("path", [])
        starting_node = path_info.get("starting_node", "Attacker")
        
        # Only add starting node if it's not generic 'Attacker' or if generic is acceptable
        # Better to start empty and add based on logs
        Tree = nx.DiGraph()
        current_source = starting_node
        
        for action in path:
            # Parse Source
            if "change_source" in action.lower() or "change source" in action.lower():
                if " to " in action:
                    current_source = action.split(" to ")[-1].strip()
            
            # Parse Exploits/Connects
            elif any(k in action.lower() for k in ["connect", "exploit", "lateral"]):
                target = None
                if " to " in action:
                    target = action.split(" to ")[-1].strip().split(" ")[0]
                elif " on " in action:
                    target = action.split(" on ")[-1].strip()

                # Clean up target string
                if target:
                    if "(" in target: target = target.split("(")[0].strip()
                    target = target.strip()
                
                if target and target != current_source:
                    method = "Exploit" if "exploit" in action.lower() else "Connect"
                    Tree.add_edge(current_source, target, method=method)

        if len(Tree.nodes) == 0: 
            return

        plt.figure(figsize=(18, 12))
        try:
            from networkx.drawing.nx_agraph import graphviz_layout
            pos = graphviz_layout(Tree, prog='dot')
        except:
            pos = nx.shell_layout(Tree)

        pivots = [n for n in Tree.nodes() if Tree.out_degree(n) > 0]
        
        nx.draw_networkx_nodes(Tree, pos, node_color='#87CEFA', node_size=800, alpha=0.8)
        nx.draw_networkx_nodes(Tree, pos, nodelist=pivots, node_color='#FF4500', node_size=1200, node_shape='D')
        nx.draw_networkx_edges(Tree, pos, edge_color='#555555', arrowstyle='-|>', arrowsize=20)
        
        labels = {n: n.split('_')[-1] if len(n)>10 else n for n in Tree.nodes()}
        nx.draw_networkx_labels(Tree, pos, labels=labels, font_size=8, font_weight="bold")
        
        edge_labels = nx.get_edge_attributes(Tree, 'method')
        nx.draw_networkx_edge_labels(Tree, pos, edge_labels=edge_labels, font_size=7)

        plt.title("Discovery Provenance Tree (Who Discovered Whom)", fontsize=18)
        plt.axis("off"); plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "discovery_tree.png"), dpi=150)
        plt.close()
        print(f"   - Saved discovery_tree.png")

    def _create_network_overview(self, G: nx.DiGraph, nodes: Dict[str, NodeInfo]):
        plt.figure(figsize=(20, 15))
        try: pos = nx.kamada_kawai_layout(G)
        except: pos = nx.spring_layout(G, k=0.5)
        
        node_colors = []
        for node in G.nodes():
            if "attacker" in nodes[node].properties: node_colors.append("#ff4d4d")
            elif "control_plane" in nodes[node].properties: node_colors.append("#ffa500")
            else: node_colors.append("#87cefa")
        
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=600, alpha=0.9, edgecolors='white')
        nx.draw_networkx_edges(G, pos, alpha=0.1, arrows=True, arrowstyle='->', arrowsize=8, edge_color='gray')
        
        labels = {n: n.split('_')[-1] if len(n) > 15 else n for n in G.nodes()}
        nx.draw_networkx_labels(G, pos, labels=labels, font_size=7, font_weight="bold")
        
        plt.title("Network Overview", fontsize=18)
        plt.axis("off"); plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "network_overview.png"), dpi=150)
        plt.close()
        print("   - Saved network_overview.png")

    def _create_vulnerability_heatmap(self, G: nx.DiGraph, nodes: Dict[str, NodeInfo]):
        plt.figure(figsize=(16, 12))
        try: pos = nx.spring_layout(G, k=1.5, seed=42)
        except: pos = nx.random_layout(G)
        
        vuln_counts = [len(nodes[node].vulnerabilities) for node in G.nodes()]
        nx.draw_networkx_nodes(G, pos, node_color=vuln_counts, node_size=700, alpha=0.9, cmap='YlOrRd', edgecolors='black')
        nx.draw_networkx_edges(G, pos, alpha=0.1, arrows=False)
        
        labels = {n: n.split('_')[-1] if len(n) > 15 else n for n in G.nodes()}
        nx.draw_networkx_labels(G, pos, labels=labels, font_size=7)
        plt.title("Vulnerability Heatmap", fontsize=16)
        plt.axis("off"); plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "vulnerability_heatmap.png"), dpi=150)
        plt.close()
        print("   - Saved vulnerability_heatmap.png")

    def _create_property_discovery_chart(self, attack_paths: Dict):
        if not attack_paths: return
        plt.figure(figsize=(12, 8))
        if "maximal_achievement" in attack_paths:
            path_info = attack_paths["maximal_achievement"]
            steps = list(range(len(path_info["path"]) + 1))
            owned_count = [1]
            current = 1
            for action in path_info["path"]:
                if any(k in action for k in ["exploit", "connect", "LateralMove"]): current += 0.5
                if "change_destination" in action: current += 0.1
                owned_count.append(int(current))
            
            if len(owned_count) > len(steps): owned_count = owned_count[:len(steps)]
            elif len(owned_count) < len(steps): steps = steps[:len(owned_count)]
            
            plt.step(steps, owned_count, where='post', color='green', linewidth=2)
            plt.fill_between(steps, owned_count, alpha=0.2, color='green')
            plt.title('Attack Progression Timeline', fontsize=16)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(os.path.join(self.output_dir, "attack_progression.png"), dpi=150)
            plt.close()
            print("   - Saved attack_progression.png")

    def _extract_path_nodes(self, path_info):
        """Extract ordered node sequence from attack path logs"""
        start_node = path_info.get("starting_node", None)
        path = path_info.get("path", [])
        
        nodes = []
        if start_node: nodes.append(start_node)
            
        for action in path:
            # Source -> Target
            if " from " in action and " to " in action:
                parts = action.split(" from ")
                if len(parts) > 1:
                    subparts = parts[1].split(" to ")
                    if len(subparts) > 1:
                        src = subparts[0].strip(); tgt = subparts[1].split(" ")[0].strip()
                        if not nodes and src: nodes.append(src)
                        if nodes and nodes[-1] != src and src not in nodes: nodes.append(src)
                        if tgt not in nodes: nodes.append(tgt)
            # Change Dest / Connect to Target
            elif " to " in action:
                tgt = action.split(" to ")[-1].strip().split(" ")[0]
                if "(" in tgt: tgt = tgt.split("(")[0]
                if " " not in tgt and tgt not in nodes: nodes.append(tgt)
            # On Target
            elif " on " in action:
                tgt = action.split(" on ")[-1].strip()
                if tgt not in nodes: nodes.append(tgt)
        return nodes
