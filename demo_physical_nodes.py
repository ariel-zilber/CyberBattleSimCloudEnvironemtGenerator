#!/usr/bin/env python3
"""
Demonstration of Physical Nodes Extension
==========================================
This script shows how to use the physical_nodes_extension.py module
to add physical node topology to Kubernetes cluster configurations.

Author: Auto-generated
Date: 2025-11-08
"""

import json
import sys
import os

# Note: In practice, you would copy the original k8s_cluster_generator.py
# to the same directory and import it. For this demo, we'll simulate it.

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def create_sample_cluster():
    """Create a sample cluster configuration (simulating the original generator)"""
    return {
        "cluster_metadata": {
            "num_nodes": 10,
            "cluster_size": "SMALL",
            "use_case": "microservices",
            "total_services": 15,
            "total_pods": 35,
            "avg_pods_per_node": "3.5",
            "total_resource_weight": 85,
            "resource_utilization": "85.0%"
        },
        "services": [
            "argo-cd", "cert-manager", "cilium", "etcd", "fluent-bit",
            "grafana", "grafana-loki", "jaeger", "kong", "kube-state-metrics",
            "metrics-server", "nginx", "postgresql", "prometheus", "redis"
        ],
        "service_instances": {
            "argo-cd": 3,
            "cert-manager": 1,
            "cilium": 1,
            "etcd": 3,
            "fluent-bit": 1,
            "grafana": 1,
            "grafana-loki": 3,
            "jaeger": 3,
            "kong": 3,
            "kube-state-metrics": 1,
            "metrics-server": 1,
            "nginx": 3,
            "postgresql": 3,
            "prometheus": 3,
            "redis": 3
        },
        "services_by_category": {
            "ci_cd": ["argo-cd"],
            "control_plane_core": ["etcd", "kube-state-metrics", "metrics-server"],
            "control_plane_networking": ["cilium", "kong"],
            "control_plane_security": ["cert-manager"],
            "data_caching": ["redis"],
            "data_sql": ["postgresql"],
            "observability_logging": ["fluent-bit", "grafana-loki"],
            "observability_metrics": ["grafana", "prometheus"],
            "observability_tracing": ["jaeger"],
            "web_servers": ["nginx"]
        },
        "deployment_stats": {
            "observability_stack": {
                "metrics": True,
                "logging": True,
                "tracing": True,
                "completeness_score": 1.0
            },
            "automation": {
                "gitops_enabled": True,
                "service_mesh": True
            },
            "data_layer": {
                "sql_databases": 1,
                "nosql_databases": 0,
                "caching": True,
                "messaging": False
            }
        }
    }


def main():
    print("="*80)
    print("PHYSICAL NODES EXTENSION DEMONSTRATION")
    print("="*80)
    
    # Step 1: Create or load a base cluster configuration
    print("\n📦 Step 1: Creating base cluster configuration...")
    cluster = create_sample_cluster()
    print(f"   ✅ Created {cluster['cluster_metadata']['cluster_size']} cluster with "
          f"{cluster['cluster_metadata']['num_nodes']} nodes")
    print(f"   Services: {cluster['cluster_metadata']['total_services']}")
    print(f"   Total Pods: {cluster['cluster_metadata']['total_pods']}")
    
    # Step 2: Import and apply the physical nodes extension
    print("\n🏗️  Step 2: Applying physical nodes extension...")
    try:
        from physical_nodes_extension import (
            extend_with_physical_nodes,
            print_cluster_summary,
            export_node_graph_to_graphviz
        )
        
        extended_cluster = extend_with_physical_nodes(cluster, seed=42)
        print("   ✅ Physical nodes generated and services placed")
        
    except ImportError as e:
        print(f"   ❌ Error: Could not import physical_nodes_extension: {e}")
        print("   Make sure physical_nodes_extension.py is in the same directory")
        return
    
    # Step 3: Display summary
    print_cluster_summary(extended_cluster)
    
    # Step 4: Show detailed node information
    print("\n" + "="*80)
    print("PHYSICAL NODE DETAILS")
    print("="*80)
    
    nodes = extended_cluster["physical_nodes"]
    print(f"\nTotal Nodes: {len(nodes)}")
    
    # Group by type
    from collections import defaultdict
    nodes_by_type = defaultdict(list)
    for node in nodes:
        nodes_by_type[node["node_type"]].append(node)
    
    for node_type, node_list in sorted(nodes_by_type.items()):
        if not node_list:
            continue
            
        print(f"\n{node_type.upper().replace('_', ' ')} ({len(node_list)} nodes):")
        print("-" * 80)
        
        for node in node_list[:3]:  # Show first 3 of each type
            print(f"  {node['node_id']:30s} "
                  f"CPU: {node['cpu_utilization_pct']:5.1f}% "
                  f"Mem: {node['memory_utilization_pct']:5.1f}% "
                  f"Pods: {node['pod_count']:2d} "
                  f"Zone: {node['zone']}")
        
        if len(node_list) > 3:
            print(f"  ... and {len(node_list) - 3} more")
    
    # Step 5: Show pod placements
    print("\n" + "="*80)
    print("POD PLACEMENT EXAMPLES")
    print("="*80)
    
    placements = extended_cluster["pod_placements"]
    print(f"\nTotal Placements: {len(placements)}")
    print("\nFirst 10 placements:")
    print("-" * 80)
    print(f"{'Pod ID':35s} {'Node':30s} {'CPU':6s} {'Memory':8s}")
    print("-" * 80)
    
    for placement in placements[:10]:
        print(f"{placement['pod_id']:35s} "
              f"{placement['node_id']:30s} "
              f"{placement['cpu_request']:5.1f}c "
              f"{placement['memory_request']:7.1f}GB")
    
    if len(placements) > 10:
        print(f"... and {len(placements) - 10} more placements")
    
    # Step 6: Network topology statistics
    print("\n" + "="*80)
    print("NETWORK TOPOLOGY")
    print("="*80)
    
    topology = extended_cluster["node_topology"]
    stats = topology["topology_stats"]
    
    print(f"\nNodes: {stats['total_nodes']}")
    print(f"Edges: {stats['total_edges']}")
    print(f"Average Degree: {stats['avg_degree']}")
    print(f"Availability Zones: {stats['zones']}")
    print(f"Control Plane Nodes: {stats['control_plane_nodes']}")
    print(f"Worker Nodes: {stats['worker_nodes']}")
    
    # Show some edge examples
    print("\nSample Network Connections:")
    print("-" * 80)
    print(f"{'Source':30s} {'Target':30s} {'Type':12s} {'Latency':10s}")
    print("-" * 80)
    
    for edge in topology["edges"][:10]:
        print(f"{edge['source']:30s} "
              f"{edge['target']:30s} "
              f"{edge['edge_type']:12s} "
              f"{edge['latency_ms']:7.2f}ms")
    
    if len(topology["edges"]) > 10:
        print(f"... and {len(topology['edges']) - 10} more connections")
    
    # Step 7: Export outputs
    print("\n" + "="*80)
    print("EXPORTING OUTPUTS")
    print("="*80)
    
    # Export JSON
    output_json = "out4/extended_cluster_demo.json"
    with open(output_json, 'w') as f:
        json.dump(extended_cluster, f, indent=2)
    print(f"\n✅ JSON configuration saved to: {output_json}")
    
    # Export Graphviz
    output_dot = "out4/node_topology_demo.dot"
    export_node_graph_to_graphviz(extended_cluster, output_dot)
    print(f"✅ Graphviz graph saved to: {output_dot}")
    print(f"   Render with: dot -Tpng {output_dot} -o node_topology.png")
    
    # Step 8: Analysis and recommendations
    print("\n" + "="*80)
    print("ANALYSIS & RECOMMENDATIONS")
    print("="*80)
    
    util = extended_cluster["node_utilization"]["utilization_pct"]
    
    print("\n📊 Resource Utilization:")
    if util["cpu"] > 80:
        print(f"   ⚠️  CPU utilization is high ({util['cpu']}%) - consider adding more nodes")
    elif util["cpu"] < 30:
        print(f"   💡 CPU utilization is low ({util['cpu']}%) - cluster may be over-provisioned")
    else:
        print(f"   ✅ CPU utilization is healthy ({util['cpu']}%)")
    
    if util["memory"] > 80:
        print(f"   ⚠️  Memory utilization is high ({util['memory']}%) - consider adding memory-optimized nodes")
    elif util["memory"] < 30:
        print(f"   💡 Memory utilization is low ({util['memory']}%) - consider downsizing")
    else:
        print(f"   ✅ Memory utilization is healthy ({util['memory']}%)")
    
    # Check for overutilized nodes
    overutilized = [n for n in nodes if n["cpu_utilization_pct"] > 80 or n["memory_utilization_pct"] > 80]
    if overutilized:
        print(f"\n⚠️  {len(overutilized)} nodes are over 80% utilized:")
        for node in overutilized[:5]:
            print(f"   {node['node_id']:30s} CPU: {node['cpu_utilization_pct']:.1f}% Mem: {node['memory_utilization_pct']:.1f}%")
    
    # Check HA
    if stats['zones'] >= 3:
        print(f"\n✅ Multi-AZ deployment across {stats['zones']} zones provides high availability")
    else:
        print(f"\n💡 Consider deploying across 3+ availability zones for better HA")
    
    # Check observability
    obs = extended_cluster["deployment_stats"]["observability_stack"]
    if obs["completeness_score"] == 1.0:
        print("\n✅ Full observability stack deployed (metrics + logging + tracing)")
    else:
        print(f"\n💡 Observability score: {obs['completeness_score']*100:.0f}%")
        if not obs["metrics"]:
            print("   Consider adding Prometheus/Grafana for metrics")
        if not obs["logging"]:
            print("   Consider adding Loki/Elasticsearch for logging")
        if not obs["tracing"]:
            print("   Consider adding Jaeger/Tempo for distributed tracing")
    
    print("\n" + "="*80)
    print("DEMONSTRATION COMPLETE")
    print("="*80)
    print(f"\n📁 Output files:")
    print(f"   - {output_json}")
    print(f"   - {output_dot}")
    print("\n💡 Next steps:")
    print("   1. Review the JSON output for complete cluster configuration")
    print("   2. Render the Graphviz graph to visualize node topology")
    print("   3. Use the extended configuration for further analysis or simulation")


if __name__ == "__main__":
    main()
