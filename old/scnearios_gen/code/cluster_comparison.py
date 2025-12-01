#!/usr/bin/env python3
"""
Cluster Comparison Tool
========================
Compare multiple Kubernetes cluster configurations and visualize differences.
"""

import json
import sys
from collections import defaultdict
from typing import List, Dict


def load_cluster(filepath: str) -> Dict:
    """Load a cluster configuration from JSON file"""
    with open(filepath, 'r') as f:
        return json.load(f)


def compare_clusters(clusters: List[Dict]) -> Dict:
    """Compare multiple cluster configurations"""
    comparison = {
        "summary": {
            "total_clusters": len(clusters),
            "cluster_sizes": [],
            "use_cases": []
        },
        "service_analysis": {
            "common_to_all": [],
            "unique_per_cluster": [],
            "service_frequency": {}
        },
        "statistics": {
            "avg_services": 0,
            "avg_resource_util": 0,
            "observability_coverage": 0
        }
    }
    
    # Extract basic info
    total_services = 0
    total_resource_util = 0
    observability_count = 0
    
    for cluster in clusters:
        meta = cluster["cluster_metadata"]
        comparison["summary"]["cluster_sizes"].append(f"{meta['num_nodes']} nodes")
        comparison["summary"]["use_cases"].append(meta["use_case"])
        total_services += meta["total_services"]
        
        # Parse resource utilization
        util = float(meta["resource_utilization"].replace("%", ""))
        total_resource_util += util
        
        # Check observability
        stats = cluster.get("deployment_stats", {})
        obs = stats.get("observability_stack", {})
        if obs.get("completeness_score", 0) >= 0.66:
            observability_count += 1
    
    comparison["statistics"]["avg_services"] = total_services / len(clusters)
    comparison["statistics"]["avg_resource_util"] = f"{total_resource_util / len(clusters):.1f}%"
    comparison["statistics"]["observability_coverage"] = f"{(observability_count / len(clusters)) * 100:.0f}%"
    
    # Service frequency analysis
    all_services = set()
    service_counts = defaultdict(int)
    
    for cluster in clusters:
        services = set(cluster["services"])
        all_services.update(services)
        for service in services:
            service_counts[service] += 1
    
    # Common to all
    comparison["service_analysis"]["common_to_all"] = sorted([
        service for service, count in service_counts.items()
        if count == len(clusters)
    ])
    
    # Service frequency
    comparison["service_analysis"]["service_frequency"] = dict(sorted(
        service_counts.items(),
        key=lambda x: x[1],
        reverse=True
    ))
    
    # Unique services per cluster
    for i, cluster in enumerate(clusters):
        cluster_services = set(cluster["services"])
        unique = cluster_services - set(comparison["service_analysis"]["common_to_all"])
        comparison["service_analysis"]["unique_per_cluster"].append({
            "cluster_id": i + 1,
            "use_case": cluster["cluster_metadata"]["use_case"],
            "unique_services": sorted(list(unique))
        })
    
    return comparison


def print_comparison_report(comparison: Dict):
    """Print a formatted comparison report"""
    print("\n" + "="*80)
    print("KUBERNETES CLUSTER COMPARISON REPORT")
    print("="*80)
    
    # Summary
    print("\n📊 SUMMARY")
    print("─" * 80)
    print(f"Total Clusters Analyzed: {comparison['summary']['total_clusters']}")
    print(f"Cluster Sizes: {', '.join(comparison['summary']['cluster_sizes'])}")
    print(f"Use Cases: {', '.join(comparison['summary']['use_cases'])}")
    
    # Statistics
    print("\n📈 STATISTICS")
    print("─" * 80)
    print(f"Average Services per Cluster: {comparison['statistics']['avg_services']:.1f}")
    print(f"Average Resource Utilization: {comparison['statistics']['avg_resource_util']}")
    print(f"Clusters with Full Observability: {comparison['statistics']['observability_coverage']}")
    
    # Common services
    print("\n🔗 COMMON SERVICES (in all clusters)")
    print("─" * 80)
    common = comparison['service_analysis']['common_to_all']
    if common:
        for i in range(0, len(common), 5):
            print("  " + ", ".join(common[i:i+5]))
    else:
        print("  No services common to all clusters")
    
    # Most frequent services
    print("\n⭐ TOP 15 MOST FREQUENT SERVICES")
    print("─" * 80)
    freq = comparison['service_analysis']['service_frequency']
    total_clusters = comparison['summary']['total_clusters']
    for service, count in list(freq.items())[:15]:
        percentage = (count / total_clusters) * 100
        bar = "█" * int(percentage / 5)
        print(f"  {service:30s} {bar:20s} {count}/{total_clusters} ({percentage:.0f}%)")
    
    # Unique services
    print("\n🎯 UNIQUE SERVICES PER CLUSTER")
    print("─" * 80)
    for cluster_info in comparison['service_analysis']['unique_per_cluster']:
        print(f"\nCluster #{cluster_info['cluster_id']} ({cluster_info['use_case']}):")
        unique = cluster_info['unique_services']
        if unique:
            for i in range(0, len(unique), 5):
                print("  " + ", ".join(unique[i:i+5]))
        else:
            print("  (no unique services)")


def main():
    """Main CLI interface"""
    if len(sys.argv) < 3:
        print("Usage: python cluster_comparison.py <cluster1.json> <cluster2.json> [cluster3.json ...]")
        print("\nExample:")
        print("  python cluster_comparison.py startup.json microservices.json data.json")
        sys.exit(1)
    
    # Load all clusters
    clusters = []
    print("\n📂 Loading cluster configurations...")
    for filepath in sys.argv[1:]:
        try:
            cluster = load_cluster(filepath)
            # Handle both single cluster and array of clusters
            if isinstance(cluster, list):
                clusters.extend(cluster)
                print(f"  ✓ Loaded {len(cluster)} clusters from {filepath}")
            else:
                clusters.append(cluster)
                print(f"  ✓ Loaded {filepath}")
        except Exception as e:
            print(f"  ✗ Error loading {filepath}: {e}")
            sys.exit(1)
    
    # Compare
    comparison = compare_clusters(clusters)
    
    # Print report
    print_comparison_report(comparison)
    
    # Optionally save to file
    output_file = "cluster_comparison_report.json"
    with open(output_file, 'w') as f:
        json.dump(comparison, f, indent=2)
    print(f"\n✅ Detailed comparison saved to {output_file}")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
