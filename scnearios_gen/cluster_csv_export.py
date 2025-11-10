#!/usr/bin/env python3
"""
Cluster CSV Exporter
====================
Export Kubernetes cluster configurations to CSV format for spreadsheet analysis.
"""

import json
import csv
import sys
from typing import List, Dict


def load_cluster(filepath: str) -> List[Dict]:
    """Load cluster(s) from JSON file"""
    with open(filepath, 'r') as f:
        data = json.load(f)
        # Handle both single cluster and array of clusters
        return data if isinstance(data, list) else [data]


def export_to_csv(clusters: List[Dict], output_file: str):
    """Export cluster configurations to CSV"""
    
    # Prepare rows
    rows = []
    for i, cluster in enumerate(clusters):
        meta = cluster["cluster_metadata"]
        stats = cluster.get("deployment_stats", {})
        obs = stats.get("observability_stack", {})
        auto = stats.get("automation", {})
        data = stats.get("data_layer", {})
        
        row = {
            "cluster_id": i + 1,
            "num_nodes": meta["num_nodes"],
            "cluster_size": meta["cluster_size"],
            "use_case": meta["use_case"],
            "total_services": meta["total_services"],
            "total_pods": meta.get("total_pods", "N/A"),
            "avg_pods_per_node": meta.get("avg_pods_per_node", "N/A"),
            "resource_utilization": meta["resource_utilization"],
            "has_metrics": obs.get("metrics", False),
            "has_logging": obs.get("logging", False),
            "has_tracing": obs.get("tracing", False),
            "observability_score": f"{obs.get('completeness_score', 0):.2f}",
            "gitops_enabled": auto.get("gitops_enabled", False),
            "service_mesh": auto.get("service_mesh", False),
            "sql_databases": data.get("sql_databases", 0),
            "nosql_databases": data.get("nosql_databases", 0),
            "has_caching": data.get("caching", False),
            "has_messaging": data.get("messaging", False),
            "services": "; ".join(sorted(cluster["services"]))
        }
        rows.append(row)
    
    # Write CSV
    if rows:
        fieldnames = rows[0].keys()
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)


def export_services_matrix(clusters: List[Dict], output_file: str):
    """Export service presence matrix (cluster x service)"""
    
    # Collect all unique services
    all_services = set()
    for cluster in clusters:
        all_services.update(cluster["services"])
    all_services = sorted(all_services)
    
    # Create matrix
    rows = []
    for i, cluster in enumerate(clusters):
        row = {
            "cluster_id": i + 1,
            "use_case": cluster["cluster_metadata"]["use_case"],
            "num_nodes": cluster["cluster_metadata"]["num_nodes"]
        }
        cluster_services = set(cluster["services"])
        for service in all_services:
            row[service] = "✓" if service in cluster_services else ""
        rows.append(row)
    
    # Write CSV
    if rows:
        fieldnames = ["cluster_id", "use_case", "num_nodes"] + all_services
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)


def export_instance_counts(clusters: List[Dict], output_file: str):
    """Export service instance counts (cluster x service with counts)"""
    
    # Collect all unique services
    all_services = set()
    for cluster in clusters:
        if "service_instances" in cluster:
            all_services.update(cluster["service_instances"].keys())
        else:
            all_services.update(cluster["services"])
    all_services = sorted(all_services)
    
    # Create matrix
    rows = []
    for i, cluster in enumerate(clusters):
        row = {
            "cluster_id": i + 1,
            "use_case": cluster["cluster_metadata"]["use_case"],
            "num_nodes": cluster["cluster_metadata"]["num_nodes"],
            "total_pods": cluster["cluster_metadata"].get("total_pods", "N/A")
        }
        
        # Get instance counts if available
        if "service_instances" in cluster:
            for service in all_services:
                row[service] = cluster["service_instances"].get(service, "")
        else:
            # Fallback to presence indicator
            cluster_services = set(cluster["services"])
            for service in all_services:
                row[service] = "1" if service in cluster_services else ""
        
        rows.append(row)
    
    # Write CSV
    if rows:
        fieldnames = ["cluster_id", "use_case", "num_nodes", "total_pods"] + all_services
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)


def export_category_summary(clusters: List[Dict], output_file: str):
    """Export service count by category"""
    
    # Collect all categories
    all_categories = set()
    for cluster in clusters:
        all_categories.update(cluster["services_by_category"].keys())
    all_categories = sorted(all_categories)
    
    rows = []
    for i, cluster in enumerate(clusters):
        row = {
            "cluster_id": i + 1,
            "use_case": cluster["cluster_metadata"]["use_case"],
            "num_nodes": cluster["cluster_metadata"]["num_nodes"],
            "total_services": cluster["cluster_metadata"]["total_services"]
        }
        
        # Add category counts
        for category in all_categories:
            services = cluster["services_by_category"].get(category, [])
            row[category] = len(services)
        
        rows.append(row)
    
    # Write CSV
    if rows:
        fieldnames = ["cluster_id", "use_case", "num_nodes", "total_services"] + all_categories
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)


def main():
    """Main CLI interface"""
    if len(sys.argv) < 2:
        print("Usage: python cluster_csv_export.py <cluster.json> [cluster2.json ...]")
        print("\nExports four CSV files:")
        print("  1. clusters_summary.csv           - High-level cluster information")
        print("  2. clusters_services_matrix.csv   - Service presence matrix")
        print("  3. clusters_instance_counts.csv   - Instance counts per service")
        print("  4. clusters_categories.csv        - Service counts by category")
        print("\nExample:")
        print("  python cluster_csv_export.py startup.json microservices.json")
        sys.exit(1)
    
    # Load all clusters
    all_clusters = []
    print("\n📂 Loading cluster configurations...")
    for filepath in sys.argv[1:]:
        try:
            clusters = load_cluster(filepath)
            all_clusters.extend(clusters)
            print(f"  ✓ Loaded {len(clusters)} cluster(s) from {filepath}")
        except Exception as e:
            print(f"  ✗ Error loading {filepath}: {e}")
            sys.exit(1)
    
    print(f"\n📊 Total clusters to export: {len(all_clusters)}")
    
    # Export to different formats
    print("\n📝 Exporting to CSV...")
    
    # Summary
    export_to_csv(all_clusters, "clusters_summary.csv")
    print("  ✓ Created clusters_summary.csv")
    
    # Service matrix
    export_services_matrix(all_clusters, "clusters_services_matrix.csv")
    print("  ✓ Created clusters_services_matrix.csv")
    
    # Instance counts
    export_instance_counts(all_clusters, "clusters_instance_counts.csv")
    print("  ✓ Created clusters_instance_counts.csv")
    
    # Category summary
    export_category_summary(all_clusters, "clusters_categories.csv")
    print("  ✓ Created clusters_categories.csv")
    
    print("\n✅ Export complete!")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
