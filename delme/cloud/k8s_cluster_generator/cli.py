import random
import json
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from enum import Enum
from cyberbattlesim_network_gen.network_generators.cloud.k8s_cluster_generator.k8s_service_catalog import SERVICE_CATALOG
from cyberbattlesim_network_gen.network_generators.cloud.k8s_cluster_generator.usae_case import UseCase
from cyberbattlesim_network_gen.network_generators.cloud.k8s_cluster_generator.cluster_size import ClusterSize
from cyberbattlesim_network_gen.network_generators.cloud.k8s_cluster_generator.service_profile import ServiceProfile
from cyberbattlesim_network_gen.network_generators.cloud.k8s_cluster_generator.cluster_generator import K8sClusterGenerator
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import random
import json

# ======================================================================
# CLI Interface
# ======================================================================

def generate_cluster_cli():
    """Command-line interface for cluster generation"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Generate realistic Kubernetes cluster configurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a 5-node microservices cluster
  python k8s_cluster_generator.py --nodes 5 --use-case microservices
  
  # Generate a 100-node data analytics cluster
  python k8s_cluster_generator.py --nodes 100 --use-case data_analytics
  
  # Generate with specific seed for reproducibility
  python k8s_cluster_generator.py --nodes 20 --use-case saas_platform --seed 42
  
  # Generate multiple clusters
  python k8s_cluster_generator.py --nodes 10 --use-case startup_mvp --count 3
        """
    )
    
    parser.add_argument(
        "--nodes", "-n",
        type=int,
        required=True,
        help="Number of nodes in the cluster"
    )
    
    parser.add_argument(
        "--use-case", "-u",
        type=str,
        required=True,
        choices=[uc.value for uc in UseCase],
        help="Primary use case for the cluster"
    )
    
    parser.add_argument(
        "--seed", "-s",
        type=int,
        default=None,
        help="Random seed for reproducibility"
    )
    
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=1,
        help="Number of clusters to generate"
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output file (JSON format). If not specified, prints to stdout"
    )
    
    parser.add_argument(
        "--generate-topology",
        action="store_true",
        help="Generate network topology graphs for the cluster"
    )
    
    parser.add_argument(
        "--firewall-probability",
        type=float,
        default=0.2,
        help="Probability that a connection is blocked by firewall (0.0-1.0)"
    )
    
    parser.add_argument(
        "--knowledge-completeness",
        type=float,
        default=0.7,
        help="How much of the network the attacker knows (0.0-1.0)"
    )
    
    parser.add_argument(
        "--cve-json",
        type=str,
        help="Path to final.json with CVE lists per service"
    )
    
    parser.add_argument(
        "--vuln-db",
        type=str,
        help="Path to vulnerability_db.yml with CVE details"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output with statistics"
    )
    
    args = parser.parse_args()
    
    use_case = UseCase(args.use_case)
    results = []
    
    for i in range(args.count):
        seed = args.seed + i if args.seed is not None else None
        generator = K8sClusterGenerator(args.nodes, use_case, seed)
        cluster_config = generator.generate()
        
        # Generate network topology if requested
        if args.generate_topology:
            try:
                # Import here to avoid dependency if not needed
                from network_topology_generator import NetworkTopologyGenerator, topology_to_dict
                
                # Initialize vulnerability assigner if paths provided
                vulnerability_assigner = None
                if args.cve_json and args.vuln_db:
                    try:
                        from vulnerability_assigner import VulnerabilityAssigner
                        vulnerability_assigner = VulnerabilityAssigner(
                            args.cve_json,
                            args.vuln_db,
                            seed=seed
                        )
                        if args.verbose:
                            print(f"✓ Loaded vulnerability database")
                    except Exception as e:
                        print(f"⚠️  Warning: Could not load vulnerability data: {e}")
                
                topo_generator = NetworkTopologyGenerator(
                    services=cluster_config["services"],
                    service_instances=cluster_config["service_instances"],
                    seed=seed,
                    vulnerability_assigner=vulnerability_assigner
                )
                
                topology = topo_generator.generate(
                    firewall_probability=args.firewall_probability,
                    knowledge_completeness=args.knowledge_completeness
                )
                
                # Add topology to cluster config
                cluster_config["network_topology"] = topology_to_dict(topology)
                
                if args.verbose and vulnerability_assigner:
                    vuln_stats = topology_to_dict(topology)["metadata"]["vulnerability_stats"]
                    print(f"✓ Assigned vulnerabilities - Total: {vuln_stats['total_vulnerabilities']}, "
                          f"Critical: {vuln_stats['total_critical']}, High: {vuln_stats['total_high']}")
                
            except ImportError:
                print("⚠️  Warning: network_topology_generator.py not found. Skipping topology generation.")
        
        results.append(cluster_config)
        
        if args.verbose:
            print(f"\n{'='*80}")
            print(f"Cluster {i+1}/{args.count}")
            print(f"{'='*80}")
            print(f"Nodes: {cluster_config['cluster_metadata']['num_nodes']}")
            print(f"Size Category: {cluster_config['cluster_metadata']['cluster_size']}")
            print(f"Use Case: {cluster_config['cluster_metadata']['use_case']}")
            print(f"Total Services: {cluster_config['cluster_metadata']['total_services']}")
            print(f"Total Pods: {cluster_config['cluster_metadata']['total_pods']}")
            print(f"Avg Pods/Node: {cluster_config['cluster_metadata']['avg_pods_per_node']}")
            print(f"Resource Utilization: {cluster_config['cluster_metadata']['resource_utilization']}")
            print(f"\nServices by Category:")
            for category, services in cluster_config['services_by_category'].items():
                print(f"  {category}: {len(services)} services")
            print(f"\nTop 10 Services by Instance Count:")
            sorted_instances = sorted(
                cluster_config['service_instances'].items(),
                key=lambda x: x[1],
                reverse=True
            )
            for service, count in sorted_instances[:10]:
                print(f"  {service:30s} {count:3d} instances")
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results if args.count > 1 else results[0], f, indent=2)
        print(f"\n✅ Configuration saved to {args.output}")
    else:
        print(json.dumps(results if args.count > 1 else results[0], indent=2))


if __name__ == "__main__":
    import sys
    
    # Check if CLI arguments provided
    if len(sys.argv) > 1:
        generate_cluster_cli()
    else:
        # Example usage if run directly without arguments
        print("Kubernetes Realistic Cluster Generator")
        print("="*80)
        print("\nExample: Generate a 10-node microservices cluster\n")
        
        generator = K8sClusterGenerator(
            num_nodes=10,
            use_case=UseCase.MICROSERVICES,
            seed=42
        )
        
        cluster = generator.generate()
        
        print(json.dumps(cluster, indent=2))
        print("\n" + "="*80)
        print("Run with --help for CLI options")
