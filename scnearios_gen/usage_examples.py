#!/usr/bin/env python3
"""
Usage Examples for Enhanced K8s Cluster Generator
==================================================
Demonstrates various ways to use dynamic configurations
"""

import json
from k8s_cluster_generator_enhanced import (
    ClusterDynamicConfig,
    SubnetConfig,
    NetworkTopologyConfig,
    ServiceDistributionConfig,
    FirewallConfig,
    OsintConfig,
    EnhancedK8sClusterGenerator,
    UseCase,
    ConfigLoader
)


def example_1_programmatic_config():
    """Example 1: Create configuration programmatically"""
    print("="*80)
    print("Example 1: Programmatic Configuration")
    print("="*80)
    
    config = ClusterDynamicConfig(
        num_nodes=20,
        use_case=UseCase.MICROSERVICES,
        
        subnet_config=SubnetConfig(
            subnet_ranges=[1, (2, 4), (2, 5), (1, 3)],  # Mix of fixed and range
            address_space_bounds=(10, 10),
            subnet_labels={
                1: "dmz",
                2: "frontend",
                3: "backend",
                4: "database"
            },
            sensitive_subnet_probabilities={
                3: 0.5,  # Backend
                4: 0.9   # Database - very sensitive
            }
        ),
        
        network_topology=NetworkTopologyConfig(
            topology_type="hub_spoke"  # DMZ as hub
        ),
        
        service_distribution=ServiceDistributionConfig(
            service_selection_strategy="graph_theory_random",
            required_services=["nginx", "postgresql", "redis"],
            excluded_services=["wordpress"]
        ),
        
        firewall_config=FirewallConfig(
            incoming="_subnets",  # Default: only same subnet
            incoming_exceptions=["nginx"],  # Nginx can accept from anywhere
            outgoing="_all"
        ),
        
        seed=12345
    )
    
    generator = EnhancedK8sClusterGenerator(config)
    result = generator.generate()
    
    print(f"\nGenerated cluster:")
    print(f"  - {result['cluster_metadata']['num_nodes']} nodes")
    print(f"  - {result['cluster_metadata']['num_subnets']} subnets")
    print(f"  - {result['cluster_metadata']['total_services']} services")
    print(f"  - {result['cluster_metadata']['total_pods']} total pods")
    
    print(f"\nSubnets:")
    for subnet in result['network']['subnets']:
        print(f"  {subnet['id']}: {subnet['label']:15s} - "
              f"{subnet['host_count']} hosts, {subnet['num_services']} services")
    
    return result


def example_2_yaml_config():
    """Example 2: Load configuration from YAML"""
    print("\n" + "="*80)
    print("Example 2: YAML Configuration")
    print("="*80)
    
    # This would load from a YAML file
    # config = ConfigLoader.load_from_yaml("example_cluster_config.yaml")
    
    # For demonstration, we'll create one similar to the YAML
    config = ClusterDynamicConfig(
        num_nodes=15,
        use_case=UseCase.MICROSERVICES,
        subnet_config=SubnetConfig(
            subnet_ranges=[1, (1,4), (1,4), (1,6), (2,9), (1,4), (1,4), (1,4)],
            address_space_bounds=(10, 10),
            subnet_labels={
                1: "public_dmz",
                2: "web_tier",
                3: "application_tier",
                4: "data_tier",
                5: "cache_tier",
                6: "messaging_tier",
                7: "analytics_tier",
                8: "management"
            },
            sensitive_subnet_probabilities={
                1: 0.0,
                2: 0.1,
                3: 0.3,
                4: 0.8,
                5: 0.2,
                6: 0.3,
                7: 0.5,
                8: 0.6
            }
        ),
        network_topology=NetworkTopologyConfig(
            topology_type="hub_spoke"
        ),
        seed=42
    )
    
    generator = EnhancedK8sClusterGenerator(config)
    result = generator.generate()
    
    print(f"\nLoaded YAML-style configuration:")
    print(f"  - Topology: {config.network_topology.topology_type}")
    print(f"  - {len(config.subnet_config.subnet_ranges)} subnets defined")
    print(f"  - Firewall: {config.firewall_config.incoming} incoming")
    
    return result


def example_3_custom_topology_matrix():
    """Example 3: Custom topology matrix"""
    print("\n" + "="*80)
    print("Example 3: Custom Topology Matrix")
    print("="*80)
    
    # Define exact topology
    custom_topology = [
        [0, 1, 1, 0, 0],  # Subnet 0 connects to 1, 2
        [1, 0, 1, 1, 0],  # Subnet 1 connects to 0, 2, 3
        [1, 1, 0, 1, 1],  # Subnet 2 is the hub - connects to all
        [0, 1, 1, 0, 0],  # Subnet 3 connects to 1, 2
        [0, 0, 1, 0, 0],  # Subnet 4 only connects to hub (2)
    ]
    
    config = ClusterDynamicConfig(
        num_nodes=25,
        use_case=UseCase.DATA_ANALYTICS,
        subnet_config=SubnetConfig(
            subnet_ranges=[3, 5, 2, 4, 6],  # Fixed host counts
            address_space_bounds=(10, 10),
            subnet_labels={
                1: "edge_nodes",
                2: "processing_cluster",
                3: "core_hub",
                4: "storage_tier",
                5: "analytics_compute"
            }
        ),
        network_topology=NetworkTopologyConfig(
            topology_matrix=custom_topology
        ),
        seed=99
    )
    
    generator = EnhancedK8sClusterGenerator(config)
    result = generator.generate()
    
    print(f"\nCustom topology matrix:")
    for i, row in enumerate(result['network']['topology_matrix']):
        print(f"  Subnet {i}: {row}")
    
    return result


def example_4_service_affinity():
    """Example 4: Service-subnet affinity"""
    print("\n" + "="*80)
    print("Example 4: Service-Subnet Affinity")
    print("="*80)
    
    config = ClusterDynamicConfig(
        num_nodes=30,
        use_case=UseCase.ECOMMERCE,
        subnet_config=SubnetConfig(
            subnet_ranges=[(2, 4), (3, 6), (2, 5), (1, 3)],
            address_space_bounds=(10, 10),
            subnet_labels={
                1: "frontend",
                2: "api_gateway",
                3: "backend_services",
                4: "databases"
            }
        ),
        service_distribution=ServiceDistributionConfig(
            service_selection_strategy="graph_theory_random",
            required_services=["nginx", "postgresql", "redis", "kafka"],
            subnet_service_affinity={
                0: ["nginx"],              # Frontend: nginx
                1: ["kong", "nginx"],      # API Gateway: kong, nginx
                2: ["redis", "rabbitmq"],  # Backend: caching and messaging
                3: ["postgresql", "mongodb", "elasticsearch"]  # Databases
            }
        ),
        seed=777
    )
    
    generator = EnhancedK8sClusterGenerator(config)
    result = generator.generate()
    
    print(f"\nService distribution by subnet:")
    for service, details in result['service_distribution'].items():
        subnet_names = [
            result['network']['subnets'][sid]['label'] 
            for sid in details['subnets']
        ]
        print(f"  {service:20s} -> {subnet_names} ({details['instances']} instances)")
    
    return result


def example_5_firewall_rules():
    """Example 5: Complex firewall configuration"""
    print("\n" + "="*80)
    print("Example 5: Complex Firewall Rules")
    print("="*80)
    
    config = ClusterDynamicConfig(
        num_nodes=40,
        use_case=UseCase.ENTERPRISE_INTERNAL,
        subnet_config=SubnetConfig(
            subnet_ranges=[(1, 2), (3, 5), (2, 4), (1, 3), (2, 3)],
            address_space_bounds=(10, 10),
            subnet_labels={
                1: "dmz",
                2: "web_servers",
                3: "app_servers",
                4: "databases",
                5: "management"
            }
        ),
        firewall_config=FirewallConfig(
            incoming="_subnets",  # Default: block cross-subnet
            incoming_exceptions=[
                "nginx",        # Public web server
                "grafana",      # Monitoring UI
                "prometheus"    # Metrics collection
            ],
            outgoing="_all",
            outgoing_exceptions=[],
            default_block_probability=0.3  # 30% random blocks
        ),
        seed=555
    )
    
    generator = EnhancedK8sClusterGenerator(config)
    result = generator.generate()
    
    print(f"\nFirewall configuration:")
    print(f"  Incoming policy: {result['firewall']['incoming_policy']}")
    print(f"  Incoming exceptions: {result['firewall']['incoming_exceptions']}")
    print(f"  Outgoing policy: {result['firewall']['outgoing_policy']}")
    print(f"  Random block rate: {result['firewall']['default_block_probability']}")
    
    return result


def example_6_multiple_scenarios():
    """Example 6: Generate multiple scenarios with variations"""
    print("\n" + "="*80)
    print("Example 6: Multiple Scenario Generation")
    print("="*80)
    
    scenarios = []
    
    for i in range(3):
        config = ClusterDynamicConfig(
            num_nodes=15 + i * 5,  # 15, 20, 25 nodes
            use_case=UseCase.MICROSERVICES,
            subnet_config=SubnetConfig(
                subnet_ranges=[(1, 4)] * 4,  # Random subnets each time
                address_space_bounds=(10, 10)
            ),
            network_topology=NetworkTopologyConfig(
                topology_type=["mesh", "star", "hub_spoke"][i]
            ),
            seed=100 + i  # Different seed for each
        )
        
        generator = EnhancedK8sClusterGenerator(config)
        result = generator.generate()
        scenarios.append(result)
        
        print(f"\nScenario {i+1}:")
        print(f"  - Nodes: {result['cluster_metadata']['num_nodes']}")
        print(f"  - Topology: {result['configuration']['topology_type']}")
        print(f"  - Services: {result['cluster_metadata']['total_services']}")
        print(f"  - Pods: {result['cluster_metadata']['total_pods']}")
    
    return scenarios


def example_7_comparison_table():
    """Example 7: Generate comparison table of different topologies"""
    print("\n" + "="*80)
    print("Example 7: Topology Comparison")
    print("="*80)
    
    topologies = ["mesh", "star", "hub_spoke", "random"]
    results_table = []
    
    for topo in topologies:
        config = ClusterDynamicConfig(
            num_nodes=20,
            use_case=UseCase.MICROSERVICES,
            subnet_config=SubnetConfig(
                subnet_ranges=[2, 3, 4, 3],
                address_space_bounds=(10, 10)
            ),
            network_topology=NetworkTopologyConfig(
                topology_type=topo,
                connectivity_probability=0.3  # For random
            ),
            seed=42  # Same seed for fair comparison
        )
        
        generator = EnhancedK8sClusterGenerator(config)
        result = generator.generate()
        
        # Calculate connectivity metrics
        matrix = result['network']['topology_matrix']
        total_connections = sum(sum(row) for row in matrix)
        
        results_table.append({
            'topology': topo,
            'services': result['cluster_metadata']['total_services'],
            'pods': result['cluster_metadata']['total_pods'],
            'connections': total_connections,
            'avg_degree': total_connections / len(matrix) if matrix else 0
        })
    
    # Print comparison table
    print(f"\n{'Topology':<15} {'Services':<10} {'Pods':<10} {'Connections':<12} {'Avg Degree':<10}")
    print("-" * 70)
    for row in results_table:
        print(f"{row['topology']:<15} {row['services']:<10} {row['pods']:<10} "
              f"{row['connections']:<12} {row['avg_degree']:<10.2f}")
    
    return results_table


def main():
    """Run all examples"""
    print("\n" + "="*80)
    print("ENHANCED K8S CLUSTER GENERATOR - USAGE EXAMPLES")
    print("="*80)
    
    # Run examples
    result1 = example_1_programmatic_config()
    result2 = example_2_yaml_config()
    result3 = example_3_custom_topology_matrix()
    result4 = example_4_service_affinity()
    result5 = example_5_firewall_rules()
    scenarios = example_6_multiple_scenarios()
    comparison = example_7_comparison_table()
    
    # Save all results
    all_results = {
        'example_1_programmatic': result1,
        'example_2_yaml': result2,
        'example_3_custom_topology': result3,
        'example_4_service_affinity': result4,
        'example_5_firewall': result5,
        'example_6_scenarios': scenarios,
        'example_7_comparison': comparison
    }
    
    with open('/mnt/user-data/outputs/cluster_examples_output.json', 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print("\n" + "="*80)
    print("✅ All examples completed!")
    print("Results saved to: cluster_examples_output.json")
    print("="*80)


if __name__ == "__main__":
    main()
