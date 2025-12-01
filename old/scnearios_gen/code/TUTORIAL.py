"""
Practical Tutorial: Real-World Scenarios
=========================================
This tutorial shows how to use the enhanced generator for common real-world scenarios.
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
    UseCase
)


# ============================================================================
# SCENARIO 1: Secure E-Commerce Platform
# ============================================================================

def scenario_ecommerce_secure():
    """
    Requirements:
    - Public-facing web tier (DMZ)
    - Application tier for business logic
    - Isolated database tier
    - Firewall restricts cross-tier access
    - Only web tier is publicly visible
    """
    print("\n" + "="*80)
    print("SCENARIO 1: Secure E-Commerce Platform")
    print("="*80)
    
    config = ClusterDynamicConfig(
        num_nodes=30,
        use_case=UseCase.ECOMMERCE,
        
        subnet_config=SubnetConfig(
            subnet_ranges=[
                (1, 2),   # DMZ - small
                (3, 5),   # Web tier
                (4, 8),   # App tier
                (2, 4),   # Database tier
                (1, 2)    # Management
            ],
            subnet_labels={
                1: "dmz",
                2: "web_tier",
                3: "application_tier",
                4: "database_tier",
                5: "management"
            },
            sensitive_subnet_probabilities={
                1: 0.0,   # DMZ - no sensitive data
                2: 0.1,   # Web tier
                3: 0.4,   # Application tier
                4: 0.9,   # Database - highly sensitive
                5: 0.6    # Management
            }
        ),
        
        # Hub-spoke with database as protected core
        network_topology=NetworkTopologyConfig(
            topology_matrix=[
                [0, 1, 0, 0, 0],  # DMZ -> Web only
                [1, 0, 1, 0, 0],  # Web -> DMZ, App
                [0, 1, 0, 1, 0],  # App -> Web, DB
                [0, 0, 1, 0, 0],  # DB -> App only
                [1, 1, 1, 1, 0],  # Mgmt -> All (for monitoring)
            ]
        ),
        
        service_distribution=ServiceDistributionConfig(
            service_selection_strategy="required",
            required_services=[
                "nginx", "kong", "redis", "postgresql",
                "rabbitmq", "prometheus", "grafana"
            ],
            subnet_service_affinity={
                0: ["nginx"],                    # DMZ
                1: ["nginx", "kong"],           # Web
                2: ["redis", "rabbitmq"],       # App
                3: ["postgresql", "mongodb"],   # Database
                4: ["prometheus", "grafana"]    # Management
            }
        ),
        
        firewall_config=FirewallConfig(
            incoming="_subnets",  # Strict: same subnet only
            incoming_exceptions=["nginx", "kong"],  # Only web servers public
            outgoing="_all",
            default_block_probability=0.1  # Low random blocks for reliability
        ),
        
        osint_config=OsintConfig(
            status="enabled",
            services_strategy="required",
            visible_services=["nginx", "kong"],  # Only web tier visible
            visibility_probability=1.0
        ),
        
        seed=100
    )
    
    generator = EnhancedK8sClusterGenerator(config)
    result = generator.generate()
    
    # Print summary
    print("\nCluster Summary:")
    print(f"  Total Nodes: {result['cluster_metadata']['num_nodes']}")
    print(f"  Total Services: {result['cluster_metadata']['total_services']}")
    print(f"  Total Pods: {result['cluster_metadata']['total_pods']}")
    
    print("\nSecurity Posture:")
    print(f"  Publicly Visible Services: {result['osint']['visible_services']}")
    print(f"  Firewall Policy: {result['firewall']['incoming_policy']}")
    print(f"  Public Exceptions: {result['firewall']['incoming_exceptions']}")
    
    print("\nTier Distribution:")
    for subnet in result['network']['subnets']:
        print(f"  {subnet['label']:20s} - {subnet['num_services']} services, "
              f"Sensitive: {subnet['sensitive_probability']:.0%}")
    
    return result


# ============================================================================
# SCENARIO 2: Data Science Platform
# ============================================================================

def scenario_data_science():
    """
    Requirements:
    - Data ingestion layer
    - Processing/compute cluster
    - Storage tier with object storage
    - Interactive analytics environment
    - Heavy resource requirements
    """
    print("\n" + "="*80)
    print("SCENARIO 2: Data Science Platform")
    print("="*80)
    
    config = ClusterDynamicConfig(
        num_nodes=50,
        use_case=UseCase.ML_PLATFORM,
        
        subnet_config=SubnetConfig(
            subnet_ranges=[
                (2, 3),    # Ingestion
                (8, 12),   # Processing - large
                (4, 6),    # Storage
                (3, 5),    # Analytics
                (1, 2)     # Management
            ],
            subnet_labels={
                1: "data_ingestion",
                2: "processing_cluster",
                3: "storage_tier",
                4: "analytics_interactive",
                5: "management"
            },
            sensitive_subnet_probabilities={
                1: 0.3,  # Ingestion
                2: 0.2,  # Processing
                3: 0.8,  # Storage - contains data
                4: 0.6,  # Analytics - working with sensitive data
                5: 0.4   # Management
            }
        ),
        
        network_topology=NetworkTopologyConfig(
            topology_type="mesh"  # All tiers need to communicate
        ),
        
        service_distribution=ServiceDistributionConfig(
            service_selection_strategy="required",
            required_services=[
                "kafka", "spark", "flink", "minio",
                "jupyterhub", "mlflow", "postgresql",
                "redis", "prometheus", "grafana"
            ],
            subnet_service_affinity={
                0: ["kafka"],                      # Ingestion
                1: ["spark", "flink"],             # Processing
                2: ["minio", "postgresql"],        # Storage
                3: ["jupyterhub", "mlflow"],       # Analytics
                4: ["prometheus", "grafana", "redis"]  # Management
            }
        ),
        
        firewall_config=FirewallConfig(
            incoming="_all",  # Open for collaboration
            outgoing="_all",
            default_block_probability=0.05  # Very low - need reliability
        ),
        
        osint_config=OsintConfig(
            status="enabled",
            services_strategy="required",
            visible_services=["jupyterhub"],  # Only notebook interface
            visibility_probability=0.3
        ),
        
        seed=200
    )
    
    generator = EnhancedK8sClusterGenerator(config)
    result = generator.generate()
    
    # Print summary
    print("\nPlatform Configuration:")
    print(f"  Compute Nodes: {result['cluster_metadata']['num_nodes']}")
    print(f"  Processing Power: {result['network']['subnets'][1]['host_count']} processing nodes")
    print(f"  Storage Nodes: {result['network']['subnets'][2]['host_count']}")
    
    print("\nData Pipeline:")
    for i, stage in enumerate(["Ingestion", "Processing", "Storage", "Analytics"]):
        subnet = result['network']['subnets'][i]
        print(f"  {stage:15s} -> {subnet['services']}")
    
    return result


# ============================================================================
# SCENARIO 3: Multi-Tenant SaaS Platform
# ============================================================================

def scenario_multi_tenant_saas():
    """
    Requirements:
    - Tenant isolation via subnets
    - Shared services layer
    - Each tenant has own compute resources
    - Strict firewall between tenants
    - Monitoring across all tenants
    """
    print("\n" + "="*80)
    print("SCENARIO 3: Multi-Tenant SaaS Platform")
    print("="*80)
    
    config = ClusterDynamicConfig(
        num_nodes=40,
        use_case=UseCase.SAAS_PLATFORM,
        
        subnet_config=SubnetConfig(
            subnet_ranges=[
                (2, 3),    # Shared services
                (3, 6),    # Tenant 1
                (3, 6),    # Tenant 2
                (3, 6),    # Tenant 3
                (2, 4),    # Shared database
                (1, 2)     # Management
            ],
            subnet_labels={
                1: "shared_services",
                2: "tenant_1",
                3: "tenant_2",
                4: "tenant_3",
                5: "shared_database",
                6: "management"
            },
            sensitive_subnet_probabilities={
                1: 0.2,  # Shared services
                2: 0.7,  # Tenant 1
                3: 0.7,  # Tenant 2
                4: 0.7,  # Tenant 3
                5: 0.9,  # Database
                6: 0.5   # Management
            }
        ),
        
        # Star topology: shared services as hub, tenants isolated
        network_topology=NetworkTopologyConfig(
            topology_matrix=[
                [0, 1, 1, 1, 1, 1],  # Shared -> All
                [1, 0, 0, 0, 1, 0],  # Tenant1 -> Shared, DB
                [1, 0, 0, 0, 1, 0],  # Tenant2 -> Shared, DB
                [1, 0, 0, 0, 1, 0],  # Tenant3 -> Shared, DB
                [1, 1, 1, 1, 0, 1],  # DB -> All except itself
                [1, 1, 1, 1, 1, 0],  # Mgmt -> All
            ]
        ),
        
        service_distribution=ServiceDistributionConfig(
            service_selection_strategy="required",
            required_services=[
                "nginx", "kong", "postgresql", "redis",
                "keycloak", "prometheus", "grafana"
            ],
            subnet_service_affinity={
                0: ["nginx", "kong", "keycloak"],  # Shared
                1: ["redis"],                       # Tenant 1
                2: ["redis"],                       # Tenant 2
                3: ["redis"],                       # Tenant 3
                4: ["postgresql"],                  # Database
                5: ["prometheus", "grafana"]        # Management
            }
        ),
        
        firewall_config=FirewallConfig(
            incoming="_subnets",  # Strict tenant isolation
            incoming_exceptions=["nginx", "kong", "keycloak"],  # Shared services
            outgoing="_subnets",  # Tenants can't talk to each other
            outgoing_exceptions=["postgresql"],  # Can access shared DB
            default_block_probability=0.2  # Moderate security
        ),
        
        osint_config=OsintConfig(
            status="enabled",
            services_strategy="required",
            visible_services=["nginx", "kong"],
            visibility_probability=0.5
        ),
        
        seed=300
    )
    
    generator = EnhancedK8sClusterGenerator(config)
    result = generator.generate()
    
    # Print summary
    print("\nTenant Isolation:")
    tenant_subnets = [s for s in result['network']['subnets'] if 'tenant' in s['label']]
    for subnet in tenant_subnets:
        print(f"  {subnet['label']:15s} - {subnet['host_count']} nodes, "
              f"{subnet['num_services']} services")
    
    print("\nShared Resources:")
    shared = result['network']['subnets'][0]
    db = result['network']['subnets'][4]
    print(f"  Shared Services: {shared['services']}")
    print(f"  Shared Database: {db['services']}")
    
    print("\nSecurity:")
    print(f"  Cross-tenant blocking: {result['firewall']['incoming_policy']}")
    print(f"  Shared service access: {result['firewall']['incoming_exceptions']}")
    
    return result


# ============================================================================
# SCENARIO 4: IoT Platform with Edge Computing
# ============================================================================

def scenario_iot_edge():
    """
    Requirements:
    - Edge ingestion layer (many small nodes)
    - Message queue for device data
    - Processing and analytics
    - Time-series database
    - Highly available messaging
    """
    print("\n" + "="*80)
    print("SCENARIO 4: IoT Platform with Edge Computing")
    print("="*80)
    
    config = ClusterDynamicConfig(
        num_nodes=60,
        use_case=UseCase.IOT_PLATFORM,
        
        subnet_config=SubnetConfig(
            subnet_ranges=[
                (8, 15),   # Edge - many small nodes
                (3, 5),    # Message queue
                (5, 8),    # Processing
                (4, 6),    # Time-series storage
                (2, 3),    # Analytics
                (1, 2)     # Management
            ],
            subnet_labels={
                1: "edge_devices",
                2: "message_queue",
                3: "stream_processing",
                4: "time_series_db",
                5: "analytics",
                6: "management"
            },
            sensitive_subnet_probabilities={
                1: 0.2,  # Edge
                2: 0.4,  # Queue
                3: 0.3,  # Processing
                4: 0.8,  # Time-series DB
                5: 0.6,  # Analytics
                6: 0.4   # Management
            }
        ),
        
        # Pipeline topology: Edge -> Queue -> Processing -> Storage -> Analytics
        network_topology=NetworkTopologyConfig(
            topology_matrix=[
                [0, 1, 0, 0, 0, 1],  # Edge -> Queue, Mgmt
                [1, 0, 1, 0, 0, 1],  # Queue -> Edge, Processing, Mgmt
                [0, 1, 0, 1, 0, 1],  # Processing -> Queue, Storage, Mgmt
                [0, 0, 1, 0, 1, 1],  # Storage -> Processing, Analytics, Mgmt
                [0, 0, 0, 1, 0, 1],  # Analytics -> Storage, Mgmt
                [1, 1, 1, 1, 1, 0],  # Mgmt -> All
            ]
        ),
        
        service_distribution=ServiceDistributionConfig(
            service_selection_strategy="required",
            required_services=[
                "nginx", "kafka", "zookeeper", "flink",
                "clickhouse", "grafana", "prometheus", "redis"
            ],
            subnet_service_affinity={
                0: ["nginx"],                        # Edge
                1: ["kafka", "zookeeper"],          # Queue
                2: ["flink", "redis"],              # Processing
                3: ["clickhouse"],                   # Time-series
                4: ["grafana"],                      # Analytics
                5: ["prometheus"]                    # Management
            }
        ),
        
        firewall_config=FirewallConfig(
            incoming="_subnets",
            incoming_exceptions=["nginx", "kafka"],  # Edge and queue ingress
            outgoing="_all",
            default_block_probability=0.15
        ),
        
        seed=400
    )
    
    generator = EnhancedK8sClusterGenerator(config)
    result = generator.generate()
    
    # Print summary
    print("\nPlatform Scale:")
    print(f"  Total Nodes: {result['cluster_metadata']['num_nodes']}")
    print(f"  Edge Nodes: {result['network']['subnets'][0]['host_count']}")
    print(f"  Message Throughput Nodes: {result['network']['subnets'][1]['host_count']}")
    
    print("\nData Pipeline:")
    pipeline_stages = ["Edge", "Queue", "Processing", "Storage", "Analytics"]
    for i, stage in enumerate(pipeline_stages):
        subnet = result['network']['subnets'][i]
        print(f"  {stage:15s} -> {subnet['services']}")
    
    return result


# ============================================================================
# SCENARIO 5: Gaming Backend with Global Distribution
# ============================================================================

def scenario_gaming_backend():
    """
    Requirements:
    - Player-facing API gateway
    - Game state management (Redis)
    - Matchmaking service
    - Leaderboards and analytics
    - Real-time messaging
    """
    print("\n" + "="*80)
    print("SCENARIO 5: Gaming Backend")
    print("="*80)
    
    config = ClusterDynamicConfig(
        num_nodes=35,
        use_case=UseCase.GAMING_BACKEND,
        
        subnet_config=SubnetConfig(
            subnet_ranges=[
                (2, 4),    # API Gateway
                (4, 8),    # Game servers
                (3, 5),    # State management
                (2, 4),    # Matchmaking
                (3, 5),    # Analytics
                (1, 2)     # Management
            ],
            subnet_labels={
                1: "api_gateway",
                2: "game_servers",
                3: "state_management",
                4: "matchmaking",
                5: "analytics",
                6: "management"
            },
            sensitive_subnet_probabilities={
                1: 0.1,  # API
                2: 0.4,  # Game servers
                3: 0.7,  # State - player data
                4: 0.3,  # Matchmaking
                5: 0.6,  # Analytics
                6: 0.5   # Management
            }
        ),
        
        network_topology=NetworkTopologyConfig(
            topology_type="mesh"  # Low latency requirements
        ),
        
        service_distribution=ServiceDistributionConfig(
            service_selection_strategy="required",
            required_services=[
                "nginx", "kong", "redis", "mongodb",
                "rabbitmq", "prometheus", "grafana", "clickhouse"
            ],
            subnet_service_affinity={
                0: ["nginx", "kong"],                   # API
                1: ["nginx", "rabbitmq"],              # Game servers
                2: ["redis", "mongodb"],               # State
                3: ["redis"],                          # Matchmaking
                4: ["clickhouse", "grafana"],          # Analytics
                5: ["prometheus"]                       # Management
            }
        ),
        
        firewall_config=FirewallConfig(
            incoming="_all",  # Need fast communication
            incoming_exceptions=[],
            outgoing="_all",
            default_block_probability=0.05  # Very low for performance
        ),
        
        seed=500
    )
    
    generator = EnhancedK8sClusterGenerator(config)
    result = generator.generate()
    
    # Print summary
    print("\nGaming Infrastructure:")
    print(f"  Total Capacity: {result['cluster_metadata']['total_pods']} pods")
    print(f"  Game Servers: {result['network']['subnets'][1]['host_count']} nodes")
    
    print("\nService Distribution:")
    for subnet in result['network']['subnets']:
        print(f"  {subnet['label']:20s} - {', '.join(subnet['services'])}")
    
    return result


# ============================================================================
# RUN ALL SCENARIOS
# ============================================================================

def run_all_scenarios():
    """Run all scenarios and save results"""
    scenarios = {
        'ecommerce_secure': scenario_ecommerce_secure(),
        'data_science_platform': scenario_data_science(),
        'multi_tenant_saas': scenario_multi_tenant_saas(),
        'iot_edge_computing': scenario_iot_edge(),
        'gaming_backend': scenario_gaming_backend()
    }
    
    # Save all results
    with open('/mnt/user-data/outputs/real_world_scenarios.json', 'w') as f:
        json.dump(scenarios, f, indent=2)
    
    print("\n" + "="*80)
    print("✅ All scenarios completed and saved to real_world_scenarios.json")
    print("="*80)
    
    return scenarios


if __name__ == "__main__":
    print("="*80)
    print("PRACTICAL TUTORIAL: REAL-WORLD SCENARIOS")
    print("="*80)
    print("\nThis tutorial demonstrates 5 common real-world scenarios:")
    print("  1. Secure E-Commerce Platform")
    print("  2. Data Science Platform")
    print("  3. Multi-Tenant SaaS Platform")
    print("  4. IoT Platform with Edge Computing")
    print("  5. Gaming Backend")
    print("\nEach scenario shows different configuration patterns and trade-offs.")
    print("="*80)
    
    run_all_scenarios()
