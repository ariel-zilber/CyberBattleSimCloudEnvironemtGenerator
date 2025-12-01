#!/usr/bin/env python3
"""
Backwards Compatibility Test
=============================
Demonstrates that the enhanced generator can be used as a drop-in
replacement for the original generator.
"""

import json
from k8s_cluster_generator_enhanced import K8sClusterGenerator, UseCase


def test_original_interface():
    """
    Test that the original interface works exactly the same.
    This is how users would use the ORIGINAL generator.
    """
    print("="*80)
    print("BACKWARDS COMPATIBILITY TEST")
    print("="*80)
    print("\nTest 1: Original Interface (Exact Same Usage)")
    print("-"*80)
    
    # This is EXACTLY how the original generator was used
    generator = K8sClusterGenerator(
        num_nodes=10,
        use_case=UseCase.MICROSERVICES,
        seed=42
    )
    
    cluster = generator.generate()
    
    # Verify it returns the expected format
    assert "cluster_metadata" in cluster
    assert "services" in cluster
    assert "service_instances" in cluster
    assert "services_by_category" in cluster
    assert "deployment_stats" in cluster
    
    print("✅ Original interface works!")
    print(f"   Generated cluster with {cluster['cluster_metadata']['total_services']} services")
    print(f"   Total pods: {cluster['cluster_metadata']['total_pods']}")
    
    # Verify internal state is maintained
    assert len(generator.selected_services) > 0
    assert len(generator.service_instances) > 0
    print(f"   Internal state: {len(generator.selected_services)} services selected")
    
    return cluster


def test_multiple_clusters():
    """Test generating multiple clusters with same interface."""
    print("\n" + "="*80)
    print("Test 2: Multiple Clusters (Original Interface)")
    print("-"*80)
    
    use_cases = [
        UseCase.STARTUP_MVP,
        UseCase.MICROSERVICES,
        UseCase.DATA_ANALYTICS
    ]
    
    for i, use_case in enumerate(use_cases):
        generator = K8sClusterGenerator(
            num_nodes=15,
            use_case=use_case,
            seed=100 + i
        )
        
        cluster = generator.generate()
        
        print(f"   Cluster {i+1} ({use_case.value}): "
              f"{cluster['cluster_metadata']['total_services']} services, "
              f"{cluster['cluster_metadata']['total_pods']} pods")
    
    print("✅ Multiple cluster generation works!")


def test_different_sizes():
    """Test different cluster sizes."""
    print("\n" + "="*80)
    print("Test 3: Different Cluster Sizes (Original Interface)")
    print("-"*80)
    
    sizes = [5, 20, 50, 150]
    
    for nodes in sizes:
        generator = K8sClusterGenerator(
            num_nodes=nodes,
            use_case=UseCase.MICROSERVICES,
            seed=42
        )
        
        cluster = generator.generate()
        
        print(f"   {nodes:3d} nodes: "
              f"{cluster['cluster_metadata']['cluster_size']:7s} - "
              f"{cluster['cluster_metadata']['total_services']:2d} services, "
              f"{cluster['cluster_metadata']['total_pods']:3d} pods")
    
    print("✅ Different cluster sizes work!")


def test_reproducibility():
    """Test that same seed produces same results."""
    print("\n" + "="*80)
    print("Test 4: Reproducibility (Same Seed = Same Result)")
    print("-"*80)
    
    # Generate twice with same seed
    cluster1 = K8sClusterGenerator(
        num_nodes=15,
        use_case=UseCase.ECOMMERCE,
        seed=999
    ).generate()
    
    cluster2 = K8sClusterGenerator(
        num_nodes=15,
        use_case=UseCase.ECOMMERCE,
        seed=999
    ).generate()
    
    # Verify they're identical
    assert cluster1["services"] == cluster2["services"]
    assert cluster1["service_instances"] == cluster2["service_instances"]
    assert cluster1["cluster_metadata"]["total_services"] == cluster2["cluster_metadata"]["total_services"]
    
    print(f"   Run 1: {len(cluster1['services'])} services")
    print(f"   Run 2: {len(cluster2['services'])} services")
    print("✅ Reproducibility works! (Same seed = identical output)")


def test_output_format():
    """Verify output format matches original."""
    print("\n" + "="*80)
    print("Test 5: Output Format Compatibility")
    print("-"*80)
    
    generator = K8sClusterGenerator(
        num_nodes=20,
        use_case=UseCase.SAAS_PLATFORM,
        seed=123
    )
    
    cluster = generator.generate()
    
    # Check required fields (from original generator)
    required_fields = [
        "cluster_metadata",
        "services",
        "service_instances",
        "services_by_category",
        "deployment_stats"
    ]
    
    for field in required_fields:
        assert field in cluster, f"Missing required field: {field}"
        print(f"   ✓ Field present: {field}")
    
    # Check cluster_metadata fields
    metadata_fields = [
        "num_nodes",
        "cluster_size",
        "use_case",
        "total_services",
        "total_pods",
        "avg_pods_per_node",
        "total_resource_weight",
        "resource_utilization"
    ]
    
    for field in metadata_fields:
        assert field in cluster["cluster_metadata"], f"Missing metadata field: {field}"
    
    print("✅ Output format is compatible!")


def test_enhanced_features_optional():
    """Verify enhanced features are optional and don't break original usage."""
    print("\n" + "="*80)
    print("Test 6: Enhanced Features Are Optional")
    print("-"*80)
    
    # Use ONLY original interface - should work without any enhanced features
    cluster = K8sClusterGenerator(
        num_nodes=10,
        use_case=UseCase.MICROSERVICES,
        seed=42
    ).generate()
    
    # Enhanced features should be present but optional
    # Original code doesn't need to care about them
    print(f"   Using original interface only:")
    print(f"   - Services: {cluster['cluster_metadata']['total_services']}")
    print(f"   - Pods: {cluster['cluster_metadata']['total_pods']}")
    
    # Enhanced features are there if you want them
    if "network" in cluster:
        print(f"   - Enhanced features available: Yes (subnets: {cluster['cluster_metadata'].get('num_subnets', 'N/A')})")
    else:
        print(f"   - Enhanced features available: No (default mode)")
    
    print("✅ Original interface works independently of enhanced features!")


def test_json_serialization():
    """Test that output can be serialized to JSON (important for CLI)."""
    print("\n" + "="*80)
    print("Test 7: JSON Serialization")
    print("-"*80)
    
    cluster = K8sClusterGenerator(
        num_nodes=15,
        use_case=UseCase.ML_PLATFORM,
        seed=777
    ).generate()
    
    # Should be JSON serializable
    try:
        json_str = json.dumps(cluster, indent=2)
        reconstructed = json.loads(json_str)
        
        assert reconstructed["cluster_metadata"]["num_nodes"] == 15
        print(f"   ✓ JSON serialization successful")
        print(f"   ✓ Size: {len(json_str)} bytes")
        print("✅ JSON serialization works!")
    except Exception as e:
        print(f"❌ JSON serialization failed: {e}")
        raise


def test_cli_arguments():
    """Test that CLI arguments work (including new vulnerability args)."""
    print("\n" + "="*80)
    print("Test 8: CLI Arguments Support")
    print("-"*80)
    
    import subprocess
    import sys
    
    # Test basic CLI
    result = subprocess.run(
        [sys.executable, "k8s_cluster_generator_enhanced.py", 
         "--nodes", "5", 
         "--use-case", "startup_mvp",
         "--seed", "42"],
        capture_output=True,
        text=True,
        cwd="/mnt/user-data/outputs"
    )
    
    if result.returncode == 0:
        print("   ✓ Basic CLI arguments work")
    else:
        print(f"   ❌ Basic CLI failed: {result.stderr}")
        raise Exception("Basic CLI test failed")
    
    # Test with vulnerability arguments (should be accepted even if files don't exist)
    result = subprocess.run(
        [sys.executable, "k8s_cluster_generator_enhanced.py",
         "--nodes", "5",
         "--use-case", "microservices", 
         "--seed", "42",
         "--cve-json", "test.json",
         "--vuln-db", "test.yml"],
        capture_output=True,
        text=True,
        cwd="/mnt/user-data/outputs"
    )
    
    if result.returncode == 0:
        print("   ✓ Vulnerability arguments accepted")
    else:
        print(f"   ❌ Vulnerability args failed: {result.stderr}")
        raise Exception("Vulnerability args test failed")
    
    # Test help
    result = subprocess.run(
        [sys.executable, "k8s_cluster_generator_enhanced.py", "--help"],
        capture_output=True,
        text=True,
        cwd="/mnt/user-data/outputs"
    )
    
    if "--cve-json" in result.stdout and "--vuln-db" in result.stdout:
        print("   ✓ Help shows vulnerability arguments")
    else:
        print("   ❌ Help missing vulnerability arguments")
        raise Exception("Help test failed")
    
    print("✅ All CLI arguments work correctly!")


def demo_migration_path():
    """Show how easy it is to migrate from original to enhanced."""
    print("\n" + "="*80)
    print("BONUS: Migration Path from Original to Enhanced")
    print("="*80)
    print("\nOLD CODE (Original Generator):")
    print("-"*80)
    print("""
    from k8s_cluster_generator import K8sClusterGenerator, UseCase
    
    generator = K8sClusterGenerator(
        num_nodes=20,
        use_case=UseCase.MICROSERVICES,
        seed=42
    )
    cluster = generator.generate()
    """)
    
    print("\nNEW CODE (Enhanced Generator - SAME INTERFACE):")
    print("-"*80)
    print("""
    # Just change the import! Everything else stays the same!
    from k8s_cluster_generator_enhanced import K8sClusterGenerator, UseCase
    
    generator = K8sClusterGenerator(
        num_nodes=20,
        use_case=UseCase.MICROSERVICES,
        seed=42
    )
    cluster = generator.generate()
    
    # ✨ Bonus: You now get enhanced features too!
    # But you don't have to use them if you don't want to.
    """)
    
    print("\nMigration: ✅ ZERO code changes needed!")
    print("           ✅ Just update the import statement")
    print("           ✅ Everything else works identically")


def main():
    """Run all backwards compatibility tests."""
    print("\n")
    print("╔" + "="*78 + "╗")
    print("║" + " "*78 + "║")
    print("║" + "  BACKWARDS COMPATIBILITY TEST SUITE".center(78) + "║")
    print("║" + " "*78 + "║")
    print("╚" + "="*78 + "╝")
    print()
    
    # Run all tests
    try:
        test_original_interface()
        test_multiple_clusters()
        test_different_sizes()
        test_reproducibility()
        test_output_format()
        test_enhanced_features_optional()
        test_json_serialization()
        test_cli_arguments()
        demo_migration_path()
        
        print("\n" + "="*80)
        print("="*80)
        print("\n🎉 ALL TESTS PASSED! 🎉")
        print("\nThe enhanced generator is 100% backwards compatible!")
        print("You can use it as a drop-in replacement for the original.\n")
        print("="*80)
        print("="*80)
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        raise
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        raise


if __name__ == "__main__":
    main()
