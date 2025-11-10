#!/bin/bash
# examples.sh - Example usage patterns for the Kubernetes Cluster Generator

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  Kubernetes Realistic Cluster Generator - Example Scenarios   ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Example 1: Quick startup
echo "📦 Example 1: Small Startup (5 nodes)"
echo "─────────────────────────────────────────────────────────────────"
python k8s_cluster_generator.py --nodes 5 --use-case startup_mvp --seed 1
echo ""
echo ""

# Example 2: Microservices with verbose
echo "🚀 Example 2: Microservices Platform (15 nodes) - Verbose"
echo "─────────────────────────────────────────────────────────────────"
python k8s_cluster_generator.py --nodes 15 --use-case microservices --seed 2 --verbose
echo ""
echo ""

# Example 3: Data analytics to file
echo "📊 Example 3: Data Analytics Cluster (100 nodes) - Save to file"
echo "─────────────────────────────────────────────────────────────────"
python k8s_cluster_generator.py --nodes 100 --use-case data_analytics --seed 3 -o data_cluster.json
echo ""
echo ""

# Example 4: Multiple clusters
echo "🎲 Example 4: Generate 3 variations of ML Platform (20 nodes)"
echo "─────────────────────────────────────────────────────────────────"
python k8s_cluster_generator.py --nodes 20 --use-case ml_platform --count 3 --seed 4 -o ml_variations.json
echo ""
echo ""

# Example 5: E-commerce
echo "🛒 Example 5: E-commerce Platform (50 nodes)"
echo "─────────────────────────────────────────────────────────────────"
python k8s_cluster_generator.py --nodes 50 --use-case ecommerce --seed 5 --verbose
echo ""
echo ""

# Example 6: IoT platform
echo "📡 Example 6: IoT Platform (75 nodes)"
echo "─────────────────────────────────────────────────────────────────"
python k8s_cluster_generator.py --nodes 75 --use-case iot_platform --seed 6 -o iot_cluster.json
echo ""
echo ""

# Example 7: Gaming backend
echo "🎮 Example 7: Gaming Backend (30 nodes)"
echo "─────────────────────────────────────────────────────────────────"
python k8s_cluster_generator.py --nodes 30 --use-case gaming_backend --seed 7 --verbose
echo ""
echo ""

echo "✅ All examples completed!"
echo ""
echo "Generated files:"
ls -lh *.json 2>/dev/null || echo "  (none - examples printed to stdout)"
