#!/bin/bash
# Instance Count Feature Demo
# Demonstrates the new v1.1 instance count capabilities

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║    Kubernetes Cluster Generator v1.1 - Instance Count Demo    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

echo "🎯 Demonstrating Instance Count Scaling Across Cluster Sizes"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Demo 1: Show scaling for same use case across different sizes
echo "📊 Demo 1: Microservices Platform Scaling"
echo "─────────────────────────────────────────────────────────────────"
echo ""

echo "▶ Generating 5-node microservices cluster..."
python k8s_cluster_generator.py --nodes 5 --use-case microservices --seed 100 -o demo_micro_5.json 2>&1 | grep -E "(Total Services|Total Pods|Avg Pods)"

echo ""
echo "▶ Generating 20-node microservices cluster..."
python k8s_cluster_generator.py --nodes 20 --use-case microservices --seed 100 -o demo_micro_20.json 2>&1 | grep -E "(Total Services|Total Pods|Avg Pods)"

echo ""
echo "▶ Generating 100-node microservices cluster..."
python k8s_cluster_generator.py --nodes 100 --use-case microservices --seed 100 -o demo_micro_100.json 2>&1 | grep -E "(Total Services|Total Pods|Avg Pods)"

echo ""
echo "📈 Key Observations:"
echo "  • Same services, but instance counts scale with cluster size"
echo "  • Pods per node decreases as cluster grows (better distribution)"
echo "  • HA services automatically scale: 2 → 4 → 6 instances"
echo ""
echo ""

# Demo 2: Show instance counts for specific services
echo "🔍 Demo 2: Service Instance Count Details"
echo "─────────────────────────────────────────────────────────────────"
echo ""

echo "▶ Generating 50-node e-commerce cluster with detailed output..."
python k8s_cluster_generator.py --nodes 50 --use-case ecommerce --seed 200 --verbose 2>&1 | grep -A 15 "Top 10 Services by Instance Count"

echo ""
echo ""

# Demo 3: Compare different use cases
echo "🎭 Demo 3: Instance Density by Use Case (20 nodes each)"
echo "─────────────────────────────────────────────────────────────────"
echo ""

echo "▶ Startup MVP (lightweight)..."
python k8s_cluster_generator.py --nodes 20 --use-case startup_mvp --seed 300 -o demo_startup.json 2>&1 | grep -E "(Total Services|Total Pods|Avg Pods)"

echo ""
echo "▶ Microservices (balanced)..."
python k8s_cluster_generator.py --nodes 20 --use-case microservices --seed 300 -o demo_microservices.json 2>&1 | grep -E "(Total Services|Total Pods|Avg Pods)"

echo ""
echo "▶ Data Analytics (intensive)..."
python k8s_cluster_generator.py --nodes 20 --use-case data_analytics --seed 300 -o demo_data.json 2>&1 | grep -E "(Total Services|Total Pods|Avg Pods)"

echo ""
echo "📊 Pod Density Comparison:"
echo "  • Startup: ~1.5-2.0 pods/node (minimal services)"
echo "  • Microservices: ~2.5-3.5 pods/node (full stack)"
echo "  • Data Analytics: ~3.0-4.0 pods/node (compute-heavy)"
echo ""
echo ""

# Demo 4: Export to CSV
echo "💾 Demo 4: CSV Export with Instance Counts"
echo "─────────────────────────────────────────────────────────────────"
echo ""

echo "▶ Exporting all demo clusters to CSV..."
python cluster_csv_export.py demo_*.json 2>&1 | tail -8

echo ""
echo "📁 Generated CSV files:"
echo "  • clusters_summary.csv - Overview with pod counts"
echo "  • clusters_instance_counts.csv - Full instance count matrix"
echo "  • clusters_services_matrix.csv - Service presence"
echo "  • clusters_categories.csv - Category breakdown"
echo ""
echo ""

# Demo 5: Show actual instance count data
echo "🔢 Demo 5: Instance Count Matrix Preview"
echo "─────────────────────────────────────────────────────────────────"
echo ""

echo "▶ Sample from clusters_instance_counts.csv:"
if [ -f "clusters_instance_counts.csv" ]; then
    head -3 clusters_instance_counts.csv | cut -d',' -f1-8 | column -t -s','
    echo "  ... (more services in full file)"
else
    echo "  (CSV file not found - run the export step)"
fi

echo ""
echo ""

# Demo 6: Quorum services
echo "🎲 Demo 6: Quorum-Based Services (always odd numbers)"
echo "─────────────────────────────────────────────────────────────────"
echo ""

echo "▶ Testing etcd instance counts across cluster sizes..."
for nodes in 5 10 20 50 100 200; do
    instances=$(python k8s_cluster_generator.py --nodes $nodes --use-case microservices --seed 999 2>/dev/null | grep -A 100 "service_instances" | grep "etcd" | grep -o "[0-9]\+")
    if [ ! -z "$instances" ]; then
        echo "  • ${nodes} nodes → etcd: ${instances} instances (odd for quorum)"
    fi
done

echo ""
echo "📐 Quorum Rule:"
echo "  • etcd always uses odd numbers: 3, 5, or 7"
echo "  • Ensures split-brain prevention"
echo "  • Automatically enforced by the generator"
echo ""
echo ""

# Summary
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                          Summary                               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "✅ Instance Count Feature Highlights:"
echo ""
echo "1. 🎯 Automatic Scaling"
echo "   Services scale intelligently with cluster size"
echo ""
echo "2. 🛡️  HA Enforcement"
echo "   Minimum 2 instances for HA services"
echo ""
echo "3. 🎲 Quorum Intelligence"
echo "   Odd numbers (3,5,7) for etcd/zookeeper/consul"
echo ""
echo "4. 📊 Accurate Metrics"
echo "   Total pods, avg pods/node, resource calculations"
echo ""
echo "5. 💾 Enhanced Exports"
echo "   New CSV with full instance count matrix"
echo ""
echo "6. 📈 Realistic Densities"
echo "   Pod distributions match real-world patterns"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🚀 Try it yourself:"
echo "   python k8s_cluster_generator.py --nodes 50 --use-case microservices --verbose"
echo ""
echo "📖 Documentation:"
echo "   See INSTANCE_COUNT_FEATURE.md for complete details"
echo ""
