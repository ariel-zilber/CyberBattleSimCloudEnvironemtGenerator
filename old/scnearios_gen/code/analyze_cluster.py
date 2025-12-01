#!/usr/bin/env python3
"""
Comprehensive Cluster Analysis Tool
====================================
Analyzes generated cluster configurations with all features.

Usage: python analyze_cluster.py <cluster.json>
"""

import json
import sys
from collections import defaultdict


def analyze_cluster(filepath):
    """Analyze complete cluster configuration"""
    
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    print("="*100)
    print("COMPLETE CLUSTER ANALYSIS")
    print("="*100)
    
    # Basic cluster info
    meta = data.get('cluster_metadata', {})
    print(f"\n📦 CLUSTER OVERVIEW")
    print(f"{'─'*100}")
    print(f"  Total Services:        {meta.get('total_services', 0)}")
    print(f"  Total Pods:            {meta.get('total_pods', 0)}")
    print(f"  Avg Pods/Node:         {meta.get('avg_pods_per_node', 0)}")
    print(f"  Resource Utilization:  {meta.get('resource_utilization_percent', 0):.1f}%")
    
    # Network topology analysis
    if 'network_topology' in data:
        topo = data['network_topology']
        metadata = topo.get('metadata', {})
        
        print(f"\n🌐 NETWORK TOPOLOGY")
        print(f"{'─'*100}")
        print(f"  Total Edges:           {metadata.get('total_edges', 0)}")
        print(f"  Firewall Blocked:      {metadata.get('firewall_blocked_edges', 0)}")
        print(f"  Entry Points:          {', '.join(metadata.get('entry_points', []))}")
        print(f"  Knows Reachability:    {metadata.get('knows_reachability_count', 0)} nodes")
        print(f"  Access Reachability:   {metadata.get('access_reachability_count', 0)} nodes")
        
        # Connectivity metrics
        conn_metrics = metadata.get('connectivity_metrics', {})
        print(f"\n  📊 Graph Metrics:")
        print(f"     Average Degree:     {conn_metrics.get('avg_degree', 0):.2f}")
        print(f"     Density:            {conn_metrics.get('density', 0):.4f}")
        print(f"     Is Connected:       {conn_metrics.get('is_connected', False)}")
        print(f"     Components:         {conn_metrics.get('num_components', 0)}")
        
        # Credential flow analysis
        cred_metrics = metadata.get('credential_metrics', {})
        if cred_metrics:
            print(f"\n🔐 CREDENTIAL FLOW")
            print(f"{'─'*100}")
            print(f"  Total Credentials:     {cred_metrics.get('total_credentials', 0)}")
            print(f"  Cached:                {cred_metrics.get('cached_credentials', 0)}")
            print(f"  Shared:                {cred_metrics.get('shared_credentials', 0)}")
            print(f"  Pivot-Capable:         {cred_metrics.get('pivot_credentials', 0)}")
            print(f"  Admin/System Level:    {cred_metrics.get('admin_or_system', 0)}")
            
            print(f"\n  📊 By Privilege Level:")
            for level, count in sorted(cred_metrics.get('by_level', {}).items()):
                print(f"     {level:15s}     {count:3d}")
            
            print(f"\n  📊 By Credential Type:")
            for ctype, count in sorted(cred_metrics.get('by_type', {}).items()):
                print(f"     {ctype:20s} {count:3d}")
        
        # Vulnerability analysis
        vuln_stats = metadata.get('vulnerability_stats', {})
        if vuln_stats and vuln_stats.get('total_vulnerabilities', 0) > 0:
            print(f"\n🛡️  VULNERABILITY ANALYSIS")
            print(f"{'─'*100}")
            print(f"  Total Vulnerabilities: {vuln_stats.get('total_vulnerabilities', 0)}")
            print(f"  Services Vulnerable:   {vuln_stats.get('services_with_vulnerabilities', 0)}")
            print(f"  Avg CVSS Score:        {vuln_stats.get('avg_cvss_score', 0):.2f}")
            print(f"  Max CVSS Score:        {vuln_stats.get('max_cvss_score', 0):.2f}")
            print(f"  Avg Exploitability:    {vuln_stats.get('avg_exploitability', 0):.2f}")
            
            print(f"\n  📊 By Severity:")
            by_sev = vuln_stats.get('by_severity', {})
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = by_sev.get(severity, 0)
                if count > 0:
                    print(f"     {severity:10s}         {count:3d}")
        
        # Detailed service analysis with vulnerabilities
        services = topo.get('services', {})
        
        # Find high-risk services
        high_risk = []
        for name, service in services.items():
            vulns = service.get('vulnerabilities', [])
            if vulns:
                critical = sum(1 for v in vulns if v.get('severity') == 'CRITICAL')
                high = sum(1 for v in vulns if v.get('severity') == 'HIGH')
                
                if critical > 0 or high > 0 or service.get('is_public', False):
                    high_risk.append({
                        'name': name,
                        'public': service.get('is_public', False),
                        'port': service.get('port', 0),
                        'critical': critical,
                        'high': high,
                        'total': len(vulns)
                    })
        
        if high_risk:
            print(f"\n⚠️  HIGH-RISK SERVICES")
            print(f"{'─'*100}")
            print(f"  {'Service':30s} {'Public':8s} {'Port':6s} {'Critical':10s} {'High':6s} {'Total':7s}")
            print(f"  {'-'*30} {'-'*8} {'-'*6} {'-'*10} {'-'*6} {'-'*7}")
            
            for item in sorted(high_risk, key=lambda x: (x['critical'], x['high']), reverse=True)[:15]:
                pub = "Yes" if item['public'] else "No"
                print(f"  {item['name']:30s} {pub:8s} {item['port']:6d} {item['critical']:10d} {item['high']:6d} {item['total']:7d}")
        
        # CyberBattleSim vulnerability type analysis
        vuln_types = defaultdict(int)
        outcome_types = defaultdict(int)
        
        for name, service in services.items():
            for vuln in service.get('vulnerabilities', []):
                vtype = vuln.get('vulnerability_type', 'UNKNOWN')
                outcome = vuln.get('outcome_type', 'UNKNOWN')
                vuln_types[vtype] += 1
                outcome_types[outcome] += 1
        
        if vuln_types:
            print(f"\n🎮 CYBERBATTLESIM VULNERABILITY TYPES")
            print(f"{'─'*100}")
            print(f"  📡 Vulnerability Type (LOCAL vs REMOTE):")
            for vtype, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
                print(f"     {vtype:15s}     {count:3d}")
            
            print(f"\n  🎯 Outcome Type Distribution:")
            for outcome, count in sorted(outcome_types.items(), key=lambda x: x[1], reverse=True):
                print(f"     {outcome:30s} {count:3d}")
        
        # Attack surface summary
        print(f"\n🎯 ATTACK SURFACE SUMMARY")
        print(f"{'─'*100}")
        
        # Public services
        public_services = [s for s, svc in services.items() if svc.get('is_public', False)]
        print(f"  Public Services:       {len(public_services)}")
        if public_services:
            print(f"     {', '.join(public_services[:5])}{' ...' if len(public_services) > 5 else ''}")
        
        # Services with credentials
        creds_by_service = defaultdict(int)
        for cred in topo.get('credential_flow', []):
            creds_by_service[cred['source']] += 1
        
        top_cred_holders = sorted(creds_by_service.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_cred_holders:
            print(f"\n  Top Credential Holders:")
            for service, count in top_cred_holders:
                pivot = "🎯" if any(c['source'] == service and c['can_pivot'] 
                                   for c in topo.get('credential_flow', [])) else "  "
                print(f"     {pivot} {service:30s} {count:3d} credentials")
        
        # Critical paths
        print(f"\n  💎 High-Value Attack Paths:")
        
        # Find paths: Public → Credentials → High-Value Target
        for entry in public_services[:3]:
            entry_creds = [c for c in topo.get('credential_flow', []) if c['source'] == entry]
            for cred in entry_creds[:2]:
                target = cred['target']
                target_svc = services.get(target, {})
                target_vulns = target_svc.get('vulnerabilities', [])
                high_vulns = [v for v in target_vulns if v.get('severity') in ['HIGH', 'CRITICAL']]
                
                if high_vulns or target_svc.get('category') in ['database', 'security']:
                    print(f"     {entry} → [{cred['credential_type']}] → {target} "
                          f"({len(high_vulns)} HIGH+ vulns)")
    
    print(f"\n{'='*100}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*100}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_cluster.py <cluster.json>")
        sys.exit(1)
    
    analyze_cluster(sys.argv[1])
