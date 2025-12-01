#!/usr/bin/env python3
import yaml
import os
import argparse
import sys
from datetime import datetime
from typing import Dict, List, Any

"""
Firewall to Network Policy Generator for CyberBattleSim

Converts firewall configurations to Kubernetes NetworkPolicy manifests.
"""

def _generate_network_policy(name: str, namespace: str, policy_spec: Dict[str, Any]) -> Dict:
    """Generate a Kubernetes NetworkPolicy manifest."""
    return {
        'apiVersion': 'networking.k8s.io/v1',
        'kind': 'NetworkPolicy',
        'metadata': {
            'name': name,
            'namespace': namespace
        },
        'spec': policy_spec
    }

def parse_firewall_rules(firewall_config: Dict[str, Any], subnet_labels: Dict[int, str], tier_zones: Dict[str, List[str]] = None) -> List[Dict]:
    """Parse firewall configuration into NetworkPolicy specs."""
    policies = []
    default_policy = firewall_config.get('default_policy', 'deny_all')
    rules = firewall_config.get('rules', [])
    
    if tier_zones is None:
        tier_zones = {}
    
    # Create default deny-all policy if needed
    if 'deny' in default_policy.lower():
        for subnet_id, subnet_name in subnet_labels.items():
            namespace = subnet_name.replace('_', '-')
            policies.append({
                'name': f'default-deny-{namespace}',
                'namespace': namespace,
                'spec': {
                    'podSelector': {},
                    'policyTypes': ['Ingress', 'Egress']
                }
            })
    
    # Process explicit rules
    for rule in rules:
        from_subnet = rule.get('from', '')
        to_subnet = rule.get('to', '')
        permission = rule.get('permission', 'deny')
        ports = rule.get('ports', [])
        
        if permission.lower() == 'allow':
            policy_spec = _create_allow_policy_spec(from_subnet, to_subnet, ports, subnet_labels, tier_zones)
            if policy_spec:
                to_namespace = _get_namespace_from_subnet(to_subnet, subnet_labels)
                policy_name = f'allow-{from_subnet}-to-{to_subnet}'.replace('_', '-')
                policies.append({
                    'name': policy_name,
                    'namespace': to_namespace,
                    'spec': policy_spec
                })
    
    return policies

def _create_allow_policy_spec(from_subnet: str, to_subnet: str, ports: List[str], subnet_labels: Dict[int, str], tier_zones: Dict[str, List[str]] = None) -> Dict:
    """Create NetworkPolicy spec for allow rule."""
    spec = {
        'podSelector': {},
        'policyTypes': ['Ingress']
    }
    
    if tier_zones is None:
        tier_zones = {}
    
    # Handle special cases
    if from_subnet == 'internet' or from_subnet == 'external':
        spec['ingress'] = [{}]  # Allow all external traffic
    else:
        # Create selector for source subnet
        ingress_rule = {
            'from': [{
                'namespaceSelector': {
                    'matchLabels': {
                        'name': from_subnet.replace('_', '-')
                    }
                }
            }]
        }
        
        # Add zone-specific selectors if topology is defined
        if from_subnet in tier_zones and tier_zones[from_subnet]:
            ingress_rule['from'].extend([
                {
                    'podSelector': {
                        'matchLabels': {
                            'topology.kubernetes.io/zone': zone
                        }
                    }
                } for zone in tier_zones[from_subnet]
            ])
        
        # Add port restrictions if specified
        if ports:
            ingress_rule['ports'] = [
                {'protocol': 'TCP', 'port': int(port) if port.isdigit() else port}
                for port in ports
            ]
        
        spec['ingress'] = [ingress_rule]
    
    return spec

def _get_namespace_from_subnet(subnet: str, subnet_labels: Dict[int, str]) -> str:
    """Get namespace name from subnet identifier."""
    # Direct mapping
    for subnet_id, subnet_name in subnet_labels.items():
        if subnet_name == subnet or subnet_name.replace('_', '-') == subnet:
            return subnet_name.replace('_', '-')
    
    # Fallback
    return subnet.replace('_', '-')

def parse_topology(topology_config: List[List[int]], subnet_labels: Dict[int, str]) -> Dict[str, List[str]]:
    """Parse topology configuration into tier-zone mapping."""
    tier_zones = {}
    
    for tier_idx, zone_replicas in enumerate(topology_config):
        tier_name = subnet_labels.get(tier_idx + 1, f"tier-{tier_idx + 1}")
        zones = []
        
        for zone_idx, replica_count in enumerate(zone_replicas):
            if replica_count > 0:
                zone_name = f"zone-{chr(97 + zone_idx)}"  # zone-a, zone-b, etc.
                zones.append(zone_name)
        
        tier_zones[tier_name] = zones
    
    return tier_zones

def generate_network_policies(config: Dict[str, Any]) -> Dict[str, Any]:
    """Generate NetworkPolicy manifests from firewall configuration."""
    sim_setup = config.get('simulation_setup', {})
    firewall_config = sim_setup.get('firewall', {})
    subnet_labels = sim_setup.get('subnet_labels', {})
    topology_config = sim_setup.get('topology', [])
    
    if not firewall_config:
        print("Warning: No firewall configuration found.")
        return {}
    
    # Parse topology to understand tier-zone structure
    tier_zones = parse_topology(topology_config, subnet_labels) if topology_config else {}
    
    # Parse firewall rules into NetworkPolicies
    policies = parse_firewall_rules(firewall_config, subnet_labels, tier_zones)
    
    # Generate manifests
    manifests = {}
    for policy in policies:
        manifest = _generate_network_policy(
            policy['name'],
            policy['namespace'], 
            policy['spec']
        )
        manifests[f"netpol_{policy['name']}.yaml"] = manifest
    
    return manifests

def main():
    """Main function to parse arguments and run the generator."""
    parser = argparse.ArgumentParser(description="Generate NetworkPolicy manifests from firewall config.")
    parser.add_argument("config_file", help="Path to the simulation configuration YAML file.")
    parser.add_argument("-b", "--base-dir", required=True, help="Base directory for output.")
    
    args = parser.parse_args()

    # Load config file
    try:
        with open(args.config_file, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file not found at '{args.config_file}'")
        sys.exit(1)

    # Create date-based subdirectory
    date_str = datetime.now().strftime("%Y-%m-%d")
    output_dir = os.path.join(args.base_dir, date_str, "network-policies")

    # Generate manifests
    print(f"🚀 Generating NetworkPolicy manifests from '{args.config_file}'...")
    generated_manifests = generate_network_policies(config)

    if not generated_manifests:
        print("⚠️ No NetworkPolicy manifests generated.")
        return

    # Write manifests to files
    os.makedirs(output_dir, exist_ok=True)
    for filename, content in generated_manifests.items():
        filepath = os.path.join(output_dir, filename)
        with open(filepath, 'w') as f:
            yaml.dump(content, f, sort_keys=False, indent=2)
    
    print(f"✅ Generated {len(generated_manifests)} NetworkPolicy manifests in '{output_dir}'")

if __name__ == '__main__':
    main()