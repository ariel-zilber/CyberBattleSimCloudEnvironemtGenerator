#!/usr/bin/env python3
import yaml
import os
import argparse
import sys
import random
from datetime import datetime
from typing import Dict, List, Any

"""
Complete Kubernetes Cluster Generator for CyberBattleSim

Generates Node manifests, NetworkPolicy manifests, and PersistentVolume/PVC pairs
from simulation configuration. All resources deploy to default namespace.
"""

def _generate_node(name: str, labels: Dict[str, str] = None, zone: str = "zone-a") -> Dict:
    """Generate a Kubernetes Node manifest suitable for kwok."""
    if labels is None:
        labels = {}
    
    default_labels = {
        'kubernetes.io/arch': 'amd64',
        'kubernetes.io/os': 'linux',
        'topology.kubernetes.io/zone': zone,
        'node.kubernetes.io/instance-type': random.choice(['m5.large', 'm5.xlarge', 'm5.2xlarge'])
    }
    labels.update(default_labels)

    return {
        'apiVersion': 'v1',
        'kind': 'Node',
        'metadata': {
            'name': name,
            'labels': labels,
            'annotations': {
                'kwok.x-k8s.io/node': 'true'
            }
        },
        'spec': {},
        'status': {
            'conditions': [{
                'type': 'Ready',
                'status': 'True',
                'reason': 'KubeletReady',
                'message': 'kubelet is posting ready status'
            }],
            'capacity': {
                'cpu': '4',
                'memory': '16000Gi',
                'ephemeral-storage': "16000Gi" ,
                'pods': '110'
            },
            'allocatable': {
                'cpu': '3.9',
                'memory': '15990Gi', 
                'ephemeral-storage': "15990Gi" ,
                'pods': '110'
            }
        }
    }

def _generate_persistent_volume(name: str, capacity: str, storage_class: str = "local-storage", access_modes: List[str] = None) -> Dict:
    """Generate a Kubernetes PersistentVolume manifest."""
    if access_modes is None:
        access_modes = ["ReadWriteOnce"]
    
    return {
        'apiVersion': 'v1',
        'kind': 'PersistentVolume',
        'metadata': {
            'name': name
        },
        'spec': {
            'capacity': {
                'storage': capacity
            },
            'accessModes': access_modes,
            'storageClassName': storage_class,
            'hostPath': {
                'path': f'/mnt/data/{name}'
            },
            'persistentVolumeReclaimPolicy': 'Retain'
        }
    }

def _generate_persistent_volume_claim(name: str, capacity: str, storage_class: str = "local-storage", access_modes: List[str] = None) -> Dict:
    """Generate a Kubernetes PersistentVolumeClaim manifest."""
    if access_modes is None:
        access_modes = ["ReadWriteOnce"]
    
    return {
        'apiVersion': 'v1',
        'kind': 'PersistentVolumeClaim',
        'metadata': {
            'name': name
        },
        'spec': {
            'accessModes': access_modes,
            'storageClassName': storage_class,
            'resources': {
                'requests': {
                    'storage': capacity
                }
            }
        }
    }

def _generate_network_policy(name: str, policy_spec: Dict[str, Any]) -> Dict:
    """Generate a Kubernetes NetworkPolicy manifest."""
    return {
        'apiVersion': 'networking.k8s.io/v1',
        'kind': 'NetworkPolicy',
        'metadata': {
            'name': name
        },
        'spec': policy_spec
    }

def parse_topology(topology_config: List[List[int]], subnet_labels: Dict[int, str]) -> Dict[str, List[str]]:
    """Parse topology configuration into tier-zone mapping."""
    tier_zones = {}
    
    for tier_idx, zone_replicas in enumerate(topology_config):
        tier_name = subnet_labels.get(tier_idx + 1, f"tier-{tier_idx + 1}")
        zones = []
        
        for zone_idx, replica_count in enumerate(zone_replicas):
            if replica_count > 0:
                zone_name = f"zone-{chr(97 + zone_idx)}"
                zones.append(zone_name)
        
        tier_zones[tier_name] = zones
    
    return tier_zones

def generate_node_manifests(config: Dict[str, Any]) -> Dict[str, Any]:
    """Generate Kubernetes Node manifests from configuration."""
    sim_setup = config.get('simulation_setup', {})
    manifests = {}
    
    subnets_config = sim_setup.get('subnets', [])
    if not subnets_config:
        return {}
    
    subnet_data = subnets_config[0]
    try:
        if isinstance(subnet_data, str):
            parts = list(map(int, subnet_data.split('-')))
        elif isinstance(subnet_data, list):
            if len(subnet_data) == 1 and isinstance(subnet_data[0], str):
                parts = list(map(int, subnet_data[0].split('-')))
            else:
                parts = list(map(int, subnet_data))
        else:
            raise ValueError(f"Unsupported subnet type: {type(subnet_data)}")
            
        num_pods = parts[0]
        min_nodes_per_subnet = parts[1:] if len(parts) > 1 else [1]
        total_min_nodes = sum(min_nodes_per_subnet)
    except (ValueError, IndexError):
        print(f"Warning: Invalid subnet format. Got: {subnet_data}")
        return {}
    
    subnet_labels = sim_setup.get('subnet_labels', {})
    sensitive_nodes = sim_setup.get('sensitive_nodes', [])
    
    num_masters = 1 if total_min_nodes <= 3 else 3
    zones = ['zone-a', 'zone-b', 'zone-c']
    node_counter = 0
    
    # Generate master nodes
    for i in range(num_masters):
        zone = zones[i % len(zones)]
        node_name = f"master-{i + 1}"
        
        node_labels = {
            'node-role.kubernetes.io/control-plane': '',
            'node-role.kubernetes.io/master': '',
            'topology.kubernetes.io/zone': zone,
            'sensitivity': 'critical'
        }
        
        manifests[f"node_{node_name}.yaml"] = _generate_node(node_name, node_labels, zone)
        node_counter += 1
    
    # Generate worker nodes per subnet
    for subnet_idx, min_nodes in enumerate(min_nodes_per_subnet):
        subnet_id = subnet_idx + 1
        subnet_name = subnet_labels.get(subnet_id, f"subnet-{subnet_id}")
        
        for i in range(min_nodes):
            zone = zones[node_counter % len(zones)]
            node_name = f"worker-{subnet_name}-{i + 1}"
            
            node_labels = {
                'node-role.kubernetes.io/worker': '',
                'topology.kubernetes.io/zone': zone,
                'subnet': subnet_name
            }
            
            if node_name in sensitive_nodes or any(sensitive in node_name for sensitive in sensitive_nodes):
                node_labels['sensitivity'] = 'high'
            
            manifests[f"node_{node_name}.yaml"] = _generate_node(node_name, node_labels, zone)
            node_counter += 1
    
    return manifests

def _create_allow_policy_spec(from_subnet: str, to_subnet: str, ports: List[str], subnet_labels: Dict[int, str], tier_zones: Dict[str, List[str]] = None) -> Dict:
    """Create NetworkPolicy spec for allow rule."""
    spec = {
        'podSelector': {
            'matchLabels': {
                'subnet': to_subnet
            }
        },
        'policyTypes': ['Ingress']
    }
    
    if tier_zones is None:
        tier_zones = {}
    
    # Handle special cases
    if from_subnet in ['internet', 'external']:
        spec['ingress'] = [{}]  # Allow all external traffic
    else:
        # Create selector for source subnet using pod labels
        ingress_rule = {
            'from': [{
                'podSelector': {
                    'matchLabels': {
                        'subnet': from_subnet
                    }
                }
            }]
        }
        
        # Add zone-specific selectors if topology is defined
        if from_subnet in tier_zones and tier_zones[from_subnet]:
            for zone in tier_zones[from_subnet]:
                ingress_rule['from'].append({
                    'podSelector': {
                        'matchLabels': {
                            'subnet': from_subnet,
                            'topology.kubernetes.io/zone': zone
                        }
                    }
                })
        
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
    for subnet_id, subnet_name in subnet_labels.items():
        if subnet_name == subnet or subnet_name.replace('_', '-') == subnet:
            return subnet_name.replace('_', '-')
    return subnet.replace('_', '-')

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
            policies.append({
                'name': f'default-deny-{subnet_name}'.replace('_', '-'),
                'spec': {
                    'podSelector': {
                        'matchLabels': {
                            'subnet': subnet_name
                        }
                    },
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
                policy_name = f'allow-{from_subnet}-to-{to_subnet}'.replace('_', '-')
                policies.append({
                    'name': policy_name,
                    'spec': policy_spec
                })
    
    return policies

def generate_network_policies(config: Dict[str, Any]) -> Dict[str, Any]:
    """Generate NetworkPolicy manifests from firewall configuration."""
    sim_setup = config.get('simulation_setup', {})
    firewall_config = sim_setup.get('firewall', {})
    subnet_labels = sim_setup.get('subnet_labels', {})
    topology_config = sim_setup.get('topology', [])
    
    if not firewall_config:
        return {}
    
    tier_zones = parse_topology(topology_config, subnet_labels) if topology_config else {}
    policies = parse_firewall_rules(firewall_config, subnet_labels, tier_zones)
    
    manifests = {}
    for policy in policies:
        manifest = _generate_network_policy(
            policy['name'],
            policy['spec']
        )
        manifests[f"netpol_{policy['name']}.yaml"] = manifest
    
    return manifests

def generate_pv_manifests(config: Dict[str, Any]) -> Dict[str, Any]:
    """Generate PersistentVolume and PersistentVolumeClaim manifests based on configuration."""
    sim_setup = config.get('simulation_setup', {})
    subnet_labels = sim_setup.get('subnet_labels', {})
    topology_config = sim_setup.get('topology', [])
    
    manifests = {}
    
    # Storage requirements by tier type
    storage_config = {
        'database': {'capacity': '50Gi', 'access_modes': ['ReadWriteOnce']},
        'backend': {'capacity': '20Gi', 'access_modes': ['ReadWriteOnce']},
        'frontend': {'capacity': '10Gi', 'access_modes': ['ReadWriteMany']},
        'default': {'capacity': '10Gi', 'access_modes': ['ReadWriteOnce']}
    }
    
    for tier_idx, zone_replicas in enumerate(topology_config):
        tier_name = subnet_labels.get(tier_idx + 1, f"tier-{tier_idx + 1}")
        
        # Determine storage type based on tier name
        storage_type = 'default'
        for key in storage_config.keys():
            if key in tier_name.lower():
                storage_type = key
                break
        
        pv_count = 0
        for zone_idx, replica_count in enumerate(zone_replicas):
            if replica_count > 0:
                zone_name = f"zone-{chr(97 + zone_idx)}"
                
                # Generate PV/PVC pairs for this zone
                for i in range(replica_count):
                    pv_count += 1
                    base_name = f"{tier_name}-{zone_name}-{i + 1}".replace('_', '-')
                    pv_name = f"pv-{base_name}"
                    pvc_name = f"pvc-{base_name}"
                    
                    # Generate PV
                    pv_manifest = _generate_persistent_volume(
                        pv_name,
                        storage_config[storage_type]['capacity'],
                        storage_class="",  # Empty for manual binding
                        access_modes=storage_config[storage_type]['access_modes']
                    )
                    
                    # Add claimRef to bind to specific PVC
                    pv_manifest['spec']['claimRef'] = {
                        'name': pvc_name
                    }
                    
                    manifests[f"pv_{pv_name}.yaml"] = pv_manifest
                    
                    # Generate matching PVC
                    pvc_manifest = _generate_persistent_volume_claim(
                        pvc_name,
                        storage_config[storage_type]['capacity'],
                        storage_class="",  # Empty for manual binding
                        access_modes=storage_config[storage_type]['access_modes']
                    )
                    
                    manifests[f"pvc_{pvc_name}.yaml"] = pvc_manifest
    
    return manifests

def main():
    """Main function to parse arguments and run the generator."""
    parser = argparse.ArgumentParser(description="Generate Kubernetes cluster manifests from simulation config.")
    parser.add_argument("config_file", help="Path to the simulation configuration YAML file.")
    parser.add_argument("-b", "--base-dir", required=True, help="Base directory for output.")
    parser.add_argument("--nodes-only", action="store_true", help="Generate only node manifests.")
    parser.add_argument("--netpol-only", action="store_true", help="Generate only NetworkPolicy manifests.")
    parser.add_argument("--pv-only", action="store_true", help="Generate only PersistentVolume manifests.")
    
    args = parser.parse_args()

    try:
        with open(args.config_file, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file not found at '{args.config_file}'")
        sys.exit(1)

    date_str = datetime.now().strftime("%Y-%m-%d")
    base_output_dir = os.path.join(args.base_dir, date_str)

    generated_count = 0

    # Generate nodes
    if not (args.netpol_only or args.pv_only):
        print("🚀 Generating Node manifests...")
        node_manifests = generate_node_manifests(config)
        
        if node_manifests:
            nodes_dir = os.path.join(base_output_dir, "nodes")
            os.makedirs(nodes_dir, exist_ok=True)
            
            for filename, content in node_manifests.items():
                filepath = os.path.join(nodes_dir, filename)
                with open(filepath, 'w') as f:
                    yaml.dump(content, f, sort_keys=False, indent=2)
            
            generated_count += len(node_manifests)
            print(f"✅ Generated {len(node_manifests)} node manifests")

    # Generate NetworkPolicies
    if not (args.nodes_only or args.pv_only):
        print("🚀 Generating NetworkPolicy manifests...")
        netpol_manifests = generate_network_policies(config)
        
        if netpol_manifests:
            netpol_dir = os.path.join(base_output_dir, "network-policies")
            os.makedirs(netpol_dir, exist_ok=True)
            
            for filename, content in netpol_manifests.items():
                filepath = os.path.join(netpol_dir, filename)
                with open(filepath, 'w') as f:
                    yaml.dump(content, f, sort_keys=False, indent=2)
            
            generated_count += len(netpol_manifests)
            print(f"✅ Generated {len(netpol_manifests)} NetworkPolicy manifests")

    # Generate PersistentVolumes
    if not (args.nodes_only or args.netpol_only):
        print("🚀 Generating PersistentVolume manifests...")
        pv_manifests = generate_pv_manifests(config)
        
        if pv_manifests:
            pv_dir = os.path.join(base_output_dir, "persistent-volumes")
            os.makedirs(pv_dir, exist_ok=True)
            
            for filename, content in pv_manifests.items():
                filepath = os.path.join(pv_dir, filename)
                with open(filepath, 'w') as f:
                    yaml.dump(content, f, sort_keys=False, indent=2)
            
            generated_count += len(pv_manifests)
            print(f"✅ Generated {len(pv_manifests)} PersistentVolume manifests")

    print(f"📁 Output directory: {base_output_dir}")
    print(f"📊 Total manifests: {generated_count}")

if __name__ == '__main__':
    main()