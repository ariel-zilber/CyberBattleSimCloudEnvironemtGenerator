#!/usr/bin/env python3
import yaml
import os
import argparse
import sys

"""
Kubernetes Manifest Generator for CyberBattleSim

This script reads a high-level simulation setup YAML and generates corresponding
Kubernetes resource manifests (Namespaces, Deployments, Services, NetworkPolicies).

Key Mappings:
- Subnets/Subnet Labels -> Kubernetes Namespaces
- Topology/Node Counts -> Kubernetes Deployments (with a simple naming convention)
- Sensitive Nodes -> Deployments with a specific label for high-value targets
- OSINT Services Strategy -> Creation of a ClusterIP Service for each Deployment
- Firewall Rules -> Kubernetes NetworkPolicy resources
"""

def _generate_namespace(name):
    """Generates a Kubernetes Namespace manifest."""
    return {
        'apiVersion': 'v1',
        'kind': 'Namespace',
        'metadata': {
            # This label is crucial for NetworkPolicy namespaceSelectors
            'name': name,
            'labels': {
                'name': name
            }
        }
    }

def _generate_deployment(name, namespace, is_sensitive=False, image="nginx:1.24-alpine"):
    """Generates a Kubernetes Deployment manifest."""
    labels = {'app': name}
    if is_sensitive:
        # Add a special label to identify high-value targets
        labels['security.cyberbattlesim/value'] = 'high'

    return {
        'apiVersion': 'apps/v1',
        'kind': 'Deployment',
        'metadata': {
            'name': name,
            'namespace': namespace,
            'labels': labels
        },
        'spec': {
            'replicas': 1,
            'selector': {
                'matchLabels': {'app': name}
            },
            'template': {
                'metadata': {
                    'labels': {'app': name}
                },
                'spec': {
                    'containers': [{
                        'name': name,
                        'image': image,
                        'ports': [{'containerPort': 80}]
                    }]
                }
            }
        }
    }

def _generate_service(name, namespace):
    """Generates a Kubernetes ClusterIP Service manifest."""
    return {
        'apiVersion': 'v1',
        'kind': 'Service',
        'metadata': {
            'name': name,
            'namespace': namespace
        },
        'spec': {
            'selector': {'app': name},
            'ports': [{'protocol': 'TCP', 'port': 80, 'targetPort': 80}],
            'type': 'ClusterIP'
        }
    }

def _generate_network_policy(name, namespace, from_namespace, to_namespace):
    """Generates a Kubernetes NetworkPolicy manifest."""
    # The policy is applied to the 'to_namespace'
    return {
        'apiVersion': 'networking.k8s.io/v1',
        'kind': 'NetworkPolicy',
        'metadata': {
            'name': name,
            'namespace': to_namespace
        },
        'spec': {
            'podSelector': {}, # Apply to all pods in the namespace
            'policyTypes': ['Ingress'],
            'ingress': [{
                'from': [{
                    'namespaceSelector': {
                        'matchLabels': {
                            'name': from_namespace
                        }
                    }
                }]
            }]
        }
    }

def generate_manifests(config):
    """
    Orchestrates the generation of all Kubernetes manifests from the config.
    Returns a dictionary of filenames to manifest content.
    """
    sim_setup = config.get('simulation_setup', {})
    manifests = {}

    # 1. Generate Namespaces from subnet_labels
    namespaces = {
        str(sub_id): name
        for sub_id, name in sim_setup.get('subnet_labels', {}).items()
    }
    for ns_name in namespaces.values():
        manifests[f"00_ns_{ns_name}.yaml"] = _generate_namespace(ns_name)

    # 2. Generate Deployments and Services
    sensitive_nodes = sim_setup.get('sensitive_nodes', [])
    
    # Example interpretation: The "4-4" in subnets might mean 4 pods.
    # Here, we'll create 4 deployments for simplicity.
    # A more complex parser could use the topology matrix.
    num_deployments = 4 
    target_namespace = namespaces.get("1", "default") # Use the first defined subnet

    for i in range(num_deployments):
        # Use a sensitive name if it's in the list, otherwise generic
        dep_name = sensitive_nodes[i] if i < len(sensitive_nodes) else f"app-{i}"
        is_sensitive = dep_name in sensitive_nodes

        # A more realistic image for an elasticsearch data node
        image = "docker.elastic.co/elasticsearch/elasticsearch:8.9.2" if dep_name.startswith("elasticsearch") else "nginx:1.24-alpine"
        
        deployment = _generate_deployment(dep_name, target_namespace, is_sensitive, image)
        manifests[f"10_deployment_{dep_name}.yaml"] = deployment

        # Generate a service for each deployment if OSINT strategy is 'all'
        osint_services = sim_setup.get('osint', {}).get('services', {})
        if osint_services.get('strategy') == 'all':
            service = _generate_service(dep_name, target_namespace)
            manifests[f"20_service_{dep_name}.yaml"] = service

    # 3. Generate Network Policies from firewall rules
    firewall = sim_setup.get('firewall', {})
    for i, rule in enumerate(firewall.get('rules', [])):
        from_ns = rule.get('from')
        to_ns = rule.get('to')
        if rule.get('permission') == 'allow' and from_ns and to_ns:
            policy_name = f"allow-{from_ns}-to-{to_ns}"
            netpol = _generate_network_policy(policy_name, to_ns, from_ns, to_ns)
            manifests[f"30_netpol_{policy_name}.yaml"] = netpol

    return manifests

def main():
    """Main function to parse arguments and run the generator."""
    parser = argparse.ArgumentParser(description="Generate Kubernetes manifests from a simulation config.")
    parser.add_argument("config_file", help="Path to the simulation configuration YAML file.")
    parser.add_argument("-o", "--output-dir", default="k8s_manifests", help="Directory to save the generated manifest files.")
    args = parser.parse_args()

    # Load config file
    try:
        with open(args.config_file, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file not found at '{args.config_file}'")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        sys.exit(1)

    # Generate manifests
    print("🚀 Generating Kubernetes manifests...")
    generated_manifests = generate_manifests(config)

    # Write manifests to files
    os.makedirs(args.output_dir, exist_ok=True)
    for filename, content in generated_manifests.items():
        filepath = os.path.join(args.output_dir, filename)
        with open(filepath, 'w') as f:
            yaml.dump(content, f, sort_keys=False, indent=2)
    
    print(f"✅ Successfully generated {len(generated_manifests)} manifests in '{args.output_dir}' directory.")


if __name__ == '__main__':
    main()