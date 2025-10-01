#!/usr/bin/env python3
import json
import yaml
import os
import argparse
from datetime import datetime
from typing import Dict, List, Any, Tuple
import random

"""
CyberBattleSim Scenario Generator

Converts kwok cluster snapshots + vulnerability/credential data into CyberBattleSim scenarios.
"""

def load_snapshot_data(snapshot_path: str) -> Dict[str, Any]:
    """Load cluster snapshot data."""
    data = {}
    
    # Load summary
    summary_path = os.path.join(snapshot_path, 'summary.json')
    if os.path.exists(summary_path):
        with open(summary_path, 'r') as f:
            data['summary'] = json.load(f)
    
    # Load key resources
    resource_files = ['nodes.yaml', 'pods.yaml', 'services.yaml', 'deployments.yaml']
    for resource_file in resource_files:
        file_path = os.path.join(snapshot_path, resource_file)
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                try:
                    data[resource_file.replace('.yaml', '')] = yaml.safe_load(f)
                except:
                    data[resource_file.replace('.yaml', '')] = None
    
    return data

def load_vulnerability_data(info_path: str) -> Tuple[Dict, Dict]:
    """Load vulnerability and credential data."""
    vuln_file = os.path.join(info_path, 'helm_analysis_with_cves_and_secrets.json')
    cred_file = os.path.join(info_path, 'raw_credentials.json')
    
    vuln_data = {}
    cred_data = {}
    
    if os.path.exists(vuln_file):
        with open(vuln_file, 'r') as f:
            vuln_data = json.load(f)
    
    if os.path.exists(cred_file):
        with open(cred_file, 'r') as f:
            cred_data = json.load(f)
    
    return vuln_data, cred_data

def map_cvss_to_vulnerability(vuln: Dict) -> Dict:
    """Map CVE data to CyberBattleSim vulnerability format."""
    vuln_id = vuln.get('VulnerabilityID', 'unknown')
    cvss_score = 0.0
    cvss_vector = ""
    
    if 'CVSS' in vuln:
        cvss = vuln['CVSS']
        if 'nvd' in cvss:
            cvss_score = cvss['nvd'].get('V3Score', cvss['nvd'].get('V2Score', 0.0))
            cvss_vector = cvss['nvd'].get('V3Vector', cvss['nvd'].get('V2Vector', ''))
    
    # Determine vulnerability type and properties
    vuln_type = "remote" if "AV:N" in cvss_vector or "AV:A" in cvss_vector else "local"
    privilege_escalation = "PR:N" in cvss_vector or "PR:L" in cvss_vector
    credential_leak = "C:H" in cvss_vector or "C:L" in cvss_vector
    
    # Map severity to success rate
    if cvss_score >= 9.0:
        success_rate = 0.85
        reward = 40
    elif cvss_score >= 7.0:
        success_rate = 0.65
        reward = 30
    elif cvss_score >= 4.0:
        success_rate = 0.35
        reward = 20
    else:
        success_rate = 0.20
        reward = 10
    
    return {
        'id': vuln_id,
        'type': vuln_type,
        'description': vuln.get('Description', vuln.get('Title', 'Unknown vulnerability')),
        'cvss_score': cvss_score,
        'success_rate': success_rate,
        'reward': reward,
        'privilege_escalation': privilege_escalation,
        'credential_leak': credential_leak,
        'pkg_name': vuln.get('PkgName', ''),
        'severity': vuln.get('Severity', 'UNKNOWN')
    }

def create_cyberbattle_nodes(snapshot_data: Dict, vuln_data: Dict, cred_data: Dict) -> Dict[str, Any]:
    """Create CyberBattleSim node definitions."""
    nodes = {}
    
    # Extract firewall configurations from NetworkPolicies
    firewall_configs = extract_firewall_from_snapshot(snapshot_data)
    
    # Process cluster nodes
    k8s_nodes = snapshot_data.get('nodes', {}).get('items', [])
    services_data = vuln_data.get('services', [])
    
    for i, node in enumerate(k8s_nodes):
        node_name = node['metadata']['name']
        node_labels = node['metadata'].get('labels', {})
        
        # Determine node role and subnet
        is_master = 'node-role.kubernetes.io/master' in node_labels
        subnet = node_labels.get('subnet', 'default')
        zone = node_labels.get('topology.kubernetes.io/zone', 'zone-a')
        
        # Get vulnerabilities for this node
        node_vulns = []
        node_credentials = []
        
        # Map services to this node based on labels/subnet
        for service in services_data:
            if should_place_service_on_node(service, node_labels, subnet):
                service_vulns = extract_service_vulnerabilities(service)
                service_creds = extract_service_credentials(service, cred_data)
                
                node_vulns.extend(service_vulns)
                node_credentials.extend(service_creds)
        
        # Create node definition
        nodes[node_name] = {
            'services': create_node_services(node_credentials),
            'vulnerabilities': create_vulnerability_library(node_vulns),
            'value': 100 if is_master else random.randint(20, 80),
            'properties': [
                'Linux' if 'linux' in node_labels.get('kubernetes.io/os', '') else 'Windows',
                subnet,
                zone,
                'Master' if is_master else 'Worker'
            ],
            'firewall': create_firewall_config(node_labels, firewall_configs),
            'network_info': create_network_info(subnet, zone)
        }
    
    return nodes

def should_place_service_on_node(service: Dict, node_labels: Dict, subnet: str) -> bool:
    """Determine if a service should be placed on a specific node."""
    service_name = service.get('name', '').lower()
    
    # Master services
    if any(term in service_name for term in ['api', 'controller', 'scheduler', 'etcd']):
        return 'node-role.kubernetes.io/master' in node_labels
    
    # Database services
    if any(term in service_name for term in ['database', 'mysql', 'postgres', 'redis']):
        return 'database' in subnet.lower()
    
    # Frontend services
    if any(term in service_name for term in ['nginx', 'frontend', 'web', 'ui']):
        return 'frontend' in subnet.lower()
    
    # Default to backend
    return 'backend' in subnet.lower() or subnet == 'default'

def extract_service_vulnerabilities(service: Dict) -> List[Dict]:
    """Extract vulnerabilities from service data."""
    vulnerabilities = []
    
    for image in service.get('docker_images', []):
        for vuln in image.get('vulnerabilities', []):
            mapped_vuln = map_cvss_to_vulnerability(vuln)
            mapped_vuln['image'] = image.get('image_name', '')
            vulnerabilities.append(mapped_vuln)
    
    return vulnerabilities

def extract_service_credentials(service: Dict, cred_data: Dict) -> List[Dict]:
    """Extract credentials from service and credential data."""
    credentials = []
    service_name = service.get('name', '')
    
    # Find matching credential data
    if cred_data.get('service_name') == service_name:
        for image, creds in cred_data.get('raw_credentials_by_image', {}).items():
            for key, value in creds.items():
                credentials.append({
                    'id': f"{service_name}_{key}",
                    'username': key,
                    'password': value,
                    'service': service_name,
                    'image': image
                })
    
    return credentials

def create_node_services(credentials: List[Dict]) -> List[Dict]:
    """Create service definitions for a node."""
    services = []
    
    # Group credentials by service type
    service_ports = {
        'ssh': 22,
        'http': 80,
        'https': 443,
        'mysql': 3306,
        'postgres': 5432,
        'redis': 6379
    }
    
    for cred in credentials:
        service_name = cred.get('service', 'unknown').lower()
        port = 80  # default
        
        for srv_type, srv_port in service_ports.items():
            if srv_type in service_name:
                port = srv_port
                break
        
        services.append({
            'name': str(port),
            'allowedCredentials': [cred['id']]
        })
    
    return services

def create_vulnerability_library(vulnerabilities: List[Dict]) -> Dict[str, Dict]:
    """Create vulnerability library for a node."""
    vuln_lib = {}
    
    for vuln in vulnerabilities:
        vuln_id = vuln['id']
        
        # Create outcomes based on vulnerability properties
        outcomes = []
        if vuln.get('credential_leak'):
            outcomes.append({
                'type': 'LeakedCredentials',
                'credentials': [f"leaked_{vuln_id}"]
            })
        
        if vuln.get('privilege_escalation'):
            outcomes.append({
                'type': 'PrivilegeEscalation',
                'level': 'admin'
            })
        
        vuln_lib[vuln_id] = {
            'description': vuln['description'],
            'type': vuln['type'],
            'cvss_score': vuln['cvss_score'],
            'success_rate': vuln['success_rate'],
            'reward': vuln['reward'],
            'outcomes': outcomes,
            'severity': vuln['severity']
        }
    
    return vuln_lib

def extract_firewall_from_snapshot(snapshot_data: Dict) -> Dict[str, Dict]:
    """Extract firewall configurations from Kubernetes NetworkPolicies."""
    firewall_configs = {}
    
    # Load NetworkPolicies from snapshot
    netpols = snapshot_data.get('networkpolicies', {}).get('items', [])
    
    for netpol in netpols:
        policy_name = netpol['metadata']['name']
        spec = netpol['spec']
        
        # Extract pod selector to determine target nodes
        pod_selector = spec.get('podSelector', {})
        match_labels = pod_selector.get('matchLabels', {})
        
        # Convert NetworkPolicy to firewall rules
        firewall_rules = convert_netpol_to_firewall(spec)
        
        # Map to nodes based on labels
        target_key = get_firewall_target_key(match_labels)
        firewall_configs[target_key] = firewall_rules
    
    return firewall_configs

def convert_netpol_to_firewall(netpol_spec: Dict) -> Dict:
    """Convert NetworkPolicy spec to CyberBattleSim firewall format."""
    incoming_rules = []
    outgoing_rules = []
    
    policy_types = netpol_spec.get('policyTypes', [])
    
    # Process ingress rules
    if 'Ingress' in policy_types:
        ingress_rules = netpol_spec.get('ingress', [])
        if not ingress_rules:  # Empty ingress = deny all
            incoming_rules.append({'port': 'ALL', 'permission': 'BLOCK'})
        else:
            for rule in ingress_rules:
                ports = rule.get('ports', [])
                if ports:
                    for port in ports:
                        port_num = port.get('port', 'ALL')
                        incoming_rules.append({'port': str(port_num), 'permission': 'ALLOW'})
                else:
                    incoming_rules.append({'port': 'ALL', 'permission': 'ALLOW'})
    
    # Process egress rules
    if 'Egress' in policy_types:
        egress_rules = netpol_spec.get('egress', [])
        if not egress_rules:  # Empty egress = deny all
            outgoing_rules.append({'port': 'ALL', 'permission': 'BLOCK'})
        else:
            for rule in egress_rules:
                ports = rule.get('ports', [])
                if ports:
                    for port in ports:
                        port_num = port.get('port', 'ALL')
                        outgoing_rules.append({'port': str(port_num), 'permission': 'ALLOW'})
                else:
                    outgoing_rules.append({'port': 'ALL', 'permission': 'ALLOW'})
    
    # Default allow if no policies
    if not incoming_rules:
        incoming_rules.append({'port': 'ALL', 'permission': 'ALLOW'})
    if not outgoing_rules:
        outgoing_rules.append({'port': 'ALL', 'permission': 'ALLOW'})
    
    return {
        'incoming': incoming_rules,
        'outgoing': outgoing_rules
    }

def get_firewall_target_key(match_labels: Dict) -> str:
    """Get target key for firewall mapping from pod labels."""
    if 'subnet' in match_labels:
        return match_labels['subnet']
    if 'app.kubernetes.io/name' in match_labels:
        return match_labels['app.kubernetes.io/name']
    return 'default'

def create_firewall_config(node_labels: Dict, firewall_configs: Dict) -> Dict:
    """Create firewall configuration for a node from NetworkPolicy data."""
    # Try to find matching firewall config
    subnet = node_labels.get('subnet', 'default')
    
    if subnet in firewall_configs:
        return firewall_configs[subnet]
    
    # Check for role-based configs
    if 'node-role.kubernetes.io/master' in node_labels:
        return firewall_configs.get('master', {
            'incoming': [
                {'port': '22', 'permission': 'ALLOW'},
                {'port': '6443', 'permission': 'ALLOW'},
                {'port': '2379', 'permission': 'ALLOW'}
            ],
            'outgoing': [{'port': 'ALL', 'permission': 'ALLOW'}]
        })
    
    # Default worker firewall
    return firewall_configs.get('default', {
        'incoming': [
            {'port': '22', 'permission': 'ALLOW'},
            {'port': '80', 'permission': 'ALLOW'},
            {'port': '443', 'permission': 'ALLOW'}
        ],
        'outgoing': [{'port': 'ALL', 'permission': 'ALLOW'}]
    })

def create_network_info(subnet: str, zone: str) -> Dict:
    """Create network information for a node."""
    # Generate IP based on subnet
    subnet_ips = {
        'frontend': '10.1.0',
        'backend': '10.2.0',
        'database': '10.3.0',
        'default': '10.0.0'
    }
    
    base_ip = subnet_ips.get(subnet.replace('-tier', ''), '10.0.0')
    node_ip = f"{base_ip}.{random.randint(10, 250)}"
    
    return {
        'subnet': f"{base_ip}.0/24",
        'ip_address': node_ip,
        'zone': zone
    }

def generate_cyberbattle_scenario(snapshot_data: Dict, vuln_data: Dict, cred_data: Dict) -> str:
    """Generate complete CyberBattleSim scenario as Python code."""
    nodes = create_cyberbattle_nodes(snapshot_data, vuln_data, cred_data)
    
    scenario_name = f"K8sScenario_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Generate Python class code
    code_lines = [
        "# Generated CyberBattleSim scenario from Kubernetes cluster snapshot",
        f"# Generated at: {datetime.now().isoformat()}",
        "",
        "from cyberbattle.simulation.nodes_types import NodeID",
        "from cyberbattle.simulation.nodes import NodeInfo", 
        "from cyberbattle.simulation.firewall import FirewallRule, RulePermission, FirewallConfiguration",
        "from cyberbattle.simulation.services import ListeningService",
        "from cyberbattle.simulation.network import NodeNetworkInfo, Subnet, NetworkInterfaces",
        "from cyberbattle.simulation.vulenrabilites import VulnerabilityInfo, VulnerabilityType, LeakedCredentials, CachedCredential, LeakedNodesId",
        "from cyberbattlesim_network_gen.generators.network_generator import NetworkGenerator",
        "from cyberbattlesim_network_gen.generators.utils import *",
        "from cyberbattle.simulation.nodes_network import infer_constants_from_nodes",
        "from typing import Dict, Iterator, Tuple, cast",
        "",
        f"class {scenario_name}(NetworkGenerator):",
        "",
        "    def __init__(self, **kwargs):",
        "        super().__init__(**kwargs)",
        "",
        "    def get_default_allow_rules(self):",
        "        return [FirewallRule('SSH', RulePermission.ALLOW)]",
        "",
        "    def get_nodes(self):",
        "        return {"
    ]
    
    # Generate node definitions
    for node_name, node_data in nodes.items():
        code_lines.extend(generate_node_code(node_name, node_data))
    
    code_lines.extend([
        "        }",
        "",
        "    def get_identifiers(self):",
        "        return infer_constants_from_nodes(",
        "            cast(Iterator[Tuple[NodeID, NodeInfo]], list(self.get_nodes().items())),",
        "            self.get_vulnerability_library())",
        "",
        "    def get_vulnerability_library(self):",
        "        return dict([])",
        "",
        f"if __name__ == '__main__':",
        f"    cli_default({scenario_name})"
    ])
    
    return "\n".join(code_lines)

def generate_node_code(node_name: str, node_data: Dict) -> List[str]:
    """Generate Python code for a single node."""
    lines = [f"            '{node_name}': NodeInfo("]
    
    # Image
    if 'image' in node_data:
        lines.append(f"                image='{node_data['image']}',")
    
    # Network info
    if 'network_info' in node_data:
        net_info = node_data['network_info']
        lines.extend([
            "                network_info=[",
            "                    NodeNetworkInfo(",
            "                        interface=NetworkInterfaces.ETH1,",
            f"                        ip_address='{net_info['ip_address']}',",
            f"                        subnet=Subnet('{net_info['subnet']}')",
            "                    )],",
        ])
    
    # Services
    if node_data.get('services'):
        lines.append("                services=[")
        for service in node_data['services']:
            creds_str = ', '.join([f'"{c}"' for c in service.get('allowedCredentials', [])])
            lines.append(f"                    ListeningService('{service['name']}', allowedCredentials=[{creds_str}]),")
        lines.append("                ],")
    
    # Firewall
    if 'firewall' in node_data:
        fw = node_data['firewall']
        lines.append("                firewall=FirewallConfiguration(")
        lines.append("                    incoming=[")
        for rule in fw.get('incoming', []):
            perm = rule['permission'].upper()
            lines.append(f"                        FirewallRule('{rule['port']}', RulePermission.{perm}),")
        lines.append("                    ],")
        lines.append("                    outgoing=[")
        for rule in fw.get('outgoing', []):
            perm = rule['permission'].upper()
            lines.append(f"                        FirewallRule('{rule['port']}', RulePermission.{perm}),")
        lines.append("                    ]),")
    
    # Value
    lines.append(f"                value={node_data.get('value', 50)},")
    
    # Properties
    if node_data.get('properties'):
        props_str = ', '.join([f'"{p}"' for p in node_data['properties']])
        lines.append(f"                properties=[{props_str}],")
    
    # Vulnerabilities
    if node_data.get('vulnerabilities'):
        lines.append("                vulnerabilities=dict(")
        for vuln_id, vuln in node_data['vulnerabilities'].items():
            lines.extend(generate_vulnerability_code(vuln_id, vuln))
        lines.append("                ),")
    
    # Agent installed
    if node_data.get('agent_installed'):
        lines.append("                agent_installed=True,")
    
    lines.append("            ),")
    return lines

def generate_vulnerability_code(vuln_id: str, vuln: Dict) -> List[str]:
    """Generate code for a vulnerability."""
    lines = [f"                    {vuln_id}=VulnerabilityInfo("]
    lines.append(f"                        description='{vuln['description']}',")
    
    vuln_type = "VulnerabilityType.REMOTE" if vuln['type'] == 'remote' else "VulnerabilityType.LOCAL"
    lines.append(f"                        type={vuln_type},")
    
    # Generate outcome
    if vuln.get('outcomes'):
        outcome = vuln['outcomes'][0]
        if outcome['type'] == 'LeakedCredentials':
            creds = ', '.join([f'CachedCredential(node="unknown", port="unknown", credential="{c}")' 
                             for c in outcome.get('credentials', [])])
            lines.append(f"                        outcome=LeakedCredentials(credentials=[{creds}]),")
        elif outcome['type'] == 'LeakedNodesId':
            nodes = ', '.join([f'"{n}"' for n in outcome.get('nodes', [])])
            lines.append(f"                        outcome=LeakedNodesId([{nodes}]),")
    
    lines.append(f"                        reward_string='Exploited {vuln_id}',")
    lines.append(f"                        cost={vuln.get('reward', 10) / 10}")
    lines.append("                    ),")
    
    return lines

def calculate_attack_surface(nodes: Dict) -> Dict:
    """Calculate attack surface metrics."""
    total_services = sum(len(node.get('services', [])) for node in nodes.values())
    high_value_targets = len([n for n in nodes.values() if n.get('value', 0) > 80])
    
    return {
        'total_services': total_services,
        'high_value_targets': high_value_targets,
        'exposed_ports': calculate_exposed_ports(nodes)
    }

def calculate_exposed_ports(nodes: Dict) -> List[str]:
    """Calculate all exposed ports across nodes."""
    ports = set()
    for node in nodes.values():
        for service in node.get('services', []):
            ports.add(service['name'])
    return sorted(list(ports))

def create_network_topology(nodes: Dict) -> Dict:
    """Create network topology description."""
    subnets = {}
    for node_name, node in nodes.items():
        subnet = node['network_info']['subnet']
        if subnet not in subnets:
            subnets[subnet] = []
        subnets[subnet].append(node_name)
    
    return {
        'subnets': subnets,
        'total_subnets': len(subnets)
    }

def extract_all_credentials(nodes: Dict) -> List[Dict]:
    """Extract all credentials from nodes."""
    credentials = []
    for node_name, node in nodes.items():
        for service in node.get('services', []):
            for cred_id in service.get('allowedCredentials', []):
                credentials.append({
                    'id': cred_id,
                    'node': node_name,
                    'service': service['name']
                })
    return credentials

def create_scenario_objectives(nodes: Dict) -> List[Dict]:
    """Create scenario objectives."""
    objectives = []
    
    # Find high-value targets
    for node_name, node in nodes.items():
        if node.get('value', 0) > 80:
            objectives.append({
                'type': 'access_target',
                'target': node_name,
                'description': f'Gain access to high-value target: {node_name}',
                'points': node['value']
            })
    
    # Add privilege escalation objectives
    objectives.append({
        'type': 'privilege_escalation',
        'description': 'Achieve administrative privileges on any master node',
        'points': 100
    })
    
    return objectives

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Generate CyberBattleSim scenarios from cluster snapshots.")
    parser.add_argument("snapshot_path", help="Path to cluster snapshot directory.")
    parser.add_argument("info_path", help="Path to directory containing vulnerability/credential files.")
    parser.add_argument("-o", "--output", required=True, help="Output Python file for generated scenario.")
    
    args = parser.parse_args()
    
    print("📊 Loading snapshot data...")
    snapshot_data = load_snapshot_data(args.snapshot_path)
    
    print("🔍 Loading vulnerability and credential data...")
    vuln_data, cred_data = load_vulnerability_data(args.info_path)
    
    print("⚙️ Generating CyberBattleSim scenario...")
    scenario_code = generate_cyberbattle_scenario(snapshot_data, vuln_data, cred_data)
    
    # Save scenario as Python file
    with open(args.output, 'w') as f:
        f.write(scenario_code)
    
    print(f"✅ Scenario generated: {args.output}")
    print(f"📈 Ready to import and use in CyberBattleSim")

if __name__ == '__main__':
    main()