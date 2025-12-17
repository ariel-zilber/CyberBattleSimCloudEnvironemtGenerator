"""
Interactive Demo Runner
=======================
Loads a pre-generated CyberBattleSim scenario from YAML files and 
starts the interactive attack path solver UI.

Usage:
    python run_interactive_demo.py --scenario-dir ./demo_output --html-file ./interactive_attack_simulator.html
"""

import os
import yaml
import argparse
import sys
import logging
from typing import Dict, List, Any

# Ensure we can import from the current directory structure
sys.path.append(os.getcwd())

try:
    from cyberbattlesim_cloud_gen.interactive_attack_solver import run_interactive_server
    
    # CyberBattleSim Dependencies
    from cyberbattle.simulation.nodes import NodeInfo, NodeNetworkInfo
    from cyberbattle.simulation.firewall import FirewallConfiguration, FirewallRule, RulePermission
    from cyberbattle.simulation.services import ListeningService
    from cyberbattle.simulation.network import Subnet, NetworkInterfaces
    from cyberbattle.simulation.vulenrabilites import (
        VulnerabilityInfo, VulnerabilityType, 
        LeakedNodesId, LeakedCredentials, CachedCredential,
        PrivilegeEscalation, AdminEscalation, SystemEscalation,
        CustomerData, LateralMove, PrivilegeLevel
    )
except ImportError as e:
    print(f"Error importing dependencies: {e}")
    print("Please ensure you are in the root directory of the project and dependencies are installed.")
    sys.exit(1)

def parse_subnet(subnet_data: Any) -> Subnet:
    """Parse subnet data from YAML which might be a dict or string"""
    if isinstance(subnet_data, dict):
        return Subnet(subnet_data.get('network', '0.0.0.0/0'))
    return Subnet(str(subnet_data))

def parse_permission(perm: Any) -> RulePermission:
    """Parse permission which might be int or Enum name"""
    if isinstance(perm, int):
        return RulePermission(perm)
    if isinstance(perm, str):
        return getattr(RulePermission, perm.upper(), RulePermission.BLOCK)
    return RulePermission.BLOCK

def load_firewall(fw_data: Dict) -> FirewallConfiguration:
    """Reconstruct FirewallConfiguration from dictionary"""
    incoming = []
    outgoing = []
    
    for rule in fw_data.get('incoming', []):
        incoming.append(FirewallRule(
            port=str(rule.get('port', '*')),
            permission=parse_permission(rule.get('permission')),
            subnet=parse_subnet(rule.get('subnet')),
            priority=rule.get('priority', 1)
        ))
        
    for rule in fw_data.get('outgoing', []):
        outgoing.append(FirewallRule(
            port=str(rule.get('port', '*')),
            permission=parse_permission(rule.get('permission')),
            subnet=parse_subnet(rule.get('subnet')),
            priority=rule.get('priority', 1)
        ))
        
    return FirewallConfiguration(incoming, outgoing)

def load_services(services_list: List[Dict]) -> List[ListeningService]:
    """Reconstruct ListeningServices from list of dicts"""
    services = []
    for s in services_list:
        services.append(ListeningService(
            name=s['name'],
            port=str(s['port']),
            allowedCredentials=s.get('allowedCredentials', []),
            running=s.get('running', True)
        ))
    return services

def load_outcome(outcome_data: Dict) -> Any:
    """Reconstruct Outcome object from dictionary"""
    if not outcome_data:
        return None
        
    o_type = outcome_data.get('type')
    kwargs = outcome_data.get('kwargs', {})
    
    if o_type == 'leaked_nodes_id':
        return LeakedNodesId(nodes=kwargs.get('nodes', []))
    
    elif o_type == 'leaked_credentials':
        creds_data = kwargs.get('credentials', [])
        creds = []
        for c in creds_data:
            # Handle CachedCredential
            if c.get('type') == 'cached_credentials':
                ckwargs = c.get('kwargs', {})
                creds.append(CachedCredential(
                    node=ckwargs.get('node'),
                    port=str(ckwargs.get('port')),
                    credential=ckwargs.get('credential')
                ))
        return LeakedCredentials(credentials=creds)
        
    elif o_type == 'lateral_move':
        return LateralMove()
    elif o_type == 'privilege_escalation':
        return PrivilegeEscalation(level=PrivilegeLevel.LocalUser)
    elif o_type == 'admin_escalation':
        return AdminEscalation()
    elif o_type == 'system_escalation':
        return SystemEscalation()
    elif o_type == 'customer_data':
        return CustomerData()
        
    return None

def load_vulnerabilities(vuln_dict: Dict) -> Dict[str, VulnerabilityInfo]:
    """Reconstruct VulnerabilityInfo objects"""
    vulns = {}
    for name, data in vuln_dict.items():
        # Map integer type to Enum if necessary, or pass int if library supports it
        v_type = data.get('type')
        if isinstance(v_type, int):
            try:
                v_type = VulnerabilityType(v_type)
            except ValueError:
                # Fallback or keep as int if library is lenient
                pass
                
        vulns[name] = VulnerabilityInfo(
            description=data.get('description', ''),
            type=v_type,
            outcome=load_outcome(data.get('outcome')),
            reward_string=data.get('reward_string', ''),
            cost=float(data.get('cost', 1.0))
        )
    return vulns

def load_node_from_yaml(file_path: str, node_id: str) -> NodeInfo:
    """Load a single node from a YAML file"""
    with open(file_path, 'r') as f:
        data = yaml.safe_load(f)
        
    # Reconstruct Network Info
    net_info = []
    for net in data.get('network_info', []):
        net_info.append(NodeNetworkInfo(
            interface=NetworkInterfaces.ETH1, # Default assumption
            ip_address=net.get('ip_address'),
            subnet=parse_subnet(net.get('subnet'))
        ))

    return NodeInfo(
        services=load_services(data.get('services', [])),
        vulnerabilities=load_vulnerabilities(data.get('vulnerabilities', {})),
        agent_installed=data.get('agent_installed', False),
        firewall=load_firewall(data.get('firewall', {})),
        network_info=net_info,
        properties=data.get('properties', []),
        value=data.get('value', 0),
        reimagable=data.get('reimagable', False)
    )

def load_scenario(nodes_dir: str) -> Dict[str, NodeInfo]:
    """Load all node YAMLs from the directory"""
    nodes = {}
    
    if not os.path.exists(nodes_dir):
        raise FileNotFoundError(f"Nodes directory not found: {nodes_dir}")
        
    files = [f for f in os.listdir(nodes_dir) if f.endswith('.yaml') or f.endswith('.yml')]
    
    print(f"Found {len(files)} node definitions in {nodes_dir}")
    
    for filename in files:
        node_id = os.path.splitext(filename)[0]
        file_path = os.path.join(nodes_dir, filename)
        try:
            nodes[node_id] = load_node_from_yaml(file_path, node_id)
            # print(f"  Loaded {node_id}")
        except Exception as e:
            print(f"  ❌ Failed to load {filename}: {e}")
            
    return nodes

def main():
    parser = argparse.ArgumentParser(description="Run Interactive CyberBattleSim Demo from Existing Scenario")
    parser.add_argument('--scenario-dir', type=str, required=True, 
                        help='Path to the directory containing the "nodes" folder (e.g., ./demo_output)')
    parser.add_argument('--html-file', type=str, required=True,
                        help='Path to the interactive_attack_simulator.html file')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the web server on')
    
    args = parser.parse_args()
    
    # Path handling
    nodes_dir = os.path.join(args.scenario_dir, "nodes")
    if not os.path.exists(nodes_dir):
        # Fallback: check if the user pointed directly to the nodes folder
        if os.path.basename(args.scenario_dir.rstrip('/')) == 'nodes':
            nodes_dir = args.scenario_dir
        else:
            print(f"Error: Could not find 'nodes' subdirectory in {args.scenario_dir}")
            sys.exit(1)

    print(f"🚀 Loading scenario from: {nodes_dir}")
    nodes = load_scenario(nodes_dir)

    for n in nodes:
        print(f"  ✓ Loaded node: {n} with {len(nodes[n].vulnerabilities)} vulnerabilities and {len(nodes[n].services)} services")
    if not nodes:
        print("Error: No nodes loaded. Exiting.")
        sys.exit(1)
        
    # Identify Attacker
    attacker_node = "attacker"
    if attacker_node not in nodes:
        # Try to find node with 'attacker' property
        for nid, n in nodes.items():
            if "attacker" in n.properties:
                attacker_node = nid
                break
    
    if attacker_node not in nodes:
        print("Error: Could not identify 'attacker' node in the scenario.")
        sys.exit(1)
        
    print(f"⚔️  Attacker Node identified as: {attacker_node}")
    
    # Run Server
    print("\nStarting Interactive Server...")
    run_interactive_server(nodes, attacker_node, port=args.port, html_path=args.html_file)

if __name__ == "__main__":
    main()