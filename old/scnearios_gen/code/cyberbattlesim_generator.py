"""
CyberBattleSim Attack Scenario Generator
========================================
Creates a CyberBattleSim attack scenario from cluster.json configuration.
Uses existing physical topology without modification, only adding attacker nodes.

Author: Based on Microsoft CyberBattleSim
Date: 2025-11-09
"""

import json
import argparse
import logging
import os
import sys
from typing import Dict, List, Set, Tuple, Optional
import ipaddress

# CyberBattleSim imports
from cyberbattle.simulation.nodes import NodeInfo
from cyberbattle.simulation.firewall import FirewallRule, RulePermission, FirewallConfiguration
from cyberbattle.simulation.vulenrabilites import VulnerabilityInfo, VulnerabilityType, LeakedNodesId, LeakedCredentials, CachedCredential
from cyberbattle.simulation.nodes_types import NodeID
from cyberbattle.simulation.services import ListeningService
from cyberbattle.simulation.network import NodeNetworkInfo, Subnet, NetworkInterfaces
from cyberbattle.simulation.identifiers import Identifiers
from cyberbattle.simulation.nodes_network import infer_constants_from_nodes

# Service to port mappings for common services
SERVICE_PORTS = {
    "etcd": [2379, 2380],
    "kube-state-metrics": [8080, 8081],
    "metrics-server": [443, 4443],
    "postgresql": [5432],
    "mysql": [3306],
    "mongodb": [27017],
    "redis": [6379],
    "valkey": [6379],
    "elasticsearch": [9200, 9300],
    "clickhouse": [8123, 9000],
    "cassandra": [7000, 7001, 9042],
    "spark": [7077, 8080, 8081],
    "flink": [6123, 8081],
    "airflow": [8080],
    "mlflow": [5000],
    "jupyterhub": [8000, 8080],
    "kafka": [9092, 9093],
    "rabbitmq": [5672, 15672],
    "zookeeper": [2181, 2888, 3888],
    "minio": [9000, 9001],
    "nginx": [80, 443],
    "prometheus": [9090],
    "grafana": [3000],
    "jaeger": [6831, 6832, 14268, 16686],
    "loki": [3100],
    "tempo": [3200, 9095]
}

class ClusterAttackScenarioGenerator:
    """Generates CyberBattleSim attack scenario from cluster.json"""
    
    def __init__(self, cluster_config: Dict):
        self.cluster_config = cluster_config
        self.nodes: Dict[str, NodeInfo] = {}
        self.attack_edges: List[Dict] = []
        
    def _get_service_port(self, service_name: str) -> int:
        """Get default port for a service"""
        return SERVICE_PORTS.get(service_name, [80])[0]
    
    def _create_cyberbattle_node(self, physical_node: Dict) -> NodeInfo:
        """Convert physical node to CyberBattleSim node"""
        node_id = physical_node["node_id"]
        zone = physical_node["zone"]
        ip_allocation = physical_node.get("ip_allocation", {})
        ip_address = ip_allocation.get("ipv4", "10.0.0.1")
        subnet_cidr = ip_allocation.get("cidr", "10.0.0.0/24")
        
        # Get services from assigned pods
        services = []
        vulnerabilities = {}
        
        for pod_assignment in physical_node["assigned_pods"]:
            service_name = pod_assignment["service"]
            instance_id = pod_assignment["instance"]
            
            # Create listening service
            port = self._get_service_port(service_name)
            service_instance_name = f"{service_name}-{instance_id}"
            credential = f"{service_name}_{instance_id}_creds"
            
            service = ListeningService(
                name=service_instance_name,
                port=str(port),
                allowedCredentials=[credential]
            )
            services.append(service)
            
            # Create exploit vulnerability
            vuln_name = f"Exploit_{service_name}_{instance_id}"
            vulnerabilities[vuln_name] = VulnerabilityInfo(
                description=f"Exploit {service_name} service on {node_id}",
                type=VulnerabilityType.REMOTE,
                cost=5.0,
                outcome=LeakedCredentials(credentials=[
                    CachedCredential(
                        node=node_id,
                        port=str(port),
                        credential=credential
                    )
                ]),
                reward_string=f"Gained access to {service_name} on {node_id}"
            )
            
            # Add CVE vulnerabilities if present in cluster config
            if "vulnerabilities" in self.cluster_config.get("network_topology", {}).get("services", {}).get(service_name, {}):
                for cve in self.cluster_config["network_topology"]["services"][service_name]["vulnerabilities"]:
                    cve_id = cve["cve_id"]
                    cve_vuln_name = f"{cve_id}_{instance_id}"
                    
                    # Map outcome types
                    outcome_type = cve.get("outcome_type", "LeakedCredentials")
                    if outcome_type == "SystemEscalation":
                        from cyberbattle.simulation.vulenrabilites import SystemEscalation
                        outcome = SystemEscalation()
                    elif outcome_type == "AdminEscalation":
                        from cyberbattle.simulation.vulenrabilites import AdminEscalation
                        outcome = AdminEscalation()
                    else:
                        outcome = LeakedCredentials(credentials=[])
                    
                    vulnerabilities[cve_vuln_name] = VulnerabilityInfo(
                        description=cve.get("description", "Unknown CVE"),
                        type=VulnerabilityType.REMOTE,
                        cost=cve.get("exploitability", 0.5) * 10,
                        outcome=outcome,
                        reward_string=f"Exploited {cve_id} on {node_id}"
                    )
        
        # Create firewall configuration based on node connections
        firewall_rules = self._create_firewall_rules(physical_node)
        
        return NodeInfo(
            network_info=[
                NodeNetworkInfo(
                    interface=NetworkInterfaces.ETH1,
                    ip_address=ip_address,
                    subnet=Subnet(subnet_cidr)
                )
            ],
            services=services,
            vulnerabilities=vulnerabilities,
            properties=[
                "kubernetes",
                physical_node["node_type"],
                zone,
                f"ip_{ip_address.replace('.', '_')}"
            ],
            value=100 if physical_node["node_type"] == "control_plane" else 50,
            firewall=firewall_rules,
            reimagable=False
        )
    
    def _create_firewall_rules(self, physical_node: Dict) -> FirewallConfiguration:
        """Create firewall rules based on physical topology connections"""
        incoming_rules = []
        outgoing_rules = []
        
        node_id = physical_node["node_id"]
        node_ip = physical_node.get("ip_allocation", {}).get("ipv4", "10.0.0.1")
        
        # Check if we have node connections in physical topology
        if "node_connections" in self.cluster_config.get("physical_topology", {}):
            for conn in self.cluster_config["physical_topology"]["node_connections"]:
                if conn["to"] == node_id and not conn["is_firewalled"]:
                    # Allow incoming connection
                    incoming_rules.append(
                        FirewallRule(
                            port="*",  # Allow all ports for simplicity
                            permission=RulePermission.ALLOW,
                            subnet=Subnet(f"{conn['from_ip']}/32"),
                            reason=f"Allowed from {conn['from']}"
                        )
                    )
                
                if conn["from"] == node_id and not conn["is_firewalled"]:
                    # Allow outgoing connection  
                    outgoing_rules.append(
                        FirewallRule(
                            port="*",
                            permission=RulePermission.ALLOW,
                            subnet=Subnet(f"{conn['to_ip']}/32"),
                            reason=f"Allowed to {conn['to']}"
                        )
                    )
        
        # Default deny for incoming, allow for outgoing
        if not incoming_rules:
            incoming_rules.append(FirewallRule(port="*", permission=RulePermission.BLOCK))
        
        if not outgoing_rules:
            outgoing_rules.append(FirewallRule(port="*", permission=RulePermission.ALLOW))
        
        return FirewallConfiguration(
            incoming=incoming_rules,
            outgoing=outgoing_rules
        )
    
    def _create_attacker_nodes(self) -> None:
        """Create attacker entry points"""
        public_nodes = self._find_public_nodes()
        
        # Main attacker node
        self.nodes["attacker"] = NodeInfo(
            network_info=[
                NodeNetworkInfo(
                    interface=NetworkInterfaces.ETH1,
                    ip_address="192.168.1.100",
                    subnet=Subnet("192.168.1.0/24")
                )
            ],
            services=[],
            vulnerabilities={
                "InitialScan": VulnerabilityInfo(
                    description="Initial network reconnaissance",
                    type=VulnerabilityType.LOCAL,
                    outcome=LeakedNodesId(nodes=list(public_nodes)),
                    cost=1.0,
                    reward_string="Discovered public-facing nodes"
                )
            },
            properties=["attacker", "external"],
            value=0,
            agent_installed=True,
            reimagable=False
        )
        
        # Add additional attacker nodes based on public services
        for i, public_node in enumerate(public_nodes[:3]):  # Limit to 3 entry points
            attacker_node_id = f"attacker_entry_{i+1}"
            self.nodes[attacker_node_id] = NodeInfo(
                network_info=[
                    NodeNetworkInfo(
                        interface=NetworkInterfaces.ETH1,
                        ip_address=f"192.168.1.{101 + i}",
                        subnet=Subnet("192.168.1.0/24")
                    )
                ],
                services=[],
                vulnerabilities={
                    "InitialAccess": VulnerabilityInfo(
                        description=f"Initial access through {public_node}",
                        type=VulnerabilityType.LOCAL,
                        outcome=LeakedNodesId(nodes=[public_node]),
                        cost=2.0,
                        reward_string=f"Gained initial access via {public_node}"
                    )
                },
                properties=["attacker", "compromised", "beachhead"],
                value=10,
                agent_installed=True,
                reimagable=False
            )
    
    def _find_public_nodes(self) -> List[str]:
        """Find nodes with public-facing services"""
        public_nodes = set()
        
        # Check network topology for public services
        if "network_topology" in self.cluster_config:
            for service_name, service_config in self.cluster_config["network_topology"].get("services", {}).items():
                if service_config.get("is_public", False):
                    # Find nodes running this service
                    if "physical_topology" in self.cluster_config:
                        for node in self.cluster_config["physical_topology"]["nodes"]:
                            for pod in node["assigned_pods"]:
                                if pod["service"] == service_name:
                                    public_nodes.add(node["node_id"])
        
        # If no public services found, use control plane nodes as entry points
        if not public_nodes and "physical_topology" in self.cluster_config:
            for node in self.cluster_config["physical_topology"]["nodes"]:
                if node["node_type"] == "control_plane":
                    public_nodes.add(node["node_id"])
        
        # Fallback: use first few worker nodes
        if not public_nodes and "physical_topology" in self.cluster_config:
            worker_nodes = [node["node_id"] for node in self.cluster_config["physical_topology"]["nodes"] 
                          if node["node_type"] == "worker"]
            public_nodes.update(worker_nodes[:2])
        
        return list(public_nodes)
    
    def _build_credential_flows(self) -> None:
        """Build credential flow vulnerabilities based on cluster configuration"""
        if "network_topology" not in self.cluster_config:
            return
            
        credential_flows = self.cluster_config["network_topology"].get("credential_flow", [])
        
        for flow in credential_flows:
            source_service = flow["source"]
            target_service = flow["target"]
            
            # Find nodes running these services
            source_nodes = self._find_nodes_with_service(source_service)
            target_nodes = self._find_nodes_with_service(target_service)
            
            if not source_nodes or not target_nodes:
                continue
                
            # Create credential leak vulnerability
            for source_node in source_nodes:
                if source_node not in self.nodes:
                    continue
                    
                vuln_name = f"CredentialLeak_{source_service}_to_{target_service}"
                credential = f"{source_service}_to_{target_service}_key"
                
                # Add vulnerability to source node
                self.nodes[source_node].vulnerabilities[vuln_name] = VulnerabilityInfo(
                    description=f"Stored credentials for {target_service}",
                    type=VulnerabilityType.LOCAL,
                    cost=3.0,
                    outcome=LeakedCredentials(credentials=[
                        CachedCredential(
                            node=target_nodes[0],  # Use first target node
                            port=str(self._get_service_port(target_service)),
                            credential=credential
                        )
                    ]),
                    reward_string=f"Found credentials for {target_service}"
                )
                
                # Add credential to target service
                for target_node in target_nodes:
                    if target_node in self.nodes:
                        for service in self.nodes[target_node].services:
                            if target_service in service.name:
                                if credential not in service.allowedCredentials:
                                    service.allowedCredentials.append(credential)
    
    def _find_nodes_with_service(self, service_name: str) -> List[str]:
        """Find nodes running a specific service"""
        nodes_with_service = []
        
        if "physical_topology" in self.cluster_config:
            for node in self.cluster_config["physical_topology"]["nodes"]:
                for pod in node["assigned_pods"]:
                    if pod["service"] == service_name:
                        nodes_with_service.append(node["node_id"])
                        break
        
        return nodes_with_service
    
    def generate_scenario(self) -> Dict[str, NodeInfo]:
        """Generate the complete attack scenario"""
        print("🔄 Generating CyberBattleSim attack scenario...")
        
        # Create nodes from physical topology
        if "physical_topology" in self.cluster_config:
            for physical_node in self.cluster_config["physical_topology"]["nodes"]:
                if physical_node["is_healthy"]:  # Only include healthy nodes
                    cyber_node = self._create_cyberbattle_node(physical_node)
                    self.nodes[physical_node["node_id"]] = cyber_node
        
        # Create attacker nodes
        self._create_attacker_nodes()
        
        # Build credential flows
        self._build_credential_flows()
        
        print(f"✅ Created {len(self.nodes)} nodes for CyberBattleSim")
        return self.nodes
    
    def get_identifiers(self) -> Identifiers:
        """Get identifiers for CyberBattleSim"""
        return infer_constants_from_nodes(
            [(node_id, node_info) for node_id, node_info in self.nodes.items()],
            {}
        )


class AttackPathAnalyzer:
    """Analyzes possible attack paths in the generated scenario"""
    
    def __init__(self, nodes: Dict[str, NodeInfo]):
        self.nodes = nodes
        
    def analyze_attack_surface(self):
        """Analyze the attack surface"""
        print("\n🔍 Attack Surface Analysis:")
        print("=" * 50)
        
        # Count vulnerabilities
        total_vulns = 0
        vuln_by_type = {}
        
        for node_id, node in self.nodes.items():
            total_vulns += len(node.vulnerabilities)
            for vuln_name, vuln_info in node.vulnerabilities.items():
                vuln_type = vuln_info.type.name
                vuln_by_type[vuln_type] = vuln_by_type.get(vuln_type, 0) + 1
        
        print(f"Total nodes: {len(self.nodes)}")
        print(f"Total vulnerabilities: {total_vulns}")
        print("Vulnerabilities by type:")
        for vuln_type, count in vuln_by_type.items():
            print(f"  {vuln_type}: {count}")
        
        # Find entry points
        entry_points = []
        for node_id, node in self.nodes.items():
            if "attacker" in node.properties:
                for vuln_name, vuln_info in node.vulnerabilities.items():
                    if "Initial" in vuln_name:
                        if hasattr(vuln_info.outcome, 'nodes'):
                            entry_points.extend(vuln_info.outcome.nodes)
        
        print(f"\nInitial entry points: {entry_points}")
        
        # Find high-value targets
        high_value_nodes = []
        for node_id, node in self.nodes.items():
            if node.value >= 100 or "control_plane" in node.properties:
                high_value_nodes.append((node_id, node.value))
        
        if high_value_nodes:
            print("\nHigh-value targets:")
            for node_id, value in sorted(high_value_nodes, key=lambda x: x[1], reverse=True):
                print(f"  {node_id}: value {value}")


def save_cyberbattlesim_environment(nodes: Dict[str, NodeInfo], output_path: str):
    """Save the environment in CyberBattleSim format"""
    environment = {
        "nodes": {},
        "vulnerability_library": {}
    }
    
    for node_id, node_info in nodes.items():
        # Convert node to serializable format
        node_data = {
            "services": [
                {
                    "name": service.name,
                    "port": service.port,
                    "allowedCredentials": service.allowedCredentials
                }
                for service in node_info.services
            ],
            "vulnerabilities": {
                vuln_name: {
                    "description": vuln_info.description,
                    "type": vuln_info.type.name,
                    "cost": vuln_info.cost,
                    "outcome": str(vuln_info.outcome),
                    "reward_string": vuln_info.reward_string
                }
                for vuln_name, vuln_info in node_info.vulnerabilities.items()
            },
            "properties": node_info.properties,
            "value": node_info.value,
            "firewall": {
                "incoming": [
                    {
                        "port": rule.port,
                        "permission": rule.permission.name,
                        "subnet": str(rule.subnet) if rule.subnet else None,
                        "reason": rule.reason
                    }
                    for rule in node_info.firewall.incoming
                ],
                "outgoing": [
                    {
                        "port": rule.port,
                        "permission": rule.permission.name,
                        "subnet": str(rule.subnet) if rule.subnet else None,
                        "reason": rule.reason
                    }
                    for rule in node_info.firewall.outgoing
                ]
            },
            "network_info": [
                {
                    "interface": info.interface.name,
                    "ip_address": info.ip_address,
                    "subnet": str(info.subnet)
                }
                for info in node_info.network_info
            ],
            "agent_installed": node_info.agent_installed,
            "reimagable": node_info.reimagable
        }
        environment["nodes"][node_id] = node_data
    
    with open(output_path, 'w') as f:
        json.dump(environment, f, indent=2)
    
    print(f"✅ CyberBattleSim environment saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate CyberBattleSim attack scenario from cluster.json"
    )
    
    parser.add_argument(
        "--input", "-i",
        type=str,
        required=True,
        help="Path to cluster.json file with physical topology"
    )
    
    parser.add_argument(
        "--output", "-o", 
        type=str,
        required=True,
        help="Output path for CyberBattleSim environment file"
    )
    
    parser.add_argument(
        "--analyze", "-a",
        action="store_true",
        help="Perform attack surface analysis"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Load cluster configuration
    try:
        with open(args.input, 'r') as f:
            cluster_config = json.load(f)
        print(f"✅ Loaded cluster configuration from {args.input}")
    except Exception as e:
        print(f"❌ Error loading cluster configuration: {e}")
        sys.exit(1)
    
    # Check if physical topology exists
    if "physical_topology" not in cluster_config:
        print("❌ Error: cluster.json must contain 'physical_topology' section")
        print("   Run physical_node_generator.py first to generate physical topology")
        sys.exit(1)
    
    # Generate attack scenario
    generator = ClusterAttackScenarioGenerator(cluster_config)
    nodes = generator.generate_scenario()
    
    # Save environment
    save_cyberbattlesim_environment(nodes, args.output)
    
    # Perform analysis if requested
    if args.analyze:
        analyzer = AttackPathAnalyzer(nodes)
        analyzer.analyze_attack_surface()
    
    print(f"\n🎯 CyberBattleSim attack scenario generation complete!")
    print(f"   Input: {args.input}")
    print(f"   Output: {args.output}")
    print(f"   Total nodes: {len(nodes)}")
    
    # Count attacker vs target nodes
    attacker_nodes = sum(1 for node in nodes.values() if "attacker" in node.properties)
    target_nodes = len(nodes) - attacker_nodes
    print(f"   Attacker nodes: {attacker_nodes}")
    print(f"   Target nodes: {target_nodes}")


if __name__ == "__main__":
    main()