"""
CyberBattleSim Attack Scenario Generator
========================================
Extends NetworkGenerator to create CyberBattleSim attack scenarios from cluster.json.
Includes comprehensive attack path analysis and visualization.

Author: Based on Microsoft CyberBattleSim
Date: 2025-11-09
"""

import json
import argparse
import logging
import os
from typing import Dict, List, Tuple, Iterator, cast
from cyberbattlesim_cloud_gen.config.ports import SERVICE_PORTS
from cyberbattlesim_cloud_gen.generators.attack_path_solver import AttackPathSolver
from cyberbattlesim_cloud_gen.generators.attack_path_visual import AttackVisualizer
import matplotlib

# Use non-interactive backend for saving files
matplotlib.use('Agg')

# --- External Dependencies ---
try:
    from cyberbattle.simulation.nodes import NodeInfo
    from cyberbattle.simulation.firewall import FirewallRule, RulePermission, FirewallConfiguration
    from cyberbattle.simulation.vulenrabilites import (
        VulnerabilityInfo, VulnerabilityType, LeakedNodesId, LeakedCredentials, 
        CachedCredential, PrivilegeEscalation, AdminEscalation, SystemEscalation,
        CustomerData, LateralMove, PrivilegeLevel
    )
    from cyberbattle.simulation.nodes_types import NodeID
    from cyberbattle.simulation.services import ListeningService
    from cyberbattle.simulation.network import NodeNetworkInfo, Subnet, NetworkInterfaces
    from cyberbattle.simulation.identifiers import Identifiers
    from cyberbattle.simulation.nodes_network import infer_constants_from_nodes

    from cyberbattlesim_network_gen.generators.network_generator import NetworkGenerator
    from cyberbattlesim_network_gen.generators.file_utils import save_yaml
    from cyberbattlesim_network_gen.generators.utils import cli_default
except ImportError as e:
    raise ImportError(f"Missing required CyberBattleSim dependencies: {e}")

class ClusterAttackGenerator(NetworkGenerator):
    """
    Generates CyberBattleSim attack scenario from cluster.json
    Extends NetworkGenerator for compatibility with cyberbattlesim_network_gen framework
    """
    
    def __init__(self,
                 out_dir: str,
                 config_file: str = None,
                 cluster_config: Dict = None,  # Supports in-memory config
                 log_level: str = "INFO",
                 **kwargs):
        """
        Initialize the generator.

        :param out_dir: The output directory.
        :param config_file: Path to the JSON file (optional).
        :param cluster_config: Dictionary containing the cluster plan (optional).
        """
        super().__init__(output_dir=out_dir, **kwargs)
        
        self.output_dir = out_dir
        logging.basicConfig(level=getattr(logging, log_level.upper()))

        if cluster_config:
            self.cluster_config = cluster_config
            print(f"✅ Using in-memory cluster configuration")
        elif config_file:
            try:
                with open(config_file, 'r') as f:
                    self.cluster_config = json.load(f)
                print(f"✅ Successfully loaded cluster configuration from {config_file}")
            except Exception as e:
                print(f"❌ Error: Could not load or parse config file {config_file}. {e}")
                raise
        else:
            raise ValueError("Must provide either config_file or cluster_config")

        self.nodes: Dict[str, NodeInfo] = {}
        self.attack_edges: List[Dict] = []

        # Validate required sections
        if "physical_topology" not in self.cluster_config:
            raise ValueError("Missing 'physical_topology' in cluster config")

    def _get_service_port(self, service_name: str) -> int:
        """Get default port for a service"""
        return SERVICE_PORTS.get(service_name, [80])[0]
    
    def _map_outcome_string_to_class(self, outcome_string: str, **kwargs):
        """Maps the 'outcome_type' string from the JSON to a CyberBattleSim class with correct parameters."""
        outcome_map = {
            "SystemEscalation": SystemEscalation(),
            "AdminEscalation": AdminEscalation(),
            "PrivilegeEscalation": PrivilegeEscalation(level=PrivilegeLevel.LocalUser),
            "CustomerData": CustomerData(),
            "LateralMove": LateralMove(),
            "LeakedNodesId": LeakedNodesId(nodes=kwargs.get('nodes', [])),
            "LeakedCredentials": LeakedCredentials(credentials=kwargs.get('credentials', [])),
        }
        return outcome_map.get(outcome_string, LeakedNodesId(nodes=[]))
    
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
            if "network_topology" in self.cluster_config:
                network_services = self.cluster_config["network_topology"].get("services", {})
                if service_name in network_services and "vulnerabilities" in network_services[service_name]:
                    for cve in network_services[service_name]["vulnerabilities"]:
                        cve_id = cve["cve_id"]
                        cve_vuln_name = f"{cve_id}_{instance_id}"
                        
                        # Get outcome type and create appropriate outcome object
                        outcome_type = cve.get("outcome_type", "LeakedCredentials")
                        
                        # Handle different outcome types with correct parameters
                        if outcome_type == "LeakedNodesId":
                            # For node discovery outcomes, discover related nodes
                            discovered_nodes = self._find_related_nodes(service_name)
                            outcome = self._map_outcome_string_to_class(outcome_type, nodes=discovered_nodes)
                        elif outcome_type == "LeakedCredentials":
                            # For credential leaks, create appropriate credentials
                            target_service = cve.get("target_service", service_name)
                            target_port = self._get_service_port(target_service)
                            credential_name = f"{service_name}_to_{target_service}_creds"
                            
                            # Find target nodes for this credential
                            target_nodes = self._find_nodes_with_service(target_service)
                            if target_nodes:
                                credentials = [
                                    CachedCredential(
                                        node=target_nodes[0],  # Use first target node
                                        port=str(target_port),
                                        credential=credential_name
                                    )
                                ]
                                outcome = self._map_outcome_string_to_class(outcome_type, credentials=credentials)
                            else:
                                outcome = self._map_outcome_string_to_class(outcome_type)
                        else:
                            # For escalation and other outcomes
                            outcome = self._map_outcome_string_to_class(outcome_type)
                    
                        vulnerabilities[cve_vuln_name] = VulnerabilityInfo(
                            description=cve.get("description", "Unknown CVE"),
                            type=VulnerabilityType.REMOTE,
                            cost=cve.get("exploitability", 0.5) * 10,
                            outcome=outcome,
                            reward_string=f"Exploited {cve_id} on {node_id}"
                        )
        
        # Create firewall configuration based on node connections
        firewall_rules = self._create_firewall_rules(physical_node)
        
        # Determine node value based on type and services
        node_value = 50  # Default value
        if physical_node["node_type"] == "control_plane":
            node_value = 150
        elif physical_node["node_type"] in ["gpu", "compute"]:
            node_value = 100
        
        # Add value for critical services
        critical_services = ["etcd", "kafka", "postgresql", "mysql", "elasticsearch"]
        for pod in physical_node["assigned_pods"]:
            if pod["service"] in critical_services:
                node_value += 25
        
        # Create properties list
        properties = [
            "kubernetes",
            physical_node["node_type"],
            zone,
            f"ip_{ip_address.replace('.', '_')}"
        ]
        
        # Add service properties
        for pod in physical_node["assigned_pods"]:
            properties.append(f"service_{pod['service']}")
            properties.append(f"running_{pod['service']}")
        
        # Add zone and network properties
        properties.append(f"zone_{zone}")
        properties.append(f"subnet_{subnet_cidr.replace('/', '_')}")
        
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
            properties=properties,
            value=node_value,
            firewall=firewall_rules,
            reimagable=False
        )
    
    def _find_related_nodes(self, service_name: str) -> List[str]:
        """Find nodes related to a service for discovery outcomes"""
        related_nodes = set()
        
        # Find nodes running the same service
        same_service_nodes = self._find_nodes_with_service(service_name)
        related_nodes.update(same_service_nodes)
        
        # Find nodes that communicate with this service
        if "network_topology" in self.cluster_config:
            access_connectivity = self.cluster_config["network_topology"].get("access_connectivity", [])
            for conn in access_connectivity:
                if conn["source"] == service_name:
                    target_nodes = self._find_nodes_with_service(conn["target"])
                    related_nodes.update(target_nodes)
                elif conn["target"] == service_name:
                    source_nodes = self._find_nodes_with_service(conn["source"])
                    related_nodes.update(source_nodes)
        
        return list(related_nodes)
    
    def _create_firewall_rules(self, physical_node: Dict) -> FirewallConfiguration:
        """Create firewall rules based on physical topology connections"""
        incoming_rules = []
        outgoing_rules = []
        
        node_id = physical_node["node_id"]
        node_ip = physical_node.get("ip_allocation", {}).get("ipv4", "10.0.0.1")
        
        # Check if we have node connections in physical topology
        if "node_connections" in self.cluster_config.get("physical_topology", {}):
            for conn in self.cluster_config["physical_topology"]["node_connections"]:
                if conn["to"] == node_id:
                    # Create rule based on firewall status
                    permission = RulePermission.ALLOW if not conn["is_firewalled"] else RulePermission.BLOCK
                    
                    incoming_rules.append(
                        FirewallRule(
                            port="*",
                            permission=permission,
                            subnet=Subnet(f"{conn['from_ip']}/32"),
                            reason=f"Connection from {conn['from']}"
                        )
                    )
                
                if conn["from"] == node_id:
                    permission = RulePermission.ALLOW if not conn["is_firewalled"] else RulePermission.BLOCK
                    
                    outgoing_rules.append(
                        FirewallRule(
                            port="*",
                            permission=permission,
                            subnet=Subnet(f"{conn['to_ip']}/32"),
                            reason=f"Connection to {conn['to']}"
                        )
                    )
        
        # Add default rules - deny incoming, allow outgoing
        incoming_rules.append(FirewallRule(port="*", permission=RulePermission.BLOCK, reason="Default deny"))
        outgoing_rules.append(FirewallRule(port="*", permission=RulePermission.ALLOW, reason="Default allow"))
        
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
                ),
                "PortScan": VulnerabilityInfo(
                    description="Detailed port scanning",
                    type=VulnerabilityType.LOCAL,
                    outcome=LeakedNodesId(nodes=list(public_nodes)),
                    cost=2.0,
                    reward_string="Detailed port scan completed"
                )
            },
            properties=["attacker", "external", "reconnaissance"],
            value=0,
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
            public_nodes.update(worker_nodes[:3])
        
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
                target_port = str(self._get_service_port(target_service))
                
                # Add vulnerability to source node
                self.nodes[source_node].vulnerabilities[vuln_name] = VulnerabilityInfo(
                    description=f"Stored credentials for {target_service}",
                    type=VulnerabilityType.LOCAL,
                    cost=3.0,
                    outcome=LeakedCredentials(credentials=[
                        CachedCredential(
                            node=target_nodes[0],  # Use first target node
                            port=target_port,
                            credential=credential
                        )
                    ]),
                    reward_string=f"Found credentials for {target_service}"
                )
                
                # Add credential to target service
                for target_node in target_nodes:
                    if target_node in self.nodes:
                        for service in self.nodes[target_node].services:
                            if target_service in service.name and service.port == target_port:
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
    
    def _perform_attack_analysis(self):
        """Perform comprehensive attack analysis"""
        print("\n🔍 Performing comprehensive attack analysis...")
        
        # Create attack path solver
        solver = AttackPathSolver(self.nodes,attacker_node='attacker')
        attack_paths = solver.solve(max_depth=12000, timeout_sec=30)
        
        # Create visualizations
        visualizer = AttackVisualizer(self.output_dir)
        visualizer.visualize_attack_paths(self.nodes, attack_paths)
        
        # Save attack analysis results
        self._save_attack_analysis(attack_paths)
        
        return attack_paths
    
    def _save_attack_analysis(self, attack_paths: Dict):
        """Save attack analysis results to files"""
        analysis_dir = os.path.join(self.output_dir, "analysis")
        os.makedirs(analysis_dir, exist_ok=True)
        
        # Save attack paths as JSON
        paths_data = {}
        for path_name, path_info in attack_paths.items():
            paths_data[path_name] = {
                "best_state": path_info.get("best_state"),
                "nodes_owned": path_info.get("nodes_owned"),
                "computation_time": path_info.get("computation_time"),
                "steps": path_info["path"]
            }
        
        with open(os.path.join(analysis_dir, "attack_paths.json"), 'w') as f:
            json.dump(paths_data, f, indent=2)
        
        # Generate analysis report
        self._generate_analysis_report(attack_paths, analysis_dir)
    
    def _generate_analysis_report(self, attack_paths: Dict, analysis_dir: str):
        """Generate comprehensive analysis report"""
        report_path = os.path.join(analysis_dir, "attack_analysis_report.txt")
        
        with open(report_path, 'w') as f:
            f.write("CYBERBATTLESIM ATTACK ANALYSIS REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            # Basic statistics
            total_nodes = len([n for n in self.nodes if "attacker" not in self.nodes[n].properties])
            total_vulns = sum(len(node.vulnerabilities) for node in self.nodes.values())
            total_properties = sum(len(node.properties) for node in self.nodes.values())
            
            f.write("BASIC STATISTICS:\n")
            f.write(f"Total target nodes: {total_nodes}\n")
            f.write(f"Total vulnerabilities: {total_vulns}\n")
            f.write(f"Total properties: {total_properties}\n")
            f.write(f"Attacker entry points: {len([n for n in self.nodes if 'attacker' in self.nodes[n].properties])}\n\n")
            
            # Attack path results
            f.write("ATTACK PATH ANALYSIS:\n")
            f.write("-" * 30 + "\n")
            
            if "maximal_achievement" in attack_paths:
                optimal = attack_paths["maximal_achievement"]
                f.write(f"Maximal achievement: {optimal['nodes_owned']}/{total_nodes} nodes owned\n")
                f.write(f"Steps required: {len(optimal['path'])}\n")
                f.write(f"Computation time: {optimal['computation_time']}\n\n")
                
                f.write("ATTACK PATH:\n")
                for i, action in enumerate(optimal["path"]):
                    f.write(f"  {i+1}. {action}\n")
                
                # Analyze action types
                action_counts = {}
                for action in optimal["path"]:
                    action_type = action.split(" ")[0] if " " in action else action
                    action_counts[action_type] = action_counts.get(action_type, 0) + 1
                
                f.write(f"\nACTION BREAKDOWN:\n")
                for action_type, count in action_counts.items():
                    f.write(f"  {action_type}: {count} actions\n")
            else:
                f.write("❌ No attack path found\n\n")
            
            # Property analysis
            f.write("\nPROPERTY ANALYSIS:\n")
            f.write("-" * 30 + "\n")
            
            # Count properties by type
            property_counts = {}
            for node in self.nodes.values():
                for prop in node.properties:
                    prop_type = prop.split('_')[0] if '_' in prop else prop
                    property_counts[prop_type] = property_counts.get(prop_type, 0) + 1
            
            for prop_type, count in sorted(property_counts.items()):
                f.write(f"{prop_type}: {count} properties\n")
            
            # Critical nodes analysis
            f.write("\nCRITICAL NODES:\n")
            f.write("-" * 30 + "\n")
            
            critical_nodes = []
            for node_id, node in self.nodes.items():
                if "attacker" not in node.properties:
                    if node.value >= 100 or "control_plane" in node.properties:
                        critical_nodes.append((node_id, node.value, len(node.properties)))
            
            for node_id, value, prop_count in sorted(critical_nodes, key=lambda x: x[1], reverse=True):
                f.write(f"{node_id}: value {value}, properties {prop_count}\n")
        
        print(f"✅ Attack analysis report saved to {report_path}")

    # --- NetworkGenerator Interface Methods ---

    def get_nodes(self) -> Dict[str, NodeInfo]:
        """
        Generate the complete dictionary of nodes for the simulation.
        """
        print("🔄 Generating CyberBattleSim attack scenario from cluster.json...")
        
        # Create nodes from physical topology (only healthy nodes)
        if "physical_topology" in self.cluster_config:
            for physical_node in self.cluster_config["physical_topology"]["nodes"]:
                if physical_node["is_healthy"]:
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
            cast(Iterator[Tuple[NodeID, NodeInfo]], list(self.nodes.items())),
            {}
        )

    def get_vulnerability_library(self):
        """Get vulnerability library (empty for now)"""
        return dict([])

    def generate(self):
        """
        Overrides the base generate() method to create the attack scenario.
        """
        generated_data = super().generate()
        
        # Perform comprehensive attack analysis
        attack_paths = self._perform_attack_analysis()
        
        # Print final summary
        attacker_nodes = sum(1 for node in self.nodes.values() if "attacker" in node.properties)
        target_nodes = len(self.nodes) - attacker_nodes
        
        print(f"\n🎯 CyberBattleSim Attack Scenario Generation Complete!")
        print(f"   Total nodes: {len(self.nodes)}")
        print(f"   Attacker nodes: {attacker_nodes}")
        print(f"   Target nodes: {target_nodes}")
        print(f"   Output directory: {self.output_dir}")
        
        # Print attack analysis summary
        if "maximal_achievement" in attack_paths:
            optimal = attack_paths["maximal_achievement"]
            print(f"   ✅ Maximal achievement: {optimal['nodes_owned']}/{target_nodes} nodes owned")
            print(f"   ⚡ Attack steps: {len(optimal['path'])}")
        
        return generated_data


# --- CLI Interface ---

def main():
    parser = argparse.ArgumentParser(
        description="Generate CyberBattleSim attack scenario from cluster.json"
    )
    
    parser.add_argument(
        'out_dir',
        type=str,
        help='Directory to write the generated environment files'
    )
    
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    )
    
    # Custom argument for cluster config file
    parser.add_argument(
        "--config-file",
        type=str,
        required=True,
        help="Path to the cluster.json configuration file with physical topology"
    )
    
    print("🚀 Running ClusterAttackGenerator...")
    cli_default(ClusterAttackGenerator, parser)
    
    print(f"\n✅ Successfully generated CyberBattleSim attack scenario!")


if __name__ == "__main__":
    main()