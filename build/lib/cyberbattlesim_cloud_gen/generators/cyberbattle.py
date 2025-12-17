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
from typing import Dict, List, Tuple, Iterator, cast, Any

from cyberbattlesim_cloud_gen.config.config_loader import ConfigLoader
from cyberbattlesim_cloud_gen.attack_path.attack_path_solver import AttackPathSolver
from cyberbattlesim_cloud_gen.attack_path.attack_visualizer import AttackVisualizer
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
                 cluster_config: Dict = None,
                 log_level: str = "INFO",
                 config_loader_instance: ConfigLoader = None,
                 **kwargs):
        """
        Initialize the generator.
        """
        super().__init__(output_dir=out_dir, **kwargs)
        
        self.output_dir = out_dir
        self.config_loader_instance = config_loader_instance or ConfigLoader.get_instance()
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
        """
        Get configured port for a service. 
        Strictly requires port definition in services.yaml.
        """
        service_ports = self.config_loader_instance.get_service_ports()
        
        # STRICT VALIDATION: No hardcoded [80] fallback
        if service_name not in service_ports or not service_ports[service_name]:
            raise ValueError(
                f"Port configuration missing for service '{service_name}'. "
                f"Please add a 'ports' list for this service (e.g., ports: [8080]) in services.yaml."
            )
            
        return service_ports[service_name][0]
    
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

    def _merge_vulnerability(self, existing_vulns: Dict, new_vuln_id: str, new_vuln: VulnerabilityInfo):
        """
        Merges a new vulnerability into the existing dictionary.
        If the ID exists (same CVE on multiple pods), it combines the outcomes (e.g. leaks BOTH credentials).
        """
        if new_vuln_id not in existing_vulns:
            existing_vulns[new_vuln_id] = new_vuln
            return

        # Conflict detected: Same CVE found for another service instance on this node.
        existing_vuln = existing_vulns[new_vuln_id]
        
        # 1. Merge LeakedCredentials (Leak credentials for ALL instances)
        if isinstance(existing_vuln.outcome, LeakedCredentials) and isinstance(new_vuln.outcome, LeakedCredentials):
            try:
                # Extend existing list if mutable
                existing_vuln.outcome.credentials.extend(new_vuln.outcome.credentials)
            except AttributeError:
                # Re-create if immutable
                combined = list(existing_vuln.outcome.credentials) + list(new_vuln.outcome.credentials)
                existing_vuln.outcome = LeakedCredentials(credentials=combined)
            
        # 2. Merge LeakedNodesId
        elif isinstance(existing_vuln.outcome, LeakedNodesId) and isinstance(new_vuln.outcome, LeakedNodesId):
            current_nodes = set(existing_vuln.outcome.nodes)
            current_nodes.update(new_vuln.outcome.nodes)
            existing_vuln.outcome.nodes = list(current_nodes)
            
        # 3. For System/Admin Escalation, the existence of one path is sufficient (no merge needed)

    def _get_library_vulnerabilities(self, service_name: str, node_id: str, port: int, credential_id: str) -> Dict[str, VulnerabilityInfo]:
        """
        Enrich service with CVEs from library using K8s-style shared credentials.
        Calculates cost using CONFIGURED strategy from YAML.
        """
        library_vulns = {}
        vuln_profiles = self.config_loader_instance.get_service_vulnerability_profiles()
        
        # NEW: Fetch scoring strategy
        scoring_strategy = self.config_loader_instance.get_vulnerability_scoring_strategy()
        base_score = scoring_strategy.get("base_score", 12.0)
        min_score = scoring_strategy.get("min_score", 1.0)
        sev_mult = scoring_strategy.get("multipliers", {}).get("severity", 2.0)
        exp_mult = scoring_strategy.get("multipliers", {}).get("exploitability", 2.0)
        sev_map = scoring_strategy.get("severity_weights", {"LOW": 1.0, "MEDIUM": 2.0, "HIGH": 3.0, "CRITICAL": 4.0})

        if service_name not in vuln_profiles:
            return library_vulns
            
        profile = vuln_profiles[service_name]
        
        cve_list = []
        if isinstance(profile, dict) and "cves" in profile:
            cve_list = profile["cves"]
        elif isinstance(profile, list):
            cve_list = profile
            
        for cve in cve_list:
            cve_id = cve.get("cve_id", "Unknown-CVE")
            if "TEMP" in cve_id or "Unknown" in cve_id: continue

            sim_vuln_id = cve_id
            
            # --- Type Classification ---
            raw_type = cve.get("vulnerability_type", cve.get("type", "REMOTE"))
            if raw_type and raw_type.upper() == "LOCAL":
                vuln_type = VulnerabilityType.LOCAL
            elif raw_type and raw_type.upper() == "CLIENT":
                vuln_type = VulnerabilityType.CLIENT
            else:
                vuln_type = VulnerabilityType.REMOTE

            # --- Outcome Mapping ---
            outcome_str = cve.get("outcome_type", "PrivilegeEscalation")
            outcome_params = {}
            
            if outcome_str == "LeakedCredentials":
                outcome_params['credentials'] = [
                     CachedCredential(node=node_id, port=str(port), credential=credential_id)
                ]
            elif outcome_str == "LeakedNodesId":
                outcome_params['nodes'] = self._find_related_nodes(service_name)

            outcome = self._map_outcome_string_to_class(outcome_str, **outcome_params)
            
            # --- Configurable Cost Calculation ---
            
            # 1. Severity Weight
            severity = cve.get("severity", "MEDIUM").upper()
            sev_weight = sev_map.get(severity, sev_map.get("MEDIUM", 2.0))
            
            # 2. Exploitability
            exploitability = 0.5 # Default
            if "exploitability" in cve and cve["exploitability"] is not None:
                exploitability = float(cve["exploitability"])
            elif cve.get("cvss_v3") and isinstance(cve["cvss_v3"], dict):
                # Optional: Extract from CVSS vector or subscore if available
                pass
            
            # Normalize Exploitability (Ensure it's 0-1 range for the formula)
            # If the input is 0-10, we divide by 10.
            if exploitability > 1.0:
                 norm_exploitability = exploitability / 10.0
            else:
                 norm_exploitability = exploitability

            # 3. Formula: Cost = Base - (Severity * SevMult) - (Exploitability * ExpMult)
            # Example: 12.0 - (4.0 * 2.0) - (0.9 * 2.0) = 12 - 8 - 1.8 = 2.2
            cost = base_score - (sev_weight * sev_mult) - (norm_exploitability * exp_mult)
            
            # Ensure it doesn't go below minimum (e.g. 1.0)
            cost = max(min_score, cost)
            
            library_vulns[sim_vuln_id] = VulnerabilityInfo(
                description=cve.get("description", f"CVE on {service_name}"),
                type=vuln_type,
                cost=round(cost, 2),
                outcome=outcome,
                reward_string=f"Exploited {cve_id} on {node_id}"
            )
            
        return library_vulns



    def _create_cyberbattle_node(self, physical_node: Dict) -> NodeInfo:
        """Convert physical node to CyberBattleSim node"""
        node_id = physical_node["node_id"]
        zone = physical_node["zone"]
        ip_allocation = physical_node.get("ip_allocation", {})
        ip_address = ip_allocation.get("ipv4", "10.0.0.1")
        subnet_cidr = ip_allocation.get("cidr", "10.0.0.0/24")
        
        services = []
        vulnerabilities = {}
        
        for pod_assignment in physical_node["assigned_pods"]:
            service_name = pod_assignment["service"]
            
            # KUBERNETES STYLE: Shared Service & Credential
            
            # 1. Port Validation (Strict)
            port_val = self._get_service_port(service_name)
            if not isinstance(port_val, int):
                try: port_val = int(port_val)
                except ValueError: raise ValueError(f"Invalid port for {service_name}")
            port_str = str(port_val)

            # 2. Shared Credential (k8s secret)
            credential = f"{service_name}_creds"
            
            # 3. Listening Service (One per service type per node)
            if not any(s.name == service_name for s in services):
                service = ListeningService(
                    name=service_name,
                    port=port_str,
                    allowedCredentials=[credential]
                )
                services.append(service)
            
            # 4. Inject Vulnerabilities (Library)
            library_vulns = self._get_library_vulnerabilities(service_name, node_id, port_val, credential)
            for vid, vinfo in library_vulns.items():
                self._merge_vulnerability(vulnerabilities, vid, vinfo)
            
            # 5. Add Cluster Config CVEs
            if "network_topology" in self.cluster_config:
                network_services = self.cluster_config["network_topology"].get("services", {})
                if service_name in network_services and "vulnerabilities" in network_services[service_name]:
                    for cve in network_services[service_name]["vulnerabilities"]:
                        cve_id = cve["cve_id"]
                        if "TEMP" in cve_id: continue

                        cve_vuln_name = cve_id 
                        outcome_type = cve.get("outcome_type", "LeakedCredentials")
                        
                        kwargs = {}
                        if outcome_type == "LeakedNodesId":
                            kwargs['nodes'] = self._find_related_nodes(service_name)
                        elif outcome_type == "LeakedCredentials":
                            target_service = cve.get("target_service", service_name)
                            target_port_val = self._get_service_port(target_service)
                            credential_name = f"{target_service}_creds"
                            target_nodes = self._find_nodes_with_service(target_service)
                            
                            if target_nodes:
                                kwargs['credentials'] = [
                                    CachedCredential(node=target_nodes[0], port=str(target_port_val), credential=credential_name)
                                ]
                        
                        outcome = self._map_outcome_string_to_class(outcome_type, **kwargs)
                        
                        v_type_str = cve.get("vulnerability_type", cve.get("type", "REMOTE")).upper()
                        v_type = VulnerabilityType.LOCAL if v_type_str == "LOCAL" else VulnerabilityType.REMOTE

                        # Use similar scoring for consistency
                        sev = cve.get("severity", "MEDIUM").upper()
                        sev_w = {"LOW": 1.0, "MEDIUM": 2.0, "HIGH": 3.0, "CRITICAL": 4.0}.get(sev, 2.0)
                        exp = float(cve.get("exploitability", 0.5))
                        norm_exp = exp / 10.0 if exp > 1.0 else exp
                        cost = max(1.0, 12.0 - (sev_w * 2.0) - (norm_exp * 2.0))

                        new_vuln = VulnerabilityInfo(
                            description=cve.get("description", "Known CVE"),
                            type=v_type,
                            cost=round(cost, 2),
                            outcome=outcome,
                            reward_string=f"Exploited {cve_id} on {node_id}"
                        )
                        self._merge_vulnerability(vulnerabilities, cve_vuln_name, new_vuln)
        
        firewall_rules = self._create_firewall_rules(physical_node)
        
        # Validation
        node_value = physical_node.get("value", 0)
        if node_value == 0:
            is_attacker_node = (
                physical_node.get("node_type") in ["internet", "external"] or 
                "attacker" in physical_node.get("properties", []) or
                node_id == "attacker" or "internet" in node_id
            )
            if not is_attacker_node:
                raise ValueError(f"Node value is missing or 0 for node '{node_id}'.")
        
        properties = [
            "kubernetes",
            physical_node["node_type"],
            zone,
            f"ip_{ip_address.replace('.', '_')}"
        ]
        
        for pod in physical_node["assigned_pods"]:
            properties.append(f"service_{pod['service']}")
            properties.append(f"running_{pod['service']}")
        
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
        same_service_nodes = self._find_nodes_with_service(service_name)
        related_nodes.update(same_service_nodes)
        
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
        """Create firewall rules based on physical topology connections AND public exposure"""
        incoming_rules = []
        outgoing_rules = []
        node_id = physical_node["node_id"]
        
        is_public_node = False
        public_ports = []
        public_services = self.config_loader_instance.get_public_services()
        
        if "network_topology" in self.cluster_config:
            net_services = self.cluster_config["network_topology"].get("services", {})
            for pod in physical_node["assigned_pods"]:
                svc_name = pod["service"]
                if svc_name in net_services and net_services[svc_name].get("is_public", False):
                    is_public_node = True
                    public_ports.append(self._get_service_port(svc_name))
                elif svc_name in public_services:
                    is_public_node = True
                    public_ports.append(self._get_service_port(svc_name))

        if is_public_node:
            for port in public_ports:
                incoming_rules.append(
                    FirewallRule(
                        port=str(port),
                        permission=RulePermission.ALLOW,
                        subnet=Subnet("192.168.1.0/24"),
                        reason=f"Public access for service"
                    )
                )

        if "node_connections" in self.cluster_config.get("physical_topology", {}):
            for conn in self.cluster_config["physical_topology"]["node_connections"]:
                if conn["to"] == node_id:
                    permission = RulePermission.ALLOW if not conn["is_firewalled"] else RulePermission.BLOCK
                    incoming_rules.append(FirewallRule(port="*", permission=permission, subnet=Subnet(f"{conn['from_ip']}/32"), reason=f"Connection from {conn['from']}"))
                if conn["from"] == node_id:
                    permission = RulePermission.ALLOW if not conn["is_firewalled"] else RulePermission.BLOCK
                    outgoing_rules.append(FirewallRule(port="*", permission=permission, subnet=Subnet(f"{conn['to_ip']}/32"), reason=f"Connection to {conn['to']}"))
        
        incoming_rules.append(FirewallRule(port="*", permission=RulePermission.BLOCK, reason="Default deny"))
        outgoing_rules.append(FirewallRule(port="*", permission=RulePermission.ALLOW, reason="Default allow"))
        
        return FirewallConfiguration(incoming=incoming_rules, outgoing=outgoing_rules)

    def _create_attacker_nodes(self) -> None:
        """Create attacker entry points with FULL network access"""
        public_nodes = self._find_public_nodes()
        
        permissive_firewall = FirewallConfiguration(
            incoming=[FirewallRule(port="*", permission=RulePermission.ALLOW, subnet=Subnet("0.0.0.0/0"), reason="Attacker Full Access")],
            outgoing=[FirewallRule(port="*", permission=RulePermission.ALLOW, subnet=Subnet("0.0.0.0/0"), reason="Attacker Full Access")]
        )
        
        self.nodes["attacker"] = NodeInfo(
            network_info=[NodeNetworkInfo(interface=NetworkInterfaces.ETH1, ip_address="192.168.1.100", subnet=Subnet("192.168.1.0/24"))],
            services=[],
            vulnerabilities={
                "InitialScan": VulnerabilityInfo(
                    description="Initial network reconnaissance", type=VulnerabilityType.LOCAL,
                    outcome=LeakedNodesId(nodes=list(public_nodes)), cost=1.0, reward_string="Discovered public-facing nodes"),
                "PortScan": VulnerabilityInfo(
                    description="Detailed port scanning", type=VulnerabilityType.LOCAL,
                    outcome=LeakedNodesId(nodes=list(public_nodes)), cost=2.0, reward_string="Detailed port scan completed")
            },
            properties=["attacker", "external", "reconnaissance"],
            value=0, agent_installed=True, firewall=permissive_firewall, reimagable=False
        )
    
    def _find_public_nodes(self) -> List[str]:
        public_nodes = set()
        public_services = self.config_loader_instance.get_public_services()
        
        if "network_topology" in self.cluster_config:
            for service_name, service_config in self.cluster_config["network_topology"].get("services", {}).items():
                if service_config.get("is_public", False) or service_name in public_services:
                    if "physical_topology" in self.cluster_config:
                        for node in self.cluster_config["physical_topology"]["nodes"]:
                            for pod in node["assigned_pods"]:
                                if pod["service"] == service_name:
                                    public_nodes.add(node["node_id"])
        
        if "physical_topology" in self.cluster_config:
            for node in self.cluster_config["physical_topology"]["nodes"]:
                for pod in node["assigned_pods"]:
                    if pod["service"] in public_services:
                        public_nodes.add(node["node_id"])
        
        if not public_nodes and "physical_topology" in self.cluster_config:
            for node in self.cluster_config["physical_topology"]["nodes"]:
                if node["node_type"] == "control_plane":
                    public_nodes.add(node["node_id"])
        
        if not public_nodes and "physical_topology" in self.cluster_config:
            worker_nodes = [node["node_id"] for node in self.cluster_config["physical_topology"]["nodes"] if node["node_type"] == "worker"]
            public_nodes.update(worker_nodes[:3])
        
        return list(public_nodes)
    
    def _build_credential_flows(self) -> None:
        if "network_topology" not in self.cluster_config: return
        credential_flows = self.cluster_config["network_topology"].get("credential_flow", [])
        
        for flow in credential_flows:
            source_service = flow["source"]
            target_service = flow["target"]
            source_nodes = self._find_nodes_with_service(source_service)
            target_nodes = self._find_nodes_with_service(target_service)
            if not source_nodes or not target_nodes: continue
                
            for source_node in source_nodes:
                if source_node not in self.nodes: continue
                vuln_name = f"CredentialLeak_{source_service}_to_{target_service}"
                credential = f"{source_service}_to_{target_service}_key"
                target_port = str(self._get_service_port(target_service))
                
                self.nodes[source_node].vulnerabilities[vuln_name] = VulnerabilityInfo(
                    description=f"Stored credentials for {target_service}", type=VulnerabilityType.LOCAL,
                    cost=3.0, outcome=LeakedCredentials(credentials=[CachedCredential(node=target_nodes[0], port=target_port, credential=credential)]),
                    reward_string=f"Found credentials for {target_service}"
                )
                
                for target_node in target_nodes:
                    if target_node in self.nodes:
                        for service in self.nodes[target_node].services:
                            if target_service == service.name and service.port == target_port:
                                if credential not in service.allowedCredentials:
                                    service.allowedCredentials.append(credential)
    
    def _find_nodes_with_service(self, service_name: str) -> List[str]:
        nodes_with_service = []
        if "physical_topology" in self.cluster_config:
            for node in self.cluster_config["physical_topology"]["nodes"]:
                for pod in node["assigned_pods"]:
                    if pod["service"] == service_name:
                        nodes_with_service.append(node["node_id"])
                        break
        return nodes_with_service
    
    def _perform_attack_analysis(self):
        print("\n🔍 Performing comprehensive attack analysis...")
        solver = AttackPathSolver(self.nodes, attacker_node='attacker')
        attack_paths = solver.solve(max_depth=12000, timeout_sec=30)
        visualizer = AttackVisualizer(self.output_dir)
        visualizer.visualize_attack_paths(self.nodes, attack_paths)
        self._save_attack_analysis(attack_paths)
        return attack_paths
    
    def _save_attack_analysis(self, attack_paths: Dict):
        analysis_dir = os.path.join(self.output_dir, "analysis")
        os.makedirs(analysis_dir, exist_ok=True)
        paths_data = {}
        for path_name, path_info in attack_paths.items():
            paths_data[path_name] = {
                "best_state": path_info.get("best_state"), "nodes_owned": path_info.get("nodes_owned"),
                "computation_time": path_info.get("computation_time"), "steps": path_info["path"]
            }
        with open(os.path.join(analysis_dir, "attack_paths.json"), 'w') as f:
            json.dump(paths_data, f, indent=2)
        self._generate_analysis_report(attack_paths, analysis_dir)
    
    def _generate_analysis_report(self, attack_paths: Dict, analysis_dir: str):
        report_path = os.path.join(analysis_dir, "attack_analysis_report.txt")
        with open(report_path, 'w') as f:
            f.write("CYBERBATTLESIM ATTACK ANALYSIS REPORT\n" + "=" * 50 + "\n\n")
            total_nodes = len([n for n in self.nodes if "attacker" not in self.nodes[n].properties])
            f.write(f"BASIC STATISTICS:\nTotal target nodes: {total_nodes}\n")
            f.write(f"Total vulnerabilities: {sum(len(node.vulnerabilities) for node in self.nodes.values())}\n")
            f.write(f"Attacker entry points: {len([n for n in self.nodes if 'attacker' in self.nodes[n].properties])}\n\n")
            
            f.write("ATTACK PATH ANALYSIS:\n" + "-" * 30 + "\n")
            if "maximal_achievement" in attack_paths:
                optimal = attack_paths["maximal_achievement"]
                f.write(f"Maximal achievement: {optimal['nodes_owned']}/{total_nodes} nodes owned\nSteps: {len(optimal['path'])}\n\nATTACK PATH:\n")
                for i, action in enumerate(optimal["path"]): f.write(f"  {i+1}. {action}\n")
            else: f.write("❌ No attack path found\n\n")
            
            f.write("\nCRITICAL NODES:\n" + "-" * 30 + "\n")
            critical_nodes = [(nid, n.value) for nid, n in self.nodes.items() if "attacker" not in n.properties and n.value >= 100]
            for nid, val in sorted(critical_nodes, key=lambda x: x[1], reverse=True): f.write(f"{nid}: value {val}\n")
            f.write("Total value:\t" + str(optimal['value']) + "\n")

        print(f"✅ Attack analysis report saved to {report_path}")

    # --- NetworkGenerator Interface Methods ---

    def get_nodes(self) -> Dict[str, NodeInfo]:
        print("🔄 Generating CyberBattleSim attack scenario from cluster.json...")
        internet_node_found = False
        if "physical_topology" in self.cluster_config:
            for physical_node in self.cluster_config["physical_topology"]["nodes"]:
                if not physical_node["is_healthy"]: continue
                if physical_node["node_type"] == "internet" or physical_node["node_id"] == "node-internet":
                    print("   ✓ Found existing Internet node, converting to Attacker entry point.")
                    internet_node_found = True
                    cyber_node = self._create_cyberbattle_node(physical_node)
                    permissive_firewall = FirewallConfiguration(
                        incoming=[FirewallRule(port="*", permission=RulePermission.ALLOW, subnet=Subnet("0.0.0.0/0"), reason="Attacker Full Access")],
                        outgoing=[FirewallRule(port="*", permission=RulePermission.ALLOW, subnet=Subnet("0.0.0.0/0"), reason="Attacker Full Access")]
                    )
                    cyber_node.firewall = permissive_firewall
                    public_nodes = self._find_public_nodes()
                    cyber_node.vulnerabilities["InitialScan"] = VulnerabilityInfo(description="Initial network reconnaissance", type=VulnerabilityType.LOCAL, outcome=LeakedNodesId(nodes=list(public_nodes)), cost=1.0, reward_string="Discovered public-facing nodes")
                    cyber_node.vulnerabilities["PortScan"] = VulnerabilityInfo(description="Detailed port scanning", type=VulnerabilityType.LOCAL, outcome=LeakedNodesId(nodes=list(public_nodes)), cost=2.0, reward_string="Detailed port scan completed")
                    for prop in ["attacker", "external", "reconnaissance"]:
                        if prop not in cyber_node.properties: cyber_node.properties.append(prop)
                    self.nodes["attacker"] = cyber_node
                else:
                    cyber_node = self._create_cyberbattle_node(physical_node)
                    self.nodes[physical_node["node_id"]] = cyber_node
        
        if not internet_node_found: self._create_attacker_nodes()
        self._build_credential_flows()
        print(f"✅ Created {len(self.nodes)} nodes for CyberBattleSim")
        return self.nodes

    def get_identifiers(self) -> Identifiers:
        return infer_constants_from_nodes(cast(Iterator[Tuple[NodeID, NodeInfo]], list(self.nodes.items())), {})

    def get_vulnerability_library(self):
        return dict([])

    def generate(self):
        generated_data = super().generate()
        attack_paths = self._perform_attack_analysis()
        attacker_nodes = sum(1 for node in self.nodes.values() if "attacker" in node.properties)
        print(f"\n🎯 CyberBattleSim Attack Scenario Generation Complete!\n   Total nodes: {len(self.nodes)}\n   Attacker nodes: {attacker_nodes}\n   Target nodes: {len(self.nodes) - attacker_nodes}")
        if "maximal_achievement" in attack_paths:
            optimal = attack_paths["maximal_achievement"]
            print(f"   ✅ Maximal achievement: {optimal['nodes_owned']}/{len(self.nodes) - attacker_nodes} nodes owned\n   ⚡ Attack steps: {len(optimal['path'])}")
        return generated_data


# --- CLI Interface ---

def main():
    parser = argparse.ArgumentParser(description="Generate CyberBattleSim attack scenario from cluster.json")
    parser.add_argument('out_dir', type=str, help='Directory to write the generated environment files')
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    parser.add_argument("--config-file", type=str, required=True, help="Path to the cluster.json configuration file")
    print("🚀 Running ClusterAttackGenerator...")
    cli_default(ClusterAttackGenerator, parser)
    print(f"\n✅ Successfully generated CyberBattleSim attack scenario!")

if __name__ == "__main__":
    main()