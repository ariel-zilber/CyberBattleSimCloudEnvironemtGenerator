#!/usr/bin/env python3
"""
Enhanced CyberBattleSim Scenario Generator for K8s Environments

Converts Kubernetes cluster snapshots + vulnerability/credential data into
CyberBattleSim scenarios. This script is a NetworkGenerator that parses
K8s YAML files to produce a simulation environment.
"""

import json
import yaml
import os
import argparse
import random
import numpy as np
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional, Set, Iterator, cast
from collections import defaultdict
import networkx as nx
from enum import Enum

# CyberBattleSim Imports
from cyberbattlesim_network_gen.generators.network_generator import NetworkGenerator
from cyberbattle.simulation.nodes_types import NodeID
from cyberbattle.simulation.nodes import NodeInfo
from cyberbattle.simulation.firewall import FirewallRule, RulePermission, FirewallConfiguration
from cyberbattle.simulation.vulenrabilites import VulnerabilityID, PrivilegeLevel, NoOutcome
from cyberbattle.simulation.services import ListeningService
from cyberbattlesim_network_gen.generators.utils import cli_default
from cyberbattle.simulation.nodes_network import infer_constants_from_nodes
from cyberbattle.simulation.network import NodeNetworkInfo, Subnet, NetworkInterfaces
from cyberbattle.simulation.vulenrabilites import VulnerabilityInfo, LeakedNodesId, VulnerabilityType, \
    LeakedCredentials, CachedCredential, PrivilegeEscalation
from cyberbattle.simulation.identifiers import Identifiers


class K8sScenarioGenerator(NetworkGenerator):
    """
    Parses a Kubernetes cluster snapshot to generate a CyberBattleSim network scenario.
    """

    def __init__(self, snapshot_path: str, info_path: str, seed: int = None, **kwargs):
        super().__init__(**kwargs)
        self.snapshot_path = snapshot_path
        self.info_path = info_path
        if seed:
            random.seed(seed)
            np.random.seed(seed)

        # Load data from snapshot
        self.snapshot_data = self._load_snapshot_data()
        self.vuln_data, _ = self._load_vulnerability_data()

        # Internal cache for generated objects
        self._nodes: Optional[Dict[NodeID, NodeInfo]] = None
        self._vulnerability_library: Optional[Dict[VulnerabilityID, VulnerabilityInfo]] = None

    def get_nodes(self) -> Dict[NodeID, NodeInfo]:
        if self._nodes is None:
            self._generate_all()
        return self._nodes

    def get_vulnerability_library(self) -> Dict[VulnerabilityID, VulnerabilityInfo]:
        if self._vulnerability_library is None:
            self._generate_all()
        return self._vulnerability_library

    def get_identifiers(self) -> Identifiers:
        # Automatically infer identifiers from the generated nodes and vulnerabilities
        return infer_constants_from_nodes(
            cast(Iterator[Tuple[NodeID, NodeInfo]], self.get_nodes().items()),
            self.get_vulnerability_library()
        )

    def _generate_all(self):
        """Orchestrates the full scenario generation process."""
        self._nodes, self._vulnerability_library = self._create_cyberbattle_objects()

    def _load_snapshot_data(self) -> Dict[str, Any]:
        """Load and validate cluster snapshot data."""
        data = {}
        resource_files = {
            'nodes': 'nodes.yaml',
            'pods': 'pods.yaml',
            'services': 'services.yaml',
            'deployments': 'deployments.yaml',
            'networkpolicies': 'networkpolicies.yaml',
        }
        for resource_key, filename in resource_files.items():
            file_path = os.path.join(self.snapshot_path, filename)
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    try:
                        content = yaml.safe_load(f)
                        data[resource_key] = content if content else {'items': []}
                    except yaml.YAMLError as e:
                        print(f"⚠️  Error loading {filename}: {e}")
                        data[resource_key] = {'items': []}
            else:
                print(f"⚠️  Warning: {filename} not found in snapshot.")
                data[resource_key] = {'items': []}
        return data

    def _load_vulnerability_data(self) -> Tuple[Dict, Dict]:
        """Load vulnerability and credential data."""
        vuln_file = os.path.join(self.info_path, 'helm_analysis_with_cves_and_secrets.json')
        vuln_data = {}
        if os.path.exists(vuln_file):
            with open(vuln_file, 'r') as f:
                vuln_data = json.load(f)
        return vuln_data, {}

    def _create_cyberbattle_objects(self) -> Tuple[Dict[NodeID, NodeInfo], Dict[VulnerabilityID, VulnerabilityInfo]]:
        """Create the final CyberBattleSim objects."""
        nodes: Dict[NodeID, NodeInfo] = {}
        vulnerability_library: Dict[VulnerabilityID, VulnerabilityInfo] = {}

        pods_by_node = defaultdict(list)
        for pod in self.snapshot_data.get('pods', {}).get('items', []):
            if pod['spec'].get('nodeName'):
                pods_by_node[pod['spec']['nodeName']].append(pod)

        firewall_configs = self._extract_firewall_rules()

        for k8s_node in self.snapshot_data.get('nodes', {}).get('items', []):
            node_name = k8s_node['metadata']['name']
            labels = k8s_node['metadata'].get('labels', {})
            is_master = 'node-role.kubernetes.io/master' in labels or 'node-role.kubernetes.io/control-plane' in labels
            subnet_name = labels.get('subnet', 'default')
            zone = labels.get('topology.kubernetes.io/zone', 'default-zone')

            # Aggregate services from all pods on this node
            node_services = []
            for pod in pods_by_node.get(node_name, []):
                for container in pod['spec'].get('containers', []):
                    node_services.extend(self._extract_container_services(container))

            # Aggregate vulnerabilities based on running services
            node_vulns = {}
            for service_data in self.vuln_data.get('services', []):
                # A simple placement logic: if service runs on this kind of node, add its vulns
                if self._should_place_service_on_node(service_data, labels, subnet_name):
                    for image in service_data.get('docker_images', []):
                        for vuln_data in image.get('vulnerabilities', []):
                            vuln_info = self._map_vuln_to_info(vuln_data)
                            node_vulns[vuln_info.description] = vuln_info
                            vulnerability_library[vuln_info.description] = vuln_info

            nodes[node_name] = NodeInfo(
                services=node_services,
                vulnerabilities=node_vulns,
                value=1000 if is_master else 500,
                properties=self._generate_node_properties(labels, is_master),
                firewall=self._apply_firewall_config(labels, firewall_configs),
                network_info=[self._create_network_info(subnet_name, zone)]
            )
        return nodes, vulnerability_library

    def _map_vuln_to_info(self, vuln_data: Dict) -> VulnerabilityInfo:
        """Directly convert vulnerability data to a VulnerabilityInfo object."""
        cvss_data = vuln_data.get('CVSS', {}).get('nvd', {})
        cvss_score = cvss_data.get('V3Score', cvss_data.get('V2Score', 0.0))

        # Simple outcome mapping
        outcome = NoOutcome()
        if cvss_score > 7.0:
            outcome = LeakedCredentials([])
        elif cvss_score > 4.0:
            outcome = LeakedNodesId([])

        return VulnerabilityInfo(
            description=vuln_data.get('VulnerabilityID', f"vuln-{random.randint(1000,9999)}"),
            type=VulnerabilityType.REMOTE,
            outcome=outcome,
            reward_string=f"Exploited {vuln_data.get('Title', 'vulnerability')}",
            cost=max(0.5, 10.0 - cvss_score)
        )

    def _extract_container_services(self, container: Dict) -> List[ListeningService]:
        """Extract ListeningService objects from a container definition."""
        services = []
        for port_def in container.get('ports', []):
            services.append(ListeningService(
                name=port_def.get('name', str(port_def.get('containerPort'))),
                port=port_def.get('containerPort'),
                allowedCredentials=[]  # Simplified: credentials can be added later
            ))
        return services

    def _generate_node_properties(self, labels: Dict, is_master: bool) -> List[str]:
        """Generate node properties from K8s labels."""
        properties = [labels.get('kubernetes.io/os', 'linux').capitalize()]
        if is_master:
            properties.append('K8s_Master')
        else:
            properties.append('K8s_Worker')
        properties.append(f"subnet:{labels.get('subnet', 'default')}")
        return properties

    def _extract_firewall_rules(self) -> Dict[str, Any]:
        """Extract and simplify NetworkPolicies."""
        firewall_configs = {}
        for netpol in self.snapshot_data.get('networkpolicies', {}).get('items', []):
            name = netpol['metadata']['name']
            firewall_configs[name] = netpol['spec']
        return firewall_configs
        
    def _apply_firewall_config(self, node_labels: Dict, firewall_configs: Dict) -> FirewallConfiguration:
        """Apply the first matching NetworkPolicy to a node."""
        for name, spec in firewall_configs.items():
            selector = spec.get('podSelector', {}).get('matchLabels', {})
            if all(node_labels.get(k) == v for k, v in selector.items()):
                incoming_rules, outgoing_rules = [], []
                if 'ingress' in spec:
                    for rule in spec.get('ingress', []):
                        for port in rule.get('ports', []):
                            incoming_rules.append(FirewallRule(port=str(port.get('port')), permission=RulePermission.ALLOW))
                if 'egress' in spec:
                    for rule in spec.get('egress', []):
                        for port in rule.get('ports', []):
                            outgoing_rules.append(FirewallRule(port=str(port.get('port')), permission=RulePermission.ALLOW))
                
                # If a policy applies but has no rules, it's deny-by-default
                if not incoming_rules:
                    incoming_rules.append(FirewallRule(port="*", permission=RulePermission.BLOCK))
                if not outgoing_rules:
                    outgoing_rules.append(FirewallRule(port="*", permission=RulePermission.BLOCK))
                    
                return FirewallConfiguration(incoming=incoming_rules, outgoing=outgoing_rules)
        
        # Default permissive firewall if no policies match
        return FirewallConfiguration(
            incoming=[FirewallRule(port="*", permission=RulePermission.ALLOW)],
            outgoing=[FirewallRule(port="*", permission=RulePermission.ALLOW)]
        )

    def _create_network_info(self, subnet_name: str, zone: str) -> NodeNetworkInfo:
        """Create detailed network information for a node."""
        subnet_mappings = {
            'frontend': "10.1.0", 'backend': "10.2.0", 'database': "10.3.0",
            'management': "10.4.0", 'dmz': "172.16.0", 'default': "10.0.0"
        }
        base_ip = subnet_mappings.get(subnet_name, "10.0.0")
        ip = f"{base_ip}.{random.randint(10, 250)}"
        subnet_str = f"{base_ip}.0/24"
        return NodeNetworkInfo(
            interface=NetworkInterfaces.ETH0,
            ip_address=ip,
            subnet=Subnet(subnet_str)
        )

    def _should_place_service_on_node(self, service: Dict, node_labels: Dict, subnet: str) -> bool:
        """Determine if a service's vulnerabilities should apply to a node."""
        service_name = service.get('name', '').lower()
        is_master = 'node-role.kubernetes.io/master' in node_labels or 'node-role.kubernetes.io/control-plane' in node_labels

        if any(term in service_name for term in ['api', 'etcd', 'controller-manager', 'scheduler']):
            return is_master
        if any(term in service_name for term in ['mysql', 'postgres', 'redis', 'mongodb']):
            return 'database' in subnet.lower()
        if any(term in service_name for term in ['nginx', 'apache', 'frontend']):
            return 'frontend' in subnet.lower()
        return not is_master

def main():
    """Main function to run the generator from the command line."""
    parser = argparse.ArgumentParser(
        description="Generate CyberBattleSim scenarios from K8s cluster snapshots."
    )
    parser.add_argument("snapshot_path", help="Path to cluster snapshot directory (containing nodes.yaml, etc.)")
    parser.add_argument("info_path", help="Path to vulnerability data directory (containing helm_analysis_with_cves_and_secrets.json)")

    # This function is designed to be used with cli_default
    cli_default(K8sScenarioGenerator, parser=parser)


if __name__ == '__main__':
    main()
