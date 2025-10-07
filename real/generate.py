#!/usr/bin/env python3
"""Enhanced CyberBattleSim Scenario Generator for K8s Environments

Converts Kubernetes cluster snapshots + vulnerability/credential data into empirically validated CyberBattleSim scenarios for DRL research.
"""
import json
import yaml
import os
import argparse
import random
import numpy as np
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict
import networkx as nx
from enum import Enum

# Custom imports
from typing import Iterator, cast, Tuple,Dict
from cyberbattlesim_network_gen.generators.network_generator import NetworkGenerator
from cyberbattle.simulation.nodes_types import NodeID
from cyberbattle.simulation.nodes import NodeInfo
from cyberbattle.simulation.firewall import FirewallRule, RulePermission, FirewallConfiguration
from cyberbattle.simulation.vulenrabilites import VulnerabilityID
from cyberbattle.simulation.services import ListeningService
from cyberbattlesim_network_gen.generators.utils import *
from cyberbattle.simulation.nodes_network import infer_constants_from_nodes
from cyberbattle.simulation.network import NodeNetworkInfo,Subnet,NetworkInterfaces
from cyberbattle.simulation.vulenrabilites import VulnerabilityInfo, LeakedNodesId, VulnerabilityType, \
    LeakedCredentials, CachedCredential, PrivilegeEscalation, PrivilegeLevel, NoOutcome

# Research metrics tracking
@dataclass
class ScenarioMetrics:
    """Metrics for empirical validation of generated scenarios."""
    total_nodes: int
    total_vulnerabilities: int
    total_credentials: int
    attack_surface_size: int
    average_path_length: float
    graph_density: float
    vulnerability_diversity: float
    credential_reuse_ratio: float
    firewall_restrictiveness: float
    estimated_difficulty: float
    cvss_distribution: Dict[str, int]
    node_value_distribution: Dict[str, int]

class VulnerabilityClass(Enum):
    """Classification of vulnerabilities for research analysis."""
    REMOTE_CODE_EXECUTION = "RCE"
    PRIVILEGE_ESCALATION = "PE"
    CREDENTIAL_DISCLOSURE = "CD"
    INFORMATION_DISCLOSURE = "ID"
    LATERAL_MOVEMENT = "LM"
    PERSISTENCE = "P"
    DEFENSE_EVASION = "DE"

@dataclass
class EnhancedVulnerability:
    """Enhanced vulnerability model with research-oriented attributes."""
    id: str
    cve_id: Optional[str]
    name: str
    description: str
    vulnerability_class: VulnerabilityClass
    cvss_score: float
    cvss_vector: str
    attack_complexity: str
    attack_vector: str
    privileges_required: str
    user_interaction: str
    success_rate: float
    detection_rate: float
    exploitation_time: float
    reward: int
    outcomes: List[Dict[str, Any]]
    preconditions: List[str]
    tags: List[str]
GET_NODES_FUNC="""    def get_nodes(self)->Dict[str,NodeInfo]:
        return self.nodes
"""
GET_IDENTIFERS_FUNC="""    def get_identifiers(self)->Identifiers:
        local_vulnerabilities=[]
        remote_vulnerabilities=[]
        ports=[]
        properties=[]
        for node in self.nodes.values():
            properties.extend(node.properties)
            for service in node.services:
                ports.append(service.name)
        for k,v in self.vulnerability_library.items():
            if v.type==VulnerabilityType.LOCAL:
                local_vulnerabilities.append(k)
            else:
                remote_vulnerabilities.append(k)
        
        # Make elements unique
        properties = sorted(list(set(properties)))
        ports = sorted(list(set(ports)))
        local_vulnerabilities = sorted(list(set(local_vulnerabilities)))
        remote_vulnerabilities = sorted(list(set(remote_vulnerabilities)))

        return Identifiers(properties=properties,ports=ports,local_vulnerabilities=local_vulnerabilities,remote_vulnerabilities=remote_vulnerabilities)

"""
class K8sScenarioGenerator:
    """Enhanced scenario generator with empirical validation."""

    def __init__(self, snapshot_path: str, info_path: str,
                 research_mode: bool = True, seed: int = None):
        self.snapshot_path = snapshot_path
        self.info_path = info_path
        self.research_mode = research_mode
        if seed:
            random.seed(seed)
            np.random.seed(seed)

        # Load data
        self.snapshot_data = self._load_snapshot_data()
        self.vuln_data, self.cred_data = self._load_vulnerability_data()

        # Research tracking
        self.metrics = None
        self.validation_results = {}

        # Vulnerability classification mappings
        self.cwe_to_class = self._init_cwe_mappings()

    def _init_cwe_mappings(self) -> Dict[str, VulnerabilityClass]:
        """Initialize CWE to vulnerability class mappings for research categorization."""
        return {
            'CWE-78': VulnerabilityClass.REMOTE_CODE_EXECUTION,  # OS Command Injection
            'CWE-89': VulnerabilityClass.REMOTE_CODE_EXECUTION,  # SQL Injection
            'CWE-94': VulnerabilityClass.REMOTE_CODE_EXECUTION,  # Code Injection
            'CWE-269': VulnerabilityClass.PRIVILEGE_ESCALATION,  # Improper Privilege Management
            'CWE-250': VulnerabilityClass.PRIVILEGE_ESCALATION,  # Execution with Unnecessary Privileges
            'CWE-256': VulnerabilityClass.CREDENTIAL_DISCLOSURE, # Unprotected Storage of Credentials
            'CWE-798': VulnerabilityClass.CREDENTIAL_DISCLOSURE, # Hard-coded Credentials
            'CWE-200': VulnerabilityClass.INFORMATION_DISCLOSURE, # Information Exposure
            'CWE-522': VulnerabilityClass.CREDENTIAL_DISCLOSURE, # Insufficiently Protected Credentials
        }

    def _load_snapshot_data(self) -> Dict[str, Any]:
        """Load and validate cluster snapshot data."""
        data = {}

        # Load summary with validation
        summary_path = os.path.join(self.snapshot_path, 'summary.json')
        if os.path.exists(summary_path):
            with open(summary_path, 'r') as f:
                data['summary'] = json.load(f)
        else:
            print(f"⚠️  Warning: No summary.json found in {self.snapshot_path}")

        # Load key K8s resources
        resource_files = {
            'nodes': 'nodes.yaml',
            'pods': 'pods.yaml',
            'services': 'services.yaml',
            'deployments': 'deployments.yaml',
            'networkpolicies': 'networkpolicies.yaml',
            'configmaps': 'configmaps.yaml',
            'secrets': 'secrets.yaml'
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
                data[resource_key] = {'items': []}

        return data

    def _load_vulnerability_data(self) -> Tuple[Dict, Dict]:
        """Load and validate vulnerability and credential data."""
        vuln_file = os.path.join(self.info_path, 'helm_analysis_with_cves_and_secrets.json')
        cred_file = os.path.join(self.info_path, 'raw_credentials.json')

        vuln_data = {}
        cred_data = {}

        if os.path.exists(vuln_file):
            with open(vuln_file, 'r') as f:
                vuln_data = json.load(f)
                print(f"✅ Loaded {len(vuln_data.get('services', []))} services with vulnerabilities")
        else:
            print(f"⚠️  No vulnerability file found at {vuln_file}")

        if os.path.exists(cred_file):
            with open(cred_file, 'r') as f:
                cred_data = json.load(f)
                print(f"✅ Loaded credential data for {cred_data.get('service_name', 'unknown')}")
        else:
            print(f"⚠️  No credential file found at {cred_file}")

        return vuln_data, cred_data

    def classify_vulnerability(self, vuln: Dict) -> VulnerabilityClass:
        """Classify vulnerability based on CVE data and attack patterns."""
        # Check CWE mapping
        cwe_ids = vuln.get('CweIDs', [])
        for cwe in cwe_ids:
            if cwe in self.cwe_to_class:
                return self.cwe_to_class[cwe]

        # Fallback to CVSS vector analysis
        cvss_vector = ""
        if 'CVSS' in vuln:
            cvss = vuln['CVSS']
            if 'nvd' in cvss:
                cvss_vector = cvss['nvd'].get('V3Vector', cvss['nvd'].get('V2Vector', ''))

        # Analyze CVSS vector components
        if 'AV:N' in cvss_vector or 'AV:A' in cvss_vector:
            if 'C:H' in cvss_vector and 'I:H' in cvss_vector:
                return VulnerabilityClass.REMOTE_CODE_EXECUTION
            elif 'C:H' in cvss_vector:
                return VulnerabilityClass.INFORMATION_DISCLOSURE

        if 'PR:L' in cvss_vector and 'S:C' in cvss_vector:
            return VulnerabilityClass.PRIVILEGE_ESCALATION

        # Default based on severity
        severity = vuln.get('Severity', 'UNKNOWN').upper()
        if severity in ['CRITICAL', 'HIGH']:
            return VulnerabilityClass.REMOTE_CODE_EXECUTION
        elif severity == 'MEDIUM':
            return VulnerabilityClass.INFORMATION_DISCLOSURE
        else:
            return VulnerabilityClass.DEFENSE_EVASION

    def map_cvss_to_enhanced_vulnerability(self, vuln: Dict) -> EnhancedVulnerability:
        """Map CVE data to enhanced vulnerability format with research attributes."""
        vuln_id = vuln.get('VulnerabilityID', f'unknown_{random.randint(1000,9999)}')

        # Extract CVSS details
        cvss_score = 0.0
        cvss_vector = ""
        attack_complexity = "LOW"
        attack_vector = "NETWORK"
        privileges_required = "NONE"
        user_interaction = "NONE"

        if 'CVSS' in vuln:
            cvss = vuln['CVSS']
            if 'nvd' in cvss:
                cvss_score = cvss['nvd'].get('V3Score', cvss['nvd'].get('V2Score', 0.0))
                cvss_vector = cvss['nvd'].get('V3Vector', cvss['nvd'].get('V2Vector', ''))

                # Parse CVSS vector
                for component in cvss_vector.split('/'):
                    if ':' in component:
                        key, value = component.split(':')
                        if key == 'AC':
                            attack_complexity = value
                        elif key == 'AV':
                            attack_vector = value
                        elif key == 'PR':
                            privileges_required = value
                        elif key == 'UI':
                            user_interaction = value
        # Classify vulnerability
        vuln_class = self.classify_vulnerability(vuln)

        # Calculate success rate based on multiple factors
        success_rate = self._calculate_success_rate(
            cvss_score, attack_complexity, privileges_required, user_interaction
        )

        # Calculate detection rate (inverse relationship with sophistication)
        detection_rate = self._calculate_detection_rate(cvss_score, vuln_class)

        # Estimate exploitation time
        exploitation_time = self._estimate_exploitation_time(attack_complexity, vuln_class)

        # Calculate reward based on impact and difficulty
        reward = self._calculate_reward(cvss_score, vuln_class)

        # Generate outcomes based on vulnerability class
        outcomes = self._generate_outcomes(vuln, vuln_class)

        # Generate preconditions
        preconditions = self._generate_preconditions(vuln, attack_vector, privileges_required)

        # Extract tags for research categorization
        tags = self._extract_tags(vuln)

        return EnhancedVulnerability(
            id=vuln_id,
            cve_id=vuln_id if vuln_id.startswith('CVE-') else None,
            name=vuln.get('Title', vuln.get('Description', 'Unknown vulnerability')[:50]),
            description=vuln.get('Description', vuln.get('Title', 'Unknown vulnerability')),
            vulnerability_class=vuln_class,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            attack_complexity=attack_complexity,
            attack_vector=attack_vector,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            success_rate=success_rate,
            detection_rate=detection_rate,
            exploitation_time=exploitation_time,
            reward=reward,
            outcomes=outcomes,
            preconditions=preconditions,
            tags=tags
        )

    def _calculate_success_rate(self, cvss_score: float, complexity: str,
                                 privileges: str, interaction: str) -> float:
        """Calculate realistic success rate based on multiple factors."""
        base_rate = cvss_score / 10.0

        # Adjust for complexity
        complexity_factors = {'LOW': 1.2, 'MEDIUM': 1.0, 'HIGH': 0.7}
        base_rate *= complexity_factors.get(complexity, 1.0)

        # Adjust for privileges required
        priv_factors = {'NONE': 1.1, 'LOW': 0.9, 'HIGH': 0.6}
        base_rate *= priv_factors.get(privileges, 1.0)

        # Adjust for user interaction
        interaction_factors = {'NONE': 1.1, 'REQUIRED': 0.7}
        base_rate *= interaction_factors.get(interaction, 1.0)

        # Add noise for realism
        noise = np.random.normal(0, 0.05)

        return max(0.1, min(0.95, base_rate + noise))

    def _calculate_detection_rate(self, cvss_score: float, vuln_class: VulnerabilityClass) -> float:
        """Calculate detection probability based on attack characteristics."""
        # Higher severity attacks are often more detectable
        base_detection = 0.3 + (cvss_score / 10.0) * 0.4

        # Adjust based on vulnerability class
        class_factors = {
            VulnerabilityClass.REMOTE_CODE_EXECUTION: 1.3,
            VulnerabilityClass.PRIVILEGE_ESCALATION: 1.1,
            VulnerabilityClass.CREDENTIAL_DISCLOSURE: 0.8,
            VulnerabilityClass.INFORMATION_DISCLOSURE: 0.7,
            VulnerabilityClass.LATERAL_MOVEMENT: 0.9,
            VulnerabilityClass.PERSISTENCE: 0.6,
            VulnerabilityClass.DEFENSE_EVASION: 0.4
        }

        base_detection *= class_factors.get(vuln_class, 1.0)

        return max(0.1, min(0.9, base_detection))

    def _estimate_exploitation_time(self, complexity: str, vuln_class: VulnerabilityClass) -> float:
        """Estimate time to exploit in simulation steps."""
        base_time = {'LOW': 1.0, 'MEDIUM': 2.0, 'HIGH': 4.0}.get(complexity, 2.0)

        class_multipliers = {
            VulnerabilityClass.REMOTE_CODE_EXECUTION: 1.5,
            VulnerabilityClass.PRIVILEGE_ESCALATION: 1.2,
            VulnerabilityClass.CREDENTIAL_DISCLOSURE: 0.8,
            VulnerabilityClass.INFORMATION_DISCLOSURE: 0.6,
            VulnerabilityClass.LATERAL_MOVEMENT: 1.0,
            VulnerabilityClass.PERSISTENCE: 1.3,
            VulnerabilityClass.DEFENSE_EVASION: 0.9
        }

        return base_time * class_multipliers.get(vuln_class, 1.0)

    def _calculate_reward(self, cvss_score: float, vuln_class: VulnerabilityClass) -> int:
        """Calculate reward points for successful exploitation."""
        base_reward = int(cvss_score * 5)

        class_bonuses = {
            VulnerabilityClass.REMOTE_CODE_EXECUTION: 20,
            VulnerabilityClass.PRIVILEGE_ESCALATION: 15,
            VulnerabilityClass.CREDENTIAL_DISCLOSURE: 10,
            VulnerabilityClass.LATERAL_MOVEMENT: 12,
            VulnerabilityClass.PERSISTENCE: 8,
            VulnerabilityClass.INFORMATION_DISCLOSURE: 5,
            VulnerabilityClass.DEFENSE_EVASION: 3
        }

        return base_reward + class_bonuses.get(vuln_class, 0)

    def _generate_outcomes(self, vuln: Dict, vuln_class: VulnerabilityClass) -> List[Dict]:
        """Generate realistic outcomes based on vulnerability class."""
        outcomes = []

        if vuln_class == VulnerabilityClass.CREDENTIAL_DISCLOSURE:
            # Generate leaked credentials
            num_creds = random.randint(1, 3)
            credentials = []
            for i in range(num_creds):
                credentials.append({
                    'node': f'target_node_{i}',
                    'port': random.choice(['SSH', 'RDP', 'HTTP', 'HTTPS']),
                    'credential': f'leaked_cred_{vuln.get("VulnerabilityID", "unknown")}_{i}'
                })
            outcomes.append({
                'type': 'LeakedCredentials',
                'credentials': credentials
            })

        elif vuln_class == VulnerabilityClass.PRIVILEGE_ESCALATION:
            outcomes.append({
                'type': 'PrivilegeEscalation',
                'level': random.choice(['Admin', 'System'])
            })

        elif vuln_class == VulnerabilityClass.INFORMATION_DISCLOSURE:
            # Reveal network topology
            num_nodes = random.randint(1, 4)
            outcomes.append({
                'type': 'LeakedNodesId',
                'nodes': [f'discovered_node_{i}' for i in range(num_nodes)]
            })

        elif vuln_class == VulnerabilityClass.LATERAL_MOVEMENT:
            outcomes.append({
                'type': 'LateralMove',
                'target_properties': ['adjacent_subnet', 'same_domain']
            })

        elif vuln_class == VulnerabilityClass.REMOTE_CODE_EXECUTION:
            outcomes.append({
                'type': 'SystemCompromise',
                'access_level': 'full'
            })

        return outcomes

    def _generate_preconditions(self, vuln: Dict, attack_vector: str,
                                privileges_required: str) -> List[str]:
        """Generate realistic preconditions for vulnerability exploitation."""
        preconditions = []

        # Network access requirements
        if attack_vector == 'NETWORK':
            preconditions.append('network_access')
        elif attack_vector == 'ADJACENT':
            preconditions.append('adjacent_network')
        elif attack_vector == 'LOCAL':
            preconditions.append('local_access')

        # Privilege requirements
        if privileges_required == 'HIGH':
            preconditions.append('admin_privileges')
        elif privileges_required == 'LOW':
            preconditions.append('user_privileges')

        # Service-specific requirements
        pkg_name = vuln.get('PkgName', '').lower()
        if 'apache' in pkg_name or 'nginx' in pkg_name:
            preconditions.append('web_service_running')
        elif 'mysql' in pkg_name or 'postgres' in pkg_name:
            preconditions.append('database_service_running')
        elif 'ssh' in pkg_name or 'openssh' in pkg_name:
            preconditions.append('ssh_service_running')

        return preconditions

    def _extract_tags(self, vuln: Dict) -> List[str]:
        """Extract research-relevant tags from vulnerability data."""
        tags = []

        # Add severity tag
        severity = vuln.get('Severity', 'UNKNOWN').upper()
        tags.append(f'severity:{severity}')

        # Add package/component tags
        pkg_name = vuln.get('PkgName', '')
        if pkg_name:
            tags.append(f'package:{pkg_name}')

        # Add CWE tags
        cwe_ids = vuln.get('CweIDs', [])
        for cwe in cwe_ids:
            tags.append(f'cwe:{cwe}')

        # Add attack vector tags
        if 'CVSS' in vuln:
            cvss = vuln['CVSS']
            if 'nvd' in cvss:
                vector = cvss['nvd'].get('V3Vector', '')
                if 'AV:N' in vector:
                    tags.append('remote')
                elif 'AV:L' in vector:
                    tags.append('local')

        return tags

    def extract_network_topology(self) -> nx.DiGraph:
        """Extract network topology from Kubernetes resources."""
        G = nx.DiGraph()

        # Add nodes from K8s nodes
        k8s_nodes = self.snapshot_data.get('nodes', {}).get('items', [])
        for node in k8s_nodes:
            node_name = node['metadata']['name']
            node_labels = node['metadata'].get('labels', {})

            G.add_node(node_name,
                       node_type='k8s_node',
                      labels=node_labels,
                      subnet=node_labels.get('subnet', 'default'))

        # Add pods as nodes
        pods = self.snapshot_data.get('pods', {}).get('items', [])
        for pod in pods:
            pod_name = pod['metadata']['name']
            pod_namespace = pod['metadata']['namespace']
            node_name = pod['spec'].get('nodeName', 'unknown')

            G.add_node(f'{pod_namespace}/{pod_name}',
                      node_type='pod',
                      host_node=node_name,
                      namespace=pod_namespace)

            # Add edge from K8s node to pod
            if node_name in G.nodes:
                G.add_edge(node_name, f'{pod_namespace}/{pod_name}')

        # Add services and their connections
        services = self.snapshot_data.get('services', {}).get('items', [])
        for service in services:
            svc_name = service['metadata']['name']
            svc_namespace = service['metadata']['namespace']
            selector = service['spec'].get('selector', {})

            G.add_node(f'{svc_namespace}/{svc_name}',
                      node_type='service',
                      selector=selector)

            # Connect service to matching pods
            for pod in pods:
                pod_labels = pod['metadata'].get('labels', {})
                if selector and all(pod_labels.get(k) == v for k, v in selector.items()):
                    G.add_edge(f'{svc_namespace}/{svc_name}',
                             f'{pod["metadata"]["namespace"]}/{pod["metadata"]["name"]}')

        return G

    def extract_firewall_rules(self) -> Dict[str, Dict]:
        """Extract and convert NetworkPolicies to firewall rules."""
        firewall_configs = {}
        netpols = self.snapshot_data.get('networkpolicies', {}).get('items', [])

        for netpol in netpols:
            policy_name = netpol['metadata']['name']
            namespace = netpol['metadata']['namespace']
            spec = netpol['spec']

            # Extract pod selector
            pod_selector = spec.get('podSelector', {})
            match_labels = pod_selector.get('matchLabels', {})

            # Initialize rules
            rules = {
                'incoming': [],
                'outgoing': [],
                'default_action': 'ALLOW'
            }

            policy_types = spec.get('policyTypes', [])

            # Process ingress rules
            if 'Ingress' in policy_types:
                ingress_rules = spec.get('ingress', [])
                if not ingress_rules:
                    # Empty ingress = deny all
                    rules['incoming'].append({
                        'port': 'ALL',
                        'permission': 'BLOCK',
                        'priority': 100
                    })
                else:
                    for idx, rule in enumerate(ingress_rules):
                        ports = rule.get('ports', [])
                        from_selectors = rule.get('from', [])

                        if ports:
                            for port in ports:
                                port_num = port.get('port', 'ALL')
                                protocol = port.get('protocol', 'TCP')
                                rules['incoming'].append({
                                    'port': str(port_num),
                                    'protocol': protocol,
                                    'permission': 'ALLOW',
                                    'from': from_selectors,
                                    'priority': 50 - idx
                                })
                        else:
                            rules['incoming'].append({
                                'port': 'ALL',
                                'permission': 'ALLOW',
                                'from': from_selectors,
                                'priority': 50 - idx
                            })

            # Process egress rules
            if 'Egress' in policy_types:
                egress_rules = spec.get('egress', [])
                if not egress_rules:
                    # Empty egress = deny all
                    rules['outgoing'].append({
                        'port': 'ALL',
                        'permission': 'BLOCK',
                        'priority': 100
                    })
                else:
                    for idx, rule in enumerate(egress_rules):
                        ports = rule.get('ports', [])
                        to_selectors = rule.get('to', [])

                        if ports:
                            for port in ports:
                                port_num = port.get('port', 'ALL')
                                protocol = port.get('protocol', 'TCP')
                                rules['outgoing'].append({
                                    'port': str(port_num),
                                    'protocol': protocol,
                                    'permission': 'ALLOW',
                                    'to': to_selectors,
                                    'priority': 50 - idx
                                })
                        else:
                            rules['outgoing'].append({
                                'port': 'ALL',
                                'permission': 'ALLOW',
                                'to': to_selectors,
                                'priority': 50 - idx
                            })

            # Store configuration
            key = f'{namespace}/{policy_name}'
            firewall_configs[key] = {
                'selector': match_labels,
                'rules': rules,
                'namespace': namespace
            }

        return firewall_configs

    def create_cyberbattle_nodes(self) -> Tuple[Dict[str, Any], ScenarioMetrics]:
        """Create CyberBattleSim nodes with empirical metrics tracking."""
        nodes = {}
        metrics_tracker = {
            'total_vulns': 0,
            'total_creds': 0,
            'cvss_dist': defaultdict(int),
            'value_dist': defaultdict(int),
            'vuln_classes': defaultdict(int)
        }

        # Extract network topology
        network_graph = self.extract_network_topology()

        # Extract firewall configurations
        firewall_configs = self.extract_firewall_rules()

        # Process K8s nodes
        k8s_nodes = self.snapshot_data.get('nodes', {}).get('items', [])
        pods = self.snapshot_data.get('pods', {}).get('items', [])
        services_data = self.vuln_data.get('services', [])

        # Map pods to nodes and extract container services
        node_to_pods = defaultdict(list)
        for pod in pods:
            node_name = pod['spec'].get('nodeName', 'unknown')
            if node_name != 'unknown':
                node_to_pods[node_name].append(pod)

        for node in k8s_nodes:
            node_name = node['metadata']['name']
            node_labels = node['metadata'].get('labels', {})

            # Determine node characteristics
            is_master = 'node-role.kubernetes.io/master' in node_labels or \
                        'node-role.kubernetes.io/control-plane' in node_labels
            subnet = node_labels.get('subnet', 'default')
            zone = node_labels.get('topology.kubernetes.io/zone', 'zone-a')

            # Calculate node value based on criticality
            if is_master:
                node_value = 100
            elif 'database' in subnet.lower():
                node_value = random.randint(70, 90)
            elif 'frontend' in subnet.lower():
                node_value = random.randint(30, 50)
            else:
                node_value = random.randint(20, 60)

            metrics_tracker['value_dist'][f'{node_value//20*20}-{node_value//20*20+19}'] += 1

            # Extract services from containers on this node
            node_services = []
            node_credentials = []

            # Process pods on this node
            for pod in node_to_pods.get(node_name, []):
                # Extract services from containers
                containers = pod['spec'].get('containers', [])
                for container in containers:
                    container_services = self._extract_container_services(container, pod)
                    node_services.extend(container_services)

                    # Extract credentials for this container
                    container_image = container.get('image', '')
                    container_creds = self._extract_container_credentials(
                        container, pod, container_image
                    )
                    node_credentials.extend(container_creds)

            # Process vulnerabilities
            node_vulns = []

            for service in services_data:
                if self._should_place_service_on_node(service, node_labels, subnet):
                    # Extract and enhance vulnerabilities
                    for image in service.get('docker_images', []):
                        for vuln in image.get('vulnerabilities', []):
                            enhanced_vuln = self.map_cvss_to_enhanced_vulnerability(vuln)
                            node_vulns.append(enhanced_vuln)
                            metrics_tracker['total_vulns'] += 1

                            # Track CVSS distribution
                            score_bucket = int(enhanced_vuln.cvss_score)
                            metrics_tracker['cvss_dist'][str(score_bucket)] += 1

                            # Track vulnerability classes
                            metrics_tracker['vuln_classes'][enhanced_vuln.vulnerability_class.value] += 1

            # Track total credentials
            metrics_tracker['total_creds'] += len(node_credentials)

            # Create node definition
            nodes[node_name] = {
                'services': node_services,
                'vulnerabilities': {v.id: v for v in node_vulns},
                'value': node_value,
                'properties': self._generate_node_properties(node_labels, is_master),
                'firewall': self._apply_firewall_config(node_labels, firewall_configs),
                'network_info': self._create_network_info(subnet, zone),
                'credentials': node_credentials,  # Store for reference
                'metadata': {
                    'kubernetes_labels': node_labels,
                    'is_master': is_master,
                    'subnet': subnet,
                    'zone': zone
                }
            }

        # Calculate final metrics
        metrics = self._calculate_scenario_metrics(nodes, network_graph, metrics_tracker)

        return nodes, metrics

    def _extract_container_services(self, container: Dict, pod: Dict) -> List[Dict]:
        """Extract services from container definition."""
        services = []
        container_name = container.get('name', 'unknown')
        container_ports = container.get('ports', [])

        # Extract exposed ports from container
        for port_def in container_ports:
            port = port_def.get('containerPort', 80)
            protocol = port_def.get('protocol', 'TCP')
            port_name = port_def.get('name', str(port))

            # Generate credential IDs for this service
            cred_ids = [
                f"{pod['metadata']['name']}_{container_name}_{port}_cred"
            ]

            services.append({
                'name': str(port),
                'port': port,
                'protocol': protocol,
                'port_name': port_name,
                'allowedCredentials': cred_ids,
                'container': container_name
            })

        # If no ports explicitly defined, infer from image
        if not services:
            image = container.get('image', '').lower()
            inferred_services = self._infer_services_from_image(image)

            for svc in inferred_services:
                cred_ids = [
                    f"{pod['metadata']['name']}_{container_name}_{svc['port']}_cred"
                ]
                svc['allowedCredentials'] = cred_ids
                svc['container'] = container_name
                services.append(svc)
        return services
    def _infer_services_from_image(self, image: str) -> List[Dict]:
        """Infer services from container image name."""
        services = []
        image_lower = image.lower()

        # Common service patterns
        service_patterns = {
            'nginx': [{'name': '80', 'port': 80, 'protocol': 'TCP', 'port_name': 'http'}],
            'apache': [{'name': '80', 'port': 80, 'protocol': 'TCP', 'port_name': 'http'}],
            'httpd': [{'name': '80', 'port': 80, 'protocol': 'TCP', 'port_name': 'http'}],
            'tomcat': [{'name': '8080', 'port': 8080, 'protocol': 'TCP', 'port_name': 'http'}],
            'mysql': [{'name': '3306', 'port': 3306, 'protocol': 'TCP', 'port_name': 'mysql'}],
            'mariadb': [{'name': '3306', 'port': 3306, 'protocol': 'TCP', 'port_name': 'mysql'}],
            'postgres': [{'name': '5432', 'port': 5432, 'protocol': 'TCP', 'port_name': 'postgres'}],
            'mongodb': [{'name': '27017', 'port': 27017, 'protocol': 'TCP', 'port_name': 'mongodb'}],
            'mongo': [{'name': '27017', 'port': 27017, 'protocol': 'TCP', 'port_name': 'mongodb'}],
            'redis': [{'name': '6379', 'port': 6379, 'protocol': 'TCP', 'port_name': 'redis'}],
            'elasticsearch': [{'name': '9200', 'port': 9200, 'protocol': 'TCP', 'port_name': 'http'}],
            'kibana': [{'name': '5601', 'port': 5601, 'protocol': 'TCP', 'port_name': 'http'}],
            'grafana': [{'name': '3000', 'port': 3000, 'protocol': 'TCP', 'port_name': 'http'}],
            'prometheus': [{'name': '9090', 'port': 9090, 'protocol': 'TCP', 'port_name': 'http'}],
            'jenkins': [{'name': '8080', 'port': 8080, 'protocol': 'TCP', 'port_name': 'http'}],
            'gitlab': [
                {'name': '80', 'port': 80, 'protocol': 'TCP', 'port_name': 'http'},
                {'name': '22', 'port': 22, 'protocol': 'TCP', 'port_name': 'ssh'}
            ],
            'ssh': [{'name': '22', 'port': 22, 'protocol': 'TCP', 'port_name': 'ssh'}],
            'ftp': [{'name': '21', 'port': 21, 'protocol': 'TCP', 'port_name': 'ftp'}],
            'rabbitmq': [{'name': '5672', 'port': 5672, 'protocol': 'TCP', 'port_name': 'amqp'}],
            'kafka': [{'name': '9092', 'port': 9092, 'protocol': 'TCP', 'port_name': 'kafka'}],
            'zookeeper': [{'name': '2181', 'port': 2181, 'protocol': 'TCP', 'port_name': 'zookeeper'}],
        }

        # Check for pattern matches
        for pattern, svcs in service_patterns.items():
            if pattern in image_lower:
                services.extend([svc.copy() for svc in svcs])
                # Do not break here to allow multiple matches, e.g. gitlab with ssh
                # break

        # Default service if nothing matched
        if not services:
            services.append({
                'name': '8080',
                'port': 8080,
                'protocol': 'TCP',
                'port_name': 'http-alt'
            })

        return services
    def _extract_container_credentials(self, container: Dict, pod: Dict,
                                       image: str) -> List[Dict]:
        """Extract credentials from container environment and secrets."""
        credentials = []
        container_name = container.get('name', 'unknown')
        pod_name = pod['metadata']['name']

        # Check environment variables for credentials
        env_vars = container.get('env', [])
        for env in env_vars:
            name = env.get('name', '').upper()
            value = env.get('value', '')

            # Common credential patterns in env vars
            cred_patterns = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'PASS', 'PWD', 'AUTH']

            if any(pattern in name for pattern in cred_patterns):
                cred_id = f"{pod_name}_{container_name}_{name}_{random.randint(1000,9999)}"

                # Determine credential type
                if 'ADMIN' in name:
                    cred_type = 'admin'
                elif 'ROOT' in name:
                    cred_type = 'root'
                elif 'API' in name:
                    cred_type = 'api_key'
                elif 'DATABASE' in name or 'DB' in name:
                    cred_type = 'database'
                else:
                    cred_type = 'service'

                credentials.append({
                    'id': cred_id,
                    'username': name.lower().replace('_password', '').replace('_secret', ''),
                    'password': 'REDACTED' if self.research_mode else value,
                    'service': container_name,
                    'image': image,
                    'type': cred_type,
                    'source': 'env'
                })
        # Check for mounted secrets
        volume_mounts = container.get('volumeMounts', [])
        for mount in volume_mounts:
            mount_name = mount.get('name', '')
            if 'secret' in mount_name.lower() or 'cred' in mount_name.lower():
                cred_id = f"{pod_name}_{container_name}_{mount_name}_{random.randint(1000,9999)}"
                credentials.append({
                    'id': cred_id,
                    'username': mount_name,
                    'password': 'REDACTED',
                    'service': container_name,
                    'image': image,
                    'type': 'secret_mount',
                    'source': 'volume'
                })

        # If no credentials found, create default service account
        if not credentials:
            cred_id = f"{pod_name}_{container_name}_sa_{random.randint(1000,9999)}"
            credentials.append({
                'id': cred_id,
                'username': 'serviceaccount',
                'password': 'REDACTED',
                'service': container_name,
                'image': image,
                'type': 'service_account',
                'source': 'default'
            })

        return credentials

    def _should_place_service_on_node(self, service: Dict, node_labels: Dict, subnet: str) -> bool:
        """Determine service placement with improved heuristics."""
        service_name = service.get('name', '').lower()
        is_master = 'node-role.kubernetes.io/master' in node_labels or \
                    'node-role.kubernetes.io/control-plane' in node_labels

        # Master node services
        master_services = ['api', 'controller', 'scheduler', 'etcd', 'coredns', 'kube-proxy']
        if any(term in service_name for term in master_services):
            return is_master

        # Database services
        db_services = ['database', 'mysql', 'postgres', 'postgresql', 'mariadb', 'mongodb',
                       'redis', 'cassandra', 'elasticsearch']
        if any(term in service_name for term in db_services):
            return 'database' in subnet.lower() or 'data' in subnet.lower()

        # Frontend services
        frontend_services = ['nginx', 'frontend', 'web', 'ui', 'portal', 'apache', 'httpd']
        if any(term in service_name for term in frontend_services):
            return 'frontend' in subnet.lower() or 'dmz' in subnet.lower()

        # Backend/API services
        backend_services = ['api', 'backend', 'service', 'app', 'application']
        if any(term in service_name for term in backend_services):
            return 'backend' in subnet.lower() or 'application' in subnet.lower()

        # Default placement for worker nodes
        return not is_master

    def _extract_service_credentials(self, service: Dict) -> List[Dict]:
        """Extract and enrich credential information."""
        credentials = []
        service_name = service.get('name', '')

        # Check for matching credential data
        if self.cred_data.get('service_name') == service_name:
            for image, creds in self.cred_data.get('raw_credentials_by_image', {}).items():
                for key, value in creds.items():
                    cred_id = f"{service_name}_{key}_{random.randint(1000,9999)}"
                    credentials.append({
                        'id': cred_id,
                        'username': key,
                        'password': value if not self.research_mode else 'REDACTED',
                        'service': service_name,
                        'image': image,
                        'type': self._infer_credential_type(key, service_name)
                    })
        # Generate synthetic credentials if none found (for completeness)
        if not credentials and self.research_mode:
            credentials.append({
                'id': f"{service_name}_default_{random.randint(1000,9999)}",
                'username': 'service_account',
                'password': 'REDACTED',
                'service': service_name,
                'type': 'service_account'
            })

        return credentials

    def _infer_credential_type(self, username: str, service: str) -> str:
        """Infer credential type from username and service context."""
        username_lower = username.lower()
        service_lower = service.lower()

        if 'admin' in username_lower:
            return 'admin'
        elif 'root' in username_lower:
            return 'root'
        elif 'sa' in username_lower or 'service' in username_lower:
            return 'service_account'
        elif 'api' in username_lower:
            return 'api_key'
        elif 'db' in service_lower or 'database' in service_lower:
            return 'database'
        else:
            return 'user'

    def _create_node_services(self, credentials: List[Dict]) -> List[Dict]:
        """Create service definitions with proper port mappings."""
        services = []
        service_ports = {
            'ssh': 22,
            'http': 80,
            'https': 443,
            'mysql': 3306,
            'postgres': 5432,
            'postgresql': 5432,
            'mongodb': 27017,
            'redis': 6379,
            'elasticsearch': 9200,
            'kibana': 5601,
            'grafana': 3000,
            'prometheus': 9090
        }

        # Group credentials by service type
        service_groups = defaultdict(list)
        for cred in credentials:
            service_name = cred.get('service', 'unknown').lower()

            # Find matching port
            port = None
            for srv_type, srv_port in service_ports.items():
                if srv_type in service_name:
                    port = srv_port
                    break

            if not port:
                port = 8080  # Default for unknown services

            service_groups[port].append(cred['id'])
        # Create service entries
        for port, cred_ids in service_groups.items():
            services.append({
                'name': str(port),
                'protocol': 'TCP',
                'allowedCredentials': cred_ids
            })

        return services

    def _generate_node_properties(self, labels: Dict, is_master: bool) -> List[str]:
        """Generate comprehensive node properties for research analysis."""
        properties = []

        # OS properties
        os_name = labels.get('kubernetes.io/os', 'linux')
        properties.append(os_name.capitalize())

        # Kubernetes role
        if is_master:
            properties.append('K8s_Master')
        else:
            properties.append('K8s_Worker')

        # Architecture
        arch = labels.get('kubernetes.io/arch', 'amd64')
        properties.append(f'arch:{arch}')

        # Container runtime
        runtime = labels.get('container.runtime', 'docker')
        properties.append(f'runtime:{runtime}')

        # Network properties
        subnet = labels.get('subnet', 'default')
        properties.append(f'subnet:{subnet}')

        # Zone/Region
        zone = labels.get('topology.kubernetes.io/zone', 'unknown')
        properties.append(f'zone:{zone}')

        return properties

    def _apply_firewall_config(self, node_labels: Dict, firewall_configs: Dict) -> Dict:
        """Apply NetworkPolicy-based firewall configuration."""
        # Find matching firewall configs
        applicable_configs = []

        for config_key, config in firewall_configs.items():
            selector = config.get('podSelector', {}).get('matchLabels', {})
            # Check if node labels match selector
            if all(node_labels.get(k) == v for k, v in selector.items()):
                applicable_configs.append(config)
        if not applicable_configs:
            # Return default permissive firewall
            return self._get_default_firewall(node_labels)

        # Merge all applicable configs (most restrictive wins)
        merged_rules = {
            'incoming': [],
            'outgoing': []
        }

        for config in applicable_configs:
            if 'ingress' in config:
                for rule in config['ingress']:
                    permission = 'ALLOW'  # Ingress rules in K8s are allow-based
                    ports = rule.get('ports', [{'port': 'ALL'}])
                    for port_rule in ports:
                        merged_rules['incoming'].append({
                            'port': str(port_rule.get('port', 'ALL')),
                            'permission': permission,
                            'protocol': port_rule.get('protocol', 'TCP')
                        })
            if 'egress' in config:
                 for rule in config['egress']:
                    permission = 'ALLOW'  # Egress rules in K8s are allow-based
                    ports = rule.get('ports', [{'port': 'ALL'}])
                    for port_rule in ports:
                        merged_rules['outgoing'].append({
                            'port': str(port_rule.get('port', 'ALL')),
                            'permission': permission,
                            'protocol': port_rule.get('protocol', 'TCP')
                        })

        # Sort by priority and remove duplicates
        merged_rules['incoming'] = self._deduplicate_rules(merged_rules['incoming'])
        merged_rules['outgoing'] = self._deduplicate_rules(merged_rules['outgoing'])

        return merged_rules

    def _get_default_firewall(self, node_labels: Dict) -> Dict:
        """Get default firewall configuration based on node type."""
        is_master = 'node-role.kubernetes.io/master' in node_labels or \
                    'node-role.kubernetes.io/control-plane' in node_labels

        if is_master:
            return {
                'incoming': [
                    {'port': '22', 'permission': 'ALLOW', 'protocol': 'TCP'},
                    {'port': '6443', 'permission': 'ALLOW', 'protocol': 'TCP'},  # API server
                    {'port': '2379', 'permission': 'ALLOW', 'protocol': 'TCP'},  # etcd
                    {'port': '10250', 'permission': 'ALLOW', 'protocol': 'TCP'}, # kubelet
                ],
                'outgoing': [
                    {'port': 'ALL', 'permission': 'ALLOW'}
                ]
            }
        else:
            return {
                'incoming': [
                    {'port': '22', 'permission': 'ALLOW', 'protocol': 'TCP'},
                    {'port': '80', 'permission': 'ALLOW', 'protocol': 'TCP'},
                    {'port': '443', 'permission': 'ALLOW', 'protocol': 'TCP'},
                    {'port': '10250', 'permission': 'ALLOW', 'protocol': 'TCP'},
                ],
                'outgoing': [
                    {'port': 'ALL', 'permission': 'ALLOW'}
                ]
            }

    def _deduplicate_rules(self, rules: List[Dict]) -> List[Dict]:
        """Remove duplicate firewall rules keeping most restrictive."""
        seen = set()
        deduped = []

        for rule in rules:
            key = (rule.get('port'), rule.get('protocol', 'TCP'))
            if key not in seen:
                seen.add(key)
                deduped.append(rule)

        return deduped

    def _create_network_info(self, subnet: str, zone: str) -> Dict:
        """Create detailed network information."""
        subnet_mappings = {
            'frontend': {'base': '10.1.0', 'vlan': 100},
            'backend': {'base': '10.2.0', 'vlan': 200},
            'database': {'base': '10.3.0', 'vlan': 300},
            'management': {'base': '10.4.0', 'vlan': 400},
            'dmz': {'base': '172.16.0', 'vlan': 50},
            'default': {'base': '10.0.0', 'vlan': 1}
        }

        subnet_info = subnet_mappings.get(subnet.replace('-tier', ''), subnet_mappings['default'])
        node_ip = f"{subnet_info['base']}.{random.randint(10, 250)}"

        return {
            'subnet': f"{subnet_info['base']}.0/24",
            'ip_address': node_ip,
            'vlan': subnet_info['vlan'],
            'zone': zone,
            'gateway': f"{subnet_info['base']}.1",
            'dns': ['8.8.8.8', '8.8.4.4']
        }

    def _calculate_scenario_metrics(self, nodes: Dict, network_graph: nx.DiGraph,
                                    tracker: Dict) -> ScenarioMetrics:
        """Calculate comprehensive metrics for empirical validation."""
        # Calculate attack surface
        total_services = sum(len(node.get('services', [])) for node in nodes.values())
        exposed_ports = set()
        for node in nodes.values():
            for service in node.get('services', []):
                exposed_ports.add(service['name'])

        # Calculate graph metrics
        if len(network_graph.nodes) > 1 and nx.is_strongly_connected(network_graph):
            try:
                avg_path_length = nx.average_shortest_path_length(network_graph)
            except nx.NetworkXError:
                avg_path_length = 0.0
        else:
            avg_path_length = 0.0

        graph_density = nx.density(network_graph) if len(network_graph.nodes) > 0 else 0.0

        # Calculate diversity metrics
        unique_vulns = len(set(v.id for node in nodes.values()
                               for v in node.get('vulnerabilities', {}).values()))
        vuln_diversity = unique_vulns / max(tracker['total_vulns'], 1) if tracker['total_vulns'] > 0 else 0

        # Calculate credential reuse
        all_creds = []
        for node in nodes.values():
            for service in node.get('services', []):
                all_creds.extend(service.get('allowedCredentials', []))

        unique_creds = len(set(all_creds))
        cred_reuse_ratio = 1 - (unique_creds / max(len(all_creds), 1)) if len(all_creds) > 0 else 0

        # Calculate firewall restrictiveness
        total_rules = 0
        block_rules = 0
        for node in nodes.values():
            fw = node.get('firewall', {})
            for direction in ['incoming', 'outgoing']:
                for rule in fw.get(direction, []):
                    total_rules += 1
                    if rule.get('permission') == 'BLOCK':
                        block_rules += 1

        firewall_restrictiveness = block_rules / max(total_rules, 1) if total_rules > 0 else 0

        # Estimate difficulty based on multiple factors
        difficulty_score = (
            (1 - vuln_diversity) * 0.2 +  # Less diversity = harder
            firewall_restrictiveness * 0.3 +  # More restrictive = harder
            (avg_path_length / 10.0) * 0.2 +  # Longer paths = harder
            (1 - graph_density) * 0.15 +  # Less connected = harder
            (1 - cred_reuse_ratio) * 0.15  # Less reuse = harder
        )

        return ScenarioMetrics(
            total_nodes=len(nodes),
            total_vulnerabilities=tracker['total_vulns'],
            total_credentials=tracker['total_creds'],
            attack_surface_size=len(exposed_ports),
            average_path_length=avg_path_length,
            graph_density=graph_density,
            vulnerability_diversity=vuln_diversity,
            credential_reuse_ratio=cred_reuse_ratio,
            firewall_restrictiveness=firewall_restrictiveness,
            estimated_difficulty=difficulty_score,
            cvss_distribution=dict(tracker['cvss_dist']),
            node_value_distribution=dict(tracker['value_dist'])
        )

    def validate_scenario(self, nodes: Dict, metrics: ScenarioMetrics) -> Dict[str, Any]:
        """Validate generated scenario for research quality."""
        validation_results = {
            'passed': True,
            'warnings': [],
            'errors': [],
            'recommendations': []
        }

        # Check minimum complexity
        if metrics.total_nodes < 3:
            validation_results['errors'].append('Scenario has fewer than 3 nodes')
            validation_results['passed'] = False

        if metrics.total_vulnerabilities < 5:
            validation_results['warnings'].append('Low vulnerability count may limit DRL exploration')

        # Check realism
        if metrics.credential_reuse_ratio > 0.8:
            validation_results['warnings'].append('Very high credential reuse - may be unrealistic')

        if metrics.graph_density > 0.9:
            validation_results['warnings'].append('Graph is nearly complete - may be unrealistic')

        # Check balance
        vuln_to_node_ratio = metrics.total_vulnerabilities / max(metrics.total_nodes, 1) if metrics.total_nodes > 0 else 0
        if vuln_to_node_ratio > 20:
            validation_results['warnings'].append('Very high vulnerability density')
        elif vuln_to_node_ratio < 2:
            validation_results['warnings'].append('Low vulnerability density may limit attack paths')

        # Research recommendations
        if metrics.estimated_difficulty < 0.3:
            validation_results['recommendations'].append(
                'Scenario may be too easy - consider increasing firewall rules or reducing vulnerabilities'
            )
        elif metrics.estimated_difficulty > 0.7:
            validation_results['recommendations'].append(
                'Scenario may be too difficult - consider adding more attack paths'
            )

        # Check for isolated nodes
        for node_name, node_data in nodes.items():
            if not node_data.get('services'):
                validation_results['warnings'].append(f'Node {node_name} has no services')

        return validation_results

    def generate_scenario(self) -> Tuple[str, ScenarioMetrics, Dict]:
        """Generate complete validated CyberBattleSim scenario."""
        print("🔧 Generating CyberBattleSim scenario...")

        # Generate nodes and calculate metrics
        nodes, metrics = self.create_cyberbattle_nodes()

        # Validate scenario
        validation = self.validate_scenario(nodes, metrics)

        # Generate Python code
        scenario_code = self._generate_python_code(nodes)

        # Store metrics and validation for research
        self.metrics = metrics
        self.validation_results = validation

        return scenario_code, metrics, validation

    def _generate_python_code(self, nodes: Dict) -> str:
        """Generate clean Python code for CyberBattleSim."""
        scenario_name = f"K8sScenario"

        # Collect all unique vulnerabilities for the library
        vulnerability_library = {}
        for node_data in nodes.values():
            for vuln_id, vuln in node_data.get('vulnerabilities', {}).items():
                if vuln_id not in vulnerability_library:
                    vulnerability_library[vuln_id] = vuln
        code_lines = [
            "#!/usr/bin/env python3",
            '"""',
            f"Generated CyberBattleSim scenario from Kubernetes cluster",
            f"Generated at: {datetime.now().isoformat()}",
            f"Total nodes: {len(nodes)}",
            f"Total vulnerabilities: {len(vulnerability_library)}",
            '"""',
"from typing import Iterator, cast, Tuple,Dict",
"from cyberbattle.simulation.vulenrabilites import *",
"from cyberbattlesim_network_gen.generators.network_generator import NetworkGenerator",
"from cyberbattle.simulation.nodes_types import NodeID",
"from cyberbattle.simulation.nodes import NodeInfo",
"from cyberbattle.simulation.firewall import FirewallRule, RulePermission, FirewallConfiguration",
"from cyberbattle.simulation.vulenrabilites import VulnerabilityID",
"from cyberbattle.simulation.services import ListeningService",
"from cyberbattlesim_network_gen.generators.utils import *",
"from cyberbattle.simulation.identifiers import Identifiers",
"from cyberbattle.simulation.nodes_network import infer_constants_from_nodes",
"from cyberbattle.simulation.network import NodeNetworkInfo,Subnet,NetworkInterfaces",
"from cyberbattle.simulation.vulenrabilites import VulnerabilityInfo, LeakedNodesId, VulnerabilityType,  LeakedCredentials, CachedCredential",            "",
            "",
            f"class {scenario_name}(NetworkGenerator):",
            '    """Auto-generated K8s environment for DRL research."""',
            "",
            "    def __init__(self,*args,**kwargs):",
            "        super().__init__(**kwargs)",
            "        # Define vulnerability library",
            "        self.vulnerability_library = {"
        ]

        # Generate vulnerability library entries
        for vuln_id, vuln in vulnerability_library.items():
            if isinstance(vuln, EnhancedVulnerability):
                # Determine vulnerability type
                vuln_type = "REMOTE" if 'N' in vuln.attack_vector else "LOCAL"

                # Generate outcome based on vulnerability class
                outcome_code = self._generate_outcome_code(vuln)

                code_lines.extend([
                    f'            "{vuln.id}": VulnerabilityInfo(',
                    f'                description="""{vuln.description[:200]}""",',
                    f'                type=VulnerabilityType.{vuln_type},',
                    f'                outcome={outcome_code},',
                    f'                reward_string="Exploited {vuln.id}",',
                    f'                cost={1.0 / vuln.success_rate:.1f}',
                    '            ),',
                ])
        code_lines.append('        }')
        code_lines.append('')
        code_lines.append('        # Define nodes')
        code_lines.append('        self.nodes: Dict[NodeID, NodeInfo] = {')

        # Generate node entries (referencing vulnerabilities from library)
        for node_name, node_data in nodes.items():
            code_lines.append(f'            "{node_name}": NodeInfo(')
            
            # Network Info
            net_info = node_data.get('network_info', {})
            ip = net_info.get('ip_address', '127.0.0.1')
            subnet = net_info.get('subnet', '127.0.0.0/24')
            code_lines.append(f'                network_info=[NodeNetworkInfo(ip_address="{ip}", subnet=Subnet("{subnet}"))],')

            code_lines.append(f'                services=[')
            for s in node_data.get("services", []):
                code_lines.append(f'                    ListeningService(name="{s["port_name"]}", port={s["port"]},')
                code_lines.append(f'                    allowedCredentials={s["allowedCredentials"]}),')
            code_lines.append(f'                ],')

            code_lines.append(f'                value={node_data.get("value", 0)},')

            # Add properties
            props_str = ', '.join([f'"{p}"' for p in node_data.get('properties', [])])
            code_lines.append(f'                properties=[{props_str}],')
            
            # Add firewall configuration
            fw_config = node_data.get('firewall', {})
            incoming_rules_str = []
            for rule in fw_config.get('incoming', []):
                permission = f"RulePermission.{rule.get('permission', 'BLOCK')}"
                incoming_rules_str.append(f'FirewallRule(port="{rule.get("port", "ALL")}", permission={permission})')

            outgoing_rules_str = []
            for rule in fw_config.get('outgoing', []):
                permission = f"RulePermission.{rule.get('permission', 'BLOCK')}"
                outgoing_rules_str.append(f'FirewallRule(port="{rule.get("port", "ALL")}", permission={permission})')

            if incoming_rules_str or outgoing_rules_str:
                code_lines.append(f'                firewall=FirewallConfiguration(')
                code_lines.append(f'                    incoming=[{", ".join(incoming_rules_str)}],')
                code_lines.append(f'                    outgoing=[{", ".join(outgoing_rules_str)}],')
                code_lines.append(f'                ),')


            # Reference vulnerabilities from library
            vuln_ids = list(node_data.get('vulnerabilities', {}).keys())
            if vuln_ids:
                vuln_refs_list = [f'"{vid}": self.vulnerability_library["{vid}"]' for vid in vuln_ids]
                vuln_refs = ', '.join(vuln_refs_list)
                code_lines.append(f'                vulnerabilities={{{vuln_refs}}},')

            else:
                code_lines.append('                vulnerabilities={},')

            code_lines.append('            ),')

        code_lines.extend([
            "        }",
        ]+GET_IDENTIFERS_FUNC.split("\n")+GET_NODES_FUNC.split("\n")+[
            "    def get_vulnerability_library(self):",
            "           return self.vulnerability_library",
            "    def get_default_allow_rules(self):",
            "        return [FirewallRule(\"SSH\", RulePermission.ALLOW), ]",
            "if __name__ == '__main__':",
            f"   cli_default({scenario_name})",
        ])

        return '\n'.join(code_lines)

    def _generate_outcome_code(self, vuln: EnhancedVulnerability) -> str:
        """Generate outcome code for vulnerability."""
        if vuln.vulnerability_class == VulnerabilityClass.CREDENTIAL_DISCLOSURE:
            # Generate leaked credentials
            creds = []
            for outcome in vuln.outcomes:
                if outcome.get('type') == 'LeakedCredentials':
                    for cred in outcome.get('credentials', []):
                        creds.append(f'CachedCredential(node="{cred.get("node", "unknown")}", '
                                   f'port="{cred.get("port", "22")}", '
                                   f'credential="{cred.get("credential", "cred")}")')
            if creds:
                return f'LeakedCredentials([{", ".join(creds)}])'
            return 'LeakedCredentials([])'

        elif vuln.vulnerability_class == VulnerabilityClass.PRIVILEGE_ESCALATION:
            level = 'Admin'  # Default
            for outcome in vuln.outcomes:
                if outcome.get('type') == 'PrivilegeEscalation':
                    level = outcome.get('level', 'Admin')
                    break
            return f'PrivilegeEscalation(PrivilegeLevel.{level})'

        elif vuln.vulnerability_class == VulnerabilityClass.INFORMATION_DISCLOSURE:
            # Find leaked nodes from outcomes
            nodes = []
            for outcome in vuln.outcomes:
                if outcome.get('type') == 'LeakedNodesId':
                    nodes.extend(outcome.get('nodes', []))
            if nodes:
                nodes_str = ', '.join([f'"{n}"' for n in nodes[:3]])  # Limit to 3
                return f'LeakedNodesId([{nodes_str}])'
            return 'LeakedNodesId([])'

        else:
            # Default to no outcome
            return 'NoOutcome()'

    def export_for_research(self, output_dir: str):
        """Export scenario with full research data."""
        if not self.metrics:
            self.generate_scenario() # Generate if not already done

        os.makedirs(output_dir, exist_ok=True)

        with open(os.path.join(output_dir, 'metrics.json'), 'w') as f:
            json.dump(asdict(self.metrics), f, indent=2)
        with open(os.path.join(output_dir, 'validation.json'), 'w') as f:
            json.dump(self.validation_results, f, indent=2)

        G = self.extract_network_topology()
        # Clean up graph for export
        for _, data in G.nodes(data=True):
            for key, value in list(data.items()):
                if isinstance(value, (dict, list)):
                    data[key] = json.dumps(value)

        nx.write_graphml(G, os.path.join(output_dir, 'topology.graphml'))
        print(f"✅ Research data exported to {output_dir}")

def main():
    """Main function with enhanced CLI."""
    parser = argparse.ArgumentParser(
        description="Generate empirically validated CyberBattleSim scenarios from K8s clusters."
    )
    parser.add_argument("snapshot_path", help="Path to cluster snapshot directory")
    parser.add_argument("info_path", help="Path to vulnerability/credential files")
    parser.add_argument("-o", "--output", required=True, help="Output Python file")
    parser.add_argument("--research-dir", help="Directory for research artifacts")
    parser.add_argument("--seed", type=int, help="Random seed for reproducibility")
    parser.add_argument("--validate-only", action="store_true", help="Only validate, don't generate")

    args = parser.parse_args()

    # Initialize generator
    generator = K8sScenarioGenerator(
        args.snapshot_path,
        args.info_path,
        research_mode=True,
        seed=args.seed
    )

    # Generate scenario
    scenario_code, metrics, validation = generator.generate_scenario()

    # Print validation results
    print("\n📊 Scenario Metrics:")
    print(f"  - Nodes: {metrics.total_nodes}")
    print(f"  - Vulnerabilities: {metrics.total_vulnerabilities}")
    print(f"  - Attack Surface: {metrics.attack_surface_size} ports")
    print(f"  - Estimated Difficulty: {metrics.estimated_difficulty:.2%}")

    print("\n✅ Validation Results:")
    print(f"  - Status: {'PASSED' if validation['passed'] else 'FAILED'}")
    if validation['errors']:
        print(f"  - Errors: {', '.join(validation['errors'])}")
    if validation['warnings']:
        print(f"  - Warnings: {', '.join(validation['warnings'][:3])}")
    if validation.get('recommendations'):
        print(f"  - Recommendations: {validation['recommendations'][0]}")

    if not args.validate_only and validation['passed']:
        # Save scenario
        with open(args.output, 'w') as f:
            f.write(scenario_code)
        print(f"\n💾 Scenario saved to: {args.output}")

        # Export research artifacts if requested
        if args.research_dir:
            generator.export_for_research(args.research_dir)
    elif not validation['passed']:
        print("\n❌ Scenario failed validation - not generated")
        return 1

    return 0

if __name__ == '__main__':
    exit(main())