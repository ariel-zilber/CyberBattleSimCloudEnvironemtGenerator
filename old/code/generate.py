#!/usr/bin/env python3
import json
import os
import sys
import re
from typing import Dict, List, Any, Tuple, Optional
from collections import deque

class CVSSParser:
    """Parse and interpret CVSS vectors for CyberBattleSim mapping"""
    
    def __init__(self):
        # CVSS v3 metric mappings
        self.v3_metrics = {
            'AV': {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'},
            'AC': {'L': 'Low', 'H': 'High'},
            'PR': {'N': 'None', 'L': 'Low', 'H': 'High'},
            'UI': {'N': 'None', 'R': 'Required'},
            'S': {'U': 'Unchanged', 'C': 'Changed'},
            'C': {'H': 'High', 'L': 'Low', 'N': 'None'},
            'I': {'H': 'High', 'L': 'Low', 'N': 'None'},
            'A': {'H': 'High', 'L': 'Low', 'N': 'None'}
        }
        
        # CVSS v2 metric mappings
        self.v2_metrics = {
            'AV': {'N': 'Network', 'A': 'Adjacent', 'L': 'Local'},
            'AC': {'L': 'Low', 'M': 'Medium', 'H': 'High'},
            'Au': {'N': 'None', 'S': 'Single', 'M': 'Multiple'},
            'C': {'N': 'None', 'P': 'Partial', 'C': 'Complete'},
            'I': {'N': 'None', 'P': 'Partial', 'C': 'Complete'},
            'A': {'N': 'None', 'P': 'Partial', 'C': 'Complete'}
        }
    
    def parse_cvss_vector(self, vector: str) -> Dict[str, str]:
        """Parse CVSS vector string into components"""
        if not vector:
            return {}
        
        version = '2.0'
        if vector.startswith('CVSS:3'):
            version = '3.x'
        
        metrics = {}
        metric_pattern = r'([A-Za-z]+):([A-Za-z]+)'
        matches = re.findall(metric_pattern, vector)
        
        for metric, value in matches:
            metrics[metric] = value
        
        metrics['version'] = version
        return metrics
    
    def get_vulnerability_type(self, metrics: Dict[str, str]) -> str:
        """Determine vulnerability type from CVSS metrics"""
        av = metrics.get('AV', '')
        
        if av in ['N', 'A']:
            return 'remote'
        elif av in ['L', 'P']:
            return 'local'
        else:
            return 'local'
    
    def requires_privileges(self, metrics: Dict[str, str]) -> bool:
        """Check if vulnerability requires existing privileges"""
        version = metrics.get('version', '2.0')
        
        if version.startswith('3'):
            pr = metrics.get('PR', 'N')
            return pr in ['L', 'H']
        else:
            au = metrics.get('Au', 'N')
            return au in ['S', 'M']
    
    def get_success_rate(self, metrics: Dict[str, str]) -> float:
        """Calculate success rate from CVSS metrics"""
        ac = metrics.get('AC', 'L')
        ui = metrics.get('UI', 'N') 
        pr = metrics.get('PR', 'N')
        
        if ac == 'H':
            base_rate = 0.3
        elif ac == 'M':
            base_rate = 0.7
        else:
            base_rate = 0.9
        
        if ui == 'R':
            base_rate *= 0.6
            
        if pr in ['L', 'H']:
            base_rate *= 0.8
            
        return max(0.1, min(1.0, base_rate))
    
    def get_probing_detection_rate(self, metrics: Dict[str, str]) -> float:
        """Calculate probing detection rate from CVSS metrics"""
        av = metrics.get('AV', 'L')
        
        if av == 'N':
            return 0.15
        elif av == 'A':
            return 0.10
        else:
            return 0.05
    
    def get_exploit_detection_rate(self, metrics: Dict[str, str]) -> float:
        """Calculate exploit detection rate from CVSS metrics"""
        av = metrics.get('AV', 'L')
        ac = metrics.get('AC', 'L')
        
        base_rate = 0.05
        
        if av == 'N':
            base_rate = 0.25
        elif av == 'A':
            base_rate = 0.15
        
        if ac == 'H':
            base_rate *= 0.7
        elif ac == 'M':
            base_rate *= 0.85
            
        return max(0.01, min(0.5, base_rate))
    
    def calculate_exploit_cost(self, metrics: Dict[str, str]) -> float:
        """Calculate exploit cost based on complexity and requirements"""
        ac = metrics.get('AC', 'L')
        ui = metrics.get('UI', 'N')
        pr = metrics.get('PR', 'N')
        
        cost = 1.0
        
        if ac == 'H':
            cost *= 3.0
        elif ac == 'M':
            cost *= 1.5
        
        if ui == 'R':
            cost *= 2.0
            
        if pr in ['L', 'H']:
            cost *= 1.5
            
        return cost
    
    def requires_user_interaction(self, metrics: Dict[str, str]) -> bool:
        """Check if vulnerability requires user interaction"""
        ui = metrics.get('UI', 'N')
        return ui == 'R'
    
    def calculate_impact_score(self, metrics: Dict[str, str]) -> Tuple[float, str]:
        """Calculate impact score and type from CIA metrics"""
        c_impact = metrics.get('C', 'N')
        i_impact = metrics.get('I', 'N')
        a_impact = metrics.get('A', 'N')
        
        impact_values = {'N': 0, 'L': 1, 'P': 1, 'H': 2, 'C': 2}
        
        c_score = impact_values.get(c_impact, 0)
        i_score = impact_values.get(i_impact, 0)
        a_score = impact_values.get(a_impact, 0)
        
        total_impact = c_score + i_score + a_score
        
        if c_score >= max(i_score, a_score):
            impact_type = "information_disclosure"
        elif i_score >= max(c_score, a_score):
            impact_type = "data_modification"
        elif a_score >= max(c_score, i_score):
            impact_type = "service_disruption"
        else:
            impact_type = "information_disclosure"
        
        return total_impact, impact_type
    
    def has_scope_change(self, metrics: Dict[str, str]) -> bool:
        """Check if vulnerability allows scope change"""
        scope = metrics.get('S', 'U')
        return scope == 'C'
    
    def map_cvss_to_cyberbattle_outcome(self, metrics: Dict[str, str], vuln_id: str) -> str:
        """Map CVSS metrics to CyberBattleSim outcome types"""
        c_impact = metrics.get('C', 'N')
        i_impact = metrics.get('I', 'N')
        has_scope_change = self.has_scope_change(metrics)
        vuln_type = self.get_vulnerability_type(metrics)
        requires_privileges = self.requires_privileges(metrics)
        
        if has_scope_change or (not requires_privileges and (c_impact in ['H', 'C'] or i_impact in ['H', 'C'])):
            if c_impact in ['H', 'C'] and i_impact in ['H', 'C']:
                return "system_escalation"
            elif c_impact in ['H', 'C'] or i_impact in ['H', 'C']:
                return "admin_escalation"
            else:
                return "privilege_escalation"
        
        if c_impact in ['H', 'C']:
            return "leaked_credentials"
        
        if c_impact in ['L', 'P'] and i_impact in ['L', 'P', 'H', 'C']:
            return "customer_data"
        
        if vuln_type == 'remote' and not requires_privileges:
            return "leaked_nodes_id"
        
        if vuln_type == 'remote' and requires_privileges:
            return "lateral_move"
        
        return "probe_succeeded"
    
    def create_cyberbattle_outcome_object(self, outcome_type: str, vuln_id: str, metrics: Dict[str, str], service_name: str = None, network_nodes: List[str] = None) -> Dict[str, Any]:
        """Create the actual outcome object structure"""
        outcome_data = {"type": outcome_type, "kwargs": {}}
        
        if outcome_type == "leaked_credentials":
            if service_name:
                outcome_data["kwargs"] = {
                    "credentials": [{
                        "type": "cached_credentials", 
                        "kwargs": {
                            "node": "target_node",
                            "port": service_name,
                            "credential": vuln_id,
                            "valid": True
                        }
                    }]
                }
            else:
                outcome_data["kwargs"] = {"credentials": []}
        
        elif outcome_type == "leaked_nodes_id":
            nodes_list = network_nodes[:3] if network_nodes else []
            outcome_data["kwargs"] = {"nodes": nodes_list}
        
        elif outcome_type in ["admin_escalation", "system_escalation", "privilege_escalation"]:
            privilege_levels = {
                "privilege_escalation": 1,
                "admin_escalation": 2,
                "system_escalation": 3
            }
            outcome_data["kwargs"] = {
                "level": privilege_levels.get(outcome_type, 1)
            }
        
        elif outcome_type == "probe_succeeded":
            properties = []
            if metrics.get('AV') == 'N':
                properties.append("network_accessible")
            if metrics.get('AC') == 'H':
                properties.append("complex_exploit")
            
            outcome_data["kwargs"] = {
                "discovered_properties": properties or ["basic_info"]
            }
        
        return outcome_data

class CyberBattleSimEnvironmentGenerator:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.cvss_parser = CVSSParser()
    
    def load_project_data(self, project_path: str) -> Dict[str, Any]:
        """Load all project data files"""
        project_data = {}
        
        analysis_path = os.path.join(project_path, "helm_analysis_with_cves_and_secrets.json")
        if os.path.exists(analysis_path):
            with open(analysis_path, 'r') as f:
                project_data['analysis'] = json.load(f)
        
        workload_path = os.path.join(project_path, "workload_details.json")
        if os.path.exists(workload_path):
            with open(workload_path, 'r') as f:
                project_data['workloads'] = json.load(f)
        
        service_path = os.path.join(project_path, "service_details.json")
        if os.path.exists(service_path):
            with open(service_path, 'r') as f:
                project_data['services'] = json.load(f)
        
        # Correctly load credentials from raw_credentials.json
        creds_path = os.path.join(project_path, "credentials", "raw_credentials.json")
        if os.path.exists(creds_path):
            with open(creds_path, 'r') as f:
                project_data['credentials'] = json.load(f)
        
        return project_data
    
    def extract_cvss_data(self, vuln_data: Dict[str, Any]) -> Tuple[float, str, Dict[str, str]]:
        """Extract CVSS score, vector and parsed metrics"""
        cvss_score = 0.0
        cvss_vector = ""
        
        if "CVSS" in vuln_data and isinstance(vuln_data["CVSS"], dict):
            nvd_data = vuln_data["CVSS"].get("nvd", {})
            
            # Use .get() for safe access to prevent KeyErrors
            cvss_vector = nvd_data.get("V3Vector")
            if cvss_vector:
                cvss_score = nvd_data.get("V3Score", 0.0)
            else:
                cvss_vector = nvd_data.get("V2Vector", "")
                if cvss_vector:
                    cvss_score = nvd_data.get("V2Score", 0.0)
        
        parsed_metrics = self.cvss_parser.parse_cvss_vector(cvss_vector)
        return cvss_score, cvss_vector, parsed_metrics
    
    def map_cvss_to_vulnerability(self, vuln_data: Dict[str, Any], service_name: str = "default-service", network_nodes: List[str] = None) -> Optional[Dict[str, Any]]:
        """Convert CVE to CyberBattleSim vulnerability"""
        vuln_id = vuln_data.get("VulnerabilityID", "N/A")
        cvss_score, cvss_vector, metrics = self.extract_cvss_data(vuln_data)
        
        if not metrics or not cvss_vector:
            return None
        
        vuln_type = self.cvss_parser.get_vulnerability_type(metrics)
        requires_privileges = self.cvss_parser.requires_privileges(metrics)
        success_rate = self.cvss_parser.get_success_rate(metrics)
        probing_detection_rate = self.cvss_parser.get_probing_detection_rate(metrics)
        exploit_detection_rate = self.cvss_parser.get_exploit_detection_rate(metrics)
        requires_user_interaction = self.cvss_parser.requires_user_interaction(metrics)
        impact_score, impact_type = self.cvss_parser.calculate_impact_score(metrics)
        
        preconditions = []
        if requires_privileges:
            if vuln_type == "remote":
                preconditions.append("has_credentials")
            else:
                preconditions.append("has_local_access")
        
        if requires_user_interaction:
            preconditions.append("user_interaction")
        
        if len(preconditions) > 1:
            precondition_obj = {
                "type": "and",
                "conditions": [{"type": cond} for cond in preconditions]
            }
        elif len(preconditions) == 1:
            precondition_obj = {"type": preconditions[0]}
        else:
            precondition_obj = {"type": "true"}
        
        outcome_type = self.cvss_parser.map_cvss_to_cyberbattle_outcome(metrics, vuln_id)
        outcome_object = self.cvss_parser.create_cyberbattle_outcome_object(outcome_type, vuln_id, metrics, service_name, network_nodes)
        
        return {
            "description": f"CVSS-based vulnerability {vuln_id}",
            "type": 3 if vuln_type == "remote" else 2,
            "outcome": outcome_object,
            "precondition": precondition_obj,
            "rates": {
                "probingDetectionRate": probing_detection_rate,
                "exploitDetectionRate": exploit_detection_rate,
                "successRate": success_rate
            },
            "URL": f"https://nvd.nist.gov/vuln/detail/{vuln_id}",
            "cost": self.cvss_parser.calculate_exploit_cost(metrics),
            "reward_string": vuln_data.get("Description", vuln_data.get("description", f"Exploited {vuln_id}")),
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "impact_type": impact_type
        }
    
    def group_vulnerabilities_by_attack_chain(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group vulnerabilities into logical attack chains"""
        initial_access = []
        privilege_escalation = []
        lateral_movement = []
        
        for vuln in vulnerabilities:
            precondition_type = vuln.get("precondition", {}).get("type", "true")
            
            if precondition_type == "true":
                if vuln["type"] == 3:
                    initial_access.append(vuln)
                else:
                    privilege_escalation.append(vuln)
            elif "has_credentials" in precondition_type:
                lateral_movement.append(vuln)
            else:
                privilege_escalation.append(vuln)
        
        return initial_access + privilege_escalation + lateral_movement
        
    def build_nodes(self, project_data: Dict[str, Any], project_name: str) -> Dict[str, Any]:
        """Build nodes from project data"""
        nodes = {}
        workloads = project_data.get('workloads', {})
        analysis = project_data.get('analysis', {})

        # Step 1: Create a lookup map of image names to their vulnerabilities for efficient access.
        image_to_vulns = {}
        for service in analysis.get('services', []):
            for image in service.get('docker_images', []):
                # Ensure the image scan was successful and vulnerabilities are present
                if image.get('status') == 'success' and 'vulnerabilities' in image:
                    # The image name/ID used in workload definitions
                    image_id = image.get('name')
                    if image_id:
                        image_to_vulns[image_id] = image.get('vulnerabilities', [])
        
        # Group nodes by workload type for Kubernetes-realistic discovery
        workload_groups = {}
        for workload_type, workload_items in workloads.items():
            workload_groups[workload_type] = []
            for workload_name in workload_items.keys():
                node_name = f"{workload_type}_{workload_name}"
                workload_groups[workload_type].append(node_name)
        
        if not workload_groups:
            workload_groups = {"default": [project_name]}
        
        # Step 2: Build nodes and correctly map vulnerabilities from images.
        for workload_type, workload_items in workloads.items():
            for workload_name, workload_data in workload_items.items():
                node_name = f"{workload_type}_{workload_name}"
                
                if isinstance(workload_data, list):
                    workload_data = workload_data[0]

                # Extract services (ports) from the workload
                services = []
                base_service_name = workload_name
                containers = workload_data.get('containers', [])
                for container in containers:
                    if isinstance(container, dict):
                        ports = container.get('ports', [])
                        if ports:
                            for port in ports:
                                port_num = port.get('containerPort', '')
                                service_name = f"{base_service_name}-{port_num}" if len(ports) > 1 else base_service_name
                                services.append({"name": service_name})
                        else:
                            services.append({"name": base_service_name})
                if not services:
                    services = [{"name": base_service_name}]
                
                # Simplified Kubernetes discovery logic (existing logic is kept)
                discoverable_nodes = []
                same_type_nodes = workload_groups.get(workload_type, [])
                discoverable_nodes.extend(same_type_nodes)
                for related_type, related_nodes in workload_groups.items():
                    if related_type != workload_type:
                        discoverable_nodes.extend(related_nodes)
                discoverable_nodes = sorted(list(set(n for n in discoverable_nodes if n != node_name)))

                # Step 3: Use the image_to_vulns map to get the right vulnerabilities.
                vulnerabilities = []
                for container in containers:
                    if isinstance(container, dict):
                        image_id = container.get('image')
                        # If the container's image has known vulnerabilities
                        if image_id in image_to_vulns:
                            # For each service on this node, map the vulnerabilities from the image
                            for service_info in services:
                                service_name = service_info.get("name", "default-service")
                                for vuln in image_to_vulns[image_id]:
                                    mapped_vuln = self.map_cvss_to_vulnerability(vuln, service_name, discoverable_nodes)
                                    if mapped_vuln and mapped_vuln not in vulnerabilities:
                                        vulnerabilities.append(mapped_vuln)
                
                vulnerabilities = self.group_vulnerabilities_by_attack_chain(vulnerabilities)
                
                nodes[node_name] = {
                    "services": services,
                    "vulnerabilities": vulnerabilities,
                    "firewall": {"incoming": [], "outgoing": []},
                    "os_type": self.infer_os_type(workload_data),
                    "node_type": workload_type
                }
        
        # Step 4: Corrected fallback for projects without workload details.
        if not nodes and image_to_vulns:
            vulnerabilities = []
            # Aggregate all vulnerabilities from all scanned images
            all_project_vulns = []
            for image_vulns in image_to_vulns.values():
                all_project_vulns.extend(image_vulns)
            
            for vuln in all_project_vulns:
                mapped_vuln = self.map_cvss_to_vulnerability(vuln, "default-service", [])
                if mapped_vuln and mapped_vuln not in vulnerabilities:
                    vulnerabilities.append(mapped_vuln)
            
            vulnerabilities = self.group_vulnerabilities_by_attack_chain(vulnerabilities)
            
            nodes[project_name] = {
                "services": [{"name": "default-service"}],
                "vulnerabilities": vulnerabilities,
                "firewall": {"incoming": [], "outgoing": []},
                "os_type": "linux",
                "node_type": "application"
            }
        
        return nodes 
   
    def infer_os_type(self, workload_data: Dict[str, Any]) -> str:
        """Infer OS type from workload data"""
        containers = workload_data.get('containers', [])
        for container in containers:
            if isinstance(container, dict):
                image = container.get('image', '').lower()
                if 'windows' in image:
                    return 'windows'
                elif any(distro in image for distro in ['ubuntu', 'debian', 'alpine', 'centos', 'rhel']):
                    return 'linux'
        
        return 'linux'
        
    def build_credentials(self, project_data: Dict[str, Any], nodes: Dict[str, Any]) -> Dict[str, Any]:
        """Build credentials from project data and map them to the correct nodes."""
        credentials = {}
        project_creds = project_data.get('credentials', [])
        print(project_creds)
        workloads = project_data.get('workloads', {})

        # Create a mapping from service name (workload name) to the full node name
        service_to_node_map = {}
        for workload_type, workload_items in workloads.items():
            for workload_name in workload_items.keys():
                node_name = f"{workload_type}_{workload_name}"
                service_to_node_map[workload_name] = node_name

        node_names = list(nodes.keys())

        if isinstance(project_creds, list):
            for i, cred in enumerate(project_creds):
                service_name = None
                node_name = None
                cred_data = {}

                if isinstance(cred, dict):
                    service_name = cred.get('service')
                    cred_data = cred
                elif isinstance(cred, str):
                    service_name = cred
                    cred_data = {'username': 'default_user', 'password': 'default_password', 'type': 'password'}

                if service_name:
                    # First, try for an exact match
                    node_name = service_to_node_map.get(service_name)

                    # If no exact match, try to find a node that contains the service name
                    if not node_name:
                        for n_name in node_names:
                            if service_name in n_name:
                                node_name = n_name
                                break
                    
                    # If still no match, assign to the first node as a fallback
                    if not node_name and node_names:
                        node_name = node_names[0]

                if node_name:
                    cred_name = f"{service_name}_cred_{i}"
                    credentials[cred_name] = {
                        "name": cred_name,
                        "node": node_name,
                        "username": cred_data.get('username', ''),
                        "password": cred_data.get('password', ''),
                        "credential_type": cred_data.get('type', 'password')
                    }

        return credentials

    def build_network(self, nodes: Dict[str, Any], project_name: str) -> Dict[str, Any]:
        """Build network topology"""
        network = {"internet": {"connects": []}}
        
        web_nodes = []
        database_nodes = []
        other_nodes = []
        
        for node_name, node_data in nodes.items():
            node_type = node_data.get("node_type", "")
            if "web" in node_type.lower() or "frontend" in node_type.lower():
                web_nodes.append(node_name)
            elif "database" in node_type.lower() or "db" in node_type.lower():
                database_nodes.append(node_name)
            else:
                other_nodes.append(node_name)
        
        for node_name in web_nodes:
            network["internet"]["connects"].append(node_name)
            network[node_name] = {"connects": database_nodes + other_nodes}
        
        for node_name in database_nodes + other_nodes:
            if node_name not in network:
                network[node_name] = {"connects": []}
            
            if not web_nodes:
                network["internet"]["connects"].append(node_name)
        
        if not network["internet"]["connects"] and nodes:
            first_node = list(nodes.keys())[0]
            network["internet"]["connects"].append(first_node)
            if first_node not in network:
                network[first_node] = {"connects": list(nodes.keys())[1:]}
        
        return network
    
    def enhance_with_credential_paths(self, environment: Dict[str, Any]) -> Dict[str, Any]:
        """Return environment without creating fake credentials"""
        return environment
    
    def predict_attack_impact(self, environment: Dict[str, Any]) -> Dict[str, Any]:
        """Predict attack impact"""
        network = environment.get("network", {})
        nodes = environment.get("nodes", {})
        
        entry_points = network.get("internet", {}).get("connects", [])
        if not entry_points:
            return {"discovered_nodes": 0, "owned_nodes": 0, "credentials_owned": 0, "maximum_score": 0.0}
        
        queue = deque(entry_points)
        discovered_nodes = set(entry_points)
        while queue:
            current_node_name = queue.popleft()
            if current_node_name in network:
                for neighbor in network[current_node_name].get("connects", []):
                    if neighbor not in discovered_nodes:
                        discovered_nodes.add(neighbor)
                        queue.append(neighbor)
        
        owned_nodes = set()
        credentials_owned = set()
        maximum_score = 0.0
        attack_paths = []
        
        for node_name in discovered_nodes:
            if node_name not in nodes:
                continue
            
            node = nodes[node_name]
            is_owned = False
            node_score = 0.0
            
            for vuln in node.get("vulnerabilities", []):
                vuln_score = vuln.get("cvss_score", 5.0)
                maximum_score += vuln_score
                node_score += vuln_score
                
                outcome_type = vuln.get("outcome", {}).get("type", "")
                if outcome_type in ["admin_escalation", "system_escalation", "privilege_escalation"]:
                    is_owned = True
                    attack_paths.append({
                        "node": node_name,
                        "vulnerability": vuln.get("description", "unknown"),
                        "reward": vuln_score,
                        "type": "remote" if vuln.get("type") == 3 else "local"
                    })
                
                if outcome_type == "leaked_credentials":
                    creds_list = vuln.get("outcome", {}).get("kwargs", {}).get("credentials", [])
                    for cred in creds_list:
                        credentials_owned.add(cred.get("kwargs", {}).get("credential", ""))
            
            if is_owned:
                owned_nodes.add(node_name)
        
        return {
            "discovered_nodes": len(discovered_nodes),
            "owned_nodes": len(owned_nodes),
            "credentials_owned": len(credentials_owned),
            "maximum_score": round(maximum_score, 2),
            "attack_paths": attack_paths,
            "avg_score_per_node": round(maximum_score / max(len(discovered_nodes), 1), 2)
        }
        
    def generate_environment(self, project_name: str) -> Dict[str, Any]:
        """Generate complete CyberBattleSim environment"""
        project_path = os.path.join(self.base_dir, project_name)
        
        if not os.path.exists(project_path):
            print(f"Project path does not exist: {project_path}")
            return {}
        
        print(f"Generating environment for project: {project_name}")
        
        project_data = self.load_project_data(project_path)
        nodes = self.build_nodes(project_data, project_name)
        # Pass the 'nodes' dictionary to build_credentials
        credentials = self.build_credentials(project_data, nodes)
        network = self.build_network(nodes, project_name)
        
        environment = {
            "nodes": nodes,
            "credentials": credentials,
            "network": network
        }
        
        environment = self.enhance_with_credential_paths(environment)
        impact = self.predict_attack_impact(environment)
        
        print(f"Environment generated with {len(nodes)} nodes, {len(credentials)} credentials")
        print(f"Predicted impact: {impact['discovered_nodes']} discoverable nodes, "
            f"{impact['owned_nodes']} ownable nodes, max score: {impact['maximum_score']}")
        
        return environment
        
    def generate_all_environments(self):
        """Generate environments for all projects"""
        if not os.path.exists(self.base_dir):
            print(f"Base directory does not exist: {self.base_dir}")
            return
        
        projects = [d for d in os.listdir(self.base_dir) 
                   if os.path.isdir(os.path.join(self.base_dir, d))]
        
        print(f"Found {len(projects)} projects to generate environments for")
        
        for project_name in projects:
            try:
                environment = self.generate_environment(project_name)
                
                if environment:
                    output_path = os.path.join(self.base_dir, project_name, "cyberbattlesim_environment.json")
                    with open(output_path, 'w') as f:
                        json.dump(environment, f, indent=4)
                    print(f"✅ Saved environment to: {output_path}\n")
                else:
                    print(f"⚠️ No environment generated for {project_name}\n")
                    
            except Exception as e:
                print(f"❌ Error generating environment for {project_name}: {e}\n")

def main():
    BASE_DIR = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic"
    
    if len(sys.argv) > 1:
        BASE_DIR = sys.argv[1]
    
    generator = CyberBattleSimEnvironmentGenerator(BASE_DIR)
    
    if len(sys.argv) > 2:
        project_name = sys.argv[2]
        environment = generator.generate_environment(project_name)
        if environment:
            output_path = os.path.join(BASE_DIR, project_name, "cyberbattlesim_environment.json")
            with open(output_path, 'w') as f:
                json.dump(environment, f, indent=4)
            print(f"✅ Generated environment for {project_name}")
    else:
        generator.generate_all_environments()

if __name__ == "__main__":
    main()