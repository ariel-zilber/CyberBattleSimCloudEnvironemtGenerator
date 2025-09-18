import json
import os
import sys
import csv
import re
from typing import Dict, List, Any, Tuple, Optional
import pandas as pd

class CVSSParser:
    """
    Parses and interprets CVSS vectors to generate realistic vulnerability
    parameters for the CyberBattleSim environment. This logic is adapted
    from the original 'generate.py' to fit our modular pipeline.
    """
    
    def parse_cvss_vector(self, vector: str) -> Dict[str, str]:
        if not vector or not isinstance(vector, str):
            return {}
        version = '2.0'
        if 'CVSS:3' in vector:
            version = '3.x'
        metrics = {match[0]: match[1] for match in re.findall(r'([A-Z]+):([A-Z])', vector)}
        metrics['version'] = version
        return metrics

    def get_vulnerability_type(self, metrics: Dict[str, str]) -> str:
        return 'remote' if metrics.get('AV') in ['N', 'A'] else 'local'

    def requires_privileges(self, metrics: Dict[str, str]) -> bool:
        if metrics.get('version', '').startswith('3'):
            return metrics.get('PR', 'N') in ['L', 'H']
        return metrics.get('Au', 'N') in ['S', 'M']

    def get_success_rate(self, metrics: Dict[str, str]) -> float:
        ac = metrics.get('AC', 'L')
        ui = metrics.get('UI', 'N')
        pr = metrics.get('PR', 'N')
        rate = 0.9 if ac == 'L' else (0.7 if ac == 'M' else 0.3)
        if ui == 'R': rate *= 0.6
        if pr in ['L', 'H']: rate *= 0.8
        return max(0.1, min(1.0, rate))

    def map_cvss_to_cyberbattle_outcome(self, metrics: Dict[str, str]) -> str:
        c_impact = metrics.get('C', 'N')
        i_impact = metrics.get('I', 'N')
        scope_change = metrics.get('S') == 'C'
        vuln_type = self.get_vulnerability_type(metrics)
        privs_required = self.requires_privileges(metrics)

        if scope_change or (not privs_required and (c_impact in ['H', 'C'] or i_impact in ['H', 'C'])):
            return "system_escalation"
        if c_impact in ['H', 'C']:
            return "leaked_credentials"
        if vuln_type == 'remote' and not privs_required:
            return "leaked_nodes_id"
        return "probe_succeeded"

    def create_exploit(self, cve_id: str, cve_details: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        nvd_data = cve_details.get("CVSS", {}).get("nvd", {})
        vector = nvd_data.get("V3Vector") or nvd_data.get("V2Vector")
        if not vector:
            return None
        
        metrics = self.parse_cvss_vector(vector)
        vuln_type = self.get_vulnerability_type(metrics)
        outcome_type = self.map_cvss_to_cyberbattle_outcome(metrics)

        preconditions = []
        if self.requires_privileges(metrics):
            preconditions.append("has_local_access" if vuln_type == 'local' else "has_credentials")
        
        return {
            "description": cve_details.get("Description", f"Exploit for {cve_id}"),
            "type": 3 if vuln_type == "remote" else 2, # Remote vs Local exploit
            "outcome": {"type": outcome_type, "kwargs": {}},
            "precondition": {"type": "true"} if not preconditions else {"type": "and", "conditions": [{"type": c} for c in preconditions]},
            "rates": {"successRate": self.get_success_rate(metrics)},
            "cost": 1.0,
            "reward_string": f"Successfully exploited {cve_id}"
        }

def generate_cyberbattle_environment(base_dir: str):
    """
    Main function to assemble all generated data into a final
    CyberBattleSim environment file for each project.
    """
    print("Starting final CyberBattleSim environment generation...")
    cvss_parser = CVSSParser()

    try:
        projects = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
    except FileNotFoundError:
        print(f"Error: Base directory not found at '{base_dir}'")
        return

    for project_name in projects:
        print(f"  - Assembling environment for '{project_name}'...")
        output_dir = os.path.join(base_dir, project_name, "generated_output")
        
        # Define paths to all our generated data files
        k8s_inventory_path = os.path.join(output_dir, "k8s_inventory.csv")
        network_map_path = os.path.join(output_dir, "network_map.csv")
        image_cve_map_path = os.path.join(output_dir, "image_to_cve_mapping.csv")
        cve_library_path = os.path.join(output_dir, "cve_details_library.json")
        creds_inventory_path = os.path.join(output_dir, "cyberbattle_credentials_inventory.csv")
        
        required_files = [k8s_inventory_path, network_map_path, image_cve_map_path, cve_library_path, creds_inventory_path]
        if not all(os.path.exists(p) for p in required_files):
            print(f"  - Skipping '{project_name}': one or more required generated files are missing.")
            continue

        # Load all data into pandas DataFrames for easy lookup
        k8s_df = pd.read_csv(k8s_inventory_path)
        network_df = pd.read_csv(network_map_path)
        image_cve_df = pd.read_csv(image_cve_map_path)
        creds_df = pd.read_csv(creds_inventory_path)
        with open(cve_library_path, 'r') as f:
            cve_library = json.load(f)

        # Initialize the main components of the environment file
        nodes: Dict[str, Any] = {}
        credentials: Dict[str, Any] = {}
        
        # 1. Populate the global credentials dictionary
        for _, row in creds_df.iterrows():
            cred_name = row["name"]
            credentials[cred_name] = {
                "name": cred_name,
                "username": row["username"],
                "password": row["password"]
            }

        # 2. Build each node from the Kubernetes inventory
        for pod_id in k8s_df["pod id"].unique():
            pod_info = k8s_df[k8s_df["pod id"] == pod_id].iloc[0]
            
            # Get services (ports) for this pod
            node_services = []
            pod_ports = network_df[network_df["pod_id"] == pod_id]
            for _, port_row in pod_ports.iterrows():
                service_name = port_row["port_name"] if pd.notna(port_row["port_name"]) else f'port-{port_row["port_number"]}'
                
                # Find credentials for this service
                allowed_credentials = creds_df[creds_df["service_name"] == pod_info["pod id"]]["name"].tolist()

                node_services.append({
                    "name": service_name,
                    "port": port_row["port_number"],
                    "allowedCredentials": allowed_credentials
                })
            
            # Get vulnerabilities for this pod's images
            node_vulnerabilities = {}
            pod_images = k8s_df[k8s_df["pod id"] == pod_id]["docker image name"].unique()
            for image in pod_images:
                cve_ids = image_cve_df[image_cve_df["docker_image_name"] == image]["cve_id"].tolist()
                for cve_id in cve_ids:
                    if cve_id in cve_library:
                        exploit = cvss_parser.create_exploit(cve_id, cve_library[cve_id])
                        if exploit:
                            node_vulnerabilities[cve_id] = exploit

            nodes[pod_id] = {
                "services": node_services,
                "vulnerabilities": node_vulnerabilities,
                "os_type": "linux", # Assuming Linux for now
                "node_type": pod_info["k8s resource type"]
            }

        # 3. Build a simple network topology
        network: Dict[str, Any] = {"internet": {"connects": []}}
        all_node_ids = list(nodes.keys())
        # Connect internet to the first node as a simple entry point
        if all_node_ids:
            entry_point = all_node_ids[0]
            network["internet"]["connects"].append(entry_point)
            network[entry_point] = {"connects": [nid for nid in all_node_ids if nid != entry_point]}

        # Assemble the final environment object
        final_environment = {
            "nodes": nodes,
            "credentials": credentials,
            "network": network
        }

        # Write the final JSON file
        output_path = os.path.join(output_dir, "cyberbattlesim_environment.json")
        with open(output_path, 'w') as f:
            json.dump(final_environment, f, indent=4)
        print(f"    ✅ CyberBattleSim environment for '{project_name}' saved to: {output_path}")

    print("\nAll environments generated successfully.")

def main():
    """Main function to run the script."""
    base_dir = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic"
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    
    if not os.path.isdir(base_dir):
        print(f"Error: The specified directory does not exist: '{base_dir}'")
        return
        
    generate_cyberbattle_environment(base_dir)

if __name__ == "__main__":
    main()
