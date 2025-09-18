import json
import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any

# --- Data Structures for the Final CyberBattleSim Environment ---

@dataclass
class VulnerabilityInfo:
    """Holds the raw vulnerability data from your input file."""
    name: str
    type: str
    reward: float
    provides_privilege_escalation: bool
    leaked_credentials: List[str]

@dataclass
class NodeInfo:
    """Holds the raw node data, including its list of vulnerabilities."""
    name: str
    vulnerabilities: List[VulnerabilityInfo]

# --- Main Conversion Script ---

def build_cyberbattle_environment(project_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Converts the intermediate vulnerability data into a complete CyberBattleSim
    environment definition with nodes, vulnerabilities, and network topology.
    """
    
    # Use a dictionary to easily find nodes by name for building connections
    nodes_map = {node_data['name']: node_data for node_data in project_data.get("nodes", [])}
    
    final_nodes = {}
    all_credentials = {}

    print("Processing nodes and de-duplicating vulnerabilities...")
    for name, node_data in nodes_map.items():
        
        # Use a dictionary to ensure each vulnerability is unique per node
        unique_vulnerabilities = {}
        for vuln_data in node_data.get("vulnerabilities", []):
            vuln_name = vuln_data['name']
            
            # If we haven't seen this CVE on this node yet, add it
            if vuln_name not in unique_vulnerabilities:
                
                # Define the CyberBattleSim vulnerability structure
                cyber_vuln = {
                    "name": vuln_name,
                    "precondition": f"leaks({vuln_name})", # A simple precondition
                    "service": "wordpress-service", # Example service
                    "reward": vuln_data['reward'],
                    "type": "remote" if vuln_data['type'] == 'remote' else 'local',
                    "privilege_escalation": vuln_data['provides_privilege_escalation']
                }
                
                # If the vulnerability leaks credentials, add them to the node and the global list
                if vuln_data.get("leaked_credentials"):
                    credential_name = vuln_data["leaked_credentials"][0]
                    cyber_vuln["leaked_credentials"] = [credential_name]
                    all_credentials[credential_name] = {
                        "name": credential_name,
                        "node": name,
                        "username": f"user_{name}",
                        "password": "password123" # Dummy password
                    }
                
                unique_vulnerabilities[vuln_name] = cyber_vuln

        final_nodes[name] = {
            "name": name,
            "services": [{"name": "wordpress-service"}], # Add a default service
            "vulnerabilities": list(unique_vulnerabilities.values()),
            "credentials": [], # We will populate this later if needed
            "firewall": { "incoming": [], "outgoing": [] } # Default firewall rules
        }

    # In a real scenario, you would use the 'dependencies' from your earlier scan
    # to build these connections. For this example, we'll create a simple topology.
    print("Building network topology...")
    network_topology = {
        "internet": {"connects": ["wordpress"]},
        "wordpress": {"connects": []} # In a real case, this might connect to a 'mariadb' node
    }
    
    # The final, complete CyberBattleSim environment definition
    cyberbattle_environment = {
        "nodes": final_nodes,
        "credentials": all_credentials,
        "network": network_topology
    }
    
    return cyberbattle_environment


def main():
    """
    Main function to find and convert all analysis files in a base directory.
    """
    # --- Configuration ---
    BASE_DIR = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic"
    INPUT_FILENAME = "cyberbattle_environment_cvss.json"
    OUTPUT_FILENAME = "final_cyberbattle_environment.json"

    # --- Execution ---
    if not os.path.isdir(BASE_DIR):
        print(f"[ERROR] Base directory not found: {BASE_DIR}")
        return

    print(f"Starting final conversion process in base directory: {BASE_DIR}\n")
    
    for root, _, files in os.walk(BASE_DIR):
        if INPUT_FILENAME in files:
            input_path = os.path.join(root, INPUT_FILENAME)
            output_path = os.path.join(root, OUTPUT_FILENAME)
            
            project_name = os.path.basename(root)
            print(f"--- Processing project: {project_name} ---")
            
            try:
                print(f"  Reading intermediate data from: {input_path}")
                with open(input_path, 'r') as f:
                    intermediate_data = json.load(f)
                
                print("  Building final CyberBattleSim environment...")
                final_environment = build_cyberbattle_environment(intermediate_data)

                print(f"  Saving final environment to: {output_path}")
                with open(output_path, 'w') as f:
                    json.dump(final_environment, f, indent=4)
                    
                print(f"  ✅ Final environment for {project_name} created successfully.\n")

            except Exception as e:
                print(f"  ❌ Error processing {project_name}: {e}\n")

    print("🎉 All projects have been processed.")

if __name__ == "__main__":
    main()