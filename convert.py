import json
import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any

# --- Data Structures for the Final CyberBattleSim Environment ---

@dataclass
class CyberBattleVulnerability:
    """Represents a vulnerability with CyberBattleSim-specific properties."""
    name: str
    type: str  # 'local' or 'remote'
    reward: float
    provides_privilege_escalation: bool
    leaked_credentials: List[str]

@dataclass
class ServiceNode:
    """Represents a node in the final CyberBattleSim environment."""
    name: str
    vulnerabilities: List[CyberBattleVulnerability]
    # In a full implementation, you would also define services, firewall rules, etc.

# --- Heuristics for Converting CVEs based on CVSS Vector ---

def map_cvss_to_cyberbattle_vuln(vuln_data: Dict[str, Any]) -> CyberBattleVulnerability:
    """
    Applies a set of rules to convert a generic CVE into a CyberBattleSim vulnerability
    using its CVSS vector and score.
    """
    vuln_id = vuln_data.get("VulnerabilityID", "N/A")
    cvss_score = 0.0
    cvss_vector_str = ""
    
    # Safely extract the primary CVSS score and vector string
    if "CVSS" in vuln_data and isinstance(vuln_data["CVSS"], dict):
        # Prioritize CVSS v3.1, fall back to v3.0, then v2
        if "nvd" in vuln_data["CVSS"] and "V3Vector" in vuln_data["CVSS"]["nvd"]:
            cvss_score = vuln_data["CVSS"]["nvd"].get("V3Score", 0.0)
            cvss_vector_str = vuln_data["CVSS"]["nvd"]["V3Vector"]
        elif "nvd" in vuln_data["CVSS"] and "V2Vector" in vuln_data["CVSS"]["nvd"]:
            cvss_score = vuln_data["CVSS"]["nvd"].get("V2Score", 0.0)
            cvss_vector_str = vuln_data["CVSS"]["nvd"]["V2Vector"]

    # --- Apply Mappings based on the CVSS Vector ---
    
    # Default values
    vuln_type = "local"
    provides_privilege_escalation = False
    leaks_credentials = False

    # 1. Attack Vector (AV) -> local/remote
    if "AV:N" in cvss_vector_str or "AV:A" in cvss_vector_str:
        vuln_type = "remote"

    # 2. Privileges Required (PR) -> privilege escalation
    if "PR:N" in cvss_vector_str or "PR:L" in cvss_vector_str:
        provides_privilege_escalation = True
        
    # 3. Confidentiality Impact (C) -> leaked credentials
    if "C:H" in cvss_vector_str or "C:L" in cvss_vector_str:
        leaks_credentials = True
        
    leaked_credentials_list = [f"creds_from_{vuln_id}"] if leaks_credentials else []

    return CyberBattleVulnerability(
        name=vuln_id,
        type=vuln_type,
        reward=cvss_score, # Use the CVSS score as the reward
        provides_privilege_escalation=provides_privilege_escalation,
        leaked_credentials=leaked_credentials_list
    )

def create_cyberbattle_environment(structured_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Converts the structured data into the final CyberBattleSim environment format.
    """
    cyber_nodes = []
    
    for node_data in structured_data.get("services", []):
        all_vulnerabilities = []
        for image in node_data.get("docker_images", []):
            if image.get("status") == "success":
                for vuln in image.get("vulnerabilities", []):
                    all_vulnerabilities.append(map_cvss_to_cyberbattle_vuln(vuln))
                    
        cyber_nodes.append(ServiceNode(
            name=node_data.get("name", "N/A"),
            vulnerabilities=all_vulnerabilities
        ))
        
    final_environment = {
        "nodes": [asdict(node) for node in cyber_nodes]
    }
    
    return final_environment

def main():
    """
    Main function to find and convert all analysis files in a base directory.
    """
    # --- Configuration ---
    BASE_DIR = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic"
    INPUT_FILENAME = "helm_analysis_with_cves_and_secrets.json"
    OUTPUT_FILENAME = "cyberbattle_environment_cvss.json"

    # --- Execution ---
    if not os.path.isdir(BASE_DIR):
        print(f"[ERROR] Base directory not found: {BASE_DIR}")
        return

    print(f"Starting CVSS-based conversion in base directory: {BASE_DIR}\n")
    
    for root, _, files in os.walk(BASE_DIR):
        if INPUT_FILENAME in files:
            input_path = os.path.join(root, INPUT_FILENAME)
            output_path = os.path.join(root, OUTPUT_FILENAME)
            
            project_name = os.path.basename(root)
            print(f"--- Processing project: {project_name} ---")
            
            try:
                print(f"  Reading raw data from: {input_path}")
                with open(input_path, 'r') as f:
                    raw_scan_data = json.load(f)
                
                print("  Applying CVSS mappings to generate CyberBattleSim entities...")
                final_environment = create_cyberbattle_environment(raw_scan_data)

                print(f"  Saving final CyberBattleSim environment to: {output_path}")
                with open(output_path, 'w') as f:
                    json.dump(final_environment, f, indent=4)
                    
                print(f"  ✅ Final environment for {project_name} created successfully.\n")

            except Exception as e:
                print(f"  ❌ Error processing {project_name}: {e}\n")

    print("🎉 All projects have been processed.")

if __name__ == "__main__":
    main()