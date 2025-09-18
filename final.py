import json
import os
from typing import Dict, Any, List
import random

def build_single_project_environment(project_name: str, all_projects_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Builds a self-contained CyberBattleSim environment for a single project.
    This version creates TWO types of credential paths for realism:
    1. Leaks the service's OWN credentials from itself (intra-service).
    2. Leaks a DEPENDENCY's credentials from the service (inter-service).
    """
    nodes: Dict[str, Any] = {}
    credentials: Dict[str, Any] = {}
    network: Dict[str, Dict[str, List[str]]] = {"internet": {"connects": [project_name]}}

    # 1. Add the main project node
    if project_name not in all_projects_data:
        return {}
    
    main_node_data = json.loads(json.dumps(all_projects_data[project_name]['cvss']))
    nodes[project_name] = main_node_data
    network[project_name] = {"connects": []}

    # --- NEW: Create Intra-Service Credential Leak ---
    # This block handles leaking a service's OWN credentials from itself.
    # This is crucial for standalone services like WordPress.
    own_credentials = all_projects_data[project_name].get('credentials', [])
    if own_credentials:
        # Pick one of its own credentials to be discoverable on the node
        own_credential_to_leak = random.choice(own_credentials)
        own_cred_name = own_credential_to_leak['name']

        # Add the credential to the environment's credential store
        credentials[own_cred_name] = own_credential_to_leak
        
        # Create a local vulnerability that leaks this credential
        # (simulates finding it in a config file, etc.)
        local_leak_vuln = {
            "name": f"LeakedLocal_{own_cred_name}",
            "service": nodes[project_name]["services"][0]["name"],
            "reward": 8.0, # High value for finding admin creds
            "type": "local",
            "privilege_escalation": False, # Finding the cred isn't escalation, using it might be
            "leaked_credentials": [own_cred_name]
        }
        if "vulnerabilities" not in nodes[project_name]:
            nodes[project_name]["vulnerabilities"] = []
        nodes[project_name]["vulnerabilities"].append(local_leak_vuln)
        print(f"  ✅ Created INTRA-SERVICE credential path: {project_name} --leaks--> its own '{own_cred_name}'")


    # --- EXISTING LOGIC: Create Inter-Service Credential Leaks (for dependencies) ---
    dependencies = all_projects_data[project_name].get('dependencies', [])
    print(f"  Dependencies for {project_name}: {dependencies or 'None'}")

    for server_name in dependencies:
        if server_name in all_projects_data:
            server_node_data = json.loads(json.dumps(all_projects_data[server_name]['cvss']))
            nodes[server_name] = server_node_data
            
            network[project_name]["connects"].append(server_name)
            network[server_name] = {"connects": []}
            print(f"    - Added dependency node '{server_name}' and network link.")

            server_credentials = all_projects_data[server_name].get('credentials', [])
            if not server_credentials:
                print(f"    - ⚠️ No pre-generated credentials found for dependency '{server_name}'. Skipping credential path.")
                continue

            target_credential = random.choice(server_credentials)
            server_cred_name = target_credential['name']
            
            # a. Vulnerability on CLIENT that leaks SERVER's credential
            leak_vuln = {
                "name": f"Leak{server_name.capitalize()}Credentials",
                "service": nodes[project_name]["services"][0]["name"],
                "reward": 7.5,
                "type": "local",
                "privilege_escalation": False,
                "leaked_credentials": [server_cred_name]
            }
            nodes[project_name]["vulnerabilities"].append(leak_vuln)
            
            # b. Add the actual credential object
            credentials[server_cred_name] = target_credential

            # c. Vulnerability on SERVER that REQUIRES the credential
            exploit_vuln = {
                "name": f"ExploitWith_{server_cred_name}",
                "precondition": f"has_credential('{server_cred_name}')",
                "service": nodes[server_name]["services"][0]["name"],
                "reward": 15.0,
                "type": "remote",
                "privilege_escalation": True
            }
            if "vulnerabilities" not in nodes[server_name]:
                nodes[server_name]["vulnerabilities"] = []
            nodes[server_name]["vulnerabilities"].append(exploit_vuln)
            
            print(f"    - Created INTER-SERVICE credential path: {project_name} --leaks--> {server_cred_name} --unlocks--> {server_name}")

    return {
        "nodes": nodes,
        "credentials": credentials,
        "network": network
    }

def main():
    """
    Main function to build the final, unified CyberBattleSim environment.
    """
    BASE_DIR = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic"
    
    if not os.path.isdir(BASE_DIR):
        print(f"[ERROR] Base directory not found: {BASE_DIR}")
        return

    print(f"Starting final environment build process for directory: {BASE_DIR}\n")
    
    all_projects_data = {}
    project_dirs = [d for d in os.listdir(BASE_DIR) if os.path.isdir(os.path.join(BASE_DIR, d))]

    print("--- Pre-loading all project data (including credentials) ---")
    for project_name in project_dirs:
        project_path = os.path.join(BASE_DIR, project_name)
        raw_analysis_path = os.path.join(project_path, "helm_analysis_with_cves_and_secrets.json")
        cvss_env_path = os.path.join(project_path, "cyberbattle_environment_cvss.json")
        creds_path = os.path.join(project_path, "credentials", "cyberbattle_credentials.json")
        
        if os.path.exists(raw_analysis_path) and os.path.exists(cvss_env_path):
            with open(raw_analysis_path, 'r') as f:
                raw_data = json.load(f)
            with open(cvss_env_path, 'r') as f:
                cvss_data = json.load(f)

            project_credentials = []
            if os.path.exists(creds_path):
                with open(creds_path, 'r') as f:
                    cred_file_content = json.load(f)
                    project_credentials = cred_file_content.get('cyberbattle_credentials', [])

            main_service = next((s for s in raw_data.get("services", []) if s.get("path") == "."), None)
            
            all_projects_data[project_name] = {
                'dependencies': main_service.get("dependencies", []) if main_service else [],
                'cvss': cvss_data["nodes"][0],
                'credentials': project_credentials
            }
    print(f"Loaded data for {len(all_projects_data)} projects.\n")

    for project_name in all_projects_data.keys():
        print(f"--- Building environment set for project: {project_name} ---")
        try:
            final_environment = build_single_project_environment(project_name, all_projects_data)

            if final_environment and final_environment["nodes"]:
                output_path = os.path.join(BASE_DIR, project_name, "final_simulation_environment.json")
                print(f"  Saving final environment to: {output_path}")
                with open(output_path, 'w') as f:
                    json.dump(final_environment, f, indent=4)
                print(f"  ✅ Environment for {project_name} created successfully.\n")
            else:
                 print(f"  ⚠️  Skipping {project_name} as no data was generated.\n")

        except Exception as e:
            print(f"  ❌ An error occurred while building environment for {project_name}: {e}\n")

if __name__ == "__main__":
    main()