import json
import os
from collections import deque

def enhance_environment_with_credential_paths(environment: dict) -> dict:
    """
    Enhances a CyberBattleSim environment by creating realistic attack paths
    that rely on leaking and then using a single, canonical credential per node.
    """

    nodes = environment.get("nodes", {})
    credentials = environment.get("credentials", {})
    network = environment.get("network", {})

    enhanced_nodes = {}
    new_credentials = {}

    print("Rebuilding environment with a more realistic credential model...")
    for node_name, node_data in nodes.items():
        # --- New Logic: Create ONE canonical credential for this node ---
        canonical_credential_name = f"creds_for_{node_name}"
        node_has_leaked_creds = False
        has_privilege_escalation = False

        new_vulnerabilities = []
        for vuln in node_data.get("vulnerabilities", []):
            # If the original vulnerability was marked as leaking credentials...
            if "leaked_credentials" in vuln and vuln["leaked_credentials"]:
                # ...replace its unique credential with the single, canonical one.
                vuln["leaked_credentials"] = [canonical_credential_name]
                node_has_leaked_creds = True

            new_vulnerabilities.append(vuln)

            if vuln.get("privilege_escalation"):
                has_privilege_escalation = True

        # If this node has any vulnerability that can leak credentials...
        if node_has_leaked_creds:
            # ...create the single credential object for it.
            new_credentials[canonical_credential_name] = {
                "name": canonical_credential_name,
                "node": node_name,
                "username": f"user_{node_name}",
                "password": "complex_password_123!" # Dummy password
            }

            # If the node doesn't already have a direct path to privilege escalation,
            # add a new vulnerability that requires the canonical credential.
            if not has_privilege_escalation:
                credential_exploit_vuln = {
                    "name": f"ExploitWith_{canonical_credential_name}",
                    "precondition": f"has_credential({canonical_credential_name})",
                    "service": node_data.get("services", [{}])[0].get("name", "default-service"),
                    "reward": 10.0,
                    "type": "local",
                    "privilege_escalation": True
                }
                new_vulnerabilities.append(credential_exploit_vuln)

        enhanced_nodes[node_name] = {
            **node_data,
            "vulnerabilities": new_vulnerabilities
        }

    final_environment = {
        "nodes": enhanced_nodes,
        "credentials": new_credentials, # Use the new, smaller set of credentials
        "network": network
    }

    return final_environment


def predict_attack_impact(environment: dict) -> dict:
    """
    Analyzes an environment to predict the total number of discovered nodes,
    owned nodes, credentials, and the maximum possible score.
    """
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

    for node_name in discovered_nodes:
        if node_name not in nodes:
            continue

        node = nodes[node_name]
        is_owned = False

        for vuln in node.get("vulnerabilities", []):
            maximum_score += vuln.get("reward", 0.0)
            if vuln.get("privilege_escalation"):
                is_owned = True

        if is_owned:
            owned_nodes.add(node_name)
            for vuln in node.get("vulnerabilities", []):
                if "leaked_credentials" in vuln:
                    for cred in vuln["leaked_credentials"]:
                        credentials_owned.add(cred)

    return {
        "discovered_nodes": len(discovered_nodes),
        "owned_nodes": len(owned_nodes),
        "credentials_owned": len(credentials_owned),
        "maximum_score": maximum_score
    }


def main():
    """
    Main function to find and enhance all generated environment files,
    then predict the maximum potential impact.
    """
    # --- Configuration ---
    BASE_DIR = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic"
    FILENAME = "final_cyberbattle_environment.json"

    # --- Execution ---
    if not os.path.isdir(BASE_DIR):
        print(f"[ERROR] Base directory not found: {BASE_DIR}")
        return

    print(f"Starting environment enhancement and analysis in base directory: {BASE_DIR}\n")

    for root, _, files in os.walk(BASE_DIR):
        if FILENAME in files:
            file_path = os.path.join(root, FILENAME)

            project_name = os.path.basename(root)
            print(f"--- Processing project: {project_name} ---")

            try:
                print(f"  Reading environment data from: {file_path}")
                with open(file_path, 'r') as f:
                    environment_data = json.load(f)

                print("  Applying realistic credential model...")
                enhanced_environment = enhance_environment_with_credential_paths(environment_data)

                print(f"  Saving enhanced environment back to: {file_path}")
                with open(file_path, 'w') as f:
                    json.dump(enhanced_environment, f, indent=4)

                print(f"  ✅ Environment for {project_name} was updated successfully.")

                print("  Analyzing attack impact...")
                impact_predictions = predict_attack_impact(enhanced_environment)

                print("  📊 Predicted Impact:")
                print(f"     - Total Discovered Nodes: {impact_predictions['discovered_nodes']}")
                print(f"     - Total Owned Nodes: {impact_predictions['owned_nodes']}")
                print(f"     - Total Credentials Owned: {impact_predictions['credentials_owned']}")
                print(f"     - Maximum Potential Score: {impact_predictions['maximum_score']:.2f}\n")

            except Exception as e:
                print(f"  ❌ Error processing {project_name}: {e}\n")

    print("🎉 All projects have been processed.")

if __name__ == "__main__":
    main()