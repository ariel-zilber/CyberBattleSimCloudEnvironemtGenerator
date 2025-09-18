import json
import os
import sys
import csv
from typing import Dict, Any, List, Optional

def find_containers_in_details(details: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    Recursively searches for the 'containers' list within a workload's details.
    This robustly handles any nesting level or structure in the JSON data.
    """
    if not isinstance(details, dict):
        return None
    # Check if the 'containers' key exists at the current level and is a list.
    if 'containers' in details and isinstance(details.get('containers'), list):
        return details['containers']
    
    # If not found, iterate through the values of the dictionary.
    for key, value in details.items():
        # If a value is another dictionary, perform a recursive search.
        if isinstance(value, dict):
            found_containers = find_containers_in_details(value)
            # If the containers are found in the nested dictionary, return them.
            if found_containers is not None:
                return found_containers
    
    # Return None if the 'containers' list is not found after a full search.
    return None

def generate_network_map_csv(base_dir: str):
    """
    Scans project directories for 'workload_details.json' and creates a CSV
    that maps out network ports defined in containers.

    Args:
        base_dir: The path to the directory containing all project folders.
    """
    print("Starting network map generation from 'workload_details.json' files...")

    # Define the headers for the new network map CSV
    headers = [
        "k8s_resource_type", "pod_id", "container_name",
        "port_name", "port_number", "protocol"
    ]

    try:
        projects = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
    except FileNotFoundError:
        print(f"Error: Base directory not found at '{base_dir}'")
        return

    print(f"Found {len(projects)} project(s). Processing now...")

    for project_name in projects:
        project_path = os.path.join(base_dir, project_name)
        workload_path = os.path.join(project_path, "workload_details.json")

        if not os.path.exists(workload_path):
            print(f"  - Skipping '{project_name}': workload_details.json not found.")
            continue

        print(f"  - Processing '{project_name}'...")

        output_dir = os.path.join(project_path, "generated_output")
        os.makedirs(output_dir, exist_ok=True)
        output_csv_path = os.path.join(output_dir, "network_map.csv")

        with open(output_csv_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)

            with open(workload_path, 'r') as f:
                try:
                    workloads_data: Dict[str, Any] = json.load(f)
                except json.JSONDecodeError:
                    print(f"  - Warning: Could not parse JSON in '{workload_path}'. Skipping.")
                    continue

                for resource_type, resources in workloads_data.items():
                    for pod_id, details in resources.items():
                        containers = find_containers_in_details(details)
                        if containers is None:
                            containers=details
                        # New robust fallback logic
                        if containers is None:
                            # Check if the details object itself is a container
                            if isinstance(details, dict) and 'image' in details:
                                containers = [details]
                        
                        if containers:
                            for container in containers:
                                if not isinstance(container, dict):
                                    continue

                                container_name = container.get("name", "N/A")
                                ports = container.get("ports", [])
                                
                                if ports and isinstance(ports, list):
                                    for port_details in ports:
                                        if isinstance(port_details, dict):
                                            port_name = port_details.get("name", "N/A")
                                            port_number = port_details.get("containerPort", "N/A")
                                            protocol = port_details.get("protocol", "TCP")
                                            
                                            writer.writerow([
                                                resource_type, pod_id, container_name,
                                                port_name, port_number, protocol
                                            ])
                                else:
                                    # Write a row for the container even if it has no ports
                                    writer.writerow([
                                        resource_type, pod_id, container_name,
                                        "N/A", "N/A", "N/A"
                                    ])
                        else:
                             # This row is written if no containers are found at all for the pod
                             writer.writerow([resource_type, pod_id, "N/A", "N/A", "N/A", "N/A"])

        print(f"    ✅ Network map for '{project_name}' saved to: {output_csv_path}")

    print("\nNetwork map generation complete.")

def main():
    """Main function to run the script."""
    base_dir = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic"
    
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    
    if not os.path.isdir(base_dir):
        print(f"Error: The specified directory does not exist: '{base_dir}'")
        print("Usage: python create_network_map.py [path_to_your_projects_directory]")
        return
        
    generate_network_map_csv(base_dir)

if __name__ == "__main__":
    main()

