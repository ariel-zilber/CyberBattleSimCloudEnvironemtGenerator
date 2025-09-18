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
    # Check if the 'containers' key exists at the current level and is a list.
    if 'containers' in details and isinstance(details['containers'], list):
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

def generate_k8s_inventory_csv(base_dir: str):
    """
    Scans project directories to create a CSV inventory of Kubernetes resources.

    For each project, this function creates a 'generated_output' directory
    and saves a 'k8s_inventory.csv' file inside it with details from the
    project's 'workload_details.json' file.

    Args:
        base_dir: The path to the directory containing all the project folders.
    """
    print("Starting inventory generation for all projects...")

    headers = ["k8s resource type", "pod id", "container id in pod", "docker image name", "instance"]

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
        output_csv_path = os.path.join(output_dir, "k8s_inventory.csv")

        # Initialize instance counter for each project
        instance_counter = 1

        with open(output_csv_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)

            with open(workload_path, 'r') as f:
                try:
                    workloads: Dict[str, Any] = json.load(f)
                except json.JSONDecodeError:
                    print(f"  - Warning: Could not parse JSON in '{workload_path}'. Skipping.")
                    continue

                for resource_type, resources in workloads.items():
                    for pod_id, details in resources.items():
                        if isinstance(details, list):
                            details = details[0] if details else {}
                        
                        containers = find_containers_in_details(details)
                        if containers is None:
                            containers = [details]
                        
                        if containers:
                            for container in containers:
                                if isinstance(container, dict):
                                    image_name = container.get('image', 'Not specified')
                                    container_name = container.get('name', 'Not specified')
                                    writer.writerow([resource_type, pod_id, container_name, image_name, instance_counter])
                                    instance_counter += 1
                        else:
                            writer.writerow([resource_type, pod_id, "N/A", "N/A", instance_counter])
                            instance_counter += 1
        
        print(f"    ✅ Inventory for '{project_name}' saved to: {output_csv_path}")

    print("\nInventory generation complete for all projects.")

def main():
    """Main function to run the script."""
    base_dir = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic"
    
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    
    if not os.path.isdir(base_dir):
        print(f"Error: The specified directory does not exist: '{base_dir}'")
        print("Usage: python create_inventory.py [path_to_your_projects_directory]")
        return
        
    generate_k8s_inventory_csv(base_dir)

if __name__ == "__main__":
    main()

