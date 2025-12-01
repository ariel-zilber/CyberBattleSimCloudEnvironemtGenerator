import json
import os
import sys
import csv
from typing import Dict, Any, List

def generate_credentials_inventory_from_json(base_dir: str):
    """
    Scans project directories for 'cyberbattle_credentials.json' and creates
    a detailed CSV inventory from its contents, including a permission level.

    Args:
        base_dir: The path to the directory containing all project folders.
    """
    print("Starting inventory generation from 'cyberbattle_credentials.json' files...")

    # Add the new "permission_level" column to the headers
    headers = ["service_name", "name", "username", "password", "docker_image", "permission_level"]

    try:
        projects = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
    except FileNotFoundError:
        print(f"Error: Base directory not found at '{base_dir}'")
        return

    print(f"Found {len(projects)} project(s). Processing now...")

    for project_name in projects:
        project_path = os.path.join(base_dir, project_name)
        creds_path = os.path.join(project_path, "credentials", "cyberbattle_credentials.json")

        if not os.path.exists(creds_path):
            print(f"  - Skipping '{project_name}': cyberbattle_credentials.json not found.")
            continue

        print(f"  - Processing '{project_name}'...")

        output_dir = os.path.join(project_path, "generated_output")
        os.makedirs(output_dir, exist_ok=True)
        output_csv_path = os.path.join(output_dir, "cyberbattle_credentials_inventory.csv")

        with open(output_csv_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)

            with open(creds_path, 'r') as f:
                try:
                    data: Dict[str, Any] = json.load(f)
                except json.JSONDecodeError:
                    print(f"  - Warning: Could not parse JSON in '{creds_path}'. Skipping.")
                    continue

                service_name = data.get("service_name", "N/A")
                credentials_list = data.get("cyberbattle_credentials", [])
                docker_images = data.get("docker_images", [])

                if not credentials_list:
                    print(f"  - Warning: No credentials found in '{creds_path}'.")
                    continue
                
                for cred in credentials_list:
                    cred_name = cred.get("name", "N/A")
                    username = cred.get("username", "N/A")
                    password = cred.get("password", "N/A")
                    
                    # Determine the permission level based on the username
                    permission_level = "user"  # Default to 'user'
                    if isinstance(username, str):
                        if "admin" in username.lower():
                            permission_level = "admin"
                        elif "root" in username.lower():
                            permission_level = "root"
                    
                    if not docker_images:
                        writer.writerow([service_name, cred_name, username, password, "N/A", permission_level])
                    else:
                        for image in docker_images:
                            writer.writerow([service_name, cred_name, username, password, image, permission_level])

        print(f"    ✅ Credential inventory for '{project_name}' saved to: {output_csv_path}")

    print("\nCredential inventory generation complete.")

def main():
    """Main function to run the script."""
    base_dir = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic"
    
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    
    if not os.path.isdir(base_dir):
        print(f"Error: The specified directory does not exist: '{base_dir}'")
        print("Usage: python your_script_name.py [path_to_your_projects_directory]")
        return
        
    generate_credentials_inventory_from_json(base_dir)

if __name__ == "__main__":
    main()

