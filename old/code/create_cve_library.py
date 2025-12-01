import json
import os
import sys
from typing import Dict, Any, List

def create_cve_library(base_dir: str):
    """
    Scans each project to create a project-specific CVE details library.

    This function iterates through all project directories, reads their
    'helm_analysis_with_cves_and_secrets.json' files, and creates a
    'cve_details_library.json' inside each project's 'generated_output' folder.

    Args:
        base_dir: The path to the directory containing all the project folders.
    """
    print("Starting creation of CVE Details Library for each project...")

    try:
        projects = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
    except FileNotFoundError:
        print(f"Error: Base directory not found at '{base_dir}'")
        return

    print(f"Found {len(projects)} project(s) to process...")

    for project_name in projects:
        project_path = os.path.join(base_dir, project_name)
        analysis_path = os.path.join(project_path, "helm_analysis_with_cves_and_secrets.json")

        if not os.path.exists(analysis_path):
            print(f"  - Skipping '{project_name}': analysis file not found.")
            continue

        print(f"  - Scanning '{project_name}'...")

        # Initialize a new, empty library for each project
        cve_library: Dict[str, Dict[str, Any]] = {}

        with open(analysis_path, 'r') as f:
            try:
                analysis_data: Dict[str, Any] = json.load(f)
            except json.JSONDecodeError:
                print(f"  - Warning: Could not parse JSON in '{analysis_path}'. Skipping.")
                continue
            
            services = analysis_data.get('services', [])
            if not isinstance(services, list):
                continue

            for service in services:
                docker_images = service.get('docker_images', [])
                if not isinstance(docker_images, list):
                    continue

                for image in docker_images:
                    if isinstance(image, dict):
                        vulnerabilities = image.get('vulnerabilities', [])
                        if isinstance(vulnerabilities, list):
                            for vuln_details in vulnerabilities:
                                if isinstance(vuln_details, dict):
                                    cve_id = vuln_details.get('VulnerabilityID')
                                    # Add the CVE to this project's library.
                                    if cve_id:
                                        cve_library[cve_id] = vuln_details

        # Define the output path inside the project's generated_output directory
        output_dir = os.path.join(project_path, "generated_output")
        os.makedirs(output_dir, exist_ok=True)
        output_json_path = os.path.join(output_dir, "cve_details_library.json")
    
        with open(output_json_path, 'w') as f:
            json.dump(cve_library, f, indent=4)
        
        print(f"    ✅ CVE Library for '{project_name}' created with {len(cve_library)} CVEs.")
        print(f"       Saved to: {output_json_path}")

    print("\nProcessing complete.")

def main():
    """Main function to run the script."""
    base_dir = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic"
    
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    
    if not os.path.isdir(base_dir):
        print(f"Error: The specified directory does not exist: '{base_dir}'")
        print("Usage: python create_cve_library.py [path_to_your_projects_directory]")
        return
        
    create_cve_library(base_dir)

if __name__ == "__main__":
    main()

