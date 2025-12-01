import json
import os
import sys
import csv
from typing import Dict, Any, List

def generate_image_to_cve_csv(base_dir: str):
    """
    Scans project directories to create a CSV mapping Docker images to CVEs.

    For each project, this function reads the 'helm_analysis_with_cves_and_secrets.json'
    file and creates a new CSV file, 'image_to_cve_mapping.csv', in the
    'generated_output' directory.

    Args:
        base_dir: The path to the directory containing all the project folders.
    """
    print("Starting CVE mapping generation for all projects...")

    headers = ["docker_image_name", "cve_id"]

    try:
        projects = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
    except FileNotFoundError:
        print(f"Error: Base directory not found at '{base_dir}'")
        return

    print(f"Found {len(projects)} project(s). Processing now...")

    for project_name in projects:
        project_path = os.path.join(base_dir, project_name)
        analysis_path = os.path.join(project_path, "helm_analysis_with_cves_and_secrets.json")

        if not os.path.exists(analysis_path):
            print(f"  - Skipping '{project_name}': helm_analysis_with_cves_and_secrets.json not found.")
            continue

        print(f"  - Processing '{project_name}' for CVE mapping...")

        output_dir = os.path.join(project_path, "generated_output")
        os.makedirs(output_dir, exist_ok=True)
        output_csv_path = os.path.join(output_dir, "image_to_cve_mapping.csv")

        with open(output_csv_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)

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
                            # Corrected: Use 'image_name' instead of 'name'
                            image_name = image.get('image_name')
                            vulnerabilities = image.get('vulnerabilities', [])
                            
                            if image_name and isinstance(vulnerabilities, list):
                                for vuln in vulnerabilities:
                                    if isinstance(vuln, dict):
                                        cve_id = vuln.get('VulnerabilityID')
                                        if cve_id:
                                            writer.writerow([image_name, cve_id])
        
        print(f"    ✅ CVE mapping for '{project_name}' saved to: {output_csv_path}")

    print("\nCVE mapping generation complete for all projects.")

def main():
    """Main function to run the script."""
    base_dir = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic"
    
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    
    if not os.path.isdir(base_dir):
        print(f"Error: The specified directory does not exist: '{base_dir}'")
        print("Usage: python map_image_to_cve.py [path_to_your_projects_directory]")
        return
        
    generate_image_to_cve_csv(base_dir)

if __name__ == "__main__":
    main()

