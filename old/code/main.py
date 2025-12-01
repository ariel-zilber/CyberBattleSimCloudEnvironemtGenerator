import os
import yaml
import json
import re
import subprocess
from typing import List, Dict, Any, Optional, Set
from tqdm import tqdm
from joblib import Parallel, delayed
import hashlib

# --- Configuration ---
CACHE_DIR = ".trivy_cache"

def get_cache_path(identifier: str) -> str:
    """Generates a safe filename for a given identifier (image or file path)."""
    hashed_identifier = hashlib.sha256(identifier.encode()).hexdigest()
    return os.path.join(CACHE_DIR, f"{hashed_identifier}.json")

def read_from_cache(identifier: str) -> Optional[Any]:
    """Reads a specific result from the cache."""
    cache_path = get_cache_path(identifier)
    if os.path.exists(cache_path):
        try:
            with open(cache_path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return None
    return None

def write_to_cache(identifier: str, data: Any):
    """Writes a result to the cache atomically."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_path = get_cache_path(identifier)
    temp_path = cache_path + ".tmp"
    with open(temp_path, 'w') as f:
        json.dump(data, f, indent=4)
    os.rename(temp_path, cache_path)

def find_charts(root_dir: str) -> List[str]:
    """Finds all Chart.yaml files in a directory."""
    chart_paths = []
    # We only look at the top-level for a Chart.yaml to define a project
    if 'Chart.yaml' in os.listdir(root_dir):
        chart_paths.append(root_dir)
    # If a chart contains subcharts, we'll handle them as part of the parent chart's dependencies
    return chart_paths

def parse_chart_yaml(chart_dir: str) -> Optional[Dict[str, Any]]:
    """Parses a Chart.yaml file."""
    chart_yaml_path = os.path.join(chart_dir, 'Chart.yaml')
    try:
        with open(chart_yaml_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        tqdm.write(f"Error parsing {chart_yaml_path}: {e}")
        return None

def find_images_in_values(chart_dir: str) -> Set[str]:
    """Finds Docker image references in the values.yaml file."""
    images = set()
    values_yaml_path = os.path.join(chart_dir, 'values.yaml')
    if os.path.exists(values_yaml_path):
        try:
            with open(values_yaml_path, 'r') as f:
                values = yaml.safe_load(f)
                if values:
                    find_images_recursive(values, images)
        except Exception as e:
            tqdm.write(f"Error parsing {values_yaml_path}: {e}")
    return images

def find_images_recursive(data: Any, images: Set[str]):
    """Recursively searches a dictionary for image references."""
    if isinstance(data, dict):
        if 'repository' in data and 'tag' in data:
            repo, tag = data.get('repository'), data.get('tag')
            if isinstance(repo, str) and tag is not None:
                images.add(f"{repo}:{tag}")
        for value in data.values():
            find_images_recursive(value, images)
    elif isinstance(data, list):
        for item in data:
            find_images_recursive(item, images)

def find_images_in_templates(chart_dir: str) -> Set[str]:
    """Finds Docker image references in template files."""
    images = set()
    templates_dir = os.path.join(chart_dir, 'templates')
    if os.path.isdir(templates_dir):
        image_pattern = re.compile(r'image:\s*["\']?([a-zA-Z0-9\./\-_]+/[a-zA-Z0-9\./\-_]+:[a-zA-Z0-9\.\-_]+)["\']?')
        for root, _, files in os.walk(templates_dir):
            for file in files:
                if file.endswith(('.yaml', '.tpl')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()
                            images.update(image_pattern.findall(content))
                    except Exception as e:
                        tqdm.write(f"Error reading {file_path}: {e}")
    return images
    
def scan_image_with_trivy(image_name: str) -> Dict:
    """Scans a single Docker image for vulnerabilities if not in cache."""
    cached_result = read_from_cache(image_name)
    if cached_result:
        return cached_result

    try:
        command = ["trivy", "image", "--format", "json", "--quiet", image_name]
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)

        if not result.stdout.strip():
            scan_data = {"image_name": image_name, "vulnerabilities": [], "status": "error_empty_output"}
        else:
            scan_results = json.loads(result.stdout)
            vulnerabilities = []
            if isinstance(scan_results, dict) and 'Results' in scan_results:
                for res in scan_results.get('Results', []):
                    vulnerabilities.extend(res.get('Vulnerabilities', []))
            scan_data = {"image_name": image_name, "vulnerabilities": vulnerabilities, "status": "success"}
    
    except Exception as e:
        scan_data = {"image_name": image_name, "vulnerabilities": [], "status": f"error_{type(e).__name__}"}

    write_to_cache(image_name, scan_data)
    return scan_data

def scan_file_for_secrets(file_path: str) -> Dict:
    """Scans a single file for secrets if not in cache."""
    cached_result = read_from_cache(file_path)
    if cached_result:
        return cached_result

    try:
        command = ["trivy", "config", "--format", "json", "--quiet", file_path]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        
        secrets = []
        if result.stdout:
            scan_results = json.loads(result.stdout)
            if isinstance(scan_results, dict) and 'Results' in scan_results:
                for res in scan_results.get('Results', []):
                    secrets.extend(res.get('Secrets', []))
        
        scan_data = {"file_path": file_path, "secrets": secrets}

    except Exception as e:
        scan_data = {"file_path": file_path, "secrets": []}

    write_to_cache(file_path, scan_data)
    return scan_data

def analyze_helm_project(root_dir: str) -> Dict[str, Any]:
    """Analyzes a Helm project for images, vulnerabilities, and secrets."""
    project_data = {"services": []}
    chart_dirs = find_charts(root_dir)

    if not chart_dirs:
        return project_data

    all_images = set()
    all_files = []
    for chart_dir in chart_dirs:
        all_images.update(find_images_in_values(chart_dir).union(find_images_in_templates(chart_dir)))
        for root, _, files in os.walk(chart_dir):
            for file in files:
                if file.endswith(('.yaml', '.tpl')):
                    all_files.append(os.path.join(root, file))

    Parallel(n_jobs=-1, prefer="threads")(delayed(scan_image_with_trivy)(img) for img in tqdm(list(all_images), desc="Scanning Images"))
    Parallel(n_jobs=-1, prefer="threads")(delayed(scan_file_for_secrets)(f) for f in tqdm(all_files, desc="Scanning for Secrets"))

    for chart_dir in tqdm(chart_dirs, desc=f"Building Report for {os.path.basename(root_dir)}"):
        chart_info = parse_chart_yaml(chart_dir)
        if not chart_info or not chart_info.get('name'):
            continue

        service_name = chart_info['name']
        images_in_chart = find_images_in_values(chart_dir).union(find_images_in_templates(chart_dir))
        
        secrets_in_chart = []
        for root, _, files in os.walk(chart_dir):
            for file in files:
                if file.endswith(('.yaml', '.tpl')):
                    file_path = os.path.join(root, file)
                    scan_result = read_from_cache(file_path)
                    if scan_result and scan_result.get("secrets"):
                        secrets_in_chart.append({
                            "file": os.path.relpath(file_path, chart_dir), 
                            "secrets": scan_result["secrets"]
                        })
        
        service_data = {
            "name": service_name,
            "version": chart_info.get('version', 'N/A'),
            "description": chart_info.get('description', ''),
            "path": os.path.relpath(chart_dir, root_dir),
            "docker_images": [read_from_cache(img) for img in images_in_chart],
            "secrets": secrets_in_chart,
            "dependencies": [dep['name'] for dep in chart_info.get('dependencies', []) if 'name' in dep]
        }
        project_data["services"].append(service_data)

    return project_data

if __name__ == '__main__':
    # --- Configuration ---
    #
    # Point this to the base directory containing all the Helm chart projects.
    # For example, "/content/charts/bitnami"
    #
    BITNAMI_CHARTS_DIR = "/content/charts/bitnami"
    
    BASE_OUTPUT_DIR = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic"

    # --- Automatic Project Discovery ---
    if not os.path.isdir(BITNAMI_CHARTS_DIR):
        print(f"[ERROR] The specified Bitnami charts directory does not exist: {BITNAMI_CHARTS_DIR}")
        print("[INFO] Please make sure you have cloned the charts repository.")
    else:
        # Find all the directories inside the base folder, each is a project
        project_paths = [os.path.join(BITNAMI_CHARTS_DIR, d) for d in os.listdir(BITNAMI_CHARTS_DIR) if os.path.isdir(os.path.join(BITNAMI_CHARTS_DIR, d))]

        print(f"Found {len(project_paths)} projects to analyze in {BITNAMI_CHARTS_DIR}")

        for project_path in project_paths:
            project_name = os.path.basename(project_path)
            
            print(f"\n{'='*60}")
            print(f"🚀 Starting analysis for project: {project_name}")
            print(f"{'='*60}\n")
            
            extracted_data = analyze_helm_project(project_path)
            
            # If the project has services, save the output
            if extracted_data and extracted_data["services"]:
                project_output_dir = os.path.join(BASE_OUTPUT_DIR, project_name)
                os.makedirs(project_output_dir, exist_ok=True)
                
                output_filename = "helm_analysis_with_cves_and_secrets.json"
                output_path = os.path.join(project_output_dir, output_filename)
                
                with open(output_path, 'w') as f:
                    json.dump(extracted_data, f, indent=4)
                
                print(f"\n✅ Analysis complete for project: {project_name}")
                print(f"   Found {len(extracted_data['services'])} services.")
                print(f"   Output saved to: {os.path.abspath(output_path)}")
            else:
                print(f"\n⚠️ No chart data found for project: {project_name}. Skipping.")


        print("\n\n🎉 All projects have been analyzed.")