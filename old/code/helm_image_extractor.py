import os
import yaml
import subprocess
from collections import defaultdict
import json
import sys

def extract_full_details(chart_path: str, output_dir: str):
    """
    Renders a Helm chart and extracts full details from its workloads (including
    pod labels) and service resources, saving them to separate JSON files.
    """
    chart_name = os.path.basename(chart_path)
    print(f"--- Analyzing Full Details for Chart: {chart_name} ---")

    # --- Step 1: Build Helm dependencies ---
    try:
        dep_build_command = ['helm', 'dependency', 'build', chart_path]
        print(f"  Running command: `{' '.join(dep_build_command)}`")
        subprocess.run(dep_build_command, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print("  ❌ ERROR: 'helm' command not found. Please ensure it's in your PATH.")
        print("-" * (len(chart_name) + 32) + "\n")
        return
    except subprocess.CalledProcessError as e:
        if "no dependencies found" not in e.stderr.lower():
            print(f"  [WARNING] 'helm dependency build' had an issue: {e.stderr.strip()}")

    # --- Step 2: Render the chart using 'helm template' ---
    release_name = f"{chart_name}-release"
    yaml_stream = ""
    try:
        template_command = ['helm', 'template', release_name, chart_path]
        print(f"  Running command: `{' '.join(template_command)}`")
        result = subprocess.run(template_command, capture_output=True, text=True, check=True)
        yaml_stream = result.stdout
    except subprocess.CalledProcessError as e:
        print(f"  ❌ ERROR: 'helm template' failed: {e.stderr.strip()}")
        print("-" * (len(chart_name) + 32) + "\n")
        return

    # --- Step 3: Parse YAML and extract workload and service details ---
    workload_kinds = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}
    workload_details = defaultdict(dict)
    service_details = []

    try:
        documents = [doc for doc in yaml.safe_load_all(yaml_stream) if doc and isinstance(doc, dict)]
        for doc in documents:
            kind = doc.get("kind")
            resource_name = doc.get("metadata", {}).get("name")

            if kind in workload_kinds:
                labels = {}
                containers_spec = []
                
                try:
                    if kind == "CronJob":
                        pod_template_spec = doc["spec"]["jobTemplate"]["spec"]["template"]
                    elif kind == "Pod":
                        pod_template_spec = doc
                    else: # Deployment, StatefulSet, DaemonSet, Job
                        pod_template_spec = doc["spec"]["template"]
                    
                    labels = pod_template_spec.get("metadata", {}).get("labels", {})
                    containers_spec = pod_template_spec.get("spec", {}).get("containers", [])
                except (KeyError, TypeError):
                    continue

                container_details_list = []
                for container in containers_spec:
                    ports = []
                    for port_info in container.get("ports", []):
                        ports.append({
                            "containerPort": port_info.get("containerPort"),
                            "protocol": port_info.get("protocol", "TCP"),
                            "name": port_info.get("name")
                        })
                    
                    container_details_list.append({
                        "image": container.get("image"),
                        "name": container.get("name"),
                        "ports": ports
                    })

                if container_details_list:
                    print(f"    Found {kind} '{resource_name}'")
                    workload_details[kind][resource_name] = {
                        "labels": labels,
                        "containers": container_details_list
                    }

            elif kind == "Service":
                print(f"    Found Service '{resource_name}'")
                service_details.append({
                    "name": resource_name,
                    "type": doc.get("spec", {}).get("type", "ClusterIP"),
                    "selector": doc.get("spec", {}).get("selector"),
                    "ports": doc.get("spec", {}).get("ports", [])
                })

    except yaml.YAMLError as e:
        print(f"  ❌ ERROR: Could not parse the YAML output from Helm: {e}")
        print("-" * (len(chart_name) + 32) + "\n")
        return

    # --- Step 4: Save the results to separate JSON files ---
    project_output_dir = os.path.join(output_dir, chart_name)
    os.makedirs(project_output_dir, exist_ok=True)
    
    if workload_details:
        with open(os.path.join(project_output_dir, "workload_details.json"), 'w') as f:
            json.dump(workload_details, f, indent=4)
        print(f"  ✅ Saved workload details.")
    
    if service_details:
        with open(os.path.join(project_output_dir, "service_details.json"), 'w') as f:
            json.dump(service_details, f, indent=4)
        print(f"  ✅ Saved service details.")
            
    print("-" * (len(chart_name) + 32) + "\n")


def main():
    """
    Main function to discover Helm charts and extract their full details.
    """
    CHARTS_BASE_DIR = "/content/charts/bitnami"
    OUTPUT_DIR = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic"

    if not os.path.isdir(CHARTS_BASE_DIR):
        print(f"[ERROR] Charts directory not found: {CHARTS_BASE_DIR}")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"🚀 Starting full detail extraction for all charts in: {CHARTS_BASE_DIR}\n")

    chart_paths = [
        os.path.join(CHARTS_BASE_DIR, d) for d in os.listdir(CHARTS_BASE_DIR)
        if os.path.isdir(os.path.join(CHARTS_BASE_DIR, d))
    ]

    for chart_path in chart_paths:
        extract_full_details(chart_path, OUTPUT_DIR)

    print("✅ Analysis Complete.")


if __name__ == "__main__":
    main()