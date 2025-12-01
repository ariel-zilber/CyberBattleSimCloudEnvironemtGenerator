import os
import yaml
import subprocess
from collections import Counter
import sys

def get_chart_statistics_via_render(chart_path: str):
    """
    Renders a Helm chart using the 'helm template' command after building
    its dependencies, then counts the Kubernetes resources from the output.
    """
    chart_name = os.path.basename(chart_path)
    print(f"--- Statistics for Chart: {chart_name} ---")

    # --- Step 1: Build Helm dependencies ---
    # This is the new, critical step to fix the error.
    try:
        dep_build_command = ['helm', 'dependency', 'build', chart_path]
        print(f"  Running command: `{' '.join(dep_build_command)}`")
        
        # We run this command first to download any missing charts (like 'common').
        subprocess.run(
            dep_build_command,
            capture_output=True,
            text=True,
            check=True
        )
    except FileNotFoundError:
        print("  ❌ ERROR: 'helm' command not found.")
        print("  Please ensure the Helm CLI is installed and in your system's PATH.")
        print("-" * (len(chart_name) + 26) + "\n")
        return
    except subprocess.CalledProcessError as e:
        # A non-zero exit code might just mean no dependencies to build, which is okay.
        # We only print a warning and continue.
        if "no dependencies found" not in e.stderr.lower():
             print(f"  [WARNING] 'helm dependency build' had an issue for chart '{chart_name}'.")
             print(f"  Stderr: {e.stderr.strip()}")


    # --- Step 2: Execute 'helm template' to render the chart ---
    release_name = f"{chart_name}-release"
    try:
        template_command = ['helm', 'template', release_name, chart_path]
        print(f"  Running command: `{' '.join(template_command)}`")
        
        result = subprocess.run(
            template_command,
            capture_output=True,
            text=True,
            check=True
        )
        yaml_stream = result.stdout

    except subprocess.CalledProcessError as e:
        print(f"  ❌ ERROR: 'helm template' failed for chart '{chart_name}'.")
        print(f"  Stderr: {e.stderr.strip()}")
        print("-" * (len(chart_name) + 26) + "\n")
        return

    # --- Step 3: Parse the rendered YAML and count the resources ---
    kind_counter = Counter()
    try:
        documents = [doc for doc in yaml.safe_load_all(yaml_stream) if doc]
        
        for doc in documents:
            if isinstance(doc, dict) and "kind" in doc:
                kind = doc.get("kind")
                if kind:
                    kind_counter[kind] += 1
                    
    except yaml.YAMLError as e:
        print(f"  ❌ ERROR: Could not parse the YAML output from Helm: {e}")
        print("-" * (len(chart_name) + 26) + "\n")
        return

    # --- Step 4: Print the results ---
    if not kind_counter:
        print("  No Kubernetes resources found in the rendered templates.")
    else:
        print("  Resource Counts:")
        for kind, count in sorted(kind_counter.items()):
            print(f"    - {kind}: {count}")
    
    print("-" * (len(chart_name) + 26) + "\n")


def main():
    """
    Main function to discover Helm charts and print their resource statistics.
    """
    CHARTS_BASE_DIR = "/content/charts/bitnami" 

    if not os.path.isdir(CHARTS_BASE_DIR):
        print(f"[ERROR] Charts directory not found: {CHARTS_BASE_DIR}")
        return

    print(f"🚀 Starting Kubernetes resource count for all charts in: {CHARTS_BASE_DIR}\n")

    chart_paths = [
        os.path.join(CHARTS_BASE_DIR, d) for d in os.listdir(CHARTS_BASE_DIR)
        if os.path.isdir(os.path.join(CHARTS_BASE_DIR, d))
    ]

    for chart_path in chart_paths:
        get_chart_statistics_via_render(chart_path)

    print("✅ Analysis Complete.")


if __name__ == "__main__":
    main()