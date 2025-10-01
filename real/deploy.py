#!/usr/bin/env python3

import subprocess
import sys
import shutil

# --- Configuration ---
# IMPORTANT: Change this to your Kubernetes API server address.
K8S_SERVER = "http://localhost:8080" 

# Helm chart details
RELEASE_NAME = "elasticsearch"
NAMESPACE = "elastic-system"
REPO_NAME = "elastic"
REPO_URL = "https://helm.elastic.co"
CHART_NAME = "elastic/elasticsearch"
CHART_VERSION = "8.5.1"  # Pinning a version is good practice

# --- ANSI Color Codes for pretty printing ---
class Colors:
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    RED = "\033[0;31m"
    NC = "\033[0m" # No Color

# --- Base commands ---
KUBECTL_BASE = ["kubectl", "-s", K8S_SERVER]
HELM_BASE = ["helm"]

def command_exists(command: str) -> bool:
    """Check if a command exists in the system's PATH."""
    return shutil.which(command) is not None

def run_command(command: list, capture_output: bool = False, check: bool = True):
    """A helper function to run a shell command and handle errors."""
    print(f"{Colors.YELLOW}--> Running: {' '.join(command)}{Colors.NC}")
    try:
        result = subprocess.run(
            command,
            capture_output=capture_output,
            text=True,
            check=check  # Raises CalledProcessError if command returns a non-zero exit code
        )
        return result
    except FileNotFoundError:
        print(f"{Colors.RED}Error: Command '{command[0]}' not found. Is it installed and in your PATH?{Colors.NC}")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}Error executing command: {' '.join(command)}{Colors.NC}")
        if e.stdout:
            print(f"STDOUT: {e.stdout}")
        if e.stderr:
            print(f"STDERR: {e.stderr}")
        sys.exit(1)

def main():
    """Main function to orchestrate the deployment."""
    print(f"{Colors.YELLOW}Starting Elasticsearch deployment...{Colors.NC}")

    # 1. Check for prerequisites
    print("--> Checking for kubectl and helm...")
    if not command_exists("kubectl") or not command_exists("helm"):
        print(f"{Colors.RED}Error: Please ensure both 'kubectl' and 'helm' are installed and in your PATH.{Colors.NC}")
        sys.exit(1)
    print(f"{Colors.GREEN}Prerequisites met.{Colors.NC}")

    # 2. Add and update the Elastic Helm repository
    repo_list_result = run_command(HELM_BASE + ["repo", "list"], capture_output=True)
    if REPO_NAME not in repo_list_result.stdout:
        run_command(HELM_BASE + ["repo", "add", REPO_NAME, REPO_URL])
        print(f"{Colors.GREEN}Helm repository '{REPO_NAME}' added.{Colors.NC}")
    else:
        print(f"{Colors.YELLOW}Helm repository '{REPO_NAME}' already exists.{Colors.NC}")
    
    run_command(HELM_BASE + ["repo", "update"])
    print(f"{Colors.GREEN}Helm repositories updated.{Colors.NC}")

    # 3. Create Kubernetes namespace if it doesn't exist
    print(f"--> Ensuring namespace '{NAMESPACE}' exists...")
    ns_check_result = run_command(
        KUBECTL_BASE + ["get", "namespace", NAMESPACE],
        check=False # We expect this to fail if the namespace doesn't exist
    )
    if ns_check_result.returncode != 0:
        run_command(KUBECTL_BASE + ["create", "namespace", NAMESPACE])
        print(f"{Colors.GREEN}Namespace '{NAMESPACE}' created.{Colors.NC}")
    else:
        print(f"{Colors.YELLOW}Namespace '{NAMESPACE}' already exists.{Colors.NC}")

    # 4. Install the Elasticsearch Helm chart
    print(f"--> Installing Elasticsearch chart '{CHART_NAME}'...")
    helm_install_cmd = HELM_BASE + [
        "install", RELEASE_NAME, CHART_NAME,
        "--namespace", NAMESPACE,
        "--version", CHART_VERSION,
        "--set", "replicas=1",
        "--set", "minimumMasterNodes=1",
        "--set", "service.type=NodePort",
    ]
    run_command(helm_install_cmd)
    
    print(f"\n{Colors.GREEN}✅ Elasticsearch deployment initiated successfully!{Colors.NC}")
    print(f"{Colors.YELLOW}It may take a few minutes for the pods to become ready.{Colors.NC}")

    # 5. Print post-installation instructions
    kubectl_get_pods_cmd = f"kubectl -s {K8S_SERVER} get pods -n {NAMESPACE} -w"
    kubectl_get_secret_cmd = f"kubectl -s {K8S_SERVER} get secret {RELEASE_NAME}-elasticsearch-credentials -n {NAMESPACE} -o go-template='{{.data.password | base64decode}}'"
    kubectl_port_forward_cmd = f"kubectl -s {K8S_SERVER} port-forward svc/{RELEASE_NAME}-elasticsearch 9200:9200 -n {NAMESPACE}"
    curl_cmd = 'curl -u "elastic:<YOUR_PASSWORD>" -k "https://localhost:9200"'

    print("\n--- Next Steps ---")
    print("1. Check the status of your deployment:")
    print(f"   {Colors.GREEN}{kubectl_get_pods_cmd}{Colors.NC}")
    print("\n2. Once the pod is running, retrieve the 'elastic' user password:")
    print(f"   {Colors.GREEN}{kubectl_get_secret_cmd}{Colors.NC}")
    print("\n3. To connect to the cluster from your local machine, forward a local port:")
    print(f"   {Colors.GREEN}{kubectl_port_forward_cmd}{Colors.NC}")
    print("\n4. In another terminal, test the connection:")
    print(f"   {Colors.GREEN}{curl_cmd}{Colors.NC}")


if __name__ == "__main__":
    main()