#!/usr/bin/env python3

import os
from kubernetes import client, config
from kubernetes.client.rest import ApiException

# --- Configuration ---
# The base directory on your Kubernetes nodes where storage will be created.
HOST_PATH_BASE_DIR = "/mnt/kube-storage"

def create_pv_for_pvc(api: client.CoreV1Api, pvc: client.V1PersistentVolumeClaim):
    """
    Creates a hostPath PersistentVolume to satisfy a given PersistentVolumeClaim.
    """
    pvc_name = pvc.metadata.name
    pvc_namespace = pvc.metadata.namespace
    pv_name = f"pv-{pvc_namespace}-{pvc_name}"

    print(f"-> Found pending PVC: '{pvc_name}' in namespace '{pvc_namespace}'.")

    # 1. Check if a matching PV already exists to avoid errors on re-runs
    try:
        api.read_persistent_volume(name=pv_name)
        print(f"   - INFO: A PersistentVolume named '{pv_name}' already exists. Skipping.")
        return
    except ApiException as e:
        if e.status != 404:
            print(f"   - ERROR: Could not check for PV '{pv_name}': {e}")
            return

    # 2. Gather required specs from the PVC
    try:
        storage_size = pvc.spec.resources.requests["storage"]
        access_modes = pvc.spec.access_modes
        storage_class_name = pvc.spec.storage_class_name or ""
    except (AttributeError, TypeError, KeyError) as e:
        print(f"   - ERROR: PVC '{pvc_name}' is missing required spec fields: {e}")
        return
        
    # 3. Define the PersistentVolume body
    host_path = os.path.join(HOST_PATH_BASE_DIR, pv_name)
    
    pv_body = client.V1PersistentVolume(
        api_version="v1",
        kind="PersistentVolume",
        metadata=client.V1ObjectMeta(name=pv_name),
        spec=client.V1PersistentVolumeSpec(
            storage_class_name=storage_class_name,
            capacity={"storage": storage_size},
            access_modes=access_modes,
            persistent_volume_reclaim_policy="Retain",
            host_path=client.V1HostPathVolumeSource(
                path=host_path,
                type="DirectoryOrCreate"
            ),
        ),
    )

    # 4. Create the PersistentVolume
    try:
        api.create_persistent_volume(body=pv_body)
        print(f"   - SUCCESS: Created PersistentVolume '{pv_name}' using hostPath '{host_path}'.")
    except ApiException as e:
        print(f"   - FAILED: Could not create PV '{pv_name}': {e}")


def main():
    """
    Main function to find and fix pending PVCs.
    """
    print("Starting script to fix unbound PersistentVolumeClaims...")

    try:
        config.load_kube_config()
        api = client.CoreV1Api()
        print("Successfully connected to the Kubernetes cluster.")
    except Exception as e:
        print(f"Error: Could not connect to Kubernetes. Is your kubeconfig set up correctly?\n{e}")
        return

    print("\n" + "="*50)
    print("WARNING: This script creates hostPath PersistentVolumes.")
    print(f"You MUST ensure the base directory '{HOST_PATH_BASE_DIR}' exists on your Kubernetes nodes.")
    print("For example, by running: 'sudo mkdir -p /mnt/kube-storage'")
    print("="*50 + "\n")

    try:
        all_pvcs = api.list_persistent_volume_claim_for_all_namespaces()
    except ApiException as e:
        print(f"Error: Could not list PVCs from the cluster: {e}")
        return
    
    pending_pvcs = [pvc for pvc in all_pvcs.items if pvc.status.phase == "Pending"]

    if not pending_pvcs:
        print("No pending PVCs found. Your cluster looks healthy!")
        return
        
    print(f"Found {len(pending_pvcs)} pending PVC(s). Attempting to create matching PVs...")
    for pvc in pending_pvcs:
        create_pv_for_pvc(api, pvc)

if __name__ == "__main__":
    main()