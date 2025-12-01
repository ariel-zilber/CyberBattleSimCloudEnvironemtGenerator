#!/usr/bin/env python3
import subprocess
import yaml
import os
import json
import argparse
from datetime import datetime
from typing import Dict, List, Any

"""
Kwok Cluster Snapshot Generator

Creates a complete snapshot of a kwok cluster state including all resources.
"""

def run_kubectl(args: List[str]) -> str:
    """Execute kubectl command and return output."""
    try:
        result = subprocess.run(['kubectl'] + args, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running kubectl {' '.join(args)}: {e.stderr}")
        return ""

def get_cluster_resources() -> Dict[str, Any]:
    """Get all cluster resources organized by type."""
    resources = {}
    
    # Resource types to export
    resource_types = [
        'nodes',
        'pods',
        'services', 
        'deployments',
        'replicasets',
        'configmaps',
        'secrets',
        'persistentvolumes',
        'persistentvolumeclaims',
        'networkpolicies',
        'serviceaccounts',
        'roles',
        'rolebindings',
        'clusterroles',
        'clusterrolebindings'
    ]
    
    for resource_type in resource_types:
        print(f"📦 Exporting {resource_type}...")
        output = run_kubectl(['get', resource_type, '-o', 'yaml', '--all-namespaces'])
        
        if output:
            try:
                resource_data = yaml.safe_load(output)
                resources[resource_type] = resource_data
            except yaml.YAMLError:
                print(f"Warning: Failed to parse {resource_type}")
                resources[resource_type] = None
    
    return resources

def get_cluster_info() -> Dict[str, Any]:
    """Get cluster information and metadata."""
    info = {}
    
    # Get cluster info
    cluster_info = run_kubectl(['cluster-info'])
    info['cluster_info'] = cluster_info
    
    # Get kubectl version
    version_info = run_kubectl(['version', '--client=true', '-o', 'yaml'])
    if version_info:
        try:
            info['kubectl_version'] = yaml.safe_load(version_info)
        except yaml.YAMLError:
            info['kubectl_version'] = version_info
    
    # Get node info
    nodes_info = run_kubectl(['get', 'nodes', '-o', 'wide'])
    info['nodes_summary'] = nodes_info
    
    return info

def filter_kwok_resources(resources: Dict[str, Any]) -> Dict[str, Any]:
    """Filter to only include kwok-managed resources."""
    filtered = {}
    
    for resource_type, resource_data in resources.items():
        if not resource_data or 'items' not in resource_data:
            continue
            
        filtered_items = []
        for item in resource_data['items']:
            metadata = item.get('metadata', {})
            annotations = metadata.get('annotations', {})
            labels = metadata.get('labels', {})
            
            # Check for kwok annotations/labels
            is_kwok = (
                'kwok.x-k8s.io/node' in annotations or
                'kwok.x-k8s.io/fake' in annotations or
                any('kwok' in str(v).lower() for v in labels.values())
            )
            
            if is_kwok or resource_type in ['persistentvolumes', 'persistentvolumeclaims', 'networkpolicies']:
                # Clean up managed fields
                if 'managedFields' in metadata:
                    del metadata['managedFields']
                filtered_items.append(item)
        
        if filtered_items:
            resource_data['items'] = filtered_items
            filtered[resource_type] = resource_data
    
    return filtered

def create_snapshot(base_dir: str) -> str:
    """Create a complete cluster snapshot."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    date_str = datetime.now().strftime("%Y-%m-%d")
    
    snapshot_dir = os.path.join(base_dir, date_str, f"snapshot_{timestamp}")
    os.makedirs(snapshot_dir, exist_ok=True)
    
    print(f"🚀 Creating cluster snapshot...")
    
    # Get all resources
    resources = get_cluster_resources()
    
    # Get cluster metadata
    cluster_info = get_cluster_info()
    
    # Create snapshot manifest
    snapshot_manifest = {
        'apiVersion': 'snapshot.kwok.io/v1',
        'kind': 'ClusterSnapshot',
        'metadata': {
            'name': f'kwok-snapshot-{timestamp}',
            'creationTimestamp': datetime.now().isoformat()
        },
        'spec': {
            'timestamp': timestamp,
            'clusterInfo': cluster_info,
            'resourceCounts': {k: len(v.get('items', [])) for k, v in resources.items()},
            'totalResources': sum(len(v.get('items', [])) for v in resources.values())
        }
    }
    
    # Save snapshot manifest
    with open(os.path.join(snapshot_dir, 'snapshot-manifest.yaml'), 'w') as f:
        yaml.dump(snapshot_manifest, f, sort_keys=False, indent=2)
    
    # Save resources by type
    for resource_type, resource_data in resources.items():
        if resource_data and 'items' in resource_data:
            filename = f"{resource_type}.yaml"
            filepath = os.path.join(snapshot_dir, filename)
            
            with open(filepath, 'w') as f:
                yaml.dump(resource_data, f, sort_keys=False, indent=2)
    
    # Save cluster info
    with open(os.path.join(snapshot_dir, 'cluster-info.json'), 'w') as f:
        json.dump(cluster_info, f, indent=2)
    
    # Create summary
    summary = {
        'snapshot_timestamp': timestamp,
        'snapshot_directory': snapshot_dir,
        'resource_counts': snapshot_manifest['spec']['resourceCounts'],
        'total_resources': snapshot_manifest['spec']['totalResources']
    }
    
    with open(os.path.join(snapshot_dir, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    
    return snapshot_dir

def main():
    """Main function to create cluster snapshot."""
    parser = argparse.ArgumentParser(description="Create kwok cluster snapshot.")
    parser.add_argument("-b", "--base-dir", required=True, help="Base directory for snapshot output.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be captured without creating snapshot.")
    
    args = parser.parse_args()
    
    if args.dry_run:
        print("🔍 Dry run - showing resources that would be captured:")
        resources = get_cluster_resources()
        
        for resource_type, resource_data in resources.items():
            if resource_data and 'items' in resource_data:
                count = len(resource_data['items'])
                print(f"  {resource_type}: {count} items")
        return
    
    try:
        snapshot_dir = create_snapshot(args.base_dir)
        print(f"✅ Snapshot created: {snapshot_dir}")
        
        # Print summary
        with open(os.path.join(snapshot_dir, 'summary.json'), 'r') as f:
            summary = json.load(f)
        
        print(f"📊 Total resources: {summary['total_resources']}")
        for resource_type, count in summary['resource_counts'].items():
            if count > 0:
                print(f"   {resource_type}: {count}")
                
    except Exception as e:
        print(f"❌ Error creating snapshot: {e}")

if __name__ == '__main__':
    main()