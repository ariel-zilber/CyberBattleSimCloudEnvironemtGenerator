"""
Logical Cluster Generator
=========================
Generates the abstract Kubernetes cluster state:
- Determines cluster size and resource capacity.
- Selects services based on UseCase probabilities or explicit configuration.
- Assigns services to logical subnets.
- Generates high-level firewall and OSINT configurations.
"""

from typing import Dict

# Relative imports


def enhance_logical_generation(cluster_data: Dict) -> Dict:
    """
    Post-process logical cluster to ensure attack surface exists.
    Call this after K8sClusterGenerator.generate()
    """

    selected_services = set(cluster_data.get("services", []))

    # 1. Ensure Control Plane Services exist
    # These are critical for targeting the control plane (and often missing in random generation)
    for cp_svc in CONTROL_PLANE_SERVICES:
        if cp_svc not in selected_services:
            selected_services.add(cp_svc)
            # Add metadata
            if "service_instances" not in cluster_data:
                cluster_data["service_instances"] = {}
            cluster_data["service_instances"][cp_svc] = 1

            if "service_distribution" not in cluster_data:
                cluster_data["service_distribution"] = {}
            # Assign to subnet 0 (logical), physical gen will move to Control Plane nodes via affinity
            cluster_data["service_distribution"][cp_svc] = {
                "instances": 1,
                "subnets": [0],
            }

    # 2. Ensure at least one public service exists
    has_public = any(svc in PUBLIC_SERVICES for svc in selected_services)

    if not has_public:
        # Force add a common public service
        public_entry = "nginx"
        selected_services.add(public_entry)

        # Add instance count
        if "service_instances" not in cluster_data:
            cluster_data["service_instances"] = {}
        cluster_data["service_instances"][public_entry] = 1

        # Assign to DMZ subnet (subnet 0)
        if "service_distribution" not in cluster_data:
            cluster_data["service_distribution"] = {}
        cluster_data["service_distribution"][public_entry] = {
            "instances": 1,
            "subnets": [0],  # DMZ
        }

    # Save back the complete list
    cluster_data["services"] = sorted(list(selected_services))

    # 3. Mark public services in metadata
    cluster_data["public_services"] = [
        svc for svc in selected_services if svc in PUBLIC_SERVICES
    ]

    # 4. Ensure DMZ subnet exists and has public services
    if "network" in cluster_data and "subnets" in cluster_data["network"]:
        subnets = cluster_data["network"]["subnets"]
        if subnets:
            # Mark first subnet as DMZ
            subnets[0]["label"] = "dmz"
            subnets[0]["is_public"] = True

            # Ensure at least one public service is in DMZ
            dmz_services = subnets[0].get("services", [])
            has_public_in_dmz = any(s in PUBLIC_SERVICES for s in dmz_services)

            if not has_public_in_dmz and cluster_data["public_services"]:
                # Move one public service to DMZ
                pub_svc = cluster_data["public_services"][0]
                if pub_svc not in dmz_services:
                    dmz_services.append(pub_svc)
                    subnets[0]["services"] = dmz_services

                    # Update service distribution
                    if pub_svc in cluster_data["service_distribution"]:
                        dist = cluster_data["service_distribution"][pub_svc]
                        if 0 not in dist["subnets"]:
                            dist["subnets"].insert(0, 0)

    return cluster_data
