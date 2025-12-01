#!/usr/bin/env python3
import json
import os
import sys
import argparse
import csv
from typing import Dict, List, Tuple, Any

# ==================== CVSS helpers ====================

def extract_cvss_score(vuln_data: dict) -> float:
    """
    Extract a representative CVSS score.
    Takes the MAX across all vendor sources (e.g., nvd, redhat, ghsa),
    preferring V3 if available, otherwise V2.
    """
    cvss = vuln_data.get("CVSS", {})
    scores: List[float] = []
    for _, vendor_data in cvss.items():
        if isinstance(vendor_data, dict):
            if "V3Score" in vendor_data and vendor_data["V3Score"] is not None:
                try:
                    scores.append(float(vendor_data["V3Score"]))
                except Exception:
                    pass
            elif "V2Score" in vendor_data and vendor_data["V2Score"] is not None:
                try:
                    scores.append(float(vendor_data["V2Score"]))
                except Exception:
                    pass
    return max(scores) if scores else 0.0


def get_severity_label(score: float) -> str:
    """Get severity label and emoji based on CVSS score."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    else:
        return "UNKNOWN"


def is_currently_affected(v: dict) -> bool:
    """Trivy-style status filter; default to 'affected'."""
    return (v.get("Status") or "affected").lower() == "affected"


# ★ NEW: map CVSS to exploitability (success probability & reward hint)
def cvss_to_exploitability(score: float) -> Tuple[float, int]:
    """
    Convert CVSS to rough success probability and reward weight.
    You can retune these in your env loader if you like.
    """
    if score >= 9.0:
        return 0.85, 40
    if score >= 7.0:
        return 0.65, 30
    if score >= 4.0:
        return 0.35, 20
    if score > 0.0:
        return 0.20, 10
    return 0.10, 5


# ==================== Image normalization & matching ====================

def normalize_image(name: str) -> str:
    """
    Normalize an image reference by stripping common registry prefixes and 'library/'.
    Keeps repo[:tag] if present.
    """
    if not name or not isinstance(name, str):
        return ""
    s = name.strip()
    for prefix in ("docker.io/", "registry-1.docker.io/", "ghcr.io/", "quay.io/"):
        if s.startswith(prefix):
            s = s[len(prefix):]
            break
    if s.startswith("library/"):
        s = s[len("library/"):]
    return s


def _normalize_image_ref(ref: str) -> Tuple[str, str]:
    """
    Return (repo, tag). Accepts 'repo:tag' or returns ('repo','') if no tag present.
    No registry normalization here; call normalize_image() first if needed.
    """
    if not ref or not isinstance(ref, str):
        return ("", "")
    if ":" in ref:
        repo, tag = ref.rsplit(":", 1)
        return (repo, tag)
    return (ref, "")


def _match_image_to_analysis(container_image: str,
                             vuln_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Best-effort match between container image ref and analysis keys.
    vuln_map maps normalized image -> {'vulns': [...], 'status': 'success'|'error_*'|...}
    """
    if not vuln_map:
        return {"vulns": [], "status": "missing"}

    norm = normalize_image(container_image)
    repo, tag = _normalize_image_ref(norm)
    full_key = f"{repo}:{tag}" if tag else repo

    if full_key in vuln_map:
        return vuln_map[full_key]
    if repo in vuln_map:
        return vuln_map[repo]

    repo_tail = repo.split("/")[-2:]  # keep last two segments
    def tail(path: str) -> List[str]:
        return (path or "").split("/")[-2:]

    candidates = []
    for k in vuln_map.keys():
        k_repo, _ = _normalize_image_ref(k)
        if tail(k_repo) == repo_tail:
            candidates.append(k)
    if len(candidates) == 1:
        return vuln_map[candidates[0]]

    return {"vulns": [], "status": "missing"}


# ==================== Analysis file loading ====================

def load_vulnerabilities(project_folder: str) -> Dict[str, Dict[str, Any]]:
    """
    Load CVE vulnerabilities from helm_analysis_with_cves_and_secrets.json.

    Returns:
      { normalized_image -> {'vulns': [...], 'status': 'success'|'error_*'|...} }
    """
    analysis_path = os.path.join(project_folder, "helm_analysis_with_cves_and_secrets.json")
    vulnerabilities_by_image: Dict[str, Dict[str, Any]] = {}

    if os.path.exists(analysis_path):
        try:
            with open(analysis_path, "r") as f:
                analysis_data = json.load(f)

            for service in analysis_data.get("services", []):
                for image in service.get("docker_images", []) or []:
                    img_key = normalize_image(image.get("image_name", "unknown"))
                    entry = vulnerabilities_by_image.setdefault(img_key, {"vulns": [], "status": "unknown"})
                    entry["status"] = image.get("status", entry["status"])
                    vulns = image.get("vulnerabilities", []) or []
                    if vulns:
                        entry["vulns"].extend(vulns)
        except Exception as e:
            print(f"Warning: Could not load vulnerabilities: {e}")

    return vulnerabilities_by_image


def load_workload_images(project_folder: str) -> List[str]:
    """
    Optional coverage checker — if workload_images.json exists, use it to warn
    about workload images missing from the analysis file.
    """
    path = os.path.join(project_folder, "workload_images.json")
    imgs: List[str] = []
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            for ref in data.get("images", []) or []:
                imgs.append(normalize_image(ref))
        except Exception:
            pass
    return imgs


# ==================== Exporters for "remaining" CVEs ====================

def _iter_all_analysis_vulns(vulnerabilities_by_image: Dict[str, Dict[str, Any]]):
    for img, payload in vulnerabilities_by_image.items():
        for v in payload.get("vulns", []):
            yield img, v

def export_all_cves_json(out_path: str, vulnerabilities_by_image: Dict[str, Dict[str, Any]]):
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    payload = []
    for img, v in _iter_all_analysis_vulns(vulnerabilities_by_image):
        payload.append({
            "image": img,
            "id": v.get("VulnerabilityID", "Unknown-CVE"),
            "pkg": v.get("PkgName"),
            "installed": v.get("InstalledVersion"),
            "fixed": v.get("FixedVersion"),
            "score": extract_cvss_score(v),
            "severity": get_severity_label(extract_cvss_score(v)),
            "title": v.get("Title"),
            "description": v.get("Description"),
            "references": v.get("References"),
            "status": v.get("Status", "affected"),
        })
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"💾 Exported full CVE list (all images) to JSON: {out_path}")

def export_all_cves_csv(out_path: str, vulnerabilities_by_image: Dict[str, Dict[str, Any]]):
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["image", "id", "package", "installed", "fixed", "score", "severity", "status", "title"])
        for img, v in _iter_all_analysis_vulns(vulnerabilities_by_image):
            score = extract_cvss_score(v)
            w.writerow([
                img,
                v.get("VulnerabilityID", "Unknown-CVE"),
                v.get("PkgName"),
                v.get("InstalledVersion"),
                v.get("FixedVersion"),
                f"{score:.1f}",
                get_severity_label(score),
                v.get("Status", "affected"),
                (v.get("Title") or "")[:120]
            ])
    print(f"💾 Exported full CVE list (all images) to CSV: {out_path}")


# ==================== CyberBattleSim summary builder ====================

def build_cyberbattle_summary(
    chart_name: str,
    workload_details: Dict[str, Any],
    services: List[Dict[str, Any]],
    credentials: List[Dict[str, Any]],
    vulnerabilities_by_image: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Build environment summary usable for CyberBattleSim generation, with explicit node-level vulnerabilities.

    Schema highlights:
      node.vulnerabilities: [
        {
          "name": "CVE-2025-XXXX in openssl",
          "type": "Remote" | "Local",
          "source": "CVE",
          "cve_id": "CVE-2025-XXXX",
          "package": "openssl",
          "installed": "1.1.1x-r2",
          "fixed": "1.1.1x-r3",
          "score": 8.1,
          "severity": "🟠 HIGH",
          "success_prob": 0.65,
          "reward": 30,
          "container": "elasticsearch",
          "ports": [9200, 9300]               # if available for that container
        },
        {
          "name": "Exploit Public-Facing Service",
          "type": "Remote",
          "source": "Heuristic",
          "score": 5.0, "severity": "🟡 MEDIUM",
          "success_prob": 0.20, "reward": 10
        }
      ]
    """
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    # Pre-index services by selector
    svc_by_selector: List[Tuple[Dict[str, str], Dict[str, Any]]] = []
    for s in services or []:
        selector = s.get("selector") if isinstance(s, dict) else None
        svc_by_selector.append((selector or {}, s))

    any_public = False

    for kind, workloads in (workload_details or {}).items():
        for wname, data in (workloads or {}).items():
            node_id = f"{kind}:{wname}"
            labels = data.get("labels", {}) if isinstance(data, dict) else {}
            containers = data.get("containers", []) if isinstance(data, dict) else []

            # Containers (with ports & per-container CVEs for reference)
            cont_list = []
            # ★ NEW: aggregate per-node vulnerability list (CVE-derived + heuristic)
            node_vulns: List[Dict[str, Any]] = []

            for c in containers:
                if not isinstance(c, dict):
                    continue
                c_name = c.get("name", "")
                c_image = c.get("image", "")
                c_ports_list = [
                    p for p in (c.get("ports") or [])
                    if isinstance(p, dict) and p.get("containerPort") is not None
                ]
                c_ports = [int(p.get("containerPort")) for p in c_ports_list]

                img_payload = _match_image_to_analysis(c_image, vulnerabilities_by_image)
                vulns_affected = [v for v in img_payload.get("vulns", []) if is_currently_affected(v)]

                # container record
                cont_list.append({
                    "name": c_name,
                    "image": c_image,
                    "ports": [
                        {"port": int(p.get("containerPort")), "protocol": str(p.get("protocol", "TCP")), "name": p.get("name")}
                        for p in c_ports_list
                    ],
                    "vulnerabilities": [  # keep for debugging/trace
                        {
                            "id": v.get("VulnerabilityID", "Unknown"),
                            "score": float(extract_cvss_score(v)),
                            "severity": get_severity_label(extract_cvss_score(v)),
                            "status": v.get("Status", "affected"),
                            "package": v.get("PkgName"),
                            "installed": v.get("InstalledVersion"),
                            "fixed": v.get("FixedVersion"),
                            "title": v.get("Title"),
                        }
                        for v in vulns_affected
                    ],
                })

                # ★ NEW: promote CVEs into node-level vulnerabilities usable by CyberBattleSim
                for v in vulns_affected:
                    score = float(extract_cvss_score(v))
                    success_prob, reward = cvss_to_exploitability(score)
                    node_vulns.append({
                        "name": f"{v.get('VulnerabilityID', 'CVE')} in {v.get('PkgName')}",
                        "type": "Remote" if c_ports else "Local",
                        "source": "CVE",
                        "cve_id": v.get("VulnerabilityID"),
                        "package": v.get("PkgName"),
                        "installed": v.get("InstalledVersion"),
                        "fixed": v.get("FixedVersion"),
                        "score": score,
                        "severity": get_severity_label(score),
                        "success_prob": success_prob,
                        "reward": reward,
                        "container": c_name,
                        "ports": c_ports,  # OK if empty
                    })

            # Credentials (chart-wide, attached per node so the env loader can distribute)
            node_creds = [
                {"name": cr.get("name", ""), "username": cr.get("username", "")}
                for cr in (credentials or [])
                if isinstance(cr, dict)
            ]

            node_entry = {
                "id": node_id,
                "kind": kind,
                "labels": labels,
                "containers": cont_list,
                "credentials": node_creds,
                "public_exposed": False,
                # ★ NEW: node-level vulnerabilities (CVE-derived + heuristic fallbacks)
                "vulnerabilities": node_vulns,
            }
            nodes.append(node_entry)

            # Service → backend edges (selector ⊆ labels)
            for selector, svc in svc_by_selector:
                if selector and set(selector.items()) <= set(labels.items()):
                    edges.append({
                        "src": f"Service:{svc.get('name')}",
                        "dst": node_id,
                        "type": "K8sServiceBackends",
                        "metadata": {
                            "service_type": svc.get("type", "ClusterIP"),
                            "ports": svc.get("ports", []),
                        },
                    })
                    # mark public exposure
                    if str(svc.get("type", "ClusterIP")) in {"NodePort", "LoadBalancer"}:
                        node_entry["public_exposed"] = True
                        any_public = True

         
    # Internet ingress edges
    if any_public:
        for n in nodes:
            if n.get("public_exposed"):
                edges.append({"src": "Internet:entry", "dst": n["id"], "type": "Ingress"})

    # Simple lateral heuristic: same app label buckets
    label_key = "app.kubernetes.io/name"
    buckets: Dict[str, List[str]] = {}
    for n in nodes:
        key = n["labels"].get(label_key)
        if key:
            buckets.setdefault(key, []).append(n["id"])
    for _, ids in buckets.items():
        if len(ids) > 1:
            for i in range(len(ids) - 1):
                edges.append({"src": ids[i], "dst": ids[i + 1], "type": "Lateral", "metadata": {"by": label_key}})

    # ★ NEW: vulnerability stats
    vuln_total = sum(len(n.get("vulnerabilities", [])) for n in nodes)
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for n in nodes:
        for v in n.get("vulnerabilities", []):
            s = v.get("score", 0.0)
            if s >= 9.0: sev_counts["CRITICAL"] += 1
            elif s >= 7.0: sev_counts["HIGH"] += 1
            elif s >= 4.0: sev_counts["MEDIUM"] += 1
            elif s > 0.0: sev_counts["LOW"] += 1

    env = {
        "name": chart_name,
        "nodes": nodes,
        "edges": edges,
        "provenance": {"chart": chart_name},
        "stats": {"nodes": len(nodes), "edges": len(edges)},
        "vulnerability_stats": {"total": vuln_total, "severity_counts": sev_counts},  # ★ NEW
    }
    return env


def save_cyberbattle_summary(project_folder: str, env_summary: Dict[str, Any]) -> str:
    """Write final summary JSON into the project directory."""
    out_path = os.path.join(project_folder, "cyberbattle_env.json")
    with open(out_path, "w") as f:
        json.dump(env_summary, f, indent=2)
    print(f"✅ Saved CyberBattleSim summary: {out_path}")
    return out_path


# ==================== Topology printer (extended) ====================

def print_topology(project_folder: str, show_all: bool = False, top_n: int = 10):
    """
    Loads workload, service, credential, and vulnerability details and prints a complete summary
    with vendor-aware CVSS, status filtering, and unmatched-image coverage.
    Also saves a cyberbattle_env.json summary usable for CyberBattleSim environment generation.
    """
    chart_name = os.path.basename(project_folder)
    workload_path = os.path.join(project_folder, "workload_details.json")
    service_path = os.path.join(project_folder, "service_details.json")
    creds_path = os.path.join(project_folder, "credentials", "cyberbattle_credentials.json")

    # --- Load All Data Files ---
    try:
        with open(workload_path, 'r') as f:
            workload_details = json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: 'workload_details.json' not found. Please run the data extractor script first.")
        return

    services = []
    if os.path.exists(service_path):
        with open(service_path, 'r') as f:
            services = json.load(f)

    credentials = []
    if os.path.exists(creds_path):
        with open(creds_path, 'r') as f:
            credentials = json.load(f).get("cyberbattle_credentials", [])

    # Load actual CVE vulnerabilities (normalized)
    vulnerabilities_by_image = load_vulnerabilities(project_folder)
    workload_images_norm = set(load_workload_images(project_folder))

    print("=" * 100)
    print(f"🗺️  Full Attack Surface Topology with CVE Scores for: {chart_name}")
    print("=" * 100)

    node_count = 0
    print("🌐 Attacker Starting Point\n │\n └──> Entry Network (Internet)")

    matched_analysis_keys = set()

    # --- Print Topology ---
    for workload_type, workloads in workload_details.items():
        for workload_name, data in workloads.items():
            if type(data) is not dict:
                data=data[0]
            node_count += 1
            node_id = f"{workload_type}: {workload_name}"
            pod_labels = data.get("labels", {})
            containers = data.get("containers", [])

            print(f"\n  [NODE {node_count}]── {node_id}")

            # --- Services ---
            associated_services = [
                s for s in services
                if s.get("selector") and pod_labels and s.get("selector").items() <= pod_labels.items()
            ]
            if associated_services:
                print("  ├─🔌 Services:")
                for i, service in enumerate(associated_services):
                    is_last = (i == len(associated_services) - 1) and not containers
                    prefix = "  │   └─" if is_last else "  │   ├─"
                    service_name = service.get('name')
                    service_type = service.get('type')
                    service_ports = service.get('ports', [])
                    ports_str = f" Ports: {[p.get('port') for p in service_ports]}" if service_ports else ""
                    print(f"{prefix} {service_name} (Type: {service_type}){ports_str}")

            for i, container in enumerate(containers):
                if not isinstance(container, dict):
                    print(f"  └─📦 Malformed container data found: {container}")
                    continue

                is_last_container = (i == len(containers) - 1)
                prefix = "  └─" if is_last_container else "  ├─"
                container_name = container.get('name', 'N/A')
                container_image = container.get('image', 'N/A')
                print(f"{prefix}📦 Container: {container_name}")

                base_prefix = "    " if is_last_container else "  │ "
                print(f"{base_prefix}  Image: {container_image}")

                # --- CVE matching (normalized) ---
                img_payload = _match_image_to_analysis(container_image, vulnerabilities_by_image)
                status = img_payload.get("status", "unknown")
                print(f"{base_prefix}  Scan status: {status}")

                # --- Ports ---
                ports = container.get("ports", [])
                if ports:
                    print(f"{base_prefix}  Ports:")
                    for j, port_info in enumerate(ports):
                        is_last_port = (j == len(ports) - 1)
                        nested_prefix = "    └─" if is_last_port else "    ├─"
                        port_display = f"{port_info.get('containerPort', 'N/A')}/{port_info.get('protocol', 'TCP')}"
                        if port_info.get('name'):
                            port_display += f" ({port_info.get('name')})"
                        print(f"{base_prefix}{nested_prefix} {port_display}")

                # --- Credentials ---
                if credentials:
                    print(f"{base_prefix}  Credentials:")
                    for k, cred in enumerate(credentials):
                        is_last_cred = (k == len(credentials) - 1)
                        cred_prefix = "    └─" if is_last_cred else "    ├─"
                        cred_name = cred.get('name', 'N/A')
                        username = cred.get('username', 'N/A')
                        print(f"{base_prefix}{cred_prefix} 🔑 {cred_name} (User: {username})")

                # --- Track matched analysis keys for unmatched section
                if img_payload.get("vulns"):
                    norm = normalize_image(container_image)
                    repo, tag = _normalize_image_ref(norm)
                    matched_analysis_keys.add(f"{repo}:{tag}" if tag else repo)

    # --- Unmatched / extra images from analysis file ---
    all_analysis_images = set(vulnerabilities_by_image.keys())
    unmatched = sorted(img for img in all_analysis_images if img not in matched_analysis_keys)

    if unmatched:
        print("\n  📦 Images found in analysis but not tied to any rendered workload/container:")
        for u in unmatched:
            vcount = len(vulnerabilities_by_image.get(u, {}).get("vulns", []))
            status = vulnerabilities_by_image.get(u, {}).get("status", "unknown")
            print(f"    - {u} ({vcount} CVEs, status={status})")

    # --- Optional coverage check against workload_images.json ---
    if workload_images_norm:
        missing_in_analysis = sorted(img for img in workload_images_norm if img not in all_analysis_images)
        if missing_in_analysis:
            print("\n  ⚠️ Workload images missing from analysis index (re-scan recommended):")
            for m in missing_in_analysis:
                print(f"    - {m}")

    # --- Save final CyberBattle summary to project dir (WITH node.vulnerabilities) ---
    env_summary = build_cyberbattle_summary(
        chart_name=chart_name,
        workload_details=workload_details,
        services=services,
        credentials=credentials,
        vulnerabilities_by_image=vulnerabilities_by_image,
    )
    save_cyberbattle_summary(project_folder, env_summary)

    # --- Summary (console) ---
    print("\n" + "=" * 100)
    print("📊 Summary:")
    print(f"  • Total Nodes: {env_summary['stats']['nodes']}")
    print(f"  • Total Services: {len(services)}")
    print(f"  • Total Credentials: {len(credentials)}")
    print(f"  • Total Vulnerabilities (node-level, CVE+heuristic): {env_summary['vulnerability_stats']['total']}")
    sev = env_summary['vulnerability_stats']['severity_counts']
    print(f"  • Severity: Critical={sev['CRITICAL']}, High={sev['HIGH']}, Medium={sev['MEDIUM']}, Low={sev['LOW']}")
    print("=" * 100 + "\n")


# ==================== CLI ====================

def parse_args():
    p = argparse.ArgumentParser(description="Print topology with CVEs and export remaining vulnerabilities.")
    p.add_argument("--project", required=False,
                   default="/content/drive/MyDrive/thesis/code/datasets/poc/realistic/rabbitmq",
                   help="Path to a single chart project folder (contains workload_details.json etc.)")
    p.add_argument("--show-all", action="store_true", help="Print ALL CVEs in console (can be huge).")
    p.add_argument("--limit", type=int, default=10, help="Top-N CVEs to show per image if not --show-all.")
    p.add_argument("--export-json", type=str, default="", help="Export ALL CVEs to this JSON file.")
    p.add_argument("--export-csv", type=str, default="", help="Export ALL CVEs to this CSV file.")
    return p.parse_args()

def main():
    args = parse_args()

    project_folder_path = args.project
    if not os.path.isdir(project_folder_path):
        print(f"❌ Error: The project directory not found at '{project_folder_path}'")
        base_dir = os.path.dirname(project_folder_path) or "."
        if os.path.exists(base_dir):
            available_projects = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
            print(f"Available projects in {base_dir}: {available_projects}")
        return

    vulnerabilities_by_image = load_vulnerabilities(project_folder_path)

    if args.export_json:
        export_all_cves_json(args.export_json, vulnerabilities_by_image)
    if args.export_csv:
        export_all_cves_csv(args.export_csv, vulnerabilities_by_image)

    print_topology(project_folder_path, show_all=args.show_all, top_n=args.limit)

if __name__ == "__main__":
    main()
