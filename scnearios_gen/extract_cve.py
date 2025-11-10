import os
import json
import yaml

# --- Configuration ---
BASE_DIR = '/content/drive/MyDrive/thesis/code/datasets/poc/realistic'
JSON_FILENAME = 'helm_analysis_with_cves_and_secrets.json'
OUTPUT_FINAL_JSON = 'final.json'
OUTPUT_DB_YAML = 'vulnerability_db.yml'
# ---------------------

def create_cvss_objects(vuln):
    """
    Parses the 'CVSS' and 'Severity' fields from a vulnerability entry
    and formats them as requested for the vulnerability database.
    """
    cvss_v31 = None
    cvss_v30 = None
    cvss_v2 = None

    base_severity = vuln.get('Severity', 'UNKNOWN').upper()
    cvss_data = vuln.get('CVSS', {})
    
    # Prioritize NVD data, but fall back to other sources if nvd is missing
    nvd_data = cvss_data.get('nvd', {})
    if not nvd_data and cvss_data:
        # Get the first available CVSS data (e.g., 'redhat')
        first_key = next(iter(cvss_data))
        nvd_data = cvss_data.get(first_key, {})

    # --- Process V3 Vectors ---
    v3_vector = nvd_data.get('V3Vector')
    v3_score = nvd_data.get('V3Score')

    if v3_vector:
        v3_obj = {
            'vectorString': v3_vector,
            'baseScore': v3_score,
            'baseSeverity': base_severity
            # Note: The fully parsed vector fields (attackVector, etc.)
            # are not present in the source JSON, so we are populating
            # the fields that are available.
        }
        if v3_vector.startswith('CVSS:3.1'):
            v3_obj['version'] = '3.1'
            cvss_v31 = v3_obj
        elif v3_vector.startswith('CVSS:3.0'):
            v3_obj['version'] = '3.0'
            cvss_v30 = v3_obj

    # --- Process V2 Vectors ---
    v2_vector = nvd_data.get('V2Vector')
    v2_score = nvd_data.get('V2Score')

    if v2_vector:
        cvss_v2 = {
            'version': '2.0',
            'vectorString': v2_vector,
            'baseScore': v2_score
        }

    return cvss_v31, cvss_v30, cvss_v2

def process_analysis_files():
    """
    Main function to walk directories and process JSON files.
    """
    final_results = {}
    vulnerability_db = {}

    if not os.path.isdir(BASE_DIR):
        print(f"Error: Base directory not found: {BASE_DIR}")
        return

    print(f"Starting processing in: {BASE_DIR}")

    # Iterate over each item in the base directory
    for subdir_name in os.listdir(BASE_DIR):
        subdir_path = os.path.join(BASE_DIR, subdir_name)

        # Only process if it's a directory
        if os.path.isdir(subdir_path):
            json_file_path = os.path.join(subdir_path, JSON_FILENAME)

            if os.path.exists(json_file_path):
                print(f"Processing: {subdir_name}/{JSON_FILENAME}")
                subdir_cves = set() # Use a set for unique CVEs

                try:
                    with open(json_file_path, 'r') as f:
                        data = json.load(f)

                    # Navigate into the nested structure
                    for service in data.get('services', []):
                        for image in service.get('docker_images', []):
                            for vuln in image.get('vulnerabilities', []):
                                cve_id = vuln.get('VulnerabilityID')
                                if not cve_id:
                                    continue
                                
                                # Add CVE to the list for final.json
                                subdir_cves.add(cve_id)

                                # If we haven't seen this CVE before, add it to our DB
                                if cve_id not in vulnerability_db:
                                    cvss_v31, cvss_v30, cvss_v2 = create_cvss_objects(vuln)
                                    
                                    vulnerability_db[cve_id] = {
                                        'description': vuln.get('Description', vuln.get('Title', 'No description available.')),
                                        'published_date': vuln.get('PublishedDate'),
                                        'last_modified_date': vuln.get('LastModifiedDate'),
                                        'cvss_v31': cvss_v31,
                                        'cvss_v30': cvss_v30,
                                        'cvss_v2': cvss_v2
                                    }
                
                except json.JSONDecodeError:
                    print(f"  WARNING: Could not decode JSON in {json_file_path}")
                except Exception as e:
                    print(f"  ERROR: Could not process file {json_file_path}: {e}")

                # Add the list of unique CVEs for this subdir to the final result
                final_results[subdir_name] = sorted(list(subdir_cves))
            
            else:
                print(f"Skipping: {subdir_name} (no {JSON_FILENAME} found)")

    # --- Write Output Files ---

    # 1. Write the final.json file
    try:
        with open(OUTPUT_FINAL_JSON, 'w') as f:
            json.dump(final_results, f, indent=2, sort_keys=True)
        print(f"\nSuccessfully created: {OUTPUT_FINAL_JSON}")
    except Exception as e:
        print(f"\nError writing {OUTPUT_FINAL_JSON}: {e}")

    # 2. Write the vulnerability_db.yml file
    try:
        with open(OUTPUT_DB_YAML, 'w') as f:
            # default_flow_style=False gives the block format you wanted
            yaml.dump(vulnerability_db, f, sort_keys=True, default_flow_style=False)
        print(f"Successfully created: {OUTPUT_DB_YAML}")
    except Exception as e:
        print(f"Error writing {OUTPUT_DB_YAML}: {e}")

if __name__ == "__main__":
    process_analysis_files()