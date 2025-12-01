import os
import json
import yaml
import re
import time
import hashlib
from tqdm import tqdm

# It's good practice to handle potential import errors.
try:
    import openai
except ImportError:
    print("[ERROR] The 'openai' library is not installed.")
    print("[INFO] Please install it by running: pip install openai")
    exit()

# --- Configuration ---
OPENAI_CACHE_FILE = ".openai_cache.json"

# --- OpenAI API Configuration ---
# Use the modern OpenAI client.
try:
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    if not OPENAI_API_KEY:
        print("[WARNING] OPENAI_API_KEY environment variable not found.")
        print("[INFO] Please set this environment variable to use OpenAI features.")
        openai_client = None
    else:
        openai_client = openai.OpenAI(api_key=OPENAI_API_KEY)
except Exception as e:
    print(f"[ERROR] Failed to configure OpenAI API client: {e}")
    openai_client = None

# --- Caching Functions ---
def load_cache(cache_file: str) -> dict:
    """Loads a JSON cache from a file."""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"[WARNING] Could not decode JSON from {cache_file}. Starting with an empty cache.")
            return {}
    return {}

def save_cache(cache: dict, cache_file: str):
    """Saves a dictionary to a JSON cache file."""
    with open(cache_file, 'w') as f:
        json.dump(cache, f, indent=4)

# --- Analysis Functions ---
def extract_docker_images(values_content: str) -> list:
    """Extracts unique Docker image references from values.yaml content."""
    images = set()
    try:
        data = yaml.safe_load(values_content)
        def find_images_recursive(obj):
            if isinstance(obj, dict):
                repo = obj.get("repository")
                tag = obj.get("tag")
                if repo and tag:
                    images.add(f"{repo}:{tag}")
                for value in obj.values():
                    find_images_recursive(value)
            elif isinstance(obj, list):
                for item in obj:
                    find_images_recursive(item)
        find_images_recursive(data)
    except yaml.YAMLError as e:
        print(f"[WARNING] Could not parse YAML content: {e}. Falling back to regex.")
        pass

    # Regex as a fallback to catch additional image definitions
    # This regex is improved to be more specific.
    regex_pattern = r'repository:\s*["\']?([^\'"\s]+)[\'"]?\s*\n\s*tag:\s*["\']?([^\'"\s]+)[\'"]?'
    for match in re.finditer(regex_pattern, values_content):
        images.add(f"{match.group(1)}:{match.group(2)}")

    return sorted(list(images))

def generate_credentials_with_openai(client: openai.OpenAI, image_name: str) -> dict:
    """Uses the OpenAI API to generate realistic credential data for a Docker image."""
    if not client:
        return {"error": "OpenAI client not configured."}

    prompt = f"""
You are a DevOps security expert. For the Docker image '{image_name}', generate a JSON object containing typical, realistic credential-related environment variables needed for a standard deployment.
The JSON object should have keys as environment variable names and realistic but fake example values.

For example, for a postgres image:
{{"POSTGRES_USER": "admin", "POSTGRES_PASSWORD": "Password123!", "POSTGRES_DB": "mydatabase"}}

Respond with ONLY the JSON object and nothing else.
"""
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a DevOps security expert. Always respond with only valid JSON objects."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=500,
            temperature=0.7,
            response_format={"type": "json_object"} # Use JSON mode for reliability
        )
        response_text = response.choices[0].message.content.strip()
        return json.loads(response_text)
    except Exception as e:
        return {"error": f"OpenAI API call failed: {e}"}

def format_credentials_for_cyberbattle(client: openai.OpenAI, image_name: str, service_name: str, generated_creds: dict) -> list:
    """Takes generated credentials and formats them into CyberBattleSim objects using OpenAI."""
    if not client or "error" in generated_creds:
        return []

    prompt = f"""
You are a CyberBattleSim environment designer. Convert the following environment variables for the service '{service_name}' into a list of structured CyberBattleSim credential objects.
Each object must have "name", "node", "username", and "password" fields.
- Infer the "username" from a user-related key.
- Infer the "password" from a password-related key.
- Create a unique "name" for the credential object (e.g., "{service_name}-creds").
- The "node" is '{service_name}'.

Input Variables: {json.dumps(generated_creds)}

Respond with ONLY a JSON list of CyberBattleSim credential objects and nothing else.
"""
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a CyberBattleSim environment designer. Always respond with only valid JSON arrays."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=500,
            temperature=0.7,
            response_format={"type": "json_object"}
        )
        response_text = response.choices[0].message.content.strip()
        # The response should be a JSON object containing the list, let's be safe
        json_response = json.loads(response_text)
        # Handle cases where the model might wrap the list in a key
        if isinstance(json_response, list):
            return json_response
        elif isinstance(json_response, dict):
             # Try to find a list within the dict
            for value in json_response.values():
                if isinstance(value, list):
                    return value
        return []

    except Exception as e:
        print(f"[WARNING] OpenAI formatting failed for {image_name}: {e}")
        return []

def save_project_credentials(project_output_dir: str, service_name: str, cyberbattle_credentials: list, docker_images: list, raw_credentials: dict):
    """Save credentials in an organized structure within a project subfolder."""
    os.makedirs(project_output_dir, exist_ok=True)
    credentials_dir = os.path.join(project_output_dir, "credentials")
    os.makedirs(credentials_dir, exist_ok=True)

    # Save CyberBattleSim formatted credentials
    cyberbattle_path = os.path.join(credentials_dir, "cyberbattle_credentials.json")
    with open(cyberbattle_path, 'w') as f:
        json.dump({
            'service_name': service_name,
            'cyberbattle_credentials': cyberbattle_credentials,
            'docker_images': docker_images
        }, f, indent=4)

    # Save raw generated credentials for reference
    raw_creds_path = os.path.join(credentials_dir, "raw_credentials.json")
    with open(raw_creds_path, 'w') as f:
        json.dump({
            'service_name': service_name,
            'docker_images': docker_images,
            'raw_credentials_by_image': raw_credentials
        }, f, indent=4)

    # Save individual credential files per image
    for image_name, creds in raw_credentials.items():
        if "error" not in creds:
            safe_image_name = re.sub(r'[^\w\-_.]', '_', image_name.replace(':', '_').replace('/', '_'))
            image_creds_path = os.path.join(credentials_dir, f"{safe_image_name}_credentials.json")
            with open(image_creds_path, 'w') as f:
                json.dump({
                    'image_name': image_name,
                    'service_name': service_name,
                    'credentials': creds
                }, f, indent=4)

    # Save summary file in the main project directory
    summary_path = os.path.join(project_output_dir, "project_summary.json")
    with open(summary_path, 'w') as f:
        json.dump({
            'service_name': service_name,
            'docker_images_count': len(docker_images),
            'docker_images': docker_images,
            'cyberbattle_credentials_count': len(cyberbattle_credentials),
            'has_credentials': len(cyberbattle_credentials) > 0,
            'credentials_location': os.path.relpath(credentials_dir, project_output_dir)
        }, f, indent=4)

    return credentials_dir

def main():
    """Main function to discover Helm charts and generate credentials using OpenAI."""
    # These paths should be configured as needed.
    BITNAMI_CHARTS_DIR = "./charts/bitnami" # Example path
    BASE_OUTPUT_DIR = "/content/drive/MyDrive/thesis/code/datasets/poc/realistic" # Example path

    if not os.path.isdir(BITNAMI_CHARTS_DIR):
        print(f"[ERROR] Directory not found: {BITNAMI_CHARTS_DIR}")
        print("[INFO] Please update the 'BITNAMI_CHARTS_DIR' variable to point to your charts directory.")
        return

    openai_cache = load_cache(OPENAI_CACHE_FILE)
    project_paths = [os.path.join(BITNAMI_CHARTS_DIR, d) for d in os.listdir(BITNAMI_CHARTS_DIR) if os.path.isdir(os.path.join(BITNAMI_CHARTS_DIR, d))]
    processed_projects = []
    failed_projects_list = [] # Renamed to avoid conflict with the dictionary key

    with tqdm(total=len(project_paths), desc="Analyzing Projects") as pbar:
        for project_path in project_paths:
            service_name = os.path.basename(project_path)
            pbar.set_description(f"Processing: {service_name}")

            values_path = os.path.join(project_path, 'values.yaml')
            chart_path = os.path.join(project_path, 'Chart.yaml')
            if not (os.path.exists(values_path) and os.path.exists(chart_path)):
                failed_projects_list.append({'service': service_name, 'reason': 'Missing values.yaml or Chart.yaml'})
                pbar.update(1)
                continue

            try:
                with open(values_path, 'r', errors='ignore') as f:
                    content = f.read()

                docker_images = extract_docker_images(content)
                cyberbattle_credentials = []
                raw_credentials = {}

                if openai_client and docker_images:
                    for image in docker_images:
                        image_hash = hashlib.sha256(image.encode()).hexdigest()

                        # Step 1: Generate credentials
                        if image_hash not in openai_cache:
                            pbar.write(f"Querying OpenAI to generate credentials for: {image}")
                            creds = generate_credentials_with_openai(openai_client, image)
                            openai_cache[image_hash] = {"generated": creds}
                            time.sleep(1)

                        generated_creds = openai_cache[image_hash].get("generated", {})
                        raw_credentials[image] = generated_creds

                        # Step 2: Format the generated credentials
                        formatted_key = f"{image_hash}_formatted_for_{service_name}"
                        if formatted_key not in openai_cache:
                             pbar.write(f"Querying OpenAI to format credentials for: {image} in service {service_name}")
                             if "error" not in generated_creds and generated_creds:
                                 formatted = format_credentials_for_cyberbattle(openai_client, image, service_name, generated_creds)
                                 openai_cache[formatted_key] = formatted
                                 time.sleep(1)
                             else:
                                 openai_cache[formatted_key] = []

                        cyberbattle_credentials.extend(openai_cache.get(formatted_key, []))

                save_cache(openai_cache, OPENAI_CACHE_FILE)

                project_output_dir = os.path.join(BASE_OUTPUT_DIR, service_name)
                credentials_dir = save_project_credentials(
                    project_output_dir,
                    service_name,
                    cyberbattle_credentials,
                    docker_images,
                    raw_credentials
                )

                processed_projects.append({
                    'service': service_name,
                    'images_count': len(docker_images),
                    'credentials_count': len(cyberbattle_credentials),
                    'output_dir': project_output_dir,
                    'credentials_dir': credentials_dir
                })
                pbar.write(f"✅ Saved credentials for {service_name} in: {credentials_dir}")

            except Exception as e:
                error_msg = f"Could not process {project_path}: {e}"
                failed_projects_list.append({'service': service_name, 'reason': str(e)})
                pbar.write(f"❌ {error_msg}")
            pbar.update(1)

    # Save overall summary
    os.makedirs(BASE_OUTPUT_DIR, exist_ok=True)
    summary_file = os.path.join(BASE_OUTPUT_DIR, "analysis_summary.json")
    with open(summary_file, 'w') as f:
        json.dump({
            'total_projects': len(project_paths),
            'processed_successfully': len(processed_projects),
            'failed_projects_count': len(failed_projects_list),
            'processed_projects': processed_projects,
            'failed_projects': failed_projects_list,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'llm_provider': 'OpenAI GPT-3.5-turbo'
        }, f, indent=4)

    print(f"\n✅ Analysis complete.")
    print(f"📊 Processed {len(processed_projects)} projects successfully")
    print(f"❌ Failed to process {len(failed_projects_list)} projects")
    print(f"📄 Summary saved to: {summary_file}")

if __name__ == "__main__":
    main()