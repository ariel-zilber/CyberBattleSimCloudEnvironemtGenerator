import yaml
def load_yaml(file_path):
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
    return data

def save_yaml(data,file_path):
    with open(file_path, 'w') as file:
        yaml.dump(data, file, sort_keys=False)
def load_yaml_all(file_path):
    with open(file_path, 'r') as file:
        data = list(yaml.safe_load_all(file))
    return data