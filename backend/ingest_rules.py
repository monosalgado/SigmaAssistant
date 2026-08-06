import os
import yaml
from pathlib import Path

def load_sigma_rules(rules_path):
    """
    Recursively load Sigma rules from a directory.

    Every parseable rule is loaded regardless of platform. An earlier version
    kept only `product == 'windows' or service == 'sysmon'`, which excluded 722
    of 3104 rules (cloud, linux, macos, network, web, application, identity)
    while prompts.py asks the model to cover network-based initial access.
    """
    rules = []
    path = Path(rules_path)
    
    # Walk through the directory and finding .yml files
    for file_path in path.rglob("*.yml"):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Use safe_load_all because some files might have multiple documents
                # though usually sigma rules are single docs
                content = yaml.safe_load(f)
                
                if not content:
                    continue

                # Handle if content is a list/generator
                if not isinstance(content, dict):
                     continue

                # Basic validation: check if it's a rule
                if 'title' not in content or 'logsource' not in content:
                    continue

                rules.append({
                    'id': content.get('id', str(file_path)),
                    'title': content.get('title'),
                    'description': content.get('description', ''),
                    'logsource': content.get('logsource', {}),
                    'detection': content.get('detection', {}),
                    'level': content.get('level', ''),
                    'tags': content.get('tags', []) or [],
                    'path': str(file_path)
                })

        except Exception as e:
            # Skip files that fail to load
            print(f"Skipping {file_path}: {e}")
            continue
            
    return rules

if __name__ == "__main__":
    # Test the loader
    rules_dir = "data/sigma/rules" 
    if os.path.exists(rules_dir):
        print("Loading rules...")
        rules = load_sigma_rules(rules_dir)
        print(f"Found {len(rules)} rules.")
        # Print a sample
        if rules:
            print("\nSample Rule:")
            print(rules[0]['title'])
    else:
        print(f"Directory {rules_dir} not found. Please ensure git clone completed.")
