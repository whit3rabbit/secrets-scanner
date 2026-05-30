#!/usr/bin/env python3
import csv
import os
import re
import sys

def generate_keywords(provider, secret_type):
    keywords = set()
    
    # First segment of secret_type
    st_parts = secret_type.lower().split('_')
    if st_parts:
        first_st = st_parts[0]
        # Exclude generic words that would cause too many false positive keyword match triggers
        if first_st not in ("api", "token", "secret", "key", "password", "private", "public"):
            keywords.add(first_st)
            
    # Clean provider name
    prov = provider.lower()
    for ext in ['.com', '.re', '.io', '.dev', '.ai', '.org', '.net']:
        if prov.endswith(ext):
            prov = prov[:-len(ext)]
            
    # Take first word of provider name
    prov_words = re.split(r'[^a-z0-9]+', prov)
    if prov_words:
        first_word = prov_words[0]
        if len(first_word) >= 3 and first_word not in ("api", "token", "secret", "key", "password", "private", "public"):
            keywords.add(first_word)
            
    if not keywords:
        keywords.add(provider.lower().split()[0])
        
    return sorted(list(keywords))

def main():
    csv_path = "tmp/github_patterns_enriched_fake_examples_regex_case_conservative.csv"
    toml_path = "assets/local.toml"
    
    if not os.path.exists(csv_path):
        print(f"Error: CSV file not found at {csv_path}", file=sys.stderr)
        sys.exit(1)
        
    rules = []
    with open(csv_path, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            provider = row.get('provider', '').strip()
            supported_secret = row.get('supportedSecret', '').strip()
            secret_type = row.get('secretType', '').strip()
            regex = row.get('regex', '').strip()
            
            if not secret_type or not regex:
                continue
                
            # Clean HTML tags and invalid characters for ID
            clean_secret_type = re.sub(r'<[^>]*>', '', secret_type)
            rule_id = re.sub(r'[^a-zA-Z0-9_-]+', '-', clean_secret_type).strip('-').replace('_', '-')
            
            # Clean HTML tags for description and provider
            clean_supported_secret = re.sub(r'<[^>]*>', '', supported_secret)
            clean_provider = re.sub(r'<[^>]*>', '', provider)
            description = f"Identified a potential {clean_supported_secret}, which could lead to unauthorized access to {clean_provider} services and sensitive data exposure."
            keywords = generate_keywords(clean_provider, clean_secret_type)
            
            rules.append({
                'id': rule_id,
                'description': description,
                'regex': regex,
                'keywords': keywords
            })
            
    os.makedirs(os.path.dirname(toml_path), exist_ok=True)
    
    with open(toml_path, mode='w', encoding='utf-8') as f:
        f.write('title = "local secrets-scanner"\n\n')
        for rule in rules:
            f.write('[[rules]]\n')
            f.write(f'id = "{rule["id"]}"\n')
            f.write(f'description = "{rule["description"]}"\n')
            
            # Use triple single quotes for regex as a literal multi-line string
            regex_val = rule["regex"]
            f.write(f"regex = '''{regex_val}'''\n")
            
            # Format keywords array
            kw_str = ", ".join(f'"{k}"' for k in rule["keywords"])
            f.write(f"keywords = [{kw_str}]\n\n")
            
    print(f"Successfully converted {len(rules)} rules to {toml_path}")

if __name__ == "__main__":
    main()
