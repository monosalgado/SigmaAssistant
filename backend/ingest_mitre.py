import requests
import json
import os

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def download_and_parse_mitre():
    print(f"Downloading MITRE ATT&CK data from {MITRE_URL}...")
    try:
        response = requests.get(MITRE_URL)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Failed to download MITRE data: {e}")
        return []

    techniques = []
    print("Parsing techniques...")
    
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            # Check if it's for Windows
            platforms = obj.get("x_mitre_platforms", [])
            if "Windows" not in platforms:
                continue

            external_references = obj.get("external_references", [])
            mitre_id = next((ref["external_id"] for ref in external_references if ref["source_name"] == "mitre-attack"), None)
            url = next((ref["url"] for ref in external_references if ref["source_name"] == "mitre-attack"), "")

            if mitre_id:
                techniques.append({
                    "id": obj.get("id"), # STIX ID
                    "mitre_id": mitre_id, # Txxxx
                    "name": obj.get("name"),
                    "description": obj.get("description", ""),
                    "external_id": mitre_id,
                    "url": url
                })
    
    print(f"Found {len(techniques)} Windows techniques.")
    return techniques

if __name__ == "__main__":
    download_and_parse_mitre()
