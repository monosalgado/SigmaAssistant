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
            # Skip revoked / deprecated techniques — they pollute the RAG and the
            # validator's tactic lookup with stale IDs (e.g. T1065).
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            # No platform filter — the full Enterprise ATT&CK matrix is needed
            # for webserver / Linux / Network / Cloud CVE detection work.

            external_references = obj.get("external_references", [])
            mitre_id = next((ref["external_id"] for ref in external_references if ref["source_name"] == "mitre-attack"), None)
            url = next((ref["url"] for ref in external_references if ref["source_name"] == "mitre-attack"), "")

            # Preserve tactics from STIX kill_chain_phases so downstream consumers
            # can validate that a declared tactic tag matches the technique's
            # legitimate tactic(s). ChromaDB metadata values must be primitives,
            # so we join as a comma-separated string.
            tactics = [
                phase.get("phase_name", "")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
            ]
            tactics_str = ",".join(sorted(set(tactics)))

            platforms = obj.get("x_mitre_platforms", []) or []
            platforms_str = ",".join(sorted(set(p for p in platforms if p)))

            if mitre_id:
                techniques.append({
                    "id": obj.get("id"), # STIX ID
                    "mitre_id": mitre_id, # Txxxx
                    "name": obj.get("name"),
                    "description": obj.get("description", ""),
                    "external_id": mitre_id,
                    "url": url,
                    "tactics": tactics_str,
                    "platforms": platforms_str,
                })

    print(f"Found {len(techniques)} Enterprise ATT&CK techniques (all platforms, non-deprecated).")
    return techniques

if __name__ == "__main__":
    download_and_parse_mitre()
