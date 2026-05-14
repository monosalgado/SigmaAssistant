from backend.sysmon_data import SYSMON_EVENTS
from backend.ingest_mitre import download_and_parse_mitre
from backend.vector_store import VectorStore
from backend.ingest_rules import load_sigma_rules
import os

def main():
    print("Initializing Vector Store...")
    vs = VectorStore()
    
    # 1. Ingest Sysmon Data
    print("\n--- Ingesting Sysmon Data ---")
    vs.add_sysmon_info(SYSMON_EVENTS)
    print("Sysmon ingestion complete.")
    
    # 2. Ingest MITRE ATT&CK Data
    print("\n--- Ingesting MITRE ATT&CK Data ---")
    mitre_data = download_and_parse_mitre()
    if mitre_data:
        # Full ingestion — no cap. Required for accurate TTP mapping in the pipeline.
        # With local embeddings this takes a few minutes (no API latency/quota).
        print(f"Adding all {len(mitre_data)} MITRE techniques...")
        vs.add_mitre_techniques(mitre_data)
        
    # 3. Ingest Sigma Rules
    print("\n--- Ingesting Sigma Rules ---")
    existing_sigma_count = vs.sigma_collection.count()
    print(f"Existing sigma rules in DB: {existing_sigma_count}")
    
    rules_path = "data/sigma/rules"
    if os.path.exists(rules_path):
        rules = load_sigma_rules(rules_path)
        print(f"Found {len(rules)} Windows/Sysmon rules on disk.")
        
        if existing_sigma_count >= len(rules):
            print(f"Sigma collection already has {existing_sigma_count} rules. Skipping ingestion.")
        else:
            # Ingest all found rules (upsert handles duplicates)
            print(f"Ingesting {len(rules)} rules...")
            vs.add_rules(rules)
    else:
        print(f"Sigma rules directory '{rules_path}' not found. Make sure the SigmaHQ repo is cloned into data/sigma.")
    
    print("\n✅ Knowledge Base Expansion Complete.")

    # Verification Search
    print("\nVerifying Search...")
    query = "Credential Dumping"
    results = vs.search(query, collections=["mitre", "sysmon"])
    
    print("\nMITRE Results:")
    if results.get("mitre"):
        for doc in results["mitre"]['documents'][0]:
            print(f"- {doc[:100]}...")

    print("\nSysmon Results:")
    if results.get("sysmon"):
         for doc in results["sysmon"]['documents'][0]:
            print(f"- {doc[:100]}...")

if __name__ == "__main__":
    main()
