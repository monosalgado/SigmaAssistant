from backend.ingest_rules import load_sigma_rules
from backend.vector_store import VectorStore

def main():
    print("Initializing components...")
    rules_dir = "data/sigma/rules"
    
    print("Loading rules from file system...")
    rules = load_sigma_rules(rules_dir)
    print(f"Loaded {len(rules)} rules.")
    
    print("Initializing Vector Store (this might take a while if creating embeddings)...")
    vs = VectorStore()
    
    # Check if we need to add rules? 
    # For now, let's just add them. Real app would check existing to avoid duplicates or use IDs
    # But since we are setting up, we'll try to add a small batch to verifying it works
    # to avoid hitting API limits immediately in this test.
    
    # We will add ALL rules in the final pipeline, but for this step verification, let's add 3.
    test_batch = rules[:3] 
    print(f"Adding test batch of {len(test_batch)} rules to DB...")
    vs.add_rules(test_batch)
    
    print("✅ Ingestion test complete.")
    
    # Test Search
    query = "mimikatz"
    print(f"\nTesting search for '{query}'...")
    results = vs.search(query, collections=["sigma"])
    print("Found in Sigma:")
    if results.get("sigma") and results["sigma"]['documents']:
        for i, doc in enumerate(results["sigma"]['documents'][0]):
             print(f"{i+1}. {doc[:100]}...")
    else:
        print("No results found.")

if __name__ == "__main__":
    main()
