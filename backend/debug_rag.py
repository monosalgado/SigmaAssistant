from backend.vector_store import VectorStore
import os
from dotenv import load_dotenv

load_dotenv()

def debug_rag():
    print("Initializing VectorStore...")
    try:
        vs = VectorStore()
    except Exception as e:
        print(f"Failed to init VS: {e}")
        return

    # 1. Check Counts
    print("\n--- Collection Counts ---")
    try:
        counts = f"Sigma Rules: {vs.sigma_collection.count()}\nMITRE: {vs.mitre_collection.count()}\nSysmon: {vs.sysmon_collection.count()}"
        print(counts)
        with open("counts.txt", "w") as f:
            f.write(counts)
    except Exception as e:
        print(f"Error checking counts: {e}")

    # 2. Test Search
    queries = [
        "mimikatz credential dump",
        "sql injection in web url",
        "suspicious child process svchost"
    ]

    print("\n--- Test Searches ---")
    for q in queries:
        print(f"\nQuery: '{q}'")
        try:
            results = vs.search(q, collections=["sigma"], n_results=3)
            docs = results.get("sigma", {}).get("documents", [[]])[0]
            ids = results.get("sigma", {}).get("ids", [[]])[0]
            
            if not docs:
                print("No results found.")
            else:
                for i, (doc_id, doc) in enumerate(zip(ids, docs)):
                    # Print first line of doc usually has title
                    title = doc.split('\n')[0]
                    print(f"  Result {i+1} [{doc_id}]: {title}...")
        except Exception as e:
            print(f"Search failed: {e}")

if __name__ == "__main__":
    debug_rag()
