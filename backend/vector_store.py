import os
import time
import chromadb
from chromadb import Documents, EmbeddingFunction, Embeddings
from chromadb import Documents, EmbeddingFunction, Embeddings
from google import genai
from dotenv import load_dotenv

load_dotenv()

class GeminiEmbeddingFunction(EmbeddingFunction):
    def __init__(self, api_key):
        self.client = genai.Client(api_key=api_key)

    def __call__(self, input: Documents) -> Embeddings:
        # Force model name just to be sure
        model = "models/gemini-embedding-001"
        title = "Combined Text" 
        embeddings = []
        for text in input:
            retry_count = 0
            while retry_count < 5:
                try:
                    # Note: For search queries, we ideally want task_type="retrieval_query"
                    # But Chroma interface is generic. 
                    # "retrieval_document" is usually fine for symmetric or database usage, 
                    # but let's try "retrieval_query" if the input text is short (likely a query)?
                    # No, that's hacky. sticking to 'retrieval_document' is consistent with index. 
                    # Let's try 'semantic_similarity' as a neutral ground if 'retrieval_document' fails?
                    # actually, let's just stick to what worked for ingestion.
                    # The error might be in the GENERATION step.
                    # The error might be in the GENERATION step.
                    response = self.client.models.embed_content(
                        model=model,
                        contents=text,
                    )
                    embeddings.append(response.embeddings[0].values)
                    time.sleep(1) 
                    break
                except Exception as e:
                    # ... existing retry logic ...
                    if "429" in str(e) or "ResourceExhausted" in str(e) or "quota" in str(e).lower():
                        wait_time = (2 ** retry_count) * 5 # 5, 10, 20...
                        print(f"Rate limit hit. Retrying in {wait_time}s...")
                        time.sleep(wait_time)
                        retry_count += 1
                    else:
                        print(f"Error embedding text: {e}")
                        # Append a dummy embedding or fail? 
                        # For now, let's skip/fail to see the issue
                        raise e
        return embeddings

class VectorStore:
    def __init__(self, persistence_path="data/chroma_db"):
        self.client = chromadb.PersistentClient(path=persistence_path)
        
        google_api_key = os.getenv("GEMINI_API_KEY")
        if not google_api_key:
             raise ValueError("GEMINI_API_KEY not found in environment variables")
             
        self.embedding_fn = GeminiEmbeddingFunction(api_key=google_api_key)
        
        # Initialize collections
        self.sigma_collection = self.client.get_or_create_collection(
            name="sigma_rules",
            embedding_function=self.embedding_fn
        )
        self.mitre_collection = self.client.get_or_create_collection(
            name="mitre_attack",
            embedding_function=self.embedding_fn
        )
        self.sysmon_collection = self.client.get_or_create_collection(
            name="sysmon_info",
            embedding_function=self.embedding_fn
        )

    def add_rules(self, rules):
        """Add Sigma rules to the sigma_rules collection."""
        if not rules: return
        
        ids = [r['id'] for r in rules]
        documents = []
        metadatas = []

        for r in rules:
            doc_text = f"Title: {r['title']}\nDescription: {r['description']}\nLog Source: {r['logsource']}\nDetection: {r['detection']}"
            documents.append(doc_text)
            metadatas.append({
                "type": "sigma_rule",
                "title": r['title'],
                "path": r['path'],
                "product": r['logsource'].get('product', 'unknown'),
                "service": r['logsource'].get('service', 'unknown')
            })

        self._batch_add(self.sigma_collection, ids, documents, metadatas)

    def add_mitre_techniques(self, techniques):
        """Add MITRE ATT&CK techniques."""
        if not techniques: return

        ids = [t['id'] for t in techniques]
        documents = []
        metadatas = []

        for t in techniques:
            doc_text = f"Technique: {t['name']} ({t['external_id']})\nDescription: {t['description']}"
            documents.append(doc_text)
            metadatas.append({
                "type": "mitre_technique",
                "name": t['name'],
                "external_id": t['external_id'],
                "url": t.get('url', '')
            })
            
        self._batch_add(self.mitre_collection, ids, documents, metadatas)

    def add_sysmon_info(self, sysmon_data):
        """Add Sysmon Event metadata."""
        if not sysmon_data: return

        ids = [f"sysmon_{e['id']}" for e in sysmon_data]
        documents = []
        metadatas = []

        for e in sysmon_data:
            doc_text = f"Sysmon Event ID {e['id']}: {e['name']}\nDescription: {e['description']}\nFields: {', '.join(e['fields'])}"
            documents.append(doc_text)
            metadatas.append({
                "type": "sysmon_info",
                "event_id": e['id'],
                "name": e['name']
            })

        self._batch_add(self.sysmon_collection, ids, documents, metadatas)

    def _batch_add(self, collection, ids, documents, metadatas):
        batch_size = 100
        total = len(ids)
        print(f"Adding {total} items to {collection.name}...")
        for i in range(0, total, batch_size):
            end = min(i + batch_size, total)
            collection.upsert(
                ids=ids[i:end],
                documents=documents[i:end],
                metadatas=metadatas[i:end]
            )
            print(f"Processed {end}/{total}")

    def search(self, query, collections=["sigma"], n_results=5):
        """
        Search specific collections.
        collections param can be a list containing 'sigma', 'mitre', 'sysmon'.
        Returns a dict with results from each requested collection.
        """
        results = {}
        
        if "sigma" in collections:
            results["sigma"] = self.sigma_collection.query(query_texts=[query], n_results=n_results)
        
        if "mitre" in collections:
            results["mitre"] = self.mitre_collection.query(query_texts=[query], n_results=n_results)
            
        if "sysmon" in collections:
            results["sysmon"] = self.sysmon_collection.query(query_texts=[query], n_results=n_results)
            
        return results

if __name__ == "__main__":
    # Test vector store init
    try:
        vs = VectorStore()
        print("✅ Vector Store initialized successfully.")
    except Exception as e:
        print(f"❌ Failed to initialize Vector Store: {e}")
