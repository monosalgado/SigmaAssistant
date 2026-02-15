import os
import time
from google import genai
from dotenv import load_dotenv
import requests
from bs4 import BeautifulSoup
import re
from backend.vector_store import VectorStore

load_dotenv()

class SigmaAgent:
    def __init__(self):
        # Initialize Vector Store (loads existing DB)
        self.vector_store = VectorStore()
        
        # Initialize Gemini with new SDK
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found")
            
        self.client = genai.Client(api_key=api_key)
        # Using the experimental model that confirmed working
        self.model_name = 'gemini-2.0-flash'

    # ... (init stays same)

    def analyze_attack(self, attack_description, history=None, media_file=None):
        """
        Main method to process a user's attack description and generate a Sigma rule.
        history: List of dicts [{"role": "user/assistant", "content": "..."}]
        media_file: Optional dict {'path': str, 'mime': str}
        """
        print(f"Analyzing: {attack_description}")
        
        # 1. Expand Context (URL Fetching)
        # 1. Expand Context (URL Fetching)
        # Scan for URLs
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', attack_description)
        
        url_context = ""
        if urls:
            # Shift content fetching logic...
            # Actually, let's keep it but formatted properly.
            pass

        # Helper to format history
        history_text = ""
        if history:
            # Limit history to last 10 messages to avoid context window issues
            recent_history = history[-10:] 
            for msg in recent_history:
                role = "User" if msg['role'] == 'user' else "AI"
                content = msg.get('content', '')
                history_text += f"{role}: {content}\n\n"
            print(f"Found URLs: {urls}. Fetching content...")
            for url in urls:
                try:
                    resp = requests.get(url, timeout=10)
                    if resp.status_code == 200:
                        soup = BeautifulSoup(resp.content, 'html.parser')
                        # Get text from paragraphs to avoid navigation noise
                        text = ' '.join([p.get_text() for p in soup.find_all('p')])
                        url_context += f"\n--- Content from {url} ---\n{text[:2000]}...\n" # Limit context size
                except Exception as e:
                    print(f"Failed to fetch {url}: {e}")

        # 2. Retrieve Context
        # We search based on the text description
        print("Retrieving context from Knowledge Base...")
        try:
            results = self.vector_store.search(
                attack_description, 
                collections=["sigma", "mitre", "sysmon"], 
                n_results=3
            )
            print(f"Context retrieved. Found {len(results.get('sigma',{}).get('documents',[[]])[0])} sigma rules.")
        except Exception as e:
           print(f"Error Retrieving Context: {e}")
           return {"rule": "Error retrieving context", "context": {}}
        
        # Format Context for Prompt
        sigma_docs = results.get("sigma", {}).get("documents", [[]])[0]
        mitre_docs = results.get("mitre", {}).get("documents", [[]])[0]
        sysmon_docs = results.get("sysmon", {}).get("documents", [[]])[0]
        
        sigma_context = "\n".join(sigma_docs) if sigma_docs else "No similar rules found."
        mitre_context = "\n".join(mitre_docs) if mitre_docs else "No MITRE context found."
        sysmon_context = "\n".join(sysmon_docs) if sysmon_docs else "No Sysmon context found."
        
        # 3. Construct Prompt
        prompt_text = f"""
        Your goal is to be a helpful assistant.
        
        1. **Classification**: First, determine if the user is asking for a Sigma Rule or analysis, or if they are just greeting/chatting (e.g., "Hello", "How are you").
        
        2. **Action**:
           - IF GREETING/CHAT: Respond naturally and briefly. Offer your help with Sigma rules. DO NOT generate a YAML block.
           - IF REQUEST/ATTACK: Create a valid Sigma Rule to detect the attack described.
        
        ### Conversation History
        {history_text}
        
        ### User Input (Latest)
        {attack_description}

        ### External Context (from URLs if any)
        {url_context}
        
        ### Knowledge Base Context (for rule generation)
        **Similar Rules:** {sigma_context}
        **MITRE:** {mitre_context}
        **Sysmon:** {sysmon_context}
        
        ### Instructions (For Rule Generation)
        If the user wants a rule:
        1. Analyze the attack and context.
        2. Write a complete Sigma Rule in YAML format.
        3. Explain your logic briefly.
        
        ### Output Format
        If generating a rule, use this format:
        ```yaml
        # Sigma Rule YAML here
        ```
        **Explanation:** ...

        If chatting, just output text.
        """
        
        # 4. Generate with Gemini (New SDK)
        print(f"Generating response with {self.model_name}...")
        
        contents = [prompt_text]
        
        # Handle Media
        if media_file:
            print(f"Uploading media: {media_file['path']}")
            try:
                # Use genai to upload file
                # The SDK usually takes 'file' object or bytes
                # client.files.upload usually returns a file ref
                # But for generate_content we can pass parts. 
                # Let's read file bytes for simplicity for images
                
                with open(media_file['path'], "rb") as f:
                    file_data = f.read()
                
                from google.genai import types
                
                # Create Part object
                part = types.Part.from_bytes(data=file_data, mime_type=media_file['mime'])
                contents.append(part)
                
            except Exception as e:
                print(f"Error handling media: {e}")
        
        # Retry logic for 429 errors
        retry_count = 0
        max_retries = 3
        
        while retry_count <= max_retries:
            try:
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=contents
                )
                print("Response generated.")
                
                return {
                    "rule": response.text,
                    "context": {
                        "sigma": sigma_docs,
                        "mitre": mitre_docs,
                        "sysmon": sysmon_docs
                    }
                }
            except Exception as e:
                err_str = str(e)
                if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
                    wait_time = (2 ** retry_count) * 2 # 2, 4, 8, 16
                    print(f"Rate limit hit (429). Retrying in {wait_time}s... (Attempt {retry_count+1}/{max_retries})")
                    time.sleep(wait_time)
                    retry_count += 1
                    if retry_count > max_retries:
                        print(f"Max retries reached. Error: {e}")
                        return {
                            "rule": f"Error: High traffic (Rate Limit). Please try again in a minute.",
                            "context": {}
                        }
                else:
                    print(f"Error Generating Content: {e}")
                    return {
                        "rule": f"Error generation content: {e}",
                        "context": {}
                    }

if __name__ == "__main__":
    # Quick Test
    agent = SigmaAgent()
    print(agent.analyze_attack("Attackers are using mimikatz to dump credentials"))
