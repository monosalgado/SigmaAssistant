import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

def check():
    api_key = os.getenv("GEMINI_API_KEY")
    client = genai.Client(api_key=api_key)
    
    print("Checking model capabilities...")
    for m in client.models.list():
        print(f"Model: {m.name}")
        # supported_generation_methods might differ in new SDK model object
        # usually checks m.supported_actions if available or just name
        print("-" * 20)
        print("-" * 20)
        
if __name__ == "__main__":
    check()
