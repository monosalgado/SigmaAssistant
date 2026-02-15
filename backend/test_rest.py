import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

def test_rest():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("API Key not found")
        return

    # List models
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    
    print(f"Sending request to {url}...")
    try:
        response = requests.get(url)
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            models = response.json().get('models', [])
            print(f"Found {len(models)} models.")
            for m in models:
                if 'generateContent' in m.get('supportedGenerationMethods', []):
                    print(f"Name: {m['name']}")
        else:
            print("Error:", response.text)
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    test_rest()
