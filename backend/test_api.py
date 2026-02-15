import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

def test_api():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY not found")
        return

    client = genai.Client(api_key=api_key)
    
    # Try the most basic model
    try:
        response = client.models.generate_content(
            model='gemini-2.0-flash', 
            contents="Hello, can you hear me?"
        )
        print(f"Response: {response.text}")
        print("API Connection Successful!")
    except Exception as e:
        print(f"API Connection Failed: {e}")

if __name__ == "__main__":
    test_api()
