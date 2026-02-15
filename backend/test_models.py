import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

def test_models():
    api_key = os.getenv("GEMINI_API_KEY")
    client = genai.Client(api_key=api_key)
    
    print("Listing available models...")
    for m in client.models.list():
        print(m.name)

    print("\nTesting Generation...")
    try:
        response = client.models.generate_content(
            model='gemini-2.0-flash',
            contents="Hello"
        )
        print(f"gemini-2.0-flash: {response.text}")
    except Exception as e:
        print(f"gemini-2.0-flash failed: {e}")

    try:
        response = client.models.generate_content(
            model='gemini-1.5-flash',
            contents="Hello"
        )
        print(f"gemini-1.5-flash: {response.text}")
    except Exception as e:
        print(f"gemini-1.5-flash failed: {e}")

if __name__ == "__main__":
    test_models()
