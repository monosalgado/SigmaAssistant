from google import genai
import os
from dotenv import load_dotenv

load_dotenv()

def test_new_sdk():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("No API Key found")
        return

    print("Initializing new genai.Client()...")
    client = genai.Client(api_key=api_key)

    model_name = "gemini-2.0-flash-exp"
    print(f"Testing generation with {model_name}...")
    
    try:
        response = client.models.generate_content(
            model=model_name, 
            contents="Explain how AI works in a few words"
        )
        print(f"✅ WORKS! Response: {response.text}")
    except Exception as e:
        print(f"❌ FAILED: {e}")

if __name__ == "__main__":
    test_new_sdk()
