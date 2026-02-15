import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

def debug_models():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("No API Key found")
        return

    client = genai.Client(api_key=api_key)
    
    candidates = [
        "gemini-1.5-flash",
        "gemini-1.5-flash-latest",
        "gemini-1.5-flash-001",
        "gemini-pro",
        "gemini-1.0-pro"
        # Removed "models/" prefix duplicates as client handles them usually
    ]
    
    print("Testing candidate models...")
    for model_name in candidates:
        print(f"\nTesting: {model_name}")
        try:
            response = client.models.generate_content(
                model=model_name,
                contents="Test"
            )
            print(f"SUCCESS: {model_name}")
            return # Stop finding after first success
        except Exception as e:
            print(f"FAILED: {model_name}")
            # print(f"Error: {e}") # Keep it clean

if __name__ == "__main__":
    debug_models()
