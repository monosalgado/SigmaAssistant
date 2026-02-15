import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

def find_working_model():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("No API Key found")
        return

    client = genai.Client(api_key=api_key)
    
    print("Fetching available models...")
    try:
        all_models = list(client.models.list())
    except Exception as e:
        print(f"Error listing models: {e}")
        return

    # Filter loosely since new SDK objects distinct
    candidates = [m for m in all_models if "gemini" in m.name]
    
    print(f"Found {len(candidates)} candidate models.")
    
    working_model = None
    
    for m in candidates:
        name = m.name
        # Strip "models/" if present for generating content sometimes
        clean_name = name.replace("models/", "")
        
        print(f"\nTesting: {name}")
        try:
            response = client.models.generate_content(
                model=clean_name,
                contents="Hi"
            )
            print(f"WORKS! Response: {response.text}")
            working_model = name
            break # Found one!
        except Exception as e:
            err_str = str(e)
            if "429" in err_str:
                print(f"Rate Limit (429) on {name}")
            elif "404" in err_str:
                print(f"Not Found (404) on {name}")
            else:
                print(f"Error on {name}: {err_str[:100]}...")

    if working_model:
        print(f"\nRecommendation: Use '{working_model}'")
    else:
        print("\nNo working model found in the list.")

if __name__ == "__main__":
    find_working_model()
