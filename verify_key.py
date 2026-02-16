import os
from dotenv import load_dotenv
from google import genai
import sys

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    print("Error: GEMINI_API_KEY not found.")
    sys.exit(1)

model_name = "models/gemini-embedding-001"

try:
    client = genai.Client(api_key=api_key)
    print(f"Testing {model_name}...")
    try:
         response = client.models.embed_content(
            model=model_name,
            contents="Test",
        )
         print(f"Success. Dimension: {len(response.embeddings[0].values)}")
    except Exception as e:
        print(f"Failed: {e}")

except Exception as e:
    print(f"Error: {e}")
