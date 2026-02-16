import requests
import json

url = "http://localhost:8000/analyze"
payload = {
    "description": "Attackers are using powershell to download payload",
    "session_id": "test_session"
}

try:
    print(f"Sending request to {url}...")
    response = requests.post(url, json=payload)
    
    if response.status_code == 200:
        print("Success! Response received.")
        data = response.json()
        print("Rule generated:")
        print(data.get("rule")[:100] + "...")
    else:
        print(f"Failed with status {response.status_code}")
        print(response.text)

except Exception as e:
    print(f"Error: {e}")
