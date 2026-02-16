import requests
import unittest
import json

BASE_URL = "http://localhost:8000"

class TestSavedRulesAPI(unittest.TestCase):
    def test_workflow(self):
        # 1. Create Rule
        print("Testing Create Rule...")
        content = "title: Test Rule\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image: 'test.exe'\n    condition: selection"
        res = requests.post(f"{BASE_URL}/rules", json={"content": content, "title": "My API Test Rule"})
        self.assertEqual(res.status_code, 200)
        rule = res.json()
        self.assertEqual(rule["title"], "My API Test Rule")
        rule_id = rule["id"]
        print(f"Created rule {rule_id}")

        # 2. Get Rules
        print("Testing Get Rules...")
        res = requests.get(f"{BASE_URL}/rules")
        self.assertEqual(res.status_code, 200)
        rules = res.json()
        self.assertTrue(any(r["id"] == rule_id for r in rules))
        print(f"Found {len(rules)} rules")

        # 3. Update Rule
        print("Testing Update Rule...")
        # Ensure content title matches our expectation or vice-versa
        new_content = content.replace("Test Rule", "Updated Title") 
        res = requests.put(f"{BASE_URL}/rules/{rule_id}", json={"content": new_content, "title": "Updated Title"})
        self.assertEqual(res.status_code, 200)
        updated_rule = res.json()
        self.assertEqual(updated_rule["title"], "Updated Title")
        
        # 4. Translate Rule
        print("Testing Translate Rule...")
        res = requests.post(f"{BASE_URL}/translate", json={"rule": new_content, "target": "leql"})
        self.assertEqual(res.status_code, 200)
        translation = res.json()
        print(f"Translation: {translation}")
        self.assertIn("query", translation)
        self.assertTrue(len(translation["query"]) > 0)

        # 5. Delete Rule
        print("Testing Delete Rule...")
        res = requests.delete(f"{BASE_URL}/rules/{rule_id}")
        self.assertEqual(res.status_code, 200)
        
        # Verify deletion
        res = requests.get(f"{BASE_URL}/rules")
        rules = res.json()
        self.assertFalse(any(r["id"] == rule_id for r in rules))
        print("Rule deleted successfully.")

if __name__ == "__main__":
    unittest.main()
