import json
import os
import uuid
from datetime import datetime
from typing import List, Dict, Optional

RULES_FILE = "data/saved_rules.json"

def _load_rules() -> List[Dict]:
    if not os.path.exists(RULES_FILE):
        return []
    try:
        with open(RULES_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

def _save_rules(rules: List[Dict]):
    # Ensure directory exists
    os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)

def get_all_rules() -> List[Dict]:
    return _load_rules()

def get_rule(rule_id: str) -> Optional[Dict]:
    rules = _load_rules()
    for r in rules:
        if r["id"] == rule_id:
            return r
    return None

def create_rule(content: str, title: str = "Untitled Rule") -> Dict:
    rules = _load_rules()
    
    # Try to extract title from content if not provided or default
    if title == "Untitled Rule":
        for line in content.splitlines():
            if line.strip().startswith("title:"):
                title = line.split(":", 1)[1].strip()
                break

    new_rule = {
        "id": str(uuid.uuid4()),
        "title": title,
        "content": content,
        "created_at": datetime.now().isoformat()
    }
    
    rules.append(new_rule)
    _save_rules(rules)
    return new_rule

def update_rule(rule_id: str, content: str, title: Optional[str] = None) -> Optional[Dict]:
    rules = _load_rules()
    for r in rules:
        if r["id"] == rule_id:
            r["content"] = content
            if title:
                r["title"] = title
            # extract title again if changed in content? 
            # Let's trust the FE or explicit title for now, 
            # but maybe re-parsing title from content is good practice in backend too.
            for line in content.splitlines():
                if line.strip().startswith("title:"):
                    r["title"] = line.split(":", 1)[1].strip()
                    break
            
            r["updated_at"] = datetime.now().isoformat()
            _save_rules(rules)
            return r
    return None

def delete_rule(rule_id: str) -> bool:
    rules = _load_rules()
    initial_len = len(rules)
    rules = [r for r in rules if r["id"] != rule_id]
    if len(rules) < initial_len:
        _save_rules(rules)
        return True
    return False
