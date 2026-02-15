from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from backend.agent import SigmaAgent
import uvicorn
import os
import uuid
from typing import List, Dict, Optional
import json

SESSIONS_FILE = "data/sessions.json"

app = FastAPI(title="Sigma Assistant API")

# Mount static files
# We mount it at /static or just serve index at root?
# Let's serve index at / and assets at /
app.mount("/static", StaticFiles(directory="frontend"), name="static")

# In-Memory Session Store
# Format: { "session_id": [ { "role": "user", "content": "..." }, ... ] }
sessions: Dict[str, List[Dict]] = {}

def load_sessions():
    global sessions
    if os.path.exists(SESSIONS_FILE):
        try:
            with open(SESSIONS_FILE, "r") as f:
                sessions = json.load(f)
            print(f"Loaded {len(sessions)} sessions.")
        except Exception as e:
            print(f"Failed to load sessions: {e}")

def save_sessions():
    try:
        with open(SESSIONS_FILE, "w") as f:
            json.dump(sessions, f, indent=2)
    except Exception as e:
        print(f"Failed to save sessions: {e}")

# Load on startup
load_sessions()

# Initialize Agent
try:
    agent = SigmaAgent()
    print("Sigma Agent Initialized")
except Exception as e:
    print(f"Failed to initialize Agent: {e}")
    agent = None

class AttackRequest(BaseModel):
    description: str
    session_id: Optional[str] = None

class Session(BaseModel):
    id: str
    amount: int
    preview: str

@app.get("/")
def read_root():
    return FileResponse('frontend/index.html')

@app.get("/style.css")
def style():
    return FileResponse('frontend/style.css')

@app.get("/script.js")
def script():
    return FileResponse('frontend/script.js')

# --- Session Management ---

@app.get("/sessions")
def get_sessions():
    """List all sessions with a preview."""
    result = []
    for sid, msgs in sessions.items():
        preview = "Empty Chat"
        if msgs:
            # Find first user message
            for m in msgs:
                if m['role'] == 'user':
                    preview = m['content'][:30] + "..."
                    break
        result.append({"id": sid, "amount": len(msgs), "preview": preview})
    return result

@app.post("/sessions")
def create_session():
    """Create a new empty session."""
    session_id = str(uuid.uuid4())
    sessions[session_id] = []
    # Send initial greeting
    sessions[session_id].append({
        "role": "assistant", 
        "content": "Hello! I am your Sigma Rule Assistant. Describe an attack technique, and I will help you create a detection rule."
    })
    save_sessions()
    return {"id": session_id}

@app.delete("/sessions/{session_id}")
def delete_session(session_id: str):
    if session_id in sessions:
        del sessions[session_id]
        save_sessions()
        return {"success": True}
    raise HTTPException(status_code=404, detail="Session not found")

@app.get("/sessions/{session_id}")
def get_session_history(session_id: str):
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    return sessions[session_id]

@app.post("/analyze")
def analyze_attack(request: AttackRequest):
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")
    
    session_id = request.session_id
    if not session_id or session_id not in sessions:
        # Auto-create if not exists or provided
        session_id = str(uuid.uuid4())
        sessions[session_id] = []
    
    # Save User Message
    sessions[session_id].append({"role": "user", "content": request.description})
    save_sessions()
    
    try:
        # Pass history (excluding the message we just added)
        history = sessions[session_id][:-1]
        response_data = agent.analyze_attack(request.description, history=history)
        
        # Save AI Response
        sessions[session_id].append({
            "role": "assistant", 
            "content": response_data["rule"],
            "context": response_data["context"]
        })
        save_sessions()
        
        # wrapper to include current session_id if it was new
        response_data["session_id"] = session_id
        
        return response_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze_multimodal")
async def analyze_multimodal(
    description: str = Form(...),
    session_id: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None)
):
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    if not session_id or session_id not in sessions:
        session_id = str(uuid.uuid4())
        sessions[session_id] = []

    # Handle File
    media_info = None
    user_msg_content = description
    
    if file:
        file_path = f"uploads/{session_id}_{file.filename}"
        with open(file_path, "wb") as buffer:
            buffer.write(await file.read())
        
        media_info = {"path": file_path, "mime": file.content_type}
        user_msg_content += f"\n[Attached: {file.filename}]"

    # Save User Message
    sessions[session_id].append({"role": "user", "content": user_msg_content})
    save_sessions()

    try:
        # Pass history (excluding current)
        history = sessions[session_id][:-1] 
        response_data = agent.analyze_attack(description, history=history, media_file=media_info)
        
        # Save AI Response
        sessions[session_id].append({
            "role": "assistant", 
            "content": response_data["rule"],
            "context": response_data["context"]
        })
        save_sessions()
        
        response_data["session_id"] = session_id
        return response_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
    # Cleanup file? For now keep it or clean it up later.

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
