from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from backend.agent import SigmaAgent
from backend.tunnel import tunnel_manager
import uvicorn
import os
import re
import uuid
from typing import List, Dict, Optional
import json

# New Imports for Rules & Translation
import backend.saved_rules as saved_rules
import backend.review_sessions as review_sessions
from backend.rule_check import check_rule
from backend.pipeline.analyst_review import ReviewError, logsource_choices
from backend.pipeline.orchestrator import LOGSOURCE_TABLE
from backend.translation import LLMTranslator
from sigma.collection import SigmaCollection
from sigma.backends.insight_idr import InsightIDRBackend

SESSIONS_FILE = "data/sessions.json"

# Upload constraints
UPLOAD_DIR = "uploads"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
ALLOWED_UPLOAD_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "application/pdf",
}

app = FastAPI(title="Sigma Assistant API")

# CORS — restrict to configured origins. Defaults to local-only access.
# Override with ALLOWED_ORIGINS (comma-separated) when hosting elsewhere.
_origins_env = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000")
ALLOWED_ORIGINS = [o.strip() for o in _origins_env.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


def _safe_upload_path(session_id: str, filename: Optional[str]) -> str:
    """Build a sanitized upload path, preventing path traversal."""
    base = os.path.basename(filename or "upload")
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:100] or "upload"
    return os.path.join(UPLOAD_DIR, f"{session_id}_{uuid.uuid4().hex}_{base}")


# Mount static files
app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.on_event("startup")
async def startup_event():
    """Open SSH tunnel to Spark on app start (only if ECONOMY_PROVIDER=ollama)."""
    tunnel_manager.start()


@app.on_event("shutdown")
async def shutdown_event():
    """Close SSH tunnel cleanly when app stops."""
    tunnel_manager.stop()

# In-Memory Session Store
sessions: Dict[str, List[Dict]] = {}

def load_sessions():
    global sessions
    if os.path.exists(SESSIONS_FILE):
        try:
            with open(SESSIONS_FILE, "r") as f:
                sessions = json.load(f)
            review_sessions.reset_interrupted(sessions)
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

# Initialize LLM Translator
try:
    translator = LLMTranslator(agent.client, agent.model_name) if agent else None
    if translator:
        print("LLM Translator Initialized")
except Exception as e:
    print(f"Failed to initialize Translator: {e}")
    translator = None

class AttackRequest(BaseModel):
    description: str
    session_id: Optional[str] = None
    feedback_data: Optional[Dict] = None  # User corrections from feedback loop
    review: bool = False  # stop after the analysis for the analyst's review

class GenerateRequest(BaseModel):
    session_id: str
    analysis_id: str
    review: Dict = Field(default_factory=dict)  # see backend/pipeline/analyst_review.py

class RuleCreateRequest(BaseModel):
    content: str
    title: Optional[str] = "Untitled Rule"

class RuleUpdateRequest(BaseModel):
    content: str
    title: Optional[str] = None

class RuleCheckRequest(BaseModel):
    content: str

class TranslateRequest(BaseModel):
    rule: str
    target: str = "leql"

@app.get("/")
def read_root():
    # Never a stale page: the assets are versioned, the page itself is not.
    return FileResponse('frontend/index.html', headers={"Cache-Control": "no-cache"})

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
        "content": "Paste the URL of a threat report, or describe an attack. The pipeline reads the source and identifies the attack vector, the log source where it would be visible and the ATT&CK techniques, then stops so you can confirm or correct what it understood before it writes the Sigma rules."
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
    return review_sessions.public_messages(sessions[session_id])

@app.get("/logsource_choices")
def get_logsource_choices():
    """Every log source in SigmaHQ's rules, for the analyst to choose from."""
    return logsource_choices(LOGSOURCE_TABLE)

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
            "context": response_data["context"],
            "pipeline_metadata": response_data.get("pipeline_metadata"),
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
        if file.content_type not in ALLOWED_UPLOAD_TYPES:
            raise HTTPException(
                status_code=415,
                detail=f"Unsupported file type: {file.content_type}. Allowed: images and PDF.",
            )
        contents = await file.read()
        if len(contents) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File too large (max 10 MB).")

        os.makedirs(UPLOAD_DIR, exist_ok=True)
        file_path = _safe_upload_path(session_id, file.filename)
        with open(file_path, "wb") as buffer:
            buffer.write(contents)

        media_info = {"path": file_path, "mime": file.content_type}
        user_msg_content += f"\n[Attached: {os.path.basename(file.filename or 'file')}]"

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
            "context": response_data["context"],
            "pipeline_metadata": response_data.get("pipeline_metadata"),
        })
        save_sessions()

        response_data["session_id"] = session_id
        return response_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
    # Cleanup file? For now keep it or clean it up later.

# --- Streaming Pipeline Endpoint (SSE) ---

@app.post("/analyze_stream")
def analyze_stream(request: AttackRequest):
    """Stream pipeline progress via Server-Sent Events."""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    session_id = request.session_id
    if not session_id or session_id not in sessions:
        session_id = str(uuid.uuid4())
        sessions[session_id] = []

    # Save User Message
    sessions[session_id].append({"role": "user", "content": request.description})
    save_sessions()

    history = sessions[session_id][:-1]
    if not request.review and not request.feedback_data:
        # Change 46 (user, 2026-10-07): the rules first; the analysis is saved for the analyst's corrections.
        return _first_pass_response(session_id, history, request.description)
    if request.review:
        events = _guarded(agent.orchestrator.analyse_for_review(request.description, history=history))
    else:
        events = agent.analyze_attack_stream(request.description, history=history, feedback_data=request.feedback_data)

    def event_generator():
        final_data = None
        for event in events:
            event_type = event.get("event", "stage")
            data = event.get("data", {})

            if event_type == "checkpoint":
                # The analysis waits in the session for the analyst's review.
                final_data = data
                analysis_id = str(uuid.uuid4())
                sessions[session_id].append(review_sessions.checkpoint_message(analysis_id, data))
                save_sessions()
                event_type = "review"
                data = {
                    "analysis_id": analysis_id,
                    "session_id": session_id,
                    "content": review_sessions.READY_TEXT,
                    "pipeline_metadata": data["pipeline_metadata"],
                    "context": data["context"],
                }

            if event_type == "result":
                final_data = data
                # Save AI response to session (including pipeline_metadata for context panel persistence)
                sessions[session_id].append({
                    "role": "assistant",
                    "content": data.get("rule", ""),
                    "context": data.get("context", {}),
                    "pipeline_metadata": data.get("pipeline_metadata"),
                })
                save_sessions()
                data["session_id"] = session_id

            yield f"event: {event_type}\ndata: {json.dumps(data)}\n\n"

        if final_data is None:
            # Ensure we always send a result event
            error_data = {
                "rule": "Pipeline completed without generating a result.",
                "context": {"sigma": [], "mitre": [], "sysmon": []},
                "pipeline_metadata": None,
                "session_id": session_id,
            }
            sessions[session_id].append({
                "role": "assistant",
                "content": error_data["rule"],
                "context": error_data["context"],
            })
            save_sessions()
            yield f"event: result\ndata: {json.dumps(error_data)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

def _first_pass_response(session_id: str, history: list, description: str):
    """The rules first (Change 46): progress events, then version 1 with the saved analysis's id."""
    messages = sessions[session_id]
    events = _guarded(agent.orchestrator.analyse_then_generate(description, history=history))

    def event_generator():
        sent_result = False
        for event_type, data in review_sessions.first_pass_events(messages, events, str(uuid.uuid4())):
            if event_type == "result":
                sent_result = True
                data["session_id"] = session_id
            save_sessions()
            yield f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
        if not sent_result:
            error_data = {"rule": "Pipeline completed without generating a result.",
                          "context": {"sigma": [], "mitre": [], "sysmon": []}, "pipeline_metadata": None,
                          "session_id": session_id}
            messages.append({"role": "assistant", "content": error_data["rule"], "context": error_data["context"]})
            save_sessions()
            yield f"event: result\ndata: {json.dumps(error_data)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})


def _guarded(events):
    """A pipeline error becomes a result event, as in SigmaAgent.analyze_attack_stream."""
    try:
        yield from events
    except Exception as e:
        print(f"Pipeline stream error: {e}")
        yield {"event": "result", "data": {
            "rule": f"Error during analysis: {e}",
            "context": {"sigma": [], "mitre": [], "sysmon": []},
            "pipeline_metadata": None,
        }}


@app.post("/generate_stream")
def generate_stream(request: GenerateRequest):
    """Generate rules from a saved analysis and the analyst's review, streamed via SSE."""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")
    messages = sessions.get(request.session_id)
    if messages is None:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        state, history = review_sessions.start_generation(messages, request.analysis_id)
    except review_sessions.AnalysisNotFound:
        raise HTTPException(status_code=404, detail="Analysis not found")
    except review_sessions.AnalysisNotAwaiting as e:
        raise HTTPException(status_code=409, detail=str(e))
    try:
        events = agent.orchestrator.generate_after_review(state, request.review, history=history)
    except ReviewError as e:
        review_sessions.abandon_generation(messages, request.analysis_id)
        raise HTTPException(status_code=400, detail=str(e))
    save_sessions()

    def event_generator():
        finished = False
        try:
            for event in events:
                event_type = event.get("event", "stage")
                data = event.get("data", {})
                if event_type == "result":
                    data["version"] = review_sessions.finish_generation(messages, request.analysis_id, data)
                    data["analysis_id"] = request.analysis_id
                    data["analysis_metadata"] = review_sessions.saved_analysis_metadata(messages, request.analysis_id)
                    data["corrections"] = messages[-1]["corrections"]
                    save_sessions()
                    finished = True
                    data["session_id"] = request.session_id
                yield f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
        except Exception as e:
            print(f"Generation stream error: {e}")
            error_data = {
                "rule": f"Error during generation: {e}. The analysis is kept - generate again to retry.",
                "context": {"sigma": [], "mitre": [], "sysmon": []},
                "pipeline_metadata": None,
                "session_id": request.session_id,
                "retry_analysis_id": request.analysis_id,
            }
            yield f"event: result\ndata: {json.dumps(error_data)}\n\n"
        finally:
            if not finished:
                review_sessions.abandon_generation(messages, request.analysis_id)
                save_sessions()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

# --- Saved Rules Management ---

@app.get("/rules")
def get_rules():
    return saved_rules.get_all_rules()

@app.post("/rules")
def create_rule(req: RuleCreateRequest):
    # Change 47: saved as the analyst wrote it, with the same check the editor shows
    return dict(saved_rules.create_rule(req.content, req.title), check=check_rule(req.content))

@app.put("/rules/{rule_id}")
def update_rule(rule_id: str, req: RuleUpdateRequest):
    rule = saved_rules.update_rule(rule_id, req.content, req.title)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return dict(rule, check=check_rule(req.content))

@app.post("/validate_rule")
def validate_rule(req: RuleCheckRequest):
    """Change 47: the edited rule checked as the analyst types - pySigma and SigmaHQ's log sources, no model."""
    return check_rule(req.content)

@app.delete("/rules/{rule_id}")
def delete_rule(rule_id: str):
    if saved_rules.delete_rule(rule_id):
        return {"success": True}
    raise HTTPException(status_code=404, detail="Rule not found")

@app.post("/translate")
def translate_rule(req: TranslateRequest):
    if not translator:
        raise HTTPException(status_code=500, detail="Translator not initialized")
    try:
        result = translator.translate(req.rule, target=req.target)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        print(f"Translation error: {e}")
        raise HTTPException(status_code=500, detail=f"Translation failed: {e}")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
