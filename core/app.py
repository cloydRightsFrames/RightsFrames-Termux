from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import rf_core

app = FastAPI(title="RightsFrames Core")
rf_core.init_db()

class Entry(BaseModel):
    entry_type: str
    payload: dict

@app.post("/entries")
def create_entry(e: Entry):
    new_id, h = rf_core.append_entry(e.entry_type, e.payload)
    return {"id": new_id, "entry_hash": h}

@app.get("/verify")
def verify():
    ok, msg = rf_core.verify_chain()
    ok2, msg2 = rf_core.verify_anchors()
    return {"chain_valid": ok, "chain_message": msg, "anchors_valid": ok2, "anchors_message": msg2}

@app.post("/anchor")
def anchor():
    ok, msg = rf_core.create_anchor()
    if not ok: raise HTTPException(400, msg)
    return {"message": msg}

@app.get("/health")
def health():
    return {"status": "ok"}
