from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import rf_core
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.cors import CORSMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
        response.headers.setdefault("X-DNS-Prefetch-Control", "off")
        response.headers.setdefault("X-Download-Options", "noopen")
        return response

app = FastAPI(title="RightsFrames Core")
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[
        "localhost",
        "127.0.0.1",
        "api.rightsframes.online",
        "rightsframes.online",
        "www.rightsframes.online",
    ],
)
app.add_middleware(GZipMiddleware, minimum_size=1024)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://rightsframes.online",
        "https://www.rightsframes.online",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

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
