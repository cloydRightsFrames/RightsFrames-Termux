from __future__ import annotations
import json, os, urllib.error, urllib.request
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
router = APIRouter(tags=["UnifiedAIHub"])
def _is_within_root(target: Path, root: Path) -> bool:
    try:
        target.relative_to(root)
        return True
    except ValueError:
        return False
def _config():
    base=os.environ.get("UNIFIEDAIHUB_BASE_URL","http://127.0.0.1:8766").rstrip("/")
    if not base.startswith("http://127.0.0.1:") and not base.startswith("http://localhost:") and not base.startswith("https://"):
        raise HTTPException(503,"UnifiedAIHub endpoint must use loopback HTTP or explicitly configured HTTPS")
    token=os.environ.get("UNIFIEDAIHUB_API_TOKEN","")
    if not token: raise HTTPException(503,"UnifiedAIHub service credential is not configured")
    return base,token
def _request(path,method="GET",payload=None):
    base,token=_config()
    body=None if payload is None else json.dumps(payload).encode("utf-8")
    req=urllib.request.Request(base+path,data=body,method=method,headers={"Authorization":"Bearer "+token,"Accept":"application/json","Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req,timeout=8) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- URL validated by _config() (loopback HTTP or HTTPS only)
            raw=response.read(2*1024*1024+1)
            if len(raw)>2*1024*1024: raise HTTPException(502,"UnifiedAIHub response exceeded limit")
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code in (401,403): raise HTTPException(502,"UnifiedAIHub service authentication or authorization failed") from None
        if e.code==404: raise HTTPException(404,"UnifiedAIHub resource not found") from None
        raise HTTPException(502,"UnifiedAIHub request failed with HTTP "+str(e.code)) from None
    except (urllib.error.URLError,TimeoutError,OSError,ValueError) as e:
        raise HTTPException(503,"UnifiedAIHub unavailable or returned invalid JSON") from None
class SearchInput(BaseModel):
    query: str = Field(min_length=1,max_length=2000)
    limit: int = Field(default=10,ge=1,le=50)
class IngestInput(BaseModel):
    path: str = Field(min_length=1,max_length=4096)
@router.get("/unified-ai-hub/health")
def hub_health():
    data=_request("/health")
    if data.get("ok") is not True: raise HTTPException(502,"UnifiedAIHub health check failed")
    return {"ok":True,"service":"charlie2-unified-ai-hub-adapter","upstream":data}
@router.post("/unified-ai-hub/search")
def hub_search(req: SearchInput):
    result=_request("/v1/search","POST",{"query":req.query,"limit":req.limit})
    if not isinstance(result.get("results"),list): raise HTTPException(502,"Invalid search response schema")
    return {"results":result["results"],"count":len(result["results"])}
@router.post("/unified-ai-hub/ingest")
def hub_ingest(req: IngestInput):
    configured=os.environ.get("UNIFIEDAIHUB_ALLOWED_INGEST_ROOTS","")
    roots=[Path(x).expanduser().resolve() for x in configured.split(os.pathsep) if x.strip()]
    if not roots: raise HTTPException(403,"Ingestion disabled: configure approved UNIFIEDAIHUB_ALLOWED_INGEST_ROOTS")
    norm=os.path.normpath(os.path.expanduser(req.path))
    matched=None
    for r in roots:
        rs=str(r)
        full=os.path.normpath(os.path.join(rs,norm))
        if full.startswith(rs+os.sep):
            matched=full
            break
    if matched is None: raise HTTPException(403,"Path is not an approved ingestion file")
    try: target=Path(os.path.realpath(matched)).resolve(strict=True)
    except (OSError,RuntimeError): raise HTTPException(400,"Invalid ingestion path") from None
    if not target.is_file() or not any(_is_within_root(target, r) for r in roots): raise HTTPException(403,"Path is not an approved ingestion file")
    if target.suffix.lower() not in {".json",".txt",".md",".log",".csv",".xml",".html"}: raise HTTPException(415,"Unsupported ingestion file type")
    if target.stat().st_size>25*1024*1024: raise HTTPException(413,"File exceeds 25 MiB ingestion limit")
    return _request("/v1/ingest","POST",{"path":str(target)})
