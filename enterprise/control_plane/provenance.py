from __future__ import annotations
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATEMENT="https://in-toto.io/Statement/v1"

def sha256_file(path: str | Path) -> str:
    digest=hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda:fh.read(1024*1024),b""): digest.update(chunk)
    return digest.hexdigest()

def git_identity() -> dict[str,str]:
    def run(arg:str)->str: return subprocess.check_output(["git","rev-parse",arg],text=True).strip()
    return {"commit":run("HEAD"),"tree":run("HEAD^{tree}")}

def _repo()->str:
    try:
        return subprocess.check_output(["git","config","--get","remote.origin.url"],text=True).strip().removesuffix(".git").split("github.com/")[-1]
    except Exception:
        return "unknown/unknown"

def statement(subjects:list[dict[str,Any]],builder:str,invocation:dict[str,Any]|None=None)->dict[str,Any]:
    identity=git_identity()
    return {"_type":STATEMENT,"subject":subjects,"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"https://rightsframes.online/build-types/enterprise-control-plane/v1","externalParameters":invocation or {},"internalParameters":{},"resolvedDependencies":[{"uri":f"git+https://github.com/{_repo()}@{identity['commit']}","digest":{"sha1":identity["commit"]}}]},"runDetails":{"builder":{"id":builder},"metadata":{"invocationId":identity["commit"],"startedOn":datetime.now(timezone.utc).isoformat()}}}}

def write_statement(path:str|Path,artifact:str|Path,builder:str,invocation:dict[str,Any]|None=None)->dict[str,Any]:
    p=Path(artifact)
    doc=statement([{"name":p.name,"digest":{"sha256":sha256_file(p)}}],builder,invocation)
    Path(path).write_text(json.dumps(doc,sort_keys=True,indent=2)+"\\n",encoding="utf-8")
    return doc
