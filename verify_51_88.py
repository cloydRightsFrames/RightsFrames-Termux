#!/usr/bin/env python3
from pathlib import Path
import subprocess, sys, os, json, hashlib, tarfile, time, tempfile, traceback

R=Path.cwd().resolve()
START,END=51,88
HEAD=subprocess.check_output(["git","rev-parse","HEAD"],cwd=R,text=True).strip()
ALL=subprocess.check_output(["git","rev-list","--reverse","--all"],cwd=R,text=True).splitlines()
SEL=ALL[START-1:END]
OUT=R/"artifacts"/f"enterprise-historical-{START}-{END}-{time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())}-{HEAD}"
OUT.mkdir(parents=True,exist_ok=False)

def run(c,cwd,t=180,env=None):
    try:
        x=subprocess.run(c,cwd=cwd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                         timeout=t,check=False,env=env)
        return x.returncode,x.stdout,x.stderr,False
    except subprocess.TimeoutExpired as e:
        a=e.stdout or ""; b=e.stderr or ""
        if isinstance(a,bytes): a=a.decode(errors="replace")
        if isinstance(b,bytes): b=b.decode(errors="replace")
        return None,a,b,True

def extract(sha,d):
    arc=d/"commit.tar.gz"
    rc,so,se,to=run(["git","archive","--format=tar.gz","--output",str(arc),sha],R,120)
    if rc!=0: raise RuntimeError(se or so)
    src=d/"source"; src.mkdir()
    root=src.resolve()
    with tarfile.open(arc,"r:gz") as tf:
        for m in tf.getmembers():
            q=(src/m.name).resolve()
            q.relative_to(root)
            if m.issym() or m.islnk(): raise RuntimeError("historical archive link rejected")
        tf.extractall(src,filter="data")
    return src

def deps(src):
    return [src/x for x in (
        "pyproject.toml","requirements.txt","requirements-dev.txt",
        "requirements-test.txt","Pipfile","Pipfile.lock",
        "poetry.lock","uv.lock","setup.py","setup.cfg"
    ) if (src/x).is_file()]

def files(src):
    return [x for x in src.rglob("*.py") if ".git" not in x.parts and "__pycache__" not in x.parts]

def digest(src):
    h=hashlib.sha256()
    for x in sorted(files(src)):
        h.update(str(x.relative_to(src)).encode())
        h.update(hashlib.sha256(x.read_bytes()).digest())
    return h.hexdigest()

def install(v,src,df):
    py=v/"bin/python"
    if not py.exists(): py=v/"Scripts/python.exe"
    if not py.exists(): raise RuntimeError("isolated Python executable missing")
    rc,so,se,to=run([str(py),"-m","pip","--version"],src,30)
    if rc!=0: return py,False,"PIP_UNAVAILABLE",so,se
    lock=[x for x in df if x.name in ("Pipfile.lock","poetry.lock","uv.lock")]
    req=[x for x in df if x.name.startswith("requirements")]
    if req:
        for f in sorted(req):
            rc,so,se,to=run([str(py),"-m","pip","install","--disable-pip-version-check","--no-input","-r",str(f)],src,600)
            if rc!=0: return py,False,"DEPENDENCY_REPRODUCTION_FAILED",so,se
    elif (src/"pyproject.toml").is_file() or (src/"setup.py").is_file() or (src/"setup.cfg").is_file():
        rc,so,se,to=run([str(py),"-m","pip","install","--disable-pip-version-check","--no-input","."],src,600)
        if rc!=0: return py,False,"DEPENDENCY_REPRODUCTION_FAILED",so,se
    elif lock:
        return py,False,"DEPENDENCY_LOCK_UNSUPPORTED",so,se
    return py,True,"",so,se

results=[]
print(f"REPOSITORY={R}")
print(f"HEAD={HEAD}")
print(f"TOTAL_REACHABLE_COMMITS={len(ALL)}")
print(f"VERIFYING_COMMITS={START}-{END}")
print(f"SELECTED_COMMITS={len(SEL)}")
print(f"REPORT={OUT}")

try:
    for n,sha in enumerate(SEL,START):
        d=OUT/f"{n:02d}-{sha[:12]}"; d.mkdir()
        z={"position":n,"sha":sha,"status":"UNVERIFIED","failure":None}
        print(f"\n[{n}/{END}] {sha[:12]}",flush=True)
        try:
            src=extract(sha,d)
            z["source_digest"]=digest(src)
            df=deps(src); z["dependency_files"]=[str(x.relative_to(src)) for x in df]
            rc,so,se,to=run([sys.executable,"-m","compileall","-q","-f","."],src,180)
            (d/"compile.stdout").write_text(so)
            (d/"compile.stderr").write_text(se)
            if to:
                z.update(status="UNVERIFIED",failure="COMPILE_TIMEOUT")
            elif rc:
                z.update(status="FAIL",failure="SYNTAX_OR_COMPILE_FAILURE")
            else:
                with tempfile.TemporaryDirectory(prefix="rf-historical-",dir=str(d)) as td:
                    v=Path(td)/"venv"
                    rc,so,se,to=run([sys.executable,"-m","venv",str(v)],src,180)
                    if rc:
                        z.update(status="UNVERIFIED",failure="ISOLATED_ENVIRONMENT_CREATION_FAILED")
                    else:
                        py,ok,reason,io,ie=install(v,src,df)
                        (d/"dependency-install.stdout").write_text(io)
                        (d/"dependency-install.stderr").write_text(ie)
                        if not ok:
                            z.update(status="UNVERIFIED",failure=reason)
                        elif not (src/"tests").is_dir():
                            z.update(status="PASS",failure=None,tests="NO_TEST_DIRECTORY")
                        else:
                            env=os.environ.copy()
                            env["PYTHONHASHSEED"]="0"
                            env["PYTHONPATH"]=str(src)
                            rc,so,se,to=run([str(py),"-m","pytest","--collect-only","-q","--disable-warnings"],
                                            src,120,env)
                            (d/"pytest.collect.stdout").write_text(so)
                            (d/"pytest.collect.stderr").write_text(se)
                            if to:
                                z.update(status="UNVERIFIED",failure="PYTEST_COLLECTION_TIMEOUT")
                            elif rc:
                                z.update(status="UNVERIFIED",failure="PYTEST_COLLECTION_FAILED")
                            else:
                                rc,so,se,to=run([str(py),"-m","pytest","-q","--disable-warnings"],
                                                src,300,env)
                                (d/"pytest.stdout").write_text(so)
                                (d/"pytest.stderr").write_text(se)
                                if to:
                                    z.update(status="UNVERIFIED",failure="PYTEST_EXECUTION_TIMEOUT")
                                elif rc:
                                    z.update(status="FAIL",failure="SOURCE_TEST_FAILURE")
                                else:
                                    z.update(status="PASS",failure=None,tests="PASS")
        except Exception as e:
            z.update(status="UNVERIFIED",failure="VERIFIER_ERROR",error=repr(e))
            (d/"exception.txt").write_text(traceback.format_exc())
        (d/"result.json").write_text(json.dumps(z,indent=2,sort_keys=True))
        results.append(z)
        print(f"STATUS={z['status']} FAILURE={z['failure'] or 'NONE'}",flush=True)
finally:
    (OUT/"summary.json").write_text(json.dumps({
        "repository":str(R),"head":HEAD,"range":[START,END],
        "selected":len(SEL),"completed":len(results),"results":results
    },indent=2,sort_keys=True))

print(f"\nCOMPLETED={len(results)}")
print(f"PASS={sum(x['status']=='PASS' for x in results)}")
print(f"FAIL={sum(x['status']=='FAIL' for x in results)}")
print(f"UNVERIFIED={sum(x['status']=='UNVERIFIED' for x in results)}")
print(f"REPORT={OUT}")
sys.exit(1 if any(x["status"]=="FAIL" for x in results) else 0)
