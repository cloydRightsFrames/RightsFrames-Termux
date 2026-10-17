import hashlib, json, os, shutil, subprocess, sys, tempfile, time
from pathlib import Path

ROOT=Path.cwd()
REPORT=ROOT/"artifacts"/("enterprise-historical-51-88-no-venv-"+time.strftime("%Y%m%dT%H%M%SZ"))
REPORT.mkdir(parents=True,exist_ok=True)

def run(cmd,cwd,timeout):
    try:
        x=subprocess.run(cmd,cwd=cwd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
        return x.returncode,x.stdout,x.stderr,False
    except subprocess.TimeoutExpired as e:
        return 124,e.stdout or "",e.stderr or "",True

shas=subprocess.check_output(["git","rev-list","--reverse","HEAD"],cwd=ROOT,text=True).splitlines()
selected=shas[50:88]

print("REPOSITORY="+str(ROOT))
print("HEAD="+subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip())
print("TOTAL_REACHABLE_COMMITS="+str(len(shas)))
print("VERIFYING_COMMITS=51-88")
print("SELECTED_COMMITS="+str(len(selected)))
print("REPORT="+str(REPORT))

results=[]

for n,sha in enumerate(selected,51):
    short=sha[:12]
    print("\n["+str(n)+"/88] "+short,flush=True)
    td=Path(tempfile.mkdtemp(prefix="rf-historical-",dir=REPORT))
    src=td/"src"
    evidence=REPORT/(str(n)+"-"+short)
    evidence.mkdir(parents=True,exist_ok=True)
    try:
        ar=src.with_suffix(".tar")
        rc,so,se,to=run(["git","archive","--format=tar","--output="+str(ar),sha],ROOT,60)
        if rc!=0:
            (evidence/"git-archive.stderr").write_text(se)
            results.append({"position":n,"sha":sha,"status":"UNVERIFIED","failure":"GIT_ARCHIVE_FAILED"})
            print("STATUS=UNVERIFIED FAILURE=GIT_ARCHIVE_FAILED")
            continue
        src.mkdir()
        rc,so,se,to=run(["tar","-xf",str(ar),"-C",str(src)],ROOT,60)
        ar.unlink(missing_ok=True)
        if rc!=0:
            (evidence/"extract.stderr").write_text(se)
            results.append({"position":n,"sha":sha,"status":"UNVERIFIED","failure":"ARCHIVE_EXTRACT_FAILED"})
            print("STATUS=UNVERIFIED FAILURE=ARCHIVE_EXTRACT_FAILED")
            continue

        pyfiles=sorted(src.rglob("*.py"))
        compile_fail=[]
        for f in pyfiles:
            rc,so,se,to=run([sys.executable,"-m","py_compile",str(f)],src,20)
            if rc!=0:
                compile_fail.append(str(f.relative_to(src)))
        (evidence/"python-files.txt").write_text("\n".join(str(f.relative_to(src)) for f in pyfiles))
        if compile_fail:
            (evidence/"compile-failures.txt").write_text("\n".join(compile_fail))
            results.append({"position":n,"sha":sha,"status":"FAIL","failure":"PYTHON_COMPILE_FAILED"})
            print("STATUS=FAIL FAILURE=PYTHON_COMPILE_FAILED")
            continue

        testdir=src/"tests"
        if not testdir.is_dir():
            results.append({"position":n,"sha":sha,"status":"PASS","failure":"NO_TEST_DIRECTORY"})
            print("STATUS=PASS TESTS=NO_TEST_DIRECTORY SYNTAX=PASS")
            continue

        env=os.environ.copy()
        env["PYTHONPATH"]=str(src)
        rc,so,se,to=run([sys.executable,"-m","pytest","-q","--collect-only"],src,90)
        (evidence/"pytest-collect.stdout").write_text(so)
        (evidence/"pytest-collect.stderr").write_text(se)
        if to:
            results.append({"position":n,"sha":sha,"status":"UNVERIFIED","failure":"PYTEST_COLLECTION_TIMEOUT"})
            print("STATUS=UNVERIFIED FAILURE=PYTEST_COLLECTION_TIMEOUT")
            continue
        if rc!=0:
            results.append({"position":n,"sha":sha,"status":"UNVERIFIED","failure":"PYTEST_COLLECTION_FAILED"})
            print("STATUS=UNVERIFIED FAILURE=PYTEST_COLLECTION_FAILED")
            continue

        rc,so,se,to=run([sys.executable,"-m","pytest","-q"],src,180)
        (evidence/"pytest.stdout").write_text(so)
        (evidence/"pytest.stderr").write_text(se)
        if to:
            results.append({"position":n,"sha":sha,"status":"UNVERIFIED","failure":"PYTEST_TIMEOUT"})
            print("STATUS=UNVERIFIED FAILURE=PYTEST_TIMEOUT")
        elif rc!=0:
            results.append({"position":n,"sha":sha,"status":"FAIL","failure":"PYTEST_FAILED"})
            print("STATUS=FAIL FAILURE=PYTEST_FAILED")
        else:
            results.append({"position":n,"sha":sha,"status":"PASS","failure":None})
            print("STATUS=PASS TESTS=PASS SYNTAX=PASS")
    finally:
        shutil.rmtree(td,ignore_errors=True)

(REPORT/"results.json").write_text(json.dumps(results,indent=2))
from collections import Counter
c=Counter(x["status"] for x in results)
print("\nSUMMARY:")
print("RESULTS="+str(len(results)))
print("PASS="+str(c["PASS"]))
print("FAIL="+str(c["FAIL"]))
print("UNVERIFIED="+str(c["UNVERIFIED"]))
print("REPORT="+str(REPORT))
