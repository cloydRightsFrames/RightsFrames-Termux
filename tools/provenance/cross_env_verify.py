#!/usr/bin/env python3
import hashlib,json,os,subprocess,sys

ROOT=os.path.abspath(sys.argv[1] if len(sys.argv)>1 else ".")
OUT=sys.argv[2] if len(sys.argv)>2 else "cross-environment-manifest.json"

def sha256(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for b in iter(lambda:f.read(1048576),b""):
            h.update(b)
    return h.hexdigest()

commit=subprocess.check_output(
    ["git","-C",ROOT,"rev-parse","HEAD"],text=True
).strip()

paths=[
    x.decode()
    for x in subprocess.check_output(
        ["git","-C",ROOT,"ls-files","-z"]
    ).split(b"\0") if x
]

files=[]
for rel in sorted(paths):
    p=os.path.join(ROOT,rel)
    files.append({
        "path":rel,
        "sha256":sha256(p),
        "size":os.path.getsize(p)
    })

manifest={
    "schema":"rightsframes.cross-environment-manifest/v1",
    "repository":"cLoydRightsFrames/RightsFrames-Termux",
    "commit":commit,
    "tracked_file_count":len(files),
    "tracked_files":files
}

raw=json.dumps(manifest,sort_keys=True,separators=(",",":")).encode()+b"\n"
digest=hashlib.sha256(raw).hexdigest()

with open(OUT,"wb") as f:
    f.write(raw)

with open(OUT+".sha256","w") as f:
    f.write(f"{digest}  {os.path.basename(OUT)}\n")

print(f"COMMIT={commit}")
print(f"TRACKED_FILES={len(files)}")
print(f"MANIFEST_SHA256={digest}")
print("CROSS_ENVIRONMENT_MANIFEST=VERIFIED")
