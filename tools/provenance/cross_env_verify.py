#!/usr/bin/env python3
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
out = Path(sys.argv[2] if len(sys.argv) > 2 else "cross-environment-manifest.json")

commit = subprocess.check_output(
    ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
).strip()

lines = subprocess.check_output(
    ["git", "-C", str(root), "ls-tree", "-r", "--long", "HEAD"],
    text=True,
    encoding="utf-8",
).splitlines()

files = []
for line in lines:
    meta, path = line.split("\t", 1)
    mode, obj_type, blob, size = meta.split(" ", 3)
    if obj_type != "blob":
        continue
    files.append({
        "path": path.replace("\\", "/"),
        "git_blob": blob,
        "size": int(size),
    })

files.sort(key=lambda x: x["path"])

manifest = {
    "schema": "rightsframes.cross-environment-manifest/v2",
    "repository": "cLoydRightsFrames/RightsFrames-Termux",
    "commit": commit,
    "tracked_file_count": len(files),
    "tracked_files": files,
}

data = json.dumps(
    manifest,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
).encode("utf-8") + b"\n"

out.write_bytes(data)
digest = hashlib.sha256(data).hexdigest()
Path(str(out) + ".sha256").write_text(
    f"{digest}  {out.name}\n",
    encoding="utf-8",
)

print(f"COMMIT={commit}")
print(f"TRACKED_FILES={len(files)}")
print(f"MANIFEST_SHA256={digest}")
