#!/usr/bin/env python3
"""Prepare scanner-only lockfile input and verify OWASP report evidence."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import quote, unquote

IMAGE = "owasp/dependency-check-action@sha256:01d78e8e60df25d1a6d42c85af2d8ce9d64a6fb69e18c6f98736dc1a7919009c"
LOCKS = ("core/requirements.txt", "core/requirements-test.txt")
REPORTS = Path("reports/owasp")
PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)(?:\s*;.+)?")


def now():
    return dt.datetime.now(dt.timezone.utc)


def canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_locks(root):
    packages, files = {}, {}
    for filename in LOCKS:
        raw = (root / filename).read_bytes()
        files[filename] = hashlib.sha256(raw).hexdigest()
        current, hashed = None, False
        for number, raw_line in enumerate(raw.decode("utf-8").splitlines(), 1):
            line = raw_line.strip().removesuffix("\\").strip()
            if not line or line.startswith("#"):
                continue
            if re.fullmatch(r"--hash=sha256:[a-fA-F0-9]{64}", line):
                if current is None:
                    raise ValueError("Hash without a pinned dependency")
                hashed = True
                continue
            match = PIN.fullmatch(line)
            if not match or (current is not None and not hashed):
                raise ValueError(f"Unsupported or unhashed lock entry: {filename}:{number}")
            name, version = match.groups()
            current = canonical(name) + "==" + version
            packages.setdefault(current, []).append({"file": filename, "line": number})
            hashed = False
        if current is None or not hashed:
            raise ValueError(f"Empty or unhashed lockfile: {filename}")
    # Include all platform markers conservatively in the scanner copy.
    return packages, files


def prepare():
    REPORTS.mkdir(parents=True, exist_ok=False)
    root = Path.cwd()
    packages, files = read_locks(root)
    snapshot = Path(tempfile.mkdtemp(prefix="rf-owasp-", dir=os.environ["RUNNER_TEMP"]))
    with tempfile.TemporaryFile() as archive:
        subprocess.run(["git", "archive", "--format=tar", "HEAD"], stdout=archive, check=True)
        archive.seek(0)
        with tarfile.open(fileobj=archive) as source:
            source.extractall(snapshot, filter="data")
    (snapshot / LOCKS[0]).write_text("\n".join(sorted(packages)) + "\n", encoding="utf-8")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    dump(REPORTS / "input.json", {"commit": commit, "prepared_at": now().isoformat(),
         "snapshot": str(snapshot), "scanner_image": IMAGE,
         "lockfile_sha256": files, "packages": packages})
    print(f"SCANNER_INPUT_PACKAGES={len(packages)}; original hash locks preserved")


def redact(text):
    for key in ("NVD_API_KEY", "OSS_INDEX_TOKEN", "OSS_INDEX_USERNAME"):
        value = os.environ.get(key, "")
        if value:
            text = text.replace(value, "***")
            if value.strip():
                text = text.replace(value.strip(), "***")
    return text


def scan():
    metadata = json.loads((REPORTS / "input.json").read_text())
    key = os.environ.get("NVD_API_KEY", "").strip()
    if not key:
        raise ValueError("NVD_API_KEY is unavailable to this job; refresh is required")
    args = ["docker", "run", "--rm", "-v", metadata["snapshot"] + ":/github/workspace:ro",
            "-v", str(REPORTS.resolve()) + ":/reports", "-w", "/github/workspace", IMAGE,
            "--project", os.environ["GITHUB_REPOSITORY"], "--scan", ".",
            "--format", "SARIF", "--format", "JSON", "--out", "/reports",
            "--enableExperimental", "--enableRetired", "--failOnCVSS", "7",
            "--nvdApiKey", key, "--nvdValidForHours", "0"]
    token = os.environ.get("OSS_INDEX_TOKEN", "").strip()
    if token:
        args += ["--ossIndexPassword", token]
        username = os.environ.get("OSS_INDEX_USERNAME", "").strip()
        if username:
            args += ["--ossIndexUsername", username]
    else:
        print("::warning::OSS_INDEX_TOKEN absent; Sonatype coverage remains unavailable")
    with (REPORTS / "scan.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, errors="replace")
        for line in process.stdout:
            clean = redact(line)
            log.write(clean)
            print(clean, end="", flush=True)
        code = process.wait()
    for report in REPORTS.glob("dependency-check-report.*"):
        original = report.read_text(encoding="utf-8")
        clean = redact(original)
        if clean != original:
            report.write_text(clean, encoding="utf-8")
    (REPORTS / "scanner-exit-code.txt").write_text(str(code) + "\n")
    return code


def timestamp(value):
    result = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("NVD timestamp lacks timezone")
    return result


def package_ids(node):
    found = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "id" and isinstance(value, str):
                match = re.fullmatch(r"pkg:pypi/([^@]+)@([^?]+)(?:\?.*)?", unquote(value))
                if match:
                    found.add(canonical(match[1]) + "==" + match[2])
            found.update(package_ids(value))
    elif isinstance(node, list):
        for item in node:
            found.update(package_ids(item))
    return found


def verify_report(report, metadata, log, checked_at=None):
    checked_at = checked_at or now()
    info = report.get("scanInfo", {})
    if info.get("analysisExceptions"):
        raise ValueError("Scanner reported analysis exceptions")
    if re.search(r"error updating.*NVD|using local data instead|unable to update.*data", log, re.I):
        raise ValueError("NVD update failed or cached-data fallback was used")
    if "Check for updates complete" not in log:
        raise ValueError("Missing successful update-completion log")
    sources = {entry["name"]: entry["timestamp"] for entry in info.get("dataSource", [])}
    checked = timestamp(sources["NVD API Last Checked"])
    modified = timestamp(sources["NVD API Last Modified"])
    prepared = timestamp(metadata["prepared_at"])
    if checked < prepared - dt.timedelta(minutes=5):
        raise ValueError("NVD was not checked during this invocation")
    for value in (checked, modified):
        age = (checked_at - value).total_seconds()
        if not -300 <= age <= 86400:
            raise ValueError("NVD metadata is stale or has an invalid future timestamp")
    missing = sorted(set(metadata["packages"]) - package_ids(report.get("dependencies", [])))
    if missing:
        raise ValueError("Locked dependencies missing from scanner coverage: " + ", ".join(missing))
    return sources


def normalize_sarif(sarif, packages):
    changes = 0

    def location(node):
        nonlocal changes
        uri = node.get("uri")
        if not isinstance(uri, str) or not uri.startswith("file:"):
            return None
        original = unquote(uri)
        match = re.fullmatch(r"file:///github/workspace/core/requirements\.txt:([^/]+)/([^/]+)", original)
        source = None
        if match:
            key = canonical(match[1]) + "==" + match[2]
            if key not in packages:
                raise ValueError("Unrecognized synthetic requirements location: " + original)
            source = packages[key][0]
            relative = source["file"]
        elif original.startswith("file:///github/workspace/"):
            relative = original.removeprefix("file:///github/workspace/")
            if ":" in relative or ".." in Path(relative).parts:
                raise ValueError("Unexpected scanner location: " + original)
        else:
            node["uri"] = quote(original, safe=":/@!$&'()*+,;=-._~")
            return None
        node.setdefault("properties", {})["rfOriginalUri"] = uri
        node["uri"] = quote(relative, safe="/-._~")
        node["uriBaseId"] = "%SRCROOT%"
        changes += 1
        return source

    def walk(node):
        if isinstance(node, dict):
            physical = node.get("physicalLocation")
            if isinstance(physical, dict) and isinstance(physical.get("artifactLocation"), dict):
                source = location(physical["artifactLocation"])
                if source:
                    physical["region"] = {"startLine": source["line"]}
            location(node)
            for key, value in list(node.items()):
                if key != "properties":
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    if sarif.get("version") != "2.1.0" or not sarif.get("runs"):
        raise ValueError("Unsupported or empty SARIF report")
    walk(sarif)
    return changes


def check():
    evidence = {"status": "failed", "verified_at": now().isoformat()}
    try:
        metadata = json.loads((REPORTS / "input.json").read_text())
        report = json.loads((REPORTS / "dependency-check-report.json").read_text())
        log = (REPORTS / "scan.log").read_text()
        sources = verify_report(report, metadata, log)
        sarif = json.loads((REPORTS / "dependency-check-report.sarif").read_text())
        changes = normalize_sarif(sarif, metadata["packages"])
        dump(REPORTS / "dependency-check-upload.sarif", sarif)
        oss_ok = "Finished Sonatype OSS Index Analyzer" in log or "Finished OSS Index Analyzer" in log
        oss_ok = oss_ok and not re.search(r"OSS Index.*disabled|OSS Index.*error", log, re.I)
        evidence.update(status="passed", commit=metadata["commit"],
                        scanner_image=metadata["scanner_image"], nvd_data_sources=sources,
                        lockfile_sha256=metadata["lockfile_sha256"],
                        locked_packages_verified=len(metadata["packages"]),
                        sarif_locations_normalized=changes,
                        scanner_exit_code=int((REPORTS / "scanner-exit-code.txt").read_text()),
                        oss_index_coverage="completed" if oss_ok else "unavailable")
        if os.environ.get("OSS_INDEX_TOKEN") and not oss_ok:
            raise ValueError("Sonatype token was supplied but OSS Index coverage did not complete")
        print("NVD_FRESHNESS=PASS; LOCKFILE_SCAN_COVERAGE=PASS; OSS_INDEX=" + evidence["oss_index_coverage"])
    except (OSError, ValueError, KeyError) as exc:
        evidence.update(status="failed", error=redact(str(exc)))
        raise
    finally:
        dump(REPORTS / "freshness-evidence.json", evidence)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as output:
                output.write("### OWASP evidence\n\n```json\n" + json.dumps(evidence, indent=2) + "\n```\n")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"prepare", "scan", "check"}:
        raise ValueError("Expected prepare, scan, or check")
    result = {"prepare": prepare, "scan": scan, "check": check}[sys.argv[1]]()
    return result or 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print("::error::" + redact(str(exc)), file=sys.stderr)
        sys.exit(1)
