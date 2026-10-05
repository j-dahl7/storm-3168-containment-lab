"""Offline structure and disclosure checks. This does NOT compile/execute KQL."""
from __future__ import annotations
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXCLUDED = {".git", ".venv", "private", "__pycache__", "artifacts", "build", "dist"}
TEXT_EXTENSIONS = {".py", ".md", ".json", ".bicep", ".kql", ".yml", ".yaml", ".toml", ".ps1", ".sh"}


def main() -> int:
    errors = []
    json_count = 0
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED or part.endswith(".egg-info") for part in relative.parts) or not path.is_file():
            continue
        if path.suffix not in TEXT_EXTENSIONS:
            continue
        text = path.read_text(encoding="utf-8-sig")
        if path.suffix == ".json":
            try:
                json.loads(text)
                json_count += 1
            except json.JSONDecodeError as exc:
                errors.append(f"{relative}: invalid JSON at line {exc.lineno}")
        # Full bearer credentials and SAS signatures are never public fixtures.
        if re.search(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", text):
            errors.append(f"{relative}: token-shaped literal")
        if re.search(r"[?&]sig=[A-Za-z0-9%+/]{18,}", text):
            errors.append(f"{relative}: SAS-signature-shaped literal")
        if re.search(r"(?i)\bAccountKey=[A-Za-z0-9+/]{32,}={0,2}", text):
            errors.append(f"{relative}: storage-account-key-shaped literal")
        if re.search(r"\b[A-Za-z0-9._~-]{2,}Q~[A-Za-z0-9._~-]{20,}\b", text):
            errors.append(f"{relative}: client-secret-shaped literal")
        if "-----BEGIN PRIVATE KEY-----" in text and path.name != "validate_assets.py":
            errors.append(f"{relative}: private-key marker")
    tracked = subprocess.run(["git", "ls-files", "--cached"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.splitlines()
    if any(name.startswith("private/") or name == ".env" for name in tracked):
        errors.append("Private live configuration/evidence is tracked")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Validated {json_count} JSON assets and public text disclosure patterns. KQL/live execution not tested by this check.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
