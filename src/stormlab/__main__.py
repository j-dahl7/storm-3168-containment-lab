"""CLI for explicit, bounded containment experiments. Default response is plan-only."""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path

from .core import (ACTIONS, CAPABILITIES, AzureCLI, Guard, HTTP, Manifest,
                   SafetyError, demo_rows, load_json, respond, run_probe, summarize, summarize_trial,
                   utc_now)


REPO_ROOT = Path(__file__).resolve().parents[2]


def private_root(manifest_path: Path) -> Path:
    path = manifest_path.resolve(strict=True)
    checkout = REPO_ROOT.resolve()
    expected = checkout / "private"
    resolved = expected.resolve()
    if resolved != expected or not path.is_relative_to(expected):
        raise SafetyError("Live manifest must stay in this checkout's private/ without symlink escapes")
    ignore = (checkout / ".gitignore").read_text(encoding="utf-8")
    if not any(line.strip() in {"private/", "/private/"} for line in ignore.splitlines()):
        raise SafetyError("The checkout must ignore private/ before live work")
    return expected


def live_output(path: str | None, root: Path, filename: str) -> Path:
    result = (Path(path) if path else root / filename).resolve()
    if not result.is_relative_to(root.resolve()):
        raise SafetyError("Live evidence output must stay inside the manifest's private/ directory")
    return result


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
        handle.flush()


def read_jsonl(path: Path) -> list[dict]:
    if path.stat().st_size > 20_000_000:
        raise SafetyError("Evidence file is too large")
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            if not isinstance(row, dict):
                raise SafetyError("Each evidence line must be an object")
            rows.append(row)
    return rows


def write_json(path: Path | None, value: dict) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True, allow_nan=False)
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Bounded Storm-3168 defensive lab; no deployment; live credentials stay in memory")
    sub = p.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="Generate explicitly simulated offline JSONL")
    demo.add_argument("--output", required=True)
    summary = sub.add_parser("summarize", help="Summarize outcomes without claiming action causality")
    source = summary.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", help="One probe JSONL, summarized without cross-run stitching")
    source.add_argument("--trial", help="Trial JSON receipt; checks sibling baseline/action/post files before stitching")
    summary.add_argument("--output")
    for name in ("preflight", "probe", "respond"):
        cmd = sub.add_parser(name, help={"preflight": "Read and verify live ownership only", "probe": "Observe one frozen credential, never refresh it", "respond": "Plan an action; requires --execute and confirmation to mutate"}[name])
        cmd.add_argument("--manifest", required=True)
        cmd.add_argument("--subscription", required=True, help="Explicit subscription UUID; must match manifest")
        cmd.add_argument("--output", help="Evidence path inside private/ (defaults to command-specific file)")
        if name == "probe":
            cmd.add_argument("--capability", choices=CAPABILITIES, required=True)
            cmd.add_argument("--auth", choices=("bearer", "shared-key", "sas"), default="bearer")
            cmd.add_argument("--token-env", default="STORMLAB_PROBE_TOKEN")
            cmd.add_argument("--credential-label", help="Random UUID shared only by phases using the same frozen credential")
            cmd.add_argument("--key-env", default="STORMLAB_STORAGE_KEY")
            cmd.add_argument("--sas-env", default="STORMLAB_SAS", help="Read-only HTTPS SAS query only, never a URL; blob-read only")
            cmd.add_argument("--interval", type=float, default=20)
            cmd.add_argument("--duration", type=float, default=180, help="Seconds, maximum 7200")
            cmd.add_argument("--allow-mutation", action="store_true", help="Allow manifest account canary tag read/merge/write; serialize all lab tag writers")
        if name == "respond":
            cmd.add_argument("--action", choices=ACTIONS, required=True)
            cmd.add_argument("--role-assignment-id", help="Exact full ID from manifest, required for role-delete")
            cmd.add_argument("--execute", action="store_true")
            cmd.add_argument("--confirm-lab-id", help="Exact lab UUID is required with --execute")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "demo":
            output = Path(args.output)
            if output.exists():
                raise SafetyError("Refusing to overwrite an existing demo/evidence file")
            for row in demo_rows():
                append_jsonl(output, row)
            print("Wrote offline simulated evidence; no Azure calls were made.")
            return 0
        if args.command == "summarize":
            if args.trial:
                path = Path(args.trial)
                receipt = load_json(path)
                action_path = path.parent / "action.jsonl"
                result = summarize_trial(receipt, read_jsonl(path.parent / "baseline.jsonl"),
                                         read_jsonl(action_path) if action_path.exists() else [],
                                         read_jsonl(path.parent / "post-action.jsonl"))
            else:
                result = summarize(read_jsonl(Path(args.input)))
            write_json(Path(args.output) if args.output else None, result)
            return 0
        manifest_path = Path(args.manifest)
        root = private_root(manifest_path)
        m = Manifest.from_dict(load_json(manifest_path))
        operator = AzureCLI(m, args.subscription)
        http = HTTP()
        guard = Guard(m, http, operator)
        if args.command == "preflight":
            guard.ownership()
            if m.actor:
                guard.actor()
            output = live_output(args.output, root, "preflight.jsonl")
            append_jsonl(output, {"schema_version": 1, "kind": "preflight", "timestamp": utc_now(), "status": "ownership_verified", "cloud_mutations": False})
            print("Live ownership checks passed; no mutation was performed.")
        elif args.command == "probe":
            if not math.isfinite(args.interval) or not math.isfinite(args.duration):
                raise SafetyError("Interval and duration must be finite")
            variable = {"bearer": args.token_env, "shared-key": args.key_env, "sas": args.sas_env}[args.auth]
            if not variable or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_" for c in variable):
                raise SafetyError("Invalid credential environment variable name")
            credential = os.environ.get(variable)
            if not credential:
                raise SafetyError("Required credential environment variable is empty")
            output = live_output(args.output, root, "probes.jsonl")
            run_probe(m, http, guard, args.capability, credential, auth=args.auth, interval=args.interval, duration=args.duration, allow_mutation=args.allow_mutation, credential_label=args.credential_label, emit=lambda row: append_jsonl(output, row))
            print("Bounded probe finished; review evidence for the specific tested capability.")
        else:
            output = live_output(args.output, root, "actions.jsonl")
            row = respond(guard, args.action, execute=args.execute, confirm_lab_id=args.confirm_lab_id, assignment_id=args.role_assignment_id)
            append_jsonl(output, row)
            print(json.dumps({key: row[key] for key in ("action", "status", "executed")}, sort_keys=True))
            if row["status"] in {"failed", "indeterminate"}:
                return 3
        return 0
    except (SafetyError, OSError, ValueError, TypeError, KeyError):
        # Never echo remote bodies, CLI stderr, credentials, or untrusted JSON.
        print("Safety check or operation failed; no automatic retry. Verify manifest, ownership, identity, permissions and inputs.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted; retain partial evidence and inspect live state before retrying.", file=sys.stderr)
        return 130
    except Exception:
        # Final credential boundary: unexpected libraries must not echo a URL,
        # response body, SAS, or token through an uncaught traceback.
        print("Unexpected failure; retain partial evidence and reconcile private state before retrying.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
