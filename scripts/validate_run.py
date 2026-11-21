#!/usr/bin/env python3
"""Validate an interop run directory.

Used by .github/workflows/validate-run.yml and meant to be run locally before
opening a pull request:

    python3 scripts/validate_run.py runs/<run-id>

In the workflow it also receives the list of files the PR changed, so it can
check that the PR touches only one run directory:

    python3 scripts/validate_run.py --changed-files changed.txt \
        [--allow-any-files] [--registry participants.yaml]

The script reads files only; it makes no network calls and runs nothing from
the run directory. Exit status is 0 when there are no errors (warnings are
allowed), 1 otherwise.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parent.parent
RUN_SCHEMA = ROOT / "schema" / "run.schema.json"
PARTICIPANTS_SCHEMA = ROOT / "schema" / "participants.schema.json"

# Files allowed in a run directory besides logs/. organizer.yaml is added by
# the organizer when merging (phase 2 of the results process).
ALLOWED_RUN_FILES = {"run.yaml", "README.md", "organizer.yaml"}

CLIENT_SIDE = {"mcp-client", "gateway"}
SERVER_SIDE = {"mcp-server", "gateway"}

# Roles that may appear in each flow, and the claims each role may offer. The
# organizer decides what the evidence supports; this only rejects rows that
# don't exist for the flow and role.
FLOW_RULES = {
    "oauth": {
        "roles": {"mcp-client", "mcp-server", "gateway"},
        "claims": {
            "mcp-client": {"oprm", "www-authenticate-scope", "scoped-access"},
            "mcp-server": {"oprm", "www-authenticate-scope", "scoped-access"},
            "gateway": {"oprm", "www-authenticate-scope", "scoped-access"},
        },
    },
    "cimd": {
        "roles": {"mcp-client", "gateway", "resource-as"},
        "claims": {
            r: {
                "cimd-preregistered", "cimd-redirect-uris", "cimd-jwks-uri", "cimd-jwks",
                "grant-code-pkce", "grant-client-credentials",
                "auth-private-key-jwt", "auth-mtls", "auth-none-public",
            }
            for r in ("mcp-client", "gateway", "resource-as")
        },
    },
    "ema": {
        "roles": {"mcp-client", "gateway", "op", "resource-as"},
        "claims": {
            r: {"valid-id-jag", "id-jag-resource", "id-jag-scope", "id-jag-sub-id"}
            for r in ("mcp-client", "gateway", "op", "resource-as")
        },
    },
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".pdf",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar",
    ".pcap", ".pcapng", ".bin", ".exe", ".dll", ".so", ".dylib",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}

REDACTED = re.compile(r"\[?REDACTED\]?|\*{3,}|<redacted>", re.I)

# Secret patterns. PEM private keys fail the run; the others warn.
SECRET_PATTERNS = [
    ("error", "PEM private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("warning", "possible unredacted JWT",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("warning", "possible unredacted bearer token",
     re.compile(r"\bBearer\s+(?!\[?REDACTED)[A-Za-z0-9._~+/=-]{20,}")),
    ("warning", "possible unredacted client_secret",
     re.compile(r"client_secret\s*[=:]\s*\"?(?!\[?REDACTED|\*{3}|<redacted>)[^&\s\"']{6,}", re.I)),
]

# Timestamp forms we recognise in log lines. Anything without a zone is taken
# as UTC, which is what the evidence guidance asks for.
TIMESTAMP_PATTERNS = [
    re.compile(
        r"(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?"
        r"(?P<tz>Z|[+-]\d{2}:?\d{2})?)"
    ),
    # Common Log Format: [03/Feb/2027:14:00:01 +0000]
    re.compile(r"\[(?P<clf>\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}) (?P<clftz>[+-]\d{4})\]"),
]
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.notes: list[str] = []
        self.github = os.environ.get("GITHUB_ACTIONS") == "true"

    def _emit(self, level: str, msg: str, file: str | None, line: int | None) -> None:
        where = f"{file}:{line}" if file and line else (file or "")
        text = f"{where}: {msg}" if where else msg
        getattr(self, level + "s").append(text)
        if self.github and level in ("error", "warning"):
            loc = ""
            if file:
                loc = f" file={file}"
                if line:
                    loc += f",line={line}"
            print(f"::{level}{loc}::{msg}")
        else:
            print(f"{level.upper()}: {text}")

    def error(self, msg: str, file: str | None = None, line: int | None = None) -> None:
        self._emit("error", msg, file, line)

    def warning(self, msg: str, file: str | None = None, line: int | None = None) -> None:
        self._emit("warning", msg, file, line)

    def note(self, msg: str) -> None:
        self._emit("note", msg, None, None)

    def write_summary(self, title: str) -> None:
        path = os.environ.get("GITHUB_STEP_SUMMARY")
        if not path:
            return
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"## {title}\n\n")
            status = "failed" if self.errors else "passed"
            fh.write(f"**Result: {status}** ({len(self.errors)} errors, {len(self.warnings)} warnings)\n\n")
            for label, items in (("Errors", self.errors), ("Warnings", self.warnings), ("Notes", self.notes)):
                if items:
                    fh.write(f"### {label}\n\n")
                    for item in items:
                        fh.write(f"- {item}\n")
                    fh.write("\n")


def load_yaml(path: Path, report: Report) -> dict | None:
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        report.error(f"cannot read {path.name}: {exc}", str(path))
        return None
    if not isinstance(data, dict):
        report.error(f"{path.name} must be a mapping", str(path))
        return None
    return data


def stringify_timestamps(obj):
    """YAML parses unquoted ISO timestamps as datetimes. Turn them back into
    the string form the schema expects so both spellings validate."""
    if isinstance(obj, dict):
        return {k: stringify_timestamps(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [stringify_timestamps(v) for v in obj]
    if isinstance(obj, dt.datetime):
        if obj.tzinfo is None:
            obj = obj.replace(tzinfo=dt.timezone.utc)
        return obj.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return obj


def parse_utc(value: str) -> dt.datetime:
    return dt.datetime.strptime(value.replace("Z", "+00:00")[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)


def load_registry(path: Path, report: Report) -> dict | None:
    data = load_yaml(path, report)
    if data is None:
        return None
    schema = json.loads(PARTICIPANTS_SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    for err in errors:
        report.error(f"participants.yaml invalid at /{'/'.join(map(str, err.path))}: {err.message}", str(path))
    if errors:
        return None
    orgs = {}
    for org in data["organizations"]:
        if org["slug"] in orgs:
            report.error(f"duplicate slug `{org['slug']}` in participants.yaml", str(path))
        orgs[org["slug"]] = org
    return {"organizer": data["organizer"]["github"], "orgs": orgs}


# --- PR scope -----------------------------------------------------------------

RUN_PATH = re.compile(r"^runs/([^/]+)/(.+)$")


def check_scope(changed: list[str], allow_any: bool, runs_root: Path, report: Report) -> Path | None:
    """Return the single run directory the PR touches, or None."""
    run_ids = set()
    outside = []
    for f in changed:
        m = RUN_PATH.match(f)
        if m:
            run_ids.add(m.group(1))
        else:
            outside.append(f)
    if outside and not allow_any:
        for f in outside:
            report.error("a run submission may only add or change files under its own runs/<run-id>/ directory", f)
    if len(run_ids) > 1:
        report.error("a pull request must cover exactly one run; this one touches: " + ", ".join(sorted(run_ids)))
        return None
    if not run_ids:
        if allow_any:
            report.note("no run directory in this pull request; nothing to validate")
        else:
            report.error("no files under runs/<run-id>/ were added or changed")
        return None
    return runs_root / run_ids.pop()


def local_scope_hint(run_dir: Path, report: Report) -> None:
    """Best-effort check of the working tree against origin/main when run locally."""
    if not run_dir.is_relative_to(ROOT):
        return
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "diff", "--name-only", "origin/main...HEAD"],
            capture_output=True, text=True, check=True, timeout=20,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return
    rel = run_dir.relative_to(ROOT).as_posix() + "/"
    outside = [f for f in out.split() if f and not f.startswith(rel)]
    if outside:
        report.warning(
            "your branch also changes files outside this run directory; the PR check will reject them: "
            + ", ".join(outside[:10])
        )


# --- Run validation -----------------------------------------------------------

def validate_run(run_dir: Path, registry: dict, report: Report) -> dict | None:
    rel = f"runs/{run_dir.name}"
    run_file = run_dir / "run.yaml"
    if not run_dir.is_dir():
        report.error(f"run directory {rel} does not exist")
        return None
    if not run_file.is_file():
        report.error("run.yaml is missing", f"{rel}/run.yaml")
        return None

    raw = load_yaml(run_file, report)
    if raw is None:
        return None
    run = stringify_timestamps(raw)
    run_yaml = f"{rel}/run.yaml"

    schema = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    schema_errors = sorted(validator.iter_errors(run), key=lambda e: list(e.path))
    for err in schema_errors:
        report.error(f"run.yaml invalid at /{'/'.join(map(str, err.path))}: {err.message}", run_yaml)
    if schema_errors:
        return None

    orgs = registry["orgs"]
    flow = run["flow"]
    rules = FLOW_RULES[flow]

    # run_id vs directory, flow and org order
    if run["run_id"] != run_dir.name:
        report.error(f"run_id `{run['run_id']}` does not match the directory name `{run_dir.name}`", run_yaml)
    segments = run["run_id"].split("-")
    id_flow, id_orgs = segments[3], segments[4:-1]
    if id_flow != flow:
        report.error(f"run_id names flow `{id_flow}` but flow is `{flow}`", run_yaml)
    part_orgs = list(dict.fromkeys(p["org"] for p in run["parts"]))
    if id_orgs != part_orgs:
        report.error(
            f"run_id organizations `{'-'.join(id_orgs)}` must be the distinct `org` values of parts in order: "
            f"`{'-'.join(part_orgs)}`", run_yaml)
    try:
        dt.date.fromisoformat("-".join(segments[:3]))
    except ValueError:
        report.error(f"run_id starts with an invalid date `{'-'.join(segments[:3])}`", run_yaml)

    # run window
    start, end = parse_utc(run["run_window"]["start"]), parse_utc(run["run_window"]["end"])
    if end <= start:
        report.error("run_window end must be after start", run_yaml)
    if (end - start) > dt.timedelta(hours=24):
        report.warning("run_window is longer than 24 hours", run_yaml)

    # submitter
    submitter = run["submitted_by"]
    if submitter not in orgs:
        report.error(f"submitted_by `{submitter}` is not in participants.yaml", run_yaml)
    elif orgs[submitter]["kind"] != "organization":
        report.error(f"submitted_by `{submitter}` is a tool, not an organization", run_yaml)
    elif submitter not in part_orgs:
        report.error(f"submitted_by `{submitter}` does not own any part of this run", run_yaml)

    # parts
    roles_present = []
    referenced_logs: dict[str, list[int]] = {}
    operators: dict[str, list[int]] = {}
    org_kinds = []
    for i, part in enumerate(run["parts"]):
        loc = f"parts[{i}] ({part['role']}, {part['org']})"
        role, org_slug = part["role"], part["org"]
        roles_present.append(role)
        if role not in rules["roles"]:
            report.error(f"{loc}: role `{role}` is not applicable in the {flow} flow "
                         f"(allowed: {', '.join(sorted(rules['roles']))})", run_yaml)
        org = orgs.get(org_slug)
        if org is None:
            report.error(f"{loc}: org `{org_slug}` is not in participants.yaml", run_yaml)
        else:
            org_kinds.append(org["kind"])
            impl = next((im for im in org["implementations"] if im["id"] == part["implementation"]), None)
            if impl is None:
                report.error(f"{loc}: implementation `{part['implementation']}` is not registered for `{org_slug}`", run_yaml)
            elif role not in impl["roles"]:
                report.error(f"{loc}: implementation `{impl['id']}` is not registered for role `{role}` "
                             f"(registered: {', '.join(impl['roles'])})", run_yaml)
        allowed_claims = rules["claims"].get(role, set())
        for claim in part["claims"]:
            if claim not in allowed_claims:
                report.error(f"{loc}: claim `{claim}` is not valid for role `{role}` in the {flow} flow", run_yaml)
        for p in part["logs"]:
            referenced_logs.setdefault(p, []).append(i)
        operators.setdefault(part["operator"].strip().casefold(), []).append(i)

    # role set per flow
    role_set = set(roles_present)
    if flow == "oauth":
        if not (role_set & CLIENT_SIDE and role_set & SERVER_SIDE):
            report.error("an oauth run needs an MCP client side (mcp-client or gateway) and an MCP server side (mcp-server or gateway)", run_yaml)
    elif flow == "cimd":
        if not (role_set & CLIENT_SIDE and "resource-as" in role_set):
            report.error("a cimd run needs an MCP client side (mcp-client or gateway) and a resource-as", run_yaml)
    elif flow == "ema":
        if not (role_set & CLIENT_SIDE and "op" in role_set and "resource-as" in role_set):
            report.error("an ema run needs an MCP client side (mcp-client or gateway), an op and a resource-as", run_yaml)
    for role in sorted(role_set):
        if roles_present.count(role) > 1 and role != "gateway":
            report.warning(f"role `{role}` appears on more than one part", run_yaml)

    # provisional signals (information for the organizer, not failures)
    if "tool" in org_kinds:
        report.note("provisional: a common tool is one of the parts")
    for names in operators.values():
        if len(names) > 1:
            report.note(f"provisional: the same operator appears on parts {names}")
    if flow == "ema":
        distinct = {p["org"] for p in run["parts"] if orgs.get(p["org"], {}).get("kind") == "organization"}
        if len(distinct) < 3:
            report.note(f"provisional: ema run has {len(distinct)} distinct organizations; a green result needs three")

    # files in the run directory
    logs_dir = run_dir / "logs"
    for entry in sorted(run_dir.iterdir()):
        if entry.name == "logs":
            if not entry.is_dir():
                report.error("logs must be a directory", f"{rel}/logs")
        elif entry.name not in ALLOWED_RUN_FILES or not entry.is_file():
            report.error(f"unexpected entry `{entry.name}` in the run directory (allowed: run.yaml, logs/, README.md)",
                         f"{rel}/{entry.name}")
    present_logs = set()
    if logs_dir.is_dir():
        for f in sorted(logs_dir.rglob("*")):
            if f.is_file():
                present_logs.add(f.relative_to(run_dir).as_posix())
    for p in referenced_logs:
        if p not in present_logs:
            report.error(f"log file `{p}` is listed in run.yaml but does not exist", run_yaml)
    for p in sorted(present_logs - set(referenced_logs)):
        report.error("file under logs/ is not listed in any part's `logs`", f"{rel}/{p}")

    # correlation must name a log file
    corr = run["correlation"]
    names = {p for p in referenced_logs} | {Path(p).name for p in referenced_logs}
    if not any(n in corr for n in names):
        report.error("correlation must mention at least one of the log files by name", run_yaml)

    # log contents (every file present, listed or not)
    for p in sorted(present_logs):
        check_log_file(run_dir / p, f"{rel}/{p}", start, end, report)

    return run


def check_log_file(path: Path, rel: str, start: dt.datetime, end: dt.datetime, report: Report) -> None:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        report.error(f"`{path.name}` looks like a binary or image file; logs must be plain text", rel)
        return
    data = path.read_bytes()
    if not data.strip():
        report.error("log file is empty", rel)
        return
    if b"\x00" in data:
        report.error("log file contains NUL bytes; logs must be plain text", rel)
        return
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        report.error(f"log file is not valid UTF-8 text ({exc.reason} at byte {exc.start})", rel)
        return
    if len(data) > 10 * 1024 * 1024:
        report.warning("log file is larger than 10 MB", rel)

    saw_timestamp = in_window = False
    for lineno, line in enumerate(text.splitlines(), 1):
        for level, label, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                getattr(report, level)(f"{label}; redact it with [REDACTED]", rel, lineno)
        for ts in iter_timestamps(line):
            saw_timestamp = True
            if start <= ts <= end:
                in_window = True
    if not saw_timestamp:
        report.warning("no recognisable timestamps found in this log file", rel)
    elif not in_window:
        report.warning(f"no log line timestamp falls inside run_window ({start:%Y-%m-%dT%H:%M:%SZ} to {end:%Y-%m-%dT%H:%M:%SZ})", rel)


def iter_timestamps(line: str):
    for pattern in TIMESTAMP_PATTERNS:
        for m in pattern.finditer(line):
            try:
                if m.groupdict().get("iso"):
                    iso = m.group("iso").replace(" ", "T")
                    if iso.endswith("Z"):
                        iso = iso[:-1] + "+00:00"
                    elif not m.group("tz"):
                        iso += "+00:00"
                    yield dt.datetime.fromisoformat(iso).astimezone(dt.timezone.utc)
                elif m.groupdict().get("clf"):
                    d, mon, rest = m.group("clf").split("/", 2)
                    y, hms = rest.split(":", 1)
                    tz = m.group("clftz")
                    iso = f"{y}-{MONTHS[mon]:02d}-{d}T{hms}{tz[:3]}:{tz[3:]}"
                    yield dt.datetime.fromisoformat(iso).astimezone(dt.timezone.utc)
            except (ValueError, KeyError):
                continue


# --- Entry point --------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run_dir", nargs="?", help="run directory to validate, e.g. runs/2027-02-03-oauth-acme-asco-1")
    ap.add_argument("--changed-files", metavar="FILE", help="newline-separated list of paths changed in the PR")
    ap.add_argument("--allow-any-files", action="store_true",
                    help="don't fail on files outside runs/ (organizer PRs)")
    ap.add_argument("--registry", metavar="FILE", default=str(ROOT / "participants.yaml"),
                    help="participants.yaml to check against (default: the one in this clone)")
    ap.add_argument("--runs-root", metavar="DIR", default=str(ROOT / "runs"),
                    help="directory holding run directories (used with --changed-files)")
    args = ap.parse_args()

    report = Report()
    registry = load_registry(Path(args.registry), report)

    run_dir: Path | None
    if args.changed_files:
        changed = [l.strip() for l in Path(args.changed_files).read_text(encoding="utf-8").splitlines() if l.strip()]
        run_dir = check_scope(changed, args.allow_any_files, Path(args.runs_root), report)
    elif args.run_dir:
        run_dir = Path(args.run_dir).resolve()
        local_scope_hint(run_dir, report)
    else:
        ap.error("give a run directory, or --changed-files in the workflow")

    if run_dir is not None and registry is not None:
        validate_run(run_dir, registry, report)

    title = f"validate-run: {run_dir.name}" if run_dir else "validate-run"
    report.write_summary(title)
    print()
    if report.errors:
        print(f"FAILED with {len(report.errors)} error(s) and {len(report.warnings)} warning(s).")
        return 1
    print(f"OK with {len(report.warnings)} warning(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
