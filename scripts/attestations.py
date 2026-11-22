#!/usr/bin/env python3
"""Compute the attestation status of a run submission pull request.

Runs from .github/workflows/attestations.yml on pull_request_target,
issue_comment and workflow_dispatch. It never checks out or executes anything
from the pull request. run.yaml is read from the PR head through the GitHub
API as data and parsed with yaml.safe_load; participants.yaml comes from the
base branch checkout.

What it does:

  * works out which organizations must attest (every organization in parts,
    excluding tools);
  * checks the submitter's attestation box in the PR body and that the PR
    author is a registered attester for submitted_by;
  * counts `/attest <sha>` comments from registered attesters that name the
    PR's current head commit;
  * requests reviews from pending attesters and reports handles that can't be
    requested (no repository access);
  * posts or updates one summary comment;
  * sets the `attestations-complete` commit status and, when it's green, adds
    the `ready-for-organizer` label and requests the organizer's review.

Environment: GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_NAME,
GITHUB_EVENT_PATH, optionally PR_NUMBER (workflow_dispatch).
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
API = "https://api.github.com"
STATUS_CONTEXT = "attestations-complete"
READY_LABEL = "ready-for-organizer"
SUMMARY_MARKER = "<!-- interop-attestations -->"
ACCESS_MARKER = "<!-- interop-access-notice -->"

ATTEST_LINE = re.compile(r"^\s*/attest\b[ \t]*([0-9a-fA-F]{7,40})?\b.*$", re.M)
RECHECK_LINE = re.compile(r"^\s*/recheck\b", re.M)
CHECKBOX = re.compile(r"^\s*[-*]\s*\[[xX]\]\s*I am authorized to attest for\b", re.M)
RUN_PATH = re.compile(r"^runs/([A-Za-z0-9._-]+)/")
SAFE_RUN_ID = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}-[a-z]+-[a-z0-9-]+-[0-9]+$")

ATTESTATION_TEXT = (
    "I am authorized to attest for {org}. The log files listed for our part(s) of this run are raw, "
    "unmodified output from our implementation, or from the tenant of our service used in this run, "
    "with only tokens and secrets redacted. They record what our implementation actually did during "
    "the run window stated in run.yaml."
)


# --- GitHub API ----------------------------------------------------------------

class GitHub:
    def __init__(self, token: str, repo: str) -> None:
        self.token = token
        self.repo = repo

    def request(self, method: str, path: str, body: dict | None = None, ok=(200, 201, 204), raw=False):
        url = path if path.startswith("http") else f"{API}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "interop-attestations",
            "Content-Type": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = resp.read()
                if raw:
                    return resp.status, payload, resp.headers
                return resp.status, (json.loads(payload) if payload else None), resp.headers
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            if exc.code in ok:
                return exc.code, (json.loads(payload) if payload else None), exc.headers
            raise ApiError(exc.code, method, path, payload.decode(errors="replace")) from None

    def get(self, path: str):
        return self.request("GET", path)[1]

    def paginate(self, path: str) -> list:
        sep = "&" if "?" in path else "?"
        url = f"{API}{path}{sep}per_page=100"
        items: list = []
        while url:
            _, page, headers = self.request("GET", url)
            items.extend(page)
            url = None
            for part in (headers.get("Link") or "").split(","):
                if 'rel="next"' in part:
                    url = part[part.find("<") + 1:part.find(">")]
        return items

    def repo_path(self, suffix: str) -> str:
        return f"/repos/{self.repo}{suffix}"


class ApiError(Exception):
    def __init__(self, code: int, method: str, path: str, body: str) -> None:
        super().__init__(f"{method} {path} -> {code}: {body[:300]}")
        self.code = code


# --- Helpers ------------------------------------------------------------------

def code(value) -> str:
    """Render an untrusted value as an inline code span so it can't carry
    markdown, @mentions or table syntax."""
    text = str(value).replace("`", "'").replace("\r", " ").replace("\n", " ").replace("|", "/")
    return f"`{text[:80]}`" if text else "`?`"


def iso(ts: str) -> str:
    try:
        return dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, AttributeError):
        return ts or ""


def load_registry() -> dict:
    with open(ROOT / "participants.yaml", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    orgs = {o["slug"]: o for o in data["organizations"]}
    attester_orgs: dict[str, set[str]] = {}
    for o in data["organizations"]:
        for h in o.get("attesters") or []:
            attester_orgs.setdefault(h.lower(), set()).add(o["slug"])
    return {"organizer": data["organizer"]["github"], "orgs": orgs, "attester_orgs": attester_orgs}


def org_name(reg: dict, slug: str) -> str:
    org = reg["orgs"].get(slug)
    return org["name"] if org else slug


def attesters_of(reg: dict, slug: str) -> list[str]:
    org = reg["orgs"].get(slug)
    return list(org.get("attesters") or []) if org else []


# --- Evaluation ----------------------------------------------------------------

class Outcome:
    """Everything the summary comment and the commit status need."""

    def __init__(self) -> None:
        self.state = "pending"              # success | pending | failure
        self.description = ""
        self.run_id: str | None = None
        self.head_sha = ""
        self.rows: list[dict] = []          # one per part
        self.problems: list[str] = []       # structural failures
        self.pending: dict[str, list[str]] = {}   # org -> attester handles still needed
        self.provisional: list[str] = []
        self.ignored: list[str] = []
        self.notes: list[str] = []
        self.submitter_org: str | None = None


def find_run_dir(files: list[dict], out: Outcome) -> str | None:
    run_ids = set()
    for f in files:
        for name in (f.get("filename"), f.get("previous_filename")):
            m = RUN_PATH.match(name or "")
            if m:
                run_ids.add(m.group(1))
    if not run_ids:
        return None
    if len(run_ids) > 1:
        out.problems.append("This pull request touches more than one run directory. One pull request covers one run.")
        return None
    run_id = run_ids.pop()
    if not SAFE_RUN_ID.match(run_id):
        out.problems.append(f"Run directory name {code(run_id)} isn't a valid run ID.")
        return None
    return run_id


def fetch_run_yaml(gh: GitHub, pr: dict, run_id: str, out: Outcome) -> dict | None:
    head_repo = (pr.get("head") or {}).get("repo") or {}
    full_name = head_repo.get("full_name")
    if not full_name:
        out.problems.append("The head repository of this pull request is no longer available.")
        return None
    path = urllib.parse.quote(f"runs/{run_id}/run.yaml")
    ref = urllib.parse.quote(out.head_sha)
    try:
        data = gh.get(f"/repos/{full_name}/contents/{path}?ref={ref}")
    except ApiError as exc:
        if exc.code == 404:
            out.problems.append(f"{code(f'runs/{run_id}/run.yaml')} is missing from the pull request.")
            return None
        raise
    if not isinstance(data, dict) or data.get("encoding") != "base64" or data.get("size", 0) > 512 * 1024:
        out.problems.append("run.yaml couldn't be read (too large or not a plain file).")
        return None
    try:
        run = yaml.safe_load(base64.b64decode(data["content"]).decode("utf-8"))
    except (ValueError, yaml.YAMLError, UnicodeDecodeError):
        out.problems.append("run.yaml isn't valid YAML. See the `validate-run` check for details.")
        return None
    parts = run.get("parts") if isinstance(run, dict) else None
    well_formed = (
        isinstance(parts, list) and parts
        and all(isinstance(p, dict) and isinstance(p.get("org"), str) and isinstance(p.get("role"), str) for p in parts)
        and isinstance(run.get("submitted_by"), str)
    )
    if not well_formed:
        out.problems.append("run.yaml doesn't have the expected `submitted_by` and `parts` fields. See the `validate-run` check.")
        return None
    return run


def collect_attest_comments(comments: list[dict], head_sha: str, reg: dict, submitter: str,
                            required: list[str], out: Outcome):
    """Return {org: (handle, timestamp)} for the first valid /attest per organization.

    A handle registered as an attester for the submitting organization can't
    attest by comment: the submitter attests in the PR description, and that
    attestation never counts for another organization (rule 3)."""
    submitter_handles = {a.lower() for a in attesters_of(reg, submitter)}
    attested: dict[str, tuple[str, str]] = {}
    for c in comments:
        body = c.get("body") or ""
        user = ((c.get("user") or {}).get("login") or "")
        if not user or "/attest" not in body:
            continue
        matches = ATTEST_LINE.findall(body)
        if not matches:
            continue
        orgs = reg["attester_orgs"].get(user.lower(), set())
        when = c.get("created_at", "")
        if c.get("updated_at") and c.get("updated_at") != when:
            when = c["updated_at"]
        if not orgs:
            out.ignored.append(f"{code('/attest')} from {code(user)}: not a registered attester for any organization.")
            continue
        if user.lower() in submitter_handles:
            out.ignored.append(
                f"{code('/attest')} from {code(user)}: attesters of the submitting organization attest in the PR "
                "description, and can't attest for other organizations.")
            continue
        eligible = (orgs & set(required)) - {submitter}
        if not eligible:
            out.ignored.append(f"{code('/attest')} from {code(user)}: not an attester for any organization in this run.")
            continue
        for sha in matches:
            sha = sha.lower()
            if not sha:
                out.ignored.append(f"{code('/attest')} from {code(user)}: no commit given. Use {code('/attest ' + head_sha[:7])}.")
                continue
            if not head_sha.startswith(sha):
                out.ignored.append(f"{code('/attest ' + sha[:12])} from {code(user)}: names an earlier commit, not the current head {code(head_sha[:7])}.")
                continue
            for org in sorted(eligible):
                if org not in attested:
                    attested[org] = (user, when)
    return attested


def evaluate(gh: GitHub, reg: dict, pr: dict, run: dict, comments: list[dict], out: Outcome) -> None:
    orgs = reg["orgs"]
    author = (pr.get("user") or {}).get("login") or ""
    submitter = run["submitted_by"]
    out.submitter_org = submitter

    part_orgs = list(dict.fromkeys(p["org"] for p in run["parts"]))
    required = [o for o in part_orgs if o in orgs and orgs[o]["kind"] == "organization"]
    unknown = [o for o in part_orgs if o not in orgs]
    for o in unknown:
        out.problems.append(f"Organization {code(o)} isn't in participants.yaml.")

    # Submitter: PR author must be a registered attester for submitted_by, and the box must be ticked.
    submitter_attesters = [a.lower() for a in attesters_of(reg, submitter)]
    if submitter not in orgs or orgs[submitter]["kind"] != "organization":
        out.problems.append(f"{code('submitted_by')} {code(submitter)} isn't a registered organization.")
    elif submitter not in part_orgs:
        out.problems.append(f"The submitting organization {code(submitter)} doesn't own any part of this run.")
    elif author.lower() not in submitter_attesters:
        out.problems.append(
            f"The pull request author {code(author)} isn't a registered attester for "
            f"{code(submitter)} ({org_name(reg, submitter)}). Only a listed attester can submit for an organization.")
    box_ticked = bool(CHECKBOX.search(pr.get("body") or ""))

    # Other organizations attest by comment.
    attested = collect_attest_comments(comments, out.head_sha, reg, submitter, required, out)

    # Per-part rows
    for p in run["parts"]:
        slug, role = p["org"], p["role"]
        row = {"role": role, "org": slug, "name": org_name(reg, slug), "attesters": attesters_of(reg, slug)}
        if slug not in orgs:
            row.update(status="❌ unknown organization", when="")
        elif orgs[slug]["kind"] == "tool":
            row.update(status="not required (tool)", when="")
        elif slug == submitter:
            if box_ticked and not out.problems:
                row.update(status="✅ attested (submitter, PR description)", when="")
            elif box_ticked:
                row.update(status="⏳ pending (see problems above)", when="")
            else:
                row.update(status="⏳ pending: tick the attestation box in the PR description", when="")
                out.pending.setdefault(slug, [])
        elif slug in attested:
            handle, when = attested[slug]
            row.update(status=f"✅ attested by @{handle}", when=iso(when))
        else:
            row.update(status="⏳ pending", when="")
            out.pending.setdefault(slug, row["attesters"])
        out.rows.append(row)

    # Provisional flags
    if any(orgs.get(o, {}).get("kind") == "tool" for o in part_orgs):
        tools = ", ".join(org_name(reg, o) for o in part_orgs if orgs.get(o, {}).get("kind") == "tool")
        out.provisional.append(f"A common tool ({tools}) is one of the parts. Tools don't attest; the result can be ☑️ at most.")
    ops: dict[str, list[str]] = {}
    for p in run["parts"]:
        op = str(p.get("operator") or "").strip().casefold()
        if op:
            ops.setdefault(op, []).append(f"{p['role']} ({org_name(reg, p['org'])})")
    for parts in ops.values():
        if len(parts) > 1:
            out.provisional.append("The same operator ran more than one part: " + " and ".join(parts) + ".")
    if run.get("flow") == "ema" and len(set(required)) < 3:
        out.provisional.append(f"This EMA run has {len(set(required))} distinct organizations; a green ✅ needs three.")

    handles_used = {}
    for org, (handle, _) in attested.items():
        handles_used.setdefault(handle, []).append(org_name(reg, org))
    for handle, names in handles_used.items():
        if len(names) > 1:
            out.notes.append(f"@{handle} attested for more than one organization: {', '.join(names)}.")

    # Overall state
    if out.problems:
        out.state = "failure"
        out.description = out.problems[0]
    elif out.pending:
        out.state = "pending"
        names = [org_name(reg, o) for o in out.pending]
        done = len(required) - len(out.pending)
        out.description = f"{done} of {len(required)} organizations attested; waiting for {', '.join(names)}"
    else:
        out.state = "success"
        out.description = f"All {len(required)} organizations attested commit {out.head_sha[:7]}"
        if out.provisional:
            out.description += " (provisional)"


# --- Side effects ------------------------------------------------------------

def request_reviewers(gh: GitHub, pr: dict, reg: dict, out: Outcome, author: str) -> list[str]:
    """Request a review from every attester still needed. Returns handles that
    couldn't be requested."""
    already = {u["login"].lower() for u in pr.get("requested_reviewers") or []}
    failed = []
    for org, handles in out.pending.items():
        for h in handles:
            if h.lower() in already or h.lower() == author.lower():
                continue
            try:
                gh.request("POST", gh.repo_path(f"/pulls/{pr['number']}/requested_reviewers"), {"reviewers": [h]})
                print(f"requested review from {h} for {org}")
            except ApiError as exc:
                if exc.code == 422:
                    print(f"could not request review from {h}: {exc}")
                    failed.append(h)
                else:
                    raise
    return failed


def upsert_comment(gh: GitHub, pr_number: int, comments: list[dict], marker: str, body: str) -> None:
    body = f"{marker}\n{body}"
    existing = next((c for c in comments if (c.get("body") or "").startswith(marker)
                     and (c.get("user") or {}).get("type") == "Bot"), None)
    if existing:
        if existing["body"].strip() == body.strip():
            print("summary comment unchanged")
            return
        gh.request("PATCH", gh.repo_path(f"/issues/comments/{existing['id']}"), {"body": body})
        print("updated comment")
    else:
        gh.request("POST", gh.repo_path(f"/issues/{pr_number}/comments"), {"body": body})
        print("posted comment")


def access_notice(gh: GitHub, pr_number: int, comments: list[dict], reg: dict, failed: list[str]) -> None:
    if not failed:
        return
    existing = next((c for c in comments if (c.get("body") or "").startswith(ACCESS_MARKER)), None)
    known = set()
    if existing:
        known = {m.lower() for m in re.findall(r"@([A-Za-z0-9-]+)", existing["body"])}
    new = [h for h in failed if h.lower() not in known]
    if existing and not new:
        return
    handles = sorted(known | {h.lower() for h in failed})
    mentions = " ".join(f"@{h}" for h in handles)
    body = (
        f"{ACCESS_MARKER}\n{mentions}: I couldn't request your review on this pull request. That usually means "
        f"the invitation to this repository hasn't been accepted yet. Once you have access "
        f"(ask the organizer @{reg['organizer']} if you don't have an invitation), post `/recheck` here."
    )
    if existing:
        gh.request("PATCH", gh.repo_path(f"/issues/comments/{existing['id']}"), {"body": body})
    else:
        gh.request("POST", gh.repo_path(f"/issues/{pr_number}/comments"), {"body": body})


def render_summary(reg: dict, out: Outcome, pr_url: str) -> str:
    lines = []
    title = f"### Attestations for {code(out.run_id)}" if out.run_id else "### Attestations"
    lines += [title, "", f"Head commit {code(out.head_sha[:7])}. Attestations apply to this commit only; a new push resets them.", ""]
    if out.problems:
        lines += ["**Problems**", ""] + [f"- {p}" for p in out.problems] + [""]
    if out.rows:
        lines += ["| Part | Organization | Attesters | Status | When |", "|---|---|---|---|---|"]
        for r in out.rows:
            att = ", ".join(f"`{h}`" for h in r["attesters"]) or "—"
            lines.append(f"| {code(r['role'])} | {r['name'] if r['org'] in reg['orgs'] else code(r['org'])} | {att} | {r['status']} | {r['when']} |")
        lines.append("")
    if out.pending:
        still = []
        for org, handles in out.pending.items():
            if org == out.submitter_org:
                continue
            still.append(f"{' '.join('@' + h for h in handles)} for {org_name(reg, org)}")
        if still:
            lines += [
                "**Still needed:** " + "; ".join(still) + ".",
                "",
                "To attest, post a comment containing this line:",
                "",
                "```",
                f"/attest {out.head_sha[:7]}",
                "```",
                "",
                "By posting it you confirm: _" + ATTESTATION_TEXT.format(org="your organization") + "_",
                "",
            ]
        if out.submitter_org in out.pending:
            lines += [f"The submitter still needs to tick the attestation box in the PR description.", ""]
    if out.provisional:
        lines += ["**Provisional ☑️**", ""] + [f"- {p}" for p in out.provisional] + [""]
    if out.notes:
        lines += [f"- {n}" for n in out.notes] + [""]
    if out.ignored:
        lines += ["<details><summary>Comments that didn't count</summary>", ""] + [f"- {i}" for i in out.ignored] + ["", "</details>", ""]
    icon = {"success": "✅", "pending": "⏳", "failure": "❌"}[out.state]
    lines += [f"{icon} `{STATUS_CONTEXT}`: **{out.state}**. {out.description}",
              "", "_Post `/recheck` to refresh this comment._"]
    return "\n".join(lines)


def set_status(gh: GitHub, out: Outcome, target_url: str) -> None:
    desc = out.description
    desc = re.sub(r"`|\*", "", desc)
    if len(desc) > 140:
        desc = desc[:137] + "..."
    gh.request("POST", gh.repo_path(f"/statuses/{out.head_sha}"), {
        "state": out.state, "context": STATUS_CONTEXT, "description": desc, "target_url": target_url,
    })
    print(f"status {STATUS_CONTEXT}={out.state}: {desc}")


def ensure_label(gh: GitHub) -> None:
    try:
        gh.request("POST", gh.repo_path("/labels"), {
            "name": READY_LABEL, "color": "0e8a16",
            "description": "All attestations are in; waiting for the organizer's review",
        }, ok=(201, 422))
    except ApiError as exc:
        print(f"could not ensure label: {exc}")


def finalize(gh: GitHub, pr: dict, reg: dict, out: Outcome) -> None:
    labels = {l["name"] for l in pr.get("labels") or []}
    n = pr["number"]
    if out.state == "success":
        if READY_LABEL not in labels:
            ensure_label(gh)
            gh.request("POST", gh.repo_path(f"/issues/{n}/labels"), {"labels": [READY_LABEL]})
            print(f"added label {READY_LABEL}")
        organizer = reg["organizer"]
        requested = {u["login"].lower() for u in pr.get("requested_reviewers") or []}
        author = ((pr.get("user") or {}).get("login") or "").lower()
        if organizer.lower() not in requested and organizer.lower() != author:
            try:
                gh.request("POST", gh.repo_path(f"/pulls/{n}/requested_reviewers"), {"reviewers": [organizer]})
                print(f"requested review from organizer {organizer}")
            except ApiError as exc:
                print(f"could not request organizer review: {exc}")
    elif READY_LABEL in labels:
        gh.request("DELETE", gh.repo_path(f"/issues/{n}/labels/{urllib.parse.quote(READY_LABEL)}"), ok=(200, 404))
        print(f"removed label {READY_LABEL}")


# --- Main ----------------------------------------------------------------------

def pr_number_from_event() -> tuple[int, dict, bool]:
    """Return (pr number, event payload, whether reviewer requests should go out)."""
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    event = {}
    path = os.environ.get("GITHUB_EVENT_PATH")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            event = json.load(fh)
    if event_name == "pull_request_target":
        return int(event["pull_request"]["number"]), event, event.get("action") != "edited"
    if event_name == "issue_comment":
        issue = event.get("issue") or {}
        if not issue.get("pull_request"):
            print("comment is not on a pull request; nothing to do")
            sys.exit(0)
        body = (event.get("comment") or {}).get("body") or ""
        if not (ATTEST_LINE.search(body) or RECHECK_LINE.search(body)):
            print("comment has no /attest or /recheck line; nothing to do")
            sys.exit(0)
        return int(issue["number"]), event, bool(RECHECK_LINE.search(body))
    if event_name == "workflow_dispatch":
        raw = os.environ.get("PR_NUMBER") or (event.get("inputs") or {}).get("pr") or ""
        if not raw.strip().isdigit():
            sys.exit("PR_NUMBER must be a pull request number")
        return int(raw), event, True
    sys.exit(f"unsupported event {event_name!r}")


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        sys.exit("GITHUB_TOKEN and GITHUB_REPOSITORY are required")
    gh = GitHub(token, repo)
    reg = load_registry()
    number, _event, do_requests = pr_number_from_event()

    pr = gh.get(gh.repo_path(f"/pulls/{number}"))
    if pr.get("state") != "open":
        print(f"PR #{number} is {pr.get('state')}; nothing to do")
        return 0
    author = (pr.get("user") or {}).get("login") or ""
    out = Outcome()
    out.head_sha = pr["head"]["sha"]

    files = gh.paginate(gh.repo_path(f"/pulls/{number}/files"))
    out.run_id = find_run_dir(files, out)
    if out.run_id is None and not out.problems:
        # Housekeeping PR (docs, registry, workflows): nothing to attest.
        out.state, out.description = "success", "No run in this pull request; nothing to attest"
        set_status(gh, out, pr["html_url"])
        return 0

    comments = gh.paginate(gh.repo_path(f"/issues/{number}/comments"))
    if out.run_id:
        run = fetch_run_yaml(gh, pr, out.run_id, out)
        if run is not None:
            evaluate(gh, reg, pr, run, comments, out)
    if out.problems and out.state != "failure":
        out.state, out.description = "failure", out.problems[0]

    failed = []
    if do_requests and out.state != "failure":
        failed = request_reviewers(gh, pr, reg, out, author)
    upsert_comment(gh, number, comments, SUMMARY_MARKER, render_summary(reg, out, pr["html_url"]))
    access_notice(gh, number, comments, reg, failed)
    set_status(gh, out, pr["html_url"])
    finalize(gh, pr, reg, out)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(render_summary(reg, out, pr["html_url"]) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
