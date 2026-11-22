"""Offline exercise of scripts/attestations.py against a fake GitHub API.

Not part of the repository's workflows; run with:
    python3 -I test/attestations_offline.py
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import attestations as A  # noqa: E402

RUN_OAUTH = """
run_id: 2027-02-03-oauth-acme-asco-1
flow: oauth
submitted_by: acme
run_window: {start: "2027-02-03T14:00:00Z", end: "2027-02-03T14:20:00Z"}
parts:
  - {role: mcp-client, org: acme, implementation: acme-mcp-client, operator: Jane Doe, logs: [logs/a.log], log_source: x, claims: [oprm]}
  - {role: mcp-server, org: asco, implementation: asco-mcp-server, operator: Sam Lee, logs: [logs/b.log], log_source: x, claims: [oprm]}
correlation: x
"""
RUN_EMA_TOOL = """
run_id: 2027-02-03-ema-inspector-asco-idpco-1
flow: ema
submitted_by: asco
run_window: {start: "2027-02-03T14:00:00Z", end: "2027-02-03T14:20:00Z"}
parts:
  - {role: mcp-client, org: inspector, implementation: mcp-inspector, operator: Sam Lee, logs: [logs/a.log], log_source: x, claims: [valid-id-jag]}
  - {role: resource-as, org: asco, implementation: asco-as, operator: Sam Lee, logs: [logs/b.log], log_source: x, claims: [valid-id-jag]}
  - {role: op, org: idpco, implementation: idpco-op, operator: Pat, logs: [logs/c.log], log_source: x, claims: [valid-id-jag]}
correlation: x
"""
RUN_EMA_FULL = """
run_id: 2027-02-03-ema-acme-idpco-asco-1
flow: ema
submitted_by: acme
run_window: {start: "2027-02-03T14:00:00Z", end: "2027-02-03T14:20:00Z"}
parts:
  - {role: mcp-client, org: acme, implementation: acme-mcp-client, operator: Jane Doe, logs: [logs/a.log], log_source: x, claims: [valid-id-jag]}
  - {role: op, org: idpco, implementation: idpco-op, operator: Pat, logs: [logs/c.log], log_source: x, claims: [valid-id-jag]}
  - {role: resource-as, org: asco, implementation: asco-as, operator: Sam Lee, logs: [logs/b.log], log_source: x, claims: [valid-id-jag]}
correlation: x
"""

BOX = "- [x] I am authorized to attest for Acme Corp. The log files listed ..."


class Fake(A.GitHub):
    def __init__(self, run_yaml, author="aaronpk", body=BOX, comments=(), head="abcdef1234567890", labels=(), run_id="2027-02-03-oauth-acme-asco-1"):
        super().__init__("t", "tulshi/test-interop")
        self.run_yaml, self.author, self.body, self.head, self.run_id = run_yaml, author, body, head, run_id
        self.comments = [dict(id=i, body=b, user={"login": u, "type": "User"}, created_at="2027-02-03T15:00:00Z") for i, (u, b) in enumerate(comments)]
        self.labels = list(labels)
        self.calls: list[tuple[str, str, dict | None]] = []

    def request(self, method, path, body=None, ok=(200, 201, 204), raw=False):
        self.calls.append((method, path, body))
        h = {}
        if method == "GET":
            if path.endswith(f"/pulls/7"):
                return 200, {"number": 7, "state": "open", "html_url": "u", "body": self.body,
                             "user": {"login": self.author}, "head": {"sha": self.head, "repo": {"full_name": "aaronpk/test-interop"}},
                             "requested_reviewers": [], "labels": [{"name": l} for l in self.labels]}, h
            if "/pulls/7/files" in path:
                return 200, [{"filename": f"runs/{self.run_id}/run.yaml"}, {"filename": f"runs/{self.run_id}/logs/a.log"}], h
            if "/issues/7/comments" in path:
                return 200, self.comments, h
            if "/contents/" in path:
                return 200, {"encoding": "base64", "size": 10, "content": base64.b64encode(self.run_yaml.encode()).decode()}, h
        if method == "POST" and "requested_reviewers" in path and body and "ghost" in json.dumps(body):
            raise A.ApiError(422, method, path, "Reviews may only be requested from collaborators")
        return 201, {}, h


def run(label, fake):
    import os
    os.environ.update(GITHUB_TOKEN="t", GITHUB_REPOSITORY="tulshi/test-interop", GITHUB_EVENT_NAME="workflow_dispatch", PR_NUMBER="7")
    os.environ.pop("GITHUB_EVENT_PATH", None)
    real = A.GitHub
    A.GitHub = lambda token, repo: fake
    print(f"\n==== {label}")
    try:
        A.main()
    finally:
        A.GitHub = real
    for m, p, b in fake.calls:
        if m != "GET":
            short = json.dumps(b)[:160] if b else ""
            if "/issues/7/comments" in p and b:
                print(f"  {m} {p.split('/repos/tulshi/test-interop')[1]}")
                print("    " + b["body"].replace("\n", "\n    "))
            else:
                print(f"  {m} {p.split('/repos/tulshi/test-interop')[1]} {short}")


if __name__ == "__main__":
    run("1 fresh OAuth PR, box ticked, nobody else yet -> pending, request tulshi", Fake(RUN_OAUTH))
    run("2 box not ticked -> pending on submitter", Fake(RUN_OAUTH, body="- [ ] I am authorized to attest for Acme"))
    run("3 author not an attester for submitted_by -> failure", Fake(RUN_OAUTH, author="someone"))
    run("4 tulshi attests current head -> success, label, organizer review", Fake(RUN_OAUTH, comments=[("tulshi", "/attest abcdef1 looks good")]))
    run("5 tulshi attests an old sha -> ignored", Fake(RUN_OAUTH, comments=[("tulshi", "/attest 1111111")]))
    run("6 unregistered handle attests -> ignored", Fake(RUN_OAUTH, comments=[("ghost-attester-test", "/attest abcdef1")]))
    run("7 submitter (aaronpk) tries to /attest for asco -> ignored", Fake(RUN_OAUTH, comments=[("aaronpk", "/attest abcdef1")]))
    run("8 bare /attest without sha -> ignored with hint", Fake(RUN_OAUTH, comments=[("tulshi", "/attest")]))
    run("9 EMA with tool + same operator + 2 orgs, submitted by asco(tulshi) -> idpco pending; tulshi can't comment-attest for idpco",
        Fake(RUN_EMA_TOOL, author="tulshi", body=BOX.replace("Acme Corp", "AS Co"), run_id="2027-02-03-ema-inspector-asco-idpco-1",
             comments=[("tulshi", "/attest abcdef1")]))
    run("10 success previously, label present, new head -> label removed, pending", Fake(RUN_OAUTH, labels=["ready-for-organizer"], head="fedcba9876543210"))
    run("12 full EMA, tulshi attests for idpco and asco in one comment -> success, note about two orgs",
        Fake(RUN_EMA_FULL, run_id="2027-02-03-ema-acme-idpco-asco-1", comments=[("tulshi", "/attest abcdef1")]))

    # unrequestable reviewer
    reg = A.load_registry(); reg["orgs"]["asco"]["attesters"].append("ghost-attester-test")
    A.load_registry = lambda: reg
    run("11 attester without repo access -> access notice", Fake(RUN_OAUTH))
