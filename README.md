# MCP Security Interop, Gartner IAM Summit London (March 2027)

Test results for the OpenID Foundation AI Identity Management (AIIM) Community Group's MCP Security Interop. Every run here is public evidence: raw logs from each participating implementation, attested by the organization that produced them, and reviewed by the organizer before merging.

> **Pilot repository.** Everything in this repository is fabricated test data marked `TEST`. The production repository will live under the OpenID Foundation organization. Event dates and the submission deadline: TODO.

Organizer: Atul Tulshibagwale ([@tulshi](https://github.com/tulshi)). The organizer reviews every submission and decides each cell of the Results Matrix.

## How it works

Three steps turn a test run into a merged result.

1. **One participant submits the whole run.** Any organization that took part in a run can upload all of its logs, including the lines that cover the other organizations' parts. If you used another participant's hosted service through a tenant you control, export the tenant's logs yourself and submit them as part of the run.
2. **Each organization attests to its own part.** Attesting means confirming that the logs for your part are genuine, unmodified output of your implementation (or of your service's tenant used in the run), and that they record what it actually did. The submitter attests in the pull request description; everyone else attests with a comment. Details below.
3. **The organizer reviews and merges.** A merged run is evidence. It is not a grade. The organizer applies the flow rules below when filling in the matrix.

Each organization's attesters are listed in [`participants.yaml`](participants.yaml). Only handles listed there can attest, and only for their own organization. If your handle is missing or wrong, ask the organizer; participants can't edit the registry.

## Submitting a run

You need to be a collaborator on this repository (the organizer invites every attester) and listed as an attester for the organization you're submitting for.

1. Fork this repository and create a branch.
2. Add one directory `runs/<run-id>/` containing:
   - `run.yaml`, described below;
   - `logs/`, holding the raw log files;
   - optionally `README.md` with correlation notes in prose.
3. Run the validator locally. It's the same script the pull request check runs, so a run that passes here passes `validate-run`:

   ```
   python3 -m pip install -r scripts/requirements.txt
   python3 scripts/validate_run.py runs/<run-id>
   ```

   It checks the structure of `run.yaml`, that every slug and implementation id is in the registry, that the roles and claims fit the flow, that every log file is listed and is plain text, that nothing looks like an unredacted secret, and that log timestamps fall inside `run_window`. Errors block the PR; warnings are for you and the organizer to look at.
4. Open a pull request. The template asks you to tick the submitter's attestation box. Tick it only if the statement is true for your organization's part(s).
5. Wait for the checks. `validate-run` repeats the checks above and also confirms the PR touches only your run directory; `attestations-complete` tracks who still needs to attest. The bot posts one summary comment on the PR and keeps it up to date.
6. Fix anything the checks report by pushing to your branch. Note that a new push resets every attestation, so try to get the content right before asking others to attest.

One pull request covers exactly one run, and it may only touch files under its own `runs/<run-id>/` directory.

### Run ID

`YYYY-MM-DD-<flow>-<org1>-<org2>[-<org3>]-<n>`, where the date is the run date in UTC, `flow` is `oauth`, `cimd` or `ema`, the org segments are slugs from `participants.yaml` in the same order as the `parts` list, and `n` distinguishes repeated runs between the same organizations on the same day. Example: `2027-02-03-ema-acme-idpco-asco-1`.

### run.yaml

```yaml
run_id: 2027-02-03-oauth-acme-asco-1
flow: oauth
run_window:
  start: "2027-02-03T14:00:00Z"
  end: "2027-02-03T14:20:00Z"
submitted_by: acme
parts:
  - role: mcp-client
    org: acme
    implementation: acme-mcp-client
    operator: Jane Doe
    logs:
      - logs/acme-client.log
    log_source: Acme agent client debug log, captured on the operator's laptop.
    claims: [oprm, scoped-access]
  - role: mcp-server
    org: asco
    implementation: asco-mcp-server
    operator: Sam Lee
    logs:
      - logs/asco-server.log
    log_source: >
      AS Co server tenant `acme-test`, exported by Acme from the AS Co admin console.
    claims: [oprm, www-authenticate-scope, scoped-access]
correlation: >
  Prose explaining how to match the lines across the files ...
```

Field by field:

| Field | Meaning |
|---|---|
| `run_id` | Must equal the directory name. |
| `flow` | `oauth`, `cimd` or `ema`. |
| `run_window` | Start and end of the run in UTC, ISO 8601 with a trailing `Z`. Log timestamps should fall inside it. |
| `submitted_by` | Slug of the organization opening the PR. The PR author must be one of its attesters. |
| `parts[].role` | `mcp-client`, `mcp-server`, `op`, `resource-as` or `gateway`. |
| `parts[].org` | Slug of the organization (or tool) that played the role. |
| `parts[].implementation` | Implementation id from the registry. |
| `parts[].operator` | Name of the person who operated this side during the run. If the same person appears on two parts, the run is marked provisional. |
| `parts[].logs` | Paths under `logs/` holding the raw lines for this part. Every file under `logs/` must be referenced by some part. |
| `parts[].log_source` | Where the lines came from. If another participant exported them from a tenant of your service, say so here. |
| `parts[].claims` | The matrix rows this part's evidence is offered for. These are claims, not grades. Allowed values per flow are listed below. |
| `correlation` | Prose (at least 200 characters) telling a reader how to match each party's lines to the others': which timestamps, request IDs, `jti`, `client_id`, `kid`, `sub`, `cf-ray` and so on tie them together. It must name at least one of the log files. |

The schema is in [`schema/run.schema.json`](schema/run.schema.json).

## Attesting

An attestation is this statement, made by a handle listed under your organization's `attesters`:

> I am authorized to attest for *organization*. The log files listed for our part(s) of this run are raw, unmodified output from our implementation, or from the tenant of our service used in this run, with only tokens and secrets redacted. They record what our implementation actually did during the run window stated in run.yaml.

**If you submitted the run**, tick the attestation box in the PR description. The bot checks the box and checks that your handle is an attester for `submitted_by`.

**If another organization submitted the run**, you'll be requested as a reviewer so that GitHub notifies you. Read the logs for your part, then post a comment on the PR:

```
/attest <commit>
```

where `<commit>` is the PR's current head commit. The bot's summary comment shows the exact line to paste, so you can copy it from there. The command must be at the start of a line in your comment; you can add a note after it.

Some things to know:

- Your attestation covers only your own organization's parts. One comment covers all of them if your organization holds several.
- It applies to one commit. If the submitter pushes again, the bot asks everyone to attest the new commit. This is deliberate: you are attesting to specific content, and the public record shows which content that was.
- A GitHub approval does not count as an attestation, and neither does a comment from a handle not listed in `participants.yaml`. The submitter's checkbox and the submitter's comments don't count for other organizations either.
- If the logs for your part don't look like your implementation's output, don't attest. Say so in a comment instead; the organizer will follow up.
- If your logs were exported by another participant from a tenant of your service, you still attest. You're confirming the lines are genuine output of your service, not that you exported them.

Tool parts (for example MCP Inspector) have no attesters and need no attestation. The run is marked provisional.

When every required attestation is in place for the current commit, `attestations-complete` turns green, the PR gets the `ready-for-organizer` label, and the organizer is asked to review.

### Keeping the status up to date

For pull requests from forks, GitHub runs the attestation check with a token that can only write when the trigger is the PR itself or a comment on it. A comment triggers a re-check immediately, so posting `/attest` updates the summary within a minute or two. If a status ever looks stale (for example after a reviewer request fails), anyone can post `/recheck` on the PR.

### Access notes

- Participants have the Read role. That is enough to fork, open PRs, be requested as a reviewer and comment.
- Branch protection requires both checks to pass and a review from the code owner (the organizer) before merging. The organizer is the only person who can merge. Protection is not enforced on administrators, so the organizer can land registry and documentation changes without a second reviewer.

## What counts as evidence

The logs must be independently verifiable. The organizer, or anyone reading this public repository, should be able to follow the run across all parties' logs without trusting a summary. Keep these in mind when you prepare a submission.

- **Raw, unmodified lines.** Submit what your implementation wrote, with tokens and secrets redacted. Summaries, harness PASS/FAIL output, reformatted or trimmed excerpts, telemetry bullets and screenshots don't qualify on their own. They're welcome in the run's `README.md` as a guide to the raw files.
- **Run-time evidence only.** Headers, metadata documents and challenge contents captured after the run don't count. For example, the 401's `WWW-Authenticate` header (`resource_metadata` and `scope`) must appear in a timestamped raw line from the run, not in a `curl` done later.
- **Include what ties the parties together.** Where your implementation logs them, keep timestamps in UTC, request IDs, `jti`, `client_id`, `kid`, `sub`, and `cf-ray` for Cloudflare-fronted services (the part before the dash is the request ID). These are examples; log what your implementation logs. Then explain the matching in `correlation`.
- **Watch for cache hits.** A cached metadata or JWKS fetch won't appear in the logs. If a row depends on the fetch happening, clear caches before the run.
- **Redact carefully.** Replace token and secret values with a marker such as `[REDACTED]` and leave the rest of the line intact. Don't redact identifiers needed for correlation (`jti`, `kid`, request IDs). The validator fails on PEM private keys and warns on things that look like unredacted JWTs, bearer tokens and client secrets.
- **Text only.** Log files must be plain text. Images and binaries are rejected.

## Flows, roles and claims

The matrix rows below are the allowed `claims` values. The validator only checks that a claim is valid for the flow and role; the organizer decides whether the evidence supports it.

### OAuth (MCP Client ↔ MCP Server)

Roles: `mcp-client`, `mcp-server`, or a `gateway` in either place. The OP and Resource AS roles are N.A.

| Claim | Row |
|---|---|
| `oprm` | OAuth Protected Resource Metadata support |
| `www-authenticate-scope` | `scope` parameter in `WWW-Authenticate` |
| `scoped-access` | Access using an appropriately scoped token |

A cell qualifies when `oprm` and `scoped-access` are both evidenced.

### CIMD (MCP Client ↔ OAuth AS)

Roles: `mcp-client` (or `gateway`) and `resource-as`. The MCP Server role is N.A. The `client_id` is a metadata URL the AS dereferences directly.

| Claim | Row |
|---|---|
| `cimd-preregistered` | Metadata: client pre-registered by metadata URL |
| `cimd-redirect-uris` | Metadata: `redirect_uris` taken from metadata |
| `cimd-jwks-uri` | Metadata: `jwks_uri` taken from metadata |
| `cimd-jwks` | Metadata: inline `jwks` taken from metadata |
| `grant-code-pkce` | Grant: authorization code with PKCE |
| `grant-client-credentials` | Grant: client credentials |
| `auth-private-key-jwt` | Client authentication: `private_key_jwt` |
| `auth-mtls` | Client authentication: mutual TLS |
| `auth-none-public` | Client authentication: none (public client) |

A cell qualifies with at least one metadata row plus at least one grant row. `private_key_jwt` or MTLS gives ✅; a public client gives "✅ (public)". A client secret doesn't count in CIMD.

### EMA / ID-JAG (MCP Client, OP, Resource AS)

Roles: `mcp-client` (or `gateway`), `op` and `resource-as`. The MCP Server role is N.A.

| Claim | Row |
|---|---|
| `valid-id-jag` | Valid ID-JAG issued and accepted (required) |
| `id-jag-resource` | `resource` handled correctly |
| `id-jag-scope` | `scope` handled correctly |
| `id-jag-sub-id` | Subject identifier handled correctly |

The OP's part must include the OP's own logs showing it issued the ID-JAG in that run, matched on time, `jti` and `sub`, and the OP must attest. An AS verifying the ID-JAG against the OP's published keys is not enough on its own. A green ✅ needs three different organizations; if one organization holds two roles the result is ☑️ at most.

### Gateways

In OAuth, a gateway needs both its MCP Client and its MCP Server halves evidenced. In CIMD and EMA, a gateway needs only the MCP Client criterion.

### Provisional results

A run is marked provisional ☑️ when a common tool (such as MCP Inspector) is the counterpart, or when the same `operator` appears on two or more parts, or when an EMA run has fewer than three organizations. The bot points these out in its summary. A pending attestation is not provisional: the run simply isn't ready.

### Symbols

| Symbol | Meaning |
|---|---|
| ✅ | Qualified |
| ☑️ | Provisional |
| ✅ (public) | CIMD, public client only |
| N.A.✅ | Credit for one half of a Gateway cell |
| N.A. | Not applicable |

## Repository layout

```
README.md                     this file
participants.yaml             registry of organizations and their attesters
runs/<run-id>/                one directory per run: run.yaml, logs/, optional README.md
schema/                       JSON Schemas for run.yaml and participants.yaml
scripts/                      validation and attestation logic used by the workflows
.github/workflows/            validate-run.yml and attestations.yml
test/fixtures/                sample runs used to test the pilot; not part of production
```
