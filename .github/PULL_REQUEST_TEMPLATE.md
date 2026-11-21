<!--
Thank you for submitting a run. Keep the sections below; the attestation
checkbox is read by a workflow. Replace the placeholders in <angle brackets>.
Leave this block in place; it isn't shown in the rendered description.
-->

## Run

- Run ID: `<run-id>`
- Flow: <oauth | cimd | ema>
- Submitting organization: `<slug>`
- Other organizations in this run: <slugs, or "none (tool counterpart)">

## Notes for the organizer

<Anything that helps a reader follow the run: which log file to start from, known gaps, why a cache fetch is missing, and so on. Optional.>

## Submitter's attestation

Tick this box only if the statement is true for your organization's part(s) of this run. Replace `<organization>` with your organization's name.

- [ ] I am authorized to attest for <organization>. The log files listed for our part(s) of this run are raw, unmodified output from our implementation, or from the tenant of our service used in this run, with only tokens and secrets redacted. They record what our implementation actually did during the run window stated in run.yaml.

## Checklist

- [ ] I ran `python3 scripts/validate_run.py runs/<run-id>` locally and it passed.
- [ ] This PR adds exactly one directory under `runs/` and changes nothing else.
- [ ] Every file under `logs/` is plain text, listed in `run.yaml`, and has tokens and secrets replaced with `[REDACTED]`.
- [ ] All timestamps in the logs fall inside `run_window`, and the lines were captured during the run, not reconstructed afterwards.
- [ ] `correlation` names the values that tie the parties' lines together.

<!--
What happens next: the checks run, and a bot comment lists each organization
that still needs to attest, with the exact `/attest <commit>` line to post.
Pushing a new commit resets all attestations.
-->
