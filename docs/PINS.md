# Pin store (FUTURE GitHub Actions variables) — placeholders and instructions only; nothing here has been configured

The identity gate compares what runs against values kept in an **independent store** (repository or environment Actions variables), not in the code that is being verified.
Repository variables can be created/edited with write access (collaborator on a personal repository); environment variables need owner/admin. Neither can be changed by a git push alone.
Use a restricted environment if the plan allows it; the workflow file does not require one.

| Variable | Value | How to compute (after the R3 ops commit is final and reviewed) |
|---|---|---|
| `OPS_COMMIT_PIN` | 40-hex commit SHA of the audited ops commit | `git rev-parse HEAD` |
| `OPS_WRAPPER_SHA256_PIN` | 64-hex SHA-256 of `shadow_ops_r3.py` | `sha256sum shadow_ops_r3.py` |
| `WORKFLOW_BLOB_PIN` | 40-hex git blob hash of `.github/workflows/shadow.yml` | `git rev-parse HEAD:.github/workflows/shadow.yml` |
| `DEP_LOCK_SHA256_PIN` | 64-hex SHA-256 of `requirements.lock` | `sha256sum requirements.lock` |
| `CANDIDATE_SOURCE_URL` | `https://github.com/<owner>/<repo>` holding `refs/tags/phase2d-freeze` | decided by the PM together with where the candidate history is published |

The candidate SHA (`422f73d5…`), tag, and the upstream commit (`600bdcd5…`) are constants inside the wrapper, so they are covered by `OPS_WRAPPER_SHA256_PIN`.

## Rules

* Any change to any tracked file means a new reviewed commit and **new pins**; a running schedule with stale pins fails closed (exit 22, durable HALT).
* A missing or malformed variable is a configuration error (exit 2): nothing is written. A well-formed mismatch is an integrity failure: durable HALT.
* The default branch must only change by deliberate, reviewed commits (the ledger lives on its own branch, so ledger writes never move it).
* `init-ledger` is run once by a human with the same pins before the schedule is enabled; it refuses to run if the ledger branch or any anchor already exists.
* Keep an independent mirror of the ledger branch and its tags (a local clone fetched periodically, or a fork). The mirror is the only defence against a coordinated ledger+anchor rewrite.

## Activation checklist (NOT executed; for the post-audit decision)

1. Resolve candidate publication, license position and identity questions (`docs/PUBLICATION.md`).
2. Run the external test plan (`docs/EXTERNAL_TEST_PLAN.md`) in a throwaway repository and review the results.
3. Pin the container image by digest; regenerate the workflow blob hash and every pin; re-audit.
4. Create the repository variables; run `check-ops`; run `init-ledger`; add ledger-branch and anchor-tag protection (block force pushes and deletions, no bypass actors; do **not** use "restrict updates" or required pull requests on the ledger branch).
5. Enable the schedule only after sign-off.
