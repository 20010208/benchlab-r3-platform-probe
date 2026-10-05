# External test plan (NOT executed; for after the independent audit and explicit PM approval)

Purpose: establish the GitHub-only properties that cannot be tested locally. **Nothing here runs the candidate or produces a forecast.**

## Hard constraints for every external test

* A **throwaway public repository** created only for these probes; deleted afterwards. Standard GitHub-hosted runners only (no larger runners). Expected cost: $0.
* No candidate prediction, no frozen-runner execution, no production ledger, no production variables, no secret of any kind, no participant-site access, no submission, no payment.
* Probe workflows are separate files (`probe-*.yml`), `workflow_dispatch` or `schedule` only, `permissions: {}` unless a test says otherwise, and never reference the production pins.
* Every test records its raw observations in the job summary; nothing is "interpreted away".

## Tests

| # | Property | Procedure | Pass criterion / what to record |
|---|---|---|---|
| T1 | Public standard runner availability and size | `runs-on: ubuntu-24.04`; print `nproc`, `free -m`, `df -h /`, image version, `uname -m` | 4 vCPU / 16 GB / x64 expected; Actions usage page shows 0 billable minutes |
| T2 | Container job support, apt, Python 3.10, hash-locked install | `container: public.ecr.aws/ubuntu/ubuntu:22.04`; `apt-get install git python3 python3-pip ca-certificates`; `python3 --version`; `pip install --require-hashes --only-binary=:all: --no-deps -r requirements.lock` using the real lock; `python3 -c "import numpy"` | Python 3.10.x, numpy 2.2.6 installs from the locked hash only. **Record the image digest** (needed to pin the image in the workflow). If `container:` is unsupported, fall back to a documented alternative and re-audit |
| T3 | `GITHUB_TOKEN` fast-forward ledger push | `permissions: contents: write`; create an orphan test branch; 3 sequential commits, each pushed with `git push --atomic origin HEAD:refs/heads/<branch> refs/tags/anchor-00000N` | all accepted; tags created |
| T4 | Force-push and deletion rejection (branch) | With the intended branch rule (block force pushes, restrict deletions, **no bypass actors**, no "restrict updates", no required PR): attempt force-push and deletion (a) with the Actions token, (b) as a repository admin from a local clone | all rejected. **Record the exact stderr text** — the wrapper classifies `[remote rejected]` / `GH006` / `GH013` as a rule rejection and `[rejected]` (fetch first / non-fast-forward / already exists) as a lost CAS |
| T5 | Anchor-tag protection | A tag rule for `anchor-*` (restrict deletions, block updates/force). Token creates `anchor-000001` (accepted); move and delete attempts (token and admin) | creation allowed, move/delete rejected. If a tag rule also blocks creation, the in-run anchor verification plus a mirror remain the defence; record it |
| T6 | Ruleset availability | Settings UI on a free-plan public repo; if rulesets are unavailable, test classic branch protection with "include administrators" | state which mechanism exists for branches and for tags |
| T7 | Atomic CAS under real concurrency | A matrix of 16 jobs, each preparing the same next record (distinct nonces) and doing an atomic push at a shared barrier time | exactly one succeeds; the others are rejected with the recorded text |
| T8 | Variable write rejection and visibility | In a job with `contents: write`, try to create/update an Actions variable with `GITHUB_TOKEN` (REST API); read `vars.*` in schedule and dispatch runs | write denied; variables visible to both triggers |
| T9 | Workflow identity observation | Print `github.workflow_sha`, `github.sha`, `GITHUB_SHA`, `github.ref`, `github.workflow_ref`, and the git blob hash of the workflow file at those commits — in a scheduled run, a dispatch run on the default branch, and a dispatch on another branch (the `if: github.ref == 'refs/heads/main'` guard must stop it) | establishes whether `workflow_sha` is usable as secondary evidence and what the schedule event's SHA means |
| T10 | Runner clock | `date -u +%s.%N` against the HTTP `Date` header of github.com and of the data hosts | skew in seconds; the 40-minute window and 13-minute lease tolerate seconds |
| T11 | Data endpoint reachability | `curl --max-time 20 --retry 0` GET of: SWPC `rtsw_wind_1m.json`, SWPC `ace_swepam_1h.json`, one tiny CDAWeb HAPI request for `AC_K0_SWE` with a one-hour window. Record status, bytes, time, `Date` header; store no content | reachable with sane latency from a GitHub runner; sizes recorded (replaces the current UNKNOWN feed sizes) |
| T12 | Schedule observation | A probe with the same cron `7,17,27,37 0,6,12,18 * * *` that only logs `date -u` and the nominal minute; observe at least 7 days (28 origins × 4 wakes) | delay distribution, number of dropped wakes, per-origin chance that no wake starts within 40 minutes. Also monitor whether bot commits count as activity for the 60-day inactivity rule (cannot be settled in a week; keep a monthly manual keep-alive in the runbook until known) |
| T13 | Fetch by exact SHA | `git fetch --depth=1` of a reachable (non-tip) commit from the throwaway repo; `git fetch` of the pinned upstream commit `600bdcd5…` from the public upstream | both succeed on GitHub (the wrapper and workflow rely on it) |

## After the tests

Record the raw observations next to the audit; update `docs/PINS.md` and the workflow (digest pin, any rule-text findings); regenerate every pin; re-audit. Delete the throwaway repository.
