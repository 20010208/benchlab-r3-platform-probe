# benchlab-shadow-ops-r3 — GitHub Actions shadow operations for the frozen Phase 2D candidate (R3)

**Status: LOCAL CANDIDATE. Not published, not installed, not enabled, never triggered. No ledger exists. This is not an activation approval.**

R3 runs the **frozen** scientific runner (`tools/shadow_run.py` of candidate `ace-ridge-v4-p2d`, freeze commit `422f73d566d8a1715bf196749621a9f4138d5fd4`, tag `phase2d-freeze`) once per canonical six-hourly UTC origin
and records every attempt in a durable, hash-chained, git-anchored ledger on an orphan branch (`shadow-ledger`). It changes no model behaviour and never edits a frozen file.
The Windows R2 wrapper (separate repository, audited) remains the fallback and is untouched.

## One wake, in order (`python3 shadow_ops_r3.py run`)

1. **Ops identity gate** — pins from the independent store (below) must equal what actually runs. No ledger mutation happens before this gate; the only write on a *mismatch* is the fail-closed HALT.
2. **Canonical origin / window** — latest origin in {00,06,12,18}Z with `origin <= now <= origin + 40 min` (inclusive, to the second). Outside the window nothing runs and nothing is written. Never selects a previous (missed) origin. The trigger time never becomes `t0`.
3. **Ledger integrity (recomputed on every wake, independent of any HALT marker):** strict record schema, hash chain, canonical serialisation, state machine, anchor tags, git-history shape.
4. **HALT check** — a chain `HALT` record or `HALT.json` stops everything.
5. **Candidate** — reconstructed from the official upstream commit `600bdcd536d04521dbd300822e7b2af886c9821a` (fetched by exact SHA) plus the minimum user candidate history, with `core.autocrlf=false` set before any checkout; then the existing frozen verifier must print `FREEZE INTACT` for exactly `422f73d5…` / `phase2d-freeze`.
6. **Journal** — the frozen journal hash chain verifies and its heads match the ledger; every ledger SUCCESS pairs one-to-one with a journal SUCCESS.
7. **Decide** — SUCCESS is terminal; at most 3 `STARTED` per origin; an incomplete attempt blocks a new claim for a 13-minute lease.
8. **Claim (CAS)** — one commit (ledger record + anchor tag `anchor-NNNNNN`) pushed atomically and never forced. Losing the race means re-fetch, re-verify, re-decide.
9. **Run the frozen runner** — token-free whitelisted environment, 600 s timeout, never `--late-ok`. Then re-verify the candidate and validate only the **new** state (`check_success` for the new SUCCESS only).
10. **Terminal record (CAS)** — SUCCESS/FAILED together with the journal files and the next anchor tag.

Other subcommands: `check-ops` (read-only identity check), `verify-ledger [--full]` (read-only audit; `--full` re-runs the frozen scorer's `check_success` for every historical SUCCESS), `init-ledger` (explicit one-time bootstrap by a human; refuses to touch an existing ledger).
Production accepts **no other options** (no `--now`, no `--t0`, no overrides).

## Correctness layers

| Layer | Role |
|---|---|
| **Ledger CAS** (fast-forward-only atomic push of record + anchor tag) | **the correctness layer**: exactly-once claim per (origin, attempt), attempt cap, terminal SUCCESS, crash lease |
| GitHub `concurrency` group (`cancel-in-progress: false`) | best-effort serialisation of live runs and coalescing of duplicate wakes only; not durable, never relied on |
| Per-record 128-bit **nonce** | two concurrent claims can never be byte-identical (an identical commit would make a no-op push look like a win) |
| Anchor tags + history-shape check | tail truncation, deleted/moved anchors, rewritten history (when anchors remain), human commits on the machine-only branch |

Timing contract: `timeout-minutes: 12` < crash lease 13 min; runner timeout 600 s < job timeout. After a crash at +7 min the next claim can happen after +20 min, so at most two real attempts fit before +40.

## Ledger records

Schema `r3.ledger.v1`, canonical JSON (sorted keys, no whitespace), one record per line, **exact key sets per state** (unknown or missing fields, floats, duplicate keys and non-canonical serialisation are rejected, never normalised).
Every record binds: schema, seq, previous record hash, state, nonce, candidate SHA, ops commit, wrapper SHA-256, workflow blob hash, dependency-lock SHA-256, `workflow_sha` (secondary evidence, nullable), journal head, wall-clock, run id, run attempt, runtime identity.
`STARTED/FAILED/SUCCESS` add origin and attempt; `SUCCESS` adds forecast SHA-256, feed hashes and the journal attempt id; `FAILED` adds a reason; `HALT` adds a reason and a class.
States: `INIT`, `STARTED`, `FAILED`, `SUCCESS`, `HALT`. `HALT` is terminal. There is **no automatic or in-band resume**: a human review is required, and continuing means a new, explicitly audited ledger epoch.

## Anchors — what they do and do not give

Each record is committed as `ledger seq=N hash=<record hash>` and tagged `anchor-00000N`. Detected in-run: tail truncation, a moved anchor, a deleted anchor, a history rewrite while anchors remain, edited/inserted/deleted/reordered records, any non-ledger commit.
**Not detected in-run:** an actor who can rewrite the ledger **and** its anchor tags (and delete the tail anchors). That case is detectable only by an independent mirror (a clone or fork kept elsewhere) or an external anchor. This is tamper-evidence, not immutability. The tests exercise this boundary explicitly (6 coordinated variants: 0 detected in-run, all detected by a mirror).

## Identity and pinning (independent store = GitHub Actions variables; see `docs/PINS.md`)

| Pin | Source | Checked |
|---|---|---|
| ops commit | `OPS_COMMIT_PIN` | `git HEAD` of the fetched ops tree; tree must be clean |
| wrapper SHA-256 | `OPS_WRAPPER_SHA256_PIN` | the running file |
| **workflow blob hash (primary workflow identity)** | `WORKFLOW_BLOB_PIN` | `git rev-parse HEAD:.github/workflows/shadow.yml` of the fetched ops commit |
| dependency lock SHA-256 | `DEP_LOCK_SHA256_PIN` | `requirements.lock` bytes; plus static checks (exactly `numpy==2.2.6`, a sha256 hash, no floating specifier) |
| candidate | hard-coded constants (covered by the wrapper-hash pin) | SHA, tag, upstream commit |
| runtime | constants | Python 3.10 and numpy 2.2.6 at run time (else HALT class RUNTIME) |

`github.workflow_sha` is **recorded as secondary evidence only**; correctness does not depend on it until it has been validated on a real runner.
A missing or malformed pin is a configuration error (exit 2, no HALT, no write). A well-formed pin that does not match is an integrity failure (exit 22, durable HALT).
**Coordinated-rewrite limit:** someone who can change both the trusted code and the independent pin store defeats this gate; for a single-owner repository that is account-compromise level. The interpreter, `apt` packages in the container image and the container image itself are outside the pin boundary.

## Dependencies and supply chain

Python 3.10 (the production image's interpreter) and `numpy==2.2.6`, hash-locked (`requirements.lock`; installed with `pip install --require-hashes --only-binary=:all: --no-deps`). The hash was verified three ways: a fresh download, PyPI's published digest, and the pre-R3 value.
numpy 2.2.6 is inside the frozen candidate's declared range (`numpy>=1.26,<2.3`); numpy 2.4.6 must not be used. The workflow uses **zero third-party actions** (git, python and pip directly). If any action is ever added it must be pinned by full commit SHA.
Open item: the container image is not yet pinned by digest (`docs/EXTERNAL_TEST_PLAN.md`).

## Network surface (what the workflow can touch)

| Purpose | Hosts |
|---|---|
| Frozen runner data feeds (the only data endpoints) | `services.swpc.noaa.gov`, `cdaweb.gsfc.nasa.gov` |
| Git: ops commit, candidate, ledger, upstream starter kit | `github.com` |
| Hash-locked install | `pypi.org`, `files.pythonhosted.org` |
| Container image pull (performed by the runner) | `public.ecr.aws` |
| Base tools inside the container | Ubuntu apt mirrors (`apt-get`) |

No participant-site, upload or submission endpoint exists anywhere in this repository. No secret other than the job's own `GITHUB_TOKEN` is used.

## Secrets and permissions

Top-level `permissions: {}`; the single job gets `contents: write` (append to the ledger branch). The token is passed to **one** step as an environment variable, read once, removed from the process environment and given only to git subprocesses talking to `github.com`;
the frozen runner runs in a whitelisted environment without it. Triggers are `schedule` and `workflow_dispatch` (no inputs) only — no `pull_request`, no `pull_request_target`. A two-job read/write split would need an artifact-transfer action; it was not adopted to keep zero third-party actions.

## Scale: per wake vs audit

Per wake: strict parse + state machine + anchors + history shape + journal chain + the **new** attempt's `check_success`. **Full historical forecast reproduction is NOT repeated per wake**; it belongs to `verify-ledger --full` and to scoring. Old attempt files are protected per wake by the history-shape check (any modification of an earlier attempt's files is a violation).

## Linux / platform status (be exact)

* **WINDOWS_TESTED** — the full test suite has been executed on Windows (Python 3.11 / 3.14 environments; the frozen model runs numpy 2.4.6 there, outside the lock).
* **LINUX_STATIC_VALIDATED** — Python 3.10 grammar check, no Windows-only APIs, no 3.11+ features, LF line endings, POSIX path handling reviewed statically.
* **GITHUB_RUNTIME_UNTESTED** — nothing has run on a GitHub runner: container support, apt, `pip --require-hashes` on the runner, token pushes, rulesets, schedule delays, endpoint reachability, `workflow_sha`, 60-day inactivity behaviour all require the external test plan.
* Any local Linux execution (if performed) is reported separately in `docs/TEST_RESULTS.txt` and is never described as GitHub validation.

## Known limits

Tamper-evident, not immutable; coordinated ledger+anchor rewrite needs an independent mirror; coordinated code+pin rewrite defeats the identity gate; the interpreter/container/apt are unpinned; a crash after a local run can lose the frozen journal's own STARTED record (the ledger is authoritative for attempts);
a late or dropped schedule event means a missed origin (never backfilled); one account owns the ledger, the code and the variables.

## Tests

`python tests/run_all.py [pure] [integration] [races] [static] [stress]` (Python with numpy; the starter-kit clone is located via `R3_TEST_KIT` or `../benchlab-starter-kit`; read-only). All tests use temporary directories, a hardened local bare repository standing in for GitHub, synthetic feeds and the real frozen code. See `docs/TEST_RESULTS.txt`.
