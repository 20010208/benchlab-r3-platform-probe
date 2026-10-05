#!/usr/bin/env python3
"""Benchlab Phase 2D shadow ops -- R3 wrapper for GitHub Actions (LOCAL CANDIDATE: not installed, not activated).

Runs the FROZEN scientific runner (tools/shadow_run.py of candidate 422f73d5...) once per canonical six-hourly UTC origin and records every attempt in a
durable, hash-chained, git-anchored ledger on the orphan branch `shadow-ledger`.  Nothing here changes model behaviour.

Subcommands (no other arguments; production mode accepts no overrides):
    run              one wake: ops gate -> origin/window -> ledger+anchor+history integrity -> HALT -> candidate -> decide -> CAS claim -> frozen runner -> CAS terminal
    check-ops        read-only: verify the ops identity pins (+ runtime) and print one JSON line
    verify-ledger    read-only audit of the ledger branch; `verify-ledger --full` additionally re-runs the frozen scorer's check_success for EVERY historical SUCCESS
    init-ledger      explicit one-time bootstrap (human): creates the INIT record and anchor-000000; refuses to touch an existing ledger

Correctness layers (see README.md):  ledger CAS (git fast-forward-only atomic push of record + anchor tag) is the CORRECTNESS layer;  the GitHub concurrency group is
best-effort serialisation only.  Integrity is recomputed on every wake and never depends on a HALT marker.  No integrity failure is ever repaired automatically.
Honest limits: tamper-EVIDENT, not immutable.  An actor who can rewrite the ledger AND its anchor tags is detectable only through an independent mirror; an actor who
can change BOTH the trusted code and the independent pin store defeats the identity gate.  No secret other than the job's GITHUB_TOKEN exists; no participant-site or submission credentials are ever read, and no submission endpoint is ever contacted.
"""
import sys, os, re, json, hashlib, subprocess, time, random, secrets, tempfile, shutil, importlib, base64, platform
sys.dont_write_bytecode = True
from datetime import datetime, timedelta, timezone

# ------------------------------------------------------------------------------------------------------------- pinned constants (covered by the wrapper-hash pin)
CANDIDATE_SHA = "422f73d566d8a1715bf196749621a9f4138d5fd4"
CANDIDATE_TAG = "phase2d-freeze"
UPSTREAM_URL = "https://github.com/Trillium-Technologies/benchlab-starter-kit"
UPSTREAM_COMMIT = "600bdcd536d04521dbd300822e7b2af886c9821a"
SCHEMA = "r3.ledger.v1"
ORIGIN_HOURS = 6                                   # origins 00/06/12/18 UTC
WINDOW = timedelta(minutes=40)                     # inclusive; inside the frozen runner's own 45-minute live window
MAX_ATTEMPTS = 3                                   # STARTED records per origin
LEASE = timedelta(minutes=13)                      # an incomplete (crashed/cancelled) attempt blocks a new claim for this long
JOB_TIMEOUT_MIN = 12                               # workflow timeout-minutes; MUST stay below LEASE
RUNNER_TIMEOUT_S = 600                             # frozen-runner subprocess timeout; below the job timeout
assert timedelta(minutes=JOB_TIMEOUT_MIN) < LEASE and RUNNER_TIMEOUT_S < JOB_TIMEOUT_MIN * 60
BRANCH = "shadow-ledger"
ANCHOR = "anchor-"
WRAPPER_NAME = "shadow_ops_r3.py"
WORKFLOW_PATH = ".github/workflows/shadow.yml"
LOCK_NAME = "requirements.lock"
PY_TARGET = (3, 10)
NUMPY_TARGET = "2.2.6"
ALLOWED_DATA_HOSTS = ("services.swpc.noaa.gov", "cdaweb.gsfc.nasa.gov")          # the ONLY data endpoints the frozen runner contacts
ALLOWED_INFRA_HOSTS = ("github.com", "pypi.org", "files.pythonhosted.org")       # git (ledger, ops, candidate) and the hash-locked dependency install
GENESIS = "0" * 64
HALT_CLASSES = ("CANDIDATE", "OPS", "WORKFLOW", "LEDGER", "JOURNAL", "DUPLICATE_SUCCESS", "REPRODUCTION", "RUNTIME", "UNEXPECTED_WRITER", "OTHER")

SUCCESS, FAILED, CLAIMED = "SUCCESS", "FAILED", "CLAIMED"
SKIPPED_NOT_DUE, SKIPPED_DONE, SKIPPED_CAP, SKIPPED_IN_FLIGHT, SKIPPED_LOST_RACE = "SKIPPED_NOT_DUE", "SKIPPED_DONE", "SKIPPED_CAP", "SKIPPED_IN_FLIGHT", "SKIPPED_LOST_RACE"
ABANDONED, INTEGRITY_FAILURE, CANDIDATE_MISMATCH, OPS_INTEGRITY_FAILURE = "ABANDONED_STALE_WRITER", "INTEGRITY_FAILURE", "CANDIDATE_MISMATCH", "OPS_INTEGRITY_FAILURE"
NOT_INITIALISED, HALTED, LEDGER_UNAVAILABLE, RULESET_REJECTION, CONFIG_ERROR = "NOT_INITIALISED", "HALTED", "LEDGER_UNAVAILABLE", "RULESET_REJECTION", "CONFIG_ERROR"
EXIT = {SUCCESS: 0, CLAIMED: 0, SKIPPED_NOT_DUE: 0, SKIPPED_DONE: 0, SKIPPED_CAP: 0, SKIPPED_IN_FLIGHT: 0, SKIPPED_LOST_RACE: 0, FAILED: 10, ABANDONED: 11, LEDGER_UNAVAILABLE: 12,
        RULESET_REJECTION: 13, INTEGRITY_FAILURE: 20, CANDIDATE_MISMATCH: 21, OPS_INTEGRITY_FAILURE: 22, NOT_INITIALISED: 23, HALTED: 30, CONFIG_ERROR: 2}

HEX40, HEX64 = re.compile(r"^[0-9a-f]{40}\Z"), re.compile(r"^[0-9a-f]{64}\Z")
NONCE_RE, ID_RE, FEEDKEY_RE = re.compile(r"^[0-9a-f]{32}\Z"), re.compile(r"^[A-Za-z0-9._-]{1,64}\Z"), re.compile(r"^[a-z0-9_]{1,16}\Z")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
UTC = timezone.utc
ISO = "%Y-%m-%dT%H:%M:%SZ"
FMT = "%Y%m%dT%H%M%SZ"


# ------------------------------------------------------------------------------------------------------------- basic helpers
def utcnow(): return datetime.now(UTC)
def sha256_hex(b): return hashlib.sha256(b).hexdigest()
def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
def fmt_ts(dt): return dt.astimezone(UTC).replace(microsecond=0).strftime(ISO)


def parse_ts(s):
    if not isinstance(s, str) or not ISO_RE.match(s): raise ValueError(f"bad timestamp {s!r}")
    return datetime.strptime(s, ISO).replace(tzinfo=UTC)


def valid_origin(s):
    try: d = parse_ts(s)
    except ValueError: return False
    return d.hour % ORIGIN_HOURS == 0 and d.minute == 0 and d.second == 0


def _no_dup(pairs):
    d = {}
    for k, v in pairs:
        if k in d: raise ValueError(f"duplicate field {k!r}")
        d[k] = v
    return d


def _reject_float(x): raise ValueError("floating-point numbers are not allowed in ledger records")
def _reject_const(x): raise ValueError("non-finite constant")
def strict_loads(s): return json.loads(s, object_pairs_hook=_no_dup, parse_float=_reject_float, parse_constant=_reject_const)


# ------------------------------------------------------------------------------------------------------------- canonical origin and eligibility (independent of any trigger time)
def canonical_origin(now):
    now = now.astimezone(UTC)
    return now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=now.hour % ORIGIN_HOURS)


def eligible_origin(now):
    """The latest canonical origin if origin <= now <= origin + 40 min (inclusive), else (None, reason).  NEVER returns a previous, missed origin."""
    o = canonical_origin(now); age = now.astimezone(UTC) - o
    return (o, None) if timedelta(0) <= age <= WINDOW else (None, "outside the 40-minute window of the latest origin (no backfill)")


# ------------------------------------------------------------------------------------------------------------- ledger records: strict schema
COMMON = ("schema", "seq", "prev_hash", "state", "nonce", "candidate_sha", "ops_commit", "wrapper_sha256", "workflow_blob", "lock_sha256", "workflow_sha",
          "journal_head", "ts", "run_id", "run_attempt", "runtime_identity")
KEYS = {"INIT": COMMON, "STARTED": COMMON + ("origin", "attempt_no"), "FAILED": COMMON + ("origin", "attempt_no", "reason", "journal_attempt_id"),
        "SUCCESS": COMMON + ("origin", "attempt_no", "forecast_sha256", "feed_sha256", "journal_attempt_id"), "HALT": COMMON + ("reason", "halt_class")}


def _is_int(x): return type(x) is int
def _text(x, lo=1, hi=300): return isinstance(x, str) and lo <= len(x) <= hi and all(32 <= ord(c) < 127 for c in x)


def shape_problems(r):
    """Exact key sets and field formats per state.  Never normalises: anything unexpected is a problem."""
    if not isinstance(r, dict): return ["record is not an object"]
    st = r.get("state")
    if st not in KEYS: return [f"unknown state {st!r}"]
    want = set(KEYS[st]) | {"record_hash"}; have = set(r)
    if have != want: return [f"field set differs (missing {sorted(want - have)}, unexpected {sorted(have - want)})"]
    p = []
    if r["schema"] != SCHEMA: p.append("unknown schema")
    if not (_is_int(r["seq"]) and r["seq"] >= 0): p.append("bad seq")
    for k in ("prev_hash", "wrapper_sha256", "lock_sha256", "journal_head", "record_hash"):
        if not (isinstance(r[k], str) and HEX64.match(r[k])): p.append(f"bad {k}")
    for k in ("candidate_sha", "ops_commit", "workflow_blob"):
        if not (isinstance(r[k], str) and HEX40.match(r[k])): p.append(f"bad {k}")
    if not (isinstance(r["nonce"], str) and NONCE_RE.match(r["nonce"])): p.append("bad nonce")
    if not (r["workflow_sha"] is None or (isinstance(r["workflow_sha"], str) and HEX40.match(r["workflow_sha"]))): p.append("bad workflow_sha")
    try: parse_ts(r["ts"])
    except ValueError: p.append("bad ts")
    if not (isinstance(r["run_id"], str) and ID_RE.match(r["run_id"])): p.append("bad run_id")
    if not (_is_int(r["run_attempt"]) and r["run_attempt"] >= 1): p.append("bad run_attempt")
    if not _text(r["runtime_identity"], 1, 200): p.append("bad runtime_identity")
    if "origin" in r:
        if not (isinstance(r["origin"], str) and valid_origin(r["origin"])): p.append("invalid origin")
        if not (_is_int(r["attempt_no"]) and 1 <= r["attempt_no"] <= MAX_ATTEMPTS): p.append("invalid attempt")
    if "forecast_sha256" in r and not (isinstance(r["forecast_sha256"], str) and HEX64.match(r["forecast_sha256"])): p.append("bad forecast_sha256")
    if "feed_sha256" in r:
        f = r["feed_sha256"]
        if not (isinstance(f, dict) and 1 <= len(f) <= 8 and all(isinstance(k, str) and FEEDKEY_RE.match(k) and isinstance(v, str) and HEX64.match(v) for k, v in f.items())): p.append("bad feed_sha256")
    if "reason" in r and not _text(r["reason"]): p.append("bad reason")
    if "journal_attempt_id" in r and not (r["journal_attempt_id"] is None or (isinstance(r["journal_attempt_id"], str) and ID_RE.match(r["journal_attempt_id"]))): p.append("bad journal_attempt_id")
    if "halt_class" in r and r["halt_class"] not in HALT_CLASSES: p.append("bad halt_class")
    return p


def make_record(prev, state, ident, **extra):
    """New record chained to `prev` (a parsed record or None).  Always carries a fresh 128-bit nonce (so two concurrent claims can never be byte-identical)."""
    body = {"schema": SCHEMA, "seq": 0 if prev is None else prev["seq"] + 1, "prev_hash": GENESIS if prev is None else prev["record_hash"], "state": state, "nonce": secrets.token_hex(16)}
    for k in ("candidate_sha", "ops_commit", "wrapper_sha256", "workflow_blob", "lock_sha256", "workflow_sha", "journal_head", "ts", "run_id", "run_attempt", "runtime_identity"):
        body[k] = ident[k]
    body.update(extra)
    body["record_hash"] = sha256_hex((body["prev_hash"] + canon(body)).encode())          # canon(body) is computed BEFORE record_hash is added to it
    bad = shape_problems(body)
    if bad: raise ValueError("refusing to build an invalid record: " + "; ".join(bad))
    return body


def _record_hash(r):
    body = {k: v for k, v in r.items() if k != "record_hash"}
    return sha256_hex((r["prev_hash"] + canon(body)).encode())


def parse_ledger(raw):
    """bytes -> (records, problems).  Strict: valid UTF-8 and JSON without duplicate keys/floats, exact schema, canonical serialisation, contiguous seq, hash chain."""
    if not raw: return [], ["ledger is empty"]
    problems, recs, prev = [], [], GENESIS
    if not raw.endswith(b"\n"): problems.append("ledger does not end with a newline (torn write)")
    lines = raw.split(b"\n")
    if lines[-1] == b"": lines = lines[:-1]
    for i, ln in enumerate(lines):
        try:
            text = ln.decode("utf-8"); r = strict_loads(text)
        except (UnicodeDecodeError, ValueError) as e:
            problems.append(f"line {i}: {e}"); break
        sp = shape_problems(r)
        if sp: problems.append(f"line {i}: {sp[0]}"); break
        if canon(r) != text: problems.append(f"line {i}: not in canonical serialisation"); break
        if r["seq"] != i: problems.append(f"line {i}: seq {r['seq']} != {i}"); break
        if r["prev_hash"] != prev: problems.append(f"line {i}: previous-hash link broken"); break
        if r["record_hash"] != _record_hash(r): problems.append(f"line {i}: record hash mismatch (edited)"); break
        recs.append(r); prev = r["record_hash"]
    return recs, problems


def semantic_problems(recs, expected_candidate=CANDIDATE_SHA):
    """State-machine validation of a chain-valid ledger."""
    p = []
    if not recs: return ["ledger has no records"]
    if recs[0]["state"] != "INIT": return ["ledger does not start with INIT"]
    halted = False; attempts = {}; done = set()
    for r in recs:
        if r["candidate_sha"] != expected_candidate: p.append(f"seq {r['seq']}: candidate sha differs from the pinned candidate")
        if halted: p.append(f"seq {r['seq']}: record after HALT"); continue
        st = r["state"]
        if st == "INIT":
            if r["seq"] != 0: p.append(f"seq {r['seq']}: INIT after the first record")
            continue
        if st == "HALT": halted = True; continue
        o = r["origin"]; lst = attempts.setdefault(o, [])
        if st == "STARTED":
            age = parse_ts(r["ts"]) - parse_ts(o)
            if not (timedelta(0) <= age <= WINDOW): p.append(f"seq {r['seq']}: claim outside the origin's 40-minute window")
            if o in done: p.append(f"seq {r['seq']}: STARTED after SUCCESS for {o}")
            n = len(lst) + 1
            if r["attempt_no"] != n: p.append(f"seq {r['seq']}: attempt_no {r['attempt_no']} != expected {n}")
            if lst and lst[-1]["term"] is None and not (parse_ts(r["ts"]) - lst[-1]["ts"] > LEASE): p.append(f"seq {r['seq']}: claim while the previous attempt is still inside its lease")
            lst.append({"ts": parse_ts(r["ts"]), "term": None})
        else:                                               # SUCCESS / FAILED
            if not lst or lst[-1]["term"] is not None or r["attempt_no"] != len(lst): p.append(f"seq {r['seq']}: terminal record without a matching open attempt"); continue
            lst[-1]["term"] = st
            if st == "SUCCESS":
                if o in done: p.append(f"seq {r['seq']}: duplicate SUCCESS for {o}")
                done.add(o)
    return p


def decide(recs, origin, now, lease=LEASE):
    """('SKIP', code) or ('CLAIM', attempt_no) -- pure."""
    o = fmt_ts(origin); st = [r for r in recs if r.get("origin") == o and r["state"] == "STARTED"]
    terms = {r["attempt_no"]: r["state"] for r in recs if r.get("origin") == o and r["state"] in ("SUCCESS", "FAILED")}
    if "SUCCESS" in terms.values(): return "SKIP", SKIPPED_DONE
    if len(st) >= MAX_ATTEMPTS: return "SKIP", SKIPPED_CAP
    if st and st[-1]["attempt_no"] not in terms and now - parse_ts(st[-1]["ts"]) <= lease: return "SKIP", SKIPPED_IN_FLIGHT
    return "CLAIM", len(st) + 1


# ------------------------------------------------------------------------------------------------------------- configuration
class Config:
    """Everything the wrapper needs.  Production values come from build_production_config(); tests construct it directly (the CLI has no override switches)."""
    def __init__(self, **kw):
        self.ops_dir = os.path.dirname(os.path.abspath(__file__)); self.pins = {}; self.ledger_remote = None; self.work_root = None
        self.now_fn = utcnow; self.final_now_fn = None
        self.run_id = "local-run"; self.run_attempt = 1; self.workflow_sha = None; self.token = None
        self.candidate_dir = None; self.candidate_source = None; self.candidate_source_kind = "git"; self.upstream_url = UPSTREAM_URL; self.upstream_commit = UPSTREAM_COMMIT
        self.git_isolated = True; self.enforce_runtime = True; self.allow_local_remotes = False
        self.verify_fn = None; self.runner_cmd_fn = None; self.runner_env_extra = {}; self.claim_only = False; self.production = False
        for k, v in kw.items():
            if not hasattr(self, k): raise TypeError(f"unknown Config field {k!r}")
            setattr(self, k, v)


class ConfigError(Exception): pass


def runner_env(cfg):
    """Environment for the frozen runner subprocess: NO token, NO inherited secrets -- only what Python needs."""
    keep = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL")
    e = {k: os.environ[k] for k in keep if k in os.environ}
    e["PYTHONDONTWRITEBYTECODE"] = "1"
    e.update(cfg.runner_env_extra)
    return e


# ------------------------------------------------------------------------------------------------------------- git layer
class GitError(Exception): pass
_EMPTY_CFG = []


def _empty_gitconfig():
    if not _EMPTY_CFG:
        fd, p = tempfile.mkstemp(prefix="r3-empty-gitconfig-"); os.close(fd); _EMPTY_CFG.append(p)
    return _EMPTY_CFG[0]


GIT_BASE = ["git", "-c", "user.name=benchlab-r3-ledger", "-c", "user.email=ledger@users.noreply.invalid", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false",
            "-c", "core.safecrlf=false", "-c", "gc.auto=0", "-c", "advice.detachedHead=false"]


class Git:
    def __init__(self, token=None, isolated=True): self.token, self.isolated = token, isolated

    def _env(self, remote):
        e = dict(os.environ); e["GIT_TERMINAL_PROMPT"] = "0"; e["PYTHONDONTWRITEBYTECODE"] = "1"
        e.pop("GITHUB_TOKEN", None)
        if self.isolated: e["GIT_CONFIG_NOSYSTEM"] = "1"; e["GIT_CONFIG_GLOBAL"] = _empty_gitconfig()
        if self.token and remote and remote.startswith("https://github.com/"):          # token only for github.com, only in this git process's environment (never argv, never the runner)
            b64 = base64.b64encode(f"x-access-token:{self.token}".encode()).decode()
            e.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.extraheader", GIT_CONFIG_VALUE_0=f"AUTHORIZATION: basic {b64}")
        return e

    def run(self, cwd, *args, check=True, remote=None):
        r = subprocess.run([*GIT_BASE, *args], cwd=cwd, capture_output=True, text=True, env=self._env(remote))
        if check and r.returncode != 0: raise GitError(self.scrub(f"git {' '.join(args)[:80]}: {r.stderr.strip()[:300]}"))
        return r

    def scrub(self, s):
        if self.token: s = s.replace(self.token, "***").replace(base64.b64encode(f"x-access-token:{self.token}".encode()).decode(), "***")
        return s


def check_remote_url(url, allow_local):
    if allow_local and os.path.isdir(url): return True
    m = re.match(r"^https://([a-z0-9.-]+)/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(\.git)?\Z", url or "")
    return bool(m and m.group(1) in ALLOWED_INFRA_HOSTS)


RULE_MARKERS = ("GH006", "GH013", "protected branch", "repository rule", "rule violations", "hook declined", "required status check", "changes must be made through")
CAS_MARKERS = ("non-fast-forward", "fetch first", "already exists", "stale info", "cannot lock ref", "failed to update ref", "updates were rejected", "[rejected]", "[remote rejected]")


def classify_push_error(err):
    """Meaning, not prefix: an explicit rule/protection text is a RULE_REJECTED (a human must look); a lost compare-and-swap (non-fast-forward, fetch first, slot already taken,
    even when the SERVER reports it as `[remote rejected]`) is REJECTED and is retried by re-fetching and re-deciding; anything else (network, DNS, auth) is ERROR."""
    low = (err or "").lower()
    if any(m.lower() in low for m in RULE_MARKERS): return "RULE_REJECTED"
    if any(m.lower() in low for m in CAS_MARKERS): return "REJECTED"
    return "ERROR"


class Store:
    """A disposable checkout of the ledger branch (= one GitHub runner)."""
    def __init__(self, g, remote, path):
        self.g, self.remote, self.path = g, remote, path
        os.makedirs(path, exist_ok=True); g.run(path, "init", "-q", "-b", "local"); g.run(path, "remote", "add", "origin", remote)

    def remote_state(self):
        r = self.g.run(self.path, "ls-remote", "--exit-code", "origin", f"refs/heads/{BRANCH}", check=False, remote=self.remote)
        return "present" if r.returncode == 0 else ("missing" if r.returncode == 2 else "error")

    def remote_has_anchors(self):
        r = self.g.run(self.path, "ls-remote", "origin", f"refs/tags/{ANCHOR}*", check=False, remote=self.remote)
        return r.returncode == 0 and bool(r.stdout.strip())

    def refresh(self):
        r = self.g.run(self.path, "fetch", "-q", "--no-tags", "origin", f"+refs/heads/{BRANCH}:refs/remotes/origin/{BRANCH}", f"+refs/tags/{ANCHOR}*:refs/tags/{ANCHOR}*", check=False, remote=self.remote)
        if r.returncode != 0: return False
        self.g.run(self.path, "checkout", "-q", "-f", "-B", BRANCH, f"origin/{BRANCH}"); self.g.run(self.path, "clean", "-fdxq"); return True

    def ledger_bytes(self):
        p = os.path.join(self.path, "ledger.jsonl"); return open(p, "rb").read() if os.path.exists(p) else None

    def halt_file(self): return os.path.exists(os.path.join(self.path, "HALT.json"))

    def anchors(self):
        out = {}
        for l in self.g.run(self.path, "for-each-ref", f"refs/tags/{ANCHOR}*", "--format=%(refname:short) %(objectname)").stdout.splitlines():
            n, c = l.split(); out[int(n[len(ANCHOR):])] = c
        return out

    def ancestry(self):
        return {l.split(" ", 1)[0]: (l.split(" ", 1)[1] if " " in l else "") for l in self.g.run(self.path, "log", "--format=%H %s", "HEAD").stdout.splitlines()}

    def anchor_problems(self, recs):
        """Every record seq has exactly one anchor tag, pointing at an ancestor of the tip whose subject binds that record's hash."""
        p = []; anc = self.anchors(); hist = self.ancestry(); last = len(recs) - 1
        for n in sorted(set(anc) | set(range(len(recs)))):
            if n > last: p.append(f"{ANCHOR}{n:06d} exists beyond the ledger tail (tail truncated or history replaced)"); continue
            if n not in anc: p.append(f"{ANCHOR}{n:06d} missing"); continue
            c = anc[n]
            if c not in hist: p.append(f"{ANCHOR}{n:06d} points at a commit that is not in the ledger history (history rewritten or tag moved)"); continue
            if f"ledger seq={n} hash={recs[n]['record_hash']}" != hist[c]: p.append(f"{ANCHOR}{n:06d}: commit does not bind record {n} (record rewritten or tag moved)")
        return p

    def shape_problems(self, recs):
        """The ledger branch is machine-only: linear history, one commit per record, only append-only paths.  Human edits (even fast-forward) are violations."""
        p = []
        if self.g.run(self.path, "rev-list", "--merges", "HEAD").stdout.strip(): p.append("merge commit in the ledger history")
        out = self.g.run(self.path, "log", "--reverse", "--no-renames", "--name-status", "--format=%x01%H%x02%P%x02%s", "HEAD").stdout
        nxt = 0; halts = 0; first = True
        for chunk in out.split("\x01")[1:]:
            head, _, body = chunk.partition("\n"); h, par, subj = head.split("\x02", 2)
            changes = [tuple(l.split("\t", 1)) for l in body.split("\n") if l.strip()]
            if len(par.split()) != (0 if first else 1): p.append(f"commit {h[:8]}: unexpected parent count")
            first = False
            m = re.match(r"^ledger seq=(\d+) hash=([0-9a-f]{64})\Z", subj)
            if m:
                if int(m.group(1)) != nxt or nxt >= len(recs) or recs[nxt]["record_hash"] != m.group(2): p.append(f"commit {h[:8]}: subject does not match ledger record {nxt}")
                nxt += 1
                for st, path in changes:
                    ok = (path == "ledger.jsonl" and st in "AM") or (path == "journal/journal.jsonl" and st in "AM") or (path.startswith("journal/attempts/") and st == "A")
                    if not ok: p.append(f"commit {h[:8]}: forbidden change {st} {path}")
            elif subj == "halt marker":
                halts += 1
                if changes != [("A", "HALT.json")] or halts > 1: p.append(f"commit {h[:8]}: malformed halt-marker commit")
            else: p.append(f"commit {h[:8]}: not a ledger commit ({subj[:40]!r})")
        if nxt != len(recs): p.append(f"history has {nxt} ledger commits for {len(recs)} records")
        return p

    # ---- append = stage (commit + anchor tag) then atomic push
    def stage(self, rec, prev_raw):
        open(os.path.join(self.path, "ledger.jsonl"), "wb").write(prev_raw + (canon(rec) + "\n").encode())
        self.g.run(self.path, "add", "-A"); self.g.run(self.path, "commit", "-q", "-m", f"ledger seq={rec['seq']} hash={rec['record_hash']}")
        tag = f"{ANCHOR}{rec['seq']:06d}"
        if self.g.run(self.path, "tag", tag, check=False).returncode != 0:        # anchor slot already taken (stale/orphaned tag): a lost CAS, never overwritten
            self.g.run(self.path, "reset", "-q", "--soft", "HEAD~1"); return None
        return tag

    def push(self, tag):
        r = self.g.run(self.path, "push", "-q", "--atomic", "origin", f"HEAD:refs/heads/{BRANCH}", f"refs/tags/{tag}", check=False, remote=self.remote)
        if r.returncode == 0: return "OK"
        return classify_push_error(r.stderr)

    def unstage(self, tag):
        self.g.run(self.path, "tag", "-d", tag, check=False); self.g.run(self.path, "reset", "-q", "--soft", "HEAD~1", check=False)


# ------------------------------------------------------------------------------------------------------------- frozen candidate: reconstruct, verify, load
def reconstruct_candidate(g, dest, kind, source, upstream_url, upstream_commit, expect_sha=CANDIDATE_SHA, tag=CANDIDATE_TAG, allow_local=False):
    """official upstream commit (by exact SHA) + the minimum user candidate history (git remote or thin bundle) -> the frozen commit.  core.autocrlf=false BEFORE any checkout."""
    os.makedirs(dest, exist_ok=True); g.run(dest, "init", "-q"); g.run(dest, "config", "core.autocrlf", "false"); g.run(dest, "config", "core.safecrlf", "false")
    if not check_remote_url(upstream_url, allow_local): return ["upstream URL is not an allowed https://github.com/... URL"]
    g.run(dest, "fetch", "-q", "--no-tags", upstream_url, upstream_commit, remote=upstream_url)
    if g.run(dest, "rev-parse", "FETCH_HEAD^{commit}").stdout.strip() != upstream_commit: return ["fetched upstream commit differs from the pinned upstream commit"]
    ref = f"refs/tags/{tag}"
    if kind == "bundle":
        if not os.path.isfile(source): return ["candidate bundle file not found"]
        if g.run(dest, "bundle", "verify", source, check=False).returncode != 0: return ["candidate bundle does not verify"]
        g.run(dest, "fetch", "-q", "--no-tags", source, f"+{ref}:{ref}")
    elif kind == "git":
        if not check_remote_url(source, allow_local): return ["candidate source is not an allowed https://github.com/... URL"]
        g.run(dest, "fetch", "-q", "--no-tags", source, f"+{ref}:{ref}", remote=source)
    else: return [f"unknown candidate source kind {kind!r}"]
    got = g.run(dest, "rev-parse", f"{ref}^{{commit}}", check=False).stdout.strip()
    if got != expect_sha: return [f"tag {tag} resolves to {got[:12] or 'nothing'}, pinned {expect_sha[:12]}"]
    g.run(dest, "checkout", "-q", "-f", "--detach", ref)
    return []


_FROZEN_MODULES = ("model", "swp_features", "verify_freeze", "shadow_journal", "shadow_run", "shadow_score")


def load_frozen(cand_dir):
    """Import the frozen journal/scorer/verifier READ-ONLY (after verification).  Fresh import each time; frozen paths first so nothing can shadow them."""
    for m in _FROZEN_MODULES: sys.modules.pop(m, None)
    for p in (os.path.join(cand_dir, "submission_pack"), os.path.join(cand_dir, "tools")):
        if p in sys.path: sys.path.remove(p)
        sys.path.insert(0, p)
    import shadow_journal as SJ, shadow_score as SS, verify_freeze as VF
    return SJ, SS, VF


def verify_candidate(cfg, cand_dir):
    if cfg.verify_fn is not None: return cfg.verify_fn(cand_dir)
    r = subprocess.run([sys.executable, "-B", os.path.join(cand_dir, "tools", "verify_freeze.py"), "--expect-sha", CANDIDATE_SHA, "--tag", CANDIDATE_TAG, "--root", cand_dir],
                       capture_output=True, text=True, env=runner_env(cfg), timeout=300)
    return [] if r.returncode == 0 and "FREEZE INTACT" in r.stdout else [(r.stdout + r.stderr).strip()[-400:] or "verify_freeze failed"]


# ------------------------------------------------------------------------------------------------------------- ops identity gate (before any ledger mutation)
def runtime_problems():
    p = []
    if sys.version_info[:2] != PY_TARGET: p.append(f"python {sys.version_info[0]}.{sys.version_info[1]} != target {PY_TARGET[0]}.{PY_TARGET[1]}")
    try:
        import numpy
        if numpy.__version__ != NUMPY_TARGET: p.append(f"numpy {numpy.__version__} != locked {NUMPY_TARGET}")
    except ImportError: p.append("numpy is not importable")
    return p


def lock_problems(raw):
    """requirements.lock must pin exactly numpy==NUMPY_TARGET with sha256 hashes (static check; pip --require-hashes enforces them at install time)."""
    t = raw.decode("utf-8", "replace"); p = []
    if not re.search(rf"(?m)^numpy=={re.escape(NUMPY_TARGET)}\b", t): p.append(f"lock does not pin numpy=={NUMPY_TARGET}")
    if not re.search(r"--hash=sha256:[0-9a-f]{64}", t): p.append("lock carries no sha256 hash")
    if re.search(r"(?m)^\s*[A-Za-z0-9_.-]+\s*(>=|<=|~=|>|<|!=)", t): p.append("lock contains a floating version specifier")
    return p


def verify_ops(cfg, g):
    """Returns (problems[(class, message)], info).  Checks the pins (well-formed, from the independent store) against what actually runs."""
    pr, info = [], {}
    pins = cfg.pins; fmt = {"ops_commit": HEX40, "wrapper_sha256": HEX64, "workflow_blob": HEX40, "lock_sha256": HEX64}
    for k, rx in fmt.items():
        if not (isinstance(pins.get(k), str) and rx.match(pins[k])): raise ConfigError(f"pin {k} missing or malformed")
    wrapper = os.path.join(cfg.ops_dir, WRAPPER_NAME)
    if cfg.production and os.path.abspath(__file__) != os.path.abspath(wrapper): pr.append(("OPS", "running wrapper is not the one in the ops directory"))
    try: info["wrapper_sha256"] = sha256_hex(open(wrapper, "rb").read())
    except OSError: info["wrapper_sha256"] = "0" * 64; pr.append(("OPS", "wrapper file unreadable"))
    if info["wrapper_sha256"] != pins["wrapper_sha256"]: pr.append(("OPS", f"wrapper SHA-256 {info['wrapper_sha256'][:12]} != pinned {pins['wrapper_sha256'][:12]}"))
    r = g.run(cfg.ops_dir, "rev-parse", "HEAD", check=False); info["ops_commit"] = r.stdout.strip() if r.returncode == 0 and HEX40.match(r.stdout.strip()) else "0" * 40
    if info["ops_commit"] != pins["ops_commit"]: pr.append(("OPS", f"ops HEAD {info['ops_commit'][:12]} != pinned {pins['ops_commit'][:12]}"))
    st = g.run(cfg.ops_dir, "status", "--porcelain", "--untracked-files=all", check=False).stdout.strip()
    if st: pr.append(("OPS", "ops tree not clean: " + "; ".join(st.split("\n")[:4])))
    r = g.run(cfg.ops_dir, "rev-parse", f"HEAD:{WORKFLOW_PATH}", check=False); info["workflow_blob"] = r.stdout.strip() if r.returncode == 0 and HEX40.match(r.stdout.strip()) else "0" * 40
    if info["workflow_blob"] != pins["workflow_blob"]: pr.append(("WORKFLOW", f"workflow blob {info['workflow_blob'][:12]} != pinned {pins['workflow_blob'][:12]}"))
    try: lraw = open(os.path.join(cfg.ops_dir, LOCK_NAME), "rb").read(); info["lock_sha256"] = sha256_hex(lraw)
    except OSError: lraw = b""; info["lock_sha256"] = "0" * 64; pr.append(("OPS", "lock file unreadable"))
    if info["lock_sha256"] != pins["lock_sha256"]: pr.append(("OPS", f"dependency lock {info['lock_sha256'][:12]} != pinned {pins['lock_sha256'][:12]}"))
    for m in lock_problems(lraw): pr.append(("OPS", m))
    if cfg.enforce_runtime:
        for m in runtime_problems(): pr.append(("RUNTIME", m))
    return pr, info


def runtime_identity():
    try:
        import numpy; np_v = numpy.__version__
    except ImportError: np_v = "none"
    return f"py{platform.python_version()}/numpy{np_v}/{platform.machine() or 'unknown'}"[:200]


# ------------------------------------------------------------------------------------------------------------- HALT
def clean_reason(s, default="integrity failure"):
    """Any text -> a schema-valid reason (printable ASCII, single-spaced, <= 300 chars).  A fail-closed path must never be defeatable by odd input."""
    t = "".join(c if 32 <= ord(c) < 127 else " " for c in str(s)); t = " ".join(t.split())[:300].strip()
    return t or default


def write_halt(cfg, g, halt_class, reason, ident, now, evidence_store=None, evidence_tip=None):
    """Durable HALT.  Preferred: a chain record (when the chain parses and no HALT exists), optionally committed together with the offending journal evidence;
    otherwise -- and whenever a chain record cannot be built or pushed for ANY reason -- a plain HALT.json commit.  Never repairs, never overwrites."""
    reason = clean_reason(reason)
    def scrub_tree(store):
        try: store.g.run(store.path, "reset", "-q", "--hard", "HEAD"); store.g.run(store.path, "clean", "-fdxq")
        except (GitError, OSError): pass
    def chain_attempt(store, with_evidence):
        """True = chain HALT pushed; 'ALREADY' = a chain HALT exists; None = not applicable (chain unreadable); False = tried and failed."""
        try:
            raw = store.ledger_bytes(); recs, probs = parse_ledger(raw) if raw else ([], ["missing"])
            if probs or not recs: return None
            if any(r["state"] == "HALT" for r in recs): return "ALREADY"
            rec = make_record(recs[-1], "HALT", dict(ident, journal_head=ident["journal_head"] if with_evidence else recs[-1]["journal_head"], ts=fmt_ts(now)), reason=reason, halt_class=halt_class)
            tag = store.stage(rec, raw)
            if tag is None: return False
            if store.push(tag) == "OK": return True
            store.unstage(tag); scrub_tree(store); return False
        except (ValueError, KeyError, GitError, OSError):
            scrub_tree(store); return False
    def marker_attempt(store):
        try:
            if os.path.exists(os.path.join(store.path, "HALT.json")): return True
            open(os.path.join(store.path, "HALT.json"), "w").write(json.dumps({"halt_class": halt_class, "reason": reason, "ts": fmt_ts(now)}))
            store.g.run(store.path, "add", "HALT.json"); store.g.run(store.path, "commit", "-q", "-m", "halt marker")
            return store.g.run(store.path, "push", "-q", "origin", f"HEAD:refs/heads/{BRANCH}", check=False, remote=store.remote).returncode == 0
        except (GitError, OSError): return False
    def attempt(store, with_evidence):
        r = chain_attempt(store, with_evidence)
        if r is True or r == "ALREADY": return True
        return marker_attempt(store)
    try:
        if evidence_store is not None and evidence_tip is not None and attempt(evidence_store, True): return True
        st = Store(g, evidence_store.remote if evidence_store else cfg.ledger_remote, tempfile.mkdtemp(prefix="halt-", dir=cfg.work_root))
        return st.refresh() and attempt(st, False)
    except (GitError, OSError, ValueError):
        return False


# ------------------------------------------------------------------------------------------------------------- one wake
def _res(result, **kw): d = dict(result=result, durable=False, ran=False); d.update(kw); return d


def structural_check(store, expected_candidate=CANDIDATE_SHA):
    raw = store.ledger_bytes()
    if raw is None: return [], ["ledger.jsonl missing on the ledger branch"]
    recs, p = parse_ledger(raw)
    if p: return recs, p
    p = semantic_problems(recs, expected_candidate) + store.anchor_problems(recs) + store.shape_problems(recs)
    return recs, p


def journal_problems(SJ, store, recs):
    J = SJ.Journal(os.path.join(store.path, "journal", "journal.jsonl")); jrecs, jp = J.read()
    if jp: return jrecs, ["journal: " + "; ".join(jp[:2])]
    heads = {GENESIS} | {r["record_hash"] for r in jrecs}; cur = jrecs[-1]["record_hash"] if jrecs else GENESIS; p = []
    for r in recs:
        if r["journal_head"] not in heads: p.append(f"seq {r['seq']}: journal_head not found in the journal chain"); break
    if recs and recs[-1]["journal_head"] != cur: p.append("journal head differs from the last ledger record's journal_head")
    ls = {r["origin"]: r for r in recs if r["state"] == "SUCCESS"}; js = {}                    # ledger SUCCESS <-> journal SUCCESS: exactly one each, same attempt, forecast and feeds
    for r in jrecs:
        if r.get("type") == "SUCCESS": js.setdefault(r.get("origin"), []).append(r)
    for o in sorted(set(ls) | set(js), key=str):
        if o not in ls: p.append(f"journal SUCCESS for {o} without a ledger SUCCESS")
        elif len(js.get(o, [])) != 1: p.append(f"{o}: ledger SUCCESS but {len(js.get(o, []))} journal SUCCESS records")
        else:
            j, l = js[o][0], ls[o]
            if (j.get("attempt_id"), j.get("forecast_sha256"), j.get("feed_sha256")) != (l["journal_attempt_id"], l["forecast_sha256"], l["feed_sha256"]): p.append(f"{o}: ledger SUCCESS differs from the journal SUCCESS")
    return jrecs, p


def run_once(cfg):
    """One wake.  Returns dict(result, durable, ran, ...)."""
    if cfg.work_root is None: cfg.work_root = tempfile.mkdtemp(prefix="r3-work-")
    g = Git(cfg.token, cfg.git_isolated); now = cfg.now_fn().astimezone(UTC).replace(microsecond=0)
    def uniq(tag): return os.path.join(cfg.work_root, f"{tag}-{secrets.token_hex(4)}")
    ident = dict(candidate_sha=CANDIDATE_SHA, ops_commit="0" * 40, wrapper_sha256="0" * 64, workflow_blob="0" * 40, lock_sha256="0" * 64, workflow_sha=cfg.workflow_sha,
                 journal_head=GENESIS, ts=fmt_ts(now), run_id=cfg.run_id, run_attempt=cfg.run_attempt, runtime_identity=runtime_identity())
    if not (cfg.workflow_sha is None or (isinstance(cfg.workflow_sha, str) and HEX40.match(cfg.workflow_sha))): ident["workflow_sha"] = None
    if not check_remote_url(cfg.ledger_remote, cfg.allow_local_remotes): return _res(CONFIG_ERROR, reason="ledger remote is not an allowed https://github.com/... URL")
    # ---- 1. ops identity gate (nothing is written before it passes; the only permitted write on a mismatch is the fail-closed HALT)
    try: probs, info = verify_ops(cfg, g)
    except ConfigError as e: return _res(CONFIG_ERROR, reason=str(e))
    ident.update({k: v for k, v in info.items() if k in ident})
    def halt(cls, why, result, store=None, tip=None):
        return _res(result, durable=write_halt(cfg, g, cls, why, ident, now, store, tip), reason=why, halt_class=cls)
    if probs:
        cls = "WORKFLOW" if any(c == "WORKFLOW" for c, _ in probs) else ("RUNTIME" if all(c == "RUNTIME" for c, _ in probs) else "OPS")
        return halt(cls, "; ".join(m for _, m in probs)[:300], OPS_INTEGRITY_FAILURE)
    # ---- 2. canonical origin / window (pure; independent of the trigger time)
    origin, why = eligible_origin(now)
    if origin is None: return _res(SKIPPED_NOT_DUE, reason=why)
    o_s = fmt_ts(origin)
    # ---- 3. ledger: present? structural integrity (chain, schema, state machine, anchors, history shape) -- recomputed every wake, independent of any HALT marker
    st = Store(g, cfg.ledger_remote, uniq("ledger")); state = st.remote_state()
    if state == "error": return _res(LEDGER_UNAVAILABLE, reason="cannot reach the ledger remote")
    if state == "missing":
        return _res(INTEGRITY_FAILURE if st.remote_has_anchors() else NOT_INITIALISED, reason="ledger branch missing" + (" while anchor tags exist (deleted)" if st.remote_has_anchors() else " (initialise explicitly with init-ledger)"))
    if not st.refresh(): return _res(LEDGER_UNAVAILABLE, reason="cannot fetch the ledger branch")
    recs, probs = structural_check(st)
    if probs: return halt("LEDGER", probs[0], INTEGRITY_FAILURE)
    if any(r["state"] == "HALT" for r in recs) or st.halt_file(): return _res(HALTED, durable=True, reason="HALT present")
    # ---- 4. candidate: reconstruct (upstream@pin + user history) and verify against the literal freeze commit
    cand = cfg.candidate_dir
    if cand is None:
        cand = uniq("candidate")
        try: cp = reconstruct_candidate(g, cand, cfg.candidate_source_kind, cfg.candidate_source, cfg.upstream_url, cfg.upstream_commit, allow_local=cfg.allow_local_remotes)
        except GitError as e: cp = [f"candidate reconstruction failed: {e}"]
    else: cp = []
    if not cp: cp = verify_candidate(cfg, cand)
    if cp: return halt("CANDIDATE", "; ".join(cp)[:300], CANDIDATE_MISMATCH)
    SJ, SS, VF = load_frozen(cand)
    # ---- 5. journal chain + heads, then HALT-independent decision
    jrecs_before, jp = journal_problems(SJ, st, recs)
    if jp: return halt("JOURNAL", jp[0], INTEGRITY_FAILURE)
    for loop in range(8):
        if loop:
            if not st.refresh(): return _res(LEDGER_UNAVAILABLE, reason="ledger vanished during claim")
            recs, probs = structural_check(st)
            if probs: return halt("LEDGER", probs[0], INTEGRITY_FAILURE)
            if any(r["state"] == "HALT" for r in recs) or st.halt_file(): return _res(HALTED, durable=True)
        verdict, arg = decide(recs, origin, now)
        if verdict == "SKIP": return _res(arg)
        jh = recs[-1]["journal_head"]
        claim = make_record(recs[-1], "STARTED", dict(ident, journal_head=jh, ts=fmt_ts(now)), origin=o_s, attempt_no=arg)
        raw = st.ledger_bytes(); tag = st.stage(claim, raw); status = st.push(tag) if tag else "REJECTED"
        if status == "OK": break
        if tag: st.unstage(tag)
        if status == "RULE_REJECTED": return _res(RULESET_REJECTION, reason="ledger push rejected by a branch/tag rule")
        if status == "ERROR": return _res(LEDGER_UNAVAILABLE, reason="ledger push failed (network)")
        time.sleep(random.uniform(0.02, 0.15))                    # lost the CAS: re-fetch, re-verify, RE-DECIDE (never a blind retry)
    else: return _res(SKIPPED_LOST_RACE)
    if cfg.claim_only: return _res(CLAIMED, durable=True, attempt_no=arg)
    # ---- 6. run the FROZEN runner (token-free environment, hard timeout), then re-verify the candidate and validate only the NEW state
    jdir = os.path.join(st.path, "journal"); os.makedirs(jdir, exist_ok=True)
    cmd = cfg.runner_cmd_fn(o_s, jdir, cand, now) if cfg.runner_cmd_fn else [sys.executable, "-B", os.path.join(cand, "tools", "shadow_run.py"), "--expect-sha", CANDIDATE_SHA,
                                                                           "--tag", CANDIDATE_TAG, "--t0", origin.strftime(FMT), "--journal-dir", jdir]
    assert "--late-ok" not in cmd, "late-ok is never used"
    try: subprocess.run(cmd, cwd=cand, capture_output=True, text=True, env=runner_env(cfg), timeout=RUNNER_TIMEOUT_S)
    except subprocess.TimeoutExpired: pass
    t_fin = (cfg.final_now_fn or cfg.now_fn)().astimezone(UTC).replace(microsecond=0)
    ident["ts"] = fmt_ts(t_fin)
    cp = verify_candidate(cfg, cand)
    if cp: return halt("CANDIDATE", "candidate mutated during/after the run: " + "; ".join(cp)[:240], CANDIDATE_MISMATCH)
    SJ, SS, VF = load_frozen(cand)
    J = SJ.Journal(os.path.join(jdir, "journal.jsonl")); jrecs, jp = J.read()
    if jp: return halt("JOURNAL", "journal integrity failure after run: " + jp[0], INTEGRITY_FAILURE)
    if jrecs[:len(jrecs_before)] != jrecs_before: return halt("JOURNAL", "previously recorded journal records changed during the run", INTEGRITY_FAILURE)
    new = jrecs[len(jrecs_before):]; jhead = jrecs[-1]["record_hash"] if jrecs else GENESIS
    ident["journal_head"] = jhead                                # HALT-with-evidence and the terminal record both bind the post-run journal head
    succ_all = [r for r in jrecs if r["type"] == "SUCCESS" and r["origin"] == o_s]
    if len(succ_all) > 1 or any(r["type"] == "REFUSED" and "duplicate" in r.get("reason", "") for r in new):
        return halt("DUPLICATE_SUCCESS", "duplicate SUCCESS for one origin", INTEGRITY_FAILURE, st, claim)
    succ = [r for r in new if r["type"] == "SUCCESS"]
    if succ:
        bad = SS.check_success(jdir, succ[0], VF.candidate_fields(cand, CANDIDATE_SHA, CANDIDATE_TAG), origin)
        if bad: return halt("REPRODUCTION", "forecast binding/reproduction failure: " + "; ".join(bad)[:240], INTEGRITY_FAILURE, st, claim)
        term = make_record(claim, "SUCCESS", ident, origin=o_s, attempt_no=arg, forecast_sha256=succ[0]["forecast_sha256"], feed_sha256=succ[0]["feed_sha256"], journal_attempt_id=succ[0]["attempt_id"])
    else:
        why = clean_reason("runner produced no journal record" if not new else (new[-1].get("reason") or ("runner exited without a final journal record" if new[-1]["type"] == "STARTED" else new[-1]["type"])), "runner failed")
        term = make_record(claim, "FAILED", ident, origin=o_s, attempt_no=arg, reason=why, journal_attempt_id=(new[-1].get("attempt_id") if new else None))
    # ---- 7. terminal record: CAS push of (record + journal files + anchor)
    tag = st.stage(term, st.ledger_bytes())
    for k in range(3):
        status = st.push(tag) if tag else "REJECTED"
        if status != "ERROR": break
        time.sleep(1.0 * (k + 1))
    if status == "OK": return _res(term["state"], durable=True, ran=True, attempt_no=arg)
    if status == "ERROR": return _res(LEDGER_UNAVAILABLE, ran=True, reason="terminal push failed (network); the claim stays incomplete until its lease expires")
    if status == "RULE_REJECTED": return _res(RULESET_REJECTION, ran=True, reason="terminal push rejected by a rule")
    if (t_fin - parse_ts(claim["ts"])) > LEASE: return _res(ABANDONED, ran=True, attempt_no=arg, reason="lease expired and the ledger moved on; local result discarded")
    return halt("UNEXPECTED_WRITER", "ledger moved during my lease", INTEGRITY_FAILURE)


# ------------------------------------------------------------------------------------------------------------- read-only audit, init, check-ops
def audit(cfg, full=False):
    """Read-only.  Per-wake checks validate only the NEW state; the expensive full historical forecast reproduction belongs here (scoring/audit)."""
    if cfg.work_root is None: cfg.work_root = tempfile.mkdtemp(prefix="r3-audit-")
    g = Git(cfg.token, cfg.git_isolated); st = Store(g, cfg.ledger_remote, os.path.join(cfg.work_root, "audit"))
    if st.remote_state() != "present" or not st.refresh(): return dict(ok=False, problems=["ledger branch missing/unreachable"])
    recs, probs = structural_check(st)
    out = dict(records=len(recs), problems=list(probs), reproduced=0)
    if probs: out["ok"] = False; return out
    cand = cfg.candidate_dir
    if cand is None:
        cand = os.path.join(cfg.work_root, "audit-candidate")
        cp = reconstruct_candidate(g, cand, cfg.candidate_source_kind, cfg.candidate_source, cfg.upstream_url, cfg.upstream_commit, allow_local=cfg.allow_local_remotes)
        if cp: out["problems"] += cp; out["ok"] = False; return out
    cp = verify_candidate(cfg, cand)
    if cp: out["problems"] += cp; out["ok"] = False; return out
    SJ, SS, VF = load_frozen(cand); jrecs, jp = journal_problems(SJ, st, recs); out["problems"] += jp
    if full and not jp:
        cf = VF.candidate_fields(cand, CANDIDATE_SHA, CANDIDATE_TAG); jdir = os.path.join(st.path, "journal")
        by_origin = {}
        for r in jrecs:
            if r["type"] == "SUCCESS": by_origin.setdefault(r["origin"], []).append(r)
        for o, lst in by_origin.items():
            if len(lst) > 1: out["problems"].append(f"{o}: duplicate SUCCESS in the journal"); continue
            bad = SS.check_success(jdir, lst[0], cf, parse_ts(o))
            if bad: out["problems"].append(f"{o}: " + "; ".join(bad)[:200])
            out["reproduced"] += 1
    out["ok"] = not out["problems"]; return out


def init_ledger(cfg):
    """Explicit one-time bootstrap.  Needs the ops gate and a verified candidate; refuses if the branch or any anchor already exists."""
    if cfg.work_root is None: cfg.work_root = tempfile.mkdtemp(prefix="r3-init-")
    g = Git(cfg.token, cfg.git_isolated); now = cfg.now_fn().astimezone(UTC).replace(microsecond=0)
    try: probs, info = verify_ops(cfg, g)
    except ConfigError as e: return _res(CONFIG_ERROR, reason=str(e))
    if probs: return _res(OPS_INTEGRITY_FAILURE, reason="; ".join(m for _, m in probs)[:300])
    cand = cfg.candidate_dir
    if cand is None:
        cand = os.path.join(cfg.work_root, "init-candidate")
        cp = reconstruct_candidate(g, cand, cfg.candidate_source_kind, cfg.candidate_source, cfg.upstream_url, cfg.upstream_commit, allow_local=cfg.allow_local_remotes)
        if cp: return _res(CANDIDATE_MISMATCH, reason=cp[0])
    cp = verify_candidate(cfg, cand)
    if cp: return _res(CANDIDATE_MISMATCH, reason="; ".join(cp)[:300])
    probe = Store(g, cfg.ledger_remote, os.path.join(cfg.work_root, "init-probe"))
    if probe.remote_state() != "missing" or probe.remote_has_anchors(): return _res(INTEGRITY_FAILURE, reason="ledger branch or anchors already exist: init-ledger never overwrites or extends")
    w = os.path.join(cfg.work_root, "init-work"); os.makedirs(w, exist_ok=True); g.run(w, "init", "-q", "-b", BRANCH); g.run(w, "remote", "add", "origin", cfg.ledger_remote)
    ident = dict(candidate_sha=CANDIDATE_SHA, workflow_sha=cfg.workflow_sha, journal_head=GENESIS, ts=fmt_ts(now), run_id=cfg.run_id, run_attempt=cfg.run_attempt, runtime_identity=runtime_identity(),
                 **{k: info[k] for k in ("ops_commit", "wrapper_sha256", "workflow_blob", "lock_sha256")})
    rec = make_record(None, "INIT", ident)
    open(os.path.join(w, "ledger.jsonl"), "wb").write((canon(rec) + "\n").encode())
    g.run(w, "add", "-A"); g.run(w, "commit", "-q", "-m", f"ledger seq=0 hash={rec['record_hash']}"); g.run(w, "tag", f"{ANCHOR}000000")
    r = g.run(w, "push", "-q", "--atomic", "origin", f"HEAD:refs/heads/{BRANCH}", f"refs/tags/{ANCHOR}000000", check=False, remote=cfg.ledger_remote)
    return _res("INIT", durable=r.returncode == 0, reason=None if r.returncode == 0 else g.scrub(r.stderr.strip()[:200]))


def check_ops(cfg):
    g = Git(cfg.token, cfg.git_isolated)
    try: probs, info = verify_ops(cfg, g)
    except ConfigError as e: return dict(ops_integrity="CONFIG_ERROR", problems=[str(e)])
    return dict(ops_integrity="ok" if not probs else "FAILED", problems=[m for _, m in probs], **info)


# ------------------------------------------------------------------------------------------------------------- production configuration (GitHub Actions environment)
def build_production_config(env):
    """Reads the independent pin store (Actions variables mapped to env by the workflow) and the GitHub run context.  Missing/malformed -> ConfigError (no HALT)."""
    need = {"ops_commit": "OPS_COMMIT_PIN", "wrapper_sha256": "OPS_WRAPPER_SHA256_PIN", "workflow_blob": "WORKFLOW_BLOB_PIN", "lock_sha256": "DEP_LOCK_SHA256_PIN"}
    pins = {k: env.get(v, "") for k, v in need.items()}
    server, repo = env.get("GITHUB_SERVER_URL", ""), env.get("GITHUB_REPOSITORY", "")
    if server != "https://github.com": raise ConfigError("GITHUB_SERVER_URL must be https://github.com")
    if not re.match(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\Z", repo): raise ConfigError("GITHUB_REPOSITORY missing or malformed")
    src = env.get("CANDIDATE_SOURCE_URL", "")
    if not check_remote_url(src, False): raise ConfigError("CANDIDATE_SOURCE_URL must be an https://github.com/<owner>/<repo> URL")
    run_id = env.get("GITHUB_RUN_ID", ""); ra = env.get("GITHUB_RUN_ATTEMPT", "1")
    if not ID_RE.match(run_id) or not ra.isdigit() or int(ra) < 1: raise ConfigError("GITHUB_RUN_ID / GITHUB_RUN_ATTEMPT missing or malformed")
    token = env.get("GITHUB_TOKEN") or None
    wf = env.get("WORKFLOW_SHA_EVIDENCE") or None
    return Config(pins=pins, ledger_remote=f"{server}/{repo}", run_id=run_id, run_attempt=int(ra), workflow_sha=wf if wf and HEX40.match(wf) else None, token=token,
                  candidate_source=src, candidate_source_kind="git", production=True, enforce_runtime=True, allow_local_remotes=False, git_isolated=True)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    ok = (len(argv) == 1 and argv[0] in ("run", "check-ops", "verify-ledger", "init-ledger")) or argv == ["verify-ledger", "--full"]
    if not ok:
        print("usage: shadow_ops_r3.py run | check-ops | verify-ledger [--full] | init-ledger   (production accepts no other options)", file=sys.stderr); return 2
    try: cfg = build_production_config(dict(os.environ))
    except ConfigError as e:
        print(json.dumps({"result": CONFIG_ERROR, "reason": str(e)}, sort_keys=True)); return EXIT[CONFIG_ERROR]
    os.environ.pop("GITHUB_TOKEN", None)                       # the token lives only in cfg.token (passed to git subprocesses on github.com); never in os.environ, never in the runner's env
    cmd = argv[0]
    if cmd == "check-ops": out = check_ops(cfg); print(json.dumps(out, sort_keys=True)); return 0 if out.get("ops_integrity") == "ok" else EXIT[OPS_INTEGRITY_FAILURE]
    if cmd == "verify-ledger": out = audit(cfg, full=len(argv) == 2); print(json.dumps(out, sort_keys=True)); return 0 if out.get("ok") else EXIT[INTEGRITY_FAILURE]
    out = init_ledger(cfg) if cmd == "init-ledger" else run_once(cfg)
    print(json.dumps({k: out.get(k) for k in ("result", "durable", "ran", "reason", "halt_class", "attempt_no")}, sort_keys=True))
    return EXIT.get(out["result"], 0)


if __name__ == "__main__":
    sys.exit(main())
