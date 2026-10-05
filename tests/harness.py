"""Shared fixtures for the R3 tests.  Disposable temp dirs only; synthetic feeds; no network; no production state."""
import os, sys, json, subprocess, tempfile, shutil, itertools, hashlib, time
sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__)); REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
import shadow_ops_r3 as R

KIT = os.environ.get("R3_TEST_KIT") or os.path.normpath(os.path.join(REPO, "..", "benchlab-starter-kit"))     # read-only source of the candidate fixtures
PY = sys.executable
STUB = os.path.join(HERE, "stub_runner.py")
ENVBASE = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
N = itertools.count()
IDG = ["-c", "user.name=t", "-c", "user.email=t@users.noreply.invalid", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"]


def sh(*a, cwd=None, check=True):
    r = subprocess.run(a, capture_output=True, text=True, cwd=cwd, env=ENVBASE)
    if check and r.returncode != 0: raise RuntimeError(f"{a[:4]}: {r.stderr[-300:]}")
    return r.stdout.strip()


def git(cwd, *a, check=True): return sh("git", *IDG, *a, cwd=cwd, check=check)


def make_bundle(td):
    out = os.path.join(td, "candidate.bundle"); sh(PY, "-B", os.path.join(REPO, "tools", "make_candidate_bundle.py"), "--kit", KIT, "--out", out); return out


def make_candidate(td, bundle=None, verify_real=True, name="candidate"):
    """Reconstruct the frozen candidate: official upstream commit (by exact SHA; here the local kit stands in for the official source) + the thin user bundle."""
    bundle = bundle or make_bundle(td); dest = os.path.join(td, name); g = R.Git(None, True)
    probs = R.reconstruct_candidate(g, dest, "bundle", bundle, KIT, R.UPSTREAM_COMMIT, allow_local=True)
    assert not probs, probs
    if verify_real:
        v = R.verify_candidate(R.Config(), dest); assert v == [], v
    return dest, bundle


def make_ops(td, name=None, mutate=None):
    """A temporary ops repository holding the REAL wrapper, lock and workflow bytes.  Returns (dir, pins)."""
    d = os.path.join(td, name or f"ops{next(N)}")
    for rel in (R.WRAPPER_NAME, R.LOCK_NAME, R.WORKFLOW_PATH, ".gitattributes", ".gitignore"):
        os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True); shutil.copyfile(os.path.join(REPO, rel), os.path.join(d, rel))
    if mutate: mutate(d)
    sh("git", "init", "-q", "-b", "main", d); git(d, "add", "-A"); git(d, "commit", "-q", "-m", "ops")
    return d, pins_of(d)


def pins_of(d):
    return dict(ops_commit=git(d, "rev-parse", "HEAD"), wrapper_sha256=hashlib.sha256(open(os.path.join(d, R.WRAPPER_NAME), "rb").read()).hexdigest(),
                workflow_blob=git(d, "rev-parse", f"HEAD:{R.WORKFLOW_PATH}"), lock_sha256=hashlib.sha256(open(os.path.join(d, R.LOCK_NAME), "rb").read()).hexdigest())


def make_remote(td, harden=True):
    p = os.path.join(td, f"remote{next(N)}.git"); sh("git", "init", "-q", "--bare", p)
    if harden:        # local analogue of "block force pushes + restrict deletions" -- NOT proof of GitHub ruleset behaviour
        git(p, "config", "receive.denyNonFastForwards", "true"); git(p, "config", "receive.denyDeletes", "true")
    return p


def stub_cmd(o_s, jdir, cand, now):
    return [PY, "-B", STUB, "--journal-dir", jdir, "--t0", R.parse_ts(o_s).strftime(R.FMT), "--expect-sha", R.CANDIDATE_SHA, "--tag", R.CANDIDATE_TAG, "--repo", cand, "--now", R.fmt_ts(now)]


def build_cfg(spec):
    """Config from a JSON-able spec (used in-process and by the multi-process worker)."""
    now = R.parse_ts(spec["now"]); fin = R.parse_ts(spec["final_now"]) if spec.get("final_now") else None
    env = {"STUB_MODE": spec.get("mode", "success")}
    if spec.get("marker"): env["STUB_MARKER"] = spec["marker"]
    if spec.get("sleep"): env["STUB_SLEEP"] = str(spec["sleep"])
    env.update(spec.get("extra_env") or {})
    return R.Config(ops_dir=spec["ops_dir"], pins=spec["pins"], ledger_remote=spec["remote"], work_root=spec["work_root"], now_fn=lambda: now, final_now_fn=(lambda: fin) if fin else None,
                    run_id=spec.get("run_id", "run-1"), run_attempt=spec.get("run_attempt", 1), workflow_sha=spec.get("workflow_sha"), token=spec.get("token"),
                    candidate_dir=spec["cand"], verify_fn=None if spec.get("real_verify") else ((lambda d, p=spec["verify_problem"]: [p]) if spec.get("verify_problem") is not None else (lambda d: [])), runner_cmd_fn=stub_cmd, runner_env_extra=env,
                    allow_local_remotes=True, enforce_runtime=bool(spec.get("enforce_runtime", False)), claim_only=bool(spec.get("claim_only", False)))


class Env:
    """One universe: hardened local ledger remote + temporary ops repo + candidate + marker file."""
    def __init__(self, td, cand, ops=None, harden=True):
        self.td, self.cand = td, cand; self.remote = make_remote(td, harden); self.ops_dir, self.pins = ops or make_ops(td); self.marker = os.path.join(td, f"marker{next(N)}.jsonl")

    def spec(self, now, **kw):
        s = dict(now=now, ops_dir=self.ops_dir, pins=self.pins, remote=self.remote, cand=self.cand, work_root=tempfile.mkdtemp(prefix="w", dir=self.td), marker=self.marker)
        s.update(kw); return s

    def cfg(self, now, **kw): return build_cfg(self.spec(now, **kw))
    def go(self, now, **kw): return R.run_once(self.cfg(now, **kw))

    def init(self):
        r = R.init_ledger(self.cfg("2026-10-05T11:00:00Z")); assert r["result"] == "INIT" and r["durable"], r; return self

    def view(self):
        st = R.Store(R.Git(None, True), self.remote, tempfile.mkdtemp(prefix="v", dir=self.td)); ok = st.refresh()
        if not ok: return st, [], ["branch missing"]
        recs, p = R.structural_check(st); return st, recs, p

    def states(self): return [r["state"] for r in self.view()[1]]
    def count(self, state, origin=None): return sum(1 for r in self.view()[1] if r["state"] == state and (origin is None or r.get("origin") == origin))
    def has_halt(self): st, recs, _ = self.view(); return any(r["state"] == "HALT" for r in recs) or st.halt_file()
    def markers(self): return [json.loads(l) for l in open(self.marker)] if os.path.exists(self.marker) else []

    def human_edit(self, relpath, fn):
        """An ordinary push-rights human/attacker: a normal fast-forward commit on the ledger branch."""
        st = R.Store(R.Git(None, True), self.remote, tempfile.mkdtemp(prefix="h", dir=self.td)); st.refresh(); p = os.path.join(st.path, relpath); os.makedirs(os.path.dirname(p), exist_ok=True)
        cur = open(p, "rb").read() if os.path.exists(p) else b""; new = fn(cur)
        if new is None:
            if os.path.exists(p): os.remove(p)
        else: open(p, "wb").write(new)
        git(st.path, "add", "-A")
        if not git(st.path, "status", "--porcelain"): return False
        git(st.path, "commit", "-q", "-m", "human edit"); return git(st.path, "push", "-q", "origin", f"HEAD:refs/heads/{R.BRANCH}", check=False) == ""

    def seed(self, specs):
        """Append schema-valid records directly (valid chain + anchors, journal untouched).  specs: (state, origin, attempt_no, ts)."""
        for stt, o, n, ts in specs:
            st = R.Store(R.Git(None, True), self.remote, tempfile.mkdtemp(prefix="s", dir=self.td)); assert st.refresh(); raw = st.ledger_bytes(); recs, p = R.parse_ledger(raw); assert not p, p
            extra = dict(origin=o, attempt_no=n)
            if stt == "FAILED": extra.update(reason="seeded failure", journal_attempt_id=None)
            rec = R.make_record(recs[-1], stt, dict(self.ident(), journal_head=recs[-1]["journal_head"], ts=ts), **extra); tag = st.stage(rec, raw); assert tag and st.push(tag) == "OK"

    def ident(self):
        return dict(candidate_sha=R.CANDIDATE_SHA, ops_commit=self.pins["ops_commit"], wrapper_sha256=self.pins["wrapper_sha256"], workflow_blob=self.pins["workflow_blob"], lock_sha256=self.pins["lock_sha256"],
                    workflow_sha=None, journal_head=R.GENESIS, ts="2026-10-05T11:00:00Z", run_id="seed", run_attempt=1, runtime_identity="py-test/numpy-test/x")


def spawn(env, now, start_at, **kw):
    """One wake in its own OS process (a separate 'runner')."""
    spec = env.spec(now, start_at=start_at, **kw)
    return subprocess.Popen([PY, "-B", os.path.join(HERE, "worker.py"), json.dumps(spec)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=ENVBASE)


def collect(ps):
    out = []
    for p in ps:
        o, e = p.communicate(timeout=900); ln = [l for l in o.splitlines() if l.startswith("{")]
        out.append(json.loads(ln[-1]) if ln else {"result": "WORKER_CRASH", "stderr": e[-400:], "rc": p.returncode})
    return out
