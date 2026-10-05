"""R3 platform probe: exercises the AUDITED wrapper module (imported from the pinned ops commit) against a real GitHub ledger branch with SYNTHETIC fixtures only.
No candidate, no live data, no participant site.  Every result is printed as one `LAB> {json}` line.  Usage: python3 lab.py <scenario>"""
import os, sys, json, time, subprocess, base64, tempfile, urllib.request, urllib.error, hashlib
sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.getcwd()
OPS = os.path.join(ROOT, "ops"); sys.path.insert(0, OPS)
import shadow_ops_r3 as R
from datetime import datetime, timezone, timedelta
REPO = os.environ["GITHUB_REPOSITORY"]; REMOTE = f"https://github.com/{REPO}"; TOKEN = os.environ.get("GITHUB_TOKEN") or None
PINS = dict(ops_commit=os.environ["OPS_COMMIT_PIN"], wrapper_sha256=os.environ["OPS_WRAPPER_SHA256_PIN"], workflow_blob=os.environ["WORKFLOW_BLOB_PIN"], lock_sha256=os.environ["DEP_LOCK_SHA256_PIN"])
CAND = os.path.join(HERE, "synthetic", "candidate"); STUB = os.path.join(HERE, "synthetic", "stub_runner.py"); MARK = os.path.join(tempfile.gettempdir(), "lab_marker.jsonl")
TMP = tempfile.mkdtemp(prefix="lab-"); N = [0]


def out(kind, **kw): print("LAB> " + json.dumps(dict(kind=kind, **kw), sort_keys=True, default=str), flush=True)
def san(s):
    s = s or ""
    if TOKEN: s = s.replace(TOKEN, "***").replace(base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode(), "***")
    return s.replace("\r", "")[:600]
def d(p): N[0] += 1; q = os.path.join(TMP, f"{p}{N[0]}"); os.makedirs(q); return q
def T(s): return R.parse_ts(s)


def stub_cmd(o_s, jdir, cand, now):
    return [sys.executable, "-B", STUB, "--journal-dir", jdir, "--t0", R.parse_ts(o_s).strftime(R.FMT), "--repo", cand, "--now", R.fmt_ts(now)]


def mkcfg(now, mode="success", pins=None, verify_problem=None, claim_only=False, token=True, remote=None, final=None, runtime=True):
    return R.Config(ops_dir=OPS, pins=pins or PINS, ledger_remote=remote or REMOTE, work_root=d("w"), now_fn=lambda: T(now), final_now_fn=(lambda: T(final)) if final else None,
                    run_id=os.environ.get("GITHUB_RUN_ID", "local"), run_attempt=int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")), workflow_sha=os.environ.get("WORKFLOW_SHA_EVIDENCE") or None,
                    token=TOKEN if token else None, candidate_dir=CAND, verify_fn=(lambda c: [verify_problem]) if verify_problem is not None else (lambda c: []), runner_cmd_fn=stub_cmd,
                    runner_env_extra={"STUB_MODE": mode, "STUB_MARKER": MARK}, enforce_runtime=runtime, claim_only=claim_only)


def store(token=True):
    return R.Store(R.Git(TOKEN if token else None, True), REMOTE, d("s"))


def refs():
    r = subprocess.run(["git", "ls-remote", REMOTE], capture_output=True, text=True, env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
    return [l.split("\t")[1] for l in r.stdout.splitlines() if "shadow-ledger" in l or "anchor-" in l]


def reset():
    """Test-environment reset of the SYNTHETIC ledger (only possible while no deletion rule is active)."""
    st = store(); rs = refs()
    if not rs: return True
    r = st.g.run(st.path, "push", "origin", "--delete", *rs, check=False, remote=REMOTE); return r.returncode == 0


def ff_edit(rel, fn, msg="synthetic human edit"):
    st = store(); assert st.refresh(); p = os.path.join(st.path, rel); cur = open(p, "rb").read() if os.path.exists(p) else b""; new = fn(cur)
    if new is None: os.remove(p)
    else: open(p, "wb").write(new)
    st.g.run(st.path, "add", "-A"); st.g.run(st.path, "commit", "-q", "-m", msg)
    return st.g.run(st.path, "push", "-q", "origin", f"HEAD:refs/heads/{R.BRANCH}", check=False, remote=REMOTE)


def view():
    st = store()
    if not st.refresh(): return dict(branch=False)
    recs, probs = R.structural_check(st)
    return dict(branch=True, states=[r["state"] for r in recs], problems=[p[:120] for p in probs[:3]], halt_file=st.halt_file(), tags=sorted(st.anchors()))


def init(now="2030-01-01T00:00:00Z"):
    r = R.init_ledger(mkcfg(now)); out("init", **{k: r.get(k) for k in ("result", "durable", "reason")}); return r


def sc_init(): reset(); init()


def sc_cas_claim():
    barrier = float(os.environ["BARRIER"]); label = os.environ.get("CLAIMER", "?")
    st = store(); ok = st.refresh(); raw = st.ledger_bytes(); recs, probs = R.parse_ledger(raw)
    ident = dict(candidate_sha=R.CANDIDATE_SHA, ops_commit=PINS["ops_commit"], wrapper_sha256=PINS["wrapper_sha256"], workflow_blob=PINS["workflow_blob"], lock_sha256=PINS["lock_sha256"], workflow_sha=None,
                 journal_head=recs[-1]["journal_head"], ts="2030-02-01T00:07:00Z", run_id="probe-identical-run", run_attempt=1, runtime_identity="probe")      # identical identity for every claimer on purpose
    rec = R.make_record(recs[-1], "STARTED", ident, origin="2030-02-01T00:00:00Z", attempt_no=1); tag = st.stage(rec, raw)
    while time.time() < barrier: time.sleep(0.005)
    t = time.time(); r = st.g.run(st.path, "push", "-q", "--atomic", "origin", f"HEAD:refs/heads/{R.BRANCH}", f"refs/tags/{tag}", check=False, remote=REMOTE)
    out("cas-claim", claimer=label, rc=r.returncode, cls=("OK" if r.returncode == 0 else R.classify_push_error(r.stderr)), stderr=san(r.stderr), base_seq=recs[-1]["seq"], pushed_at=t, started_before_barrier=(t >= barrier))


def sc_cas_verify():
    st = store(); st.refresh(); recs, probs = R.structural_check(st)
    out("cas-verify", states=[r["state"] for r in recs], started_for_origin=sum(1 for r in recs if r["state"] == "STARTED" and r.get("origin") == "2030-02-01T00:00:00Z"), problems=probs[:3], tags=sorted(st.anchors()))


def sc_single():
    reset(); init()
    # (a) byte-identical claim commits: what happens when the SAME commit is pushed twice
    s1, s2 = store(), store(); s1.refresh(); s2.refresh(); raw = s1.ledger_bytes(); recs, _ = R.parse_ledger(raw)
    os.environ["GIT_AUTHOR_DATE"] = os.environ["GIT_COMMITTER_DATE"] = "2030-02-01T00:00:00 +0000"
    ident = dict(candidate_sha=R.CANDIDATE_SHA, ops_commit=PINS["ops_commit"], wrapper_sha256=PINS["wrapper_sha256"], workflow_blob=PINS["workflow_blob"], lock_sha256=PINS["lock_sha256"], workflow_sha=None,
                 journal_head=recs[-1]["journal_head"], ts="2030-02-01T00:07:00Z", run_id="probe-identical-run", run_attempt=1, runtime_identity="probe")
    rec = R.make_record(recs[-1], "STARTED", ident, origin="2030-02-01T00:00:00Z", attempt_no=1)       # ONE record object -> byte-identical in both clones
    t1 = s1.stage(rec, raw); t2 = s2.stage(rec, raw); c1 = s1.g.run(s1.path, "rev-parse", "HEAD").stdout.strip(); c2 = s2.g.run(s2.path, "rev-parse", "HEAD").stdout.strip()
    r1 = s1.g.run(s1.path, "push", "-q", "--atomic", "origin", f"HEAD:refs/heads/{R.BRANCH}", f"refs/tags/{t1}", check=False, remote=REMOTE)
    r2 = s2.g.run(s2.path, "push", "--atomic", "origin", f"HEAD:refs/heads/{R.BRANCH}", f"refs/tags/{t2}", check=False, remote=REMOTE)
    for k in ("GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE"): os.environ.pop(k, None)
    out("identical-commit", same_commit_sha=(c1 == c2), first_rc=r1.returncode, second_rc=r2.returncode, second_stderr=san(r2.stderr), second_class_by_wrapper=("OK" if r2.returncode == 0 else R.classify_push_error(r2.stderr)),
        conclusion=("second identical push is reported as SUCCESS by git (a no-op): the per-record nonce is REQUIRED" if r2.returncode == 0 and c1 == c2 else "second push rejected"))
    # (b) remote moved between fetch and push
    reset(); init(); a, b = store(), store(); a.refresh(); b.refresh(); ra = a.ledger_bytes(); rr, _ = R.parse_ledger(ra); idn = dict(ident, journal_head=rr[-1]["journal_head"], run_id="probe-a")
    rec_b = R.make_record(rr[-1], "STARTED", dict(idn, run_id="probe-b"), origin="2030-02-01T00:00:00Z", attempt_no=1); tb = b.stage(rec_b, ra); sb = b.push(tb)
    rec_a = R.make_record(rr[-1], "STARTED", idn, origin="2030-02-01T00:00:00Z", attempt_no=1); ta = a.stage(rec_a, ra)
    ra_ = a.g.run(a.path, "push", "--atomic", "origin", f"HEAD:refs/heads/{R.BRANCH}", f"refs/tags/{ta}", check=False, remote=REMOTE)
    out("remote-moved", winner_push=sb, loser_rc=ra_.returncode, loser_class=R.classify_push_error(ra_.stderr), loser_stderr=san(ra_.stderr))
    # (c) ambiguous / non-CAS failures: bad token, missing repository
    bad = R.Git("ghs_" + "0" * 36, True); w = d("bad"); bs = R.Store(bad, REMOTE, w); r = bs.g.run(w, "push", "origin", "HEAD:refs/heads/probe-badtoken", check=False, remote=REMOTE)
    out("bad-token-push", rc=r.returncode, cls=R.classify_push_error(r.stderr), stderr=san(r.stderr))
    miss = REMOTE + "-does-not-exist"; w2 = d("miss"); ms = R.Store(R.Git(TOKEN, True), miss, w2); r = ms.g.run(w2, "fetch", "origin", check=False, remote=miss)
    out("missing-repo-fetch", rc=r.returncode, cls=R.classify_push_error(r.stderr), stderr=san(r.stderr))
    out("single-final", view=view())


def run_wake(label, now, **kw):
    r = R.run_once(mkcfg(now, **kw)); out("wake", label=label, now=now, **{k: r.get(k) for k in ("result", "durable", "ran", "reason", "halt_class", "attempt_no")}); return r


def sc_flow():
    reset(); init()
    if os.path.exists(MARK): os.remove(MARK)
    for lab, now, kw in (("o1 +7 runner fails", "2030-03-01T00:07:00Z", dict(mode="fail")), ("o1 +17 runner fails", "2030-03-01T00:17:00Z", dict(mode="fail")),
                         ("o1 +27 success (env dump)", "2030-03-01T00:27:00Z", dict(mode="envdump")), ("o1 +37 after SUCCESS", "2030-03-01T00:37:00Z", {}), ("o1 +41 outside window", "2030-03-01T00:41:00Z", {}),
                         ("o2 +7 claim only (simulated crash)", "2030-03-01T06:07:00Z", dict(claim_only=True)), ("o2 +17 inside lease", "2030-03-01T06:17:00Z", {}), ("o2 +27 after lease", "2030-03-01T06:27:00Z", {}),
                         ("o2 +37 after SUCCESS", "2030-03-01T06:37:00Z", {}), ("o3 +7 fail", "2030-03-01T12:07:00Z", dict(mode="fail")), ("o3 +17 fail", "2030-03-01T12:17:00Z", dict(mode="fail")),
                         ("o3 +27 fail", "2030-03-01T12:27:00Z", dict(mode="fail")), ("o3 +37 fourth wake", "2030-03-01T12:37:00Z", {}), ("o4 no backfill: wake at 18:41", "2030-03-01T18:41:00Z", {})):
        run_wake(lab, now, **kw)
    marks = [json.loads(l) for l in open(MARK)] if os.path.exists(MARK) else []
    out("env-marker", entries=marks); out("flow-final", view=view())


def corrupt_ledger(): return ff_edit("ledger.jsonl", lambda b: b.replace(b'"state":"INIT"', b'"state":"INIX"', 1))


def sc_halt_all():
    NOW = "2030-04-01T00:07:00Z"; res = {}
    def case(name, setup, **kw):
        reset(); init(); setup(); r = R.run_once(mkcfg(NOW, **kw)); v = view()
        out("halt-case", case=name, result=r.get("result"), durable=r.get("durable"), ran=r.get("ran"), halt_class=r.get("halt_class"), reason=san(str(r.get("reason")))[:160], remote_view=v)
    case("malformed ledger (FF edit of ledger.jsonl)", lambda: corrupt_ledger())
    case("missing anchor tag", lambda: (run_wake("seed success", "2030-04-01T00:05:00Z"), store().g.run(d("x"), "push", "origin", "--delete", f"refs/tags/{R.ANCHOR}000001", check=False, remote=REMOTE)))
    def beyond():
        s = store(); s.refresh(); s.g.run(s.path, "tag", f"{R.ANCHOR}000002"); s.g.run(s.path, "push", "origin", f"refs/tags/{R.ANCHOR}000002", check=False, remote=REMOTE)
    case("stale/occupied anchor beyond the ledger tail", beyond)
    case("verifier failure (candidate)", lambda: None, verify_problem="synthetic verifier failure" + chr(10) + "second line")
    case("pin mismatch (wrapper sha256)", lambda: None, pins=dict(PINS, wrapper_sha256="0" * 64))
    case("remote inconsistency (ledger.jsonl deleted by FF commit)", lambda: ff_edit("ledger.jsonl", lambda b: None))
    case("authorization failure while a HALT is needed (no token)", lambda: corrupt_ledger(), token=False)
    out("halt-final", view=view())
    reset(); init(); corrupt_ledger(); out("halt-prepared-for-nowrite", view=view())


def sc_halt_nowrite():
    r = R.run_once(mkcfg("2030-04-01T00:07:00Z")); out("nowrite-wake", result=r.get("result"), durable=r.get("durable"), ran=r.get("ran"), halt_class=r.get("halt_class"), reason=san(str(r.get("reason")))[:200], remote_view=view())


def api(method, path, body=None, token=TOKEN):
    req = urllib.request.Request("https://api.github.com" + path, method=method, data=(json.dumps(body).encode() if body is not None else None),
                                 headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "r3-probe"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, r.read()[:300].decode("utf-8", "replace")
    except urllib.error.HTTPError as e: return e.code, e.read()[:300].decode("utf-8", "replace")


def sc_perms():
    out("token-present", present=bool(TOKEN), length_class=("ghs-style" if TOKEN and TOKEN.startswith("ghs_") else "other"))
    tests = {"read repo": ("GET", f"/repos/{REPO}"), "read variables": ("GET", f"/repos/{REPO}/actions/variables"), "create variable": ("POST", f"/repos/{REPO}/actions/variables", {"name": "PROBE_TOKEN_WRITE", "value": "x"}),
             "update pin variable": ("PATCH", f"/repos/{REPO}/actions/variables/OPS_COMMIT_PIN", {"name": "OPS_COMMIT_PIN", "value": "0" * 40}), "list rulesets": ("GET", f"/repos/{REPO}/rulesets"),
             "create ruleset": ("POST", f"/repos/{REPO}/rulesets", {"name": "probe-token", "target": "branch", "enforcement": "disabled"}), "create issue": ("POST", f"/repos/{REPO}/issues", {"title": "probe"}),
             "dispatch workflow": ("POST", f"/repos/{REPO}/actions/workflows/probe-lab.yml/dispatches", {"ref": "main"}), "read secrets list": ("GET", f"/repos/{REPO}/actions/secrets")}
    for k, v in tests.items():
        st, body = api(*v); out("api", test=k, status=st, body=(san(body)[:140] if st >= 400 else "ok"))
    s = store(); s.refresh() if refs() else None
    w = d("wf"); g = R.Git(TOKEN, True); g.run(w, "init", "-q", "-b", "x"); g.run(w, "remote", "add", "origin", REMOTE); os.makedirs(os.path.join(w, ".github", "workflows")); open(os.path.join(w, ".github", "workflows", "evil.yml"), "w").write("name: evil\non: workflow_dispatch\njobs: {}\n")
    g.run(w, "add", "-A"); g.run(w, "commit", "-q", "-m", "synthetic workflow-file push attempt")
    r = g.run(w, "push", "origin", "HEAD:refs/heads/probe-wf-push", check=False, remote=REMOTE); out("workflow-file-push-with-job-token", rc=r.returncode, stderr=san(r.stderr)[:300])
    w2 = d("plain"); g.run(w2, "init", "-q", "-b", "y"); g.run(w2, "remote", "add", "origin", REMOTE); open(os.path.join(w2, "plain.txt"), "w").write("x"); g.run(w2, "add", "-A"); g.run(w2, "commit", "-q", "-m", "plain file push")
    r = g.run(w2, "push", "origin", "HEAD:refs/heads/probe-plain-push", check=False, remote=REMOTE); out("plain-branch-push-with-job-token", rc=r.returncode, stderr=san(r.stderr)[:200])
    g.run(w2, "push", "origin", "--delete", "probe-plain-push", "probe-wf-push", check=False, remote=REMOTE)


if __name__ == "__main__":
    {"init": sc_init, "cas-claim": sc_cas_claim, "cas-verify": sc_cas_verify, "single": sc_single, "flow": sc_flow, "halt-all": sc_halt_all, "halt-nowrite": sc_halt_nowrite, "perms": sc_perms}[sys.argv[1]]()
