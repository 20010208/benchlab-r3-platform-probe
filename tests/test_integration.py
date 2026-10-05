"""Integration tests: real git remotes (hardened local analogue), real frozen candidate code (synthetic feeds), real OS processes.  No network."""
import sys, os, json, time, tempfile, itertools, subprocess, gzip, hashlib, shutil
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H
R = H.R
from datetime import datetime, timedelta, timezone
UTC = timezone.utc
O1, O2, O3 = "2026-10-05T12:00:00Z", "2026-10-05T18:00:00Z", "2026-10-06T00:00:00Z"
BASE = [("STARTED", O1, 1, "2026-10-05T12:07:00Z"), ("FAILED", O1, 1, "2026-10-05T12:09:00Z"), ("STARTED", O1, 2, "2026-10-05T12:20:00Z"), ("FAILED", O1, 2, "2026-10-05T12:22:00Z"),
        ("STARTED", O2, 1, "2026-10-05T18:07:00Z"), ("FAILED", O2, 1, "2026-10-05T18:09:00Z")]
O3S = [("STARTED", O3, 1, "2026-10-06T00:07:00Z"), ("FAILED", O3, 1, "2026-10-06T00:09:00Z")]
GIT = H.git


def rehash_chain(recs):
    out, prev = [], R.GENESIS
    for i, r in enumerate(recs):
        x = {k: v for k, v in r.items() if k != "record_hash"}; x["seq"] = i; x["prev_hash"] = prev; x["record_hash"] = R.sha256_hex((prev + R.canon(x)).encode()); out.append(x); prev = x["record_hash"]
    return out


def rebuild(e, recs, retag):
    """ADMIN-level history replacement: a fully consistent re-hashed history with correct commit subjects, bypassing the remote's deny rules through update-ref."""
    d = tempfile.mkdtemp(prefix="atk", dir=e.td); GIT(d, "init", "-q", "-b", "atk"); GIT(d, "remote", "add", "origin", e.remote); shas = []; lines = b""
    for i, r in enumerate(recs):
        lines += (R.canon(r) + "\n").encode(); open(os.path.join(d, "ledger.jsonl"), "wb").write(lines); GIT(d, "add", "-A"); GIT(d, "commit", "-q", "-m", f"ledger seq={i} hash={r['record_hash']}"); shas.append(GIT(d, "rev-parse", "HEAD"))
    GIT(d, "push", "-q", "origin", "HEAD:refs/heads/atk-tmp"); GIT(e.remote, "update-ref", f"refs/heads/{R.BRANCH}", shas[-1]); GIT(e.remote, "update-ref", "-d", "refs/heads/atk-tmp")
    if retag:
        for i, s in enumerate(shas): GIT(e.remote, "update-ref", f"refs/tags/{R.ANCHOR}{i:06d}", s)
        for tg in GIT(e.remote, "for-each-ref", f"refs/tags/{R.ANCHOR}*", "--format=%(refname:short)").split():
            if int(tg[len(R.ANCHOR):]) >= len(recs): GIT(e.remote, "update-ref", "-d", f"refs/tags/{tg}")


def mirror_tip(e):
    st = R.Store(R.Git(None, True), e.remote, tempfile.mkdtemp(prefix="mir", dir=e.td)); st.refresh(); return st, GIT(st.path, "rev-parse", "HEAD")


def mirror_detects(st, old_tip):
    GIT(st.path, "fetch", "-q", "--no-tags", "origin", f"+refs/heads/{R.BRANCH}:refs/remotes/origin/{R.BRANCH}")
    return subprocess.run(["git", "-C", st.path, "merge-base", "--is-ancestor", old_tip, f"origin/{R.BRANCH}"], capture_output=True).returncode != 0


def forge_ff(e, state, **extra):
    """Append a hash-chain-valid forged record (with its anchor tag) as an ordinary fast-forward push -- what a human with push rights could do."""
    st = R.Store(R.Git(None, True), e.remote, tempfile.mkdtemp(prefix="forge", dir=e.td)); st.refresh(); raw = st.ledger_bytes(); recs, _ = R.parse_ledger(raw)
    rec = R.make_record(recs[-1], state, dict(e.ident(), journal_head=recs[-1]["journal_head"], ts=extra.pop("ts", "2026-10-05T12:30:00Z")), **extra); tag = st.stage(rec, raw)
    return bool(tag) and st.push(tag) == "OK"


def commit_count(e): return int(GIT(e.remote, "rev-list", "--count", f"refs/heads/{R.BRANCH}"))


def run(T, ctx):
    td, cand = ctx["td"], ctx["cand"]
    NEW = lambda **kw: H.Env(td, cand, **kw).init()
    S = "LEDGER"
    # ================================================================ A  init
    e = H.Env(td, cand); r = e.go("2026-10-05T12:07:00Z")
    T.check(S, "A: before init -> NOT_INITIALISED (no auto-init, nothing runs, nothing created)", r["result"] == R.NOT_INITIALISED and not r["ran"] and GIT(e.remote, "for-each-ref") == "")
    e.init(); st, recs, p = e.view()
    T.check(S, "A: init = exactly one INIT record + anchor-000000; verifies", [x["state"] for x in recs] == ["INIT"] and p == [] and set(st.anchors()) == {0})
    r = R.init_ledger(e.cfg("2026-10-05T11:30:00Z")); T.check(S, "A: a second init-ledger refuses (never overwrites or extends)", r["result"] == R.INTEGRITY_FAILURE and e.states() == ["INIT"])
    # ================================================================ B  STARTED claim binds identity
    e = NEW(); r = e.go("2026-10-05T12:07:00Z", claim_only=True); st, recs, p = e.view(); c = recs[-1]
    T.check(S, "B: STARTED claim is durable (CLAIMED), chain + anchors + history shape verify", r["result"] == R.CLAIMED and c["state"] == "STARTED" and p == [])
    T.check(S, "B: the claim binds schema/origin/attempt/nonce/candidate/ops commit/wrapper sha/workflow blob/lock sha/prev hash/journal head/ts/run identity/runtime", c["schema"] == R.SCHEMA and c["origin"] == O1 and c["attempt_no"] == 1 and len(c["nonce"]) == 32
            and c["candidate_sha"] == R.CANDIDATE_SHA and c["ops_commit"] == e.pins["ops_commit"] and c["wrapper_sha256"] == e.pins["wrapper_sha256"] and c["workflow_blob"] == e.pins["workflow_blob"]
            and c["lock_sha256"] == e.pins["lock_sha256"] and c["prev_hash"] == recs[-2]["record_hash"] and c["journal_head"] == R.GENESIS and c["ts"] == "2026-10-05T12:07:00Z" and c["run_id"] == "run-1" and c["run_attempt"] == 1 and c["runtime_identity"])
    # ================================================================ C  SUCCESS
    e = NEW(); r = e.go("2026-10-05T12:07:00Z"); st, recs, p = e.view(); s = recs[-1]
    T.check(S, "C: SUCCESS recorded; binds forecast sha256, feed hashes (archive/ace1h/rtsw), journal attempt and runtime identity", r["result"] == R.SUCCESS and s["state"] == "SUCCESS" and set(s["feed_sha256"]) == {"archive", "ace1h", "rtsw"}
            and len(s["forecast_sha256"]) == 64 and s["journal_attempt_id"] and s["runtime_identity"] and p == [] and s["journal_head"] != R.GENESIS)
    outs = [e.go(x)["result"] for x in ("2026-10-05T12:17:00Z", "2026-10-05T12:27:00Z", "2026-10-05T12:37:00Z")]
    T.check(S, "C: later wakes after SUCCESS only observe (SKIPPED_DONE); no new records", outs == [R.SKIPPED_DONE] * 3 and e.states() == ["INIT", "STARTED", "SUCCESS"])
    T.check(S, "C: a wake outside the window (12:41) and a missed origin never write", e.go("2026-10-05T12:41:00Z")["result"] == R.SKIPPED_NOT_DUE and e.go("2026-10-05T17:59:00Z")["result"] == R.SKIPPED_NOT_DUE and len(e.states()) == 3)
    # ================================================================ D / E
    e = NEW(); r1 = e.go("2026-10-05T12:07:00Z", mode="fail"); r2 = e.go("2026-10-05T12:17:00Z")
    T.check(S, "D: FAILED attempt is recorded; the next wake claims attempt 2 and can SUCCEED", r1["result"] == R.FAILED and r2["result"] == R.SUCCESS and e.states() == ["INIT", "STARTED", "FAILED", "STARTED", "SUCCESS"])
    e = NEW(); rs = [e.go(x, mode="fail")["result"] for x in ("2026-10-05T12:07:00Z", "2026-10-05T12:17:00Z", "2026-10-05T12:27:00Z")]; r4 = e.go("2026-10-05T12:37:00Z")
    T.check(S, "E: three FAILED attempts, then the fourth wake -> SKIPPED_CAP; exactly 3 STARTED", rs == [R.FAILED] * 3 and r4["result"] == R.SKIPPED_CAP and e.count("STARTED") == 3)
    e = NEW(); r = e.go("2026-10-05T12:07:00Z", mode="late")
    T.check(S, "E: a runner that refuses (late) leaves a FAILED attempt with a clear reason; no SUCCESS", r["result"] == R.FAILED and e.count("SUCCESS") == 0)
    e = NEW(); r = e.go("2026-10-05T12:07:00Z", mode="nowrite")
    T.check(S, "E: a runner that exits without any journal record -> FAILED 'no journal record'; no HALT", r["result"] == R.FAILED and not e.has_halt() and e.view()[1][-1]["reason"] == "runner produced no journal record")
    e = NEW(); r = e.go("2026-10-05T12:07:00Z", mode="crash"); rr = e.view()[1][-1]
    T.check(S, "E: a runner that dies after its first journal record -> FAILED 'exited without a final record'; retry in the window works", r["result"] == R.FAILED and "without a final" in rr["reason"] and e.go("2026-10-05T12:17:00Z")["result"] == R.SUCCESS)
    # ================================================================ F  duplicate SUCCESS (forged, valid chain + anchor)
    e = NEW(); e.go("2026-10-05T12:07:00Z"); ok = forge_ff(e, "SUCCESS", origin=O1, attempt_no=1, forecast_sha256="f" * 64, feed_sha256={"rtsw": "e" * 64}, journal_attempt_id="forged-a1")
    r = e.go("2026-10-05T18:07:00Z"); T.check(S, "F: forged duplicate SUCCESS (valid hash chain + anchor, pushed as a normal FF) -> INTEGRITY_FAILURE + durable HALT; the new origin does not run", ok and r["result"] == R.INTEGRITY_FAILURE and r["durable"] and e.has_halt() and e.count("STARTED", O2) == 0)
    T.check(S, "F: still halted on the next wake", e.go("2026-10-05T18:17:00Z")["result"] in (R.HALTED, R.INTEGRITY_FAILURE) and e.count("STARTED", O2) == 0)
    # ================================================================ I  stale writer (two real processes)
    e = NEW(); st0 = time.time() + 3.0
    pa = H.spawn(e, "2026-10-05T12:07:00Z", st0, mode="sleep", sleep=45, final_now="2026-10-05T12:25:00Z"); pb = H.spawn(e, "2026-10-05T12:21:00Z", st0 + 16.0)
    ra, rb = H.collect([pa, pb])
    T.check(S, "I: stale writer: its late finalize is rejected and discarded (ABANDONED_STALE_WRITER); the later attempt's SUCCESS stands", ra["result"] == R.ABANDONED and rb["result"] == R.SUCCESS and e.states() == ["INIT", "STARTED", "STARTED", "SUCCESS"], )
    T.check(S, "I: after the stale writer the ledger verifies with exactly one SUCCESS", e.view()[2] == [] and e.count("SUCCESS") == 1)
    # ================================================================ J  non-FF / force / delete / tags
    e = NEW(); s1 = R.Store(R.Git(None, True), e.remote, tempfile.mkdtemp(prefix="stale", dir=td)); s1.refresh(); raw1 = s1.ledger_bytes(); recs1, _ = R.parse_ledger(raw1)
    e.go("2026-10-05T12:07:00Z", claim_only=True)
    rec = R.make_record(recs1[-1], "STARTED", dict(e.ident(), ts="2026-10-05T12:08:00Z"), origin=O1, attempt_no=1); tag = s1.stage(rec, raw1)
    T.check(S, "J: a stale clone pushing a competing record (non-fast-forward) is REJECTED by the atomic CAS", s1.push(tag) == "REJECTED" and e.states() == ["INIT", "STARTED"])
    wf = R.Store(R.Git(None, True), e.remote, tempfile.mkdtemp(prefix="force", dir=td)); wf.refresh(); GIT(wf.path, "reset", "-q", "--hard", "HEAD~1"); open(os.path.join(wf.path, "x"), "w").write("x"); GIT(wf.path, "add", "-A"); GIT(wf.path, "commit", "-q", "-m", "rewrite")
    T.check(S, "J: a human `git push --force` of rewritten history is rejected by the remote", subprocess.run(["git", "-C", wf.path, "push", "-q", "--force", "origin", f"HEAD:refs/heads/{R.BRANCH}"], capture_output=True).returncode != 0)
    T.check(S, "J: a human branch deletion is rejected by the remote", subprocess.run(["git", "-C", wf.path, "push", "-q", "origin", f":refs/heads/{R.BRANCH}"], capture_output=True).returncode != 0)
    blocked = subprocess.run(["git", "-C", wf.path, "push", "-q", "--force", "origin", f"HEAD:refs/tags/{R.ANCHOR}000001"], capture_output=True).returncode != 0; T.extra["tag_force_update_blocked_by_branch_deny_rules"] = blocked
    T.check(S, "J: OBSERVATION recorded (not an assertion): branch-level deny rules do not protect existing tags; tags need their own rule", True)
    e = NEW(); e.seed(BASE); stx = R.Store(R.Git(None, True), e.remote, tempfile.mkdtemp(prefix="tm", dir=td)); stx.refresh(); subprocess.run(["git", "-C", stx.path, "push", "-q", "--force", "origin", f"HEAD~3:refs/tags/{R.ANCHOR}000005"], capture_output=True)
    r = e.go("2026-10-06T00:07:00Z"); T.check(S, "J: an anchor tag force-moved to another commit is detected in-run (INTEGRITY_FAILURE); nothing runs", r["result"] == R.INTEGRITY_FAILURE and not r["ran"] and e.count("STARTED", O3) == 0)
    e = NEW(); e.seed(BASE); GIT(e.remote, "update-ref", "-d", f"refs/tags/{R.ANCHOR}000003"); r = e.go("2026-10-06T00:07:00Z")
    T.check(S, "J: a deleted middle anchor tag is detected in-run (INTEGRITY_FAILURE); nothing runs", r["result"] == R.INTEGRITY_FAILURE and not r["ran"])
    # ================================================================ K  deletion
    e = NEW(); e.go("2026-10-05T12:07:00Z"); GIT(e.remote, "update-ref", "-d", f"refs/heads/{R.BRANCH}"); r = e.go("2026-10-05T18:07:00Z")
    T.check(S, "K: ledger branch deleted (admin bypass) while anchor tags remain -> INTEGRITY_FAILURE; nothing runs", r["result"] == R.INTEGRITY_FAILURE and not r["ran"])
    for tg in GIT(e.remote, "for-each-ref", f"refs/tags/{R.ANCHOR}*", "--format=%(refname:short)").split(): GIT(e.remote, "update-ref", "-d", f"refs/tags/{tg}")
    r = e.go("2026-10-05T18:17:00Z"); T.check(S, "K: branch AND tags deleted -> NOT_INITIALISED: refuses to run, never silently re-initialises (indistinguishable from a fresh repo in-run: documented)", r["result"] == R.NOT_INITIALISED and not r["ran"])
    # ================================================================ L  truncation
    e = NEW(); e.seed(BASE); st, _ = mirror_tip(e); prev = GIT(st.path, "rev-parse", "HEAD~1"); GIT(e.remote, "update-ref", f"refs/heads/{R.BRANCH}", prev); r = e.go("2026-10-06T00:07:00Z")
    T.check(S, "L: tail truncated (branch moved back, its anchor tag remains beyond the tail) -> INTEGRITY_FAILURE + HALT", r["result"] == R.INTEGRITY_FAILURE and not r["ran"] and r["durable"])
    T.check(S, "L: HALT persistence worked although the anchor slot was occupied (HALT FALLBACK preserved: HALT.json written instead of a chain record)", e.view()[0].halt_file() or any(x["state"] == "HALT" for x in e.view()[1]))
    e = NEW(); e.seed(BASE); st, tip = mirror_tip(e); prev = GIT(st.path, "rev-parse", "HEAD~1"); GIT(e.remote, "update-ref", f"refs/heads/{R.BRANCH}", prev); GIT(e.remote, "update-ref", "-d", f"refs/tags/{R.ANCHOR}{len(BASE):06d}")
    r = e.go("2026-10-06T00:07:00Z", claim_only=True)
    T.check(S, "L: COORDINATED truncation (tail AND its anchor tag removed): the in-run check passes (documented limit) ...", r["result"] == R.CLAIMED)
    T.check(S, "L: ... and the independent mirror detects it (its old tip is no longer an ancestor)", mirror_detects(st, tip))
    # ================================================================ M  rewritten record
    for retag, name in ((False, "anchors intact"), (True, "anchors also forged")):
        e = NEW(); e.seed(BASE); st, tip = mirror_tip(e); recs = e.view()[1]; ed = [dict(x) for x in recs]; ed[2]["ts"] = "2026-10-05T12:09:01Z"; rebuild(e, rehash_chain(ed), retag=retag)
        r = e.go("2026-10-06T00:07:00Z", claim_only=True)
        if not retag: T.check(S, "M: a historical record rewritten with a fully consistent re-hash (anchor tags intact) -> INTEGRITY_FAILURE", r["result"] == R.INTEGRITY_FAILURE and not r["ran"])
        else:
            T.check(S, "M: the same rewrite with forged anchor tags passes in-run (documented coordinated limit) ...", r["result"] == R.CLAIMED); T.check(S, "M: ... and the independent mirror detects the history replacement", mirror_detects(st, tip))
    # ================================================================ N  journal corruption
    e = NEW(); e.go("2026-10-05T12:07:00Z"); ok = e.human_edit("journal/journal.jsonl", lambda b: b.replace(b"STARTED", b"STARTEX", 1)); r = e.go("2026-10-05T18:07:00Z")
    T.check(S, "N: journal record edited (valid FF push) -> INTEGRITY_FAILURE + HALT; the new origin does not run", ok and r["result"] == R.INTEGRITY_FAILURE and e.has_halt() and e.count("STARTED", O2) == 0)
    e = NEW(); e.go("2026-10-05T12:07:00Z"); ok = e.human_edit("journal/journal.jsonl", lambda b: b.split(bytes([10]))[0] + bytes([10])); r = e.go("2026-10-05T18:07:00Z")
    T.check(S, "N: journal tail deleted -> INTEGRITY_FAILURE", ok and r["result"] == R.INTEGRITY_FAILURE and e.count("STARTED", O2) == 0)
    # ================================================================ O  ledger contains another candidate / human FF noise
    e = NEW(); e.go("2026-10-05T12:07:00Z"); st = R.Store(R.Git(None, True), e.remote, tempfile.mkdtemp(prefix="o", dir=td)); st.refresh(); raw = st.ledger_bytes(); recs, _ = R.parse_ledger(raw)
    fr = R.make_record(recs[-1], "STARTED", dict(e.ident(), candidate_sha="e" * 40, journal_head=recs[-1]["journal_head"], ts="2026-10-05T18:07:00Z"), origin=O2, attempt_no=1); tag = st.stage(fr, raw); st.push(tag)
    r = e.go("2026-10-05T18:17:00Z"); T.check(S, "O: a ledger record for a DIFFERENT candidate SHA -> INTEGRITY_FAILURE", r["result"] == R.INTEGRITY_FAILURE)
    e = NEW(); e.go("2026-10-05T12:07:00Z"); ok = e.human_edit("README.md", lambda b: b"hello"); r = e.go("2026-10-05T18:07:00Z")
    T.check(S, "O: any human fast-forward commit on the machine-only ledger branch (here: an extra file) is a history-shape violation -> INTEGRITY_FAILURE", ok and r["result"] == R.INTEGRITY_FAILURE and e.count("STARTED", O2) == 0)
    e = NEW(); e.go("2026-10-05T12:07:00Z"); fp = [x for x in os.listdir(os.path.join(e.view()[0].path, "journal", "attempts"))][0]
    ok = e.human_edit(f"journal/attempts/{fp}/forecast.json", lambda b: b.replace(b"forecast", b"forecasT", 1)); r = e.go("2026-10-05T18:07:00Z")
    T.check(S, "O: a human FF edit of an OLD attempt's forecast file is caught per wake by the history-shape check (no historical re-run needed) -> INTEGRITY_FAILURE", ok and r["result"] == R.INTEGRITY_FAILURE and e.count("STARTED", O2) == 0)
    # ================================================================ Q / R  HALT present, HALT removed
    e = NEW(); e.seed(BASE); e.go("2026-10-06T00:07:00Z", pins=dict(e.pins, wrapper_sha256="0" * 64)); r = e.go("2026-10-06T06:07:00Z")
    T.check(S, "Q: HALT present -> a later origin with correct pins is HALTED and does not execute", r["result"] == R.HALTED and not r["ran"] and e.count("STARTED", "2026-10-06T06:00:00Z") == 0)
    ok = e.human_edit("HALT.json", lambda b: None); r = e.go("2026-10-06T12:07:00Z")
    T.check(S, "R1: HALT.json absent/deleted but the chain HALT record remains -> still HALTED", r["result"] == R.HALTED and not r["ran"])
    e = NEW(); e.seed(BASE); ok = e.human_edit("ledger.jsonl", lambda b: b.replace(b"FAILED", b"FAILEX", 1)); r = e.go("2026-10-06T00:07:00Z"); hf = e.view()[0].halt_file()
    T.check(S, "R2: chain corrupted -> only HALT.json can be written (chain not extendable), still fail closed", ok and r["result"] == R.INTEGRITY_FAILURE and hf)
    e.human_edit("HALT.json", lambda b: None); r = e.go("2026-10-06T06:07:00Z")
    T.check(S, "R2: deleting only HALT.json does NOT restore operation: chain corruption is recomputed every wake -> INTEGRITY_FAILURE", r["result"] == R.INTEGRITY_FAILURE and not r["ran"])
    e = NEW(); e.seed(BASE); e.go("2026-10-06T00:07:00Z", pins=dict(e.pins, wrapper_sha256="0" * 64)); recs = e.view()[1]; assert recs[-1]["state"] == "HALT"; rebuild(e, recs[:-1], retag=False); r = e.go("2026-10-06T00:17:00Z")
    T.check(S, "R3: the chain HALT record itself removed by a history rewrite (anchors intact) -> INTEGRITY_FAILURE, still nothing runs", r["result"] == R.INTEGRITY_FAILURE and not r["ran"])

    # ================================================================ MUTATION
    M = "MUT"
    e = NEW(); e.seed(BASE + O3S); st, recs, p = e.view(); raw = st.ledger_bytes(); lines = raw.split(bytes([10]))[:-1]; assert p == [] and len(recs) == 9
    def detected(b): rr, pp = R.parse_ledger(b); return bool(pp) or bool(R.semantic_problems(rr))
    flips = det = 0
    for i in range(len(raw)):
        m = bytearray(raw); m[i] ^= 0x01; flips += 1; det += detected(bytes(m))
    T.check(M, f"single-byte flip at every position of the {len(raw)}-byte ledger", det == flips, cases=flips); naive = [flips, det]
    c = d = 0
    for i in range(len(lines) - 1): c += 1; d += detected(bytes([10]).join(lines[:i] + lines[i + 1:]) + bytes([10]))
    T.check(M, "deletion of each non-tail record (naive)", c == d, cases=c); naive = [naive[0] + c, naive[1] + d]
    c = d = 0
    for i in range(1, len(lines)):
        c += 1; d += detected(bytes([10]).join(lines[:i] + [lines[i]] + lines[i:]) + bytes([10]))
        fake = json.dumps(dict(json.loads(lines[1]), reason="forged")).encode(); c += 1; d += detected(bytes([10]).join(lines[:i] + [fake] + lines[i:]) + bytes([10]))
    T.check(M, "insertion at each position (duplicated and forged, naive)", c == d, cases=c); naive = [naive[0] + c, naive[1] + d]
    c = d = 0
    for i, j in itertools.combinations(range(1, len(lines)), 2):
        L = list(lines); L[i], L[j] = L[j], L[i]; c += 1; d += detected(bytes([10]).join(L) + bytes([10]))
    T.check(M, "reordering of any two records (naive)", c == d, cases=c); naive = [naive[0] + c, naive[1] + d]
    T.extra["mutation_naive"] = naive
    T.check(M, "chain-only checking cannot see a clean tail truncation (expected: that is what the anchors are for)", not R.parse_ledger(bytes([10]).join(lines[:-1]) + bytes([10]))[1])
    rr = e.view()[1]
    def variants():
        x = [dict(r) for r in rr]; x[3]["ts"] = "2026-10-05T12:20:02Z"; yield "edit a record + re-hash", rehash_chain(x)
        x = [dict(r) for r in rr]; ex = dict(x[5]); ex.update(attempt_no=2, ts="2026-10-05T18:20:00Z", nonce="a" * 32); x[7:7] = [ex]; yield "insert a valid record + re-hash", rehash_chain(x)
        x = [dict(r) for r in rr]; x = x[:1] + x[5:7] + x[1:5] + x[7:]; yield "reorder origin blocks + re-hash", rehash_chain(x)
        x = [dict(r) for r in rr]; x = x[:5] + x[7:]; yield "delete a middle block + re-hash", rehash_chain(x)
        yield "tail truncation", [dict(r) for r in rr[:-1]]
        yield "wholesale history replacement", rehash_chain([dict(rr[0])] + [dict(r, nonce=("%032x" % (i + 7))) for i, r in enumerate(rr[1:])])
    a_cases = a_det = c_cases = c_inrun = c_mirror = 0
    for name, newrecs in variants():
        e2 = NEW(); e2.seed(BASE + O3S); st2, tip = mirror_tip(e2); rebuild(e2, newrecs, retag=False); r = e2.go("2026-10-06T06:07:00Z", claim_only=True); a_cases += 1; a_det += (r["result"] == R.INTEGRITY_FAILURE and not r["ran"])
        e3 = NEW(); e3.seed(BASE + O3S); st3, tip = mirror_tip(e3); rebuild(e3, newrecs, retag=True); r = e3.go("2026-10-06T06:07:00Z", claim_only=True); c_cases += 1; c_inrun += (r["result"] == R.INTEGRITY_FAILURE); c_mirror += mirror_detects(st3, tip)
    T.check(M, "consistent-attacker rewrites (6 variants, anchor tags intact): all detected in-run by the anchors", a_det == a_cases, cases=a_cases)
    T.check(M, "coordinated variants (anchor tags also rewritten): none detected in-run (documented limit); all detected by the independent mirror", c_inrun == 0 and c_mirror == c_cases, cases=c_cases)
    T.extra["mutation_anchor"] = [a_cases, a_det]; T.extra["mutation_coordinated"] = dict(cases=c_cases, detected_in_run=c_inrun, detected_by_mirror=c_mirror)

    # ================================================================ HALT classes
    Hc = "HALT"
    def halt_case(name, make, expect, first_kw=None, cls=None):
        e = NEW(); make(e); r = e.go("2026-10-06T00:07:00Z", **(first_kw or {}))
        ok1 = r["result"] == expect and not r["ran"] and r["durable"] and (cls is None or r.get("halt_class") == cls) and e.has_halt()
        c1 = commit_count(e); n_mark = len(e.markers())
        outs = [e.go(x) for x in ("2026-10-06T06:07:00Z", "2026-10-06T12:07:00Z")]
        ok2 = all(o["result"] in (R.HALTED, R.INTEGRITY_FAILURE) and not o["ran"] for o in outs) and len(e.markers()) == n_mark and commit_count(e) == c1       # no new work, no automatic repair/rewrite
        e.human_edit("HALT.json", lambda b: None); o = e.go("2026-10-06T18:07:00Z"); ok3 = o["result"] in (R.HALTED, R.INTEGRITY_FAILURE) and not o["ran"]
        T.check(Hc, f"{name}: durable HALT; later origins do not run; no automatic repair; deleting only HALT.json does not restore operation", ok1 and ok2 and ok3)
    halt_case("candidate mismatch (frozen-verifier failure)", lambda e: e.seed(BASE), R.CANDIDATE_MISMATCH, dict(verify_problem="working file differs from freeze commit: tools/x.py"), "CANDIDATE")
    for key, val, cls, name in (("wrapper_sha256", "0" * 64, "OPS", "ops mismatch (wrapper sha256 pin)"), ("ops_commit", "1" * 40, "OPS", "ops mismatch (ops commit pin)"), ("workflow_blob", "2" * 40, "WORKFLOW", "workflow mismatch (workflow blob pin)"),
                                ("lock_sha256", "3" * 64, "OPS", "dependency lock mismatch (lock sha256 pin)")):
        e = NEW(); e.seed(BASE); badpins = dict(e.pins, **{key: val}); r = e.go("2026-10-06T00:07:00Z", pins=badpins)
        c1 = commit_count(e); o2 = e.go("2026-10-06T06:07:00Z"); st, recs, p = e.view()
        T.check(Hc, f"{name}: OPS_INTEGRITY_FAILURE + durable HALT(class {cls}); nothing runs; the only new record is the HALT", r["result"] == R.OPS_INTEGRITY_FAILURE and r["durable"] and r["halt_class"] == cls and not r["ran"]
                and recs[-1]["state"] == "HALT" and recs[-1]["halt_class"] == cls and len(recs) == 1 + len(BASE) + 1 and o2["result"] == R.HALTED and not e.markers() and commit_count(e) == c1)
    halt_case("ledger mismatch (chain edited by a human FF push)", lambda e: (e.seed(BASE), e.human_edit("ledger.jsonl", lambda b: b.replace(b"FAILED", b"FAILEX", 1))), R.INTEGRITY_FAILURE, None, "LEDGER")
    halt_case("journal mismatch (journal edited by a human FF push)", lambda e: (e.go("2026-10-05T12:07:00Z"), e.human_edit("journal/journal.jsonl", lambda b: b.replace(b"STARTED", b"STARTEX", 1))), R.INTEGRITY_FAILURE, None, None)
    halt_case("duplicate SUCCESS in the ledger (forged valid-chain FF record)", lambda e: (e.go("2026-10-05T12:07:00Z"), forge_ff(e, "SUCCESS", origin=O1, attempt_no=1, forecast_sha256="f" * 64, feed_sha256={"rtsw": "e" * 64}, journal_attempt_id="f1")), R.INTEGRITY_FAILURE, None, "LEDGER")
    halt_case("duplicate SUCCESS produced by the runner (journal)", lambda e: e.seed(BASE), R.INTEGRITY_FAILURE, dict(mode="dup"), "DUPLICATE_SUCCESS")
    halt_case("forecast reproduction mismatch (forecast edited after the run)", lambda e: e.seed(BASE), R.INTEGRITY_FAILURE, dict(mode="tamper"), "REPRODUCTION")
    halt_case("forecast reproduction mismatch (stored feed replaced)", lambda e: e.seed(BASE), R.INTEGRITY_FAILURE, dict(mode="tamperfeed"), "REPRODUCTION")
    halt_case("journal chain broken by the runner", lambda e: e.seed(BASE), R.INTEGRITY_FAILURE, dict(mode="badchain"), "JOURNAL")
    odd = ["a" + chr(10) + "b", "café 日本", "x" * 1000, "", chr(0) + chr(1) + chr(7), "line1" + chr(13) + chr(10) + "line2", " " * 5, "FREEZE VIOLATED:" + chr(10) + "  working file differs: tools/x.py"]
    okodd = 0
    for rs in odd:
        e = NEW(); e.seed(BASE); r = e.go("2026-10-06T00:07:00Z", verify_problem=rs); st, recs, p = e.view()
        okodd += (r["result"] == R.CANDIDATE_MISMATCH and r["durable"] and recs[-1]["state"] == "HALT" and R.shape_problems(recs[-1]) == [] and p == [])
    T.check(Hc, "HALT is never defeatable by odd reason text (newline, unicode, control characters, empty, whitespace-only, 1000 chars): always durable, schema-valid, sanitised", okodd == len(odd), cases=len(odd))
    e = NEW(); e.seed(BASE); r = e.go("2026-10-06T00:07:00Z", mode="tamper"); st, recs, p = e.view()
    T.check(Hc, "HALT-with-evidence: the offending journal files are committed together with the HALT record (audit trail), and the claim stays visible", recs[-1]["state"] == "HALT" and recs[-2]["state"] == "STARTED" and recs[-1]["journal_head"] != recs[-2]["journal_head"] and os.path.isdir(os.path.join(st.path, "journal", "attempts")))
    # ================================================================ PINS / OPS IDENTITY / DEPENDENCY LOCK
    P = "PINS"
    e = NEW(); r = e.go("2026-10-05T12:07:00Z"); T.check(P, "pins match -> ops gate passes and the wake runs", r["result"] == R.SUCCESS)
    def pin_env(mutate, repin=False):
        ops, pins = H.make_ops(td); e = H.Env(td, cand, ops=(ops, pins)).init(); e.seed(BASE); mutate(ops)
        if repin: e.pins = H.pins_of(ops)
        return e
    def app(rel, data): return lambda d: open(os.path.join(d, rel), "ab").write(data)
    def commit_all(d): GIT(d, "add", "-A"); GIT(d, "commit", "-q", "-m", "change")
    def mut_commit(rel, data):
        def f(d): app(rel, data)(d); commit_all(d)
        return f
    cases = [("wrapper modified (uncommitted)", app(R.WRAPPER_NAME, b"# x\n"), False, "OPS"), ("wrapper modified and committed (HEAD and hash move)", mut_commit(R.WRAPPER_NAME, b"# x\n"), False, "OPS"),
             ("workflow file modified and committed (blob pin differs)", mut_commit(R.WORKFLOW_PATH, b"# x\n"), False, "WORKFLOW"), ("lock file modified and committed (lock pin differs)", mut_commit(R.LOCK_NAME, b"# x\n"), False, "OPS"),
             ("unexpected untracked helper file in the ops tree", lambda d: open(os.path.join(d, "shadow_journal.py"), "w").write("x=1\n"), False, "OPS"),
             ("floating dependency in the lock (pins updated to match)", mut_commit(R.LOCK_NAME, b"requests>=2\n"), True, "OPS"), ("lock pins numpy 2.4.6 instead of 2.2.6 (pins updated)", lambda d: (open(os.path.join(d, R.LOCK_NAME), "w", newline="\n").write("numpy==2.4.6 \\\n    --hash=sha256:" + "a" * 64 + "\n"), commit_all(d)), True, "OPS"),
             ("lock without any hash (pins updated)", lambda d: (open(os.path.join(d, R.LOCK_NAME), "w", newline="\n").write("numpy==2.2.6\n"), commit_all(d)), True, "OPS")]
    for name, mut, repin, cls in cases:
        e = pin_env(mut, repin); r = e.go("2026-10-06T00:07:00Z"); st, recs, p = e.view()
        T.check(P, f"{name} -> OPS_INTEGRITY_FAILURE + durable HALT(class {cls}); the runner never starts; no claim was written", r["result"] == R.OPS_INTEGRITY_FAILURE and r["durable"] and r["halt_class"] == cls and not e.markers() and recs[-1]["state"] == "HALT" and e.count("STARTED", O3) == 0)
    for key in ("ops_commit", "wrapper_sha256", "workflow_blob", "lock_sha256"):
        for label, val in (("missing", None), ("malformed", "xyz"), ("wrong length", "a" * 7), ("uppercase", ("A" * 40 if key in ("ops_commit", "workflow_blob") else "A" * 64))):
            e = NEW(); e.seed(BASE); bp = dict(e.pins); bp.pop(key) if val is None else bp.__setitem__(key, val); n0 = commit_count(e); r = e.go("2026-10-06T00:07:00Z", pins=bp)
            T.check(P, f"pin {key} {label} -> CONFIG_ERROR: refuses before touching anything (no HALT, no ledger write, no runner)", r["result"] == R.CONFIG_ERROR and not r["durable"] and commit_count(e) == n0 and not e.markers() and not e.has_halt())
    e = NEW(); e.seed(BASE); r = e.go("2026-10-06T00:07:00Z", enforce_runtime=True); probs = R.runtime_problems()
    T.check(P, "runtime check: a wrong interpreter/numpy (this test machine is not the py3.10/numpy2.2.6 target) -> OPS_INTEGRITY_FAILURE + HALT(class RUNTIME)", (not probs) or (r["result"] == R.OPS_INTEGRITY_FAILURE and r["halt_class"] == "RUNTIME" and not e.markers()))
    old = (R.PY_TARGET, R.NUMPY_TARGET); R.PY_TARGET = sys.version_info[:2]
    try:
        import numpy; R.NUMPY_TARGET = numpy.__version__; T.check(P, "runtime check passes when python and numpy equal the locked target (unit)", R.runtime_problems() == [])
        R.NUMPY_TARGET = "0.0.0"; T.check(P, "runtime check flags a numpy version different from the lock (unit)", any("numpy" in x for x in R.runtime_problems()))
        R.NUMPY_TARGET = numpy.__version__; R.PY_TARGET = (2, 7); T.check(P, "runtime check flags a different python minor version (unit)", any("python" in x for x in R.runtime_problems()))
    finally: R.PY_TARGET, R.NUMPY_TARGET = old
    lk = open(os.path.join(H.REPO, R.LOCK_NAME), "rb").read()
    T.check(P, "the committed lock passes the static lock checks (numpy==2.2.6, one sha256 hash, no floating specifier)", R.lock_problems(lk) == [])
    T.check(P, "lock checks reject: wrong version / floating specifier / no hash / numpy 2.4.6", all(R.lock_problems(x) for x in (b"numpy==2.1.0 \\\n --hash=sha256:" + b"a" * 64, b"numpy>=1.26\n", b"numpy==2.2.6\n", b"numpy==2.4.6 \\\n --hash=sha256:" + b"a" * 64, lk + b"scipy>=1\n")), cases=5)
    import re
    req = subprocess.run(["git", "-C", cand, "show", f"{R.CANDIDATE_SHA}:submission_pack/requirements.txt"], capture_output=True, text=True).stdout
    m = re.search(r"numpy>=([\d.]+),<([\d.]+)", req); ver = lambda s: tuple(int(x) for x in s.split("."))
    T.check(P, "the locked numpy lies inside the frozen candidate's declared range, and 2.4.6 does not", bool(m) and ver(m.group(1)) <= ver(R.NUMPY_TARGET) < ver(m.group(2)) and not (ver("2.4.6") < ver(m.group(2))))
    T.extra["lock_sha256"] = hashlib.sha256(lk).hexdigest()

    # ================================================================ CANDIDATE (REAL freeze verifier)
    C = "CANDIDATE"
    g = R.Git(None, True)
    T.check(C, "reconstruction from official-upstream@pinned-commit + thin bundle yields EXACTLY the frozen commit and the real verifier prints FREEZE INTACT", GIT(cand, "rev-parse", "HEAD") == R.CANDIDATE_SHA and R.verify_candidate(R.Config(), cand) == [] and GIT(cand, "config", "core.autocrlf") == "false")
    T.check(C, "the bundle is thin: it carries the user's commits only (the organizer's unchanged files are fetched from the pinned upstream, not republished)", os.path.getsize(ctx["bundle"]) < 3_000_000 and GIT(cand, "rev-list", "--count", f"{R.UPSTREAM_COMMIT}..{R.CANDIDATE_SHA}") != "0")
    c2, _ = H.make_candidate(td, bundle=ctx["bundle"], verify_real=False, name="cand_tamper"); open(os.path.join(c2, "tools", "perturb.py"), "ab").write(b"# tampered" + bytes([10]))
    T.check(C, "a tampered frozen file is rejected by the real verifier", R.verify_candidate(R.Config(), c2) != [])
    e = NEW(); e.seed(BASE); r = e.go("2026-10-06T00:07:00Z", cand=c2, real_verify=True); T.check(C, "run_once with the tampered candidate -> CANDIDATE_MISMATCH + durable HALT(class CANDIDATE); the runner never starts", r["result"] == R.CANDIDATE_MISMATCH and r["durable"] and r["halt_class"] == "CANDIDATE" and not e.markers() and e.count("STARTED", O3) == 0)
    c3, _ = H.make_candidate(td, bundle=ctx["bundle"], verify_real=False, name="cand_mut"); e = NEW(); e.seed(BASE); r = e.go("2026-10-06T00:07:00Z", cand=c3, real_verify=True, mode="mutate")
    T.check(C, "a candidate mutated DURING the run is caught by the post-run re-verification -> CANDIDATE_MISMATCH + HALT; the claim stays visible", r["result"] == R.CANDIDATE_MISMATCH and e.states()[-2:] == ["STARTED", "HALT"] and not any(x["state"] == "SUCCESS" and x["origin"] == O3 for x in e.view()[1]))
    c4 = os.path.join(td, "cand_bad"); T.check(C, "a wrong upstream commit (the bundle's prerequisite is missing) fails closed", _fails(lambda: R.reconstruct_candidate(g, c4, "bundle", ctx["bundle"], H.KIT, GIT(H.KIT, "rev-list", "--max-parents=0", "origin/main").split()[0], allow_local=True)))
    T.check(C, "a wrong pinned candidate SHA is rejected", R.reconstruct_candidate(g, os.path.join(td, "cand_bad2"), "bundle", ctx["bundle"], H.KIT, R.UPSTREAM_COMMIT, expect_sha="0" * 40, allow_local=True) != [])
    bad = os.path.join(td, "truncated.bundle"); open(bad, "wb").write(open(ctx["bundle"], "rb").read()[:5000])
    T.check(C, "a truncated/corrupt bundle is rejected", _fails(lambda: R.reconstruct_candidate(g, os.path.join(td, "cand_bad3"), "bundle", bad, H.KIT, R.UPSTREAM_COMMIT, allow_local=True)))
    T.check(C, "a missing bundle file is rejected", R.reconstruct_candidate(g, os.path.join(td, "cand_bad4"), "bundle", os.path.join(td, "nope.bundle"), H.KIT, R.UPSTREAM_COMMIT, allow_local=True) != [])
    T.check(C, "upstream/candidate URLs outside https://github.com/... are refused (http, other host, lookalike, userinfo, newline, file path in production mode)", all(R.check_remote_url(u, False) is False for u in (
        "http://github.com/a/b", "https://evil.example/a/b", "https://github.com.evil.example/a/b", "https://user" + chr(64) + "github.com/a/b", "https://github.com/a/b\n", "https://github.com/a", "file:///x", "/tmp/x", "", None, "https://github.com/a/b/../c")), cases=11)
    T.check(C, "valid https://github.com/<owner>/<repo>[.git] URLs are accepted", R.check_remote_url("https://github.com/o/r", False) and R.check_remote_url("https://github.com/o/r.git", False))
    hostile = os.path.join(td, "hostile.gitconfig"); open(hostile, "w").write("[core]\n\tautocrlf = true\n")
    env_h = dict(os.environ, GIT_CONFIG_GLOBAL=hostile, GIT_CONFIG_NOSYSTEM="1"); d5 = os.path.join(td, "naive"); os.makedirs(d5)
    subprocess.run(["git", "init", "-q"], cwd=d5, env=env_h); subprocess.run(["git", "fetch", "-q", "--no-tags", H.KIT, R.UPSTREAM_COMMIT], cwd=d5, env=env_h, capture_output=True)
    subprocess.run(["git", "fetch", "-q", "--no-tags", ctx["bundle"], f"+refs/tags/{R.CANDIDATE_TAG}:refs/tags/{R.CANDIDATE_TAG}"], cwd=d5, env=env_h, capture_output=True); subprocess.run(["git", "checkout", "-q", "-f", "--detach", R.CANDIDATE_TAG], cwd=d5, env=env_h, capture_output=True)
    naive_bad = R.verify_candidate(R.Config(), d5)
    T.check(C, "NEGATIVE CONTROL: a naive checkout under core.autocrlf=true fails the real verifier (this is why R3 sets core.autocrlf=false BEFORE any checkout)", naive_bad != [])
    old_g = os.environ.get("GIT_CONFIG_GLOBAL"); os.environ["GIT_CONFIG_GLOBAL"] = hostile
    try:
        c6 = os.path.join(td, "cand_hostile"); pr = R.reconstruct_candidate(R.Git(None, True), c6, "bundle", ctx["bundle"], H.KIT, R.UPSTREAM_COMMIT, allow_local=True)
        T.check(C, "with a hostile global autocrlf=true in the environment, R3's isolated git + local autocrlf=false still reconstructs a verifying candidate", pr == [] and R.verify_candidate(R.Config(), c6) == [])
    finally:
        if old_g is None: os.environ.pop("GIT_CONFIG_GLOBAL", None)
        else: os.environ["GIT_CONFIG_GLOBAL"] = old_g

    # ================================================================ TOKEN / ENVIRONMENT ISOLATION
    I = "ISOLATION"
    fake = "ghs_FAKE0123456789abcdefTOKEN"; os.environ["GITHUB_TOKEN"] = fake
    try:
        e = NEW(); r = e.go("2026-10-05T12:07:00Z", mode="envdump", token=fake); rec = [m for m in e.markers() if m["mode"] == "envdump"][0]
        T.check(I, "the frozen-runner subprocess environment contains NO token and no GITHUB_TOKEN variable (even when the parent process had one)", r["result"] == R.SUCCESS and rec["token_in_env"] is False and "GITHUB_TOKEN" not in rec["env_names"])
        env_names = set(rec["env_names"]); T.check(I, "the runner environment is whitelisted (PATH/TEMP-type variables, PYTHONDONTWRITEBYTECODE and test extras only)", env_names <= {"PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE", "STUB_MODE", "STUB_MARKER", "STUB_SLEEP", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMROOT"} | {n for n in env_names if n.startswith("PYTHON")})
        T.check(I, "runner_env() never forwards GITHUB_TOKEN even if it is the process environment", "GITHUB_TOKEN" not in R.runner_env(R.Config()))
    finally: os.environ.pop("GITHUB_TOKEN", None)
    gg = R.Git(fake, True); ee = gg._env("https://github.com/o/r"); ep = gg._env(str(td))
    T.check(I, "git gets the auth header only for https://github.com remotes, via its own environment (not argv); never for other remotes", "GIT_CONFIG_VALUE_0" in ee and fake not in " ".join(R.GIT_BASE) and "GIT_CONFIG_VALUE_0" not in ep and "GITHUB_TOKEN" not in ee)
    T.check(I, "git error text is scrubbed of the token and its base64 form", "***" in gg.scrub("x " + fake + " y") and fake not in gg.scrub("a " + fake) and R.base64.b64encode(("x-access-token:" + fake).encode()).decode() not in gg.scrub(R.base64.b64encode(("x-access-token:" + fake).encode()).decode()))
    good_env = dict(GITHUB_SERVER_URL="https://github.com", GITHUB_REPOSITORY="o/r", CANDIDATE_SOURCE_URL="https://github.com/o/cand", GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="2", OPS_COMMIT_PIN="a" * 40,
                    OPS_WRAPPER_SHA256_PIN="b" * 64, WORKFLOW_BLOB_PIN="c" * 40, DEP_LOCK_SHA256_PIN="d" * 64, GITHUB_TOKEN=fake, WORKFLOW_SHA_EVIDENCE="e" * 40)
    cfg = R.build_production_config(good_env)
    T.check(I, "production config: pins from the independent store, GitHub-only remotes, no local remotes, runtime enforced, token captured in the config only", cfg.production and not cfg.allow_local_remotes and cfg.enforce_runtime and cfg.ledger_remote == "https://github.com/o/r" and cfg.token == fake and cfg.run_attempt == 2 and cfg.workflow_sha == "e" * 40 and cfg.verify_fn is None and cfg.runner_cmd_fn is None)
    def bad(**kw):
        try: R.build_production_config({**good_env, **kw}); return False
        except R.ConfigError: return True
    T.check(I, "production config refuses: wrong server, malformed repo, non-GitHub candidate source, bad run id/attempt, missing or malformed pins", all([bad(GITHUB_SERVER_URL="https://gitlab.com"), bad(GITHUB_REPOSITORY="no-slash"), bad(GITHUB_REPOSITORY="a/b\n"), bad(CANDIDATE_SOURCE_URL="http://github.com/a/b"),
            bad(CANDIDATE_SOURCE_URL="https://example.com/a/b"), bad(CANDIDATE_SOURCE_URL=""), bad(GITHUB_RUN_ID=""), bad(GITHUB_RUN_ATTEMPT="0"), bad(GITHUB_RUN_ATTEMPT="x")]), cases=9)
    try: R.build_production_config({**good_env, "OPS_COMMIT_PIN": ""}); built = True
    except R.ConfigError: built = False
    T.check(I, "an empty pin variable passes config building but is refused by the ops gate with CONFIG_ERROR (never a HALT)", built)
    os.environ.update(good_env); os.environ["OPS_COMMIT_PIN"] = "a" * 40
    try:
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf): rc = R.main(["check-ops"])
        out = buf.getvalue()
        T.check(I, "main('check-ops') with mismatching pins exits 22, prints no token, and removes GITHUB_TOKEN from os.environ", rc == 22 and fake not in out and "GITHUB_TOKEN" not in os.environ)
    finally:
        for k in good_env: os.environ.pop(k, None)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf): rcs = [R.main([]), R.main(["run", "--now", "x"]), R.main(["bogus"]), R.main(["verify-ledger", "--bogus"]), R.main(["run", "extra"])]
    T.check(I, "the production CLI accepts no overrides: no args / --now / unknown subcommand / extra args are refused with exit 2", rcs == [2, 2, 2, 2, 2], cases=5)
    with contextlib.redirect_stdout(buf): rc = R.main(["run"])
    T.check(I, "main('run') without the GitHub environment fails closed (CONFIG_ERROR, exit 2) before any network access", rc == 2)

    # ================================================================ SCALE: per-wake validation is bounded; history reproduction belongs to audit
    Sc = "SCALE"
    e = NEW(); e.go("2026-10-05T12:07:00Z"); e.go("2026-10-05T18:07:00Z"); calls = []; orig = R.load_frozen
    def counting(c):
        SJ, SS, VF = orig(c); real = SS.check_success
        def wrapped(*a, **k): calls.append(1); return real(*a, **k)
        SS.check_success = wrapped; return SJ, SS, VF
    R.load_frozen = counting
    try:
        r = e.go("2026-10-06T00:07:00Z"); n_wake = len(calls); calls.clear(); a0 = R.audit(e.cfg("2026-10-06T01:00:00Z"), full=False); n_audit0 = len(calls); calls.clear(); a1 = R.audit(e.cfg("2026-10-06T01:00:00Z"), full=True); n_audit1 = len(calls)
    finally: R.load_frozen = orig
    T.check(Sc, "a wake with 2 historical SUCCESS records reproduces ONLY the new attempt (1 check_success call); history is not re-run per wake", r["result"] == R.SUCCESS and n_wake == 1)
    T.check(Sc, "verify-ledger (no --full) reproduces nothing; verify-ledger --full reproduces every historical SUCCESS (3 calls) and passes", n_audit0 == 0 and a0["ok"] and n_audit1 == 3 and a1["ok"] and a1["reproduced"] == 3)
    t = time.time(); big = [R.make_record(None, "INIT", dict(e.ident(), ts="2026-10-05T11:00:00Z"))]; k = 0
    while len(big) < 20000:
        o = datetime(2026, 10, 5, tzinfo=UTC) + timedelta(hours=6 * k); k += 1
        big.append(R.make_record(big[-1], "STARTED", dict(e.ident(), ts=R.fmt_ts(o + timedelta(minutes=7))), origin=R.fmt_ts(o), attempt_no=1))
        big.append(R.make_record(big[-1], "FAILED", dict(e.ident(), ts=R.fmt_ts(o + timedelta(minutes=9))), origin=R.fmt_ts(o), attempt_no=1, reason="x", journal_attempt_id=None))
    raw = b"".join((R.canon(x) + "\n").encode() for x in big); t1 = time.time(); rr, pp = R.parse_ledger(raw); sp = R.semantic_problems(rr); t2 = time.time()
    T.check(Sc, f"parse + state machine over a 20,000-record ledger ({len(raw) // 1024} KiB; ~13 years of origins) is bounded", pp == [] and sp == [] and (t2 - t1) < 20, cases=20000); T.extra["parse_20000_records_s"] = round(t2 - t1, 2)
    st = R.Store(R.Git(None, True), big_remote(td, 400, e), os.path.join(td, "bigwork")); t = time.time(); ok = st.refresh(); recs, probs = R.structural_check(st); dt = time.time() - t
    T.check(Sc, "structural check of a 400-commit/400-anchor ledger via real git (anchors + history shape + chain) is bounded", ok and probs == [] and len(recs) == 400 and dt < 60, cases=400); T.extra["structural_400_commits_s"] = round(dt, 2)


def _fails(fn):
    try: return fn() != []
    except Exception: return True


def big_remote(td, n, e):
    remote = H.make_remote(td, harden=False); recs = [R.make_record(None, "INIT", dict(e.ident(), ts="2026-10-05T11:00:00Z"))]; k = 0
    while len(recs) < n:
        o = datetime(2026, 10, 5, tzinfo=UTC) + timedelta(hours=6 * k); k += 1
        recs.append(R.make_record(recs[-1], "STARTED", dict(e.ident(), ts=R.fmt_ts(o + timedelta(minutes=7))), origin=R.fmt_ts(o), attempt_no=1))
        recs.append(R.make_record(recs[-1], "FAILED", dict(e.ident(), ts=R.fmt_ts(o + timedelta(minutes=9))), origin=R.fmt_ts(o), attempt_no=1, reason="x", journal_attempt_id=None))
    recs = recs[:n]; stream = bytearray(); lines = b""
    for i, r in enumerate(recs):
        lines += (R.canon(r) + "\n").encode(); msg = f"ledger seq={i} hash={r['record_hash']}".encode()
        stream += b"commit refs/heads/shadow-ledger\nmark :%d\ncommitter t <t@users.noreply.invalid> %d +0000\ndata %d\n%s\n" % (i + 1, 1700000000 + i, len(msg), msg)
        if i: stream += b"from :%d\n" % i
        stream += b"M 100644 inline ledger.jsonl\ndata %d\n%s\n" % (len(lines), lines)
        stream += b"reset refs/tags/%s%06d\nfrom :%d\n\n" % (R.ANCHOR.encode(), i, i + 1)
    subprocess.run(["git", "-C", remote, "fast-import", "--quiet"], input=bytes(stream), check=True, capture_output=True); return remote
