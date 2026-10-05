"""CAS race tests: real OS processes racing on a real git remote.  Every worker has the SAME run id and the SAME virtual time -- the exact condition that produced byte-identical claim commits
(a false double winner) before the per-record nonce was added -- so these rounds are a regression test of the NONCE fix as well."""
import sys, os, time, collections
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H
R = H.R
O1, O2 = "2026-10-05T12:00:00Z", "2026-10-05T18:00:00Z"
W = 16
LEDGER_OK = lambda e: e.view()[2] == []


def full_round(T, e, label):
    st = time.time() + 9.0; res = H.collect([H.spawn(e, "2026-10-05T12:10:00Z", st, sleep=1.0) for _ in range(W)]); c = collections.Counter(x["result"] for x in res); ran = sum(1 for x in res if x.get("ran"))
    ok = ran == 1 and c[R.SUCCESS] == 1 and e.count("STARTED", O1) == 1 and e.count("SUCCESS", O1) == 1 and LEDGER_OK(e) and "WORKER_CRASH" not in c and e.states() == ["INIT", "STARTED", "SUCCESS"]
    if not ok: print("DIAG", label, dict(c), "ran", ran, "states", e.states(), "problems", e.view()[2], [x for x in res if x["result"] in ("WORKER_CRASH", R.INTEGRITY_FAILURE, R.ABANDONED)][:2], flush=True)
    T.check("CAS", f"{label}: {W} simultaneous identical claimants on one origin -> exactly 1 ran, 1 STARTED, 1 SUCCESS; chain verifies", ok, cases=W)
    return ran, c


def run(T, ctx):
    td, cand = ctx["td"], ctx["cand"]; NEW = lambda: H.Env(td, cand).init(); winners = []; agg = collections.Counter(); rounds = 0
    for i in range(12): ran, c = full_round(T, NEW(), f"full-run race {i}"); winners.append(ran); agg.update(c); rounds += 1
    for i in range(8):
        e = NEW(); st = time.time() + 9.0; res = H.collect([H.spawn(e, "2026-10-05T12:10:00Z", st, claim_only=True) for _ in range(W)]); c = collections.Counter(x["result"] for x in res)
        T.check("CAS", f"claim-only race {i}: exactly 1 CLAIMED among {W}; exactly 1 STARTED(attempt 1)", c[R.CLAIMED] == 1 and e.count("STARTED", O1) == 1 and "WORKER_CRASH" not in c and LEDGER_OK(e), cases=W); winners.append(c[R.CLAIMED]); agg.update(c); rounds += 1
    for i in range(6):
        e = NEW(); e.go("2026-10-05T12:07:00Z", claim_only=True)               # attempt 1 claimed and never finished (crash/cancel)
        st = time.time() + 9.0; res = H.collect([H.spawn(e, "2026-10-05T12:21:00Z", st, claim_only=True) for _ in range(W)]); c = collections.Counter(x["result"] for x in res)
        T.check("CAS", f"crash-lease race {i}: after the 13-minute lease exactly 1 of {W} claims attempt 2; attempt 1 is never re-claimed", c[R.CLAIMED] == 1 and [r["attempt_no"] for r in e.view()[1] if r["state"] == "STARTED"] == [1, 2] and LEDGER_OK(e), cases=W); winners.append(c[R.CLAIMED]); agg.update(c); rounds += 1
    for i in range(3):
        e = NEW(); e.go("2026-10-05T12:07:00Z", mode="fail"); st = time.time() + 9.0; res = H.collect([H.spawn(e, "2026-10-05T12:17:00Z", st, claim_only=True) for _ in range(W)]); c = collections.Counter(x["result"] for x in res)
        T.check("CAS", f"retry race {i}: after a FAILED attempt exactly 1 of {W} claims attempt 2", c[R.CLAIMED] == 1 and e.count("STARTED", O1) == 2 and LEDGER_OK(e), cases=W); winners.append(c[R.CLAIMED]); agg.update(c); rounds += 1
    for i in range(2):
        e = NEW(); e.go("2026-10-05T12:07:00Z", mode="fail"); e.go("2026-10-05T12:17:00Z", mode="fail")
        st = time.time() + 9.0; res = H.collect([H.spawn(e, "2026-10-05T12:27:00Z", st, claim_only=True) for _ in range(W)]); c = collections.Counter(x["result"] for x in res)
        T.check("CAS", f"cap race {i}: exactly 1 of {W} claims the third (last) attempt, then the cap holds", c[R.CLAIMED] == 1 and e.count("STARTED", O1) == 3 and e.go("2026-10-05T12:37:00Z")["result"] in (R.SKIPPED_IN_FLIGHT, R.SKIPPED_CAP) and LEDGER_OK(e), cases=W); winners.append(c[R.CLAIMED]); agg.update(c); rounds += 1
    for i in range(4):
        e = NEW(); st = time.time() + 9.0; res = H.collect([H.spawn(e, "2026-10-05T12:10:00Z", st, claim_only=True) for _ in range(W // 2)] + [H.spawn(e, "2026-10-05T18:10:00Z", st, claim_only=True) for _ in range(W // 2)]); c = collections.Counter(x["result"] for x in res)
        T.check("CAS", f"two-origin claim race {i}: 8+8 workers on two different origins -> each origin exactly 1 STARTED (claims serialise through the CAS, both succeed); chain verifies", e.count("STARTED", O1) == 1 and e.count("STARTED", O2) == 1 and c[R.CLAIMED] == 2 and LEDGER_OK(e) and "WORKER_CRASH" not in c, cases=W); rounds += 1
    e = NEW(); st0 = time.time() + 3.0; pa = H.spawn(e, "2026-10-05T12:07:00Z", st0, mode="sleep", sleep=40); pb = H.spawn(e, "2026-10-05T18:10:00Z", st0 + 16.0, claim_only=True); ra, rb = H.collect([pa, pb]); st, recs, p = e.view()
    T.check("CAS", "interleave policy: if ANOTHER writer moves the ledger while my lease is valid (impossible in production: origins are 6 h apart and same-origin wakes skip), my result is discarded and the system HALTs (class UNEXPECTED_WRITER) -- fail closed, no rebase of a hash-chained journal",
            ra["result"] == R.INTEGRITY_FAILURE and ra.get("halt_class") == "UNEXPECTED_WRITER" and rb["result"] == R.CLAIMED and recs[-1]["state"] == "HALT" and recs[-1]["halt_class"] == "UNEXPECTED_WRITER" and e.count("SUCCESS") == 0 and p == []); rounds += 1
    e = NEW(); st0 = time.time() + 6.0; res = H.collect([H.spawn(e, "2026-10-05T12:12:00Z", st0, sleep=0.5) for _ in range(4)])
    T.check("CAS", "four wakes delivered at the same instant (the 4-wake schedule collapsing) -> exactly one attempt", sum(1 for x in res if x.get("ran")) == 1 and e.count("STARTED") == 1 and e.count("SUCCESS") == 1); rounds += 1
    T.extra["race_rounds"] = rounds; T.extra["race_winners_per_round"] = winners; T.extra["race_results"] = dict(agg); T.extra["race_processes"] = rounds * W
