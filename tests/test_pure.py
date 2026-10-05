"""Pure-logic tests: strict schema, state machine, nonce, origin/window, decide(), retry model + fuzz.  No git, no network."""
import sys, os, json, random, itertools, copy, time
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H
R = H.R
from datetime import datetime, timedelta, timezone
UTC = timezone.utc
IDENT = dict(candidate_sha=R.CANDIDATE_SHA, ops_commit="a" * 40, wrapper_sha256="b" * 64, workflow_blob="c" * 40, lock_sha256="d" * 64, workflow_sha=None, journal_head=R.GENESIS,
             ts="2026-10-05T12:07:00Z", run_id="run-1", run_attempt=1, runtime_identity="py3.10/numpy2.2.6/x86_64")
O1, O2 = "2026-10-05T12:00:00Z", "2026-10-05T18:00:00Z"
FH = {"rtsw": "e" * 64, "ace1h": "f" * 64}


def _raises(fn):
    try: fn()
    except (ValueError, KeyError, AssertionError): return True
    return False


def mk(prev, state, ts="2026-10-05T12:07:00Z", **kw):
    ex = {}
    if state in ("STARTED", "FAILED", "SUCCESS"): ex.update(origin=kw.pop("origin", O1), attempt_no=kw.pop("attempt_no", 1))
    if state == "FAILED": ex.update(reason="x", journal_attempt_id=None)
    if state == "SUCCESS": ex.update(forecast_sha256="9" * 64, feed_sha256=FH, journal_attempt_id="20261005T120000Z-a1-abcd1234")
    if state == "HALT": ex.update(reason="x", halt_class="LEDGER")
    ex.update(kw)
    return R.make_record(prev, state, dict(IDENT, ts=ts), **ex)


def chain(*specs):
    out = []
    for st, kw in specs: out.append(mk(out[-1] if out else None, st, **kw))
    return out


def raw_of(recs): return b"".join((R.canon(r) + "\n").encode() for r in recs)
def rehash_manual(r):                                       # hand-craft an otherwise-valid chain element (used to build records make_record would refuse)
    r = dict(r); r.pop("record_hash", None); r["record_hash"] = R.sha256_hex((r["prev_hash"] + R.canon(r)).encode()); return r


def run(T):
    S = "SCHEMA"
    good = chain(("INIT", {}), ("STARTED", {}), ("FAILED", dict(ts="2026-10-05T12:09:00Z")), ("STARTED", dict(attempt_no=2, ts="2026-10-05T12:20:00Z")), ("SUCCESS", dict(attempt_no=2, ts="2026-10-05T12:23:00Z")),
                 ("STARTED", dict(origin=O2, ts="2026-10-05T18:07:00Z")), ("HALT", dict(ts="2026-10-05T18:09:00Z")))
    recs, p = R.parse_ledger(raw_of(good)); T.check(S, "a valid chain of every state parses with no problems", p == [] and len(recs) == 7 and R.semantic_problems(recs) == [])
    # missing mandatory field: every key of every state
    n = bad = 0
    for r in good:
        for k in R.KEYS[r["state"]]:
            m = {x: y for x, y in r.items() if x != k}; n += 1; bad += bool(R.shape_problems(m))
    T.check(S, "removing ANY mandatory field of ANY state is rejected", n == bad, cases=n)
    m = dict(good[1], extra="x"); T.check(S, "unexpected extra field rejected", bool(R.shape_problems(m)))
    for v in ("r3.ledger.v0", "r3.ledger.v2", "", None, 1): pass
    T.check(S, "unknown / altered schema string rejected", all(R.shape_problems(dict(good[1], schema=v)) for v in ("r3.ledger.v0", "r3.ledger.v2", "", None, 1, "R3.LEDGER.V1")), cases=6)
    T.check(S, "unknown state rejected", all(R.shape_problems(dict(good[1], state=v)) for v in ("started", "DONE", "", None, 7)), cases=5)
    base = good[1]
    badorigins = ["2026-10-05T12:00:01Z", "2026-10-05T12:01:00Z", "2026-10-05T07:00:00Z", "2026-10-05 12:00:00", "2026-10-05T12:00:00+00:00", "2026-13-05T12:00:00Z", "2026-10-05T12:00:00z", " 2026-10-05T12:00:00Z", "", None, 12, "2026-10-05T24:00:00Z"]
    T.check(S, "invalid origin (non-boundary, malformed, wrong type) rejected", all(R.shape_problems(dict(base, origin=v)) for v in badorigins), cases=len(badorigins))
    badatt = [0, 4, -1, 2 ** 40, True, False, "1", None, 1.5, [1]]
    T.check(S, "invalid attempt (0, >3, negative, bool, string, null, float, list) rejected", all(R.shape_problems(dict(base, attempt_no=v)) for v in badatt), cases=len(badatt))
    cnt = ok = 0
    for r in good:
        for k in ("prev_hash", "wrapper_sha256", "lock_sha256", "journal_head", "record_hash", "candidate_sha", "ops_commit", "workflow_blob", "nonce"):
            if k not in r: continue
            L = {"prev_hash": 64, "wrapper_sha256": 64, "lock_sha256": 64, "journal_head": 64, "record_hash": 64, "candidate_sha": 40, "ops_commit": 40, "workflow_blob": 40, "nonce": 32}[k]
            for v in ("A" * L, "a" * (L - 1), "a" * (L + 1), "g" * L, "", None, 12345, "a" * L + "\n", ("a" * (L - 1)) + "G"):
                cnt += 1; ok += bool(R.shape_problems(dict(r, **{k: v})))
    T.check(S, "invalid hash/sha/nonce formats (uppercase, short, long, non-hex, empty, null, int, newline) rejected for every hash field", cnt == ok, cases=cnt)
    s = good[4]
    badfeeds = [{}, {"RTSW": "e" * 64}, {"rtsw": "E" * 64}, {"rtsw": "e" * 63}, ["x"], None, {"rtsw": 1}, {"a" * 17: "e" * 64}, {str(i): "e" * 64 for i in range(9)}]
    T.check(S, "invalid feed_sha256 maps rejected", all(R.shape_problems(dict(s, feed_sha256=v)) for v in badfeeds), cases=len(badfeeds))
    T.check(S, "invalid forecast_sha256 / reason / halt_class / run id / run_attempt / ts / workflow_sha rejected", all([
        R.shape_problems(dict(s, forecast_sha256="x")), R.shape_problems(dict(good[2], reason="")), R.shape_problems(dict(good[2], reason="é")), R.shape_problems(dict(good[2], reason="a" * 301)),
        R.shape_problems(dict(good[6], halt_class="BOGUS")), R.shape_problems(dict(base, run_id="bad id!")), R.shape_problems(dict(base, run_attempt=0)), R.shape_problems(dict(base, run_attempt=True)),
        R.shape_problems(dict(base, ts="2026-10-05")), R.shape_problems(dict(base, workflow_sha="z" * 40)), R.shape_problems(dict(base, runtime_identity=""))]), cases=11)
    T.check(S, "make_record refuses to build an invalid record", all(_raises(lambda kw=kw: mk(good[0], "STARTED", **kw)) for kw in (dict(origin="2026-10-05T12:00:01Z"), dict(attempt_no=4), dict(attempt_no=0))), cases=3)
    # raw-line level rejections
    line = R.canon(good[1]).encode(); head = raw_of(good[:1])
    raw_cases = {
        "duplicate JSON key": line.replace(b'"state":"STARTED"', b'"state":"STARTED","state":"STARTED"'),
        "float number": line.replace(b'"seq":1', b'"seq":1.0'), "NaN constant": line.replace(b'"seq":1', b'"seq":NaN'),
        "non-canonical whitespace": line.replace(b'":"', b'": "', 1), "reordered keys": json.dumps(good[1], sort_keys=False).encode(),
        "trailing garbage": line + b"xx", "UTF-8 BOM": b"\xef\xbb\xbf" + line, "invalid UTF-8": line.replace(b"run-1", b"run-\xff"), "CRLF": line + b"\r",
        "blank line in the middle": b"", "not an object": b"[1]"}
    n = bad = 0
    for name, ln in raw_cases.items():
        n += 1; recs2, p2 = R.parse_ledger(head + ln + b"\n"); bad += bool(p2) and len(recs2) == 1
    T.check(S, "raw-line attacks (duplicate key, float, NaN, whitespace, key order, garbage, BOM, bad UTF-8, CRLF, blank line, non-object) rejected without silent normalisation", n == bad, cases=n)
    T.check(S, "missing trailing newline / empty ledger / torn last line rejected", all(R.parse_ledger(x)[1] for x in (b"", raw_of(good[:2])[:-1], raw_of(good[:2])[:-20])), cases=3)
    # state machine
    def sem(*specs):
        rs = chain(*specs); r2, p2 = R.parse_ledger(raw_of(rs)); assert not p2, p2; return R.semantic_problems(r2)
    I = ("INIT", {}); A1 = ("STARTED", {}); F1 = ("FAILED", dict(ts="2026-10-05T12:09:00Z")); S1 = ("SUCCESS", dict(ts="2026-10-05T12:10:00Z"))
    cases = {
        "first record is not INIT": [A1],
        "INIT twice": [I, ("INIT", {})],
        "attempt 2 while attempt 1 is still inside its lease": [I, A1, ("STARTED", dict(attempt_no=2, ts="2026-10-05T12:15:00Z"))],
        "attempt number skips": [I, ("STARTED", dict(attempt_no=2))],
        "terminal without a STARTED": [I, ("FAILED", {})],
        "STARTED after SUCCESS": [I, A1, S1, ("STARTED", dict(attempt_no=2, ts="2026-10-05T12:20:00Z"))],
        "duplicate SUCCESS (second attempt after a FAILED, then another SUCCESS)": [I, A1, ("SUCCESS", dict(ts="2026-10-05T12:10:00Z")), ("SUCCESS", dict(ts="2026-10-05T12:11:00Z"))],
        "terminal for the wrong attempt": [I, A1, F1, ("STARTED", dict(attempt_no=2, ts="2026-10-05T12:20:00Z")), ("SUCCESS", dict(attempt_no=1, ts="2026-10-05T12:22:00Z"))],
        "record after HALT": [I, ("HALT", {}), A1],
        "claim outside the 40-minute window": [I, ("STARTED", dict(ts="2026-10-05T12:41:00Z"))],
        "claim before its origin": [I, ("STARTED", dict(ts="2026-10-05T11:59:00Z"))],
        "second terminal for one attempt": [I, A1, F1, ("FAILED", dict(ts="2026-10-05T12:10:00Z"))],
        "different candidate SHA inside the ledger": [I, ("STARTED", dict(candidate_sha="e" * 40))]}
    n = bad = 0
    for name, sp in cases.items():
        n += 1
        try:
            rs = []
            for st, kw in sp:
                kw = dict(kw); cs = kw.pop("candidate_sha", None); ident = dict(IDENT, ts=kw.pop("ts", "2026-10-05T12:07:00Z"))
                if cs: ident["candidate_sha"] = cs
                ex = {}
                if st in ("STARTED", "FAILED", "SUCCESS"): ex.update(origin=kw.pop("origin", O1), attempt_no=kw.pop("attempt_no", 1))
                if st == "FAILED": ex.update(reason="x", journal_attempt_id=None)
                if st == "SUCCESS": ex.update(forecast_sha256="9" * 64, feed_sha256=FH, journal_attempt_id="a1")
                if st == "HALT": ex.update(reason="x", halt_class="LEDGER")
                rs.append(R.make_record(rs[-1] if rs else None, st, ident, **ex))
            r2, p2 = R.parse_ledger(raw_of(rs)); assert not p2, (name, p2); bad += bool(R.semantic_problems(r2))
        except AssertionError as e: print("setup problem", e)
    T.check(S, "invalid state transitions rejected by the state machine (13 distinct violations)", n == bad, cases=n)
    four = rehash_manual(dict(mk(good[0], "STARTED"), attempt_no=4)); T.check(S, "attempt 4 (more than 3 STARTED) is rejected at parse time", bool(R.parse_ledger(raw_of([good[0], four]))[1]))
    # nonce
    nn = [R.make_record(good[0], "STARTED", IDENT, origin=O1, attempt_no=1) for _ in range(3000)]
    T.check("NONCE", "3000 byte-identical-input claims all carry distinct nonces and record hashes", len({r["nonce"] for r in nn}) == 3000 and len({r["record_hash"] for r in nn}) == 3000, cases=3000)
    T.check("NONCE", "nonce is 128 bits of hex in every record state", all(len(r["nonce"]) == 32 for r in good))
    # ---------------------------------------------------------------- origins
    O = "ORIGIN"
    def eo(s):
        o, why = R.eligible_origin(R.parse_ts(s)); return R.fmt_ts(o) if o else None
    cases = [("2026-10-05T00:00:00Z", "2026-10-05T00:00:00Z"), ("2026-10-05T00:06:00Z", "2026-10-05T00:00:00Z"), ("2026-10-05T00:39:59Z", "2026-10-05T00:00:00Z"), ("2026-10-05T00:40:00Z", "2026-10-05T00:00:00Z"),
             ("2026-10-05T00:40:01Z", None), ("2026-10-05T05:59:00Z", None), ("2026-10-05T06:00:00Z", "2026-10-05T06:00:00Z"), ("2026-10-05T06:39:59Z", "2026-10-05T06:00:00Z"), ("2026-10-05T06:40:00Z", "2026-10-05T06:00:00Z"),
             ("2026-10-05T06:40:01Z", None), ("2026-10-05T11:59:00Z", None), ("2026-10-05T12:00:00Z", "2026-10-05T12:00:00Z"), ("2026-10-05T18:39:59Z", "2026-10-05T18:00:00Z"), ("2026-10-05T18:40:00Z", "2026-10-05T18:00:00Z"),
             ("2026-10-05T18:40:01Z", None), ("2026-10-05T23:59:00Z", None), ("2026-10-05T23:59:59Z", None), ("2027-12-31T23:59:00Z", None), ("2028-01-01T00:00:00Z", "2028-01-01T00:00:00Z"), ("2028-01-01T00:40:00Z", "2028-01-01T00:00:00Z"),
             ("2028-02-28T23:59:59Z", None), ("2028-02-29T00:00:00Z", "2028-02-29T00:00:00Z"), ("2028-02-29T18:39:59Z", "2028-02-29T18:00:00Z"), ("2028-02-29T23:59:59Z", None), ("2028-03-01T00:05:00Z", "2028-03-01T00:00:00Z"),
             ("2026-11-30T23:59:00Z", None), ("2026-12-01T00:10:00Z", "2026-12-01T00:00:00Z"), ("2026-12-31T23:59:59Z", None), ("2027-01-01T00:00:00Z", "2027-01-01T00:00:00Z"), ("2100-02-28T18:20:00Z", "2100-02-28T18:00:00Z"), ("2100-03-01T00:20:00Z", "2100-03-01T00:00:00Z")]
    T.check(O, "explicit boundary / month / year / leap-day cases (00:40:00 inclusive = identical to Windows R2; 40:01 refused)", sum(eo(a) == b for a, b in cases) == len(cases), cases=len(cases))
    inst = datetime(2026, 10, 5, 12, 5, tzinfo=UTC); zones = [timezone(timedelta(hours=h, minutes=m)) for h, m in ((8, 0), (-5, 0), (5, 45), (-12, 0), (14, 0), (0, 0))]
    T.check(O, "UTC invariance: one instant in 6 different UTC offsets selects the same origin", len({R.canonical_origin(inst.astimezone(z)) for z in zones}) == 1 and all(R.eligible_origin(inst.astimezone(z))[0] == R.canonical_origin(inst) for z in zones), cases=6)
    sweep = bad = never_prev = 0; cur = datetime(2027, 12, 30, tzinfo=UTC); end = datetime(2028, 3, 2, tzinfo=UTC)
    while cur < end:
        for sec in (0, 59):
            now = cur + timedelta(seconds=sec); e = int(now.timestamp()); oe = (e // 21600) * 21600; want = datetime.fromtimestamp(oe, UTC) if e - oe <= 2400 else None
            got, _ = R.eligible_origin(now); sweep += 1
            if (got is None) != (want is None) or (got is not None and got != want): bad += 1
            if got is not None and (int(got.timestamp()) % 21600 != 0 or got > now): bad += 1
            if got is None: never_prev += 1
        cur += timedelta(minutes=1)
    T.check(O, "per-minute sweep 2027-12-30..2028-03-02 (leap day, month, year rollover) vs an independent epoch oracle", bad == 0, cases=sweep)
    edge = ok = 0
    for d in range(40):
        for h in (0, 6, 12, 18):
            o = datetime(2028, 2, 1, h, tzinfo=UTC) + timedelta(days=d)
            for sec, want in ((2399, True), (2400, True), (2401, False)): edge += 1; ok += (R.eligible_origin(o + timedelta(seconds=sec))[0] is not None) == want
    T.check(O, "second-level 40:00 edge at 160 origins (39:59 yes, 40:00 yes, 40:01 no)", edge == ok, cases=edge)
    T.check(O, "no backfill: every late instant yields NO origin (never the previous or any past origin)", never_prev > 0 and all(R.eligible_origin(datetime(2026, 10, 5, 12, 41, tzinfo=UTC) + timedelta(minutes=k))[0] is None for k in range(0, 319)), cases=never_prev)
    T.check(O, "the wake/trigger time never becomes t0 (t0 always a 6-hour boundary <= now)", all(int(R.canonical_origin(datetime(2026, 10, 5, 0, 0, tzinfo=UTC) + timedelta(minutes=m)).timestamp()) % 21600 == 0 for m in range(0, 1440)), cases=1440)
    # ---------------------------------------------------------------- decide() + retry model + fuzz
    Rt = "RETRY"; o = datetime(2026, 10, 5, 12, tzinfo=UTC); t = lambda mn: o + timedelta(minutes=mn)
    D = lambda recs, mn: R.decide(recs, o, t(mn))
    c0 = chain(("INIT", {})); c1 = chain(("INIT", {}), ("STARTED", dict(ts="2026-10-05T12:07:00Z")))
    T.check(Rt, "decide: empty origin -> CLAIM attempt 1", D(c0, 7) == ("CLAIM", 1))
    T.check(Rt, "decide: incomplete attempt inside the 13-minute lease -> SKIPPED_IN_FLIGHT (through 12:20:00); after it -> CLAIM 2", D(c1, 19) == ("SKIP", R.SKIPPED_IN_FLIGHT) and D(c1, 20) == ("SKIP", R.SKIPPED_IN_FLIGHT) and D(c1, 21) == ("CLAIM", 2))
    c3 = chain(("INIT", {}), ("STARTED", dict(ts="2026-10-05T12:07:00Z")), ("FAILED", dict(ts="2026-10-05T12:08:00Z")), ("STARTED", dict(attempt_no=2, ts="2026-10-05T12:17:00Z")), ("FAILED", dict(attempt_no=2, ts="2026-10-05T12:18:00Z")),
               ("STARTED", dict(attempt_no=3, ts="2026-10-05T12:27:00Z")))
    T.check(Rt, "decide: a 4th attempt is never claimed, even after the lease expires (cap = 3 STARTED)", D(c3, 28) == ("SKIP", R.SKIPPED_CAP) and D(c3, 39) == ("SKIP", R.SKIPPED_CAP))
    cs = chain(("INIT", {}), ("STARTED", dict(ts="2026-10-05T12:07:00Z")), ("SUCCESS", dict(ts="2026-10-05T12:09:00Z")))
    T.check(Rt, "decide: SUCCESS is terminal (SKIPPED_DONE at every later minute)", all(D(cs, mn) == ("SKIP", R.SKIPPED_DONE) for mn in range(9, 41)), cases=32)
    ident = dict(IDENT)
    def sim(wakes, outcomes, job=3, timeout=12):
        recs = [R.make_record(None, "INIT", dict(ident, ts="2026-10-05T11:00:00Z"))]; busy = -1; oc = list(outcomes); log = []
        for w in sorted(wakes):
            s = max(w, busy); now = o + timedelta(seconds=round(s * 60))
            org, why = R.eligible_origin(now)
            if org is None: log.append(("SKIPPED_NOT_DUE", s)); busy = max(busy, s); continue
            v, arg = R.decide(recs, org, now)
            if v == "SKIP": log.append((arg, s)); busy = max(busy, s); continue
            res = oc.pop(0) if oc else "failed"; recs.append(R.make_record(recs[-1], "STARTED", dict(ident, ts=R.fmt_ts(now)), origin=R.fmt_ts(org), attempt_no=arg))
            if res == "crash": busy = s + timeout
            else:
                tn = now + timedelta(minutes=job)
                kw = dict(reason="x", journal_attempt_id=None) if res != "success" else dict(forecast_sha256="9" * 64, feed_sha256=FH, journal_attempt_id="a1")
                recs.append(R.make_record(recs[-1], "SUCCESS" if res == "success" else "FAILED", dict(ident, ts=R.fmt_ts(tn)), origin=R.fmt_ts(org), attempt_no=arg, **kw)); busy = s + job
            log.append(("CLAIM:" + res, s))
        return recs, log
    def inv(recs, log):
        st = [r for r in recs if r["state"] == "STARTED"]; su = [r for r in recs if r["state"] == "SUCCESS"]
        after = bool(su) and any(r["state"] == "STARTED" and r["seq"] > su[0]["seq"] for r in recs)
        return len(st) <= 3 and len(su) <= 1 and not after and [r["attempt_no"] for r in st] == list(range(1, len(st) + 1)) and R.semantic_problems(recs) == []
    NOM = (7, 17, 27, 37); cnt = lambda r, s: sum(x["state"] == s for x in r)
    scen = [("first wake succeeds", NOM, ["success"], lambda r, l: cnt(r, "STARTED") == 1 and cnt(r, "SUCCESS") == 1 and all(x[0] == R.SKIPPED_DONE for x in l[1:])),
            ("first fails / second succeeds", NOM, ["failed", "success"], lambda r, l: cnt(r, "STARTED") == 2 and cnt(r, "SUCCESS") == 1),
            ("first two fail / third succeeds", NOM, ["failed", "failed", "success"], lambda r, l: cnt(r, "STARTED") == 3 and cnt(r, "SUCCESS") == 1),
            ("all three fail; the fourth wake only observes (SKIPPED_CAP)", NOM, ["failed", "failed", "failed", "success"], lambda r, l: cnt(r, "STARTED") == 3 and cnt(r, "SUCCESS") == 0 and l[-1][0] == R.SKIPPED_CAP),
            ("first wake delayed to +25", (25, 27, 37), ["failed", "success"], lambda r, l: cnt(r, "SUCCESS") == 1),
            ("all four delivered simultaneously", (12, 12, 12, 12), ["success"], lambda r, l: cnt(r, "STARTED") == 1 and cnt(r, "SUCCESS") == 1),
            ("wakes at >= 40:01 are refused", (40.02, 55), ["success"], lambda r, l: all(x[0] == R.SKIPPED_NOT_DUE for x in l) and cnt(r, "STARTED") == 0),
            ("SUCCESS exists: later wakes skip", NOM, ["success", "success"], lambda r, l: cnt(r, "STARTED") == 1),
            ("crash then retry only after the lease (max two real attempts before +40)", NOM, ["crash", "success"], lambda r, l: cnt(r, "SUCCESS") == 1 and cnt(r, "STARTED") == 2 and any(x[0] == R.SKIPPED_IN_FLIGHT for x in l))]
    for name, wk, oc, chk in scen:
        rr, ll = sim(wk, oc); T.check(Rt, f"4-wake model: {name}", inv(rr, ll) and chk(rr, ll))
    rng = random.Random(20261005); fuzz = fuzz_ok = 0; max_claims = 0; max_succ = 0
    for _ in range(20000):
        wk = sorted(rng.choice([7, 17, 27, 37]) + rng.choice([0, 0, 0, 3, 11, 25, 40]) for _ in range(rng.choice([1, 2, 3, 4, 4, 4, 6]))); oc = [rng.choice(["success", "failed", "crash", "failed"]) for _ in range(6)]
        rr, ll = sim(wk, oc, job=rng.choice([1, 3, 8])); fuzz += 1; fuzz_ok += inv(rr, ll); max_claims = max(max_claims, cnt(rr, "STARTED")); max_succ = max(max_succ, cnt(rr, "SUCCESS"))
    T.check(Rt, "randomised wake/outcome fuzz: <=3 STARTED, <=1 SUCCESS, none after SUCCESS, contiguous attempts, and every generated ledger passes the state machine", fuzz == fuzz_ok and max_claims <= 3 and max_succ <= 1, cases=fuzz)
    T.extra["fuzz"] = dict(cases=fuzz, ok=fuzz_ok, max_started_per_origin=max_claims, max_success_per_origin=max_succ)
    T.extra["origin_counts"] = dict(explicit=len(cases), sweep_instants=sweep, edge_instants=edge)
    # ---------------------------------------------------------------- push-error classification (lost CAS vs rule rejection vs network error)
    C = R.classify_push_error
    cas = [" ! [remote rejected] HEAD -> shadow-ledger (non-fast-forward)", " ! [rejected]        HEAD -> shadow-ledger (fetch first)", " ! [rejected] HEAD -> shadow-ledger (non-fast-forward)", " ! [rejected] anchor-000003 -> anchor-000003 (already exists)",
           "error: failed to push some refs; hint: Updates were rejected because the remote contains work", "error: cannot lock ref 'refs/heads/shadow-ledger': is at abc but expected def", " ! [rejected] x (stale info)"]
    rule = ["remote: error: GH006: Protected branch update failed for refs/heads/shadow-ledger.", "remote: error: GH013: Repository rule violations found for refs/heads/shadow-ledger.", " ! [remote rejected] HEAD -> shadow-ledger (protected branch hook declined)",
            "remote: error: Cannot force-push to this branch (protected branch)", " ! [remote rejected] x (Changes must be made through a pull request)", " ! [remote rejected] x (required status check is expected)"]
    net = ["fatal: unable to access 'https://github.com/o/r/': Could not resolve host: github.com", "fatal: unable to access: Connection timed out after 30001 milliseconds", "fatal: Authentication failed for 'https://github.com/o/r/'", "", None, "error: RPC failed; HTTP 502"]
    T.check("CAS", "push-error classification: lost CAS (incl. server-reported [remote rejected] non-fast-forward / fetch first / slot taken) -> REJECTED (retry); rule/protection texts -> RULE_REJECTED; network/auth/empty -> ERROR",
            all(C(x) == "REJECTED" for x in cas) and all(C(x) == "RULE_REJECTED" for x in rule) and all(C(x) == "ERROR" for x in net), cases=len(cas) + len(rule) + len(net))
