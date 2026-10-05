"""SYNTHETIC runner for platform tests: writes journal records and fixture files using the synthetic Journal.  No model, no network, no real data.
STUB_MODE: success | fail | sleep | envdump (records the environment variable NAMES and whether anything token-like is present)."""
import sys, os, json, gzip, hashlib, argparse, time
sys.dont_write_bytecode = True
ap = argparse.ArgumentParser()
for k in ("journal-dir", "t0", "repo", "now"): ap.add_argument("--" + k, required=True)
a = ap.parse_args()
sys.path.insert(0, os.path.join(a.repo, "tools"))
import shadow_journal as SJ
sha = lambda b: hashlib.sha256(b).hexdigest()
mode = os.environ.get("STUB_MODE", "success"); origin = f"{a.t0[0:4]}-{a.t0[4:6]}-{a.t0[6:8]}T{a.t0[9:11]}:{a.t0[11:13]}:{a.t0[13:15]}Z"
if mode == "envdump":
    rec = {"names": sorted(os.environ), "token_like": any("TOKEN" in k.upper() or "x-access-token" in v or v.startswith(("ghs_", "gho_", "ghp_")) for k, v in os.environ.items())}
    if os.environ.get("STUB_MARKER"): open(os.environ["STUB_MARKER"], "a").write(json.dumps(rec) + chr(10))
if mode == "sleep": time.sleep(float(os.environ.get("STUB_SLEEP", "5")))
J = SJ.Journal(os.path.join(a.journal_dir, "journal.jsonl")); recs, _ = J.read()
n = sum(1 for r in recs if r.get("type") == "STARTED" and r.get("origin") == origin) + 1; aid = f"{a.t0}-a{n}-synthetic"
J.append(dict(type="STARTED", origin=origin, attempt_id=aid, attempt_no=n))
if mode == "fail": J.append(dict(type="FAILED", origin=origin, attempt_id=aid, attempt_no=n, reason="synthetic failure")); sys.exit(1)
adir = os.path.join("attempts", aid); os.makedirs(os.path.join(a.journal_dir, adir), exist_ok=True)
feed = json.dumps([1, 2, 3]).encode(); fp = f"{adir}/feed_x.json.gz"; open(os.path.join(a.journal_dir, fp), "wb").write(gzip.compress(feed, mtime=0))
fc = json.dumps({"t0": origin, "synthetic": True, "n": n}).encode(); fcp = f"{adir}/forecast.json"; open(os.path.join(a.journal_dir, fcp), "wb").write(fc)
J.append(dict(type="SUCCESS", origin=origin, attempt_id=aid, attempt_no=n, forecast_sha256=sha(fc), forecast_path=fcp, feed_sha256={"x": sha(feed)}, feed_paths={"x": fp}))
print("SUCCESS", aid); sys.exit(0)
