"""TEST-ONLY stand-in for tools/shadow_run.py.  It never fetches live feeds: it calls the REAL frozen shadow_run.record() with SYNTHETIC feeds into the
journal directory it is given.  Behaviour via STUB_MODE:  success | fail | late | sleep | crash | nowrite | dup | tamper | tamperfeed | badchain | envdump
STUB_MARKER (file) receives one JSON line per entry (pid, mode, argv, and for envdump the environment variable NAMES and a token-leak flag)."""
import sys, os, json, argparse, time, gzip
sys.dont_write_bytecode = True
from datetime import datetime, timedelta, timezone

ap = argparse.ArgumentParser()
for k in ("journal-dir", "t0", "expect-sha", "tag", "repo", "now"): ap.add_argument("--" + k, required=True)
a = ap.parse_args()
sys.path.insert(0, os.path.join(a.repo, "tools")); sys.path.insert(0, os.path.join(a.repo, "submission_pack"))
import numpy as np
import shadow_run as SR, shadow_journal as SJ, model as M

mode = os.environ.get("STUB_MODE", "success")
if os.environ.get("STUB_MARKER"):
    rec = {"pid": os.getpid(), "mode": mode, "argv": sys.argv[1:]}
    if mode == "envdump":
        rec["env_names"] = sorted(os.environ); rec["token_in_env"] = any("TOKEN" in k or "x-access-token" in v for k, v in os.environ.items())
    with open(os.environ["STUB_MARKER"], "a") as f: f.write(json.dumps(rec) + "\n")
t0 = datetime.strptime(a.t0, SR.FMT).replace(tzinfo=timezone.utc); now = datetime.strptime(a.now, SR.ISO).replace(tzinfo=timezone.utc)
if mode == "late": now = t0 + timedelta(hours=2)
if mode == "nowrite": sys.exit(1)
if mode == "crash":
    SJ.Journal(os.path.join(a.journal_dir, "journal.jsonl")).append(dict(type="STARTED", status="STARTED", attempt_id="crash-a1", attempt_no=1, origin=t0.strftime(SR.ISO),
                                                                         timestamp_utc=now.strftime(SR.ISO), late=False, retry_of=[], candidate_freeze_sha_claimed=a.expect_sha, candidate_tag=a.tag))
    os._exit(1)
if mode == "sleep": time.sleep(float(os.environ.get("STUB_SLEEP", "3")))

S = lambda h: 450.0 + 50.0 * np.sin(h / 37.0)                       # synthetic speed by absolute epoch hour
iso = lambda h, m=0: datetime.fromtimestamp(h * 3600 + m * 60, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
i = int(t0.timestamp() // 3600); base = i - M.W
arch = [[iso(h, 5 * k) + "Z", float(S(h))] for h in range(base, i - M.ARCHIVE_MARGIN_H) for k in range(12)]
ace = [{"time_tag": iso(h), "dsflag": 0, "speed": float(S(h))} for h in range(base, i - M.ACE1H_MARGIN_H)]
rt = [{"time_tag": iso(h, mi), "active": False, "source": "ACE", "proton_speed": float(S(h))} for h in range(i - 24, i - 1) for mi in range(60)]
feeds = {"archive": lambda: arch, "ace1h": lambda: ace, "rtsw": lambda: rt}
if mode == "fail": feeds = {"archive": lambda: None, "ace1h": lambda: None, "rtsw": lambda: None}

r = SR.record(t0, lambda: now, a.journal_dir, a.expect_sha, a.tag, root=a.repo, fetchers=feeds)
jp = os.path.join(a.journal_dir, "journal.jsonl")
if r["type"] == "SUCCESS" and mode in ("dup", "tamper", "tamperfeed", "badchain"):
    if mode == "dup":
        d = {k: v for k, v in r.items() if k not in ("seq", "prev_hash", "record_hash")}; d["attempt_id"] = "dup-" + d["attempt_id"]; SJ.Journal(jp).append(d)
    elif mode == "tamper":
        fp = os.path.join(a.journal_dir, r["forecast_path"]); f = json.loads(open(fp, "rb").read()); f["forecast_speed_kms"][5] += 1.0; open(fp, "wb").write(SJ.canon(f).encode())
    elif mode == "tamperfeed":
        fp = os.path.join(a.journal_dir, r["feed_paths"]["rtsw"]); open(fp, "wb").write(gzip.compress(b"[]"))
    elif mode == "badchain":
        L = open(jp, "rb").read(); open(jp, "wb").write(L.replace(b'"type":"STARTED"', b'"type":"STARTEX"', 1))
if mode == "mutate":
    with open(os.path.join(a.repo, "tools", "perturb.py"), "ab") as f: f.write(b"# tampered during the run" + bytes([10]))
print(r["type"], r.get("attempt_id", ""), r.get("reason", ""))
sys.exit(0 if r["type"] == "SUCCESS" else 1)
