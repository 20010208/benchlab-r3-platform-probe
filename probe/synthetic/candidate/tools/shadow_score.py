"""SYNTHETIC stand-in for the scorer's check_success (platform tests only).  Verifies stored forecast/feed hashes; no model."""
import os, json, gzip, hashlib

sha = lambda b: hashlib.sha256(b).hexdigest()


def check_success(logdir, rec, cand, t0):
    p = []
    try:
        fb = open(os.path.join(logdir, rec["forecast_path"]), "rb").read()
        if sha(fb) != rec["forecast_sha256"]: p.append("forecast file hash != recorded forecast_sha256")
        for k, rel in rec["feed_paths"].items():
            if sha(gzip.decompress(open(os.path.join(logdir, rel), "rb").read())) != rec["feed_sha256"][k]: p.append(f"feed {k} hash != recorded")
    except (OSError, KeyError, ValueError) as e:
        p.append(f"cannot verify stored artifacts: {type(e).__name__}")
    return p
