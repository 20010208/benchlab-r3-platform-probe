"""SYNTHETIC stand-in for a shadow journal (platform tests only; NOT the frozen candidate's code).  Same interface the R3 wrapper uses: Journal(path).read()/head()/append()."""
import os, json, hashlib

GENESIS = "0" * 64


def canon(d): return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
def rec_hash(prev, body): return hashlib.sha256((prev + canon(body)).encode()).hexdigest()


class Journal:
    def __init__(self, path):
        self.path = path; os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def read(self, expected_head=None):
        recs, problems, prev = [], [], GENESIS
        if not os.path.exists(self.path): return recs, []
        lines = open(self.path, "rb").read().split(b"\n")
        if lines and lines[-1] == b"": lines = lines[:-1]
        else: problems.append("journal does not end with a newline")
        for i, ln in enumerate(lines):
            try: r = json.loads(ln.decode("utf-8"))
            except ValueError: problems.append(f"line {i}: invalid JSON"); break
            h = r.pop("record_hash", None)
            if r.get("seq") != i or r.get("prev_hash") != prev or h != rec_hash(r.get("prev_hash", ""), r): problems.append(f"line {i}: chain broken"); break
            r["record_hash"] = h; recs.append(r); prev = h
        return recs, problems

    def head(self):
        recs, probs = self.read(); return (recs[-1]["record_hash"] if recs else GENESIS), probs

    def append(self, rec):
        recs, probs = self.read()
        if probs: raise RuntimeError("corrupt journal")
        body = dict(rec); body["seq"] = len(recs); body["prev_hash"] = recs[-1]["record_hash"] if recs else GENESIS
        h = rec_hash(body["prev_hash"], body)
        with open(self.path, "ab") as f: f.write((canon(dict(body, record_hash=h)) + "\n").encode()); f.flush(); os.fsync(f.fileno())
        return dict(body, record_hash=h)
