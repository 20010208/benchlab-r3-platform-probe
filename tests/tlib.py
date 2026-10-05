"""Tiny test collector shared by the R3 test modules."""
import collections, json, sys, time
sys.dont_write_bytecode = True


class T:
    def __init__(self):
        self.c = collections.defaultdict(lambda: [0, 0]); self.cases = collections.defaultdict(int); self.fails = []; self.extra = {}; self.t0 = time.time()

    def check(self, cat, name, cond, cases=1):
        self.c[cat][0] += 1; self.cases[cat] += cases
        if cond: self.c[cat][1] += 1
        else: self.fails.append((cat, name)); print("FAIL", cat, "|", name, flush=True)

    def summary(self):
        lines = []; tot = [0, 0, 0]
        for k, (n, p) in sorted(self.c.items()):
            lines.append(f"{k:10s} checks={n:4d} pass={p:4d} cases={self.cases[k]}"); tot[0] += n; tot[1] += p; tot[2] += self.cases[k]
        lines.append(f"TOTAL      checks={tot[0]} pass={tot[1]} fail={tot[0] - tot[1]} cases={tot[2]} elapsed_s={round(time.time() - self.t0)}")
        return "\n".join(lines)

    def dump(self, path):
        json.dump({"counts": self.c, "cases": self.cases, "extra": self.extra, "fails": self.fails}, open(path, "w"), default=str, indent=1)
