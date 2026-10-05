"""Extra full-run race stress rounds (default 30; set R3_STRESS_ROUNDS).  Same conditions as test_races.full_round: identical run ids and identical virtual time."""
import sys, os, collections
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H
import test_races as TR


def run(T, ctx):
    n = int(os.environ.get("R3_STRESS_ROUNDS", "30")); td, cand = ctx["td"], ctx["cand"]; winners = []; agg = collections.Counter()
    for i in range(n):
        ran, c = TR.full_round(T, H.Env(td, cand).init(), f"stress round {i}"); winners.append(ran); agg.update(c)
    T.extra["stress_rounds"] = n; T.extra["stress_winners"] = winners; T.extra["stress_processes"] = n * TR.W
