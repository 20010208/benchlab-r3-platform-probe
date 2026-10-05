"""Runs the R3 test modules.  usage: python tests/run_all.py [pure] [integration] [races] [static] [stress]   (default: all but stress)
Environment:  R3_TEST_OUT=<file for the results json>   R3_STRESS_ROUNDS=<n extra full-run race rounds for 'stress'>"""
import sys, os, tempfile, importlib, time, json
sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import tlib, harness as H

NEEDS_CANDIDATE = ("integration", "races", "stress", "static")


def main(argv):
    want = argv or ["pure", "integration", "races", "static"]; T = tlib.T()
    with tempfile.TemporaryDirectory() as td:
        ctx = {"td": td}
        if any(w in NEEDS_CANDIDATE for w in want):
            t = time.time(); ctx["cand"], ctx["bundle"] = H.make_candidate(td); T.extra["candidate_reconstruct_and_real_verify_s"] = round(time.time() - t, 1)
        for w in want:
            t = time.time(); m = importlib.import_module("test_" + w)
            m.run(T) if w == "pure" else m.run(T, ctx)
            print(f"-- section {w} done in {round(time.time() - t)} s", flush=True)
    print("\n==== SUMMARY ====\n" + T.summary())
    print("EXTRA", json.dumps(T.extra, default=str)[:2000]); print("FAILS", T.fails)
    T.dump(os.environ.get("R3_TEST_OUT") or os.path.join(tempfile.gettempdir(), "r3_results.json"))
    return 1 if T.fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
