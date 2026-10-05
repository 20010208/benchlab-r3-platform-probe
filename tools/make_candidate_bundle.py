"""Create the THIN candidate bundle (the user's candidate commits only; the organizer's unchanged files are NOT included) from a local starter-kit clone.
Read-only on the kit.  The bundle is never committed to this repository (see .gitignore); where it is published is a separate PM decision.
usage:  python tools/make_candidate_bundle.py --kit <path to the starter-kit clone> --out <file.bundle>"""
import argparse, os, subprocess, sys
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import shadow_ops_r3 as R


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--kit", required=True); ap.add_argument("--out", required=True); a = ap.parse_args()
    def git(*x, cwd=None): return subprocess.run(["git", *x], cwd=cwd, capture_output=True, text=True)
    got = git("-C", a.kit, "rev-parse", f"{R.CANDIDATE_TAG}^{{commit}}").stdout.strip()
    if got != R.CANDIDATE_SHA: print(f"REFUSED: tag {R.CANDIDATE_TAG} resolves to {got[:12]}, pinned {R.CANDIDATE_SHA[:12]}", file=sys.stderr); return 1
    if git("-C", a.kit, "cat-file", "-t", R.UPSTREAM_COMMIT).stdout.strip() != "commit": print("REFUSED: pinned upstream commit not present in the kit", file=sys.stderr); return 1
    r = git("-C", a.kit, "bundle", "create", os.path.abspath(a.out), f"refs/tags/{R.CANDIDATE_TAG}", f"^{R.UPSTREAM_COMMIT}")
    if r.returncode: print(r.stderr, file=sys.stderr); return 1
    v = git("bundle", "verify", os.path.abspath(a.out), cwd=a.kit)
    print("bundle created and verified" if v.returncode == 0 else "bundle verify failed", os.path.getsize(a.out), "bytes"); return v.returncode


if __name__ == "__main__": sys.exit(main())
