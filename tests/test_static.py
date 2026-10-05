"""Static checks: workflow structure, network allowlist, Linux static validation, publication hygiene.  No network; reads files only."""
import sys, os, re, ast, subprocess, json
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H
R = H.R
REPO = H.REPO
rd = lambda rel: open(os.path.join(REPO, rel), encoding="utf-8", newline="").read()


def strip_comments(t): return "\n".join(l.split(" #")[0] if not l.lstrip().startswith("#") else "" for l in t.splitlines())


def tracked_and_new():
    r = subprocess.run(["git", "-C", REPO, "ls-files", "--cached", "--others", "--exclude-standard"], capture_output=True, text=True, env=H.ENVBASE)
    return sorted(set(x for x in r.stdout.split("\n") if x))


def run(T, ctx):
    W = "WORKFLOW"; wf = rd(R.WORKFLOW_PATH); code = strip_comments(wf); lines = wf.splitlines()
    on_keys = []; inside = False
    for l in lines:
        if re.match(r"^on:\s*$", l): inside = True; continue
        if inside:
            if l and not l.startswith(" "): break
            m = re.match(r"^  ([a-z_]+):", l)
            if m: on_keys.append(m.group(1))
    T.check(W, "triggers are exactly schedule + workflow_dispatch (no pull_request, pull_request_target, push, or anything else)", sorted(on_keys) == ["schedule", "workflow_dispatch"] and "pull_request" not in code)
    T.check(W, "exactly one schedule: '7,17,27,37 0,6,12,18 * * *' (UTC wakes 7/17/27/37 minutes after each six-hourly origin)", re.findall(r"cron:\s*'([^']+)'", wf) == ["7,17,27,37 0,6,12,18 * * *"])
    T.check(W, "workflow_dispatch has NO inputs (no user-controlled t0); no t0/late-ok anywhere", re.search(r"workflow_dispatch:\s*\{\}", wf) is not None and "inputs" not in code and "late-ok" not in code and "t0" not in code.lower().replace("shadow_ops_r3", ""))
    jp = []; grab = False
    for l in lines:
        if re.match(r"^    permissions:\s*$", l): grab = True; continue
        if grab:
            if re.match(r"^      \S", l): jp.append(l.split("#")[0].strip())
            else: break
    T.check(W, "top-level permissions: {} and the single job grants exactly `contents: write` and nothing else", re.search(r"(?m)^permissions:\s*\{\}\s*$", wf) is not None and jp == ["contents: write"] and wf.count("permissions:") == 2)
    T.check(W, "no secrets context and NO `uses:` at all (zero third-party actions)", "secrets." not in code and not re.search(r"(?m)^\s*-?\s*uses:", code))
    exprs = [l for l in lines if "${{" in l and not l.lstrip().startswith("#")]
    T.check(W, "every ${{ }} expression is a plain env mapping of vars.* / github.token / github.workflow_sha (no expression inside a shell script)", all(re.match(r"^\s+[A-Z0-9_]+: \$\{\{ (vars\.[A-Z0-9_]+|github\.token|github\.workflow_sha) \}\}\s*$", l) for l in exprs) and len(exprs) == 7, cases=len(exprs))
    steps = re.split(r"(?m)^      - name: ", wf)[1:]
    tok = [i for i, s in enumerate(steps) if "github.token" in s]
    T.check(W, "github.token appears in exactly ONE step -- the final wrapper step", tok == [len(steps) - 1] and wf.count("github.token") == 1 and steps[-1].startswith("Shadow wake"))
    T.check(W, "job timeout is 12 minutes (< the 13-minute crash lease); the runner timeout is below it", re.search(r"timeout-minutes: 12\b", wf) is not None and R.JOB_TIMEOUT_MIN == 12 and R.JOB_TIMEOUT_MIN * 60 > R.RUNNER_TIMEOUT_S and R.LEASE.total_seconds() / 60 > R.JOB_TIMEOUT_MIN)
    T.check(W, "concurrency group with cancel-in-progress: false; runs only on the default branch; pinned runner image label", "cancel-in-progress: false" in wf and "if: github.ref == 'refs/heads/main'" in wf and "runs-on: ubuntu-24.04" in wf)
    T.check(W, "dependency install is hash-locked: --require-hashes --only-binary=:all: --no-deps -r ops/requirements.lock", "pip install --no-cache-dir --require-hashes --only-binary=:all: --no-deps -r ops/requirements.lock" in wf)
    T.check(W, "ops commit is fetched by exact SHA with autocrlf off and HEAD is compared with the pin before anything runs", 'fetch -q --depth=1 "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" "$OPS_COMMIT_PIN"' in wf and "core.autocrlf=false" in wf and 'test "$(git -C ops rev-parse HEAD)" = "$OPS_COMMIT_PIN"' in wf)
    T.check(W, "the wrapper is invoked with the single subcommand `run` and no overrides", re.search(r"run: python3 -B ops/shadow_ops_r3\.py run\s*$", wf, re.M) is not None)
    T.extra["workflow_blob_hash"] = subprocess.run(["git", "hash-object", os.path.join(REPO, R.WORKFLOW_PATH)], capture_output=True, text=True).stdout.strip()
    T.extra["container_image_pinned_by_digest"] = "@sha256:" in wf          # OPEN ITEM: expected False until the external test records the digest
    # ---------------------------------------------------------------- network allowlist
    N = "NETWORK"; cand = ctx["cand"]; hosts = set(); bad_imports = []
    for rel in ("submission_pack/model.py", "submission_pack/swp_features.py", "tools/shadow_run.py", "tools/shadow_journal.py", "tools/verify_freeze.py", "tools/shadow_score.py"):
        src = open(os.path.join(cand, rel), encoding="utf-8").read(); hosts |= {m.group(1) for m in re.finditer(r"https?://([A-Za-z0-9.-]+)", src)}
        for node in ast.walk(ast.parse(src)):
            names = [a.name.split(".")[0] for a in node.names] if isinstance(node, ast.Import) else ([node.module.split(".")[0]] if isinstance(node, ast.ImportFrom) and node.module else [])
            bad_imports += [n for n in names if n in ("requests", "boto3", "botocore", "socket", "ftplib", "smtplib", "paramiko", "httpx", "aiohttp")]
    T.check(N, "the FROZEN runner/model/journal/scorer/verifier source contacts only the two allowed data hosts (literal URLs)", hosts == set(R.ALLOWED_DATA_HOSTS), cases=len(hosts))
    T.check(N, "the frozen runtime uses urllib only (no requests/boto/socket/ftp/smtp/other client libraries)", bad_imports == [])
    wsrc = rd(R.WRAPPER_NAME); whosts = {m.group(1) for m in re.finditer(r"https?://([A-Za-z0-9.-]+)", wsrc)}
    T.check(N, "every literal URL host in the wrapper is an allowed infrastructure host", whosts <= set(R.ALLOWED_INFRA_HOSTS) and "github.com" in whosts, cases=len(whosts))
    readme = rd("README.md")
    T.check(N, "the README network-surface table documents every host the workflow/wrapper/lock can touch (data hosts, github.com, pypi, files.pythonhosted, public.ecr.aws, apt mirrors)", all(h in readme for h in (*R.ALLOWED_DATA_HOSTS, *R.ALLOWED_INFRA_HOSTS, "public.ecr.aws", "apt")), cases=8)
    forb = ["port" + "al", "up" + "load.sh", "submit_" + "conformance", "pre" + "sign", "X-" + "Amz"]
    T.check(N, "no participant-site / upload / submission / presigned-URL endpoint or credential name appears in the wrapper, workflow or lock", not any(f.lower() in (wsrc + wf + rd(R.LOCK_NAME)).lower() for f in forb), cases=len(forb))
    T.check(N, "the allowlists are tuples of exactly the expected hosts", R.ALLOWED_DATA_HOSTS == ("services.swpc.noaa.gov", "cdaweb.gsfc.nasa.gov") and R.ALLOWED_INFRA_HOSTS == ("github.com", "pypi.org", "files.pythonhosted.org"))
    # ---------------------------------------------------------------- Linux static validation
    L = "LINUX_STATIC"
    for rel in (R.WRAPPER_NAME, "tools/make_candidate_bundle.py", "tests/harness.py", "tests/stub_runner.py", "tests/worker.py", "tests/run_all.py", "tests/test_pure.py", "tests/test_integration.py", "tests/test_races.py", "tests/test_static.py", "tests/test_stress.py", "tests/tlib.py"):
        try: ast.parse(rd(rel), feature_version=(3, 10)); ok = True
        except SyntaxError as e: ok = False; print("py3.10 grammar problem in", rel, e)
        T.check(L, f"{rel}: valid Python 3.10 grammar", ok)
    ban = ["ct" + "ypes", "msv" + "crt", "win" + "reg", "os.start" + "file", "LOCAL" + "APPDATA", "tom" + "llib", "Exception" + "Group", "typing.Self", "datetime.UTC", "StrEnum", "TaskGroup", "os.getlogin"]
    T.check(L, "the wrapper uses no Windows-only API and no Python 3.11+ feature", not any(b in wsrc for b in ban) and "except*" not in wsrc, cases=len(ban))
    T.check(L, "no drive-letter path literal and no os.sep/backslash joining in the wrapper (paths via os.path only)", not re.search(r"[A-Za-z]:\\\\", wsrc) and "os.sep" not in wsrc and "ntpath" not in wsrc and "'\\\\'" not in wsrc and '"\\\\"' not in wsrc)
    T.check(L, "LF line endings only and a python3 shebang (the workflow executes the file directly on Linux)", all(b"\r" not in open(os.path.join(REPO, f), "rb").read() for f in tracked_and_new() if f.endswith((".py", ".yml", ".md", ".lock", ".gitattributes", ".gitignore"))) and wsrc.startswith("#!/usr/bin/env python3\n"))
    T.check(L, ".gitattributes keeps bytes unconverted (`* -text`) so on-disk bytes are what gets hashed", rd(".gitattributes").strip() == "* -text")
    T.check(L, "every subprocess/git invocation in the wrapper is an argv list (no shell=True, no string commands)", "shell=True" not in wsrc and "os.system" not in wsrc and "os.popen" not in wsrc)
    # ---------------------------------------------------------------- publication hygiene
    Hy = "HYGIENE"; files = tracked_and_new(); texts = {f: open(os.path.join(REPO, f), encoding="utf-8", errors="replace").read() for f in files if not f.endswith((".png",))}
    bad_parts = {".te" + "am", "kit.zip", "evi" + "dence", "wo" + "rk", "node_modules", ".env"}
    T.check(Hy, "no forbidden path component (private-notes, secrets, archive, evidence, scratch directories) anywhere in the file set", not [f for f in files if set(f.split("/")) & bad_parts], cases=len(files))
    T.check(Hy, "no bundle, wheel, archive or key file is part of the repository", not [f for f in files if f.endswith((".bundle", ".whl", ".zip", ".pem", ".key", ".pfx", ".token"))] and all(os.path.getsize(os.path.join(REPO, f)) < 400_000 for f in files))
    pats = {"team-config file name": r"\." + "te" + r"am\b", "participant-site word": "port" + "al", "sync-folder name": "One" + "Drive", "windows user path": r"[A-Za-z]:\\+Us" + "ers", "unix home path": r"/(?:home|Users)/[a-z]",
            "email address": r"[A-Za-z0-9._%+-]+@(?!users\.noreply\.invalid)[A-Za-z0-9-]+\.[A-Za-z.]+", "personal mail domain": "gm" + "ail", "cloud access key": "AK" + r"IA[0-9A-Z]{16}", "presigned marker": "X-" + "Amz", "private key block": "BEGIN [A-Z ]*PRIV" + "ATE KEY",
            "owner name": "(?i)ch" + "iji", "owner first name": "(?i)ko" + "ki", "bearer token": r"(?i)bearer\s+[A-Za-z0-9._-]{20,}"}
    hits = {k: [f for f, t in texts.items() if re.search(p, t)] for k, p in pats.items()}
    T.check(Hy, "no credential, personal identifier, local path, sync-folder name or participant-site reference in ANY file", all(not v for v in hits.values()), cases=len(pats))
    if any(hits.values()): print("HYGIENE HITS", {k: v for k, v in hits.items() if v})
    r = subprocess.run(["git", "-C", REPO, "log", "--format=%an <%ae>|%cn <%ce>"], capture_output=True, text=True, env=H.ENVBASE)
    idents = [x for x in r.stdout.split("\n") if x]; T.extra["commit_identities"] = sorted(set(idents))
    T.check(Hy, "every commit (if any exist yet) uses the neutral noreply.invalid identity", all(x.count("@users.noreply.invalid>") == 2 for x in idents), cases=len(idents))
    T.check(Hy, "the lock file and wrapper carry no secret-like strings and the documentation states the privacy caveats separately", "existing candidate-history privacy caveats" in rd("docs/PUBLICATION.md").lower())
