"""One simulated wake in its own OS process (for the CAS race tests).  usage: worker.py <json spec>"""
import sys, json, time, os
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H
spec = json.loads(sys.argv[1])
while time.time() < spec["start_at"]: pass                       # barrier: every worker fires at the same instant
print(json.dumps(H.R.run_once(H.build_cfg(spec))))
