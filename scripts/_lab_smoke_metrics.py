"""Print Phase D1 smoke-sweep metrics from the lab server."""

import sys
import paramiko


REMOTE_SCRIPT = r"""
python3 - <<'PY'
import json, glob, os
rows = []
pattern = os.path.expanduser("~/sukem/CrossLLM/results/smoke_realbytecode/*/run_001.json")
for p in sorted(glob.glob(pattern)):
    d = json.load(open(p))
    it = d["stats"]["total_iterations"]
    bs = d["coverage"]["basic_blocks_source"]
    bd = d["coverage"]["basic_blocks_dest"]
    vc = len(d["violations"])
    ttes = [v["detected_at_s"] for v in d["violations"]]
    tte_min = min(ttes) if ttes else 0.0
    tte_mean = sum(ttes)/len(ttes) if ttes else 0.0
    bridge = os.path.basename(os.path.dirname(p))
    rows.append((bridge, it, bs, bd, vc, tte_min, tte_mean))
print("%-12s %8s %8s %8s %5s %10s %10s" % ("bridge","iters","bb_src","bb_dst","viol","tte_min","tte_mean"))
for r in rows:
    print("%-12s %8d %8d %8d %5d %10.4f %10.4f" % r)
PY
"""


def main():
    host, user, password = sys.argv[1:4]
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, password=password, timeout=15)
    _, stdout, stderr = c.exec_command(REMOTE_SCRIPT, timeout=60)
    print(stdout.read().decode().rstrip())
    err = stderr.read().decode().strip()
    if err:
        print("STDERR:", err)
    c.close()


if __name__ == "__main__":
    main()
