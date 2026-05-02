"""Run the Phase D1 smoke sweep on the lab server (12 benchmarks × 1 run × 60 s).
Streams the sweep log line-by-line so we can spot per-bridge failures.

Usage:
    python scripts/_lab_smoke_sweep.py <host> <user> <password>
"""

import sys
import paramiko
import time


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    host, user, password = sys.argv[1:4]

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, password=password, timeout=15)

    cmd = (
        "cd ~/sukem/CrossLLM && "
        "PATH=$HOME/.cargo/bin:$PATH "
        "BUDGET=60 RUNS=1 OUTDIR=$HOME/sukem/CrossLLM/results/smoke_realbytecode "
        "bash scripts/run_full_sweep_real.sh"
    )
    print(f"=== running: {cmd}\n")
    _, stdout, stderr = c.exec_command(cmd, timeout=1500)

    t0 = time.time()
    for line in iter(stdout.readline, ""):
        line = line.rstrip()
        if line:
            print(f"[{int(time.time()-t0):4d}s] {line}")
            sys.stdout.flush()

    rc = stdout.channel.recv_exit_status()
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        print("\nSTDERR:")
        print(err.strip())
    print(f"\n=== smoke sweep exit code: {rc} ===")

    print("\n=== quick metrics across smoke results ===")
    py = (
        "python3 -c '"
        "import json,glob,os; "
        "rows=[]; "
        "for p in sorted(glob.glob(os.path.expanduser(\"~/sukem/CrossLLM/results/smoke_realbytecode/*/run_001.json\"))): "
        "  d=json.load(open(p)); "
        "  it=d[\"stats\"][\"total_iterations\"]; "
        "  bs=d[\"coverage\"][\"basic_blocks_source\"]; "
        "  bd=d[\"coverage\"][\"basic_blocks_dest\"]; "
        "  vc=len(d[\"violations\"]); "
        "  ttes=[v[\"detected_at_s\"] for v in d[\"violations\"]]; "
        "  tte_min=min(ttes) if ttes else 0; "
        "  tte_mean=sum(ttes)/len(ttes) if ttes else 0; "
        "  bridge=os.path.basename(os.path.dirname(p)); "
        "  rows.append((bridge,it,bs,bd,vc,tte_min,tte_mean)); "
        "print(\"%-12s %8s %8s %8s %5s %10s %10s\" % (\"bridge\",\"iters\",\"bb_src\",\"bb_dst\",\"viol\",\"tte_min\",\"tte_mean\")); "
        "[print(\"%-12s %8d %8d %8d %5d %10.4f %10.4f\" % r) for r in rows]'"
    )
    _, stdout, stderr = c.exec_command(py, timeout=60)
    print(stdout.read().decode().rstrip())
    err = stderr.read().decode().strip()
    if err:
        print("STDERR:", err)
    c.close()


if __name__ == "__main__":
    main()
