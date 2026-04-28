"""Check Phase D1 full-sweep progress on the lab server.

Reports live: how many run_*.json have landed per bridge, the
last 10 log lines, and whether the daemon is still alive.

Usage:
    python scripts/_lab_check_full_sweep.py <host> <user> <password>
"""

import sys
import paramiko


BRIDGES = [
    "nomad", "qubit", "pgala", "polynetwork", "wormhole", "socket",
    "ronin", "harmony", "multichain", "orbit", "fegtoken", "gempad",
]


def run(c, cmd, timeout=30):
    _, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace").rstrip()


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    host, user, password = sys.argv[1:4]

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, password=password, timeout=15)

    print("=== latest sweep outdir ===")
    outdir = run(c, "ls -dt ~/sukem/CrossLLM/results/realbytecode_full_* 2>/dev/null | head -1")
    print(outdir or "(no sweep dir found)")

    print("\n=== process tree (sweep + active fuzzer) ===")
    print(run(c, "ps -eo pid,ppid,etime,cmd | grep -E 'run_full_sweep|bridgesentry-fuzzer' | grep -v grep | head -5") or "(no live processes)")

    if outdir:
        print("\n=== run files per bridge ===")
        bridges = " ".join(BRIDGES)
        cmd = (
            f'for b in {bridges}; do '
            f'  n=$(ls "{outdir}"/$b/run_*.json 2>/dev/null | wc -l); '
            f'  printf "  %-12s %2d/20\\n" $b $n; '
            f'done'
        )
        print(run(c, cmd))

    print("\n=== latest log file ===")
    log = run(c, "ls -t /tmp/realbytecode_sweep_*.log 2>/dev/null | head -1")
    print(log or "(no log)")
    if log:
        print("\n=== log tail (last 12 lines) ===")
        print(run(c, f"tail -12 {log}"))

    c.close()


if __name__ == "__main__":
    main()
