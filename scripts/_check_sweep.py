"""Check status of remote sweep on lab server."""

import sys
import paramiko


def run(c, cmd: str, label: str = None):
    print(f"$ {label or cmd[:70]}")
    _, stdout, _ = c.exec_command(cmd, timeout=30)
    out = stdout.read().decode().rstrip()
    print(out if out else "(empty)")
    print()


def main():
    host, user, password = sys.argv[1:4]
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, password=password, timeout=15)

    run(c, "tmux ls 2>&1")
    run(c, "wc -l /tmp/sukem_sweep.log 2>&1")
    run(c, "tail -40 /tmp/sukem_sweep.log 2>&1", "tail -40 /tmp/sukem_sweep.log")
    run(c, "ps -ef | grep -E 'sukem_sweep|bridgesentry-fuzzer' | grep -v grep | head -5",
        "running sweep processes?")
    run(c, "uptime")

    print("=== Run files per bridge ===")
    bridges = ["nomad", "qubit", "pgala", "polynetwork", "wormhole", "socket",
               "ronin", "harmony", "multichain", "orbit", "fegtoken", "gempad"]
    cmd = (
        "for b in " + " ".join(bridges) + "; do "
        "n=$(ls ~/sukem/CrossLLM/results/$b/run_*.json 2>/dev/null | wc -l); "
        'printf "  %-12s %d/20\\n" $b $n; done'
    )
    run(c, cmd, "for b in ...; ls run_*.json | wc -l")
    c.close()


if __name__ == "__main__":
    main()
