"""Kill orphan bridgesentry-fuzzer processes (PPID=1) on the lab server,
keeping the ones that belong to the active sweep tree."""

import sys
import time
import paramiko


def run(c, cmd: str) -> str:
    _, stdout, _ = c.exec_command(cmd, timeout=20)
    return stdout.read().decode().rstrip()


def main():
    host, user, password = sys.argv[1:4]
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, password=password, timeout=15)

    print("=== Before cleanup ===")
    print(run(c, "ps -eo pid,ppid,cmd | grep -E 'sukem_sweep|bridgesentry-fuzzer' | grep -v grep"))
    print()

    print("=== Kill orphan fuzzer (PPID=1) ===")
    cmd = (
        "for pid in $(ps -eo pid,ppid,cmd | grep bridgesentry-fuzzer | "
        "grep -v grep | awk '$2==1{print $1}'); do "
        "kill $pid 2>&1 && echo killed_$pid; done"
    )
    print(run(c, cmd) or "(no orphans)")
    print()

    time.sleep(3)
    print("=== After cleanup ===")
    print(run(c, "ps -eo pid,ppid,cmd | grep -E 'sukem_sweep|bridgesentry-fuzzer' | grep -v grep"))
    print()

    print("=== Log tail ===")
    print(run(c, "tail -10 /tmp/sukem_sweep.log"))
    print()

    bridges = "nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad"
    cmd = (
        f"for b in {bridges}; do "
        "n=$(ls ~/sukem/CrossLLM/results/$b/run_*.json 2>/dev/null | wc -l); "
        'printf "  %-12s %d/20\\n" $b $n; done'
    )
    print("=== Run file counts ===")
    print(run(c, cmd))
    c.close()


if __name__ == "__main__":
    main()
