"""Run aggregator on remote server, fetch RQ1 results."""

import sys
import paramiko


def run(c, cmd: str, timeout: int = 60) -> str:
    _, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    return stdout.read().decode().rstrip()


def main():
    host, user, password = sys.argv[1:4]
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, password=password, timeout=15)

    # Try aggregator using project venv (which has paramiko? probably not)
    # Use python3 system-wide.
    print("=== Phase D2 aggregator output (--format table) ===")
    print(run(c, "cd ~/sukem/CrossLLM && python3 scripts/collect_baseline_results.py --format table"))
    print()

    print("=== Per-benchmark detail (--format detail via collect_results.py) ===")
    print(run(c, "cd ~/sukem/CrossLLM && python3 scripts/collect_results.py --format table"))

    c.close()


if __name__ == "__main__":
    main()
