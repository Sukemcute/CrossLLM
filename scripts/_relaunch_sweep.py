"""Relaunch BridgeSentry sweep on remote server using setsid -f.

`setsid -f` (with fork) creates a new session AND forks the process so
the parent exits immediately, leaving the child running detached. This
also lets paramiko's exec_command channel close right away instead of
hanging on file descriptors held by the background process.

Idempotent: the underlying script skips run_*.json files that already
exist.

Usage:
    python scripts/_relaunch_sweep.py <host> <user> <password>
"""

import sys
import time
import paramiko


def run(c, cmd: str, timeout: int = 30) -> str:
    _, stdout, _ = c.exec_command(cmd, timeout=timeout)
    return stdout.read().decode().rstrip()


def fire_and_forget(c, cmd: str) -> None:
    """Run a command without waiting for its output to drain."""
    transport = c.get_transport()
    channel = transport.open_session()
    channel.exec_command(cmd)
    # Don't read stdout/stderr — let the channel close on its own.
    # Brief wait to ensure the command at least started.
    time.sleep(1)
    channel.close()


def main():
    host, user, password = sys.argv[1:4]
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, password=password, timeout=15)

    # Clean up any stale processes
    print("=== Clean stale processes ===")
    print(run(c, "pkill -u quoc -f sukem_sweep 2>&1; pkill -u quoc -f bridgesentry-fuzzer 2>&1; sleep 1; echo cleanup_done"))
    print()

    # Launch via setsid -f (forks + detaches)
    print("=== Launch sweep via setsid -f ===")
    launch_cmd = (
        "setsid -f bash /tmp/sukem_sweep.sh "
        "> /tmp/sukem_sweep.log 2>&1 < /dev/null"
    )
    fire_and_forget(c, launch_cmd)
    print("(launched fire-and-forget)")
    print()

    # Wait, then verify
    time.sleep(5)
    print("=== Verify running (after 5s) ===")
    print(run(c, "ps -ef | grep -E 'sukem_sweep|bridgesentry-fuzzer' | grep -v grep | head -5"))
    print()
    print("=== Log tail ===")
    print(run(c, "tail -15 /tmp/sukem_sweep.log 2>&1"))
    print()
    print("=== Run files (nomad) ===")
    print(run(c, "ls /home/quoc/sukem/CrossLLM/results/nomad/run_*.json 2>/dev/null | wc -l"))

    c.close()


if __name__ == "__main__":
    main()
