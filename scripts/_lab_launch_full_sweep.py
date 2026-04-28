"""Daemonize the Phase D1 full sweep on the lab server (600 s × 20 × 12).

Uses setsid -f + nohup so the sweep survives our SSH disconnect and any
session/logind teardown. Returns the launched PID + log path.

Usage:
    python scripts/_lab_launch_full_sweep.py <host> <user> <password>
"""

import sys
import time
import paramiko


def run(c, cmd, timeout=60):
    _, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").rstrip()
    err = stderr.read().decode("utf-8", errors="replace").rstrip()
    rc = stdout.channel.recv_exit_status()
    return rc, out, err


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    host, user, password = sys.argv[1:4]

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, password=password, timeout=15)

    # Sanity check: not already running.
    rc, out, _ = run(c, "ps -eo pid,cmd | grep -E 'run_full_sweep_real|bridgesentry-fuzzer' | grep -v grep | head -5")
    if out:
        print("WARNING — fuzzer-related processes already running:")
        print(out)
        print("Aborting. Stop them first or pick a fresh path.")
        c.close()
        sys.exit(1)

    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    outdir = f"$HOME/sukem/CrossLLM/results/realbytecode_full_{ts}"
    log = f"/tmp/realbytecode_sweep_{ts}.log"
    pidfile = f"/tmp/realbytecode_sweep_{ts}.pid"

    # Daemonize: setsid -f detaches from controlling terminal AND its
    # session, so logind tearing down our SSH session does not propagate
    # SIGHUP to the sweep. nohup is belt-and-suspenders.
    launch = (
        f"cd $HOME/sukem/CrossLLM && "
        f"PATH=$HOME/.cargo/bin:$PATH "
        f"OUTDIR={outdir} BUDGET=600 RUNS=20 "
        f"setsid -f nohup bash scripts/run_full_sweep_real.sh "
        f"> {log} 2>&1 < /dev/null"
    )
    print(f"=== launching:\n{launch}\n")
    rc, out, err = run(c, launch, timeout=15)
    if err:
        print("STDERR:", err)

    # Give the kernel a moment, then capture the pid by name.
    time.sleep(3)
    rc, pid, _ = run(
        c,
        "ps -eo pid,ppid,cmd | grep run_full_sweep_real | grep -v grep | "
        "awk '$2==1 {print $1; exit}'",
    )
    if pid:
        run(c, f"echo {pid} > {pidfile}")
        print(f"PID    : {pid}")
        print(f"PIDFILE: {pidfile}")
    else:
        print("WARN: could not detect PID — sweep may have failed to launch")

    print(f"OUTDIR : {outdir}")
    print(f"LOG    : {log}")

    print("\n=== ps tree (first 5 lines) ===")
    _, out, _ = run(c, "ps -eo pid,ppid,etime,cmd | grep -E 'run_full_sweep|bridgesentry-fuzzer' | grep -v grep | head -5")
    print(out or "(nothing yet — sweep may still be starting)")

    print("\n=== log tail (first 10 lines) ===")
    _, out, _ = run(c, f"tail -10 {log} 2>/dev/null || echo '(log not yet flushed)'")
    print(out)

    c.close()


if __name__ == "__main__":
    main()
