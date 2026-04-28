"""Phase D1 lab-server setup: pull feat/real-bytecode-fuzz, build release,
verify Rust toolchain. Does NOT kick off the sweep — that step runs
separately so we can confirm the environment first.

Usage:
    python scripts/_lab_phase_a_setup.py <host> <user> <password>
"""

import sys
import paramiko


def run(c, cmd, timeout=900):
    """Run blocking; return (exit_code, stdout, stderr_tail)."""
    _, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
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

    print("=== rustc on PATH? ===")
    rc, out, _ = run(c, 'PATH=$HOME/.cargo/bin:$PATH; rustc --version 2>&1; cargo --version 2>&1')
    print(out.strip() or "(none)")

    print("\n=== git status before pull ===")
    rc, out, _ = run(c, "cd ~/sukem/CrossLLM && git fetch origin && git status -sb 2>&1 | head -3")
    print(out.strip())

    print("\n=== checkout + pull feat/real-bytecode-fuzz ===")
    rc, out, err = run(
        c,
        "cd ~/sukem/CrossLLM && git checkout feat/real-bytecode-fuzz 2>&1 || "
        "git checkout -b feat/real-bytecode-fuzz origin/feat/real-bytecode-fuzz 2>&1",
        timeout=60,
    )
    print(out.strip())
    if err.strip():
        print("STDERR:", err.strip())
    rc, out, err = run(c, "cd ~/sukem/CrossLLM && git pull --ff-only 2>&1")
    print(out.strip())

    print("\n=== HEAD commit ===")
    rc, out, _ = run(c, "cd ~/sukem/CrossLLM && git log --oneline -5")
    print(out.strip())

    print("\n=== cargo build --release (this can take 5-15 min on first build) ===")
    rc, out, err = run(
        c,
        "cd ~/sukem/CrossLLM/src/module3_fuzzing && PATH=$HOME/.cargo/bin:$PATH "
        "cargo build --release --bin bridgesentry-fuzzer 2>&1 | tail -30",
        timeout=1200,
    )
    print(out.strip())
    if rc != 0:
        print(f"BUILD FAILED rc={rc}")
        if err.strip():
            print("STDERR tail:", err.strip()[-500:])
        sys.exit(rc)

    rc, out, _ = run(
        c,
        "ls -la ~/sukem/CrossLLM/src/module3_fuzzing/target/release/bridgesentry-fuzzer 2>&1",
    )
    print("\n=== binary ===")
    print(out.strip())

    c.close()
    print("\nSetup OK — ready for smoke sweep.")


if __name__ == "__main__":
    main()
