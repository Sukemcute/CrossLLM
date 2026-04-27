"""Pull RQ1 sweep results from lab server (~/sukem/CrossLLM/results/<bridge>/)
to local results/lab_sweep_2026_04_27/<bridge>/.

Usage:
    python scripts/_pull_results.py <host> <user> <password>
"""

import sys
import time
from pathlib import Path

import paramiko

BRIDGES = [
    "nomad", "qubit", "pgala", "polynetwork", "wormhole", "socket",
    "ronin", "harmony", "multichain", "orbit", "fegtoken", "gempad",
]
REMOTE_BASE = "/home/{user}/sukem/CrossLLM/results"
LOCAL_BASE = Path(__file__).resolve().parent.parent / "results" / "lab_sweep_2026_04_27"


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    host, user, password = sys.argv[1:4]

    LOCAL_BASE.mkdir(parents=True, exist_ok=True)
    print(f"Pulling to: {LOCAL_BASE}")

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, password=password, timeout=15)
    sftp = c.open_sftp()

    remote_base = REMOTE_BASE.format(user=user)
    total_files = 0
    t0 = time.time()

    for bridge in BRIDGES:
        local_dir = LOCAL_BASE / bridge
        local_dir.mkdir(parents=True, exist_ok=True)
        remote_dir = f"{remote_base}/{bridge}"
        try:
            entries = sftp.listdir(remote_dir)
        except FileNotFoundError:
            print(f"  {bridge:12s}  MISSING on remote")
            continue

        files = [f for f in entries if f.startswith("run_") and f.endswith(".json")]
        for fname in sorted(files):
            sftp.get(f"{remote_dir}/{fname}", str(local_dir / fname))
        total_files += len(files)
        print(f"  {bridge:12s}  {len(files):2d} files")

    sftp.close()
    c.close()
    dt = time.time() - t0
    print(f"\nDONE - {total_files} files in {dt:.1f}s -> {LOCAL_BASE}")


if __name__ == "__main__":
    main()
