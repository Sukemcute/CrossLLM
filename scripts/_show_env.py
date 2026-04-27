"""One-shot helper: read a remote .env via SFTP and show key=masked-value.

Usage:
    python scripts/_show_env.py <host> <user> <password> <remote_path>
"""

import sys
import paramiko


def main():
    if len(sys.argv) != 5:
        print("Usage: python scripts/_show_env.py <host> <user> <password> <remote_path>")
        sys.exit(2)
    host, user, password, remote_path = sys.argv[1:]
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, password=password, timeout=15)
    sftp = c.open_sftp()
    with sftp.open(remote_path, "r") as f:
        content = f.read().decode()
    sftp.close()
    c.close()

    print(f"=== {remote_path} — keys + masked values ===")
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip().strip('"').strip("'")
        n = len(v)
        if n > 10:
            masked = f"{v[:4]}...{v[-3:]} ({n} chars)"
        else:
            masked = f"***({n})"
        print(f"  {k:30s} = {masked}")


if __name__ == "__main__":
    main()
