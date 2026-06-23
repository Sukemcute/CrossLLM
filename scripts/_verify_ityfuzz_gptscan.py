"""One-off: verify ItyFuzz/GPTScan self-run results directly from raw logs on lab.

Usage: python scripts/_verify_ityfuzz_gptscan.py <host> <user> <password>
"""
import sys
import paramiko

BRIDGES = ["nomad", "qubit", "pgala", "polynetwork", "wormhole", "socket",
           "ronin", "harmony", "multichain", "orbit", "fegtoken", "gempad"]

DET_RE = "found vulnerability|oracle.*triggered|invariant violated|bug found"
ROOT = "~/sukem/CrossLLM/results/baselines"


def run(c, cmd):
    _, out, err = c.exec_command(cmd, timeout=60)
    return out.read().decode(errors="replace").rstrip(), err.read().decode(errors="replace").rstrip()


def main():
    host, user, password = sys.argv[1:4]
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=user, password=password, timeout=15)
    print(f"# connected to {user}@{host}\n")

    # Confirm dirs exist
    out, _ = run(c, f"ls -d {ROOT}/ityfuzz {ROOT}/gptscan 2>&1")
    print("dirs:", out, "\n")

    for tool in ("ityfuzz", "gptscan"):
        print(f"========== {tool.upper()} ==========")
        total_det = 0
        for b in BRIDGES:
            d = f"{ROOT}/{tool}/{b}"
            # number of run json files, number of detected=true, raw-log grep hits
            nfiles, _ = run(c, f"ls {d}/run_*.json 2>/dev/null | wc -l")
            ndet_json, _ = run(c, f"grep -l '\"detected\": true' {d}/run_*.json 2>/dev/null | wc -l")
            graw, _ = run(c, f"grep -liE '{DET_RE}' {d}/*.raw.txt 2>/dev/null | wc -l")
            # detect early-exit: smallest wall_clock & whether ABI/abi error present
            abi_err, _ = run(c, f"grep -hiE 'abi|deployment-script|please specify|error' {d}/run_001.raw.txt 2>/dev/null | head -1")
            det = "DETECT" if (ndet_json.strip() not in ("0", "") or graw.strip() not in ("0", "")) else "none"
            if det == "DETECT":
                total_det += 1
            print(f"  {b:12s} json_runs={nfiles:>3} detected_json={ndet_json:>3} rawlog_hits={graw:>3}  -> {det}"
                  + (f"   [run_001 note: {abi_err[:70]}]" if abi_err else ""))
        print(f"  >>> {tool}: {total_det}/12 bridges with any detection signal\n")

    # Spot-check tails of the 4 suspected early-exit ityfuzz bridges
    print("========== ItyFuzz early-exit spot-check (tail of run_001.raw.txt) ==========")
    for b in ("qubit", "ronin", "fegtoken", "gempad"):
        out, _ = run(c, f"tail -4 {ROOT}/ityfuzz/{b}/run_001.raw.txt 2>&1")
        print(f"--- {b} ---\n{out}\n")

    c.close()


if __name__ == "__main__":
    main()
