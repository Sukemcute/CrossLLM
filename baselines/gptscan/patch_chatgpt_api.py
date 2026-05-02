"""Patch GPTScan's chatgpt_api.py to use NVIDIA NIM via env vars.

Run AFTER cloning GPTScan/GPTScan into ~/baselines/gptscan/GPTScan-full/.

Sets:
- openai.api_base from OPENAI_API_BASE env (default OpenAI)
- model name from OPENAI_MODEL / OPENAI_MODEL_GPT4 env

This way GPTScan's hardcoded `gpt-3.5-turbo` / `gpt-4` calls become
configurable without forking the upstream code.
"""

from pathlib import Path
import sys

DEFAULT_PATH = Path.home() / "baselines/gptscan/GPTScan-full/src/chatgpt_api.py"

INJECT = """
# === BridgeSentry patch — redirect to NVIDIA NIM ===
import os as _os
openai.api_base = _os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
_GPTSCAN_MODEL = _os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo")
_GPTSCAN_MODEL_GPT4 = _os.environ.get("OPENAI_MODEL_GPT4", _GPTSCAN_MODEL)
# === end patch ===
"""


def patch(path: Path) -> None:
    text = path.read_text()
    if "OPENAI_API_BASE" not in text:
        text = text.replace("import openai\n", "import openai\n" + INJECT, 1)
    text = text.replace('model="gpt-3.5-turbo"', "model=_GPTSCAN_MODEL")
    text = text.replace('model="gpt-4"', "model=_GPTSCAN_MODEL_GPT4")
    path.write_text(text)
    print(f"patched: {path}")


if __name__ == "__main__":
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PATH
    if not p.exists():
        print(f"ERROR: {p} not found", file=sys.stderr)
        sys.exit(1)
    patch(p)
