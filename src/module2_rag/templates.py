"""Attack scenario templates per vulnerability class.

Each template is a list of partial Action dicts. Values in ``{curly_braces}``
are substituted by :func:`instantiate_template` using ATG context (contract
node, default amount, attacker address, etc.).

Templates are modelled on real historical exploits:

* ``fake_deposit`` — Nomad-style zero-root bypass.
* ``replay`` / ``replay_attack`` — Multichain/Nomad replay double-mint.
* ``state_desync`` — revert-on-source-after-mint-on-destination (PolyNetwork-style).
* ``signature_forgery`` — Wormhole guardian bypass.
* ``key_compromise`` / ``unauthorized_mint`` — Ronin validator compromise.
* ``logic_bug`` — Qubit zero-value deposit.
* ``timeout_manipulation`` — HTLC expiry abuse.

The templates intentionally keep action counts ≤ 6 so the Rust fuzzer has a
manageable seed to mutate from.
"""

from __future__ import annotations

from typing import Any

ScenarioTemplate = list[dict[str, Any]]


FAKE_DEPOSIT_TEMPLATE: ScenarioTemplate = [
    {
        "step": 1,
        "chain": "destination",
        "contract": "{contract}",
        "function": "process",
        "params": {
            "message": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "description": "Submit forged message with zero merkle root (Nomad-style bypass)",
    },
    {
        "step": 2,
        "chain": "destination",
        "contract": "{contract}",
        "function": "handle",
        "params": {"amount": "{amount}", "recipient": "{attacker}"},
        "description": "Mint tokens against forged proof without legitimate source deposit",
    },
]


REPLAY_TEMPLATE: ScenarioTemplate = [
    {
        "step": 1,
        "chain": "source",
        "contract": "{contract}",
        "function": "dispatch",
        "params": {"amount": "{amount}", "nonce": "1"},
        "description": "Legitimate deposit on source chain",
    },
    {
        "step": 2,
        "chain": "relay",
        "action": "faithful",
        "params": {},
        "description": "Relay message to destination",
    },
    {
        "step": 3,
        "chain": "destination",
        "contract": "{contract}",
        "function": "proveAndProcess",
        "params": {},
        "description": "First process on destination (legitimate)",
    },
    {
        "step": 4,
        "chain": "relay",
        "action": "replay",
        "params": {"replay_index": 0},
        "description": "Replay same relay message",
    },
    {
        "step": 5,
        "chain": "destination",
        "contract": "{contract}",
        "function": "proveAndProcess",
        "params": {},
        "description": "Process replayed message (double mint)",
    },
]


STATE_DESYNC_TEMPLATE: ScenarioTemplate = [
    {
        "step": 1,
        "chain": "source",
        "contract": "{contract}",
        "function": "dispatch",
        "params": {"amount": "{amount}"},
        "description": "Legitimate deposit",
    },
    {
        "step": 2,
        "chain": "relay",
        "action": "faithful",
        "params": {},
        "description": "Relay message to destination",
    },
    {
        "step": 3,
        "chain": "destination",
        "contract": "{contract}",
        "function": "handle",
        "params": {"amount": "{amount}"},
        "description": "Mint on destination chain",
    },
    {
        "step": 4,
        "chain": "source",
        "contract": "{contract}",
        "function": "refund",
        "params": {"nonce": "1"},
        "description": "Refund on source AFTER mint succeeded (state desync)",
    },
]


SIGNATURE_FORGERY_TEMPLATE: ScenarioTemplate = [
    {
        "step": 1,
        "chain": "relay",
        "action": "tamper",
        "params": {"field": "signatures", "value": "0xforged"},
        "description": "Inject forged guardian/validator signatures (Wormhole-style)",
    },
    {
        "step": 2,
        "chain": "destination",
        "contract": "{contract}",
        "function": "verifyAndExecute",
        "params": {"amount": "{amount}"},
        "description": "Submit forged signature bundle to destination",
    },
]


KEY_COMPROMISE_TEMPLATE: ScenarioTemplate = [
    {
        "step": 1,
        "chain": "destination",
        "contract": "{contract}",
        "function": "executeWithdraw",
        "params": {
            "amount": "{amount}",
            "signatures": "{multisig_threshold_met}",
        },
        "description": "Use compromised validator keys to authorize withdrawal (Ronin-style)",
    },
]


LOGIC_BUG_TEMPLATE: ScenarioTemplate = [
    {
        "step": 1,
        "chain": "source",
        "contract": "{contract}",
        "function": "deposit",
        "params": {"amount": "0"},
        "description": "Trigger edge case: zero-value deposit (Qubit-style)",
    },
    {
        "step": 2,
        "chain": "destination",
        "contract": "{contract}",
        "function": "handle",
        "params": {"amount": "{large_amount}"},
        "description": "Exploit logic flaw to mint unrelated amount",
    },
]


TIMEOUT_TEMPLATE: ScenarioTemplate = [
    {
        "step": 1,
        "chain": "source",
        "contract": "{contract}",
        "function": "dispatch",
        "params": {"amount": "{amount}"},
        "description": "Legitimate deposit",
    },
    {
        "step": 2,
        "chain": "relay",
        "action": "delayed",
        "params": {"delta_blocks": 100},
        "description": "Delay relay past timeout boundary",
    },
    {
        "step": 3,
        "chain": "source",
        "contract": "{contract}",
        "function": "refund",
        "params": {"nonce": "1"},
        "description": "Claim refund while relay still pending (race)",
    },
    {
        "step": 4,
        "chain": "destination",
        "contract": "{contract}",
        "function": "proveAndProcess",
        "params": {},
        "description": "Late relay delivery mints despite refund (double spend)",
    },
]


TEMPLATES: dict[str, ScenarioTemplate] = {
    "fake_deposit": FAKE_DEPOSIT_TEMPLATE,
    "verification_bypass": FAKE_DEPOSIT_TEMPLATE,
    "replay": REPLAY_TEMPLATE,
    "replay_attack": REPLAY_TEMPLATE,
    "state_desync": STATE_DESYNC_TEMPLATE,
    "signature_forgery": SIGNATURE_FORGERY_TEMPLATE,
    "key_compromise": KEY_COMPROMISE_TEMPLATE,
    "unauthorized_mint": KEY_COMPROMISE_TEMPLATE,
    "unauthorized_access": KEY_COMPROMISE_TEMPLATE,
    "logic_bug": LOGIC_BUG_TEMPLATE,
    "oracle_manipulation": LOGIC_BUG_TEMPLATE,
    "timeout_manipulation": TIMEOUT_TEMPLATE,
}


DEFAULT_SUBSTITUTIONS: dict[str, str] = {
    "amount": "1000000000000000000",  # 1 ETH
    "large_amount": "1000000000000000000000",  # 1000 ETH
    "attacker": "0x000000000000000000000000000000000000dEaD",
    "multisig_threshold_met": "true",
}


def instantiate_template(
    template: ScenarioTemplate,
    contract: str,
    extra_subs: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Expand ``{placeholder}`` fields in a template with concrete values."""
    subs: dict[str, str] = {**DEFAULT_SUBSTITUTIONS, "contract": contract}
    if extra_subs:
        subs.update(extra_subs)

    result: list[dict[str, Any]] = []
    for action in template:
        new_action: dict[str, Any] = {}
        for key, value in action.items():
            if isinstance(value, str):
                new_action[key] = _format_safe(value, subs)
            elif isinstance(value, dict):
                new_action[key] = {
                    k: _format_safe(str(v), subs) for k, v in value.items()
                }
            else:
                new_action[key] = value
        result.append(new_action)
    return result


def get_template(vuln_class: str) -> ScenarioTemplate:
    """Look up a template by vulnerability class, defaulting to fake_deposit."""
    key = (vuln_class or "").lower().strip()
    return TEMPLATES.get(key, FAKE_DEPOSIT_TEMPLATE)


def _format_safe(text: str, subs: dict[str, str]) -> str:
    """Safe ``str.format`` that leaves unknown placeholders intact."""

    class _Default(dict):
        def __missing__(self, key: str) -> str:  # type: ignore[override]
            return "{" + key + "}"

    try:
        return text.format_map(_Default(**subs))
    except (KeyError, IndexError, ValueError):
        return text
