# Plan Cải thiện Module 1 + 2 + Orchestrator (Member A)

> Tài liệu chi tiết từng bước cải thiện, dựa trên review so với paper BridgeSentry và các source reference (GPTScan, Slither, SmartAxe, Connector).

## Tổng quan

**Mục tiêu:** Đưa implementation Member A sát hơn với yêu cầu paper, giảm gap với baseline tools, tăng độ chính xác của pipeline.

**Chia thành 3 sprint:**

| Sprint | Thời gian | Nội dung | Blocker cho |
|--------|-----------|----------|-------------|
| **Sprint 1 — Critical LLM gaps** | 3-5 ngày | Fix `invariant_synth.py`, system prompts, scenario templates | Phase 3 (integration) |
| **Sprint 2 — Quality & Data** | 4-6 ngày | Slither parser, retry logic, knowledge base expansion, caching | Phase 4 (benchmarks) |
| **Sprint 3 — Polish** | 2-3 ngày | Schema validation, progress bar, hybrid search | Phase 5 (experiments) |

**Tổng:** ~2 tuần làm việc part-time, có thể rút xuống 1 tuần nếu làm full-time.

---

## SPRINT 1 — Critical LLM Gaps

### Task 1.1: `invariant_synth.py` dùng LLM thật (QUAN TRỌNG NHẤT)

**Vấn đề hiện tại:** Hardcode 4 invariants giống nhau cho mọi bridge → không match paper claim "18.3 candidates, 12.1 final, 89.3% precision".

**Deliverable:** LLM sinh invariants contextualize theo ATG cụ thể, pipeline 3-stage validation.

**Code changes:**

File: `src/module1_semantic/invariant_synth.py`

```python
from __future__ import annotations

import json
import os
from typing import Any

SYSTEM_PROMPT = """You are a formal verification expert specializing in cross-chain blockchain bridges.
Your task is to analyze the protocol structure encoded in an Atomic Transfer Graph (ATG)
and derive protocol invariants that must hold for the bridge to behave correctly.

You understand:
- Cross-chain asset flows (lock on source, mint on destination)
- Relay message authentication
- Timeout and refund mechanics
- Nonce-based replay protection
- Cryptographic primitives (hashlocks, timelocks, signatures)

Output concrete, verifiable invariants with Solidity assertions, not abstract descriptions."""


USER_PROMPT_TEMPLATE = """Analyze this bridge ATG and generate 15-20 protocol invariants.

ATG:
```json
{atg_json}
```

Generate invariants across 4 categories:
1. **asset_conservation** — balance preservation across chains (locked == minted - fees)
2. **authorization** — mint/unlock requires valid deposit + relay verification (causal order)
3. **uniqueness** — each nonce/message consumed at most once (replay protection)
4. **timeliness** — locked assets refundable after timeout expiry

For each invariant, provide:
- `invariant_id`: unique snake_case identifier (e.g., "inv_lock_mint_balance")
- `category`: one of [asset_conservation, authorization, uniqueness, timeliness]
- `description`: plain English explanation
- `predicate`: formal logical expression (e.g., "forall m in mints: exists d in deposits: d.nonce == m.nonce")
- `solidity_assertion`: executable require/assert statement targeting contract state
- `related_edges`: list of ATG edge_ids this invariant depends on (subset of actual edges)

Return JSON: {{"invariants": [...]}}"""


class InvariantSynthesizer:
    def __init__(self, model: str = "gpt-4o-mini", temperature: float = 0.0):
        self.model = model
        self.temperature = temperature
        self._cache_dir = None  # Set later when caching added

    def synthesize(self, atg: dict) -> list[dict]:
        """3-stage pipeline: generate → trace-filter → consistency-check."""
        candidates = self._llm_generate_candidates(atg)
        if not candidates:
            return self._fallback_invariants(atg)

        filtered = self._filter_with_traces(candidates, atg, normal_traces=[])
        consistent = self._cross_check_consistency(filtered)
        return consistent

    def _llm_generate_candidates(self, atg: dict) -> list[dict]:
        """Stage 1: LLM generates 15-20 candidate invariants."""
        provider = _resolve_provider()
        if not provider:
            return []

        client, model = provider
        prompt = USER_PROMPT_TEMPLATE.format(atg_json=json.dumps(atg, ensure_ascii=False, indent=2)[:8000])

        try:
            resp = client.chat.completions.create(
                model=model,
                temperature=self.temperature,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )
            content = resp.choices[0].message.content or "{}"
            data = json.loads(content)
            invariants = data.get("invariants", [])
            if isinstance(invariants, list):
                # Validate required fields
                valid = [inv for inv in invariants if self._is_well_formed(inv)]
                return valid
        except Exception as e:
            print(f"[InvariantSynth] LLM call failed: {e}")
            return []

        return []

    def _is_well_formed(self, inv: dict) -> bool:
        required = {"invariant_id", "category", "description", "predicate", "solidity_assertion"}
        return required.issubset(inv.keys())

    def _filter_with_traces(self, candidates: list[dict], atg: dict, normal_traces: list) -> list[dict]:
        """Stage 2: Drop invariants that would flag legitimate behavior."""
        if not normal_traces:
            # No traces to filter against → return all (but log warning)
            return candidates

        filtered = []
        for inv in candidates:
            if not any(self._trace_violates(inv, tr) for tr in normal_traces):
                filtered.append(inv)
        return filtered

    def _trace_violates(self, invariant: dict, trace: dict) -> bool:
        # Check if trace marks this invariant as expected-false
        return invariant.get("invariant_id") in trace.get("expected_false_invariants", [])

    def _cross_check_consistency(self, invariants: list[dict]) -> list[dict]:
        """Stage 3: Remove pairwise-contradictory invariants.

        Lightweight version: detect duplicates by predicate text similarity.
        Full version (future): LLM batch-check contradictions.
        """
        seen_predicates = set()
        unique = []
        for inv in invariants:
            pred_key = inv.get("predicate", "").lower().replace(" ", "")
            if pred_key and pred_key not in seen_predicates:
                seen_predicates.add(pred_key)
                unique.append(inv)
        return unique

    def _fallback_invariants(self, atg: dict) -> list[dict]:
        """Deterministic fallback when LLM unavailable."""
        edges = atg.get("edges", [])
        edge_ids = [e.get("edge_id", "") for e in edges]
        return [
            {
                "invariant_id": "inv_asset_conservation",
                "category": "asset_conservation",
                "description": "Locked value minus fees equals minted/unlocked value.",
                "predicate": "sum(locked) - fee == sum(minted_or_unlocked)",
                "solidity_assertion": "assert(totalLocked() >= totalMinted());",
                "related_edges": edge_ids,
            },
            {
                "invariant_id": "inv_authorization",
                "category": "authorization",
                "description": "Mint requires valid prior lock and verified relay message.",
                "predicate": "mint -> exists(valid_lock && verified_relay)",
                "solidity_assertion": "require(isVerified(msgHash) && lockExists(nonce));",
                "related_edges": edge_ids,
            },
            {
                "invariant_id": "inv_uniqueness",
                "category": "uniqueness",
                "description": "Each deposit nonce consumed at most once.",
                "predicate": "forall n: processed[n] == false before consume",
                "solidity_assertion": "require(!processed[nonce]);",
                "related_edges": edge_ids,
            },
            {
                "invariant_id": "inv_timeliness",
                "category": "timeliness",
                "description": "Locks become refundable after timeout.",
                "predicate": "expired(lock) && !finalized -> refundable",
                "solidity_assertion": "require(block.timestamp < lockTime + timeout);",
                "related_edges": edge_ids,
            },
        ]

    def validate(self, invariants: list[dict], normal_traces: list) -> list[dict]:
        """Public API kept for orchestrator compatibility."""
        return self._filter_with_traces(invariants, {}, normal_traces)

    def compile_to_solidity(self, invariant: dict) -> str:
        assertion = invariant.get("solidity_assertion", "").strip()
        if assertion:
            return assertion
        predicate = invariant.get("predicate", "true")
        return f"assert({predicate});"


def _resolve_provider():
    """Return (client, model) tuple or None, supporting both OpenAI and NVIDIA NIM."""
    try:
        from openai import OpenAI
    except ImportError:
        return None

    # Prefer NVIDIA NIM for free dev testing
    nvidia_key = os.getenv("NVIDIA_API_KEY")
    if nvidia_key:
        base_url = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
        model = os.getenv("NVIDIA_MODEL", "meta/llama-3.3-70b-instruct")
        return OpenAI(api_key=nvidia_key, base_url=base_url), model

    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        return OpenAI(api_key=openai_key), model

    return None
```

**Tests cần thêm:**

File: `tests/test_module1_semantic.py` — thêm:
```python
def test_invariant_synth_fallback_without_api():
    # Ensure no NVIDIA_API_KEY or OPENAI_API_KEY
    import os
    for k in ("NVIDIA_API_KEY", "OPENAI_API_KEY"):
        os.environ.pop(k, None)

    synth = InvariantSynthesizer()
    atg = {"bridge_name": "test", "nodes": [], "edges": [
        {"edge_id": "e1", "label": "lock", "src": "u", "dst": "b"},
        {"edge_id": "e2", "label": "mint", "src": "b", "dst": "u"},
    ]}
    invariants = synth.synthesize(atg)
    categories = {inv["category"] for inv in invariants}
    assert {"asset_conservation", "authorization", "uniqueness", "timeliness"}.issubset(categories)


def test_invariant_synth_validation_filters_contradictions():
    synth = InvariantSynthesizer()
    invariants = [
        {"invariant_id": "a", "predicate": "x > 0", "category": "asset_conservation", 
         "description": "", "solidity_assertion": ""},
        {"invariant_id": "b", "predicate": "x > 0", "category": "asset_conservation",
         "description": "", "solidity_assertion": ""},  # duplicate
    ]
    result = synth._cross_check_consistency(invariants)
    assert len(result) == 1
```

**Acceptance:**
- Test `test_invariant_synth_fallback_without_api` pass
- Chạy orchestrator với NVIDIA_API_KEY → invariants có >= 8 entries, categories đa dạng
- Khi không có API key → fallback 4 invariants như cũ

**Ước tính:** 4-6 giờ

---

### Task 1.2: Scenario templates theo vulnerability class

**Vấn đề:** Fallback luôn là `deposit → tamper → process` bất kể vuln class.

**Deliverable:** 5 templates riêng cho 5 vuln classes, fallback pick template đúng.

**Code changes:**

File mới: `src/module2_rag/templates.py`
```python
"""Attack scenario templates per vulnerability class.

Each template is a list of partial Action dicts. Values in {curly_braces}
are substituted by _fallback_scenario() based on ATG context.
"""

from typing import Any

ScenarioTemplate = list[dict[str, Any]]

FAKE_DEPOSIT_TEMPLATE: ScenarioTemplate = [
    {
        "step": 1,
        "chain": "destination",
        "contract": "{contract}",
        "function": "process",
        "params": {"message": "0x0000000000000000000000000000000000000000000000000000000000000000"},
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
        "description": "Relay",
    },
    {
        "step": 3,
        "chain": "destination",
        "contract": "{contract}",
        "function": "handle",
        "params": {"amount": "{amount}"},
        "description": "Mint on destination",
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
        "params": {"amount": "{amount}", "signatures": "{multisig_threshold_met}"},
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

TEMPLATES: dict[str, ScenarioTemplate] = {
    "fake_deposit": FAKE_DEPOSIT_TEMPLATE,
    "replay": REPLAY_TEMPLATE,
    "replay_attack": REPLAY_TEMPLATE,
    "state_desync": STATE_DESYNC_TEMPLATE,
    "signature_forgery": SIGNATURE_FORGERY_TEMPLATE,
    "key_compromise": KEY_COMPROMISE_TEMPLATE,
    "unauthorized_mint": KEY_COMPROMISE_TEMPLATE,
    "logic_bug": LOGIC_BUG_TEMPLATE,
}

DEFAULT_SUBSTITUTIONS = {
    "amount": "1000000000000000000",  # 1 ETH
    "large_amount": "1000000000000000000000",  # 1000 ETH
    "attacker": "0x000000000000000000000000000000000000dEaD",
    "multisig_threshold_met": "true",
}


def instantiate_template(
    template: ScenarioTemplate,
    contract: str,
    extra_subs: dict[str, str] | None = None,
) -> list[dict]:
    """Expand template placeholders with concrete values."""
    subs = {**DEFAULT_SUBSTITUTIONS, "contract": contract}
    if extra_subs:
        subs.update(extra_subs)

    result = []
    for action in template:
        new_action = {}
        for key, value in action.items():
            if isinstance(value, str):
                new_action[key] = _format_safe(value, subs)
            elif isinstance(value, dict):
                new_action[key] = {k: _format_safe(str(v), subs) for k, v in value.items()}
            else:
                new_action[key] = value
        result.append(new_action)
    return result


def _format_safe(text: str, subs: dict[str, str]) -> str:
    try:
        return text.format(**subs)
    except (KeyError, IndexError):
        return text
```

File: `src/module2_rag/scenario_gen.py` — thay `_fallback_scenario`:
```python
from .templates import TEMPLATES, instantiate_template

def _fallback_scenario(self, idx, invariant, retrieved, contract, bridge_name):
    vuln_class = self._class_from_invariant(invariant)
    template = TEMPLATES.get(vuln_class, TEMPLATES["fake_deposit"])
    actions = instantiate_template(template, contract=contract)
    retrieved_ids = [e.get("exploit_id", "") for e in retrieved if e.get("exploit_id")]

    return {
        "scenario_id": f"s{idx}_{vuln_class}",
        "target_invariant": invariant.get("invariant_id", "inv_unknown"),
        "vulnerability_class": vuln_class,
        "confidence": 0.65 if retrieved_ids else 0.45,
        "actions": actions,
        "retrieved_exploits": retrieved_ids,
    }
```

**Tests:**
```python
def test_fallback_templates_differ_by_vuln_class():
    gen = AttackScenarioGenerator()
    atg = {"bridge_name": "test", "nodes": [{"node_id": "bridge", "node_type": "contract", 
                                              "chain": "source", "address": "", "functions": []}], "edges": []}
    
    # Replay invariant → replay template (5 steps)
    replay_inv = {"invariant_id": "inv_u", "category": "uniqueness", ...}
    s1 = gen._fallback_scenario(1, replay_inv, [], "bridge", "test")
    assert len(s1["actions"]) == 5
    assert any(a.get("action") == "replay" for a in s1["actions"])
    
    # Conservation invariant → fake_deposit template (2 steps)
    conservation_inv = {"invariant_id": "inv_c", "category": "asset_conservation", ...}
    s2 = gen._fallback_scenario(2, conservation_inv, [], "bridge", "test")
    assert len(s2["actions"]) == 2
    assert "0x00" in s2["actions"][0]["params"].get("message", "")
```

**Ước tính:** 3-4 giờ

---

### Task 1.3: System prompts cho toàn bộ LLM calls

**Vấn đề:** `extractor.py` và `scenario_gen.py` không dùng system message, temperature khác nhau.

**Deliverable:** File `prompts/` có các file template, mọi LLM call dùng system prompt nhất quán.

**Code changes:**

File mới: `src/module1_semantic/prompts/system_auditor.txt`
```
You are a smart contract security auditor specializing in cross-chain bridges.

Your tasks involve:
1. Parsing Solidity bridge contracts to identify entities, functions, and asset flows
2. Recognizing bridge-specific patterns: lock/unlock/mint/burn, relay verification, message passing
3. Identifying guards: access control, signature verification, timelock, nonce validation

Guidelines:
- Be precise: distinguish between router contracts, token contracts, and relay components
- Follow schema strictly: return JSON matching the requested structure exactly
- Mark uncertain classifications with confidence < 0.5 rather than guessing
- Do not invent functions or entities not present in the source code
```

File mới: `src/module2_rag/prompts/system_adversary.txt`
```
You are a rational adversary analyzing cross-chain bridge protocols for economically
motivated attack vectors.

Your perspective:
- You have full knowledge of historical bridge exploits (Nomad, Ronin, Wormhole, PolyNetwork)
- You understand MEV, front-running, and game-theoretic incentives (He-HTLC style)
- You generate concrete attack sequences, not abstract descriptions
- You favor attacks with highest expected value and lowest detection risk

Output requirements:
- Action sequences must be executable on an EVM fuzzer
- Each step specifies: chain, contract, function, parameters
- Include relay manipulation (faithful/delayed/tampered/replay) where applicable
- Provide waypoints as verifiable state predicates, not narrative
```

File mới: `src/module1_semantic/prompts/__init__.py`
```python
from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent


def load(name: str) -> str:
    path = _PROMPTS_DIR / name
    if not path.suffix:
        path = path.with_suffix(".txt")
    return path.read_text(encoding="utf-8").strip()
```

File mới: `src/module2_rag/prompts/__init__.py` (tương tự)

**Refactor extractor.py:**
```python
from .prompts import load as load_prompt

def _try_llm_extract(self, source_code, contract_name):
    provider = _resolve_provider()  # Moved to shared util
    if not provider:
        return None
    client, model = provider

    system = load_prompt("system_auditor.txt")
    user = f"""Extract bridge semantics from this Solidity contract.

Contract name: {contract_name}

Source:
```solidity
{source_code[:12000]}
```

Return JSON with exactly these keys:
- entities: [{{entity_id, entity_type, chain, address, roles}}]
- functions: [{{name, signature, parameters, mutability, visibility, role}}]
- asset_flows: [{{src, dst, label, token, function_signature, conditions}}]
- guards: [string]"""

    try:
        res = client.chat.completions.create(
            model=model,
            temperature=0.0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return json.loads(res.choices[0].message.content or "{}")
    except Exception:
        return None
```

**Refactor scenario_gen.py:** tương tự, dùng `system_adversary.txt`, temperature=0.3 (đúng paper).

**Ước tính:** 2 giờ

---

### Task 1.4: Shared LLM provider utility

**Vấn đề:** Mỗi file tự resolve OpenAI/NVIDIA key, code duplicate.

**Deliverable:** Single function `get_llm_client()` dùng chung.

**Code changes:**

File mới: `src/common/llm_client.py`
```python
"""Unified LLM client resolution supporting both OpenAI and NVIDIA NIM."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


@dataclass
class LLMProvider:
    client: Any
    model: str
    provider_name: str


def get_llm_client(prefer: str = "auto") -> LLMProvider | None:
    """Resolve LLM provider from environment.

    prefer: "nvidia" | "openai" | "auto"
    - "auto": NVIDIA first (free for dev), fall back to OpenAI
    """
    try:
        from openai import OpenAI
    except ImportError:
        return None

    providers = []

    nvidia_key = os.getenv("NVIDIA_API_KEY")
    if nvidia_key and not nvidia_key.startswith("nvapi-YOUR"):
        providers.append(("nvidia", OpenAI(
            api_key=nvidia_key,
            base_url=os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"),
        ), os.getenv("NVIDIA_MODEL", "meta/llama-3.3-70b-instruct")))

    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key and openai_key.startswith("sk-"):
        providers.append(("openai", OpenAI(api_key=openai_key), 
                         os.getenv("OPENAI_MODEL", "gpt-4o-mini")))

    if not providers:
        return None

    if prefer == "nvidia":
        providers.sort(key=lambda p: 0 if p[0] == "nvidia" else 1)
    elif prefer == "openai":
        providers.sort(key=lambda p: 0 if p[0] == "openai" else 1)

    name, client, model = providers[0]
    return LLMProvider(client=client, model=model, provider_name=name)
```

File `src/common/__init__.py` (empty).

**Replace trong 3 files:** `extractor.py`, `invariant_synth.py`, `scenario_gen.py`:
```python
from src.common.llm_client import get_llm_client

provider = get_llm_client()
if not provider:
    return None  # or fallback
# Use provider.client, provider.model
```

**Ước tính:** 1 giờ

---

## SPRINT 2 — Quality & Data

### Task 2.1: Retry logic với exponential backoff

**Deliverable:** Decorator/helper cho tất cả LLM calls, retry 3 lần khi rate limit / transient errors.

File: `src/common/llm_client.py` — thêm:
```python
import time
from functools import wraps


def with_retry(max_retries: int = 3, base_delay: float = 2.0):
    """Retry decorator for LLM API calls."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    err_name = type(e).__name__
                    last_error = e
                    if err_name == "RateLimitError":
                        delay = 30 * (2 ** attempt)
                    elif err_name in ("APIConnectionError", "APITimeoutError", "APIError"):
                        delay = base_delay * (2 ** attempt)
                    else:
                        # Non-retryable
                        raise
                    if attempt < max_retries - 1:
                        print(f"[LLM] {err_name}, retry in {delay}s...")
                        time.sleep(delay)
            if last_error:
                raise last_error
        return wrapper
    return decorator
```

**Sử dụng:**
```python
@with_retry(max_retries=3)
def _call_llm(self, system, user):
    return self.client.chat.completions.create(...)
```

**Ước tính:** 1 giờ

---

### Task 2.2: LLM response caching

**Deliverable:** Mọi LLM call cached theo hash của prompt → không trả phí khi dev lặp.

File: `src/common/llm_cache.py`
```python
"""File-based LLM response cache to avoid redundant API calls during development."""

import hashlib
import json
from pathlib import Path
from typing import Any


class LLMCache:
    def __init__(self, cache_dir: str = ".llm_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

    def _key(self, model: str, system: str, user: str) -> str:
        content = f"{model}\n---\n{system}\n---\n{user}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    def get(self, model: str, system: str, user: str) -> str | None:
        key = self._key(model, system, user)
        path = self.cache_dir / f"{key}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data.get("response")
        except Exception:
            return None

    def put(self, model: str, system: str, user: str, response: str) -> None:
        key = self._key(model, system, user)
        path = self.cache_dir / f"{key}.json"
        payload = {
            "model": model,
            "system_hash": hashlib.md5(system.encode()).hexdigest()[:8],
            "user_preview": user[:200],
            "response": response,
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


# Global singleton
_cache = LLMCache()


def cached_chat_completion(client, model: str, system: str, user: str, **kwargs) -> str:
    cached = _cache.get(model, system, user)
    if cached is not None:
        return cached

    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        **kwargs,
    )
    content = resp.choices[0].message.content or ""
    _cache.put(model, system, user, content)
    return content
```

**Thêm vào `.gitignore`:** `.llm_cache/`

**Sử dụng trong 3 modules:**
```python
from src.common.llm_cache import cached_chat_completion

content = cached_chat_completion(
    provider.client, provider.model,
    system=load_prompt("system_auditor.txt"),
    user=user_prompt,
    temperature=0.0,
    response_format={"type": "json_object"},
)
data = json.loads(content)
```

**Ước tính:** 2 giờ

---

### Task 2.3: Extractor dùng Slither

**Vấn đề:** Regex fail với complex Solidity (comments, nested contracts, multiline).

**Deliverable:** Slither-based parser làm primary, regex là fallback.

**Dependency:**
```bash
pip install slither-analyzer
# hoặc thêm vào requirements.txt: slither-analyzer>=0.10.0
```

**Code changes:**

File mới: `src/module1_semantic/slither_parser.py`
```python
"""Slither-based Solidity parser for extracting semantic information.

Falls back gracefully when slither fails to compile the contract.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def parse_with_slither(file_path: str) -> dict[str, Any] | None:
    """Extract entities, functions, guards using Slither's IR.

    Returns None on failure (caller should fall back to regex parser).
    """
    try:
        from slither.slither import Slither
    except ImportError:
        return None

    try:
        sl = Slither(file_path)
    except Exception as e:
        print(f"[Slither] Failed to compile {file_path}: {e}")
        return None

    entities = []
    functions = []
    asset_flows = []
    guards = set()

    for contract in sl.contracts:
        if contract.is_interface or _is_test_contract(contract):
            continue

        entities.append({
            "entity_id": contract.name.lower(),
            "entity_type": "contract",
            "chain": _guess_chain(contract.name),
            "address": "",
            "roles": _guess_roles(contract),
        })

        for func in contract.functions:
            if func.visibility in ("internal", "private") and not func.is_reachable_from_external:
                continue
            if func.is_constructor:
                continue

            params = [str(p.type) for p in func.parameters]
            functions.append({
                "name": func.name,
                "signature": f"{func.name}({','.join(params)})",
                "parameters": params,
                "mutability": "view" if func.view else ("pure" if func.pure else "nonpayable"),
                "visibility": func.visibility,
                "role": _classify_role(func.name),
            })

            # Guards from require/assert in function body
            for node in func.nodes:
                if node.type.name in ("IF", "THROW"):
                    for ir in node.irs:
                        if hasattr(ir, "arguments") and ir.arguments:
                            guards.add(str(ir.arguments[0])[:200])

            # Asset flows
            role = _classify_role(func.name)
            if role in ("deposit", "withdraw", "mint", "burn", "relay"):
                flow = _infer_flow(role)
                if flow:
                    flow["function_signature"] = f"{func.name}({','.join(params)})"
                    asset_flows.append(flow)

    return {
        "entities": entities,
        "functions": functions,
        "asset_flows": asset_flows,
        "guards": list(guards)[:50],
    }


def _is_test_contract(contract) -> bool:
    name = contract.name.lower()
    return any(x in name for x in ("test", "mock", "fake"))


def _guess_chain(name: str) -> str:
    n = name.lower()
    if any(x in n for x in ("dest", "target", "mint", "wrap")):
        return "destination"
    return "source"


def _guess_roles(contract) -> list[str]:
    name = contract.name.lower()
    roles = []
    if any(x in name for x in ("router", "bridge")):
        roles.append("router_contract")
    if any(x in name for x in ("token", "erc20", "erc721")):
        roles.append("token_contract")
    if "replica" in name:
        roles.append("message_receiver")
    if "home" in name or "outbox" in name:
        roles.append("message_sender")
    return roles or ["support_contract"]


def _classify_role(fn_name: str) -> str:
    n = fn_name.lower()
    if any(x in n for x in ("deposit", "lock", "send")):
        return "deposit"
    if any(x in n for x in ("withdraw", "release", "unlock")):
        return "withdraw"
    if "mint" in n:
        return "mint"
    if "burn" in n:
        return "burn"
    if any(x in n for x in ("relay", "process", "handle", "dispatch")):
        return "relay"
    if any(x in n for x in ("admin", "owner", "pause", "upgrade")):
        return "admin"
    return "other"


def _infer_flow(role: str) -> dict | None:
    mapping = {
        "deposit": {"src": "user", "dst": "bridge", "label": "lock"},
        "withdraw": {"src": "bridge", "dst": "user", "label": "unlock"},
        "mint": {"src": "bridge", "dst": "user", "label": "mint"},
        "burn": {"src": "user", "dst": "bridge", "label": "burn"},
        "relay": {"src": "relay", "dst": "bridge", "label": "verify"},
    }
    flow = mapping.get(role)
    if flow:
        flow = {**flow, "token": "UNKNOWN", "conditions": []}
    return flow
```

**Refactor `extractor.py`:**
```python
from .slither_parser import parse_with_slither

def extract_from_file(self, file_path: str) -> dict:
    # Try Slither first
    slither_result = parse_with_slither(file_path)
    if slither_result:
        # Enrich with LLM if available
        llm_payload = self._try_llm_extract(Path(file_path).read_text(), Path(file_path).stem)
        if llm_payload:
            # Merge: prefer Slither structure, LLM guards
            slither_result["guards"] = llm_payload.get("guards", slither_result["guards"])
        return {
            "contract_name": Path(file_path).stem,
            **slither_result,
            "metadata": {"parser": "slither", "llm_used": bool(llm_payload)},
        }

    # Fallback to regex
    return self._extract_regex_fallback(file_path)
```

**Tests:**
```python
def test_slither_parser_on_nomad_contract():
    slither_out = parse_with_slither("benchmarks/nomad/contracts/Message.sol")
    if slither_out is None:
        pytest.skip("Slither not installed or compilation failed")
    assert len(slither_out["functions"]) > 0
    roles = {f.get("role") for f in slither_out["functions"]}
    # Message.sol should have relay-like functions
    assert roles & {"relay", "other"}
```

**Ước tính:** 4-5 giờ (bao gồm debug Slither compile issues với Solidity versions)

---

### Task 2.4: Expand knowledge base — 51 exploit records

**Deliverable:** Script tự sinh JSON records từ references, kèm 31 records minimum.

**Code changes:**

File mới: `scripts/build_exploit_kb.py`
```python
"""Build exploit knowledge base from reference datasets.

Sources:
1. references/FSE24-SmartAxe/20 CCV attack list.xlsx  (19 records)
2. references/Cross-Chain-Attacks/README.md          (12 records)
3. scripts/extra_exploits.yaml                        (manual additions)
"""

import json
import re
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    pd = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent
KB_DIR = PROJECT_ROOT / "src" / "module2_rag" / "data"
REFS = PROJECT_ROOT.parent / "references"  # ../references

VULN_CLASS_MAP = {
    "verification_bypass": "fake_deposit",
    "fake_deposit": "fake_deposit",
    "replay": "replay",
    "replay_attack": "replay",
    "key_compromise": "key_compromise",
    "unauthorized_access": "key_compromise",
    "state_desync": "state_desync",
    "signature_forgery": "signature_forgery",
    "logic_bug": "logic_bug",
    "oracle_manipulation": "oracle_manipulation",
}

ATTACK_STAGE_MAP = {
    0: "not_attack",
    1: "source_chain",
    2: "destination_chain",
    3: "off_chain",
}


def extract_from_smartaxe() -> list[dict]:
    """Extract records from SmartAxe Excel + manual dataset."""
    if pd is None:
        print("pandas not installed, skipping SmartAxe")
        return []

    records = []
    xlsx = REFS / "FSE24-SmartAxe" / "20 CCV attack list.xlsx"
    if not xlsx.exists():
        print(f"Not found: {xlsx}")
        return []

    try:
        df = pd.read_excel(xlsx)
    except Exception as e:
        print(f"Failed to read {xlsx}: {e}")
        return []

    for idx, row in df.iterrows():
        bridge = str(row.get("Bridge", row.get("Name", f"unknown_{idx}"))).strip()
        if not bridge or bridge.lower() == "nan":
            continue

        record = {
            "exploit_id": f"{_slugify(bridge)}_{row.get('Date', idx)}",
            "bridge": bridge,
            "date": str(row.get("Date", "")),
            "loss_usd": _parse_loss(row.get("Loss", 0)),
            "chains": _parse_chains(row.get("Chains", "")),
            "vulnerability_class": VULN_CLASS_MAP.get(
                str(row.get("Class", "")).lower(), "logic_bug"
            ),
            "attack_stage": ATTACK_STAGE_MAP.get(int(row.get("Stage", 1) or 1), "source_chain"),
            "attack_trace": [str(row.get("Description", ""))],
            "root_cause": str(row.get("Root Cause", "")),
            "summary": str(row.get("Summary", ""))[:500],
            "source": "smartaxe_fse24",
        }
        records.append(record)

    return records


def extract_from_xscope() -> list[dict]:
    """Parse Cross-Chain-Attacks README for 12 documented attacks."""
    readme = REFS / "Cross-Chain-Attacks" / "README.md"
    if not readme.exists():
        print(f"Not found: {readme}")
        return []

    content = readme.read_text(encoding="utf-8")
    records = []

    # Simple pattern: bold bridge name followed by description
    pattern = re.compile(r"\*\*([^*]+)\*\*.*?(?:\n([^\n]+))?", re.DOTALL)
    for match in pattern.finditer(content):
        bridge = match.group(1).strip()
        desc = (match.group(2) or "").strip()

        if len(bridge) > 50 or not desc:
            continue

        record = {
            "exploit_id": f"{_slugify(bridge)}_xscope",
            "bridge": bridge,
            "vulnerability_class": _guess_class_from_desc(desc),
            "attack_stage": "off_chain" if "off" in desc.lower() else "destination_chain",
            "summary": desc[:500],
            "attack_trace": [desc],
            "source": "xscope_ase22",
        }
        records.append(record)

    return records


def _slugify(s: str) -> str:
    return re.sub(r"\W+", "_", s.strip().lower())


def _parse_loss(val) -> int:
    try:
        s = str(val).replace("$", "").replace("M", "000000").replace(",", "")
        return int(float(s))
    except (ValueError, TypeError):
        return 0


def _parse_chains(val) -> list[str]:
    if not val:
        return []
    return [c.strip() for c in str(val).split(",")]


def _guess_class_from_desc(desc: str) -> str:
    d = desc.lower()
    if "replay" in d:
        return "replay"
    if "signature" in d or "forge" in d:
        return "signature_forgery"
    if "validator" in d or "key" in d:
        return "key_compromise"
    if "parse" in d or "logic" in d:
        return "logic_bug"
    return "fake_deposit"


def write_records(records: list[dict]) -> int:
    KB_DIR.mkdir(parents=True, exist_ok=True)
    written = 0
    for rec in records:
        if not rec.get("exploit_id"):
            continue
        path = KB_DIR / f"{rec['exploit_id']}.json"
        path.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
        written += 1
    return written


if __name__ == "__main__":
    all_records = []
    all_records.extend(extract_from_smartaxe())
    all_records.extend(extract_from_xscope())

    # Dedupe by exploit_id
    seen = {}
    for rec in all_records:
        seen.setdefault(rec["exploit_id"], rec)

    count = write_records(list(seen.values()))
    print(f"Wrote {count} exploit records to {KB_DIR}")
```

**Chạy:**
```bash
cd ~/CrossLLM
python scripts/build_exploit_kb.py
ls src/module2_rag/data/ | wc -l  # Should be 20-30+
```

**Thêm manual records trong `scripts/extra_exploits.yaml`** (nếu cần thêm 20 nữa cho đủ 51).

**Ước tính:** 3-4 giờ (bao gồm debug Excel parsing)

---

### Task 2.5: State-based waypoint extraction

**Vấn đề hiện tại:** Waypoint chỉ ghi "called_process" - không đủ để Rust checker verify.

**Deliverable:** Waypoint có Solidity-like state predicates khớp với `scenario_sim.rs`.

**Code changes:**

File: `src/module2_rag/scenario_gen.py` — replace `_extract_waypoints`:
```python
def _extract_waypoints(self, scenario: dict) -> list[dict]:
    """Extract state-predicate waypoints that scenario_sim.rs can evaluate."""
    waypoints = []
    actions = scenario.get("actions", [])
    cumulative_amount = 0

    for i, action in enumerate(actions, start=1):
        step = action.get("step", i)
        chain = action.get("chain", "")
        function = action.get("function", "")
        act = action.get("action", "")
        params = action.get("params", {})

        predicate = None
        description = action.get("description", f"After step {step}")

        # Source chain deposits
        if chain == "source" and function in ("dispatch", "deposit", "lock", "send"):
            amt_str = str(params.get("amount", "0"))
            try:
                amt = int(amt_str)
                cumulative_amount += amt
                predicate = f"sourceRouter.totalLocked() >= {cumulative_amount}"
            except ValueError:
                predicate = "sourceRouter.saw_dispatch == true"

        # Destination chain mints
        elif chain == "destination" and function in ("mint", "handle", "release"):
            predicate = f"destRouter.totalMinted() >= {cumulative_amount or 1000000000000000000}"

        # Process with zero root (Nomad-style)
        elif chain == "destination" and function in ("process", "proveAndProcess"):
            msg = str(params.get("message", ""))
            if msg and set(msg.strip("0x")) <= {"0"}:
                predicate = "replica.zero_root_accepted == true"
            else:
                predicate = "replica.processedMessages(messageHash) == true"

        # Relay manipulation
        elif chain == "relay":
            if act in ("replay", "replayed"):
                predicate = "relay.message_count > sourceRouter.deposits_count"
            elif act in ("tamper", "tampered"):
                predicate = "relay.pendingMessage.amount != sourceRouter.deposits(nonce).amount"
            elif act in ("delay", "delayed"):
                predicate = f"relay.delayed_count > 0"
            else:
                predicate = "relay.message_count > 0"

        # Refund after destination action (state desync)
        elif chain == "source" and function in ("refund", "unlock"):
            predicate = "destRouter.totalMinted() > 0 && sourceRouter.refunded > 0"

        if not predicate:
            predicate = f"step_{step}_executed"

        waypoints.append({
            "waypoint_id": f"w{step}",
            "after_step": step,
            "predicate": predicate,
            "description": description,
        })

    return waypoints
```

**Test:**
```python
def test_waypoints_are_state_predicates():
    gen = AttackScenarioGenerator()
    scenario = {
        "actions": [
            {"step": 1, "chain": "source", "function": "dispatch", 
             "params": {"amount": "1000000000000000000"}, "description": "deposit"},
            {"step": 2, "chain": "destination", "function": "handle",
             "params": {}, "description": "mint"},
        ]
    }
    waypoints = gen._extract_waypoints(scenario)
    assert "totalLocked" in waypoints[0]["predicate"]
    assert "totalMinted" in waypoints[1]["predicate"]
```

**Ước tính:** 2 giờ

---

## SPRINT 3 — Polish

### Task 3.1: JSON schema validation trong orchestrator

**Deliverable:** Validate atg.json và hypotheses.json trước khi pass cho Rust binary.

**Code changes:**

File: `src/orchestrator.py` — thêm:
```python
import jsonschema

SCHEMAS_DIR = Path(__file__).resolve().parents[1] / "schemas"


def _validate_output(data: dict, schema_name: str):
    schema_path = SCHEMAS_DIR / f"{schema_name}.schema.json"
    if not schema_path.exists():
        print(f"[Validator] Schema not found: {schema_path}, skipping")
        return
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(data, schema)
        print(f"[Validator] {schema_name}: OK")
    except jsonschema.ValidationError as e:
        print(f"[Validator] {schema_name} INVALID: {e.message}")
        print(f"  Path: {list(e.path)}")
        raise


# Trong run_pipeline, sau Module 1:
atg_json = atg_builder.to_json(atg)
atg_json["bridge_name"] = benchmark_dir.name
atg_json["invariants"] = invariants
_validate_output(atg_json, "atg")

# Sau Module 2:
hypotheses = {"bridge_name": benchmark_dir.name, "scenarios": scenarios}
_validate_output(hypotheses, "hypotheses")
```

**Dependency:** `jsonschema>=4.0.0` (đã có trong requirements? kiểm tra)

**Ước tính:** 1 giờ

---

### Task 3.2: Progress bar với rich

**Deliverable:** User-friendly progress khi chạy pipeline.

**Code changes:**

File: `src/orchestrator.py`:
```python
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.console import Console

console = Console()

def run_pipeline(args):
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task1 = progress.add_task("[cyan]Module 1: Semantic extraction", total=len(contract_files))
        merged = {"entities": [], "functions": [], "asset_flows": [], "guards": []}
        for path in contract_files:
            sem = extractor.extract_from_file(str(path))
            for key in merged:
                merged[key].extend(sem.get(key, []))
            progress.update(task1, advance=1)

        task2 = progress.add_task("[green]Module 1: ATG + invariants", total=2)
        atg = atg_builder.build(merged)
        progress.update(task2, advance=1)
        atg_json = atg_builder.to_json(atg)
        invariants = invariant_synth.synthesize(atg_json)
        atg_json["invariants"] = invariants
        progress.update(task2, advance=1)

        task3 = progress.add_task("[yellow]Module 2: RAG scenarios", total=len(invariants))
        scenarios = []
        for inv in invariants:
            scenario = scenario_gen._generate_one(atg_json, inv)  # new helper
            scenarios.append(scenario)
            progress.update(task3, advance=1)

        task4 = progress.add_task("[red]Module 3: Fuzzing", total=args.runs)
        for run_id in range(args.runs):
            # ... run fuzzer ...
            progress.update(task4, advance=1)

    console.print(f"\n[bold green]✓ Pipeline complete[/] Report: {output_dir / 'report.json'}")
```

**Ước tính:** 2 giờ

---

### Task 3.3: Typed ATG conditions

**Deliverable:** `ATGEdge.conditions` là list typed object, không phải string.

**Code changes:**

File: `src/module1_semantic/atg_builder.py`:
```python
from dataclasses import dataclass, field


@dataclass
class Condition:
    """Typed edge condition."""
    type: str  # "hashlock" | "timelock" | "signature" | "nonce" | "balance" | "generic"
    params: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {"type": self.type, "params": self.params}


@dataclass
class ATGEdge:
    src: str
    dst: str
    label: str
    edge_id: str = ""
    token: str = "UNKNOWN"
    function_signature: str = ""
    conditions: list[Condition] = field(default_factory=list)


def parse_condition(text: str) -> Condition:
    """Heuristic classify string condition into typed condition."""
    t = text.lower()
    if "hash" in t or "keccak" in t:
        return Condition(type="hashlock", params={"expression": text})
    if "timestamp" in t or "block.number" in t or "timeout" in t:
        return Condition(type="timelock", params={"expression": text})
    if "signature" in t or "ecrecover" in t or "sig" in t:
        return Condition(type="signature", params={"expression": text})
    if "nonce" in t or "processed" in t:
        return Condition(type="nonce", params={"expression": text})
    if "balance" in t or "amount" in t:
        return Condition(type="balance", params={"expression": text})
    return Condition(type="generic", params={"expression": text})
```

**BREAKING CHANGE** với Rust: `types.rs` hiện nhận `conditions: Vec<String>`. Cần thống nhất với Member B.

**Option 1** (không breaking): Giữ Rust nhận `Vec<String>`, chỉ dùng Condition object nội bộ Python.

**Option 2** (breaking, sát paper hơn): Thay đổi cả Rust:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtgCondition {
    pub r#type: String,
    pub params: HashMap<String, serde_json::Value>,
}

pub struct AtgEdge {
    // ...
    pub conditions: Vec<AtgCondition>,
    // ...
}
```

→ Cần update schema `atg.schema.json`.

**Khuyến nghị:** Option 1 trước, Option 2 khi có thời gian.

**Ước tính:** 2 giờ (Option 1) / 4 giờ (Option 2 với migration)

---

### Task 3.4: Embedding cache

File: `src/module2_rag/embedder.py`:
```python
import hashlib

def build_index(self, exploits):
    self.exploits = exploits
    kb = ExploitKnowledgeBase()
    self.exploit_texts = [kb.to_text(e) for e in exploits]
    if not self.exploit_texts:
        return

    # Cache based on text hash + model
    combined = f"{self.model_name}||{'|'.join(self.exploit_texts)}"
    key = hashlib.sha256(combined.encode()).hexdigest()[:12]
    cache_path = Path(f".embedding_cache/{key}.npy")

    if cache_path.exists():
        try:
            self._matrix = np.load(cache_path)
        except Exception:
            self._matrix = self._encode_texts(self.exploit_texts)
    else:
        self._matrix = self._encode_texts(self.exploit_texts)
        cache_path.parent.mkdir(exist_ok=True)
        np.save(cache_path, self._matrix)

    # ... FAISS index setup as before ...
```

**Ước tính:** 30 phút

---

## Lịch trình đề xuất

### Tuần 1 — Sprint 1 (Critical)

| Ngày | Task | Giờ |
|------|------|-----|
| Mon | 1.4 Shared LLM client + 1.3 System prompts | 3h |
| Tue | 1.1 invariant_synth LLM (generate + fallback) | 4h |
| Wed | 1.1 tests + debug + validation | 3h |
| Thu | 1.2 Scenario templates (5 templates) | 4h |
| Fri | 1.2 tests + integration với orchestrator | 2h |

**End of week 1:** Run `python src/orchestrator.py --benchmark benchmarks/nomad/ --skip-fuzzer --output results/week1_test/` → đủ invariants đa dạng + scenarios đúng vuln class.

### Tuần 2 — Sprint 2 (Quality)

| Ngày | Task | Giờ |
|------|------|-----|
| Mon | 2.1 Retry logic + 2.2 LLM cache | 3h |
| Tue | 2.4 Build exploit KB script | 4h |
| Wed | 2.4 Manual add records tới 51 | 3h |
| Thu | 2.3 Slither parser (initial) | 4h |
| Fri | 2.3 Slither debug + 2.5 waypoints | 3h |

**End of week 2:** KB có 30+ records, Slither parse được Nomad, waypoints là state predicates.

### Tuần 3 — Sprint 3 (Polish)

| Ngày | Task | Giờ |
|------|------|-----|
| Mon | 3.1 Schema validation | 1h |
| Mon | 3.2 Progress bar | 2h |
| Tue | 3.4 Embedding cache + misc | 2h |
| Wed | 3.3 Typed conditions (Option 1) | 2h |
| Thu-Fri | End-to-end test Nomad + debug | 6h |

**End of week 3:** Full pipeline chạy Nomad end-to-end thành công, phát hiện >= 1 violation.

---

## Dependencies giữa các task

```
1.4 (shared client) ──┐
                      ├─> 1.3 (prompts) ──> 1.1 (invariant LLM)
                      └─> 2.1 (retry) ─────> 2.2 (cache)

1.1 ───┐
       ├──> 1.2 (scenario templates)
       │
       └──> 2.5 (waypoints)

2.3 (Slither) độc lập

2.4 (KB script) ───> 1.2 retrieved exploits tốt hơn

3.1 ──> sau khi schemas/*.schema.json đã stable (check với Member B)
```

Có thể parallelize: 2.3 (Slither) + 2.4 (KB) cùng lúc nếu có thời gian.

---

## Định nghĩa "Done" cho từng Sprint

### Sprint 1 Done khi:
- [ ] `pytest tests/` pass toàn bộ
- [ ] `python src/orchestrator.py --benchmark benchmarks/nomad/ --skip-fuzzer` sinh `atg.json` có >= 8 invariants phân theo category
- [ ] `hypotheses.json` có scenarios khác nhau theo vuln class (không cùng 3-step pattern)
- [ ] LLM calls dùng system prompt nhất quán, temperature=0 (extractor/invariant) hoặc 0.3 (scenario)

### Sprint 2 Done khi:
- [ ] `src/module2_rag/data/` có >= 30 exploit records
- [ ] `pytest tests/` pass
- [ ] Retry logic có tests (simulate rate limit)
- [ ] `.llm_cache/` được tạo và reuse khi chạy lại orchestrator
- [ ] Slither parse được Message.sol của Nomad (hoặc graceful fallback regex)

### Sprint 3 Done khi:
- [ ] `jsonschema.validate` pass cho cả atg.json và hypotheses.json
- [ ] Progress bar hiển thị đẹp khi chạy orchestrator
- [ ] **End-to-end Nomad pipeline chạy thành công** (với Rust binary built từ Member B)

---

## File mới sẽ tạo

```
src/
├── common/
│   ├── __init__.py
│   ├── llm_client.py           # Sprint 1.4
│   └── llm_cache.py            # Sprint 2.2
├── module1_semantic/
│   ├── prompts/
│   │   ├── __init__.py         # Sprint 1.3
│   │   └── system_auditor.txt  # Sprint 1.3
│   └── slither_parser.py       # Sprint 2.3
├── module2_rag/
│   ├── prompts/
│   │   ├── __init__.py         # Sprint 1.3
│   │   └── system_adversary.txt
│   └── templates.py            # Sprint 1.2
└── (existing files updated)

scripts/
├── build_exploit_kb.py         # Sprint 2.4
└── extra_exploits.yaml         # Sprint 2.4

tests/
└── (new tests for each task)

.llm_cache/                     # Sprint 2.2 (gitignored)
.embedding_cache/               # Sprint 3.4 (gitignored)
```

---

## Chi phí API dự kiến

Với NVIDIA NIM free tier (gpt-oss-120b hoặc llama-3.3-70b):
- Sprint 1 dev: $0
- Sprint 2 dev: $0
- Sprint 3 testing: $0

Với OpenAI gpt-4o-mini (khi chạy experiments):
- 12 benchmarks × 1 full run × ~5$ per bridge = **~$60**

Có LLM cache → chạy lặp không tốn thêm.

---

## Kết luận

Plan này ưu tiên fix những gap CAO (`invariant_synth` + scenario templates) trước để match paper methodology, sau đó mới polish. Sau 3 tuần, Module 1 + 2 sẽ đạt chất lượng đủ chạy experiments cho paper.

**Bắt đầu từ đâu?** Tôi đề xuất Task 1.4 (shared LLM client) vì nó unblock cả Task 1.1, 1.2, 1.3. Sau đó 1.1 là most critical fix.
