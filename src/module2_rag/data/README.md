# Exploit Knowledge Base Data

This directory contains structured JSON records of 51 documented cross-chain bridge exploits.

## Record Schema

```json
{
  "id": "nomad_2022",
  "bridge": "Nomad",
  "date": "2022-08-01",
  "loss_usd": 190000000,
  "chains": ["ethereum", "moonbeam"],
  "vulnerability_class": "fake_deposit",
  "attack_stage": "destination_chain",
  "attack_trace": [
    "Step 1: ...",
    "Step 2: ..."
  ],
  "root_cause": "Description of the code-level flaw"
}
```

## Sources
- Wu et al. (2025) — BridgeGuard dataset of 51 attack events
- Rekt.news post-mortems
- SlowMist, Certik audit reports
- Etherscan transaction analysis
