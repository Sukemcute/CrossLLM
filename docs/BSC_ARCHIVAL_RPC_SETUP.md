# BSC archival RPC setup — for XScope replay of 4 BSC bridges

The XScope replay path (see [REIMPL_XSCOPE_X4_OUTCOME.md](REIMPL_XSCOPE_X4_OUTCOME.md))
forks the source chain at `(exploit_block - 1)` and dispatches the
attacker's actual transaction through revm. For four bridges
(`fegtoken`, `gempad`, `qubit`, `pgala`) the source chain is BSC, so
revm queries state (`eth_getBalance`, `eth_getCode`, `eth_call`) at
old blocks. A **non-archival** node will reject these with
`missing trie node` and the replay aborts.

The default `bsc-dataseed.binance.org` returns this error past ~128
blocks back. We've reproduced it locally at the four fork blocks:

```
fegtoken fork 17127537 — eth_getBalance ✗ missing trie node
gempad   fork 44500000 — eth_getBalance ✗ missing trie node
```

So we need an **archival** BSC endpoint, mounted as
`BSC_ARCHIVE_RPC_URL` in `.env`.

## Provider options (free tiers, ranked)

| Provider | Free tier archival? | Sign-up | Notes |
|---|---|---|---|
| **Alchemy** | ✅ Yes (300M CU/mo) | https://www.alchemy.com/ | Easiest. BSC mainnet support added 2024. |
| **NodeReal MegaNode** | ✅ Yes (~3M req/day) | https://nodereal.io/meganode | BSC-native; archival included on Free. |
| **DRPC** | ✅ Yes (multi-chain) | https://drpc.org/ | Reliable; cap is rate not depth. |
| **QuickNode** | ❌ Free tier non-archival | https://www.quicknode.com/ | BSC archival is paid only. Skip. |
| **Ankr Premium** | ❌ Paid | https://www.ankr.com/rpc/ | Free tier non-archival on BSC. Skip. |
| **GetBlock** | ⚠ Limited | https://getblock.io/ | Archival via shared node, low daily cap. |

**Recommendation: Alchemy.** It already serves your `ETH_RPC_URL`,
and adding a BSC app to the same account is one click.

## Steps

### 1. Sign up for Alchemy BSC

1. Go to https://www.alchemy.com/ → log in (or sign up — free).
2. Click **Apps** → **Create new app**.
3. Network: **BNB Smart Chain** (BSC). Mainnet.
4. Copy the **HTTPS** URL — looks like:
   `https://bnb-mainnet.g.alchemy.com/v2/<YOUR_API_KEY>`

### 2. Add to `.env`

Append to `.env` (don't replace `BSC_RPC_URL` — keep the public one
for non-archival uses):

```bash
BSC_ARCHIVE_RPC_URL=https://bnb-mainnet.g.alchemy.com/v2/<YOUR_API_KEY>
```

### 3. Verify archival capability

```bash
set -a; source .env; set +a
curl -s -X POST "$BSC_ARCHIVE_RPC_URL" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x10ED43C718714eb63d5aA57B78B54704E256024E","0x1052AD0"],"id":1}'
```

Expected: `{"jsonrpc":"2.0","id":1,"result":"0x..."}`
Bad sign:  `"error":{"code":-32000,"message":"missing trie node"}`

If the result returns hex, the endpoint is archival. ✅

### 4. Run the rest of the pipeline

After `BSC_ARCHIVE_RPC_URL` is set, the rest is automated:

```bash
# Apply verified hashes (script writes them to metadata.exploit_replay)
python scripts/_apply_replay_hashes.py

# Fetch on-chain tx data via the archival RPC
python scripts/fetch_exploit_txs.py

# Re-run the replay sweep (the BSC bridges should now run, not SKIP)
bash scripts/run_xscope_replay_sweep.sh

# Verify
python scripts/verify_xscope_acceptance.py results/baselines/xscope
```

## Cost expectation

Each replay tx burns ~10–30 archival queries (state preload + the
revm DB callbacks). With 4 bridges × ~2 txs each × 30 queries ≈ 240
archival reads per sweep. Alchemy free is 300M CU/mo (≈2 M
eth_call-equivalents); this is well within free.

## Fallback if Alchemy doesn't work

If Alchemy rejects BSC for your region or you hit quota:

1. NodeReal MegaNode: same pattern, set `BSC_ARCHIVE_RPC_URL=https://bsc-mainnet.nodereal.io/v1/<API_KEY>`
2. DRPC: `BSC_ARCHIVE_RPC_URL=https://lb.drpc.org/ogrpc?network=bsc&dkey=<API_KEY>`

Both work with the unmodified pipeline — only the env var content
changes.
