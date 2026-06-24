#!/usr/bin/env bash
#
# Reference ERC-8196 relayer (off-chain half of the bridge).
# Publishes an agent's ERC-8126 risk score to the on-chain ERC8126ScoreAnchor so
# ERC-8196 wallets can read it. Dependency-free: uses Foundry's `cast`.
#
# PRODUCTION wiring (this reference takes RISK + AGENT_ID as inputs instead):
#   1. Fetch the agent from erc8126scan.
#   2. effectiveRisk = (status == 'verified') ? overall_risk_score : 100   # unverified/NULL => fail-closed
#   3. Map the scan agent -> ERC-8004 agentId (erc8004_agent_id).
#   4. setScore(agentId, effectiveRisk).
# Refresh policy: lazy / event-driven / value-tiered. The anchor auto-expires stale
# scores (maxScoreAge, default 24h), so the relayer only needs to keep live agents fresh.
#
# Required env:
#   RPC_URL     node RPC endpoint
#   ANCHOR      ERC8126ScoreAnchor address
#   ORACLE_KEY  the relayer hot key (oracle). KEEP IN A SECRETS MANAGER. Never commit.
#   AGENT_ID    ERC-8004 agent id (uint256)
#   RISK        risk score 0..100 (higher = worse)
#
set -euo pipefail
: "${RPC_URL:?set RPC_URL}"
: "${ANCHOR:?set ANCHOR}"
: "${ORACLE_KEY:?set ORACLE_KEY}"
: "${AGENT_ID:?set AGENT_ID}"
: "${RISK:?set RISK}"

# Fail-closed clamp: anything outside 0..100 (incl. unverified) becomes max risk.
if ! [[ "$RISK" =~ ^[0-9]+$ ]] || (( RISK > 100 )); then
  echo "[relay] RISK '$RISK' invalid/out-of-range -> publishing 100 (fail-closed)"
  RISK=100
fi

echo "[relay] setScore(agentId=$AGENT_ID, risk=$RISK) -> $ANCHOR"
cast send "$ANCHOR" "setScore(uint256,uint8)" "$AGENT_ID" "$RISK" \
  --rpc-url "$RPC_URL" --private-key "$ORACLE_KEY"
echo "[relay] done."
