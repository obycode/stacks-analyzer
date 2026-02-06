# Rejection Patterns (AI Notes)

Purpose: document known rejection patterns and the log signals that identify
those patterns, so an AI or rule engine can classify rejections quickly when
reviewing stored history.

## Pattern: Burn-Block Boundary Split (NotLatestSortitionWinner)

Summary: a proposal arrives very close to a new bitcoin burn block. Some signers
observe the new burn block first and reject the proposal as not the latest
sortition winner, while others accept based on the previous burn view. The
proposal crosses the 30% rejection threshold and is finalized as rejected.

Signals:
- `Received block rejection` with `reject_reason: NotLatestSortitionWinner`.
- `percent_rejected` climbs to >= 30% (rejection threshold).
- Proposal `burn_height` is N, and a new burn block event at height N+1 occurs
  within a small window (about 10-15s) of the proposal or rejection threshold.
- Mixed accept/reject responses for the same `signer_signature_hash` in a short
  window (if acceptance logs are available).

Data to persist for AI analysis:
- `signer_signature_hash`, proposal block height, proposal burn height,
  consensus hash.
- First/last rejection timestamps, max percent rejected, max percent approved.
- Counts of accepting vs rejecting signer pubkeys (when logged).
- Timestamp and height of the nearest burn block update.

Example (abbreviated):
- Proposal: `signer_signature_hash: f98f...` with `burn_height: 935234`.
- Rejections: `reject_reason: NotLatestSortitionWinner`,
  `percent_rejected: 32.54`.
- New burn block: `burn_block_height: 935235` shortly after.

Interpretation: the proposal likely raced a burn block boundary; signers split
on which burn block they observed first.

## Pattern Template

When adding more patterns, include:
- short summary and log signals,
- data fields to persist for LLM analysis,
- a brief interpretation statement,
- one real log-based example.
