# AI Notes: Stacks Analyzer Basics

Purpose: summarize what the analyzer knows today so an AI can reason about
logs and state quickly. This includes observed log events, thresholds, derived
state, and alert behavior.

## System Overview

The analyzer ingests stacks-node and stacks-signer logs and builds a live
state machine that powers:
- alerts (stdout, web UI, optional Telegram)
- a web dashboard
- periodic reports (stdout, optional Telegram)

The analyzer is intentionally conservative: it prefers to finalize proposals
from explicit signer signals (block pushed or new block event) but also handles
known rejection thresholds.

## Core Entities and Identifiers

- `signer_signature_hash`: primary id for a block proposal; key for all
  acceptance/rejection/threshold events.
- `block_height`: Stacks block height for the proposal.
- `burn_height`: Bitcoin burn block height tied to a proposal or burn event.
- `consensus_hash`: burn block consensus hash.
- `block_id`: Stacks block hash (used for height mapping).
- signer pubkey: used for signer identity and participation.

## Key Log Events (Signer)

Proposal lifecycle:
- `received a block proposal for a new block.` -> proposal created.
- `Received block acceptance` -> adds signer acceptance and weight.
- `Received block acceptance and have reached the threshold` -> threshold met.
- `Got block pushed message` -> proposal finalized as accepted.
- `Received a new block event.` -> also finalizes proposal as accepted
  (covers cases where block push is missing).

Rejections:
- `Received block rejection` -> adds rejection info and percent rejected.
- `Received block rejection and have reached the rejection threshold`
  -> finalize proposal as rejected.
- `Broadcasting block response to stacks node` -> local signer response,
  includes `reject_reason` for early local rejects.

Burn block changes:
- `Received a new burn block event for block height <n>` -> burn height update
  used for boundary analysis.
- `Received state machine update ... ActiveMiner` -> also carries burn height.

## Key Log Events (Node)

Sortition and miner commits:
- `ACCEPTED(<burn>) leader block commit ...` -> commit observed.
- `SORTITION(<burn>): WINNER SELECTED` -> winner selected.
- `SORTITION(<burn>): WINNER REJECTED` -> null miner (or rejection reason).
- `Received burnchain block #<burn> including block_commit_op (winning)`
  -> winning commit metadata.

Chain and tenure:
- `CONSENSUS(<burn>): <consensus_hash>` -> consensus hash and burn height.
- `Tenure: Notify burn block!` -> burn height/consensus updates.
- `payload: TenureChange(Extend...)` -> tenure extend metadata.

## Thresholds and Finalization Rules

- Proposal accepted threshold: 70% approvals (signer threshold log).
- Proposal rejection threshold: 30% rejections (signer rejection logs).
- A proposal is finalized as accepted on `block pushed` or `new block event`.
- A proposal is finalized as rejected when rejection threshold is reached, or
  when the local signer response is a reject (early checks).

## Alerting Behavior

Alert levels:
- `info`: informational events (new burn block, tenure extend, signer reject).
- `warning`: non-critical degradations (e.g., large signer participation drop).
- `critical`: stalls or hard failures.

Telegram:
- Only alerts with severity >= configured minimum are sent to Telegram.

## Derived State (Dashboard and AI Use)

The analyzer maintains:
- open proposals and recent proposals.
- signer participation and weight estimates.
- current and recent miners, sortition rounds, and commit metadata.
- current bitcoin and stacks heights, consensus hash, and tip ages.
- tenure extend history and last extend metadata.

Key derived signals:
- "open proposals" are those seen but not finalized.
- "recent proposals" include the last 50 proposals, with status and reason.
- proposals can be finalized without a block pushed message if a new block event
  is logged (covers miner stopping at burn boundary).

## Known Issues and Interpretations

Early local reject:
- If the signer rejects early, it may not store the proposal and therefore
  never logs other signer responses. To avoid false "never finalized" alerts,
  the analyzer now finalizes as rejected on local reject.

Block pushed missing:
- Sometimes a block is accepted but a block-pushed message is not emitted
  (miner stops due to new burn block). The "new block event" log is used to
  finalize in that case.

Burn-boundary rejections:
- `reject_reason: NotLatestSortitionWinner` or `SortitionViewMismatch` can indicate
  a burn-block boundary race (signers saw different burn views). This can delay
  threshold acceptance without ultimately rejecting the proposal.

Signer response flip:
- `reject -> accept` is allowed (signer saw different burn view later).
- `accept -> reject` is treated as anomalous and should raise a warning, except
  for extremely rare signer conditions.

Null miner wins:
- Sortition winner can be the null miner; the previous miner can extend tenure.
  This is reflected in node sortition logs and the active miner state machine.

## Related Docs

- Rejection patterns and AI classification rules live in
  `docs/rejection-patterns.md`.
