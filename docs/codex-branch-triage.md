# Codex branch triage

Generated: 2026-07-20 22:46  (repository `/Users/ryanwible/projects/wrela7`, current branch `complete`).

This document inventories all local and remote `codex/*` refs. No merges or deletions were performed.

## Current branch relationship

| Ref | Last commit |
|-----|-------------|
| `complete` | 2026-07-20 22:42:19 -0600 `25b43aa6` fixes |
| `origin/main` | 2026-07-20 19:53:45 -0600 `c9cad93c` Merge pull request #1 from rywible/cursor/cloud-env-linux-02f5 |

`complete` vs `origin/main`: **4 ahead**, **2 behind** (`git rev-list --left-right --count origin/main...complete`).

None of the listed `codex/*` tips are ancestors of `complete` (history diverged after shared merge-base `973bfc87`); treat them as parallel Codex automation lines to harvest or retire.

## Verdict legend

- **keep** — retain the ref as an integration spine or active coordination branch.
- **harvest** — cherry-pick or port valuable commits onto `complete`, then delete the ref.
- **harvest (Task B5)** — prioritized harvest for bounded recurring actor scheduler work (Task B5).
- **delete** — redundant tip or exploratory stub; safe to remove after confirming no unique commits.

## Summary counts

| Verdict | Count |
|---------|------:|
| keep | 1 |
| harvest (incl. Task B5) | 59 |
| ↳ Task B5 (subset) | 2 |
| delete | 22 |
| **Total refs** | **82** |

## Task B5 — actor scheduler harvest

Task B5 should treat these branches as primary inputs:

| Branch | Tip | Notes |
|--------|-----|-------|
| `codex/lane-c-bounded-scheduler` | 2026-07-17 09:21:16 -0600 `516b0ec5` Implement bounded recurring actor scheduler -Codex Automated | Tip commit `516b0ec5` is on this branch. |
| `codex/lane-n-oracle-full-identity` | 2026-07-17 09:34:22 -0600 `7f7b42f5` merge: publish proof-false builder agent overlay -Codex Automated | Merge tip includes scheduler merge `47105a4d` plus phase differential and builder overlay merges atop lane stack. |

### Commit `516b0ec5` — Implement bounded recurring actor scheduler

2026-07-17 09:21:16 -0600 `516b0ec5` Implement bounded recurring actor scheduler -Codex Automated

**Scope:** +2788 / −296 lines across 15 files — backend scheduling hooks, LLVM validation, compiler analysis facts, flow/machine WIR and lowering (especially `scalar.rs`), image-report decode, and actor/runtime vertical tests.

| Path | Area |
|------|------|
| `crates/wrela-backend/src/lib.rs` | Backend scheduler integration |
| `crates/wrela-codegen-llvm/src/validate.rs` | LLVM validation for recurring actors |
| `crates/wrela-compiler/src/analysis_facts.rs` | Compiler analysis facts for scheduler |
| `crates/wrela-compiler/tests/actor_two_queued_vertical.rs` | Actor queue vertical evidence |
| `crates/wrela-compiler/tests/runtime_flat_structure_vertical.rs` | Runtime layout vertical |
| `crates/wrela-compiler/tests/runtime_result_vertical.rs` | Runtime result vertical |
| `crates/wrela-flow-lower/src/lib.rs` | Flow lowering |
| `crates/wrela-flow-wir-codec/src/canonical.rs` | Flow WIR canonical codec |
| `crates/wrela-flow-wir-codec/src/lib.rs` | Flow WIR codec surface |
| `crates/wrela-flow-wir/src/lib.rs` | Flow WIR model |
| `crates/wrela-image-report/src/decode.rs` | Image report decode |
| `crates/wrela-image-report/src/lib.rs` | Image report model |
| `crates/wrela-machine-lower/src/lib.rs` | Machine lowering entry |
| `crates/wrela-machine-lower/src/scalar.rs` | Scalar / actor machine lowering |
| `crates/wrela-machine-wir/src/lib.rs` | Machine WIR scheduler semantics |

Use this commit as the concrete reference implementation when porting scheduler semantics through backend validation, flow/machine lowering, and actor vertical tests.

## Branch inventory

| Branch | Location | Last commit (CI) | Hash | Subject | Verdict | Reason |
|--------|----------|------------------|------|---------|---------|--------|
| `codex/c1-machine-handoff` | local | 2026-07-17 05:37:59 -0600 | `d5111d26` | Precompute generated scenario Machine locus -Codex Automated | **harvest** | Machine locus precompute; not on `complete`. |
| `codex/integration-review` | local | 2026-07-16 22:45:57 -0600 | `ebfb457e` | merge: enroll Alpine verifier and blocked builder profile -Codex Automated | **harvest** | Early Alpine verifier and builder-profile merge predating rev01 integration. |
| `codex/lane-a-appliance` | local | 2026-07-17 07:29:48 -0600 | `756efe69` | linux: retain failed launcher cleanup authority -Codex Automated | **harvest** | Lane A Linux launcher cleanup authority. |
| `codex/lane-a-builder-initramfs` | local | 2026-07-17 08:51:16 -0600 | `c26c8d23` | Publish proof-false builder agent overlay -Codex Automated | **harvest** | Lane A proof-false builder agent overlay. |
| `codex/lane-a-payload` | local | 2026-07-17 07:44:47 -0600 | `62989be8` | Authenticate Alpine package acquisition and runtime publication -Codex Automated | **harvest** | Lane A Alpine package acquisition and runtime publication. |
| `codex/lane-b-actor-case-handoff` | local | 2026-07-17 07:03:33 -0600 | `aeb02b08` | dist: consume recurring actor QEMU evidence -Codex Automated | **harvest** | Lane B recurring-actor QEMU evidence in dist. |
| `codex/lane-b-current-tuple-handoff` | local | 2026-07-17 07:15:25 -0600 | `1eebbe1c` | dist: bind current compatibility tuple -Codex Automated | **harvest** | Lane B current compatibility tuple binding. |
| `codex/lane-b-qemu-tranche` | local | 2026-07-17 06:45:08 -0600 | `928929ec` | Harden Cargo acquisition parent authority -Codex Automated | **harvest** | Lane B Cargo acquisition parent authority. |
| `codex/lane-b-vendor-handoff` | local | 2026-07-17 06:49:22 -0600 | `912367c2` | Reconcile stdlib time TestPlan schema -Codex Automated | **harvest** | Lane B stdlib time TestPlan schema reconciliation. |
| `codex/lane-c-bounded-scheduler` | local | 2026-07-17 09:21:16 -0600 | `516b0ec5` | Implement bounded recurring actor scheduler -Codex Automated | **harvest (Task B5)** | Primary Task B5 input: bounded recurring actor scheduler + merged oracle/lane stack (see § Task B5). |
| `codex/lane-c-recurrence-handoff` | local | 2026-07-17 06:37:56 -0600 | `6bc85376` | Preserve ordinary actor test groups -Codex Automated | **harvest** | Lane C ordinary actor test group preservation. |
| `codex/lane-c-runtime-abi3` | local | 2026-07-17 07:08:30 -0600 | `1cac436c` | Add ABI3 cancellation runtime seam -Codex Automated | **harvest** | Lane C ABI3 cancellation runtime seam. |
| `codex/lane-c-surface` | local | 2026-07-17 05:54:34 -0600 | `e63e6f6e` | Add bounded recurring actor mailbox execution -Codex Automated | **harvest** | Lane C bounded recurring actor mailbox execution (scheduler precursor). |
| `codex/lane-n-oracle-full-identity` | local | 2026-07-17 09:34:22 -0600 | `7f7b42f5` | merge: publish proof-false builder agent overlay -Codex Automated | **harvest (Task B5)** | Primary Task B5 input: bounded recurring actor scheduler + merged oracle/lane stack (see § Task B5). |
| `codex/lane-n-phase-differential` | local | 2026-07-17 08:34:42 -0600 | `c7f9a9ce` | test phase-neutral function differential evidence -Codex Automated | **harvest** | Lane N phase-neutral function differential evidence. |
| `codex/lane-n-phaseset-machine` | local | 2026-07-17 08:08:09 -0600 | `46bc1225` | Enforce canonical PhaseSet oracle identity -Codex Automated | **harvest** | Lane N canonical PhaseSet oracle identity (feeds scheduler lowering). |
| `codex/lane-n-temporary-verb-matrix` | local | 2026-07-17 07:11:30 -0600 | `356e91e3` | Centralize temporary access verb policy -Codex Automated | **harvest** | Lane N temporary access verb policy matrix. |
| `codex/next-vertical` | local | 2026-07-17 06:52:19 -0600 | `830aac9c` | Harden image report corpus publication -Codex Automated | **harvest** | Image report corpus publication hardening. |
| `codex/rev01-a-15-a1` | local | 2026-07-18 17:29:02 -0600 | `14557440` | Merge A-20 production authority respec -Codex Automated | **harvest** | A-20 production authority merge checkpoint. |
| `codex/rev01-a-15-a2` | local | 2026-07-18 17:37:36 -0600 | `bcec64c1` | Merge P0-10 architecture ownership correction -Codex Automated | **harvest** | P0-10 architecture ownership correction merge. |
| `codex/rev01-a-15-respec` | local | 2026-07-18 18:41:06 -0600 | `a8dcbe99` | Respec A-15 static agent and archive cutover -Codex Automated | **harvest** | A-15 static agent and archive cutover respec. |
| `codex/rev01-a-17-a1` | local | 2026-07-18 17:37:35 -0600 | `20cdab6c` | extract builder-tool disk module for A-17 -Codex Automated | **harvest** | A-17 builder-tool disk module extraction. |
| `codex/rev01-a-18-a1` | local | 2026-07-18 18:09:03 -0600 | `45440523` | A-18 add bounded zstd frame and raw-RLE decoder -Codex Automated | **harvest** | A-18 bounded zstd frame and raw-RLE decoder. |
| `codex/rev01-a-18-gate-fix` | local | 2026-07-18 18:19:55 -0600 | `9d580b1d` | register A-18 zstd gate fixture family -Codex Automated | **harvest** | A-18 zstd gate fixture family registration. |
| `codex/rev01-a-19-a1` | local | 2026-07-18 19:47:06 -0600 | `2f162bcd` | Implement bounded zstd entropy tables -Codex Automated | **harvest** | A-19 bounded zstd entropy tables implementation. |
| `codex/rev01-a-20-a1` | local | 2026-07-18 14:15:56 -0600 | `fb28763b` | Merge H-00 fixed hardware contract -Codex Automated | **harvest** | Shared H-00 / A-20 merge checkpoint (duplicate-tips exist). |
| `codex/rev01-a-20-a2` | local | 2026-07-18 14:15:56 -0600 | `fb28763b` | Merge H-00 fixed hardware contract -Codex Automated | **delete** | Duplicate tip (`fb28763`) of `codex/rev01-a-20-a1`; no unique commits. |
| `codex/rev01-a-20-respec` | local | 2026-07-18 17:23:15 -0600 | `54bfaf94` | respec A-20 production builder authority -Codex Automated | **harvest** | A-20 production builder authority respec. |
| `codex/rev01-a-24-a1` | local | 2026-07-18 20:13:54 -0600 | `d0d84ce6` | Implement bounded zstd literals sections -Codex Automated | **harvest** | A-24 bounded zstd literals sections. |
| `codex/rev01-a-27-a1` | local | 2026-07-18 20:50:10 -0600 | `489811c0` | Implement bounded zstd sequence execution -Codex Automated | **harvest** | A-27 bounded zstd sequence execution. |
| `codex/rev01-a-28-respec` | local | 2026-07-18 20:58:40 -0600 | `be0af903` | Respec A-28 checksum and frame integration plan -Codex Automated | **harvest** | A-28 checksum and frame integration plan respec. |
| `codex/rev01-a-46-a1` | local | 2026-07-18 19:06:50 -0600 | `0d54b133` | prove A-46 static builder agent publication -Codex Automated | **harvest** | A-46 static builder agent publication proof. |
| `codex/rev01-a-46-a2` | local | 2026-07-18 19:22:44 -0600 | `f298400b` | Merge C-19 semantic ISR diagnostic respec -Codex Automated | **delete** | Duplicate tip (`f298400`) of `codex/rev01-c-19-gate-a2`; no unique commits. |
| `codex/rev01-a-46-respec` | local | 2026-07-18 21:04:16 -0600 | `468fec3e` | Respec A-46 static agent production -Codex Automated | **harvest** | A-46 static agent production respec. |
| `codex/rev01-a-53-a1` | local | 2026-07-18 21:02:19 -0600 | `546640a6` | Merge A-53 checksum and A-28 frame integration plan -Codex Automated | **delete** | Duplicate tip (`546640a`) of `codex/rev01-integration`; no unique commits. |
| `codex/rev01-a-61-fixture-followup` | local | 2026-07-18 21:02:19 -0600 | `546640a6` | Merge A-53 checksum and A-28 frame integration plan -Codex Automated | **delete** | Duplicate tip (`546640a`) of `codex/rev01-integration`; no unique commits. |
| `codex/rev01-a13-a14-respec` | local | 2026-07-18 20:34:50 -0600 | `ebf1564e` | Merge C-20 and C-21 semantic gate repair plan -Codex Automated | **delete** | Duplicate tip (`ebf1564`) of `codex/rev01-explore-a13-a14-1`; no unique commits. |
| `codex/rev01-c-01-a1` | local | 2026-07-18 11:35:50 -0600 | `cf705550` | workflow setup | **delete** | Duplicate tip (`cf70555`) of `workflow-setup stub`; no unique commits. |
| `codex/rev01-c-01-a2` | local | 2026-07-18 11:35:50 -0600 | `cf705550` | workflow setup | **delete** | Duplicate tip (`cf70555`) of `workflow-setup stub`; no unique commits. |
| `codex/rev01-c-01-respec` | local | 2026-07-18 14:07:45 -0600 | `81575b06` | respec C-01 into session-sized cutover tasks -Codex Automated | **harvest** | C-01 session-sized cutover respec. |
| `codex/rev01-c-15-a1` | local | 2026-07-18 13:59:06 -0600 | `d312fc3d` | test(sema): prove analyzer decomposition bounds | **harvest** | C-15 sema analyzer decomposition bound tests. |
| `codex/rev01-c-16-a1` | local | 2026-07-18 14:54:34 -0600 | `299b986f` | frontend: represent independent function dimensions | **harvest** | C-16 independent function dimensions in frontend. |
| `codex/rev01-c-17-a1` | local | 2026-07-18 17:01:07 -0600 | `ad882c60` | frontend: add layouts and result shapes -Codex Automated | **harvest** | C-17 layouts and projection result shapes. |
| `codex/rev01-c-18-a1` | local | 2026-07-18 17:04:38 -0600 | `cb6d7423` | Merge C-17 layouts and projection result shapes -Codex Automated | **harvest** | C-17 layouts merge checkpoint. |
| `codex/rev01-c-18-a2` | local | 2026-07-18 17:04:38 -0600 | `cb6d7423` | Merge C-17 layouts and projection result shapes -Codex Automated | **delete** | Duplicate tip (`cb6d742`) of `codex/rev01-c-18-a1`; no unique commits. |
| `codex/rev01-c-18-respec` | local | 2026-07-18 18:06:32 -0600 | `aff41090` | Respec C-18 sema dimension dependency -Codex Automated | **harvest** | C-18 sema dimension dependency respec. |
| `codex/rev01-c-19-a1` | local | 2026-07-18 18:33:22 -0600 | `bba46d10` | Fix C-19 compiler seam ownership -Codex Automated | **harvest** | C-19 compiler seam ownership fix. |
| `codex/rev01-c-19-a2` | local | 2026-07-18 18:43:30 -0600 | `80ba671c` | Merge A-15 static-agent handoff respec -Codex Automated | **harvest** | C-19 static-agent handoff respec merge. |
| `codex/rev01-c-19-gate-a2` | local | 2026-07-18 19:22:44 -0600 | `f298400b` | Merge C-19 semantic ISR diagnostic respec -Codex Automated | **harvest** | C-19 semantic ISR diagnostic respec merge. |
| `codex/rev01-c-19-gate-respec` | local | 2026-07-18 20:25:37 -0600 | `6622b455` | Respec C-19 semantic gate closure | **harvest** | C-19 semantic gate closure respec. |
| `codex/rev01-c-19-post-respec` | local | 2026-07-18 19:45:58 -0600 | `f3aa75ba` | Restore semantic function dimension ownership -Codex Automated | **harvest** | C-19 semantic function dimension ownership restore. |
| `codex/rev01-c-19-respec` | local | 2026-07-18 19:13:03 -0600 | `811acc2d` | Respec C-19 ISR proof boundary -Codex Automated | **harvest** | C-19 ISR proof boundary respec. |
| `codex/rev01-c-19-scope-fix` | local | 2026-07-18 18:31:42 -0600 | `4010458c` | Correct C-19 compiler format ownership -Codex Automated | **harvest** | C-19 compiler format ownership correction. |
| `codex/rev01-c-20-a1` | local | 2026-07-18 21:02:19 -0600 | `546640a6` | Merge A-53 checksum and A-28 frame integration plan -Codex Automated | **delete** | Duplicate tip (`546640a`) of `codex/rev01-integration`; no unique commits. |
| `codex/rev01-explore-a-28-1` | local | 2026-07-18 20:21:42 -0600 | `c73bc003` | Merge A-24 bounded zstd literals sections -Codex Automated | **delete** | Exploratory merge snapshot superseded by the rev01 integration path. |
| `codex/rev01-explore-a-28-2` | local | 2026-07-18 20:21:42 -0600 | `c73bc003` | Merge A-24 bounded zstd literals sections -Codex Automated | **delete** | Duplicate tip (`c73bc00`) of `codex/rev01-explore-a-28-1`; no unique commits. |
| `codex/rev01-explore-a13-a14-1` | local | 2026-07-18 20:34:50 -0600 | `ebf1564e` | Merge C-20 and C-21 semantic gate repair plan -Codex Automated | **delete** | Exploratory merge snapshot superseded by the rev01 integration path. |
| `codex/rev01-explore-a13-a14-2` | local | 2026-07-18 20:34:50 -0600 | `ebf1564e` | Merge C-20 and C-21 semantic gate repair plan -Codex Automated | **delete** | Duplicate tip (`ebf1564`) of `codex/rev01-explore-a13-a14-1`; no unique commits. |
| `codex/rev01-explore-c18-p013-1` | local | 2026-07-18 20:57:02 -0600 | `1a6a82ab` | Merge P0-16 final backend lock authority plan -Codex Automated | **delete** | Exploratory merge snapshot superseded by the rev01 integration path. |
| `codex/rev01-explore-c18-p013-2` | local | 2026-07-18 20:57:02 -0600 | `1a6a82ab` | Merge P0-16 final backend lock authority plan -Codex Automated | **delete** | Duplicate tip (`1a6a82a`) of `codex/rev01-explore-c18-p013-1`; no unique commits. |
| `codex/rev01-h-00-a1` | local | 2026-07-18 14:10:57 -0600 | `ed99ec61` | H-00 encode fixed hardware execution contract -Codex Automated | **harvest** | H-00 fixed hardware execution contract encoding. |
| `codex/rev01-h-00-a2` | local | 2026-07-18 12:31:26 -0600 | `c88d4afe` | refactor(semantic): decompose analysis god-files | **harvest** | H-00 semantic analysis god-file decomposition. |
| `codex/rev01-h-00-respec` | local | 2026-07-18 13:27:00 -0600 | `3e06e98a` | respec(H-00): own locked target dependency -Codex Automated | **harvest** | H-00 locked target dependency respec. |
| `codex/rev01-h-00-respec2` | local | 2026-07-18 13:33:17 -0600 | `e155d354` | respec H-00 reviewed target closure - Codex Automated | **harvest** | H-00 reviewed target closure respec. |
| `codex/rev01-h-00-respec3` | local | 2026-07-18 13:38:05 -0600 | `29fff12a` | docs(release): scope H-00 backend lock pin update -Codex Automated | **harvest** | H-00 backend lock pin update scope documentation. |
| `codex/rev01-h-00-respec4` | local | 2026-07-18 13:50:20 -0600 | `eb217319` | Clarify H-00 probe provenance -Codex Automated | **harvest** | H-00 probe provenance clarification. |
| `codex/rev01-h-10-a1` | local | 2026-07-18 14:15:56 -0600 | `fb28763b` | Merge H-00 fixed hardware contract -Codex Automated | **delete** | Duplicate tip (`fb28763`) of `codex/rev01-a-20-a1`; no unique commits. |
| `codex/rev01-h-10-a2` | local | 2026-07-18 14:15:56 -0600 | `fb28763b` | Merge H-00 fixed hardware contract -Codex Automated | **delete** | Duplicate tip (`fb28763`) of `codex/rev01-a-20-a1`; no unique commits. |
| `codex/rev01-h-10-respec` | local | 2026-07-18 21:05:25 -0600 | `577c3568` | Split H-10 target and semantic authority -Codex Automated | **harvest** | H-10 target vs semantic authority split respec. |
| `codex/rev01-integration` | local | 2026-07-18 21:02:19 -0600 | `546640a6` | Merge A-53 checksum and A-28 frame integration plan -Codex Automated | **keep** | Canonical local rev01 Codex integration line; retain until merged into `complete` / `main`. |
| `codex/rev01-p0-05-a1` | local | 2026-07-18 11:35:50 -0600 | `cf705550` | workflow setup | **delete** | Duplicate tip (`cf70555`) of `workflow-setup stub`; no unique commits. |
| `codex/rev01-p0-05-a2` | local | 2026-07-18 11:35:50 -0600 | `cf705550` | workflow setup | **delete** | Duplicate tip (`cf70555`) of `workflow-setup stub`; no unique commits. |
| `codex/rev01-p0-05-respec` | local | 2026-07-18 15:41:06 -0600 | `4d678844` | Respec P0-05 representation epoch rollout -Codex Automated | **harvest** | P0-05 representation epoch rollout respec. |
| `codex/rev01-p0-07-a1` | local | 2026-07-18 12:31:26 -0600 | `c88d4afe` | refactor(semantic): decompose analysis god-files | **harvest** | P0-07 semantic analysis decomposition refactor. |
| `codex/rev01-p0-10-a1` | local | 2026-07-18 15:46:42 -0600 | `974e21d2` | Merge P0-05 dependency-safe respec -Codex Automated | **harvest** | P0-05 dependency-safe respec merge checkpoint. |
| `codex/rev01-p0-10-a2` | local | 2026-07-18 15:46:42 -0600 | `974e21d2` | Merge P0-05 dependency-safe respec -Codex Automated | **delete** | Duplicate tip (`974e21d`) of `codex/rev01-p0-10-a1`; no unique commits. |
| `codex/rev01-p0-10-a3` | local | 2026-07-18 17:42:25 -0600 | `d0c1b1e3` | Establish shared representation authority -Codex Automated | **harvest** | P0-10 shared representation authority establishment. |
| `codex/rev01-p0-10-respec` | local | 2026-07-18 17:32:53 -0600 | `21e5f92b` | Respec P0-10 architecture registration -Codex Automated | **harvest** | P0-10 architecture registration respec. |
| `codex/rev01-p0-13-a1` | local | 2026-07-18 17:47:52 -0600 | `e650809f` | Merge P0-10 representation authority -Codex Automated | **harvest** | P0-10 representation authority merge checkpoint. |
| `codex/rev01-p0-13-a2` | local | 2026-07-18 17:47:52 -0600 | `e650809f` | Merge P0-10 representation authority -Codex Automated | **delete** | Duplicate tip (`e650809`) of `codex/rev01-p0-13-a1`; no unique commits. |
| `codex/rev01-p0-16-respec` | local | 2026-07-18 20:53:12 -0600 | `6b4d299d` | respec final Linux backend Cargo pin refresh -Codex Automated | **harvest** | P0-16 final Linux backend Cargo pin refresh respec. |
| `origin/codex/rev01-integration` | remote | 2026-07-18 11:35:50 -0600 | `cf705550` | workflow setup | **delete** | Stale remote tip at workflow-setup stub; superseded by local `codex/rev01-integration`. |

## Execution record (2026-07-21)

Lane 0 stabilize executed the **delete** verdicts on branch `drive`. Safety rule: tip must equal or be an ancestor of the named surviving duplicate (or of local `codex/rev01-integration` for superseded explore tips) before `git branch -D`.

### Deleted local branches (21)

| Branch | Tip | Safety check |
|--------|-----|--------------|
| `codex/rev01-a-20-a2` | `fb28763b` | same tip as `codex/rev01-a-20-a1` |
| `codex/rev01-a-46-a2` | `f298400b` | same tip as `codex/rev01-c-19-gate-a2` |
| `codex/rev01-a-53-a1` | `546640a6` | same tip as `codex/rev01-integration` |
| `codex/rev01-a-61-fixture-followup` | `546640a6` | same tip as `codex/rev01-integration` |
| `codex/rev01-a13-a14-respec` | `ebf1564e` | same tip as `codex/rev01-explore-a13-a14-1` (then explore tip ancestor of integration) |
| `codex/rev01-c-01-a1` | `cf705550` | same tip as peer workflow stubs; ancestor of `codex/rev01-integration` |
| `codex/rev01-c-01-a2` | `cf705550` | same tip as peer workflow stubs; ancestor of `codex/rev01-integration` |
| `codex/rev01-c-18-a2` | `cb6d7423` | same tip as `codex/rev01-c-18-a1` |
| `codex/rev01-c-20-a1` | `546640a6` | same tip as `codex/rev01-integration` |
| `codex/rev01-explore-a-28-1` | `c73bc003` | ancestor of `codex/rev01-integration` |
| `codex/rev01-explore-a-28-2` | `c73bc003` | same tip as `codex/rev01-explore-a-28-1` |
| `codex/rev01-explore-a13-a14-1` | `ebf1564e` | ancestor of `codex/rev01-integration` |
| `codex/rev01-explore-a13-a14-2` | `ebf1564e` | same tip as `codex/rev01-explore-a13-a14-1` |
| `codex/rev01-explore-c18-p013-1` | `1a6a82ab` | ancestor of `codex/rev01-integration` |
| `codex/rev01-explore-c18-p013-2` | `1a6a82ab` | same tip as `codex/rev01-explore-c18-p013-1` |
| `codex/rev01-h-10-a1` | `fb28763b` | same tip as `codex/rev01-a-20-a1` |
| `codex/rev01-h-10-a2` | `fb28763b` | same tip as `codex/rev01-a-20-a1` |
| `codex/rev01-p0-05-a1` | `cf705550` | same tip as peer workflow stubs; ancestor of `codex/rev01-integration` |
| `codex/rev01-p0-05-a2` | `cf705550` | same tip as peer workflow stubs; ancestor of `codex/rev01-integration` |
| `codex/rev01-p0-10-a2` | `974e21d2` | same tip as `codex/rev01-p0-10-a1` |
| `codex/rev01-p0-13-a2` | `e650809f` | same tip as `codex/rev01-p0-13-a1` |

### Deleted remote branch (1)

| Branch | Tip | Action |
|--------|-----|--------|
| `origin/codex/rev01-integration` | `cf705550` | `git push origin --delete codex/rev01-integration` (stale workflow-setup stub; local `codex/rev01-integration` kept) |

### Skips

None — all 22 delete-verdict refs passed the ancestor/same-tip check.

### Retained

- Local `codex/rev01-integration` (**keep**) and all **harvest** / **harvest (Task B5)** branches remain.
- `lane-*` branches, worktrees under `.claude/worktrees/`, `complete`, and `worldclass` were out of scope.

### Stale remote-tracking prune (same pass)

Removed leftover remote-tracking refs from deleted remotes: `complete-latest`, `complete-local`, `complete-tip`, `local/complete`, `main-complete`, `main-repo/complete`, `mainrepo-complete`, `origin-complete`. Ran `git remote prune origin` (also dropped gone `origin/complete` and `origin/complete-local`). Remaining remotes: `origin/main`, `origin/cursor/cloud-env-linux-02f5`.
