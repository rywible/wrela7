# Loom: a compiler from lived history to safe affordances

**Status:** exploratory design sketch, revision 2 — incorporates one external
review round. Non-normative. Nothing here is a delivery claim; every code
block is illustrative. Every contested call is marked **D1–D27** inline and
collected in §19 with its status (kept / amended / reversed / new) and the
tradeoff that was accepted. The document deliberately leaves no open
questions: where the answer was genuinely uncertain, a default was chosen and
the cost of being wrong is recorded.

## 1. Thesis

An LLM's gigabytes are rent paid for the open world: all of human text
amortized into weights so the model can say something about anything. Wrela
owes none of that rent. The platform has two properties no cloud model has:

1. **A closed, typed operational world.** Every action is a typed capability;
   every visible object is a typed entity. Nonexistent operations and
   ill-typed plans are unrepresentable.
2. **A total, replayable history.** The event store records everything that
   happens, and the system can re-experience any of it deterministically.

One honesty clause up front: the *operational* world is closed, but the
*content* world is not. What a document, photo, or message **means** is
open-world, and pretending otherwise is how hallucination sneaks back in.
Loom therefore keeps a hard membrane between exact system facts and inferred
content facts (§6).

The thesis: **Loom continuously compiles Wrela's event graph into
inspectable concepts, calibrated forecasts, and capability-safe
affordances.** Materialized views over the log are the representation for
memory and concepts — but views are not the intelligence. The intelligence
is the loop: choose what to represent, test what it predicts, identify what
matters to the user, propose actions, and learn from what happens next. Loom
begins almost empty, stays small (megabytes of state, a rounding error of one
core), and becomes deeply specific to the one life lived through the machine.

Non-goals, permanently: open-world question answering, prose generation,
conversation as entertainment, engagement optimization. And the moat, stated
once so the point is never mistaken for an ideology about weights: **the moat
is not "weight-free AI" — it is a deterministic, inspectable, user-specific
compiler from lived history into safe affordances.**

## 2. Principles

- **P1 — Weight-free core, legible knowledge.** Loom's knowledge is counts,
  clauses, automata, views, and programs: inspectable, editable, diffable.
  Learned weights appear only in optional, zero-authority components (the
  parse ranker, §14.5; content extractors, §6).
- **P2 — Deterministic folds under a declared cognitive ABI.** Every learner
  consumes events in a defined order; every update is a function of
  `(state, event)`; every checkpoint carries a `FoldDescriptor` (§12.3)
  naming the code, schemas, feature definitions, numeric mode, and
  dependencies that produced it. "We logged the PRNG seed" is not
  determinism; the descriptor is.
- **P3 — Compute follows surprise; anticipation spends only idle capacity.**
- **P4 — Forecast scores are value-free; attention is value-laden and
  auditable.** Prediction quality is settled with proper scoring rules inside
  typed contracts (§8). Deciding *what to predict, retain, and surface* is a
  value decision, made explicitly by the Attention Allocator (§8.3) with
  inspectable inputs — never smuggled into the scores.
- **P5 — Autonomy is earned per-routine and gated by effect class and
  uncertainty bounds** (§10), never by occurrence counts alone.
- **P6 — Anticipation over conversation.** Conversation text is never system
  state; the evolving typed plan is the state, and a transcript, when useful,
  is a view of it (§14.6).
- **P7 — Local-first.** Personal events never leave the device. Skills
  arrive through a curated ecosystem; anything flowing outward is a separate,
  explicit opt-in (§16).
- **P8 — Provenance, sensitivity inheritance, and an off switch.** Every
  learned artifact records the episodes that created it, inherits the maximum
  sensitivity of its provenance, and can be disabled by the user in one
  action.
- **P9 — Loom is never on the durability path.** A bug in Loom must produce a
  bad suggestion, not an unreadable disk (§5).

## 3. Architecture at a glance

```text
 user ◀──▶ INTERFACE    omnibox · chips · previews · explanations · Mind page (§14, §15)
                │ intent-IR
                ▼
            PATTERNS    routines + effect-gated autonomy (§10)
                │ checked against
                ▼
            POLICY      declared invariants ▸ contextual preference poset (§11)
                ▲ implicit feedback via reversal linkage
                │
  REGISTER ◀─ EXCHANGES ◀─ ALLOCATOR     situation ◀ scored forecasts ◀ attention (§8, §9)
                ▲ features
                │
            GRAMMAR ◀── MEMBRANE         episodes, concepts ◀ content annotations (§6, §7)
                ▲
                │ immutable projection feed (never the durability path)
            CHRONICLE ◀──▶ MIRROR        canonical log (§5) ◀ fork/replay engine (§12)
                ▲
            SENSORIUM                    typed event envelopes from the capability layer (§4)
```

| Component | Plain name | One line |
|---|---|---|
| Sensorium | event contract | typed, principal-attributed envelopes emitted by the capability layer |
| Chronicle | durable memory | canonical log under a boring lossless codec; recall queries; Loom downstream only |
| Membrane | content semantics | exact facts vs. inferred annotations, with source, confidence, sensitivity |
| Grammar | episodes & concepts | segmentation first, mining second; concepts as versioned views with availability tags |
| Exchanges | forecasting | typed forecast contracts, settled prequentially with proper scores |
| Allocator | attention | value-laden, auditable allocation of compute and retention |
| Register | situation | the OS's "now" as a sparse set of calibrated, decision-relevant forecasts |
| Patterns | habits | mined routines promoted by effect class and uncertainty bounds, compiled to native code |
| Policy | values | declared invariants above a contextual preference poset; evidence-classed causality |
| Mirror | imagination | one deterministic fork/replay engine; preview, dreaming, speculation, reconstruction |
| Metabolism | scheduler | surprise-driven budgets; speculation at idle under power caps |
| Ledger | self-knowledge | four separated streams; the mind has a commit history without eating the log |
| Interface | language | an intent compiler with a risk-adaptive surface, not a chatbot |
| Instincts | cold start / fleet | curated skill ecosystem in; explicit opt-in export path out |

## 4. Sensorium: the event contract

Intelligence quality is decided here, before any learning code exists. The
canonical envelope:

```text
EventEnvelope {
    id: EventId,
    log_index: u64,          // storage order — not cognitive meaning (§4.2)

    wall_time: Instant,
    monotonic_time: Duration,

    principal: PrincipalId,
    actor: User | App | System | Remote,
    initiated_by: DirectUser | DerivedUserIntent | Routine | App | External,

    transaction: TransactionId?,
    caused_by: Set<EventId>, // guaranteed within capability call chains and
                             // transactions; best-effort across async
                             // boundaries, timers, and remote responses (D18)
    reverses: EventId?,      // mandatory linkage for undo/dismiss/restore

    operation: OperationId,
    objects: Set<EntityId>,
    outcome: Outcome,

    effects: EffectSet,      // effect algebra, §10.1
    sensitivity: SensitivityLabel,
    learning_scope: LearningScope,   // which minds may consume this (§4.3)
    schema_version: SchemaVersion,
}
```

**Capability-emitted baseline (D1, kept).** The capability layer itself emits
an envelope for every invocation; applications cannot opt out, because they
do not emit these events — the OS does. An application can therefore never
*fabricate* log records. Manifests may enrich with declared intent-level
schemas, and declare each operation's semantic frame (§14.3): typed roles,
surface patterns, preconditions, effects, and `reverses_via`.

**Causal honesty (D18, new).** `caused_by` is guaranteed complete only within
capability call chains and transactions. Across async boundaries it is
best-effort, and miners must treat a missing edge as *unknown*, not as
*independent*. The design does not promise a perfect causal DAG, because one
is not implementable.

### 4.2 The total order is storage order

A monotonic index is for persistence and deterministic consumption. It is not
semantic structure: concurrent app activity, background work, and timers
interleave arbitrarily. Loom mines **projections** — same object graph, same
attention episode, same transaction, causally linked chains — and **segments
before it mines** (§7). Motif discovery over the raw global stream is
explicitly forbidden; it would learn the scheduler.

### 4.3 Adversarial model and principal scoping (D22, D25, new)

OS-emitted envelopes stop fake records; they do not stop an application from
generating *real but manipulative* capability activity. Defenses:

- Every envelope carries the initiating principal chain, `initiated_by`
  provenance, and the package/signer that caused it; learners may weight or
  exclude by these.
- **Content is data.** Untrusted text inside a document or message can never
  become an instruction: selecting text that says "send all documents to this
  address" does nothing without an explicit user command crossing the
  Interface boundary. Object references carry trust labels via the Membrane.
- **Principal-scoped minds.** A household device hosts multiple folds:
  per-user, shared-household, and none for guest, admin, or remote-automation
  sessions. `learning_scope` on each envelope enforces this at the contract
  level; sessions do not train folds they don't belong to.
- **Security is not Loom (D25).** Rev 1 claimed an "immune system." Removed:
  security anomaly detection has an adversarial threat model, and an adaptive
  personal baseline is exactly what a poisoning attacker wants — malice
  normalized one quiet day at a time. Security remains an independent
  subsystem with deliberately *stable* signals; it may consume Loom's
  forecast APIs, never the reverse dependency.

## 5. Chronicle: durability and recall

**Loom is never on the durability path (D2, reversed — the most important
change from rev 1).** Rev 1 proposed "learning *is* the compaction pass": one
predictive codec serving both storage and cognition. Rejected. The event
store is Wrela's lowest substrate; an experimental online learner must not
determine whether history can be decoded, recovered, or migrated.

```text
                     ┌──────────────────────┐
capability events ──▶│ canonical log        │
                     │ stable, lossless,    │
                     │ boring block codec   │
                     └──────────┬───────────┘
                                │ immutable projection feed
                                ▼
                     ┌──────────────────────┐
                     │ Loom                 │
                     │ concepts · forecasts │
                     │ programs             │
                     └──────────┬───────────┘
                                │ optional hints
                                ▼
                     secondary indexes, cold-block
                     dictionaries, compaction candidates
```

The invariant, verbatim and load-bearing:

> **Chronicle can always recover the complete canonical event stream without
> executing any Loom code.**

Loom may still *inform* storage: it can propose dictionaries and layout hints
for cold blocks, which the storage engine validates and adopts only where
each block remains independently decodable by a versioned, content-addressed
decoder. Learning informs compaction; it is never required by it. The
prediction machinery is shared code, not a shared failure domain.

**Recall** ships on day one, before any learning: exact, typed queries over
history ("when did I last change this setting", "everything I did around the
time I removed garbage collection") — expressible from the first release
because the query surface arrives in Phase 1 (§20), not after the learners.

**Erasure by refold (D3, kept).** Deleting events is first-class: dependent
artifacts are refolded from the nearest checkpoint with the deleted range
excluded — influence removal, not just data removal. Background job, 24-hour
SLA, executed under the checkpoint's `FoldDescriptor` (§12.3).

## 6. Membrane: exact facts, inferred meaning (D17, new)

The capability graph makes *actions* finite. It does not make "foundation
damage" or "decided against tracing GC" free to ground. The Membrane keeps
system facts and content interpretation permanently distinct:

```text
Exact fact:                              Inferred annotation:
    document.owner    == User                section.topic  ~= MemoryOwnership   p=0.78
    document.opened_at == T                  edit.intent    ~= RejectTracingGC   p=0.61
    section.heading   == "Ownership"
```

```text
Annotation {
    subject: EntityId,
    predicate: ConceptId,
    value: EntityId | Scalar | TextSpan,
    source: Declared | UserNamed | StructuralParser
          | Extractor | BehavioralInference,
    confidence: Probability?,
    provenance: EventSet,
    sensitivity: SensitivityLabel,
    valid_during: Interval?,
}
```

Rules:

- Intent programs may type-check against either kind, but inferred predicates
  carry their uncertainty into grounding, preview, and explanation — a plan
  built on a 0.61 annotation *shows* it.
- `BehavioralInference` (objects co-active in the same episodes are related)
  is the weight-free default source. `Extractor` slots exist for optional
  perception/text packs under the same zero-authority pattern as the parse
  ranker: they may only write labeled, sourced annotations, never act.
- Annotations inherit provenance sensitivity (P8): a concept learned from
  private messages does not surface in a general explanation context merely
  because its definition contains no plaintext.

This yields the honest hallucination claim: **nonexistent capabilities are
unrepresentable; ill-typed plans are unrepresentable; semantic misgrounding
remains possible and is exposed, not denied.**

## 7. Grammar: episodes and concepts

**Segment first, mine second (D18).** Miners run over projections — object
graphs, attention episodes, causal chains, transactions — never the raw
interleaved stream. Concrete algorithms (Sequitur-style online grammar
induction, anti-unification/library-learning passes at idle) are *candidate
implementations* living in `loom-lab` (§Appendix A), not architecture.

A **concept** is a versioned, executable view over the event graph, with an
explicit temporal availability tag (D27, new):

```text
concept FocusedWorkSession/v3 {
    availability: Retrospective,   // end is knowable only ~12m after the fact
    begins_when:     editor.active && notifications.mode == quiet,
    continues_while: edit_rate > τ₁ || compile_events > τ₂,
    ends_when:       idle > 12m || communication.active > 3m,
}
```

`PrefixSafe` concepts may feed online forecasting. `Provisional` may feed it
with later revision events. `Retrospective` concepts are for recall and
analysis and are **excluded from replay evaluations of anything
promotion-relevant** — using them there leaks the future and silently
inflates precision.

Survival is decided by the Allocator (§8.3), not by any single score:

```text
survives if:  predictive_gain > θ₁
          OR  decision_contribution > θ₂     (measured by counterfactual replay:
                                              did removing it change a chosen plan,
                                              clarification, or abstention?)
          OR  user_usage > θ₃
          OR  user_pinned
          OR  safety_sentinel
```

Forgetting is archiving a view; the underlying history is never destroyed.

## 8. Exchanges and the Allocator: prediction

Rev 1 had one "market." Rev 2 splits the epistemic and value boundaries
correctly (D4, amended; D19, new).

### 8.1 Typed forecast contracts

Predictors compete only inside contracts whose target semantics they
implement:

```text
ForecastContract NextEventInEpisode { target: EventType,  horizon: 1.event,   score: LogLoss }
ForecastContract UndoAfterPlan      { target: Bool,       horizon: 10.minutes,
                                      condition: CandidatePlan,               score: LogLoss }
ForecastContract ReturnToObject     { target: TimeToEvent, horizon: 48.hours, score: SurvivalScore }
ForecastContract EpisodeContinues   { target: Bool,       horizon: 30.minutes, score: BrierScore }
```

Each contract tracks baseline, calibration, coverage, prequential score,
resource cost, and exposure regime. **Evaluation is chronological
(prequential): predict, record, observe, settle.** Historical replay screens
candidates only — and never with `Retrospective` features (§7).

### 8.2 Performativity (D19)

Once Loom surfaces a suggestion, the prediction can cause the event it
predicted, and a theory can look increasingly right because Loom trained the
user into following it. Every exposure is logged —

```text
policy_id · candidate_set · was_shown · display_position
selection_probability · user_response · resulting_events
```

— and every contract keeps **separate scores for shadow predictions, exposed
suggestions, and autonomous actions.** Promotion decisions read the shadow
score.

### 8.3 The Attention Allocator (D4)

Scores are value-free; attention is not, and pretending otherwise just hides
the value function. The Allocator decides which contracts exist, which
theories get memory, which rare distinctions are preserved, and which
concepts are retained — from inspectable inputs: decision relevance, user
usage, risk, resource cost, declared priorities, and the survival rule of §7.
A model that predicts frequent worthless events brilliantly while dropping a
rare distinction that changes an important decision is an Allocator failure,
and the Allocator is where it is fixed.

**Bits-per-event is demoted to a developer diagnostic named *stream
predictability* (D26, new).** It is schema-sensitive and misreadable — a new
hobby raises it because the user is growing, not because Loom got worse.
User-facing progress is measured in outcomes: successful anticipation rate,
suggestion correction rate, undo/regret rate, time-to-resume, and routines
still enabled after 30 days.

## 9. Register: situation as predictions (D5, kept)

The OS's *now* is a sparse, typed set of calibrated forecasts drawn from the
Exchanges — predictive state, not latent state:

```text
register = {
    P(editor opened within 60s)           = 0.83,
    P(current task survives interruption) = 0.41,
    P(session ends within 10m)            = 0.12,
    E(interruption cost)                  = high,
    ...  ≤ 256 slots
}
```

A forecast earns a slot by being decision-relevant — actually consulted by
Patterns, the Interface, or the Metabolism — and is evicted on disuse. Only
`PrefixSafe`/`Provisional` features may feed it. Hidden-state models are
welcome as implementations behind contracts; they are not the semantics.
*Accepted cost:* no unified latent world-model and no completeness guarantee;
a validated bag of predictions is buildable and auditable.

## 10. Patterns: routines and effect-gated autonomy

### 10.1 The effect algebra (D20, new — replaces `reversible: bool`)

Reversibility is not binary: opening a message fires a read receipt; opening
an app steals focus during a presentation; a restorable delete may be
socially irreversible.

```text
Effect =
    Pure
  | LocalMutation { compensation: OperationId,
                    fidelity: Exact | Approximate,
                    expires_after: Duration? }
  | ForegroundAttention
  | ExternalObservable
  | Communication
  | Financial
  | Destructive
  | CredentialUse
  | PhysicalWorld
```

Every operation declares its effect set in the manifest; envelopes carry it;
plans aggregate it.

### 10.2 Promotion (D6, amended)

Mined candidates (from segmented episodes, generalized with typed parameters)
face a replay battery on the Mirror — would-have-fired precision and recall,
counterexample search, undo estimate, Policy check, capability check — with
prequential shadow evaluation after screening. Rev 1's fixed gates ("5
occurrences at 0.80 precision") were statistically weak: 4-of-5 *is* 0.80
with enormous uncertainty. Rev 2 gates on effect class and uncertainty
bounds; occurrence floors remain necessary but never sufficient.

```text
auto_prepare      allowed for Pure effects and invisible derived state
auto_commit       requires upper_bound(P(regret)) < risk_budget(effect_set)
                  (conservative posterior bound, e.g. Jeffreys, on the
                  routine's shadow contract)
foreground change requires an explicit per-routine user grant
ExternalObservable | Communication | Financial | Destructive
| CredentialUse | PhysicalWorld
                  staged + confirm, forever — no trust level unlocks these
```

Initial risk budgets (calibration constants, expected to be tuned by wedge
metrics, §17): `LocalMutation/Exact` 5%, `LocalMutation/Approximate` 2%,
`ForegroundAttention` 1% *and* a grant. The ladder of visible standing —
shadow → suggest → user-invoked macro → guarded (undo toast) → granted —
survives from rev 1 as the *presentation* of these gates, with demotion on
drift via the same bounds with hysteresis. Every routine carries provenance
and a one-action off switch (P8).

Accepted routines are ordinary Wrela programs: intent-IR lowers through
`semantic-wir → flow-wir → machine-wir` to native code (D14, kept). The OS
recompiles its habits.

## 11. Policy: invariants, preferences, causality

Renamed from rev 1's "Lattice," which was not one (no meets/joins;
learned contextual preferences can even cycle) (D7, amended).

- **Declared invariants** live in the capability system, not in learning
  (`never_send_without_confirmation`, quiet rules). The learned layer
  structurally cannot override them — the check is in intent-IR's types.
- **Learned preferences** form a *contextual preference poset*: scoped pairwise
  rules mined chiefly from the Sensorium's reversal linkage (undo, rapid
  reversal, dismissal, repeated acceptance), each admitted after ≥4
  independent, time-decayed evidence events.

```text
when FocusedWorkSession && weekday:  QuietNotifications ≻ ImmediateDelivery
when AwaitingCriticalReply:          ImmediateDelivery  ≻ QuietNotifications
```

No global transitive closure across contexts. Cycles or incomparable
candidates resolve to **inaction** (or a question, if the Interface is
already open) — predictability over helpfulness, accepted.

**Causality is evidence-classed (D8, amended).** Every learned relationship
carries one of:

```text
Association | NaturalExperiment | LoggedRandomization
| UserDeclared | MechanisticallyGuaranteed
```

Explanations are language-gated by class: *"messages are associated with
shorter sessions in this context"* until the evidence permits more. Natural
experiments in the log are mined continuously but treated as confounded by
default. Active experiments remain: globally opt-in, reversible-only, ≤1/day,
ledgered, with behavior policy and exposure probabilities logged so
off-policy estimates aren't silently biased. They are a last resort, never a
default.

## 12. Mirror: forks and replay

One deterministic fork/replay engine; forks are pure by construction —
effectful capabilities are absent from the fork context's capability set, so
external effects in a fork are a type error.

### 12.1 Consumers

| Consumer | What it does |
|---|---|
| Preview | every intent program simulated on a fork before commit |
| Dreaming | idle screening of candidate concepts/routines against history (then prequential shadow) |
| Speculation | precompute likely-useful derivations so the chosen future is warm |
| Reconstruction | reproduce past beliefs; counterfactual refolds (erasure, §5) |

### 12.2 Speculation (D9, amended)

Rev 1's fixed 8/2/0 fork policy was a placeholder pretending to be a
decision. Speculation is now scheduled by expected value —

```text
speculation_value = P(branch) × latency_saved × P(result_used)
                    − energy_cost − memory_cost − staleness_cost
```

— **under hard power-state ceilings kept from rev 1** (mains+idle ≤8
concurrent speculative derivations, battery ≤2, low battery 0), because
predictable energy behavior is a product property of an appliance, not an
optimizer input. Most speculative work is a precomputed query, a materialized
workspace projection, resolved references, a warmed render, or a prepared-
but-uncommitted plan — not eight coherent future operating systems. Branches
share structure via persistent snapshots; speculative caches respect
sensitivity partitions.

**Preview honesty:** a fork proves the exact local diff and deterministic
derived state; it can state an expected external effect; it cannot know a
remote outcome. Previews label all four kinds distinctly — a fork can prove a
plan *sends* a message, never how the recipient responds.

### 12.3 The cognitive ABI (P2; D3 amended)

Bit-reproducible folds need more than a seed. Every checkpoint carries:

```text
FoldDescriptor {
    learner_code_hash, schema_set_hash, feature_definitions_hash,
    numeric_mode, scheduler_version, dependency_snapshot,
}
```

Two distinct operations, answering different questions:

```text
reconstruct_exactly   "What did Loom believe on March 4?"
                      → run the historical fold implementation under its descriptor
reinterpret           "What would today's Loom conclude from history through March 4?"
                      → run current learners over historical events
```

Migration to new hardware is therefore not "free via replay": it requires
either a compatibility runtime for old fold implementations or a defined
artifact migration. Wrela ships the compatibility runtime (the descriptor
pins it); artifact migration is the escape hatch when a learner is retired.

## 13. Metabolism: budgets

Surprise is the scheduler: per-event work is tiered by prediction error, and
deep machinery (theory spawning, re-mining, consolidation) activates on
surprise, disagreement, novel event types, repeated correction, or Allocator
request.

| Tier | Steady state | Surprise burst | Idle (dreaming/speculation, mains) | Loom RAM |
|---|---|---|---|---|
| minimal | ≤0.5% of one core; ≤20µs/event typical | ≤2ms/event | ≤10% core | ≤16 MB |
| standard | ≤1% of one core | ≤2ms/event; ≤25% core ≤1s | ≤20% core | ≤96 MB (+ ≤16 MB optional parse ranker) |

These are budgets, not estimates: the Allocator degrades (drop contexts,
retire theories, archive views) to stay inside them. Assumed load: ≤200
events/s sustained, 2k/s burst.

## 14. Interface: the intent compiler

LLMs bundle parsing, world knowledge, and deciding. Wrela unbundles them: the
event graph is the knowledge, Loom is the deciding, and language is a thin,
honest compiler in between. The surface is an omnibox fused with direct
manipulation — selection defines scope, grounded arguments become editable
chips, dragging an object binds a referent, a prior episode can be inserted
as an example, and uncertainty is shown **on the specific slot**, not the
whole command.

### 14.1 Pipeline (D10, amended)

```text
utterance
  → deterministic grammar produces type-correct AST candidates
      (grammar-beam with fuzzy lexical anchoring over manifest frames + dialect)
  → compact ranker orders candidates                       (optional pack, §14.5)
  → grounding scores against selection, Register, episodes (exact facts and
                                                            labeled annotations, §6)
  → confidence calibration
  → risk-adaptive interaction                              (§14.4)
```

Dialogue is constraint accumulation: "not the LLVM ones" edits the typed
query; sentence and structure are two views of one program, and the user may
edit either.

### 14.2 intent-IR (D14, kept)

A small front-end WIR dialect lowering into `semantic-wir`:

```text
SELECT · FILTER · RELATE · COMPARE · GENERALIZE · SIMULATE · ACT · EXPLAIN · NAME
```

`GENERALIZE` powers analogy commands — "set this up like the parser rewrite"
is episode retrieval + generalization + substitution + preview — the most
differentiated language capability this platform has, because no other system
holds the user's exact history.

### 14.3 Semantic frames, not alias lists

Aliases don't encode argument roles, prepositions, ellipsis, or salience.
Manifests declare frames:

```text
operation MoveDocument {
    frame: MOVE { theme: Document, goal: Collection },
    surface_patterns: ["move {theme} to {goal}",
                       "put {theme} in {goal}",
                       "file {theme} under {goal}"],
    preconditions: [...],
    effects: [LocalMutation { compensation: RestoreLocation, fidelity: Exact }],
}
```

The parseable language is generated from installed frames; nothing outside
the capability graph can be expressed.

### 14.4 Risk-adaptive interaction

Preview-everything is replaced by a policy keyed to confidence and effects:

```text
high confidence + pure query                  execute immediately
high confidence + local reversible mutation   concise preview, or act with undo
medium confidence                             show the interpreted plan
low confidence                                paraphrase the program; ask
external / destructive effects                confirm critical arguments
                                              regardless of parser confidence
```

### 14.5 The parse ranker (D10)

The weight-free path is the foundation and must be complete alone: grammar,
frames, dialect, chips, repair (every correction teaches). The optional pack
is a **candidate ranker, not a program generator** — ≤16 MB, CPU-only, zero
authority: it orders grammar-produced ASTs and trains its ranking weights and
phrase→fragment mappings on the user's corrections. Honest caveat: grammar
enumeration can blow up on long free-form utterances; the beam plus lexical
anchoring prunes, slot-level clarification is the floor, and if coverage
plateaus a constrained sequence *proposer* may be added later behind the same
zero-authority boundary (ceiling 48 MB). That would be a lexer upgrade, not a
mind.

### 14.6 Dialect, conversation, and output honesty

`NAME` bindings are scoped and versioned:

```text
"compiler mode"  { scope: user, context: Work, meaning: Routine/7, version: 3 }
```

An established phrase's meaning is **never silently changed**: Loom proposes
a new version and shows the difference. Conversation may render as a
transcript when repair is genuinely conversational — but the transcript is a
view over the evolving typed plan, never opaque state (P6).

Output uses no generative model: explanations render from proof traces
through a small evidence grammar (claim, evidence, confidence, exception,
suggestion) —

> You usually open this diagnostics checklist after compiler tests fail —
> 9 of your last 11 compiler sessions. The tests failed a minute ago.

— and the guarantee is stated precisely (D11, amended): **faithful to the
system's evidence and current belief.** A proof trace can be faithfully
verbalized and still rest on a wrong concept or a spurious association; the
evidence class (§11) and annotation confidence (§6) therefore travel into the
wording.

## 15. Ledger: four streams and the Mind page (D21, new)

"Every cognitive act is a Chronicle event" invited write amplification and
reflexive learning (the mind studying its own bookkeeping). Rev 2 separates
logical streams:

```text
world/     user, application, capability, and external observations
control/   proposed, previewed, committed, and reversed plans
belief/    artifact admission/promotion/demotion/deletion, checkpoints,
           preference changes, dialect versions
audit/     explanations shown, grants, corrections, experiments, exposures
```

Ordinary count increments and posterior updates are deterministic derived
state — reproducible from `world/` under a `FoldDescriptor` — and are **not**
individually durable events. Persisted: behavior-affecting changes, artifact
lifecycle, predictions that caused an intervention, corrections, snapshots.
Learners consume `world/` (and `control/` where contract-relevant); consuming
`belief/` or `audit/` requires explicit subscription, so the mind does not
learn the rhythms of its own bookkeeping by accident.

**The Mind page** (browse and edit): pin or delete a habit, edit a concept
definition, review provenance and evidence class, grant or revoke per-routine
autonomy, read the experiment and exposure ledgers, and see progress as
outcomes (anticipation rate, correction rate, undo rate, time-to-resume,
30-day retention — §8.3). Both replay questions are exposed to the user in
plain form: *what did you believe then* (reconstruct) and *what would you
believe now* (reinterpret). Edits are events; teaching is part of history.

## 16. Instincts: cold start and the curated skill ecosystem (D12, amended)

Devices ship with **instinct packs** — routine templates, clause sets,
concept templates with declared capability requirements, evidence schemas,
and safety invariants — evaluated on the Mirror against local history and
promoted through the same gates as native routines. No shortcuts.

Rev 1 called the default "fleet evolution." That was dishonest: import-only
means no selection signal returns, so the shared population cannot evolve.
Stated plainly now:

- **Default: a curated skill ecosystem.** Import-only; nothing leaves the
  device — not acceptance counts, not anonymized telemetry.
- **Optional: an explicit export protocol.** Opt-in sharing of *generalized
  artifacts and evidence summaries* (never events, never content), k-anonymous
  at the population level, signed. Only when this path is enabled may the
  word "evolution" be used, because only then does selection information flow
  back.

## 17. The first wedge: the resume capsule (D24, new)

The first Loom product is one end-to-end interaction:

> *Pick up Wrela where I left it yesterday.*

1. Segment yesterday's work episode (§7).
2. Identify the active project's object graph.
3. Record workspace state, recent edits, unresolved diagnostics, references.
4. Compile a restore plan in intent-IR.
5. Preview it on a fork (§12) — every step labeled by effect class.
6. Restore only `Pure`/`LocalMutation`-exact state.
7. Learn the user's phrase for it (`NAME`: "compiler mode").
8. Measure whether restored objects were actually used.
9. Explain, on demand, exactly why each object was restored.

It exercises the envelope, segmentation, intent-IR, Policy, Mirror, codegen,
dialect, and the Mind page — with no open-world intelligence and no
autonomy. Its metrics are the product thesis, measured:

```text
time_to_resume · fraction_of_restored_objects_used · objects_user_had_to_add
objects_user_immediately_closed · plan_correction_count
routine_retention_after_30_days · CPU / RAM / energy · replay reproducibility
```

## 18. Boundaries and failure modes

**What Loom will never do:** answer open-world questions, write prose,
discuss a book it has never seen. If Wrela ever wants reference knowledge,
the sanctioned path is curated offline knowledge packs with exact retrieval —
a library, not a mind — and it is out of scope here.

| Risk | Mitigation |
|---|---|
| Creepiness | effect-gated autonomy (§10), inaction default (§11), Mind page, consent-gated experiments |
| Loom bug corrupts durability | impossible by construction: Chronicle recovers without Loom (P9, §5) |
| Semantic misgrounding | Membrane: sourced, confidence-labeled annotations; uncertainty surfaces in preview and wording |
| Replay leakage inflates promotion | availability tags (§7); prequential shadow scores gate promotion (§8) |
| Self-fulfilling predictions | exposure logging; shadow/exposed/autonomous score separation (§8.2) |
| Poisoning via real-but-manipulative activity | principal attribution, content-as-data boundary, principal-scoped minds (§4.3); security independent (D25) |
| Concept drift | decay everywhere; demotion by the same bounds with hysteresis |
| Write amplification / reflexive learning | stream split; derived state not durably evented; no self-subscription by default (§15) |
| Storage growth | canonical codec owns durability; Allocator evicts artifacts; views archived |
| Battery | Metabolism gates; EV speculation under power ceilings (§12.2) |
| Parser distrust | zero-authority ranker; grammar-only candidates; risk-adaptive confirmation (§14) |
| Learning bug corrupts the mind | deterministic folds + FoldDescriptor: roll the mind back without touching history |

## 19. Decision register

| # | Status | Decision | Accepted cost |
|---|---|---|---|
| D1 | kept | capability layer emits baseline envelopes; apps enrich via declared frames | coarser baseline than ideal app intent |
| D2 | **reversed** | rev 1's "learning *is* the compaction pass" rejected; Loom never on the durability path; canonical boring codec; Loom proposes cold-block dictionaries only (versioned, content-addressed, independently decodable) | loses the unified-mechanism elegance; part of the storage win deferred |
| D3 | amended | erasure = refold from checkpoints, 24h SLA, under FoldDescriptor | checkpoint storage + refold compute |
| D4 | amended | proper scores inside typed contracts; Attention Allocator is the explicit, auditable value layer | two mechanisms instead of one currency |
| D5 | kept | predictive state is the semantics; latent-state models are implementations | no completeness guarantee |
| D6 | amended | promotion by effect class + conservative posterior bound on regret vs. per-class risk budgets; count/time floors necessary but never sufficient; outward effects staged+confirm forever | harder math; slower autonomy for risky effects |
| D7 | amended | "Lattice" → Policy: declared invariants + *contextual preference poset*; no global closure; cycles/incomparability ⇒ inaction | forfeits some helpfulness |
| D8 | amended | natural experiments treated as confounded; evidence classes gate causal language; active experiments opt-in, ≤1/day, ledgered with exposure probabilities | slower causal learning |
| D9 | amended | speculation scheduled by expected value, capped by power state (≤8 / ≤2 / 0); derivations, not whole futures | fewer warm hits on battery |
| D10 | amended | parser pack is a candidate *ranker* (≤16 MB, zero authority) over grammar-produced ASTs; constrained proposer only if coverage plateaus (ceiling 48 MB) | possible early-days stiltedness; enumeration limits on long utterances |
| D11 | amended | output guarantee stated as "faithful to the system's evidence and current belief" | admits faithful-but-wrong verbalization exists |
| D12 | amended | default is a *curated skill ecosystem* (import-only, zero telemetry); "evolution" claimable only with the explicit opt-in export protocol | weaker collective signal by default |
| D13 | kept | one Mirror engine serves preview, dreaming, speculation, reconstruction | fork purity is a hard early platform requirement |
| D14 | kept | intent-IR is a WIR dialect lowering to `semantic-wir`; habits compile to native | front-end dialect work in the toolchain |
| D15 | kept | VSA/hyperdimensional memory deferred, index-only if ever; HTM and spiking layers rejected | one fewer paradigm; revisit on evidence |
| D16 | kept | subsystem named Loom; components renamed where math demanded (Policy, Exchanges, Allocator, Membrane) | whimsy in a systems doc |
| D17 | new | semantic membrane: exact facts vs. sourced, confidence-labeled annotations; misgrounding exposed, not denied | admits the content world is open |
| D18 | new | causal envelope; `caused_by` guaranteed only within capability chains/transactions; log_index is storage order; segment first, mine second | miners must handle unknown edges |
| D19 | new | typed forecast contracts, prequential settlement, exposure logging, shadow/exposed/autonomous score separation | more bookkeeping per prediction |
| D20 | new | effect algebra replaces `reversible: bool` | manifest authors must classify effects |
| D21 | new | ledger split (world/control/belief/audit); derived updates not durably evented; no self-subscription by default; sensitivity inheritance | some introspection requires recomputation |
| D22 | new | principal-scoped minds; `learning_scope` on every envelope | multiple folds to maintain on shared devices |
| D23 | new | three stable ABIs (EventGraph, Artifact, Plan); algorithms are replaceable `loom-lab` candidates; six starter crates | less concrete guidance to implementers up front |
| D24 | new | the resume capsule is the first deliverable; product metrics outrank prediction metrics | narrow first release |
| D25 | new | security anomaly detection removed from Loom core; independent subsystem may consume forecast APIs | no "immune system" story |
| D26 | new | bits-per-event demoted to developer diagnostic ("stream predictability"); user-facing progress is outcome metrics | loses a cute dial |
| D27 | new | concept availability tags (PrefixSafe/Provisional/Retrospective); retrospective features banned from promotion-relevant replay | some rich concepts unusable for forecasting |

## 20. Phasing

Reordered from rev 1, which had a real dependency bug (Patterns required
Mirror one phase before Mirror existed) and starved early learners of
corrections by shipping the Interface last. Each phase still ships standalone
value.

| Phase | Ships | Proves |
|---|---|---|
| 0 — constitutional substrate | event envelope, causal linkage, principal attribution, effect algebra, sensitivity propagation, schema evolution, deterministic fold harness, first intent-IR types. **No learning.** | the contract that cannot be retrofitted |
| 1 — recall + language skeleton | exact recall, structured temporal queries, selection-grounded omnibox with editable chips, `EXPLAIN`, basic Mind/audit surface | the event contract is actually useful; queries expressible day one |
| 2 — Mirror + explicit teaching | fork preview, explicit macros, demonstration, `NAME`, compiled routines invoked only by the user | intent-IR, Policy checks, replay, and codegen — before any mining |
| 3 — ambient discovery, suggest-only | episode segmentation + one conservative miner; **resume capsule complete (§17)** | the wedge; the product thesis, measured |
| 4 — forecast contracts + anticipation | Exchanges, Register, surprise scheduling, speculative materialization; a count/context-tree baseline measured before any heterogeneous zoo | anticipation |
| 5 — contextual preferences + guarded autonomy | preference poset, posterior-bound promotion/demotion, per-routine grants | earned autonomy |
| 6 — skills and sharing | curated ecosystem; the opt-in export protocol | the fleet path, honestly named |

## Appendix A: stable ABIs and starter crates (D23)

The 2026 algorithm shortlist (context-tree/count baselines first; PPM,
Alergia-style automata, Sequitur, anti-unification library learning, Tsetlin
clause sets, temporal point processes, small Bayes nets, reservoirs as
candidates) must not fossilize into the architecture. The stable contracts:

```text
EventGraph ABI   typed observations, causality, objects, principals, sensitivity
Artifact ABI     concepts, forecasts, segmentations, candidate plans —
                 with provenance, calibration, availability, validity, cost
Plan ABI         intent-IR, effect sets, policy proof, preview, execution
```

Plugin surfaces:

```text
theory:   subscribe(contract) · predict(prefix) → Distribution
          observe(outcome) · checkpoint() · explain(prediction) → Evidence
          resource_usage()

miner:    propose(event_graph_projection) → ConceptCandidate
          incrementally_maintain(view) · estimate_online_availability()
          explain_membership(episode)
```

Starter crates — split only when real dependency boundaries emerge:

```text
wrela-loom-core      event/artifact/plan contract types
wrela-loom-runtime   folds, scheduling, checkpoints, FoldDescriptor
wrela-loom-lab       replaceable learners and miners
wrela-loom-intent    intent-IR, frames, grounding
wrela-loom-policy    effects, invariants, preference poset
wrela-loom-ui        command surface, previews, Mind/audit views
```

Integration touchpoints: `wrela-package` (manifest frames, effect
declarations), `wrela-semantic-wir` (intent-IR lowering target), and the
standard `semantic-wir → flow-wir → machine-wir → codegen` pipeline for
compiled routines.
