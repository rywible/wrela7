# The sealed scene: UI as a compiled, parameterized image

**Status:** exploratory design sketch, revision 4 — incorporates two external
review rounds and adds the audio stream. Non-normative. Not part of revision
0.1. Nothing here is a delivery claim; every code block is illustrative.

## 1. Thesis

The load-bearing invention is this: **UI structure is a sealed, parameterized
scene, compiled into a renderer.** Implicit fields are the certified geometry
mechanism inside that architecture — powerful, and the sole geometry mechanism
in the first revision — but they are a technique the architecture uses, not a
premise it depends on. The two ideas are deliberately separable so that no
future rendering concern has to prove it is secretly a distance field.

Frame semantics are one function:

```text
render(ScenePlan, FrameParams, RasterSpec) -> PixelGrid
```

- **`ScenePlan`** — immutable, image-static structure: the geometry/paint
  expression DAG, parameter slot layout, bounded pools, baked assets. Built by
  comptime code and sealed, exactly like the image graph.
- **`FrameParams`** — a fixed-layout, immutable snapshot of one frame's
  parameter values.
- **`RasterSpec`** — dimensions, pixel format, color space, sample and filter
  rules, quality level. The spec is versioned: a different filter rule or
  quality level is a different `RasterSpec`, and the frame's identity includes
  it (section 8).
- **`PixelGrid`** — the deterministic result.

The written numerical and raster contract (sections 7 and 14) is the normative
definition of this function. A slow, simple **reference renderer** implements
it directly and serves as the **canonical conformance oracle** — the
executable against which every optimized renderer is differentially tested.
The prose contract wins conflicts, so a defect in the oracle is a findable
bug, not a definition.

Honesty about reconciliation: runtime work does exist — parameter comparison,
tile invalidation, buffer repair. The claim is not "no reconciliation"; it is
that reconciliation is **fixed-shape and compiler-generated** from build-time
dependency analysis. No runtime framework maintains a dynamic dependency
graph, and the programmer never directs invalidation. Mainstream UI's
impedance mismatch comes from putting that machinery at runtime inside a
framework; wrela's closed world moves it to build time inside the compiler,
where it becomes ordinary whole-image optimization with a report.

The resulting split is wrela's existing phase split:

- **Structure is comptime.** The scene plan is to a frame what the image
  graph is to boot.
- **State is runtime and imperative.** Plain actor code mutates plain state.
  No hooks, no effects system, no hidden re-render triggers.
- **Rendering is generated.** The compiler lowers the sealed plan to a
  specialized evaluator, the way it lowers async functions to state machines —
  and, like every async function, that evaluator is checkpointable (section 3).

The same contract shape covers the image's second stream: audio (section 10)
is the one-dimensional instance of it — sealed structure, typed runtime
triggers, a pure sample function, versioned sampling contract, typed
degradation — drained at 48 kHz instead of 120 Hz.

## 2. What the design must deliver

1. CPU-only rendering into a framebuffer, presented via virtio-gpu on the
   reference target.
2. A 120 Hz frame cadence: 8.33 ms of budget per frame, with typed,
   admission-time behavior when the budget cannot be met.
3. Implicit-field geometry as the certified shape mechanism —
   resolution-independent, composable, consistently filtered.
4. A surface language humans and coding assistants can reason about without
   fighting a paradigm: not runtime-reconciled declarative trees, and not
   per-pixel math soup.
5. Deterministic output: the renderer never presents a partially rendered
   buffer, filtering is consistent everywhere, and color handling is correct
   end to end.
6. 2D now, with a shape algebra and scene philosophy that extend to 3D.
7. An audio stream under the same contract discipline — bounded mixing,
   typed underrun policy, deterministic replay — with authoring quality
   explicitly scoped out (section 10).

## 3. Plan, instance, and snapshot

Three artifacts with distinct ownership:

- **`ScenePlan`** — immutable image-static structure, sealed at comptime.
- **`SceneInstance`** — app-owned mutable parameter storage and bounded
  pools; ordinary actor state.
- **`FrameParams`** — an immutable snapshot of the instance, taken once per
  frame from a bounded snapshot pool and *moved* across the presentation
  boundary.

The snapshot is not a convenience; it is what makes the design legal wrela.
A cross-actor call cannot borrow app-owned state — views do not cross actor
boundaries, and non-scalar payloads must be copied, moved, or `iso`. The
snapshot is the explicit, fixed-layout value that crosses. It is also,
non-coincidentally, the correct unit for replay, frame comparison,
cancellation, reporting, and future multicore rendering.

The frame turn is honest imperative code:

```wrela
# Illustrative only.
@app
class Kiosk:
    scene: KioskInstance         # mutable parameters + bounded pools
    cart: Cart
    press: Spring

    async fn frame(mut self, input: InputBatch, dt: Duration):
        for event in input.events:            # bounded: typed input messages
            self.apply(event)
        self.press.step(dt)                   # animators are plain structs
        self.layout()                         # plain code -> writes transforms
        self.scene.checkout_label.set(f"Pay {self.cart.total:>8}")

        frame = self.scene.snapshot()         # FrameParams from a bounded pool
        spec = self.pacer.admit(read frame)   # RasterSpec chosen BEFORE rendering
        target = await render(take frame, spec)   # generated; checkpoints per tile batch
        released = await self.display.commit(take target)
        self.pacer.record(released.outcome)   # feeds the next admission and replay
```

Nothing above is reactive. State changes are visible, ordered, and bounded.
Rendering allocates nothing and diffs no trees; it consumes a parameter block.

**Rendering is actor-local and checkpointable.** The generated renderer is
not a service and not a synchronous monolith: it is an async state machine
that renders in **statically bounded tile batches with a semantic checkpoint
after each batch** — exactly the language's existing rule that async loop
back edges are checkpoints unless a finite uninterrupted bound is proved. A
full render may take several milliseconds; running it synchronously would
monopolize the single cooperative core and starve driver bottom halves,
input, and every other actor for most of the scheduling horizon. With
checkpoints, the app actor remains in its non-reentrant frame turn — the
immutable snapshot keeps the frame coherent while input events queue for the
next turn — and other actors interleave. When the compiler proves a render's
uninterrupted bound is small enough, the as-if rule collapses the
checkpoints into straight-line code. Checkpointed is the semantic default;
synchronous is the proven optimization, never the other way around.

The honest consequence: admission budgets the **shared core**, not a private
renderer. How the render task's budget composes with other actors' work
near the deadline is an open scheduling question (section 19), surfaced
rather than hidden — and audio gives that question its most demanding
tenant (section 10).

## 4. The shape algebra and its certifications

The public geometry family is **`Shape2` / `Shape3`**: implicit shapes whose
sign and zero set are authoritative. "Signed distance field" is deliberately
not the public name, because it is not generally true: min/max CSG, smooth
combination, and non-uniform transforms produce distance *estimates*, not
exact Euclidean distance — even min/max of two exact SDFs need not remain
exact (see *Operations on Signed Distance Function Estimates*, CAD Journal
20(6), 2023). Pretending otherwise would silently corrupt strokes, shadows,
culling, and 3D stepping.

Every shape value therefore carries a small set of **independent certified
facts** as comptime metadata — a product of properties, not one ordered
lattice, because the properties are genuinely orthogonal:

- **authoritative sign** — the sign and zero set are exact;
- **conservative range/slope** — sound interval evaluation and/or a tracked
  Lipschitz bound;
- **non-overestimating step bound** — a distance value safe for sphere
  tracing;
- **near-boundary metric behavior** — a certified relationship between field
  value and Euclidean distance near the zero set, which is what filtering
  needs; and
- **exact distance** — true Euclidean distance everywhere.

Combinators propagate each fact independently, and facts only ever degrade.
Operations demand the facts they actually need:

- fill and inside testing require authoritative sign;
- interval pruning requires conservative range/slope — sufficient for
  pruning soundness, and *only* for pruning: a Lipschitz bound does not make
  a field value a correct screen-space distance for filtering;
- 3D sphere tracing requires a non-overestimating step bound;
- antialiased coverage requires certified near-boundary metric behavior; and
- geometrically exact stroke and offset require exact distance. Stroke on an
  estimate is legal only as a **documented approximation with a certified
  error bound** — rescaling an estimate does not recover true distance.

A composition that cannot supply a demanded fact is a build error naming the
combinator that degraded it. Guarantees live in metadata and diagnostics —
one public vocabulary, wrela-style — rather than in parallel public types.

Alongside shapes:

- **`Paint`** — color fields, premultiplied, linear-light.
- **`Coverage`** — the pixel-filter semantic result. Coverage is produced
  from a shape *under the active `RasterSpec`'s filter rule*; it is not a
  claim that a smoothstep of the field value is analytic area coverage
  (section 7).
- Combinators — affine transforms, CSG and smooth variants, morph, `over`
  (Porter–Duff on paints), masking a paint by a coverage.

Every operation is total, pure, deterministic, and legal comptime code. The
same algebra evaluates during the build (baked assets, golden tests) and at
runtime.

Parameter slots declare **valid domains** — nonnegative radii, invertible
transforms, bounded scale — checked at build time where provable. Writing a
value outside a declared domain at runtime is a bug in the wrela sense:
abandonment, not a rendering glitch. Renderer preconditions stay honest
because the domain system keeps dishonest parameters out.

## 5. The figure vocabulary

Named shapes, styles, and text, all defined in the algebra with no private
semantics: `rounded_rect`, `capsule`, `circle`, `path` (bounded contour
set), `text(atlas, s)`, styled by `fill`, `stroke(width)`,
`shadow(radius, offset)`, `glow`. A figure is a value. Styles are values.
There is no cascade, no inheritance, no ambient context: a figure's pixels
are fully determined by its expression and its parameters. That property is
what makes local reasoning work for a person, and typed,
hallucination-resistant composition work for a coding assistant — an
invented property is a type error, not a silently ignored string.

Layout is deliberately not a constraint solver. It is ordinary bounded
runtime code — stacks, rows, padding, measurement — that computes
transforms, and transforms are parameters. Layout is steppable, debuggable,
imperative wrela; the geometry it positions is sealed structure.

Effects with non-local influence — blur, wide shadows, sampling filters,
masks — are **explicit raster-pass nodes** in the plan. Each pass has a
**finite support**: a true Gaussian has infinite support, so a blur pass is
an explicitly truncated kernel with a declared error threshold, not a
pretense of exactness. Influence halos **compose automatically** from
pass-local support through chained passes; requiring users to declare total
chain halos would recreate manual dirty tracking in another form. Modeling
passes as first-class nodes now (even though backdrop filtering is deferred)
gives the algebra a clean place to put them and gives invalidation the
information it needs (section 8).

## 6. Scene construction mirrors image construction

```wrela
# Illustrative only.
comptime fn kiosk_scene() -> ScenePlan:
    s = Scene(logical_size=(1920, 1080))
    atlas = comptime bake_glyph_sdf(font_source, sizes=[16, 24, 40])

    card = s.figure(
        rounded_rect(radius=12.px).fill(theme.surface).shadow(8.px),
        id=Card.Checkout,
    )
    s.pool[RowFigure](count=32, id=Rows)      # bounded dynamic children
    label = s.text(atlas, capacity=24, id=Label.Checkout)
    return s.seal()
```

Sealing gives the compiler the complete expression DAG, every parameter slot
and its domain, every pool capacity, every raster-pass support, and every
baked asset. Dynamic UI shape is handled the closed-world way, and it is the
same answer the foundations chapter already gives for "a compositor scene
with a dynamic number of objects per frame": closed enums of sealed scene
variants for modes and screens, bounded pools for variable-count children,
and runtime parameters activating sealed structure. Topology is sealed
completely; runtime chooses among sealed possibilities. For the appliance
products wrela names — kiosks above all — this is the correct discipline,
not a tolerated restriction.

## 7. The raster contract

A pixel represents a **filtered area, not a point sample**. A color-at-a-point
function therefore does not by itself define an antialiased pixel, and the
design does not pretend it does.

`RasterSpec` makes the sampling contract explicit: output dimensions, pixel
format, color space, the distance-to-coverage filter rule, and a quality
level. The first-revision filter is one fixed kernel (≈0.5 px smoothstep on
certified near-boundary distance) applied identically everywhere, including
text. That buys **consistency** — never two filtering policies on one
screen — and is stated as exactly that. It is not analytic coverage, and it
is known to be approximate at corners, intersections, and subpixel features.

**Filtering order is part of the contract.** Filtering and compositing do
not commute, particularly along shared translucent edges, so the contract
names its choice: the first revision filters **per figure, before
Porter–Duff composition** — each figure produces coverage under the filter
rule, then layers composite. This is what the tile renderer computes
naturally and what production 2D rasterizers do; its known cost, conflation
artifacts along coincident translucent edges, is documented rather than
denied. A supersampled variant (compose the continuous scene, then filter)
is a higher-cost `RasterSpec`, not a different scene language.

Better filter rules are likewise **not a scene-language change, but they are
a semantic change to a particular render** — which is why they arrive only
as new versioned `RasterSpec`s, and why the frame's identity includes the
spec (section 8).

`RasterSpec` also makes degradation precise: `coarsen` renders the same
`(ScenePlan, FrameParams)` under a lower-cost spec and upscales. That is a
well-defined statement — same scene, different sampling contract — rather
than a vague claim that the result is "the same image."

Color discipline: linear-light internally, one encode to the scanout format
at the end, ordered dithering on gradient encode to kill 8-bit banding.

## 8. The generated renderer

Semantics: every frame, `render` is evaluated over the whole grid.
Implementation, under the as-if rule:

1. **Binning.** Each figure has a conservative screen-space bound derived
   from its transform parameters and certified shape bounds. Figures bin
   into tiles (e.g. 16×16); a tile's work list holds only figures that can
   touch it.
2. **Tile classification, three paths.** *Empty* (background fill),
   *interior* (covered by one opaque figure with certified distance below
   −1 px — degenerates to a solid fill or gradient ramp, no per-pixel
   geometry math), or *edge* (the filter band and true overlaps — the only
   place the full evaluator runs, SIMD across pixels, span-level within the
   tile so interior spans of edge tiles still fill). Most pixels in real UI
   are interiors. Fields are only *evaluated* where they are interesting;
   they are only *semantic* everywhere.
3. **Interval culling.** Within edge tiles, interval/Lipschitz evaluation
   prunes the expression DAG per region — sound because certified facts
   guarantee conservativeness, and cheap because the DAG is sealed.
4. **Checkpointed execution.** Tile batches are the units of the generated
   async state machine (section 3); the batch size is a statically bounded
   quantum, and each batch boundary is a semantic checkpoint.
5. **Incrementality over frame identity.** The identity a buffer can match
   is **`(FrameParams, RasterSpec)`**, not parameters alone: quality,
   filter, resolution, encoding, and dithering changes alter pixels with no
   parameter change, and admission may legally switch specs between
   consecutive frames. Damage comparison, layer-cache keys, and buffer
   generations all carry the spec identity. **A `RasterSpec` change causes a
   full buffer rebase unless the compiler proves reuse between the two
   specs equivalent.** Within one spec, the programmer never marks anything
   dirty; the generated renderer diffs the new snapshot against the prior
   one and converts changed slots into affected tiles through the
   build-time dependency map. Four rules are load-bearing:
   - Comparison is a **generated per-slot comparator** over the fixed
     layout, not raw `memcmp`: padding, enum encodings, and string slots
     need slot semantics. (The language's canonical-NaN rule already removes
     the worst floating-point hazard; the comparator handles the rest,
     including signed zero policy per slot.)
   - A moving figure invalidates the **union of its old and new**
     conservative footprints.
   - Every raster-pass node expands invalidation by its **automatically
     composed influence halo** (section 5); geometry bounds alone are
     insufficient for blur, shadow, and mask effects.
   - Declared **parameter domains** (section 4) are what make conservative
     footprints computable at all.
6. **Buffer repair.** With multiple framebuffers, the buffer acquired for
   frame N may be several frames stale, so "this frame's dirty tiles" is
   not a correct repair set. Each buffer carries the **generation and spec
   identity** it last fully matched; the renderer repairs the union of
   per-frame damage sets since that generation, kept in a bounded ring,
   with copy-forward from the newest complete buffer as the fallback when
   the ring is exceeded — and a full rebase when the spec identity differs.
   This is the buffer-age discipline, made a checked structural invariant
   instead of a compositor convention.

## 9. Transactional presentation

Degradation decisions are **admission decisions, made before rendering** —
not consequences discovered after a deadline has already been missed:

```text
snapshot -> admit (predict cost, choose RasterSpec or skip)
         -> render in checkpointed batches into a CPU-owned, invisible buffer
         -> commit the complete buffer to the driver
         -> strict receipt resolves; a released buffer returns to the pool
```

- `reuse_last` — admission predicts the work cannot fit and skips rendering;
  the last committed frame remains on scanout.
- `coarsen` — admission selects a lower-cost `RasterSpec` before rendering.
- `half_rate` — a cadence policy across multiple turns, not a per-frame
  fallback.
- An **unexpected** overrun produces a typed frame-miss value and preserves
  the last committed frame. Admission outcomes feed the pacer and the
  replay record (section 12).

**Buffer ownership is an explicit state machine**, because "the buffer
returns after fenced completion" is not one rule but three target paths:

```text
cpu_free -> rendering -> transfer_pending -> scanned_out
   ^                                             │
   └───────── released by a later commit ────────┘
```

- With a host-copy virtio resource, guest backing may become CPU-owned again
  after the fenced transfer completes.
- With blob/zero-copy scanout, the displayed buffer remains
  device/display-owned while scanned out.
- With resource flipping, the newly displayed resource stays current and the
  *previously* displayed one becomes reusable.

Accordingly, `commit(new)` returns the **old** scanout buffer (or a
target-specific receipt); the new scanout buffer is never implicitly
reusable. **Commitment is a one-way point:** before the first externally
visible command, cancellation discards scratch state and returns the buffer;
after `SET_SCANOUT` or any externally visible submission, the operation is a
**strict, non-cancellable receipt** requiring an explicit terminal
transition — the language's existing published-I/O-receipt pattern — because
cancellation there would produce an outcome-unknown display state. DMA
quarantine rules apply unchanged after submission.

The pools are bounded, and the safety claim is stated exactly: occupancy
**cannot exceed the declared bound**; when no buffer or snapshot is
available, admission returns **typed backpressure** (or invokes declared
target policy) rather than blocking indefinitely or exhausting anything
silently. Repeated misses degrade cadence; they surface as typed values, not
as pool corruption.

The presentation guarantee is likewise exact: **the renderer never exposes a
partially rendered buffer to the driver.** The pinned Virtio 1.2 CS01
contract (the repository's normative reference; 1.3 is explicitly not
pinned) provides multi-resource scanout via `SET_SCANOUT`,
`TRANSFER_TO_HOST_2D`, and `RESOURCE_FLUSH`, but no vblank-synchronized or
atomic-display guarantee — so none is claimed. Target packages MAY provide
stronger atomic or vblank-synchronized presentation where the hardware
contract actually supplies it. Dirty-tile coalescing still minimizes
transfer regions, and blob-resource/zero-copy scanout is a target-package
option where supported.

**The pointer cursor uses the transport's cursor plane.** Virtio-gpu's
dedicated `cursorq` (`UPDATE_CURSOR` / `MOVE_CURSOR`) lets the host
composite the cursor, giving sub-frame pointer latency with zero contact
with frame semantics — no late-latched parameters, no snapshot impurity.
Software cursor composition and late-latched inputs are research appendix
material (appendix A).

```text
@app  Kiosk ── frame turn: snapshot, admit, render (checkpointed batches) ──┐
                                                                            ▼
                                              commit(buffer) ──> @driver VirtioGpu
                                                                       │ TRANSFER_TO_HOST_2D (dirty rects)
                                                                       │ RESOURCE_FLUSH / SET_SCANOUT
                                                                       │ cursorq: MOVE_CURSOR
                                                                       ▼
                                                                    scanout
```

## 10. The audio stream

Audio is the one-dimensional instance of the same contract, and the design
treats the rhyme as structural rather than decorative. There is no "playing
a file": hardware audio is a ring of sample buffers that a DAC drains at a
fixed rate, exactly as the display drains the framebuffer. Video is 120
"frames" per second of ~2 M samples each; audio is 48 000 frames per second
of 2 samples each. The mapping is one-to-one:

| Video | Audio |
|---|---|
| framebuffer / swapchain | period ring buffer |
| scanout clock (120 Hz) | sample clock (48 kHz) |
| `render(plan, params, spec)` | `mix(voices, triggers, spec)` |
| `RasterSpec` (versioned sampling contract) | `AudioSpec` (rate, channel layout, period size — versioned) |
| `commit` + strict receipt | period submission + strict receipt |
| typed frame miss | typed underrun |

**The workload is video's mirror image.** Video is enormous compute under a
soft deadline — a held frame is invisible. Audio is trivial compute under a
hard deadline — a missed period is an audible pop, because a waveform
discontinuity cannot be hidden. Mixing two dozen voices at 48 kHz stereo is
on the order of 20 M operations per second — well under 1 % of the core.
The entire audio problem is **scheduling discipline, not throughput**: the
mixer must run every period (~5 ms at 256 samples) without fail while the
renderer chews through tile batches. This is precisely why checkpointed
rendering (section 3) is load-bearing: a synchronous 8 ms render would blow
through every audio period it overlaps. The mixer holds the **tightest
recurring deadline in the image** — tighter than video's — and is the
concrete first tenant of the shared-core scheduling question (section 19).

**Pipeline.**

```text
@app / game logic ── typed triggers: play(Sfx.MenuSelect), music(Track.Floor7) ──┐
                                                                                 ▼
                                        @service Mixer (bounded voice pool)
                                              │ sums voices into period buffers
                                              ▼
                                        @driver VirtioSnd ── TX queue ──> DAC
```

- The `@driver` owns a TX queue of period buffers in DMA memory — the
  swapchain analog, with the same ownership state machine shape as section 9
  (`cpu_free → mixing → submitted → drained → cpu_free`) and the same
  receipt, cancellation, and quarantine machinery.
- The `@service Mixer` owns a bounded voice pool. A voice is a small state
  machine — read position, pitch (read rate), envelope, gain — and mixing is
  a bounded sum. Period depth (pre-fill) is a **declared latency-versus-
  safety parameter**, reported like every other capacity.
- Underrun policy is typed and admission-shaped, but the medium changes the
  sane policies: video's `reuse_last` is invisible, audio's repeat-a-period
  is audible, so degradation is fade-to-silence on predicted starvation plus
  a typed underrun fault on unexpected misses — never a silent glitch.

**The data was never a closure problem.** The closed world seals *code* and
*declares* data; string literals, glyph atlases, and the seed filesystem are
already baked data, and audio enters identically:

- Small SFX bake into read-only image data — the glyph-atlas analog.
- Music lives on the comptime-built seed disk (`img.seed_disk(...)`) and
  streams through the storage service into bounded staging pools at
  runtime — sealed code, streamed content-addressed data, the same pattern
  as any large asset.
- Comptime transcoding (compressed source in, PCM or ADPCM out, during the
  build) is the font-rasterization pattern applied to sound; the
  disk-versus-decode-CPU tradeoff is a build decision.

**Synthesis is a marked aesthetic option, not a free lunch.** Sound as a
1D field over time is a true statement about *evaluation*: a tracker-style
score is kilobytes of sealed note data plus procedural instruments, and
parametric game audio (a layer that enters when health is low) falls out of
parameters. But synthesis has its own aliasing problem — a naive sawtooth
aliases exactly as naively point-sampled geometry does, and band-limited
oscillators are the audio analog of the coverage contract — plus filter
design, click-free envelopes, and denormal hazards in feedback DSP (the
pinned denormal behavior of section 14 matters doubly here). The result of
doing all that well is an instrument, and instrument design is a craft.
Chiptune-class aesthetics are honestly achievable; "orchestral from a synth
we wrote" is not a claim.

**The authoring boundary, stated plainly: the platform transports sound; it
does not author it.** For visuals, the substrate genuinely changes authoring
— figures, styles, and layout are the design surface. For audio it changes
nothing: composition and production remain DAW work done by people with
taste, and the produced result enters as a declared build input. Adaptive
music is **stems plus typed gain rules** (the runtime half is exactly the
trivial mixing above; the authoring half stays in the composer's tools), not
live synthesis. No audio figure vocabulary is proposed — that would be a
DAW, which is out of scope on every horizon. "Music as fields" as a creation
story would be the math-soup mistake relocated to the ear.

What the build *can* honestly contribute is the objective floor:

- **Deterministic bounces** — mixing is pure arithmetic over typed triggers,
  so a cue renders bit-exactly at comptime and can be exported and
  auditioned on real monitors.
- **Golden waveform tests** — regression detection ("the mix changed"),
  never quality judgment ("the mix is good").
- **Loudness gates** — LUFS and true-peak metering are math, so "every SFX
  at target loudness, music at −16 LUFS, true peak under −1 dB" can be a
  comptime assertion. The compiler enforces the checkable floor of
  production discipline; everything above the floor is human judgment.
- **Bit-exact replay** — the recorded trigger stream replays the audio
  alongside the frames (section 12).

## 11. The interaction scene

Visual geometry is the right *default* for interaction, and the wrong
*definition* of it. Strokes and transparent fills, shadows and decorative
overlays, clipping, disabled and click-through figures, deliberately
enlarged touch targets, occlusion, and focus navigation all make the
interactive region diverge from the painted one.

The plan therefore seals a parallel **interaction graph**: identity, role,
label, action, focus order, enabled state, and hit shape. A figure derives a
default interaction node — its hit shape defaults to its visual shape, so
the sign of the shape at the pointer still answers "inside?" and the
distance still turns kiosk touch slop into arithmetic — but the two graphs
are explicitly separable, and either can be edited without the other.

This is also the accessibility story — often a legal requirement and always
a product-level one for appliance UI: role, label, and focus order are
sealed, enumerable structure, checkable at build time — not a bolted-on
annotation layer. Input arrives as typed messages from a `@driver`
(virtio-input) actor; hover, focus, and press are ordinary state in the app
actor; stacking order for picking is the sealed `over` order.

## 12. Time, animation, and replay

Time is a parameter, not an engine. Animators (`Spring`, `Timeline`,
`Ease`) are plain structs stepped explicitly in the frame turn; their
outputs are written into parameter slots like any other value.

A frame's pixels are a pure function of `(ScenePlan, FrameParams,
RasterSpec)` — but the *selected spec* is not a pure function of input
events: admission reads measured misses, buffer availability, and observed
timing. Bit-exact replay therefore records, per frame, the **admission
outcome** — the chosen `RasterSpec`, frame-miss results, and relevant pacing
decisions — alongside the input stream and timestamps. Replaying the
recorded specs against the recorded snapshots reproduces every frame
bit-exactly without pretending the pacer was deterministic. (A strictly
deterministic admission mode — modeled costs only, no measured feedback —
remains available for tests that want replay from inputs alone.)

The same record replays the audio stream: mixing is pure arithmetic over
recorded typed triggers, so frames and samples replay bit-exactly together.

The snapshot is the replay unit — one more job the presentation boundary was
already doing. Record the stream, scrub through a bug, diff two frames.

Golden-image tests run in the compiler: a `@test comptime fn` renders a
sealed scene through the **reference renderer** at fixed parameters and a
fixed spec, then asserts on pixels — no emulator, no screenshot
infrastructure, no flakiness. What comptime goldens validate is the
reference oracle against the written contract, and only that; the optimized
renderer and the display path are validated by the differential and image
tests of section 14. A coding assistant editing UI gets the full loop —
edit, comptime-render, pixel-assert — which is the strongest practical
answer to "assistants can't see what they styled."

## 13. Text

- Glyph rendering: comptime-baked multi-size SDF atlases (a sanctioned
  comptime role). Runtime text samples the atlas as a shape — same filter
  rule as every other figure.
- Coverage proof: static strings are known; dynamic text slots declare a
  capacity *and an alphabet*. The build proves every reachable string
  renders from the baked atlas. Tofu becomes a build error, which no
  runtime UI stack can offer.
- Shaping: first-revision scope is precomposed scripts and simple shaping.
  Complex-script shaping is named deferred research, not smuggled in.

## 14. Determinism, numerics, and differential testing

"No fast-math" (already a language rule) is necessary but not sufficient for
bit-exact agreement between comptime, scalar, and SIMD evaluation. The
design makes bit-exactness a **theorem with named preconditions** instead of
an aspiration:

- the runtime field op set is pinned to correctly-rounded IEEE primitives —
  add, mul, FMA, sqrt, abs, min/max — which covers almost everything shapes
  need;
- generated code fixes evaluation order and carries an explicit
  FMA-contraction policy (contraction decided at build time, identically
  for scalar and SIMD lowering);
- transcendentals enter only through pinned polynomial kernels;
- NaN canonicalization comes from the language; denormal and rounding-mode
  behavior are pinned by the target package; and
- narrowing to u8/u16 in the filter band is a certified transformation (the
  band needs ~8 bits post-filter), proved where applied, never assumed.

The written numerical and raster contract is normative; the reference
renderer is its conformance oracle. Enforcement is layered testing:

1. **Comptime goldens** — reference oracle, pixel-exact assertions,
   deterministic by construction, validating the oracle against the
   contract.
2. **Differential tests** — generated renderer versus reference oracle on
   the same `(plan, params, spec)`, bit-exact under the preconditions
   above; any divergence is a build/test failure naming the tile.
3. **Image tests** — full display path under QEMU: boot, present, scanout
   protocol. These are integration evidence, never performance evidence.

The audio mixer inherits the same discipline with a smaller op set, and adds
golden waveform and loudness assertions (section 10).

## 15. 3D

The shape algebra and the sealed-scene philosophy are shared; the evaluator
is not. `Shape3` reuses composition, certification, parameters, and
invalidation, but ray traversal, visibility, lighting, and compositing
constitute a distinct renderer with its own admission costs. The honest
promise is "shared scene philosophy and implicit algebra," not "3D without a
renderer rewrite."

Sphere tracing demands the strictest certified fact (a non-overestimating
step bound), which the type system can actually enforce — a small
vindication of the certification design. Normals from gradients and soft
shadows from distance queries remain the cheap SDF dividends. Scope: bounded
3D *viewports* as budgeted figures (a 300×300 product spinner is ~90 K
pixels), with internal resolution and refinement policy set at admission.
Full-screen raymarching at native 1080p/120 on one core is not a claim.

## 16. Performance roadmap

**The roofline, labeled honestly.** 1080p at 120 Hz is 249 M pixels/s. One
~4 GHz core gives ~16 cycles per pixel at full invalidation; NEON with dual
FMA pipes is roughly 32 GFLOP/s, i.e. ~128 flops per pixel per frame. These
are **optimistic roofline bounds, not an execution budget**: they hide
instruction latency and throughput for sqrt, division, conversion, min/max,
and shuffles; branch and compositing costs; cache misses and atlas access;
write allocation; framebuffer transfer and virtio overhead; and — on one
cooperative core — the time every other actor in the image needs, including
the audio mixer's hard periodic deadline. The architecture's two jobs are
unchanged (keep the average touched-pixel count near zero; keep per-pixel
work on touched edge pixels small), but whether a given workload fits is a
**measurement question the vertical slice must answer**, not an arithmetic
one. Every optimization below is an as-if optimization with a proof
obligation and an image-report line — never a semantic knob the programmer
tunes.

**Tier 0 — the vertical slice** (section 17): snapshot diff → tile reuse via
the dependency map, keyed by frame identity including the spec;
empty/interior/edge classification with span-level fills; straight-line
specialized per-figure evaluators (no tape interpreter — the sealed DAG
compiles to machine code with constants folded); checkpointed tile-batch
execution; correct per-buffer generation/spec damage repair. These are the
baseline and the correctness skeleton.

**Tier 1 — first wave after measurement.** Each of these is an
equality-preserving rewrite — the optimized pixels are provably identical to
re-evaluation:

- **Instancing from purity.** Two figures provably identical up to integer
  translation render once and blit N times — list rows, buttons, tiled
  backgrounds collapse. Glyph atlases are the special case; this is the
  general theorem.
- **Scroll-as-blit.** Integer translation commutes with sampling — a
  theorem in the algebra, not a heuristic, and unlike temporal reprojection
  it is exact: when a subtree's only changed parameter is an integer
  translation, the renderer derives "blit region + evaluate the exposed
  strip." Scrolling costs a memmove plus one strip.
- **Static overdraw culling.** Composition order and opacity are sealed;
  the compiler computes topmost-opaque coverage per tile class and deletes
  the work underneath at build time.
- **NEON lowering and certified narrowing** in the filter band.

**Tier 2 — closed-world deep cuts:**

- **Automatic layerization from dependency analysis.** Partition the sealed
  DAG by which parameters reach it: no parameters → baked at build time;
  slow parameters (theme, layout) → cached rasterized layer regenerated on
  change; per-frame parameters → live evaluation. Layer-cache keys include
  the spec identity. This is compositor layer promotion and memoization,
  derived and sound instead of hand-annotated.
- **Build-time transition diffing.** Scene transitions are between sealed
  variants, so the compiler can diff baked baselines at build time; even a
  full navigation invalidates only parameter-dependent regions.
- **Algebraic rewrites.** Regular pools rewrite to domain repetition
  (O(1) per pixel instead of O(n)); whole-scene CSE; bake-versus-evaluate
  decided per subfield by the cost model.
- **Profile-guided decisions.** Real usage traces (which slots actually
  change, dirty-tile histograms) enter as declared hashed build inputs —
  the mechanism chapter 06 already admits — and steer layerization and tile
  sizing.
- **Hierarchical importance-guided evaluation.** Evaluate coarse; certified
  conservative bounds prove which regions cannot contain a zero crossing;
  refine only the rest. This is the hierarchical generalization of interval
  culling — sound via the certified facts, and still a single-frame,
  equality-preserving strategy, unlike cross-frame refinement (appendix A).

Speculative directions — temporal reprojection, cross-frame progressive
refinement, late-latched inputs, and game workloads — live in appendix A,
because each one either breaks the pure render signature or needs `RasterSpec`
machinery the first revision does not have.

**Measurement discipline.** The report separates structural operation
counts (exact, from the sealed plan) from timing estimates (a calibrated
model against pinned reference hardware). QEMU numbers are integration
evidence only. A `@frame_assert`-style post-layout check gates the modeled
worst case; regression gates hold golden-scene frame costs. Consistent with
the repository's stance, no unmeasured latency claim is made.

## 17. Prototype vertical slice

Build a thin slice before committing language surface:

1. sealed scene plus generated typed parameter block and snapshot pool;
2. rounded rectangles, circles, affine transforms, flat fills, bounded text;
3. the slow authoritative reference renderer, implementing the written
   contract;
4. tiled scalar renderer executing in checkpointed batches, with old∪new
   invalidation and the generated per-slot comparator;
5. correct multi-buffer generation/spec/damage tracking, including a forced
   spec-change rebase;
6. virtio-gpu complete-buffer presentation through the driver actor, with
   the explicit buffer-ownership state machine and cursorq;
7. differential pixel tests (tiled vs. oracle) and measured
   full-invalidation frames on reference hardware; and
8. the audio spine: virtio-snd driver, bounded mixer, period ring with the
   ownership state machine, a forced-underrun test proving the typed miss
   path, and one golden-waveform plus loudness-gate comptime test —
   exercised *concurrently* with rendering, because the point is the shared
   core.

Then add NEON, interval pruning, smooth CSG, instancing, scroll-as-blit,
and static cost modeling in the order the measurements justify. The slice
deliberately exercises every load-bearing correctness mechanism — snapshot
boundary, checkpointing, dependency map, spec-keyed damage repair,
ownership states, the mixer's hard period deadline, differential testing —
with the simplest possible content.

## 18. Prior art, briefly

- **Immediate-mode GUIs** (Dear ImGui): the honest frame loop and
  state-in-plain-code stance — kept; per-frame procedural drawing without
  identity or incrementality — replaced by sealed structure.
- **React/SwiftUI/Elm**: UI-as-function-of-state — kept as semantics;
  runtime reconciliation — replaced by generated, fixed-shape invalidation.
- **libfive / Keeter's implicit-surface rendering**: interval-pruned field
  evaluation — adopted for edge tiles, over a DAG sealed at build time.
- **Wayland buffer-age / damage tracking**: the multi-buffer repair
  discipline, promoted from compositor convention to checked invariant.
- **Vello, blend2d, tiny-skia**: evidence that tiled CPU 2D at 1080p and
  high refresh is a real budget for moderate scenes; the interior/edge
  split keeps field math off the easy pixels.
- **FMOD/Wwise**: the stems-plus-rules model for adaptive audio — adopted
  as the authoring boundary; runtime moves typed gains, composers keep
  their tools.
- ***Operations on Signed Distance Function Estimates*** (CAD Journal
  20(6), 2023): why exactness is a certified fact, not an assumption.

## 19. Decision ledger and open questions

Settled across two review rounds and the audio design pass (non-normative
reconciliation, in the spirit of the language's decision ledger):

| Topic | Decision |
|---|---|
| Headline concept | The sealed scene is the invention; implicit fields are the certified geometry mechanism inside it. |
| Frame semantics | `render(ScenePlan, FrameParams, RasterSpec) -> PixelGrid`; the written numerical/raster contract is normative and the reference renderer is its conformance oracle. |
| Presentation boundary | Explicit immutable `FrameParams` snapshot, moved with `take`; app state never crosses the boundary. |
| Renderer execution | Actor-local generated async state machine, checkpointing after statically bounded tile batches; the as-if rule may collapse checkpoints when the uninterrupted bound is proven small. Synchronous is the optimization, not the default. |
| Frame identity | `(FrameParams, RasterSpec)`. Damage, buffer generations, and layer caches carry spec identity; a spec change forces rebase unless reuse is proven equivalent. |
| Geometry types | One public `Shape` family carrying independent certified facts (authoritative sign, conservative range/slope, non-overestimating step bound, near-boundary metric behavior, exact distance); operations demand facts; stroke on an estimate is a documented approximation with an error bound. |
| Filtering order | Per-figure coverage before Porter–Duff composition, with conflation artifacts documented; supersampled composition is a higher-cost `RasterSpec`. |
| Sealing strictness | Topology sealed completely; runtime activates bounded slots and closed scene variants. |
| Invalidation | Old∪new conservative footprints, automatically composed effect halos from per-pass finite support, declared parameter domains, generated per-slot comparator, per-buffer generation+spec damage repair. |
| Non-local effects | Explicit raster-pass nodes with finite (truncated, error-declared) support now; backdrop filtering deferred. |
| Degradation | Admission-time policy; typed miss on unexpected overrun; `half_rate` is cadence policy. |
| Buffer ownership | Explicit state machine (`cpu_free → rendering → transfer_pending → scanned_out`); `commit` returns the previous scanout buffer or a target receipt; post-submission presentation is a strict non-cancellable receipt. |
| Pool safety claim | Occupancy cannot exceed the declared bound; admission returns typed backpressure or invokes declared target policy. |
| Cursor | The virtio-gpu `cursorq` cursor plane; no late-latched parameters in the first revision. |
| Replay | Records admission outcomes (chosen spec, misses, pacing) alongside inputs; a deterministic-admission mode exists for tests. Audio triggers replay in the same record. |
| Tear-free claim | Stated as "never expose a partially rendered buffer"; stronger guarantees are target-package properties. Virtio 1.2 CS01 is the pinned reference. |
| Interaction | Sealed parallel interaction graph (identity, role, label, action, focus, enabled, hit shape); figures derive defaults; accessibility is often a legal and always a product-level requirement. |
| Bit-exactness | A theorem with preconditions: correctly-rounded op set, fixed evaluation order, explicit contraction policy, pinned kernels; enforced by differential tests. |
| Cost model | Structural counts separated from timing estimates; roofline numbers are optimistic bounds; calibration on pinned hardware; QEMU is integration evidence. |
| Audio transport | The 1D instance of the stream contract: a virtio-snd `@driver` period ring (swapchain analog, same ownership state machine) fed by a bounded mixer `@service`; period depth is a declared latency/safety parameter; underrun policy is typed and admission-shaped (fade-to-silence, typed fault — never a silent glitch). |
| Audio data | SFX bake into read-only data; music streams from the comptime-built seed disk through bounded staging pools; comptime transcoding is the font-rasterization pattern. Closure seals code and declares data — audio files never threatened it. |
| Audio authoring boundary | The platform transports sound and gates the objective floor (deterministic bounces, golden-waveform regressions, LUFS/true-peak assertions); it does not author it. DAW-produced assets are the default; adaptivity is stems plus typed gain rules; synthesis is a marked aesthetic option whose DSP craft (band-limiting, filters, envelopes) is costed as real work. No audio figure vocabulary is proposed — that would be a DAW. |
| Speculative work | Temporal reprojection, cross-frame progressive refinement, late-latched inputs, and games are research appendix material, outside the first revision. |

Still open:

1. **Shared-core scheduling.** How the checkpointed render task's budget
   composes with other actors' admission near the frame deadline —
   priority, quantum size, and what the pacer may assume about foreign
   work. The audio mixer's period deadline is the concrete hardest case:
   it is the tightest recurring deadline in the image and must be
   satisfiable between any two tile batches.
2. **Certification surface.** How much of the certified-fact set ordinary
   users ever see, versus tooling-only display; the error-message design
   when a composition degrades below an operation's demand.
3. **`RasterSpec` quality vocabulary.** What the quality axis concretely
   enumerates (filter rule, internal resolution) and how admission selects
   among versioned specs.
4. **Damage-ring depth.** The bounded ring size versus copy-forward policy,
   and whether the report should surface repair-path statistics.
5. **Dynamic-text alphabet ergonomics.** How alphabets are declared without
   tedium (script presets, locale bundles) while keeping the coverage proof.
6. **Audio staging policy.** Bake-versus-stream thresholds, decode-at-build
   versus decode-at-runtime, period depth defaults per target, and how the
   report itemizes audio staging pools.
7. **Naming.** "Sealed scene" is the concept name. `Scene`, `Figure`,
   `Shape`, `Paint`, `Coverage`, `present` read well; the substrate itself
   still needs a name.

## 20. Explicit non-claims

- No GPU compute; virtio-gpu is a scanout transport here, nothing more.
- No general dynamic scene graphs, no runtime style systems, no cascade —
  deliberately.
- No hard real-time guarantee; the frame budget is modeled, measured, and
  degraded under admission policy, not proved. (The audio period deadline
  is engineered and tested for, but likewise not formally proved.)
- No vblank-atomic presentation claim beyond what a target package
  actually supplies.
- No history-dependent rendering: every first-revision frame is a pure
  function of `(ScenePlan, FrameParams, RasterSpec)`.
- No audio authoring or production tooling: no DAW, no claim that
  synthesis yields production-quality sound, no pretense that loudness
  gates measure musical quality. Above the objective floor, audio quality
  is human judgment applied in external tools.
- No full-screen 3D, no complex text shaping, and no backdrop filtering in
  the first revision.

## Appendix A: research directions (explicitly speculative)

None of the following is part of the first revision. Each is recorded with
the reason it does not qualify yet, so a future revision starts from the
constraint rather than rediscovering it.

- **Temporal reprojection and frame interpolation.** Motion is parameter
  change, so motion vectors are exact rather than estimated — a real
  advantage. But reprojection introduces *history* into the semantic input:
  the pure `render(plan, params, spec)` signature no longer describes the
  system, and exact motion vectors do not solve disocclusion, transparency,
  or changing paint. Admissible only with an explicitly history-carrying
  semantics and its own correctness story.
- **Cross-frame progressive refinement.** Committing a coarse frame and
  refining it over subsequent frames is sound only if every committed frame
  is a complete render under a `RasterSpec` that includes a spatial
  quality/refinement map. That spec machinery does not exist yet; without
  it, progressive present conflicts with transactional presentation.
  (Single-frame hierarchical refinement under certified bounds is *not*
  speculative and lives in section 16, Tier 2.)
- **Late-latched inputs.** Sampling any input after the snapshot breaks
  snapshot purity. The principled shape is an explicit
  `render(ScenePlan, FrameParams, LateParams, RasterSpec)` with `LateParams`
  immutable, bounded, and recorded for replay. The first revision does not
  need it: the cursor — the only latency-critical input — rides the
  virtio-gpu cursor plane (section 9).
- **Game workloads.** A desktop is this architecture's best case: sparse
  change, deeply layerizable. 2D games (baked/instanced figures,
  mostly-opaque blits, live math at edges) are a plausible target — as a
  *hypothesis to be tested against slice measurements*, not a claim.
  Full-screen 3D at native resolution stays excluded (section 15); 3D
  arrives as budgeted viewports with admission-time internal resolution.
  Turn-based, UI-heavy genres (the creature-battler shape) are the
  closest-fit stress test: they exercise asset streaming, saves, audio,
  and heavy effect frames while staying inside the architecture's
  sparse-change sweet spot.
