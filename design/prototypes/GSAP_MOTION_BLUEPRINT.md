# GSAP Motion Blueprint

## Shared motion language

The acid-green **proof signal** is the common motion motif across all three surfaces. It should travel through existing UI structure instead of becoming decorative noise.

- Use one entrance `gsap.timeline()` per page for typography, separators, data nodes, and the primary action.
- Animate `x`, `y`, `scale`, CSS variables, and `autoAlpha`; avoid layout animation through `top`, `left`, `width`, or `height`.
- Use `gsap.matchMedia()` for responsive choreography and `prefers-reduced-motion`.
- In Vue components, create animations in `onMounted()` inside a root-scoped `gsap.context()` and call `ctx.revert()` in `onUnmounted()`.
- Register `ScrollTrigger` once at app entry. Refresh only after fonts, images, or async content change layout.

## Desktop client

1. **App arrival** — reveal the navigation rail, background wordmark, proof track, then actions with a 60–90 ms stagger.
2. **Proof-chain progress** — animate the signal from L1 to the active level; completed nodes settle once, the active node breathes subtly, future nodes remain quiet.
3. **Selection handoff** — selecting a record moves the signal into the right inspector and reveals the proof details as one coordinated timeline.
4. **Micro-interactions** — restrained magnetic motion on the primary action via `gsap.quickTo()`; table rows use transform/opacity only.

## Web operations console

1. **Live pipeline** — a low-cost repeating timeline moves a small number of proof particles through INGEST → WAL → BATCH → GLOBAL LOG → ANCHOR.
2. **Anomaly focus** — the amber anomaly indicator enters at BATCH, the pipeline momentarily compresses in emphasis, then the right rail slides in with the selected batch.
3. **Data refresh** — metrics count to their new values while bars scale from the left; unchanged values do not replay.
4. **Navigation** — route transitions use one short `autoAlpha + y` handoff and cancel/revert cleanly when switching quickly.

## Official website

1. **Hero** — a master timeline reveals the file hash, draws the proof signal across the topographic field, then exposes the cropped “PROVABLE” word and CTAs.
2. **Pinned proof story** — use a top-level `ScrollTrigger` timeline with `pin: true` and `scrub: 1`; the signal advances through L1–L5 while the background moves from black to warm off-white.
3. **Evidence journey** — each technical stage enters as the signal reaches it. Avoid putting individual ScrollTriggers on child tweens; keep them on the owning timeline.
4. **Quick start** — command lines reveal in sequence as the section enters; the green signal resolves into the final GitHub CTA.
5. **Responsive/reduced motion** — remove pinning and scrub on narrow screens, use short discrete reveals, and show the final readable state immediately when reduced motion is requested.

## Performance guardrails

- Keep animated particles bounded and pause repeating timelines when off-screen.
- Use stagger/batching rather than one independently delayed tween per item.
- Apply `will-change` only to elements that actually animate.
- Never combine `scrub` and `toggleActions` on the same ScrollTrigger.
- Create ScrollTriggers in page order and use `ease: "none"` for any scroll-mapped horizontal movement.
