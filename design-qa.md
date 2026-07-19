# TrustDB Design QA

## Comparison targets

### Desktop client

- source visual truth path: `/Users/liuzewen/Documents/trustdb/design/prototypes/generated/trustdb-client-ui-v1.png`
- implementation screenshot path: `/Users/liuzewen/Documents/trustdb/design/qa/desktop-implementation-final.png`
- viewport: `1536 × 1080`
- state: dark theme, dashboard route, demo record selected, system online, L4 active
- full-view comparison evidence: `/Users/liuzewen/Documents/trustdb/design/qa/desktop-comparison-final.png`
- focused region comparison evidence: `/Users/liuzewen/Documents/trustdb/design/qa/desktop-comparison-proof-focus.png`

### Web admin

- source visual truth path: `/Users/liuzewen/Documents/trustdb/design/prototypes/generated/trustdb-web-admin-ui-v1.png`
- implementation screenshot path: `/Users/liuzewen/Documents/trustdb/design/qa/admin-implementation-final.png`
- viewport: `1536 × 1080`
- state: dark theme, dashboard route, explicit demo fixture, three pending anchor batches, service online
- full-view comparison evidence: `/Users/liuzewen/Documents/trustdb/design/qa/admin-comparison-final.png`
- focused region comparison evidence: `/Users/liuzewen/Documents/trustdb/design/qa/admin-comparison-pipeline-focus.png`

### Official website

- source visual truth path: `/Users/liuzewen/Documents/trustdb/design/prototypes/generated/trustdb-official-website-ui-v2.png`
- implementation screenshot paths:
  - `/Users/liuzewen/Documents/trustdb/design/qa/website-implementation-hero-final.png`
  - `/Users/liuzewen/Documents/trustdb/design/qa/website-implementation-final.png`
  - `/Users/liuzewen/Documents/trustdb/design/qa/website-implementation-proof-final.png`
  - `/Users/liuzewen/Documents/trustdb/design/qa/website-implementation-journey-final.png`
  - `/Users/liuzewen/Documents/trustdb/design/qa/website-implementation-quick-final.png`
  - `/Users/liuzewen/Documents/trustdb/design/qa/website-implementation-mobile.png`
- viewport: desktop hero `1536 × 1080`, supporting sections `1440 × 1000`; mobile `390 × 844`
- state: desktop top, proof, journey and quick-start scroll states; mobile top state
- full-view comparison evidence: `/Users/liuzewen/Documents/trustdb/design/qa/website-comparison-final.png`
- focused region comparison evidence: `/Users/liuzewen/Documents/trustdb/design/qa/website-hero-comparison-final.png`
- normalization note: the website source truth is a downscaled full-page composite, so implementation evidence uses four real browser viewports assembled into a labeled contact sheet; focused hero comparison verifies the primary above-the-fold state.

## Findings

No actionable P0, P1 or P2 differences remain.

- [P3] Exact display-font glyph shape differs slightly from the generated mock.
  - Location: desktop `DESKTOP-1`, admin `ALL SYSTEMS PROVABLE`, website hero.
  - Evidence: the reference raster uses an unidentified condensed/grotesk display face; implementation uses the repository-safe display/system fallback stack.
  - Impact: minor glyph-width difference only; hierarchy, wrapping and optical scale match.
  - Classification: acceptable because no redistributable source font was supplied.

- [P3] Desktop and admin backgrounds are cleaner than the original mock.
  - Location: main dashboard canvases.
  - Evidence: the source contains a faint contour/dot field; the implementation intentionally uses pure black after explicit user feedback to remove every uniform green dot and scan texture.
  - Impact: reduced visual noise and stronger focus on the signal rail.
  - Classification: intentional approved deviation.

## Required fidelity surfaces

- Fonts and typography: display hierarchy, weights, wrapping, letter spacing, monospaced metadata and Chinese UI copy checked. No clipped headings or broken wrapping at target viewports.
- Spacing and layout rhythm: desktop sidebar, 290 px inspector, five-level rail, five-row table and health strip align to the reference. Admin 390 px anomaly panel, 618 px overview row and approximately 990 px lower-table split align to the source.
- Colors and tokens: black/acid-green palette, green completion state, orange anomaly state, muted gray hierarchy and hairline borders are consistent across all three surfaces.
- Image quality and asset fidelity: website hero, evidence field and terminal background are full-resolution ImageGen assets with slot-correct crops. Icons use Lucide or Phosphor rather than handcrafted SVG substitutes. Dynamic signal lines and particles are deliberately code-rendered because they animate.
- Copy and content: product-specific Chinese and English copy is coherent; GitHub targets the real repository; production dashboards use API/store data, while realistic proof fixtures are gated behind explicit `VITE_TRUSTDB_DEMO=1` review mode.
- Responsiveness: website checked at `390 × 844` with `scrollWidth === 390`; client and admin have explicit intermediate breakpoints that reduce/hide inspectors before content collision; persistent controls stay reachable.
- Accessibility: semantic links/buttons, labeled navigation, image alt text, focus-visible styling, copy-state label, reduced-motion handling and non-color state text are present.

## Primary interactions tested

- Desktop client: selected `合同条款.pdf`; right inspector updated to the selected file and L5 completed status. Sidebar `验证证据` route reached `#/verify` and returned to dashboard.
- Web admin: `刷新数据` executed, advanced the last-updated time and retained the healthy dashboard state; the data APIs also have unit coverage for full and partial responses.
- Website: `文档` anchor reached `#quick-start`; terminal copy button changed from `复制命令` to `命令已复制`; GitHub link resolves to `https://github.com/ryan-wong-coder/trustdb`.

## Console errors checked

- Website: no new runtime or Vite errors after final load, anchor navigation and copy interaction.
- Desktop client: browser-only Wails bridge rejection removed by `Promise.allSettled`; demo mode skips first-run onboarding and reports system online; no new runtime errors after final load.
- Web admin: explicit demo mode bypasses unavailable localhost proxy calls; no new proxy or runtime errors after the final reload and refresh pass.

## Comparison history

### Pass 1

- [P1] Desktop client major-region proportions drifted from the source: device title was too small, inspector too narrow, proof nodes too small and vertical rhythm compressed.
- [P2] Website collapsed to mobile structure at the reference-review width, hiding navigation and converting proof/quick-start layouts.
- [P2] Admin first grid row stretched to 666 px, placing the lower dashboard at y=738 instead of the source y=690.
- [P2] Desktop browser review produced an unhandled missing-Wails-bridge rejection.

### Fixes applied

- Desktop title enlarged to the source scale, converted to a vertical transparency fade, inspector expanded to 290 px, records/health dimensions aligned, L1–L5 nodes rescaled and all uniform point/scan overlays removed.
- Website desktop breakpoint lowered to 720 px, title/GitHub metadata corrected and browser review moved to the intended 1440 px desktop viewport.
- Admin grid set to `618px minmax(320px, 1fr)`, anomaly panel set to 390 px, lower grid split aligned to the reference, pipeline nodes enlarged and vertically centered.
- Desktop store hydration changed to `Promise.allSettled`; demo-mode health/onboarding logic and background-tab GSAP safety added.

### Pass 2

- [P2] Desktop L5 selection still read `进行中`; inspector muted event CSS rendered as a gray bar.
- [P2] Admin demo review still emitted expected-but-noisy proxy failures because the backend was not running.
- [P2] Uniform green point textures remained visually dominant after layout alignment.

### Fixes applied

- Proof-state helper now marks L5 fully completed; muted event styling corrected.
- Demo mode now bypasses admin health/dashboard proxy calls while production continues to use real APIs.
- Desktop and admin point grids, scan overlays and ambient dot masks were removed completely; only semantic signals and data graphics remain.

### Post-fix visual evidence

- `/Users/liuzewen/Documents/trustdb/design/qa/desktop-comparison-final.png`
- `/Users/liuzewen/Documents/trustdb/design/qa/desktop-comparison-proof-focus.png`
- `/Users/liuzewen/Documents/trustdb/design/qa/admin-comparison-final.png`
- `/Users/liuzewen/Documents/trustdb/design/qa/admin-comparison-pipeline-focus.png`
- `/Users/liuzewen/Documents/trustdb/design/qa/website-comparison-final.png`
- `/Users/liuzewen/Documents/trustdb/design/qa/website-hero-comparison-final.png`

### Production-data audit

- Desktop demo records are no longer a silent production fallback; device identity, records, service health and metrics come from the existing Wails/store APIs unless explicit review mode is enabled.
- Admin pipeline, batches, proof distribution and attention states come from metrics and records APIs; partial failures surface honestly instead of fabricating a healthy or failed state.
- Final `1536 × 1080` browser captures and same-input comparison boards were regenerated after the data wiring pass.

## Implementation checklist

- [x] Desktop client visual system and dashboard implemented in the main repository.
- [x] Web admin mission-control dashboard implemented in the main repository.
- [x] New official website implemented in the main repository.
- [x] ImageGen assets integrated at native slot ratios.
- [x] GSAP timelines, ScrollTrigger, code-drawn signals and reduced-motion fallbacks implemented.
- [x] Primary interactions tested in a real browser.
- [x] Final browser screenshots and same-input comparisons saved.
- [x] All three production builds pass.
- [x] Web admin unit tests pass: 10 files, 26 tests, including live dashboard data and partial-failure states.
- [x] Go repository tests pass.

## Follow-up polish

- Optional P3 only: license and bundle the exact display font if the original mock's font source becomes available.

final result: passed
