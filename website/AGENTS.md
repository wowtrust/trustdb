# Prototype Instructions

Run the local server yourself and open the preview in the browser available to this environment. Do not give the user server-start instructions when you can run it.

Before making substantial visual changes, use the Product Design plugin's `get-context` skill when the visual source is unclear or no longer matches the current goal. When the user gives durable prototype-specific design feedback, preferences, or decisions, record them in `AGENTS.md`.

When implementing from a selected generated mock, treat that image as the source of truth for layout, component anatomy, density, spacing, color, typography, visible content, and hierarchy.

## Durable visual direction

- Keep the original TrustDB carbon-black and acid-green palette, but use editorial scale, sharp hierarchy, and substantially more negative space than the old UI.
- Trust ImageGen for polished static visual assets such as terrain, evidence fields, and ambient textures.
- Draw visuals that need to move in code: proof signals, topology nodes, live pipeline lines, and particles should use Canvas/SVG/DOM and GSAP so motion stays responsive and meaningful.
- The official website should feel closer to premium data-landscape editorial work than to a dense SaaS dashboard.
- The homepage client preview must be rendered from the real desktop client in the currently selected language; never reuse a Chinese client screenshot for other locales.
