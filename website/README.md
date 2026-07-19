# TrustDB Official Website

The public TrustDB website is maintained in this repository as a standalone React + Vite application.

## Development

```bash
npm ci
npm run dev
```

The Vite development server accepts an explicit host and port, for example:

```bash
npm run dev -- --host 0.0.0.0 --port 4173 --strictPort
```

## Production build

```bash
npm run build
npm run preview
```

The generated static site is written to `dist/`. Generated raster artwork used by the site is versioned under `src/assets/generated/`; moving proof signals and particles are rendered in code and animated with GSAP.

## Accessibility and motion

- Landmark navigation and the primary conversion links are keyboard accessible.
- Decorative canvas layers are hidden from assistive technology.
- `prefers-reduced-motion` disables scroll reveals, parallax, and continuous canvas animation.
