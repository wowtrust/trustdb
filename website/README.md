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

## Production deployment

Relevant changes merged into `main` are deployed automatically by [`.github/workflows/website-deploy.yml`](../.github/workflows/website-deploy.yml). The workflow can also be started manually from GitHub Actions.

The production job builds the site with Node.js 22 and `npm ci`, writes `deployment.json` with the source commit, uploads an immutable release over SSH, and atomically switches the Caddy document root symlink. It retains the five newest releases. A public health check must return the expected commit; otherwise the workflow restores the previous symlink.

Configure these values in the GitHub `production` environment:

| Kind | Name | Value |
| --- | --- | --- |
| Variable | `WEBSITE_DEPLOY_HOST` | SSH host serving the website |
| Variable | `WEBSITE_DEPLOY_USER` | Dedicated, non-root deployment user |
| Variable | `WEBSITE_DEPLOY_ROOT` | Absolute release root, currently `/srv/trustdb-website` |
| Secret | `WEBSITE_DEPLOY_SSH_KEY` | Private key for the deployment user |
| Secret | `WEBSITE_DEPLOY_KNOWN_HOSTS` | Pinned OpenSSH host-key entry |

Caddy serves `${WEBSITE_DEPLOY_ROOT}/current` and must retain the SPA fallback:

```caddyfile
root * /srv/trustdb-website/current
try_files {path} /index.html
file_server
```

To inspect the active release:

```bash
readlink /srv/trustdb-website/current
curl --fail https://www.trustdb.ryan-wong.cn/deployment.json
```

To roll back manually, atomically repoint `current` to one of the retained release directories:

```bash
cd /srv/trustdb-website
ln -s releases/<release-id> .current-rollback
mv -Tf .current-rollback current
```

## Accessibility and motion

- Landmark navigation and the primary conversion links are keyboard accessible.
- Decorative canvas layers are hidden from assistive technology.
- `prefers-reduced-motion` disables scroll reveals, parallax, and continuous canvas animation.
