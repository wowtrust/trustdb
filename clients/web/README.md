# TrustDB Admin Web

Vue 3 + Vite + Pinia + Tailwind 运维控制台，风格对齐 `clients/desktop/frontend`。

## 开发

```bash
npm ci
npm run dev
```

默认将 `/admin/api` 代理到 `http://127.0.0.1:8080`。请先启用服务端 `admin` 配置并运行 `trustdb serve`。

当前控制台使用 `trustdb.admin-policy.v1`，不再读取单用户名/单密码配置。先执行
`trustdb admin policy bootstrap` 建立系统、安全、审计三员分立账号；角色、CLI、
MFA/OIDC/mTLS 接入和紧急恢复见
[管理 RBAC 手册](../../docs/zh-CN/ADMINISTRATIVE_RBAC.md)。

## 生产构建

```bash
npm ci
npm run build
```

将 `admin.web_dir` 指向本目录下的 `dist`（需包含 `index.html`）。
