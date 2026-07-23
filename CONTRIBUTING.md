# Contributing Guide

TrustDB protects proof semantics, durable storage boundaries, and large-data paths. Contributions should be small, reviewable, and tied to a clearly scoped issue or maintenance task.

This guide is bilingual. The Chinese section is authoritative for day-to-day project work; the English section mirrors the same rules.

## 中文版

### 第一次参与

- 使用问题、部署讨论和尚未收敛的集成想法先发到 [GitHub Discussions](https://github.com/wowtrust/trustdb/discussions)。
- 首次代码或文档贡献优先选择 [`good first issue`](https://github.com/wowtrust/trustdb/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)。需要社区协作的任务见 [`help wanted`](https://github.com/wowtrust/trustdb/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)。
- 在 Issue 下留言说明准备处理的范围，维护者确认后再开始较大的改动，避免重复工作。
- 安全漏洞必须按照 [SECURITY.md](SECURITY.md) 私密报告，不要创建公开 Issue。

### 基本原则

- 先有 Issue，再有实现。Bug、功能、重构、文档、CI、发布和运维工作都要先说明背景、范围、验收标准和验证方式。
- 一个 PR 只解决一个主题。不要混入无关格式化、本地数据、构建产物、草稿文档或顺手重构。
- README 和用户文档只描述已经实现的能力，不把路线图写成现状。
- 改动 proof、WAL、proofstore、backup、SDK、HTTP/gRPC 或 desktop 主路径时，必须覆盖失败路径和边界条件。
- `main` 合并前必须通过 CI。CI 红了先看日志、定位原因，再修或明确残余风险。

### 分支命名

分支名只允许使用以下变更类型前缀：

| 类型 | 用途 | 示例 |
| --- | --- | --- |
| `feat/` | 新功能或用户可见能力 | `feat/admin-audit-log` |
| `fix/` | Bug 修复或回归修复 | `fix/restore-checkpoint-validation` |
| `docs/` | README、贡献指南、格式文档、模板 | `docs/standardize-templates` |
| `test/` | 测试补强、夹具、CI 覆盖 | `test/global-log-consistency` |
| `refactor/` | 不改变行为的结构调整 | `refactor/proofstore-indexes` |
| `perf/` | 性能优化 | `perf/batch-proof-range-read` |
| `security/` | 安全加固、鉴权、密钥、输入边界 | `security/admin-session-hardening` |
| `chore/` | 依赖、工具、发布、仓库维护 | `chore/update-ci-cache` |
| `ci/` | CI 配置和流水线 | `ci/cache-go-modules` |
| `build/` | 构建系统、打包、镜像 | `build/desktop-installer` |
| `release/` | 版本发布和发布说明 | `release/v1.2.0` |
| `revert/` | 回滚已合并变更 | `revert/restore-checkpoint-change` |

分支名使用小写 kebab-case，保持短而具体。

`dependabot/` 是 GitHub Dependabot App 专用的自动化命名空间，不用于人工分支。仓库分支规则必须仅对该 App 放行此命名空间，不能向普通用户开放规则绕过。

### Issue 标准

Issue 标题使用以下格式之一：

```text
[Bug] <简短问题>
[Feature] <用户可见能力>
[Task] <工程维护事项>
```

Issue 必须包含：

- 背景和真实问题。
- 影响范围：CLI、HTTP、gRPC、SDK、desktop、proof、WAL、proofstore、backup、global log、anchor、docs、CI 等。
- 目标和非目标。
- 安全、兼容性、迁移、恢复或性能影响。
- 验收标准。
- 验证计划。

不允许空白 Issue。公开 Issue 中不要放真实密钥、token、生产配置、客户数据或可利用的安全细节。

### PR 标准

PR 标题使用 Conventional Commit 风格：

```text
feat(scope): add ...
fix(scope): reject ...
docs(scope): update ...
test(scope): cover ...
refactor(scope): simplify ...
perf(scope): reduce ...
security(scope): harden ...
chore(scope): maintain ...
```

PR 描述必须包含：

- 关联 Issue：`Fixes #123`、`Closes #123` 或 `Refs #123`。
- 变更摘要。
- 证明语义、持久化、恢复、兼容性和规模路径影响。
- 已运行的测试和未运行测试的原因。
- 风险和回滚方式。

不要删除 PR 模板里的风险和验证字段。没有关联 Issue 的紧急修复必须在 PR 描述中说明原因，并在合并后补记录。

### 提交格式

提交信息使用 Conventional Commits：

```text
<type>(<scope>): <imperative summary>
```

允许的 `type`：

- `feat`: 新功能。
- `fix`: Bug 修复。
- `docs`: 文档。
- `test`: 测试。
- `refactor`: 不改变行为的重构。
- `perf`: 性能优化。
- `security`: 安全加固。
- `chore`: 工具、依赖、发布、仓库维护。
- `ci`: CI 配置。
- `build`: 构建系统。
- `revert`: 回滚。

示例：

```text
fix(backup): validate restore checkpoints
docs(github): standardize issue templates
security(admin): bound config update payloads
perf(global-log): avoid full tree rebuild for proofs
```

提交正文用于说明原因、兼容性、迁移方式或风险。不要把多个无关主题塞进同一个提交。

可选本地设置：

```powershell
git config commit.template .github/commit_message_template.txt
```

### 架构不变量

- L1-L5 的含义必须在 CLI、HTTP、gRPC、SDK、desktop 和 verifier 中保持一致。
- L4 只表示 batch root 进入 Global Transparency Log；L5 才表示 STH/global root 被外部锚定。
- `.sproof` 是推荐交换格式；`.tdproof`、`.tdgproof`、`.tdanchor-result` 是分步高级格式。
- 验证器必须独立复算 hash、signature、Merkle path、STH 和 anchor 绑定，不信任服务端等级标签。
- WAL accepted、batch committed、global log appended、anchor published 是不同 durable boundary。
- replay、outbox retry、backup restore 必须幂等。
- 生产路径不能重新引入全量扫描、全量排序、全量加载或为单个 proof 重建整棵树。
- 新文件写入必须考虑原子性、目录目标、路径边界、权限和失败清理。

### 测试门

按改动范围选择检查。后端主路径通常需要：

```powershell
go test ./...
go vet ./...
go test -race ./...
go test -tags=integration ./...
go test -tags=e2e ./...
```

前端和桌面相关改动通常需要：

```powershell
cd clients/web
npm ci
npm run build

cd ../desktop
go test ./...
go test -race ./...
```

如果某项检查无法运行，PR 必须说明原因和残余风险。

### 文档边界

- `README.md` 和 `README.zh-CN.md` 是用户入口，只写当前实现。
- `CONTRIBUTING.md` 维护协作、分支、Issue、PR、提交和质量门标准。
- `formats/` 记录稳定公开格式。
- `configs/` 记录可运行配置模板。
- 不提交本地密钥、数据库、备份包、构建产物、日志或临时演示文件。

## English Version

### First contribution

- Use [GitHub Discussions](https://github.com/wowtrust/trustdb/discussions) for support, deployment questions, and integration ideas that are not yet scoped.
- Start with a [`good first issue`](https://github.com/wowtrust/trustdb/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22), or browse [`help wanted`](https://github.com/wowtrust/trustdb/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) for community work.
- Comment on the issue with the scope you plan to handle and wait for maintainer confirmation before beginning a large change.
- Report vulnerabilities privately according to [SECURITY.md](SECURITY.md), never through a public issue.

### Core Rules

- Start with an issue for bugs, features, refactors, docs, CI, release, and operations work.
- Keep each PR focused on one topic.
- User-facing docs must describe implemented behavior only.
- Changes to proof semantics, WAL, proofstore, backup, SDK, HTTP/gRPC, or desktop paths need tests for boundaries and failures.
- `main` must pass CI before merge.

### Branch Names

Branch names must use one of these type prefixes:

| Prefix | Purpose |
| --- | --- |
| `feat/` | New user-facing capability |
| `fix/` | Bug or regression fix |
| `docs/` | Documentation and templates |
| `test/` | Test coverage |
| `refactor/` | Behavior-preserving structure changes |
| `perf/` | Performance work |
| `security/` | Security hardening |
| `chore/` | Tooling, dependencies, release, repo maintenance |
| `ci/` | CI configuration and pipelines |
| `build/` | Build systems, packaging, images |
| `release/` | Version release and release notes |
| `revert/` | Reverting merged changes |

Use lowercase kebab-case, for example `fix/restore-checkpoint-validation`.

`dependabot/` is an automated namespace reserved for the GitHub Dependabot App, not a prefix for human-authored branches. Repository branch rules must permit that namespace only for the App without granting rule bypasses to regular users.

### Issues

Issue titles use:

```text
[Bug] <short problem>
[Feature] <capability>
[Task] <maintenance work>
```

Every issue should state context, affected area, goals, non-goals, risk, acceptance criteria, and validation.

### Pull Requests

PR titles use Conventional Commit style:

```text
fix(scope): reject malformed restore checkpoints
docs(github): standardize templates
```

PR bodies must link the issue, summarize the change, explain proof/storage/recovery/compatibility impact, list validation, and describe risk or rollback.

### Commits

Commit messages use:

```text
<type>(<scope>): <imperative summary>
```

Allowed types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `security`, `chore`, `ci`, `build`, `revert`.

Optional local setup:

```powershell
git config commit.template .github/commit_message_template.txt
```

### Validation

Run the narrowest relevant checks while iterating and the broader checks before merge. If a relevant check cannot run, document why and state the residual risk in the PR.
