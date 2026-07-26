# 发布供应链、离线验签与国产镜像运维

本手册适用于 `v2.0.0-rc.1` 及此后由受控工作流生成的版本，说明如何约束
发布输入、生成可留存的发布证据，以及目标环境完全断网时如何验证并导入
TrustDB。历史 `v1.0.0` 只提供 `SHA256SUMS`，不具备本文所述的新证据包。

## 正式发布必须携带什么

| 文件 | 作用 | 信任方式 |
| --- | --- | --- |
| `TRUSTDB_RELEASE_MANIFEST.json` | 记录源 commit、策略摘要、必备文档，以及每个文件的大小、SHA-256、SM3 | 必须先验证它的 Sigstore 证明，才能信任内部摘要 |
| `trustdb-release-attestation.sigstore.json` | GitHub Actions 对 manifest 签发的构建来源证明 | 使用单独保管的本地 trusted root 验证 |
| `SHA256SUMS` / `SM3SUMS` | 覆盖 manifest 与全部发布文件的双摘要 | 两份都必须与已验签 manifest 精确一致 |
| `trustdb-release.spdx.json` | SPDX JSON 依赖和许可证清单 | 必须在 manifest 中；上线前处理 `NOASSERTION` 或例外 |
| `TRUSTDB_PRODUCTION_INPUTS.json` | 原生 SDK、合约、lock、镜像、许可证与架构矩阵 | 摘要必须等于 manifest 中的 policy digest |
| `TRUSTDB_VULNERABILITY_REPORT.json` | npm 与 `govulncheck` 的留存结果 | 必须对应同一个源 commit |
| `TRUSTDB_CONTAINER_DIGESTS.json` | 多架构 OCI digest 与仓库引用 | 始终按 digest 导出、镜像和导入 |
| `trustdb-container-attestation.sigstore.json` | 精确 OCI digest 的来源证明 | 使用同一份独立 trusted root 验证 |

以下任一情况都会在发布前失败：

- release workflow 中 Action 使用浮动 tag，而不是完整 40 位 commit；
- Docker 基础镜像没有通过策略控制的 `name@sha256:digest` 引用；
- FISCO BCOS C/Go SDK、合约、PKCS#11、SDF、TLCP、Go/npm/桌面/官网
  输入缺失、字节变化、许可证未解决或没有架构声明；
- `go mod verify`、任一 npm 高危审计或 `govulncheck` 失败；
- SBOM、漏洞报告、生产输入矩阵、容器摘要、双摘要或来源证明生成失败；
- 发布目录中出现 manifest 未覆盖的文件，或缺少必备文档。

## 信任根必须独立下发

绝不能把“和 release 放在一起的 root 文件”直接当成信任根，否则攻击者可以
同时替换产物、签名和自称的 root。

维护窗口前，应通过独立批准渠道取得 GitHub/Sigstore trusted-root 快照，并
把 SHA-256 登记到组织信任根台账：

```bash
gh attestation trusted-root > github-public-good-trusted-root.json
sha256sum github-public-good-trusted-root.json
```

将已批准的 GitHub CLI、trusted root、预期仓库身份 `wowtrust/trustdb` 和
目标版本保存在只读介质或认证内部制品库。root 轮换是独立安全变更，不能在
TrustDB 升级时被隐式接受。

## 在联网中转区验证

把 release 全部文件下载到一个空目录，trusted root 放在目录外：

```bash
mkdir trustdb-release
gh release download vX.Y.Z \
  --repo wowtrust/trustdb \
  --dir trustdb-release

APPROVED_COMMIT=replace-with-approved-40-character-commit
gh attestation verify \
  trustdb-release/TRUSTDB_RELEASE_MANIFEST.json \
  --repo wowtrust/trustdb \
  --signer-workflow wowtrust/trustdb/.github/workflows/release.yml \
  --source-digest "$APPROVED_COMMIT" \
  --deny-self-hosted-runners \
  --bundle trustdb-release/trustdb-release-attestation.sigstore.json \
  --custom-trusted-root /secure/trust-roots/github-public-good-trusted-root.json
```

`APPROVED_COMMIT` 必须来自签字的发版审批记录或另一条独立仓库渠道，不能从
尚未信任的 manifest 中读取。然后使用**此前已经准入的** TrustDB verifier
验证精确文件集合与双摘要：

```bash
trustdb release verify --dir trustdb-release
```

命令会拒绝路径穿越、符号链接、子目录、多余文件、必备文档缺失、重复 checksum、
大小变化，以及任何 SHA-256/SM3 不一致。不要把同一 release 中尚未验证的
新二进制当作唯一 verifier。没有旧 verifier 时，应先独立核对两份 checksum，
再解压已通过摘要准入的新二进制做第二次交叉检查。

上线审批前检查：

```bash
jq . trustdb-release/TRUSTDB_PRODUCTION_INPUTS.json
jq . trustdb-release/TRUSTDB_VULNERABILITY_REPORT.json
jq . trustdb-release/TRUSTDB_CONTAINER_DIGESTS.json
```

## 断网介质与目标环境导入

对已验证 release 和独立 trusted root 生成介质清单：

```bash
find trustdb-release -maxdepth 1 -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum > transfer-media.sha256
sha256sum /secure/trust-roots/github-public-good-trusted-root.json \
  >> transfer-media.sha256
```

将 release、可信 verifier、trusted root 与介质清单写入受控介质。在断网区：

1. 验证介质清单；
2. 把 release 复制到空目录；
3. 使用 `--bundle` 与 `--custom-trusted-root` 重做 `gh attestation verify`；
4. 重做 `trustdb release verify`；
5. 核对版本、source commit、policy digest 和目标架构；
6. 只解压匹配系统/架构的包；
7. 执行 `trustdb version`、`config validate`、`doctor`；
8. 隔离启动 canary，导出 `.sproof v2`，停止服务并用独立证据信任根离线验证。

至少在业务证据保存期内，保留 manifest、两份 attestation bundle、双 checksum、
生产输入矩阵、SBOM、漏洞报告、审批记录和介质清单。

## OCI 导出、国产镜像与离线导入

从 `TRUSTDB_CONTAINER_DIGESTS.json` 读取不可变 digest，不能导出 `latest`：

```bash
DIGEST="$(jq -r .digest trustdb-release/TRUSTDB_CONTAINER_DIGESTS.json)"
skopeo copy --all \
  "docker://ghcr.io/wowtrust/trustdb@${DIGEST}" \
  oci-archive:trustdb-X.Y.Z.oci.tar
skopeo inspect --format '{{.Digest}}' \
  oci-archive:trustdb-X.Y.Z.oci.tar
```

inspect 结果必须精确等于 `DIGEST`，并把 OCI archive 的 SHA-256 加入介质清单。
在断网主机导入：

```bash
skopeo inspect --format '{{.Digest}}' \
  oci-archive:trustdb-X.Y.Z.oci.tar
skopeo copy --all \
  oci-archive:trustdb-X.Y.Z.oci.tar \
  docker-daemon:trustdb:X.Y.Z
```

同步到国产制品库时复制完整 manifest list，并要求目标 digest 不变：

```bash
skopeo copy --all \
  "docker://ghcr.io/wowtrust/trustdb@${DIGEST}" \
  "docker://registry.example.cn/wowtrust/trustdb@${DIGEST}"
skopeo inspect --format '{{.Digest}}' \
  "docker://registry.example.cn/wowtrust/trustdb@${DIGEST}"
```

源码构建可复制 `supply-chain/domestic-mirrors.env.example`，配置已批准的
Go/npm 镜像，并在不重写 OCI manifest 的前提下镜像三种基础镜像。构建时用
`NODE_IMAGE`、`GO_IMAGE`、`RUNTIME_IMAGE` 传入国产仓库中的同 digest 引用。
镜像只改变下载路线，不能削弱 `go.sum`、npm integrity、policy digest 或 OCI
digest 校验。

## 原生库、合约与架构矩阵

`supply-chain/production-inputs.json` 是机器强制执行的清单，每项都记录：

- 精确 release、commit、ABI、编译器或 lock generation；
- 文件/目录 canonical SHA-256；
- license expression 与仓库内证据路径；
- 已准入的系统和架构。

当前覆盖 vendored FISCO BCOS C SDK/Go SDK、标准/国密合约源文件和编译产物、
PKCS#11、版本化 SDF adapter ABI、可复现 TLCP gateway baseline、服务端/桌面
Go 图、全部 npm 图和 Docker 基础镜像。厂商 SDF 动态库、HSM 固件、已部署
BCOS 合约、运维证书仍是部署输入，必须在项目 dossier 中另行记录版本、摘要、
许可、架构、测评结果与保管责任。

## 如何升级一个生产输入

不能只手改摘要。一个小 PR 内按顺序完成：

1. 更新源码、lock、SDK、编译器、合约或镜像；
2. 复核许可证与架构支持；
3. 执行 `trustdb release digest-input --path <仓库相对路径>`；
4. 更新 `supply-chain/production-inputs.json`；
5. 执行 `trustdb release verify-policy`；
6. 跑单测、race、跨平台、漏洞、合约和相关硬件 qualification；
7. 用同一 commit 和 commit timestamp 构建两次并比较产物；
8. 若门禁暂时不能通过，登记审批例外和到期时间。

任何失败都不能静默降级到浮动 tag、未签名文件、未知许可证或旧二进制。

## 洁净环境演练

每季度用一台无 TrustDB cache、无网络的主机，只提供登记过的 verifier、
trusted root、release bundle、OCI archive 和部署 secrets：

- 验证 provenance 与全部摘要；
- 导入包和镜像；
- 把测试备份恢复到新 namespace；
- 生成并离线验证 canary `.sproof v2`；
- 分别篡改包字节、manifest 摘要、attestation、trusted root、OCI digest 和
  SBOM/policy 文件，要求在预期阶段全部失败。

记录耗时、操作人、工具版本、root digest、source commit、平台、失败阶段和
整改项。演练未通过的版本不能标记为可离线/隔离区部署。
