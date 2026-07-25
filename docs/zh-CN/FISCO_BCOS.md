# FISCO BCOS 锚定中文部署指南

TrustDB 的 FISCO BCOS sink 把一个精确的 Signed Tree Head 发布到
`TrustDBAnchorV1` 合约，并把交易回执 inclusion、block/header、PBFT finality、
validator transition 和链身份材料装入 `.sproof v2`。离线验证时不连接 TrustDB、
BCOS 节点或网络。

完整参数、失败阶段和证据字段以
[英文运维手册](../integrations/FISCO_BCOS_OPERATIONS.md)为准；本文给出中文上线路径。

## 1. 能证明什么

成功的 L5 验证证明：目标记录属于一个 batch，该 batch root 属于精确 Signed STH，
该 STH payload 被指定合约收录到指定 BCOS 链的最终区块，并且证据与本地可信
TrustConfig 完整匹配。

它不表示：

- BCOS block time 自动等于法定可信时间戳；
- 上链自动获得司法认可；
- 支持 SM2/SM3/SM4 就自动通过密评、等保或产品认证。

这些边界不削弱技术能力，而是避免把可验证事实错误扩大为合规结论。

## 2. 当前支持矩阵

| 部署形态 | 标准模式 | 国密模式 | 当前结论 |
| --- | --- | --- | --- |
| Air，Linux/amd64，四节点 | CI 完整 qualification | 独立 CI 完整 qualification | 可按本文上线 |
| Air，Linux/arm64 | 仅 artifact 校验 | 仅 artifact 校验 | 缺少原生四节点 qualification，拒绝生产准入 |
| Air，macOS/arm64 | 开发 smoke | 开发 smoke | 开发测试，不等同 Linux 生产 |
| Pro / Max | 未准入 | 未准入 | 必须按手册单独完成完整 admission |
| 容器 | 无固定 v3.16.3 image digest | 同左 | 未准入 |

TrustDB 当前固定 FISCO BCOS `v3.16.3` 兼容矩阵和 C SDK `v3.6.0`。部署前执行：

```bash
python3 scripts/fisco-bcos/compatibility.py validate

python3 scripts/fisco-bcos/compatibility.py check \
  --deployment air --crypto standard --platform linux/amd64

python3 scripts/fisco-bcos/compatibility.py check \
  --deployment air --crypto guomi --platform linux/amd64
```

## 3. 构建和资格验证

生产 publisher 需要 `CGO_ENABLED=1`、`fiscobcos_sdk` build tag 和已校验的 C SDK
动态库。上游二进制必须先按固定大小和 SHA-256 验证：

```bash
python3 scripts/fisco-bcos/compatibility.py verify-artifacts \
  --platform linux/amd64 \
  --cache-dir /var/cache/trustdb/fisco-bcos

python3 scripts/fisco-bcos/build_anchor_contract.py \
  --platform linux/amd64 \
  --cache-dir /var/cache/trustdb/fisco-bcos \
  --check
```

在目标环境分别运行标准和国密四节点 qualification：

```bash
sudo unshare --net -- true

scripts/fisco-bcos/smoke-air.sh \
  --mode standard --qualification \
  --work-dir /tmp/trustdb-bcos-standard \
  --cache-dir /var/cache/trustdb/fisco-bcos

scripts/fisco-bcos/smoke-air.sh \
  --mode guomi --qualification \
  --work-dir /tmp/trustdb-bcos-guomi \
  --cache-dir /var/cache/trustdb/fisco-bcos
```

通过条件包括真实四节点交易、单 validator 停止与追赶、validator 权重变化、
provider journal replay、`.sproof v2` 导出、节点全停、`unshare --net` 断网验证和
分阶段篡改拒绝。标准/国密结果不能互相代替。

## 4. 合约和 publisher

部署 `contracts/fisco-bcos/TrustDBAnchorV1.sol` 的固定 standard/guomi artifact：

1. 先执行 artifact `--check`；
2. 部署后读取 runtime bytecode，按模式使用 Keccak-256 或 SM3，与 manifest 匹配；
3. 保存 chain/group、genesis、checkpoint、contract address、部署交易/区块、runtime
   code hash、管理员、publisher 和审批记录；
4. publisher 最小授权，不存业务明文，不使用可替换 proxy；
5. 私钥生产环境使用 remote、PKCS#11 或 SDF plugin，不能回退到 core 软件私钥。

## 5. 创建 canonical TrustConfig

从受控部署记录填写 JSON。标准/国密示例分别参考：

- `configs/fisco-bcos-trust-config.example.json`
- `configs/fisco-bcos-guomi-trust-config.example.json`

JSON 至少固定 crypto mode、chain/group、genesis、trusted checkpoint、contract、
endpoints/read quorum、account provider、证书和 validators。转换成 canonical CBOR：

```bash
trustdb anchor fisco-bcos trust-config create \
  --input /etc/trustdb/fisco/trust-config.json \
  --out /etc/trustdb/fisco/trust-config.cbor

trustdb anchor fisco-bcos trust-config inspect \
  --input /etc/trustdb/fisco/trust-config.cbor
```

保存 inspect 输出和 config digest。TrustConfig 至少配置两个 endpoint，
`read_quorum >= 2`；endpoint 不得携带 URL credential。

## 6. 配置外部 signer

TrustConfig 中 `account_provider.provider` 选择 `remote`、`pkcs11` 或 `sdf` 时，
TrustDB YAML 必须配置对应监督进程：

```yaml
crypto:
  signer_plugins:
    sdf:
      command: "/usr/local/libexec/trustdb-sdf-signer"
      args: ["--config", "/etc/trustdb/sdf-signer.yaml"]
      inherit_env: []
      start_timeout: "10s"
      rpc_timeout: "30s"
      max_concurrency: 8
```

启动会校验 provider 返回的公开 key、算法、suite 和 key reference。plugin 只托管
私钥运算；suite、framing、哈希和验证仍由 TrustDB 核心执行。

## 7. 开启锚定

YAML：

```yaml
global_log:
  enabled: true
  log_id: "production-log-2026"

anchor:
  scope: "global"
  sink: "fisco-bcos"
  max_delay: "5m"
  poll_interval: "2s"
  fisco_bcos:
    trust_config_file: "/etc/trustdb/fisco/trust-config.cbor"
```

或使用 CLI：

```bash
trustdb serve \
  --config /etc/trustdb/production.yaml \
  --anchor-sink fisco-bcos \
  --anchor-fisco-bcos-trust-config /etc/trustdb/fisco/trust-config.cbor
```

启动 probe 会逐 endpoint 校验 chain ID、group ID、genesis、checkpoint、crypto mode、
合约 runtime code hash 和保守 quorum height。任何身份/代码不一致都永久失败；
不足 quorum 暂停发布并保留 durable intent。

## 8. 验证真正生效

1. 提交 canary 并等待 L4 STH；
2. 等待固定、非滑动的 `anchor.max_delay` 窗口；
3. 检查 anchor scheduler 从 Pending/InFlight 到 immutable result；
4. 导出 `.sproof v2`；
5. 准备验证者本地 trust roots：客户端/服务端公钥和 canonical TrustConfig；
6. 停止 TrustDB 和全部 BCOS 节点，在断网环境验证；
7. 分别篡改 record/path/STH/receipt/block/finality/TrustConfig，全部必须失败。

证据文件自带的公钥、validator 或 TrustConfig 不能自动成为信任根。

## 9. checkpoint 与 validator 变化

TrustConfig v2 用 authenticated transition chain 推进 checkpoint。先用当前 config
导出/取得完整 `.sproof` transition evidence，再执行：

```bash
trustdb anchor fisco-bcos trust-config advance \
  --input /etc/trustdb/fisco/trust-config.cbor \
  --evidence /var/lib/trustdb/evidence/validator-transition.sproof \
  --expect-current-digest <当前32字节config-digest> \
  --out /etc/trustdb/fisco/trust-config.cbor
```

`--input` 与 `--out` 必须是同一文件。命令要求目标区块严格更高、当前 digest 匹配，
并原子更新 generation/previous digest。保留 old/new digest 和报告；未知来源的
`.advance.lock` 不能直接删除。

## 10. 关闭与恢复

关闭新锚定：

1. 摘流或停止新写入；
2. 检查是否有 InFlight 和未知外部交易结果；
3. 优雅停止服务；
4. 设置 `anchor.sink=off` 后重启；
5. 保留 TrustConfig、合约部署记录、证书、publisher descriptor、scheduler journal、
   anchor result 和链证据。

不要删除 InFlight 来“取消”交易。一旦可能产生外部副作用，失败重试必须继续使用
同一 STH 和 provider state；只有精确成功结果能原子完成该 attempt。

## 11. 监控和告警

至少采集：

- `trustdb_anchor_provider_quorum_healthy`；
- `trustdb_anchor_provider_endpoint_healthy/stale/height`；
- `trustdb_anchor_provider_quorum_failures_total`；
- `trustdb_anchor_provider_retry_events_total`；
- `trustdb_anchor_published_total`。

`insufficient` 通常是可恢复的可用性/滞后问题；`disagreement` 表示 endpoint 对链
身份、合约或记录产生冲突，必须作为安全事件停止发布并保存冲突响应。

## 12. 备份边界

`.tdbackup v4` 会保存 immutable anchor result、Pending/InFlight 和 FISCO BCOS
provider state，但不保存 publisher 私钥、证书、TrustConfig、节点数据或 SDF
recovery bundle。当前 backup v4 只支持 `INTL_V1`；国密链或国密 TrustDB suite
不应被错误改标以绕过限制。完整策略见[备份与恢复](BACKUP_AND_RECOVERY.md)。

## 13. 上线清单

- [ ] 当前 topology/mode/platform 在兼容矩阵为 admitted。
- [ ] 上游 artifact、C SDK、合约编译产物和 runtime code hash 已验证。
- [ ] 四节点 standard/guomi qualification 在目标环境分别通过。
- [ ] publisher 使用受控 provider，至少双 endpoint、read quorum >= 2。
- [ ] canonical TrustConfig 已 inspect、双人复核、备份并记录 digest。
- [ ] canary 达到 L5，断网验证与分阶段篡改测试通过。
- [ ] endpoint disagreement、unknown outcome、validator transition 和恢复已演练。
- [ ] 对外材料区分 STH 时间、BCOS block time 和可信时间戳。
