# 备份、恢复与灾难恢复

TrustDB 当前只创建和读取 `.tdbackup v5`。它把 proofstore 中可恢复的证据状态导出
为流式 PAX tar，并使用随机 DEK 对压缩后的 archive 进行 SM4-GCM 分帧加密。旧
`.tdbackup v4` 不读取、不迁移、不回退；输入旧文件会明确返回 unsupported format。

恢复成功不能只看命令退出码。最终验收必须同时证明：目标 proofstore 可以启动、
历史 `.sproof v2` 可以断网验证、immutable anchor result 未改变、Pending/InFlight
调度状态可以安全续跑。

## 1. v5 解决了什么

每个 archive 都固定绑定以下公开身份：

- `trustdb.backup.v5`、proofstore format generation 5；
- `INTL_V1` 或 `CN_SM_V1`；
- 来源 NodeID、LogID 和 NamespaceID；
- 创建时间、BackupID、压缩算法、KEK provider 名称和非秘密 key ID；
- 每个 entry 的连续 ordinal、path、type、size、suite 与摘要。

`INTL_V1` entry 使用 SHA-256，`CN_SM_V1` entry 使用 SM3。archive 内容使用随机
128-bit DEK 和 SM4-GCM；DEK 由 KEK provider 包装，文件中只有 opaque wrapped
DEK。默认 1 MiB 一帧，每帧绑定 header digest、ordinal、长度和 flags；独立的最终
认证帧用于检测截断和尾随数据。修改 header、manifest、entry、tag，交换帧顺序，
使用错误 KEK，或在最终帧后追加数据都会验证失败。

恢复在写第一条数据前完整执行一次 verify。随后第二次读取仍重新验证所有 SM4-GCM
帧，并比较 envelope 与 manifest，避免文件在 verify 和 restore 之间被替换。

## 2. archive 包含和不包含什么

包含：

- batch manifest、ProofBundle、batch root、batch tree leaf/node；
- Global Log leaf、node、state、Signed Tree Head、history tile 和 durable outbox；
- 精确的 immutable `STHAnchorResult`，包括 FISCO BCOS 离线证据；
- STH anchor scheduler 的 Pending、InFlight、generation、重试和 provider state。
- `paths.key_registry` 指向的 V2 key registry：它保存公开 key descriptor 与签名的
  key lifecycle audit event，不包含 descriptor 所引用的私钥或 credential。

不包含：

- 客户端、服务端、registry 或 anchor publisher 私钥；
- passphrase、KEK、KMS credential、PIN、token、HSM/SDF 设备秘密；
- SDF recovery bundle、TrustDB YAML、证书、TLCP manifest、BCOS TrustConfig；
- WAL、原始业务文件、对象存储、NATS stream/result/DLQ；
- TiKV 集群的 PD/Region 物理灾备材料。

因此 `.tdbackup` 是 proofstore 逻辑恢复材料，不是整套系统的唯一灾备包。配置、公开
信任根、私钥 provider 恢复材料、WAL/对象/NATS/BCOS 灾备必须分开保护。

## 3. KEK provider 与秘密输入

核心备份 API 使用 `keyenvelope.KEKProvider`，KEK 可以留在 HSM/KMS/provider
边界内，TrustDB 只接收被包装的随机 DEK。CLI 当前内置
`passphrase-dev-v1`，用于开发和离线恢复演练，不应被描述为 HSM、KMS、SDF 或
经认证的生产密码设备。

CLI 不接受 passphrase 参数，避免秘密进入 shell history 和进程列表。必须只设置下列
两种来源之一：

- `TRUSTDB_BACKUP_PASSPHRASE`
- `TRUSTDB_BACKUP_PASSPHRASE_FILE`

passphrase 文件必须是普通文件；Unix 权限不得向 group/other 开放。passphrase 长度
必须为 12–1024 bytes。

Linux/macOS（交互读取，不回显）：

```bash
read -r -s TRUSTDB_BACKUP_PASSPHRASE
export TRUSTDB_BACKUP_PASSPHRASE
printf '\n'
```

Windows PowerShell（临时写入当前用户 ACL 保护的文件）：

```powershell
$SecretPath = Join-Path $env:LOCALAPPDATA "TrustDB\backup-passphrase.txt"
New-Item -ItemType Directory -Force (Split-Path $SecretPath) | Out-Null
$Secure = Read-Host "Backup passphrase" -AsSecureString
$Plain = [System.Net.NetworkCredential]::new("", $Secure).Password
[System.IO.File]::WriteAllText($SecretPath, $Plain)
icacls $SecretPath /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
$env:TRUSTDB_BACKUP_PASSPHRASE_FILE = $SecretPath
$Plain = $null
```

`backup.key_id` 或 `--key-id` 只是写入 header 的非秘密 KEK 引用，不是密钥文件路径。
`--out` 是最终加密 `.tdbackup` 文件的路径；父目录会创建，同目录临时文件只有在
archive 完整关闭并 fsync 后才原子发布。

`--key-registry` 默认取 `paths.key_registry`。create 会完整解析 V2 registry、验证事件
签名链和 suite 后才纳入 archive；只有 magic 前缀但内容损坏的文件会导致创建失败。
确实没有 registry 的部署可显式使用 `--key-registry=`，此时 manifest inventory 也不会
声称包含 key-registry evidence。

## 4. 配置

```yaml
backup:
  compression: "gzip"             # gzip | none
  key_provider: "passphrase-dev-v1"
  key_id: "development-backup-key" # 非秘密引用
  frame_bytes: 1048576              # 65536..16777216
```

压缩发生在加密前。较小帧能更早发现损坏并降低单帧内存，较大帧减少 AEAD 调用；默认
1 MiB 是吞吐和内存的折中。不要为了吞吐关闭认证或复用旧 archive 的 nonce/DEK。

## 5. 创建备份

备份前停止或冻结写入，记录版本、suite、NodeID、LogID、backend、配置 digest，
并确认输出介质不与 proofstore/WAL 位于同一故障域。

Linux/macOS：

```bash
trustdb backup create \
  --metastore pebble \
  --metastore-path /var/lib/trustdb/proofs/pebble \
  --crypto-suite CN_SM_V1 \
  --compression gzip \
  --key-provider passphrase-dev-v1 \
  --key-id development-backup-key \
  --key-registry /var/lib/trustdb/keys.tdkeys \
  --out /var/backups/trustdb/proofstore-20260725T020000Z.tdbackup
```

Windows PowerShell：

```powershell
.\trustdb.exe backup create `
  --metastore pebble `
  --metastore-path "D:\TrustDB\proofs\pebble" `
  --crypto-suite CN_SM_V1 `
  --compression gzip `
  --key-provider passphrase-dev-v1 `
  --key-id development-backup-key `
  --key-registry "D:\TrustDB\keys.tdkeys" `
  --out "E:\TrustDB-Backup\proofstore-20260725T020000Z.tdbackup"
```

file backend 把 `--metastore pebble --metastore-path ...` 替换为
`--metastore file --proof-dir ...`。create 报告中的对象计数应与变更记录对比，不能
接受无解释的骤降或意外为零。

## 6. 验证

Linux/macOS：

```bash
trustdb backup verify \
  --key-provider passphrase-dev-v1 \
  --file /var/backups/trustdb/proofstore-20260725T020000Z.tdbackup
```

Windows PowerShell：

```powershell
.\trustdb.exe backup verify `
  --key-provider passphrase-dev-v1 `
  --file "E:\TrustDB-Backup\proofstore-20260725T020000Z.tdbackup"
```

verify 会完整解密并检查 final frame、gzip footer、tar 结构、严格 PAX control
metadata、确定性 CBOR、entry 摘要、manifest inventory 和对象类型。外部介质摘要
可以用于传输清单，但不能替代 v5 内部认证。

## 7. 恢复

目标必须是全新空 namespace，或持有同一 BackupID checkpoint 的中断恢复目标。
suite、format generation、NodeID、LogID 必须与 archive 一致；目标 NamespaceID
允许不同，因此可恢复到新目录或在 file/Pebble/TiKV 实现之间迁移。来源和目标
NamespaceID 会同时写入 checkpoint，不能把 checkpoint 换到另一目标继续。

Linux/macOS：

```bash
trustdb backup restore \
  --file /var/backups/trustdb/proofstore-20260725T020000Z.tdbackup \
  --metastore pebble \
  --metastore-path /var/lib/trustdb-restore/proofs/pebble \
  --crypto-suite CN_SM_V1 \
  --key-provider passphrase-dev-v1 \
  --checkpoint /var/lib/trustdb-restore/restore-checkpoint.json \
  --recovery-dir /var/lib/trustdb-restore/recovery \
  --resume
```

Windows PowerShell：

```powershell
.\trustdb.exe backup restore `
  --file "E:\TrustDB-Backup\proofstore-20260725T020000Z.tdbackup" `
  --metastore pebble `
  --metastore-path "D:\TrustDB-Restore\proofs\pebble" `
  --crypto-suite CN_SM_V1 `
  --key-provider passphrase-dev-v1 `
  --checkpoint "D:\TrustDB-Restore\restore-checkpoint.json" `
  --recovery-dir "D:\TrustDB-Restore\recovery" `
  --resume
```

`--resume` 默认开启。checkpoint 记录最后完成的 archive ordinal；batch tree 的一组
leaf/node 在对应 manifest 成功前不会推进 checkpoint，崩溃后可幂等重放。
key registry 不会覆盖当前运行实例的 registry；它恢复到 `--recovery-dir` 下的
`key-registry.tdkeys`，由操作者使用独立可信 registry 公钥验证后再安装。

## 8. 恢复验收

1. 在隔离环境启动恢复实例，确认 `/healthz`、日志和 metrics 没有 schema/suite/
   namespace 错误。
2. 对照 create/verify/restore 报告检查 manifest、bundle、root、STH、anchor result、
   schedule 和 batch tree 数量。
3. 查询备份前记录并重新导出 `.sproof v2`。
4. 断开网络，用本地可信公钥、证书和 BCOS TrustConfig 完成离线验证。
5. 篡改原文件、proof path、STH、anchor proof 和信任根，确认负向验证失败。
6. 检查 Pending/InFlight：可能已产生外部副作用的 InFlight 不能换成更高 STH。
7. 完成验收后再切换服务；原目录保持只读直到回退窗口结束。

## 9. 外部系统灾备

| 状态 | 必须另行保护的内容 |
| --- | --- |
| WAL | namespace/WAL identity、segment、checkpoint；不要把其他 LogID 的 WAL 接到恢复库。 |
| 原文件/对象 | 对象版本、保留锁、复制和业务恢复点；TrustDB 通常只保存摘要与元数据。 |
| NATS JetStream | stream、consumer、result、DLQ，并与 proofstore 恢复点对齐。 |
| FISCO BCOS | 节点数据、证书、合约部署记录、canonical TrustConfig 和 validator history。 |
| 软件 key envelope | 与 passphrase/KEK 分域保护；不得把二者放入同一 archive。 |
| remote/PKCS#11/SDF/HSM/KMS | provider 自身 HA、备份、key ceremony、公开 descriptor 与版本记录。 |
| 配置与证书 | 去密 YAML、digest、证书链、TLCP profile、TrustConfig 和变更审批。 |

## 10. KEK 丢失与轮换演练

V5 没有恢复后门。KEK、对应 HSM/KMS key version 或开发演练 passphrase 丢失后，相关
archive 必须视为不可恢复；不能改 header 的 `key_id`，也不能跳过 GCM tag。至少每季度
执行一次以下 tabletop，并把结果纳入变更记录：

1. 用当前 KEK 创建、验证并在断网隔离环境恢复一个 archive。
2. 创建新 KEK/key version，把 `backup.key_id` 切到新引用，创建第二个 archive。
3. 分别用旧、新 provider 版本验证各自 archive，并确认交叉使用失败。
4. 保留旧 KEK 到最后一个旧 archive 超出保留期；删除前记录 archive inventory、到期
   日期、审批人与两次恢复演练结果。
5. 模拟当前 KEK 不可用，确认任务明确失败、不会生成明文/半成品 archive，也不会回退
   到其他 provider。

V5 当前不提供原地 rewrap。需要提前淘汰旧 KEK 时，应在隔离环境用旧 KEK 完整恢复，
验证证据后再用新 KEK 创建新 archive；新旧备份报告和离线验证结果要一起留档。

## 11. 常见故障

| 症状 | 处理 |
| --- | --- |
| `unsupported backup format: expected encrypted .tdbackup v5` | 输入了 v4/plain tar；使用产生该旧文件的版本做人工审计，新版本不迁移。 |
| `backup authentication failed` | passphrase/KEK 错误，或 header/frame/tag 被修改；保留介质现场，不要覆盖最后一份好备份。 |
| `truncated before its final frame` | 文件截断或复制未完成；重新传输并核对介质清单。 |
| `namespace bindings do not match` | suite、NodeID 或 LogID 不一致；建立正确身份的空目标，不能改 archive 字段绕过。 |
| `restore destination is not empty` | 目标已有业务数据；换新 namespace，或使用与该中断恢复严格配对的 checkpoint。 |
| checkpoint binding mismatch | archive、来源或目标被换过；恢复正确配对并调查原 checkpoint。 |
| Pebble lock 被占用 | 服务或另一任务仍持有目录；正常停止 owner，不要强删锁文件。 |

每次发布、密钥轮换、TrustConfig advance 和 backend 变更前后都应创建并验证备份。
至少每月恢复到全新 namespace，每季度执行 proofstore、provider、BCOS、NATS 和对象
存储的联合演练，并记录 RPO、RTO、BackupID、suite、失败注入与离线验证结果。
