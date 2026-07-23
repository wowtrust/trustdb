# ADR-0005：Proofstore 不可变密码套件标记

> 状态：Accepted
>
> 日期：2026-07-24
>
> 关联 Issue：[#446](https://github.com/wowtrust/trustdb/issues/446)

## 1. 决策

TrustDB 的 file、Pebble 和 TiKV proofstore namespace 必须在首次空库初始化时持久化同一结构的 suite marker。marker 与 storage schema 元数据处于同一个 durable initialization boundary；启动配置必须与已存 marker 精确相等，任何缺失、未知、损坏或不一致都在服务接收流量前 fail closed。

当前 marker 使用 deterministic CBOR，字段为：

```text
schema_version     = trustdb.proofstore-suite-marker.v1
storage_schema     = trustdb-proofstore-v4
format_generation  = 4
crypto_suite       = INTL_V1 | CN_SM_V1
```

`crypto_suite` 大小写敏感，不做别名、trim、默认推断或未知值回退。调用方未显式配置 suite 时，仅“新建/打开当前默认部署”的请求值为 `INTL_V1`；一旦 namespace 非空，缺失 marker 绝不据此补写。

本 ADR 不启用 `CN_SM_V1` 业务写路径，也不改变 model、proof、WAL 或 API 字节。`CN_SM_V1` marker 可用于后续实现和 conformance 测试；实际 claim/proof 生成仍受 suite/provider/format availability gate 阻止。V2/V5 全量切换仍按 ADR-0002 单独执行。

## 2. 后端持久化边界

### 2.1 File

- `.trustdb-proofstore-schema` 从 string-only schema 改为完整 CBOR marker；旧 string-only 文件明确失败，不做 backfill。
- 初始化先写同目录临时文件，完成 file fsync 后 atomic rename，再执行 directory fsync。
- 进程在 rename 前退出只会留下已知命名的初始化临时文件；确认没有其他数据时可以删除该临时文件并重新初始化。
- namespace 中出现其他文件但 marker 缺失时立即拒绝，不扫描对象来猜测 suite。

### 2.2 Pebble

- suite marker 与空库的 idempotency projection readiness marker 使用同一个 `Sync` batch。
- 进程内初始化由互斥区串行化；Pebble 自身的目录锁阻止多个数据库句柄同时写同一目录。
- 任意已有 key 且 suite marker 缺失，均视为未绑定非空库并拒绝。

### 2.3 TiKV

- suite marker 与初始 metadata 使用一个 optimistic transaction。
- 事务读取 marker、确认 namespace 为空、写入 marker 和 readiness metadata 后一起 commit。
- 并发初始化写同一 marker key；冲突方必须重试并重新校验胜者的完整 marker。不同 suite 的并发请求只能有一个成功，另一方返回 `FAILED_PRECONDITION`，不得 last-writer-wins。
- marker 缺失但 namespace 已有任何 key 时拒绝初始化。

## 3. 错误语义

| 状态 | 结果 |
| --- | --- |
| 空 namespace、合法 suite | 原子初始化并开放 |
| marker 完整且与配置相同 | 正常开放 |
| marker suite 与配置不同 | `FAILED_PRECONDITION` |
| marker suite 未注册 | `FAILED_PRECONDITION` |
| string-only 旧 schema | `FAILED_PRECONDITION`，不兼容、不迁移 |
| marker CBOR 损坏或无法严格解码 | `DATA_LOSS` |
| 非空 namespace 缺少 marker | `FAILED_PRECONDITION` |
| 配置 suite 未注册 | `INVALID_ARGUMENT` |

## 4. Backup 与 metastore migration

逻辑备份的每个 PAX entry 都携带 `trustdb.crypto_suite`。`backup verify` 必须验证所有 entry 均存在、已注册且完全相同；`backup restore` 在写第一条数据前比较归档 suite 与目标 proofstore marker，并在第二次流式读取时再次校验，防止验证后发生 suite 替换。

现有不含 suite PAX binding 的 archive 明确失败，不做默认 `INTL_V1` 解释。此处没有把文件内公钥、证书或其他自声明材料升级为信任根。

`metastore migrate` 在枚举任何 proof、root、STH 或 anchor 前读取源和目标的已验证 binding；suite 不同则整个迁移失败。迁移报告显式输出 `crypto_suite`。

## 5. 测试与审计证据

- `internal/proofstoremeta/proofstoremetatest` 为三个后端运行相同的初始化、重开、非空缺失、损坏、未知和 mismatch contract。
- File、Pebble、TiKV 分别覆盖并发初始化；TiKV 额外覆盖事务冲突行为。
- File 覆盖初始化临时文件恢复；Pebble 覆盖部分 metadata 状态拒绝；TiKV 覆盖 namespace 隔离。
- backup 覆盖 suite round trip、跨 suite restore 在首条写入前失败；metastore migration 覆盖跨 suite 拒绝。

## 6. 后续边界

本 marker 只解决“一个 namespace 只能有一个 suite”的持久不变量。以下工作仍由后续 Issue 完成：

- #447：SM3 与 RFC6962-SM3；
- #448：SM2-SM3；
- #454：server 将 suite 显式传播到 claim、receipt、batch、Global Log、STH 和 anchor；
- V2/V5 cutover：将 NodeID、LogID、namespace identity 与新格式代际一起绑定，删除当前 V1/V4 生产实现。
