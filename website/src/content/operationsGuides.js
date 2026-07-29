const zhCN = {
  featureCatalog: {
    eyebrow: "Docs / Operations / 01",
    title: "功能开关与配置全表",
    lead: "不是参数清单，而是每项能力的用途、开启、验收、关闭和持久化边界。先在这里决定要启用什么，再进入专项教程。",
    updated: "更新于 2026.07.29 · 适用于 TrustDB v2.0.1（proofstore schema v5）",
    summary: [["配置原则", "YAML 为基线，环境变量覆盖，CLI 显式参数最高"], ["证据套件", "INTL_V1 / CN_SM_V1；一个 namespace 只能选择一个"], ["证明交付", "L1–L5 与 .sproof v2 完整离线复算"]],
    sections: [
      {
        title: "统一的启停方法",
        body: ["任何功能变更都要完成五件事：明确边界、修改配置、验证生效、设计关闭路径、确认备份范围。关闭只改变后续行为，不能删除已经签发的证据、WAL identity、checkpoint、TrustConfig 或历史公开密钥。"],
        code: "trustdb config validate --config /etc/trustdb/production.yaml\ntrustdb config show --config /etc/trustdb/production.yaml\ntrustdb doctor --config /etc/trustdb/production.yaml",
        note: "config show 输出的是去敏后的合并配置，不是私钥或 secret 备份。",
      },
      {
        title: "入口：HTTP、gRPC 与 NATS",
        cards: [
          ["HTTP", "server.listen 开启。/healthz 和 /metrics 适合探针；业务写入使用 deterministic CBOR，优先使用 SDK。摘流或停止服务关闭。"],
          ["gRPC", "server.grpc_listen 使用非空地址开启，清空并重启关闭。与 HTTP 共用同一 submission、WAL 和 proofstore。"],
          ["NATS / JetStream", "nats.enabled=true 开启 durable fan-in。关闭前停止 publisher、drain consumer，保留 stream、result 和 DLQ；它们不进入 .tdbackup。"],
          ["管理 RBAC", "先 bootstrap 版本化策略，实现系统/安全/审计三员分立；admin.enabled 控制网页，cli_enforce 独立保护高权限 CLI，并支持 mTLS SPKI、OIDC/MFA 钩子、break-glass 恢复和受审计的在线客户端密钥生命周期。"],
        ],
      },
      {
        title: "批次与证明物化",
        body: ["batch.max_records 和 batch.max_delay 决定批次何时关闭。proof_mode 只改变 L3 ProofBundle 的生成时机，不改变 claim、receipt 或 Merkle 语义。"],
        cards: [
          ["inline", "提交路径直接完成证明，查询最简单；适合中低吞吐和证明立即可用。"],
          ["async", "durable prepared job 在后台物化；关闭前等待队列收敛，重启后可恢复。"],
          ["on_demand", "第一次查询承担物化成本；适合只读取少量证明的高写入场景。"],
          ["Global Log", "global_log.enabled=true 产生 L4。关闭后新 batch 最高停在 L2/L3；历史 STH 不删除。"],
        ],
      },
      {
        title: "proofstore、索引与 WAL",
        cards: [
          ["file", "开发和小规模诊断。迁移前停写并做逻辑备份，不复制半个目录。"],
          ["Pebble", "推荐单节点生产 backend，独占目录锁，支持原子 artifacts、checkpoint 和安全裁剪前置条件。"],
          ["TiKV", "共享集群中的存算分离；一个 namespace 只允许一个逻辑 writer。使用集群级备份，trustdb backup 不直接打开 TiKV。"],
          ["索引", "full、no_storage_tokens、time_only 控制查询能力和写放大；关闭索引不能删除证明对象。"],
        ],
        code: "wal:\n  fsync_mode: \"group\"\n  group_commit_interval: \"10ms\"\n  max_segment_bytes: 1073741824\n  keep_segments: 2",
        note: "strict 每条 fsync；group 合并窗口；batch 延迟到 rotate/close。WAL 分段大小和 checkpoint 后保留数量已经进入 YAML；CLI flags 仅作显式覆盖。",
      },
      {
        title: "L5 锚定怎么选择",
        cards: [
          ["off", "不产生新 L5；历史 anchor result 仍可验证。"],
          ["noop / file", "用于管线测试或本地审计。它们能形成 L5 结构，但不提供独立第三方时间来源。"],
          ["OpenTimestamps", "配置 calendars、min_accepted 和 timeout。首次接受形成 L5，upgrader 后续丰富 Bitcoin 证明。"],
          ["plugin", "监督外部进程，握手、发布和离线 verifier 都必须有版本化边界。"],
          ["FISCO BCOS", "要求 canonical TrustConfig、至少双 endpoint/read quorum、receipt inclusion、PBFT finality 和 exact binding。"],
          ["调度状态", "每个 key 最多 Pending + 不可替换 InFlight；关闭不强制提交，重启恢复固定窗口。"],
        ],
      },
      {
        title: "密码、传输和私钥",
        cards: [
          ["INTL_V1 / CN_SM_V1", "suite 由 signer descriptor 固定。切换必须新密钥、新 LogID、新 WAL 和空 proofstore namespace。"],
          ["软件 key", "仅开发使用 sm4-envelope-v1；生产密钥使用 remote、PKCS#11、SDF 或受控 HSM/KMS。"],
          ["TLS / mTLS", "server.transport.mode=mtls 配置证书、client CA 和可选 pin。allow_local_plaintext 只用于明确的本机边界。"],
          ["TLCP", "由受监管网关终止并用 active identity manifest 认证；摘流后才能移除 gateway profile。"],
        ],
      },
      {
        title: "国产生产、离线隔离与测评 Profile",
        body: ["china_production、offline_isolated 和 assessment 不只是标签。TrustDB 在打开 WAL、proofstore 和监听端口之前，读取真实 signer descriptor 与 FISCO BCOS TrustConfig 并执行 fail-closed 门禁。"],
        cards: [
          ["国产生产", "强制 CN_SM_V1、非 software 服务/审计/BCOS 账户密钥、带 pin 的 mTLS 或受验证 TLCP、可信时间审计、国密 BCOS 和精确出站清单。"],
          ["离线隔离", "强制 deny_all，关闭 NATS 和网络 anchor；仍可生成 L4、导出 .sproof v2 并在完全断网环境验证。"],
          ["测评", "与国产生产同等门禁；例外必须单项、具名审批、关联工单、最长 30 天，并在监听前写入签名安全审计。"],
          ["出站与 DNS", "NATS、TiKV、BCOS、remote signer 的 scheme://host:port 必须精确列入 allowed_endpoints；域名还必须进入 dns_allowlist。"],
        ],
        code: "run_profile: china_production\ndeployment_policy:\n  egress_mode: allowlist\n  allowed_endpoints:\n    - gm-tls://10.0.0.20:20200\n  dns_allowlist: []\n  telemetry_enabled: false\n  update_checks_enabled: false\n  exceptions: []",
        note: "应用清单不能替代防火墙、NetworkPolicy、安全组和 DNS 策略；生产中应下发同一目的地址集合并监控配置漂移。",
      },
      {
        title: "变更后的最低验收",
        bullets: ["健康检查和关键 metrics 正常", "提交固定 canary 并达到目标 L2/L3/L4/L5", "导出 .sproof v2，在服务停止和断网环境验证", "错误原文件、公钥和 anchor trust config 必须失败", "涉及存储、suite、WAL 或 anchor 时完成备份与恢复演练"],
      },
    ],
    links: [["国产化部署 Profile", "https://github.com/wowtrust/trustdb/blob/main/docs/zh-CN/CHINA_DEPLOYMENT_PROFILES.md"], ["管理 RBAC 手册", "https://github.com/wowtrust/trustdb/blob/main/docs/zh-CN/ADMINISTRATIVE_RBAC.md"], ["不可变安全审计", "/docs/security-audit"], ["备份与恢复", "/docs/backup-recovery"], ["生产运维", "/docs/operations"], ["FISCO BCOS", "/docs/fisco-bcos"]],
  },
  backupRecovery: {
    eyebrow: "Docs / Operations / 02",
    title: "备份、恢复与灾备",
    lead: ".tdbackup 是 proofstore 的逻辑证据归档，不是整机快照。这里把 archive、WAL、密钥 provider、NATS、对象和区块链的恢复责任拆开。",
    updated: "更新于 2026.07.27 · 当前 .tdbackup v5 支持 INTL_V1 与 CN_SM_V1",
    summary: [["直接 backend", "file / Pebble"], ["恢复方式", "全新目标 + 默认可续传 checkpoint"], ["验收标准", "历史查询、immutable anchor、断网 .sproof 验证"]],
    sections: [
      {
        title: "archive 包含和不包含什么",
        body: [".tdbackup 保存 batch/ProofBundle/root、Global Log leaf/node/state/STH/tile/outbox、immutable anchor result 和完整 scheduler Pending/InFlight/provider state。"],
        cards: [
          ["包含", "proofstore 中可枚举的不可变证据对象和可恢复调度状态，每个 entry 带 suite、ordinal、类型、大小和摘要。"],
          ["不包含", "安全审计链、私钥、credential、PIN、证书、YAML、TrustConfig、WAL、原文件、NATS、BCOS 节点数据和 SDF recovery bundle。"],
        ],
        note: "v5 使用随机 DEK 和 SM4-GCM 分帧认证加密，并严格绑定 suite、proofstore generation、NodeID、LogID 与 namespace；v4/plain tar 明确拒绝。",
      },
      {
        title: "创建并立即验证",
        body: ["Pebble 先优雅停服并确认锁释放。file backend 也应停止写入，以取得清晰恢复点。输出放在 proofstore/WAL 之外的故障域。"],
        code: "trustdb backup create \\\n  --metastore pebble \\\n  --metastore-path /var/lib/trustdb/proofs/pebble \\\n  --crypto-suite INTL_V1 \\\n  --compression gzip \\\n  --out /var/backups/trustdb/proofstore.tdbackup\n\ntrustdb backup verify --file /var/backups/trustdb/proofstore.tdbackup",
      },
      {
        title: "恢复到隔离的新目录",
        code: "trustdb backup restore \\\n  --file /var/backups/trustdb/proofstore.tdbackup \\\n  --metastore pebble \\\n  --metastore-path /var/lib/trustdb-restore/proofs/pebble \\\n  --crypto-suite INTL_V1 \\\n  --checkpoint /var/lib/trustdb-restore/restore-checkpoint.json \\\n  --resume",
        body: ["resume 默认开启。checkpoint 绑定 BackupID 和最后 ordinal；中断后使用同一 archive、目标和 checkpoint 继续，不允许两个恢复进程共享。"],
      },
      {
        title: "恢复后不要马上切流量",
        bullets: ["使用相同 suite、NodeID、LogID 和 namespace identity 启动隔离实例", "核对 create/restore 对象计数和历史查询", "比较备份前后的 immutable anchor result", "用备份前原文件与独立 trust roots 断网验证 .sproof v2", "错误文件、公钥和 TrustConfig 做负向测试", "验收通过后再切换负载均衡，旧目录保持只读直到回退窗口结束"],
      },
      {
        title: "其他状态必须单独保护",
        cards: [
          ["WAL", "保存 namespace binding 和 checkpoint；逻辑备份不包含 WAL，不能混入其他 LogID/suite。"],
          ["NATS", "独立备份 stream、consumer、result 和 DLQ，恢复点与 proofstore 对齐。"],
          ["对象", "业务对象存储使用版本化、保留锁和异地灾备；TrustDB 通常只绑定摘要。"],
          ["私钥 provider", "按 remote/PKCS#11/SDF/HSM 的 ceremony 和恢复包处理，保留公开 descriptor。"],
          ["FISCO BCOS", "保护节点数据、证书、部署记录和 canonical TrustConfig；链上数据不进入 archive。"],
          ["TiKV", "使用集群级备份与隔离 keyspace 演练；CLI 当前只直接支持 file/Pebble。"],
        ],
      },
      {
        title: "演练节奏",
        bullets: ["每次发布、密钥/证书轮换、TrustConfig advance 和 backend 变更前后创建备份", "每月恢复到全新目录并做离线证据验收", "每季度联合演练 proofstore、provider、NATS、对象和 BCOS", "报告保存 RPO、RTO、BackupID、版本、suite、对象计数、失败注入和责任人"],
      },
    ],
    links: [["功能开关", "/docs/features"], ["生产运维", "/docs/operations"], ["仓库中文完整手册", "https://github.com/wowtrust/trustdb/blob/main/docs/zh-CN/BACKUP_AND_RECOVERY.md"]],
  },
  operations: {
    eyebrow: "Docs / Operations / 03",
    title: "生产部署与日常运维",
    lead: "从目录、身份和上线门禁开始，覆盖启动、停止、容量、日常巡检、升级、回退和事故分流。",
    updated: "更新于 2026.07.27 · 适用于当前 V2 正式版（V5 写入代际）",
    summary: [["上线门禁", "validate + doctor + canary + offline verify"], ["日常核心", "队列、WAL、proof、STH、anchor、容量"], ["恢复原则", "保留现场，禁止删除状态掩盖错误"]],
    sections: [
      {
        title: "先固定日志身份和目录",
        body: ["suite、NodeID、LogID、proofstore namespace 和 WAL identity 共同定义一个写入流。切换 suite、NodeID、LogID 或格式代际必须建立新日志，不能复用旧目录。"],
        code: "/etc/trustdb/              # 配置、公开证书、TrustConfig\n/var/lib/trustdb/wal/      # WAL\n/var/lib/trustdb/proofs/   # proofstore\n/var/lib/trustdb/objects/  # 可选对象\n/var/backups/trustdb/      # 本地恢复点，另做异地副本",
      },
      {
        title: "启动与就绪",
        code: "trustdb config validate --config /etc/trustdb/production.yaml\ntrustdb config show --config /etc/trustdb/production.yaml\ntrustdb doctor --config /etc/trustdb/production.yaml\ntrustdb serve --config /etc/trustdb/production.yaml",
        bullets: ["启动日志无 schema/suite/WAL namespace/key/transport 错误", "/healthz 与 /metrics 可用", "外部 signer/anchor 完成身份和 quorum probe", "canary 达到目标等级并成功离线验证", "通过后才进入负载均衡"],
      },
      {
        title: "优雅停止",
        bullets: ["从负载均衡摘除并停止 publisher", "等待 ingest、batch、materializer、outbox 和 NATS consumer 收敛", "发送正常终止信号并等待 shutdown_timeout", "确认端口和 Pebble 锁释放", "需要时创建并验证备份"],
        note: "不能通过删除 WAL、checkpoint、Pending/InFlight 或 LOCK 文件强制收口。",
      },
      {
        title: "每天、每周、每月看什么",
        cards: [
          ["每天", "health/restart、错误日志、证书有效期、队列、proof-ready、STH/anchor 进度、磁盘和最新备份。"],
          ["每周", "抽样断网验证 .sproof；错误 trust root 负向测试；检查 registry、provider 版本、NATS DLQ/redelivery。"],
          ["每月", "恢复到全新目录；检查容量趋势、WAL 裁剪和索引；演练 endpoint、validator、signer、磁盘和网络故障。"],
          ["每次变更", "只改一类设置，保存前后配置 digest、metrics、证据样本和回退结果。"],
        ],
      },
      {
        title: "性能和容量怎么调",
        body: ["worker 数不是 CPU 核数。入口 worker 后面仍共享签名、WAL writer、proofstore、batch、Global Log 和 provider。固定语义与数据集逐级增加并发；p99、上下文切换、锁等待或磁盘队列恶化时停止。"],
        bullets: ["记录 HTTP/gRPC/NATS 吞吐与 p50/p95/p99", "监控 ingest queue、batch/materializer、WAL fsync/segment、proofstore 延迟", "监控 outbox、STH、Pending/InFlight、quorum/retry/published", "监控 CPU、RSS、GC、句柄、磁盘 IOPS/容量和外部 provider 延迟"],
      },
      {
        title: "升级与破坏性边界",
        body: ["当前 V2 正式版只接受 V2 model/WAL/API/.sproof 和 proofstore schema v5。v1/schema v4 不双读、不迁移、不回退。保留旧版本与旧 LogID 作为历史验证环境；新版本使用新密钥、新 LogID、新 namespace 和新 WAL。"],
        note: "旧二进制不能打开已经写入 V2/V5 的目录；也不能把旧对象重新编码后声称密码学身份不变。",
      },
      {
        title: "按症状分流",
        cards: [
          ["connection refused", "先检查进程、监听地址、TLS 和启动日志；修正脚本，不要继续压测未监听端口。"],
          ["停在 L2/L3", "检查 batch/materializer 或 Global Log/outbox；等待/恢复 durable job，不删除 accepted record。"],
          ["L4 不升 L5", "检查 sink、固定窗口、Pending/InFlight 和 provider quorum；保留 journal。"],
          ["WAL namespace mismatch", "核对 suite、NodeID、LogID 和 proofstore marker；使用正确目录或建立新日志。"],
          ["Pebble LOCK", "找到 owner 并优雅停止，不强删锁文件。"],
          ["BCOS disagreement", "按安全事件隔离 endpoint，保存冲突响应并停止发布。"],
        ],
      },
    ],
    links: [["功能开关", "/docs/features"], ["安全审计", "/docs/security-audit"], ["备份恢复", "/docs/backup-recovery"], ["故障排查", "/docs/troubleshooting"]],
  },
  securityAudit: {
    eyebrow: "Docs / Operations / Security audit",
    title: "不可变安全审计与可信时间",
    lead: "把登录、授权、配置、密钥、备份、Anchor、TrustConfig 和服务生命周期写入独立签名链；链损坏、容量耗尽或强制时间不同步时阻止高权限操作。",
    updated: "更新于 2026.07.27 · INTL_V1 / CN_SM_V1 · Linux / macOS / Windows",
    summary: [["完整性", "签名 + 前序哈希 + 单调 sequence"], ["生产策略", "审计或可信时间不可用即 fail closed"], ["交付物", "JSONL 全链 + 独立签名 checkpoint"]],
    sections: [
      {
        title: "它与普通日志、业务证据的区别",
        body: ["安全审计链只记录高权限控制面活动，不替代应用日志、Prometheus、业务 record、WAL 或 .sproof。每条事件包含 actor、roles、action、object、result、request ID、policy version、时间状态和有界脱敏 context。"],
        cards: [["INTL_V1", "Ed25519 签名、SHA-256 哈希链。"], ["CN_SM_V1", "SM2 签名、SM3 哈希链。"], ["隐私", "敏感 key 自动改成 <redacted>；break-glass 原因只记录摘要。"], ["并发", "稳定追加走 O(1) checkpoint 快路径；慢导出不占用在线写锁。"]],
        note: "本机时间、NTP 样本和 BCOS block time 都不会自动变成具有法律效力的可信时间戳。",
      },
      {
        title: "1. 生成独立审计密钥",
        body: ["审计密钥不要复用 client/server 证明签名密钥。生产使用 SDF、PKCS#11、HSM/KMS 或 remote descriptor；下面仅创建可丢弃的本地 CN_SM_V1 身份。--out 是本地目录。"],
        platformCode: {
          macos: "mkdir -p .trustdb-audit-key\nread -r -s -p 'Audit key passphrase: ' TRUSTDB_DEV_KEY_PASSPHRASE\nprintf '\\n'\nexport TRUSTDB_DEV_KEY_PASSPHRASE\n./bin/trustdb key generate --suite CN_SM_V1 --out .trustdb-audit-key --prefix audit\nunset TRUSTDB_DEV_KEY_PASSPHRASE",
          linux: "mkdir -p .trustdb-audit-key\nread -r -s -p 'Audit key passphrase: ' TRUSTDB_DEV_KEY_PASSPHRASE\nprintf '\\n'\nexport TRUSTDB_DEV_KEY_PASSPHRASE\n./bin/trustdb key generate --suite CN_SM_V1 --out .trustdb-audit-key --prefix audit\nunset TRUSTDB_DEV_KEY_PASSPHRASE",
          windows: "# 仅用于可丢弃测试；Windows 生产使用 SDF/PKCS#11/remote descriptor\nNew-Item -ItemType Directory -Force .trustdb-audit-key | Out-Null\n.\\bin\\trustdb.exe key generate --suite CN_SM_V1 --out .trustdb-audit-key --prefix audit --protection plaintext-dev-v1",
        },
        bullets: ["audit.key 是 signer descriptor", "audit.pub 是验证方独立保管的 public verifier descriptor", "audit.material 是本地私钥材料；不能与 KEK 放在同一备份范围"],
      },
      {
        title: "2. 配置审计与 time-reference",
        code: "audit:\n  enabled: true\n  required: true\n  path: \"/var/lib/trustdb/audit/security.audit\"\n  checkpoint_path: \"/var/lib/trustdb/audit/security.checkpoint\"\n  signing_key: \"/etc/trustdb/keys/audit.tdkey\"\n  max_bytes: 4294967296\n  retention: \"4380h\"\n  time_reference_path: \"/run/trustdb/time-reference.json\"\n  time_max_sample_age: \"2m\"\n  time_max_drift: \"5s\"\n  require_synchronized_time: true",
        body: ["time-monitor agent 必须原子刷新 trustdb.time-reference.v1 JSON，写入来源、采样时间、offset、uncertainty、synchronized 和 confidence。local confidence 始终是 unverified，不能满足生产强制同步。"],
        bullets: ["状态包括 synchronized、stale、drift-exceeded、unsynchronized、unavailable、invalid、unverified", "失败时先签入 result=blocked，再拒绝操作", "Admin 通用配置接口不能修改 admin/audit 块"],
      },
      {
        title: "3. 检查、导出和完全离线验证",
        platformCode: {
          macos: "./bin/trustdb --config /etc/trustdb/trustdb.yaml audit status\n./bin/trustdb --config /etc/trustdb/trustdb.yaml audit export --out ./security-audit.jsonl\n./bin/trustdb audit verify --file ./security-audit.jsonl --public-key ./audit.pub\n./bin/trustdb --config /etc/trustdb/trustdb.yaml audit checkpoint export --out ./audit-checkpoint.json\n./bin/trustdb audit checkpoint verify --file ./audit-checkpoint.json --public-key ./audit.pub",
          linux: "./bin/trustdb --config /etc/trustdb/trustdb.yaml audit status\n./bin/trustdb --config /etc/trustdb/trustdb.yaml audit export --out ./security-audit.jsonl\n./bin/trustdb audit verify --file ./security-audit.jsonl --public-key ./audit.pub\n./bin/trustdb --config /etc/trustdb/trustdb.yaml audit checkpoint export --out ./audit-checkpoint.json\n./bin/trustdb audit checkpoint verify --file ./audit-checkpoint.json --public-key ./audit.pub",
          windows: ".\\bin\\trustdb.exe --config C:\\TrustDB\\trustdb.yaml audit status\n.\\bin\\trustdb.exe --config C:\\TrustDB\\trustdb.yaml audit export --out .\\security-audit.jsonl\n.\\bin\\trustdb.exe audit verify --file .\\security-audit.jsonl --public-key .\\audit.pub\n.\\bin\\trustdb.exe --config C:\\TrustDB\\trustdb.yaml audit checkpoint export --out .\\audit-checkpoint.json\n.\\bin\\trustdb.exe audit checkpoint verify --file .\\audit-checkpoint.json --public-key .\\audit.pub",
        },
        body: ["verify 不访问服务器、provider 或网络，只接受验证方本地提供且与导出 metadata 精确匹配的 audit.pub。周期 checkpoint 应进入独立 WORM/Object Lock，或由受控外部流程锚定其精确字节/摘要。"],
      },
      {
        title: "4. 容量、备份和保留",
        body: ["估算公式：峰值事件数/天 × 实测字节/事件 × 保留天数 × 安全系数。默认 4 GiB / 4380h 约为每天 23.5 MiB；若平均 2 KiB，未留余量时约 12,000 条/天。"],
        bullets: ["达到 max_bytes 后阻止需要审计的操作，不自动删除或轮转历史", ".tdbackup v5 不包含安全审计链；JSONL、checkpoint、audit.pub、time-monitor 配置和外部 receipt 单独保管", "restore 会被审计，但不会覆盖目标环境原有审计历史"],
      },
      {
        title: "5. 出现异常怎么处理",
        cards: [["rollback / truncation", "停止高权限操作，逐字节保全 log/checkpoint/lock，并与独立 checkpoint 比对；禁止 truncate 或重建。"], ["unsafe storage", "检查 owner、mode/DACL、父目录可写权限、symlink 和文件类型。"], ["capacity exhausted", "保留链、扩容、审批提高 max_bytes；不能删除 checkpoint 或尾部。"], ["time unsynchronized", "修复 time monitor，检查 age、offset、uncertainty、confidence、权限和 schema；blocked 事件已入链。"]],
      },
    ],
    links: [["仓库中文完整手册", "https://github.com/wowtrust/trustdb/blob/main/docs/zh-CN/IMMUTABLE_SECURITY_AUDIT.md"], ["管理 RBAC", "https://github.com/wowtrust/trustdb/blob/main/docs/zh-CN/ADMINISTRATIVE_RBAC.md"], ["备份恢复", "/docs/backup-recovery"], ["生产运维", "/docs/operations"]],
  },
  keyLifecycle: {
    eyebrow: "Docs / Operations / Online key lifecycle",
    title: "在线客户端密钥生命周期",
    lead: "让审批系统把浏览器或业务客户端的公钥注册、查询和撤销直接同步到 TrustDB 当前进程使用的追加式注册表，同时沿用管理员鉴权、RBAC 和不可变安全审计。",
    updated: "更新于 2026.07.29 · TrustDB v2.0.1",
    summary: [["鉴权", "管理员会话 / 直接 mTLS / 固定网关 OIDC"], ["授权", "key.read / key.manage；内置 key-operator"], ["生效", "单进程立即作用于真实 claim admission"]],
    sections: [
      {
        title: "只有一个准入事实源",
        body: ["在线 API 不维护第二份缓存，也不允许 ingest 请求夹带“可信公钥”。它修改的就是当前 trustdb serve 进程验证 claim 时读取的 V2 Key Registry；注册后立即可用，撤销生效后新 claim 立即被拒绝，历史记录仍按当时状态验证。"],
        cards: [["注册", "POST /admin/api/keys；只接受公开 verifier descriptor。"], ["查询", "GET /admin/api/keys/{tenant}/{client}/{key}?at=...；支持历史时点。"], ["撤销", "POST /admin/api/keys/{tenant}/{client}/{key}/revoke；生效时间进入签名事件。"], ["审计", "认证、授权、路径、方法和结果进入不可变安全审计；required audit 失败时操作 fail closed。"]],
        note: "静态 keys.client_public 部署保持只读，也不会暴露可写注册表。不要把 Admin 子树作为公开 ingest 端点。",
      },
      {
        title: "1. 配置可签名的 V2 注册表",
        code: "paths:\n  key_registry: /var/lib/trustdb/keys/clients.tdkeys\nregistry:\n  key_id: registry-key\nkeys:\n  client_public: \"\"\n  registry_private: /run/secrets/registry.key\n  registry_public: /etc/trustdb/keys/registry.pub\nadmin:\n  enabled: true\n  base_path: /admin\n  policy_path: /etc/trustdb/admin-policy.json\n  session_secret: ${TRUSTDB_ADMIN_SESSION_SECRET}",
        body: ["registry_private 和 registry_public 必须描述同一 suite、key ID、算法、编码与公钥。缺少私有 signer 时，claim admission 和历史查询仍可用，但在线修改返回 503。"],
      },
      {
        title: "2. 使用专用 key-operator 鉴权",
        code: "curl --fail-with-body \\\n  --cookie-jar trustdb-admin.cookies \\\n  --header 'Content-Type: application/json' \\\n  --data '{\"username\":\"proof-mesh-key-operator\",\"password\":\"...\"}' \\\n  https://trustdb.example/admin/api/session",
        body: ["自动化优先绑定直接 mTLS 管理员身份，或使用受 pin 约束的 OIDC 网关。密码、cookie 和注册表 signer 必须来自 secret manager，不能进入配置、命令历史或业务日志。"],
      },
      {
        title: "3. 注册并确认同一把公钥",
        code: "curl --fail-with-body --cookie trustdb-admin.cookies \\\n  --header 'Content-Type: application/json' \\\n  --data @browser-key.json \\\n  https://trustdb.example/admin/api/keys\n\ncurl --fail-with-body --cookie trustdb-admin.cookies \\\n  https://trustdb.example/admin/api/keys/tenant-a/chrome-extension%3Aproof-mesh/browser-key-2026-07",
        bullets: ["descriptor.kind 必须是 verifier，provider 必须是 public", "SM2 descriptor 明确绑定 CN_SM_V1、sm2-sm3、SM2 user ID 与 SEC1 公钥编码", "同一 tenant/client/key 的完全相同请求返回原 sequence/event hash，不追加事件", "相同 identity 下更换公钥或有效期返回 409，必须使用新的 key_id"],
      },
      {
        title: "4. 撤销并验证 admission",
        code: "curl --fail-with-body --cookie trustdb-admin.cookies \\\n  --header 'Content-Type: application/json' \\\n  --data '{\"revoked_at\":\"2026-07-29T09:00:00Z\",\"reason\":\"tenant administrator revoked browser key\"}' \\\n  https://trustdb.example/admin/api/keys/tenant-a/chrome-extension%3Aproof-mesh/browser-key-2026-07/revoke",
        bullets: ["新的撤销时间可以是当前时间或未来时间；超过五秒的回溯时间会被拒绝", "完全相同的已持久化撤销可在任意时间重试并返回原事件", "撤销时点之后的新 claim 返回 FAILED_PRECONDITION / HTTP 412", "重启后注册、撤销和历史 accepted record 必须保持同样结果"],
      },
      {
        title: "5. 多副本部署边界",
        body: ["这个 API 立即更新的是处理请求的进程。单二进制和单 TrustDB Compose 服务可直接使用；NATS + TiKV 多副本不能把密钥管理请求随机发给任意节点。"],
        bullets: ["建立一个有序、受鉴权、可重放的注册表事件分发控制面", "所有 claim-admitting replica 应用到同一序列后再通过 readiness", "落后或无法验证事件的副本必须摘流", "在完成该控制面前，使用受控注册表发布加全副本重启/就绪屏障"],
      },
    ],
    links: [["仓库完整接口手册", "https://github.com/wowtrust/trustdb/blob/main/docs/zh-CN/ONLINE_KEY_LIFECYCLE.md"], ["管理 RBAC", "https://github.com/wowtrust/trustdb/blob/main/docs/zh-CN/ADMINISTRATIVE_RBAC.md"], ["不可变安全审计", "/docs/security-audit"], ["生产运维", "/docs/operations"]],
  },
  supplyChain: {
    eyebrow: "Docs / Operations / Release supply chain",
    title: "正式版验签、国产镜像与隔离区导入",
    lead: "不要只看下载页上的文件名。先验证来源，再验证 manifest 中的每一个 SHA-256/SM3，最后按不可变 digest 导入目标环境。",
    updated: "更新于 2026.07.27 · 适用于当前 V2 正式版的发布证据包",
    summary: [["来源", "Sigstore bundle + 独立下发 trusted root"], ["完整性", "签名 manifest + SHA-256 + SM3"], ["隔离区", "精确文件集合 + OCI digest + 可留存报告"]],
    sections: [
      {
        title: "认识完整证据包",
        cards: [["Manifest", "源 commit、policy digest、必备文档和每个文件的大小/双摘要。"], ["Attestation", "GitHub Actions 对 manifest 与 OCI digest 的 provenance bundle。"], ["SBOM", "SPDX 依赖与许可清单。"], ["生产输入", "BCOS SDK/合约、PKCS#11、SDF、TLCP、lockfile、基础镜像和架构矩阵。"], ["漏洞结果", "npm 与 govulncheck 的 fail-on-high 留存输出。"], ["容器摘要", "linux/amd64 + linux/arm64 的不可变 manifest digest。"]],
        note: "和 release 一起下载的 root 不能自动成为信任根。trusted root 必须提前从独立批准渠道下发并登记摘要。",
      },
      {
        title: "1. 先验证签名 manifest",
        code: "APPROVED_COMMIT=replace-with-approved-40-character-commit\ngh attestation verify \\\n  trustdb-release/TRUSTDB_RELEASE_MANIFEST.json \\\n  --repo wowtrust/trustdb \\\n  --signer-workflow wowtrust/trustdb/.github/workflows/release.yml \\\n  --source-digest \"$APPROVED_COMMIT\" \\\n  --deny-self-hosted-runners \\\n  --bundle trustdb-release/trustdb-release-attestation.sigstore.json \\\n  --custom-trusted-root /secure/trust-roots/github-public-good-trusted-root.json",
        body: ["预期 identity 必须是 wowtrust/trustdb 的 release workflow，source digest 必须来自独立审批记录，root 位于 release 目录之外。root 轮换要走独立审批，不能在升级时被产物自带文件替换。"],
      },
      {
        title: "2. 在完全断网条件下检查全部文件",
        platformCode: {
          macos: "./trusted/trustdb release verify --dir ./trustdb-release",
          linux: "./trusted/trustdb release verify --dir ./trustdb-release",
          windows: ".\\trusted\\trustdb.exe release verify --dir .\\trustdb-release",
        },
        bullets: ["使用此前已准入的 verifier，避免让新二进制自证可信", "正式版的 media type 由产物文件名确定，不依赖宿主 MIME 数据库；macOS、Linux 与 Windows 执行同一套 manifest 规则", "任何额外文件、子目录、symlink、缺失报告、重复 checksum 或双摘要不一致都会失败", "检查 version、source commit、policy digest、SBOM 与漏洞报告属于同一版本"],
      },
      {
        title: "3. 导出并导入 OCI 镜像",
        code: "DIGEST=\"$(jq -r .digest trustdb-release/TRUSTDB_CONTAINER_DIGESTS.json)\"\nskopeo copy --all \\\n  \"docker://ghcr.io/wowtrust/trustdb@${DIGEST}\" \\\n  oci-archive:trustdb-X.Y.Z.oci.tar\nskopeo inspect --format '{{.Digest}}' \\\n  oci-archive:trustdb-X.Y.Z.oci.tar",
        body: ["inspect 结果必须精确等于发布证据中的 DIGEST。把 OCI archive 的 SHA-256 加入受控介质清单；断网区再次 inspect 后再复制到 docker-daemon 或内部 registry。"],
      },
      {
        title: "4. 镜像已准入的发布产物",
        code: "DIGEST=\"$(jq -r .digest trustdb-release/TRUSTDB_CONTAINER_DIGESTS.json)\"\nskopeo copy --all \\\n  \"docker://ghcr.io/wowtrust/trustdb@${DIGEST}\" \\\n  \"docker://registry.internal.example/wowtrust/trustdb@${DIGEST}\"",
        body: ["内网镜像只改变分发路线，不重新构建 TrustDB。目标 registry 的 manifest digest 必须与发布证据完全相同；服务器和 CLI 归档同样直接镜像 GitHub Release 原文件并保留双摘要。"],
      },
      {
        title: "5. 上线与演练",
        bullets: ["把 release、可信 verifier、trusted root、介质清单和 OCI archive 带入隔离区", "重做 provenance、双摘要和 OCI digest 验证", "只解压匹配系统和架构的包", "运行 version、config validate、doctor 与 canary", "导出 .sproof v2，停服务断网后用独立证据信任根验证", "篡改包、manifest、attestation、root、OCI digest 和 SBOM/policy，要求全部在预期阶段失败"],
      },
    ],
    links: [["中文完整手册", "https://github.com/wowtrust/trustdb/blob/main/docs/zh-CN/SUPPLY_CHAIN_RELEASES.md"], ["生产运维", "/docs/operations"], ["离线证据验证", "/docs/offline-verification"], ["下载", "/downloads"]],
  },
  fiscoBCOS: {
    eyebrow: "Docs / Integrations / FISCO BCOS",
    title: "把 TrustDB STH 锚定到 FISCO BCOS",
    lead: "从兼容矩阵、四节点资格验证、合约和 TrustConfig 开始，直到可携带、可断网复算的 receipt inclusion + PBFT finality 证据。",
    updated: "更新于 2026.07.25 · FISCO BCOS v3.16.3 / C SDK v3.6.0",
    summary: [["生产准入", "Air · Linux/amd64 · 四节点"], ["密码模式", "standard 与 Guomi 独立 qualification"], ["离线结果", "receipt inclusion + PBFT finality + exact STH binding"]],
    sections: [
      {
        title: "先确认你在支持矩阵里",
        body: ["当前生产准入是 Air/Linux amd64 四节点，标准和国密分别有完整 CI qualification。macOS arm64 只用于开发 smoke；Linux arm64 只有 artifact 验证；Pro、Max 和容器必须单独 admission。"],
        code: "python3 scripts/fisco-bcos/compatibility.py validate\npython3 scripts/fisco-bcos/compatibility.py check \\\n  --deployment air --crypto standard --platform linux/amd64\npython3 scripts/fisco-bcos/compatibility.py check \\\n  --deployment air --crypto guomi --platform linux/amd64",
      },
      {
        title: "验证上游 artifact 和合约",
        code: "python3 scripts/fisco-bcos/compatibility.py verify-artifacts \\\n  --platform linux/amd64 --cache-dir /var/cache/trustdb/fisco-bcos\npython3 scripts/fisco-bcos/build_anchor_contract.py \\\n  --platform linux/amd64 --cache-dir /var/cache/trustdb/fisco-bcos --check",
        body: ["生产二进制使用 CGO_ENABLED=1、fiscobcos_sdk tag 和固定 C SDK 动态库。合约部署后必须读取 runtime bytecode，并与模式对应 manifest digest 匹配。"],
      },
      {
        title: "在目标环境运行四节点 qualification",
        code: "scripts/fisco-bcos/smoke-air.sh \\\n  --mode standard --qualification \\\n  --work-dir /tmp/trustdb-bcos-standard \\\n  --cache-dir /var/cache/trustdb/fisco-bcos\n\nscripts/fisco-bcos/smoke-air.sh \\\n  --mode guomi --qualification \\\n  --work-dir /tmp/trustdb-bcos-guomi \\\n  --cache-dir /var/cache/trustdb/fisco-bcos",
        body: ["资格验证覆盖真实交易、单 validator 停止与追赶、权重变化、journal replay、backup（支持的 suite）、节点全停、unshare --net 断网验证和分阶段篡改拒绝。"],
      },
      {
        title: "创建 canonical TrustConfig",
        code: "trustdb anchor fisco-bcos trust-config create \\\n  --input /etc/trustdb/fisco/trust-config.json \\\n  --out /etc/trustdb/fisco/trust-config.cbor\ntrustdb anchor fisco-bcos trust-config inspect \\\n  --input /etc/trustdb/fisco/trust-config.cbor",
        bullets: ["固定 crypto mode、chain/group、genesis 和 trusted checkpoint", "固定合约地址/runtime code hash", "至少两个 endpoint，read_quorum >= 2", "固定 account provider、证书与 validators", "保存 inspect 输出和 config digest"],
      },
      {
        title: "开启 sink",
        code: "global_log:\n  enabled: true\n  log_id: \"production-log-2026\"\nanchor:\n  sink: \"fisco-bcos\"\n  max_delay: \"5m\"\n  fisco_bcos:\n    trust_config_file: \"/etc/trustdb/fisco/trust-config.cbor\"",
        body: ["publisher 私钥生产环境使用 remote、PKCS#11 或 SDF signer plugin。启动 probe 会逐 endpoint 检查链身份、checkpoint、crypto mode、合约代码和保守 quorum height。"],
      },
      {
        title: "证明 L5 真的可离线验证",
        bullets: ["提交 canary，等待 L4 STH 和固定非滑动 anchor 窗口", "确认 scheduler 从 Pending/InFlight 到 immutable result", "导出 .sproof v2", "验证者从本地提供客户端/服务端 trust roots 和 canonical TrustConfig", "停止 TrustDB 和 BCOS 节点，断网验证", "篡改 receipt、block、finality、STH 或 TrustConfig 必须在对应阶段失败"],
        note: "证据文件自带的公钥、validator 和 TrustConfig 不能自动授权自己；BCOS block time 也不是法定可信时间戳。",
      },
      {
        title: "validator/checkpoint 推进与关闭",
        code: "trustdb anchor fisco-bcos trust-config advance \\\n  --input /etc/trustdb/fisco/trust-config.cbor \\\n  --evidence ./validator-transition.sproof \\\n  --expect-current-digest <current-digest> \\\n  --out /etc/trustdb/fisco/trust-config.cbor",
        body: ["推进必须使用完整离线 transition evidence、严格更高区块和当前 digest，并原子替换同一文件。关闭新锚定时先检查未知结果/InFlight，再设 anchor.sink=off；保留 TrustConfig、部署记录、证书、journal 和历史 result。"],
      },
    ],
    links: [["英文完整运维手册", "https://github.com/wowtrust/trustdb/blob/main/docs/integrations/FISCO_BCOS_OPERATIONS.md"], ["中文仓库指南", "https://github.com/wowtrust/trustdb/blob/main/docs/zh-CN/FISCO_BCOS.md"], ["离线验证", "/docs/offline-verification"]],
  },
};

const en = {
  featureCatalog: {
    eyebrow: "Docs / Operations / 01", title: "Feature and configuration catalog",
    lead: "Choose capabilities by purpose, enablement, verification, shutdown, and persistence boundary—not by copying an unexplained YAML block.",
    updated: "Updated 2026.07.29 · TrustDB v2.0.1 (proofstore schema v5)",
    summary: [["Precedence", "YAML baseline, environment override, explicit CLI flag wins"], ["Suites", "INTL_V1 / CN_SM_V1; one suite per namespace"], ["Delivery", "L1–L5 and fully offline .sproof v2 verification"]],
    sections: [
      { title: "One change method", body: ["Validate and display the merged configuration, preserve the previous digest and evidence sample, change one boundary, run a canary, then test shutdown and recovery. Disabling future behavior never authorizes deleting historical evidence or trust material."], code: "trustdb config validate --config /etc/trustdb/production.yaml\ntrustdb config show --config /etc/trustdb/production.yaml\ntrustdb doctor --config /etc/trustdb/production.yaml" },
      { title: "Ingress and administration", cards: [["HTTP", "server.listen; use SDK deterministic CBOR for writes."], ["gRPC", "Set server.grpc_listen; clear it and restart to disable."], ["NATS", "Set nats.enabled=true; drain before disabling and retain stream/result/DLQ."], ["Administrative RBAC", "Bootstrap separated system/security/audit identities. admin.enabled controls Web access; cli_enforce protects privileged CLI, with mTLS/OIDC/MFA hooks, break-glass recovery, and the audited online client-key lifecycle."]] },
      { title: "Proof materialization", cards: [["inline", "Proof ready on the direct path."], ["async", "Durable background jobs lower submit latency."], ["on_demand", "First proof read pays materialization cost."], ["Global Log", "global_log.enabled=true produces L4; disabling caps new records at L2/L3."]] },
      { title: "Storage and WAL", cards: [["file", "Development and diagnostics."], ["Pebble", "Recommended single-node production store."], ["TiKV", "One logical writer per namespace; use cluster backup."], ["Indexes", "full, no_storage_tokens, or time_only."]], code: "wal:\n  fsync_mode: \"group\"\n  group_commit_interval: \"10ms\"\n  max_segment_bytes: 1073741824\n  keep_segments: 2", note: "Segment rotation and post-checkpoint retention are part of the YAML schema; serve flags remain explicit overrides." },
      { title: "Anchors", cards: [["off", "No new L5."], ["noop/file", "Pipeline/local audit only; no independent third-party time."], ["OTS", "Calendar acceptance plus later upgrade."], ["plugin", "Versioned supervised publisher and offline verifier."], ["FISCO BCOS", "Canonical TrustConfig, quorum, receipt inclusion, PBFT finality, exact binding."], ["Scheduler", "At most Pending plus immutable InFlight per key."]] },
      { title: "Cryptography and transport", cards: [["Suites", "Changing suite requires a new key, LogID, WAL, and empty proofstore namespace."], ["Key custody", "Software envelopes are for development; production uses remote/PKCS#11/SDF/HSM."], ["TLS/mTLS", "Configure server.transport and trusted client roots."], ["TLCP", "Terminate at an authenticated, controlled gateway boundary."]] },
      { title: "Minimum acceptance", bullets: ["Health and metrics pass", "Canary reaches the intended level", "Export and verify .sproof v2 while offline", "Wrong content/key/anchor trust fails", "Backup and restore every changed durable boundary"] },
    ],
    links: [["Administrative RBAC", "https://github.com/wowtrust/trustdb/blob/main/docs/compliance/ADMINISTRATIVE_RBAC.md"], ["Immutable security audit", "/docs/security-audit"], ["Backup and recovery", "/docs/backup-recovery"], ["Production operations", "/docs/operations"], ["FISCO BCOS", "/docs/fisco-bcos"]],
  },
  backupRecovery: {
    eyebrow: "Docs / Operations / 02", title: "Backup and recovery", lead: ".tdbackup is a logical proofstore archive, not a machine image or key-custody recovery package.", updated: "Updated 2026.07.27 · encrypted .tdbackup v5 supports INTL_V1 and CN_SM_V1",
    summary: [["Direct stores", "file / Pebble"], ["Restore", "new target + resumable checkpoint"], ["Acceptance", "historical reads, immutable anchors, offline proof verification"]],
    sections: [
      { title: "Know the boundary", body: ["The archive includes proof bundles, roots, Global Log state, STHs, outboxes, immutable anchor results, and complete scheduler state."], cards: [["Included", "Enumerable proofstore evidence and recovery intents."], ["Excluded", "Security audit chain, private keys, credentials, YAML, certificates, TrustConfig, WAL, content, NATS, BCOS nodes, and SDF recovery bundles."]], note: "V5 uses a random DEK and framed SM4-GCM authentication, binds the exact suite and namespace generation, and rejects v4/plain tar." },
      { title: "Create and verify", code: "trustdb backup create --metastore pebble \\\n  --metastore-path /var/lib/trustdb/proofs/pebble \\\n  --crypto-suite INTL_V1 --compression gzip \\\n  --out /var/backups/trustdb/proofstore.tdbackup\ntrustdb backup verify --file /var/backups/trustdb/proofstore.tdbackup" },
      { title: "Restore to a new target", code: "trustdb backup restore --file /var/backups/trustdb/proofstore.tdbackup \\\n  --metastore pebble --metastore-path /var/lib/trustdb-restore/proofs/pebble \\\n  --crypto-suite INTL_V1 --checkpoint /var/lib/trustdb-restore/checkpoint.json --resume", body: ["Resume uses the same archive, target, and BackupID-bound checkpoint. Never share one checkpoint between restore processes."] },
      { title: "Acceptance before traffic", bullets: ["Start an isolated instance with the same suite/NodeID/LogID/namespace", "Compare object counts and immutable anchor results", "Verify a pre-backup .sproof offline with independent trust roots", "Run wrong-content/key/TrustConfig negative tests", "Keep the old directory read-only through the rollback window"] },
      { title: "Protect the rest separately", cards: [["WAL", "Preserve binding and checkpoint."], ["NATS", "Protect streams, consumers, results, and DLQ."], ["Objects", "Use versioning and retention lock."], ["Key providers", "Follow provider ceremony and recovery artifacts."], ["FISCO BCOS", "Protect nodes, certificates, deployment records, and TrustConfig."], ["TiKV", "Use qualified cluster backup and isolated keyspace drills."]] },
      { title: "Rehearse", bullets: ["Back up around every release and trust change", "Restore monthly to a new directory", "Run quarterly joined recovery drills", "Record RPO/RTO, BackupID, suite, counts, failures, and owners"] },
    ], links: [["Feature catalog", "/docs/features"], ["Production operations", "/docs/operations"], ["Repository guide", "https://github.com/wowtrust/trustdb/blob/main/docs/zh-CN/BACKUP_AND_RECOVERY.md"]],
  },
  operations: {
    eyebrow: "Docs / Operations / 03", title: "Production operations", lead: "Plan identity and storage, gate startup, stop safely, monitor proof progression, and rehearse recovery.", updated: "Updated 2026.07.27 · current stable V2/V5 write generation",
    summary: [["Go-live", "validate + doctor + canary + offline verify"], ["Observe", "queues, WAL, proofs, STH, anchors, capacity"], ["Incidents", "preserve state; never delete evidence to hide an error"]],
    sections: [
      { title: "Fix the log identity", body: ["Suite, NodeID, LogID, proofstore namespace, and WAL identity define one writer stream. A suite, identity, or format-generation change requires a new stream."], code: "/etc/trustdb/\n/var/lib/trustdb/wal/\n/var/lib/trustdb/proofs/\n/var/backups/trustdb/" },
      { title: "Start and admit traffic", code: "trustdb config validate --config /etc/trustdb/production.yaml\ntrustdb doctor --config /etc/trustdb/production.yaml\ntrustdb serve --config /etc/trustdb/production.yaml", bullets: ["No schema/suite/WAL/key/transport startup error", "Health and metrics work", "Provider identity/quorum probes pass", "Canary reaches and independently verifies the intended proof level"] },
      { title: "Graceful stop", bullets: ["Remove traffic and stop publishers", "Drain queues, materializers, outboxes, and NATS", "Wait for shutdown_timeout", "Confirm listeners and Pebble lock are released", "Create and verify a backup when required"], note: "Never delete WAL, checkpoints, Pending/InFlight, or LOCK files to force completion." },
      { title: "Operating rhythm", cards: [["Daily", "Health, restarts, certificate expiry, queues, proof readiness, STH/anchor progress, disk, backup."], ["Weekly", "Offline proof and negative trust tests; registry/provider and NATS audit."], ["Monthly", "Fresh-target restore, capacity review, fault drills."], ["Every change", "One boundary, before/after digest, metrics, proof sample, rollback result."]] },
      { title: "Capacity and performance", body: ["Workers are not CPU cores. Increase concurrency against fixed semantics and data until p99, context switches, lock waits, or storage queues regress."], bullets: ["Transport latency and throughput", "Ingest/batch/materializer queues", "WAL fsync/segments and proofstore latency", "Outbox/STH/anchor/provider progress", "CPU/RSS/GC/fd/disk/network"] },
      { title: "Breaking upgrade", body: ["Current main accepts V2 model/WAL/API/.sproof and proofstore schema v5 only. Preserve the old version and LogID for historical verification; initialize the new generation with new keys, LogID, namespace, and WAL."], note: "Never let an old binary open V2/V5 data or re-encode old objects as new cryptographic identities." },
      { title: "Incident routing", cards: [["Connection refused", "Check process, listener, TLS, and startup log."], ["Stuck at L2/L3", "Inspect materializer or Global Log outbox."], ["No L5", "Inspect window, Pending/InFlight, and provider quorum."], ["WAL mismatch", "Use the correct identity-bound directory."], ["Pebble LOCK", "Find the owner; do not remove the lock."], ["BCOS disagreement", "Stop publishing and treat as a security event."]] },
    ], links: [["Feature catalog", "/docs/features"], ["Security audit", "/docs/security-audit"], ["Backup", "/docs/backup-recovery"], ["Troubleshooting", "/docs/troubleshooting"]],
  },
  securityAudit: {
    eyebrow: "Docs / Operations / Security audit", title: "Immutable security audit and trusted-time evidence", lead: "Write authentication, authorization, configuration, key, backup, anchor, trust configuration, and lifecycle activity to a separate signed chain; fail closed on broken continuity, capacity exhaustion, or required-time failure.", updated: "Updated 2026.07.27 · INTL_V1 / CN_SM_V1 · Linux / macOS / Windows",
    summary: [["Integrity", "signature + previous hash + monotonic sequence"], ["Production", "audit and synchronized time are mandatory"], ["Artifacts", "full JSONL chain + signed checkpoint"]],
    sections: [
      { title: "Separate from logs and business proofs", body: ["The security chain records privileged control-plane actions. It does not replace application logs, Prometheus, business records, WAL, or .sproof. Events carry actor, roles, action, object, result, request ID, policy version, time state, and bounded redacted context."], cards: [["INTL_V1", "Ed25519 signatures and a SHA-256 chain."], ["CN_SM_V1", "SM2 signatures and an SM3 chain."], ["Privacy", "Sensitive keys become <redacted>; emergency reasons are digested."], ["Concurrency", "Stable appends use an O(1) checkpoint path; slow output does not hold the live writer lock."]], note: "Local time, NTP samples, and BCOS block time are not automatically legal trusted timestamps." },
      { title: "1. Create a dedicated audit key", body: ["Do not reuse client/server proof keys. Production uses SDF, PKCS#11, HSM/KMS, or remote custody. These commands create a disposable CN_SM_V1 identity; --out is a local directory."], platformCode: {
        macos: "mkdir -p .trustdb-audit-key\nread -r -s -p 'Audit key passphrase: ' TRUSTDB_DEV_KEY_PASSPHRASE\nprintf '\\n'\nexport TRUSTDB_DEV_KEY_PASSPHRASE\n./bin/trustdb key generate --suite CN_SM_V1 --out .trustdb-audit-key --prefix audit\nunset TRUSTDB_DEV_KEY_PASSPHRASE",
        linux: "mkdir -p .trustdb-audit-key\nread -r -s -p 'Audit key passphrase: ' TRUSTDB_DEV_KEY_PASSPHRASE\nprintf '\\n'\nexport TRUSTDB_DEV_KEY_PASSPHRASE\n./bin/trustdb key generate --suite CN_SM_V1 --out .trustdb-audit-key --prefix audit\nunset TRUSTDB_DEV_KEY_PASSPHRASE",
        windows: "# Disposable test only; use SDF/PKCS#11/remote custody in production\nNew-Item -ItemType Directory -Force .trustdb-audit-key | Out-Null\n.\\bin\\trustdb.exe key generate --suite CN_SM_V1 --out .trustdb-audit-key --prefix audit --protection plaintext-dev-v1",
      }, bullets: ["audit.key is the signer descriptor", "audit.pub is independently distributed verifier trust", "audit.material must not share a backup boundary with its KEK"] },
      { title: "2. Configure audit and time reference", code: "audit:\n  enabled: true\n  required: true\n  path: \"/var/lib/trustdb/audit/security.audit\"\n  checkpoint_path: \"/var/lib/trustdb/audit/security.checkpoint\"\n  signing_key: \"/etc/trustdb/keys/audit.tdkey\"\n  max_bytes: 4294967296\n  retention: \"4380h\"\n  time_reference_path: \"/run/trustdb/time-reference.json\"\n  time_max_sample_age: \"2m\"\n  time_max_drift: \"5s\"\n  require_synchronized_time: true", body: ["A time-monitor agent atomically refreshes trustdb.time-reference.v1 with source, sample time, offset, uncertainty, synchronization, and confidence. local confidence is always unverified and cannot satisfy production policy."], bullets: ["States: synchronized, stale, drift-exceeded, unsynchronized, unavailable, invalid, unverified", "A failed time gate signs result=blocked before rejecting the operation", "The generic Admin config endpoint cannot modify admin/audit"] },
      { title: "3. Inspect, export, and verify offline", platformCode: {
        macos: "./bin/trustdb --config /etc/trustdb/trustdb.yaml audit status\n./bin/trustdb --config /etc/trustdb/trustdb.yaml audit export --out ./security-audit.jsonl\n./bin/trustdb audit verify --file ./security-audit.jsonl --public-key ./audit.pub\n./bin/trustdb --config /etc/trustdb/trustdb.yaml audit checkpoint export --out ./audit-checkpoint.json\n./bin/trustdb audit checkpoint verify --file ./audit-checkpoint.json --public-key ./audit.pub",
        linux: "./bin/trustdb --config /etc/trustdb/trustdb.yaml audit status\n./bin/trustdb --config /etc/trustdb/trustdb.yaml audit export --out ./security-audit.jsonl\n./bin/trustdb audit verify --file ./security-audit.jsonl --public-key ./audit.pub\n./bin/trustdb --config /etc/trustdb/trustdb.yaml audit checkpoint export --out ./audit-checkpoint.json\n./bin/trustdb audit checkpoint verify --file ./audit-checkpoint.json --public-key ./audit.pub",
        windows: ".\\bin\\trustdb.exe --config C:\\TrustDB\\trustdb.yaml audit status\n.\\bin\\trustdb.exe --config C:\\TrustDB\\trustdb.yaml audit export --out .\\security-audit.jsonl\n.\\bin\\trustdb.exe audit verify --file .\\security-audit.jsonl --public-key .\\audit.pub\n.\\bin\\trustdb.exe --config C:\\TrustDB\\trustdb.yaml audit checkpoint export --out .\\audit-checkpoint.json\n.\\bin\\trustdb.exe audit checkpoint verify --file .\\audit-checkpoint.json --public-key .\\audit.pub",
      }, body: ["Verification uses no server, provider, or network. It requires the verifier-local audit.pub to exactly match export metadata. Retain checkpoints in independent WORM/Object Lock or anchor their exact bytes/digest through an approved process."] },
      { title: "4. Capacity, backup, and retention", body: ["Formula: peak events/day × measured bytes/event × retention days × safety factor. The default 4 GiB / 4380h budget is about 23.5 MiB/day, or roughly 12,000 2-KiB events/day before safety margin."], bullets: ["max_bytes exhaustion blocks audited operations; history is never silently deleted or rotated", ".tdbackup v5 excludes this chain; retain JSONL, checkpoint, audit.pub, time-monitor configuration, and external receipt separately", "Restore is audited but does not replace destination audit history"] },
      { title: "5. Incident response", cards: [["rollback / truncation", "Stop privileged operations, preserve log/checkpoint/lock bytes, and compare independent checkpoints. Never truncate or recreate."], ["unsafe storage", "Correct owner, mode/DACL, parent writability, symlink, or file type."], ["capacity exhausted", "Preserve the chain, add capacity, and approve a higher max_bytes. Do not delete the tail."], ["time unsynchronized", "Repair the time monitor and inspect age, offset, uncertainty, confidence, permissions, and schema; the blocked event is retained."]] },
    ], links: [["Full repository guide", "https://github.com/wowtrust/trustdb/blob/main/docs/compliance/IMMUTABLE_SECURITY_AUDIT.md"], ["Administrative RBAC", "https://github.com/wowtrust/trustdb/blob/main/docs/compliance/ADMINISTRATIVE_RBAC.md"], ["Backup", "/docs/backup-recovery"], ["Operations", "/docs/operations"]],
  },
  keyLifecycle: {
    eyebrow: "Docs / Operations / Online key lifecycle",
    title: "Online client-key lifecycle",
    lead: "Synchronize approved browser or service-client keys into the append-only registry used by the running TrustDB admission path, under the existing administrator authentication, RBAC, and immutable audit controls.",
    updated: "Updated 2026.07.29 · TrustDB v2.0.1",
    summary: [["Authentication", "admin session / direct mTLS / pinned-gateway OIDC"], ["Authorization", "key.read / key.manage; built-in key-operator"], ["Effect", "immediate real claim admission in one process"]],
    sections: [
      { title: "One admission source of truth", body: ["The API does not create a second key cache or trust a key carried by an ingest request. It mutates the V2 Key Registry used by the running claim-admission path. Registration is immediately usable; claims at or after revocation are rejected while historical records remain verifiable."], cards: [["Register", "POST /admin/api/keys; public verifier descriptors only."], ["Inspect", "GET /admin/api/keys/{tenant}/{client}/{key}?at=...; historical lookup."], ["Revoke", "POST /admin/api/keys/{tenant}/{client}/{key}/revoke; signed effective time."], ["Audit", "Authentication, authorization, method, path, and outcome enter immutable security audit."]], note: "Static keys.client_public deployments remain read-only. Never expose the Admin subtree as a public ingest endpoint." },
      { title: "1. Configure a signable V2 registry", code: "paths:\n  key_registry: /var/lib/trustdb/keys/clients.tdkeys\nregistry:\n  key_id: registry-key\nkeys:\n  client_public: \"\"\n  registry_private: /run/secrets/registry.key\n  registry_public: /etc/trustdb/keys/registry.pub\nadmin:\n  enabled: true\n  base_path: /admin\n  policy_path: /etc/trustdb/admin-policy.json\n  session_secret: ${TRUSTDB_ADMIN_SESSION_SECRET}", body: ["The private and public registry descriptors must match suite, key ID, algorithm, encoding, and public bytes. Without registry_private, admission and historical reads remain available but mutation returns 503."] },
      { title: "2. Authenticate a dedicated key operator", code: "curl --fail-with-body \\\n  --cookie-jar trustdb-admin.cookies \\\n  --header 'Content-Type: application/json' \\\n  --data '{\"username\":\"proof-mesh-key-operator\",\"password\":\"...\"}' \\\n  https://trustdb.example/admin/api/session", body: ["Prefer a directly bound mTLS administrator or a pinned OIDC gateway for automation. Passwords, cookies, and registry-signing material belong in a secret manager, never configuration, shell history, or business logs."] },
      { title: "3. Register and inspect the exact key", code: "curl --fail-with-body --cookie trustdb-admin.cookies \\\n  --header 'Content-Type: application/json' --data @browser-key.json \\\n  https://trustdb.example/admin/api/keys\n\ncurl --fail-with-body --cookie trustdb-admin.cookies \\\n  https://trustdb.example/admin/api/keys/tenant-a/chrome-extension%3Aproof-mesh/browser-key-2026-07", bullets: ["Only kind=verifier and provider=public are accepted", "SM2 descriptors bind CN_SM_V1, sm2-sm3, user ID, and SEC1 public encoding", "An identical retry returns the original sequence/event hash", "Changed material or validity under one identity returns 409; rotate to a new key_id"] },
      { title: "4. Revoke and verify admission", code: "curl --fail-with-body --cookie trustdb-admin.cookies \\\n  --header 'Content-Type: application/json' \\\n  --data '{\"revoked_at\":\"2026-07-29T09:00:00Z\",\"reason\":\"tenant administrator revoked browser key\"}' \\\n  https://trustdb.example/admin/api/keys/tenant-a/chrome-extension%3Aproof-mesh/browser-key-2026-07/revoke", bullets: ["A new revocation may take effect now or in the future; more than five seconds of past skew is rejected", "An exact persisted revocation remains idempotent at any later retry", "New claims at or after the effective instant return FAILED_PRECONDITION / HTTP 412", "Restart must preserve registration, revocation, and historical accepted-record results"] },
      { title: "5. Multi-replica boundary", body: ["The request immediately updates the process that serves it. A single binary or one TrustDB Compose service can use it directly; NATS + TiKV replicas must not receive random key-management requests."], bullets: ["Distribute one ordered, authenticated, replayable registry event stream", "Gate readiness until every claim-admitting replica reaches the same sequence", "Remove lagging or unverifiable replicas from traffic", "Until then, use a controlled registry rollout and all-replica restart/readiness barrier"] },
    ],
    links: [["Complete API guide", "https://github.com/wowtrust/trustdb/blob/main/docs/integrations/ONLINE_KEY_LIFECYCLE.md"], ["Administrative RBAC", "https://github.com/wowtrust/trustdb/blob/main/docs/compliance/ADMINISTRATIVE_RBAC.md"], ["Immutable security audit", "/docs/security-audit"], ["Production operations", "/docs/operations"]],
  },
  supplyChain: {
    eyebrow: "Docs / Operations / Release supply chain", title: "Verify releases, use domestic mirrors, and import offline",
    lead: "Verify provenance first, enforce every SHA-256 and SM3 in the signed manifest, then import the exact platform package or immutable OCI digest.",
    updated: "Updated 2026.07.27 · release-evidence bundle for the current stable V2 release",
    summary: [["Provenance", "Sigstore bundle + separately provisioned trusted root"], ["Integrity", "signed manifest + SHA-256 + SM3"], ["Air gap", "exact file set + OCI digest + retained reports"]],
    sections: [
      { title: "Know the bundle", cards: [["Manifest", "Source commit, policy digest, required documents, size, SHA-256, and SM3 for every file."], ["Attestations", "Downloadable provenance for the manifest and OCI digest."], ["SBOM", "SPDX dependency and license inventory."], ["Production inputs", "BCOS SDK/contracts, PKCS#11, SDF, TLCP, locks, images, and architecture matrix."], ["Security results", "Retained npm and govulncheck fail-on-high output."], ["Container digest", "Immutable linux/amd64 + linux/arm64 manifest digest."]], note: "A root shipped beside a release cannot authorize itself. Provision and register the trusted-root digest through an independent channel." },
      { title: "1. Verify the signed manifest", code: "APPROVED_COMMIT=replace-with-approved-40-character-commit\ngh attestation verify \\\n  trustdb-release/TRUSTDB_RELEASE_MANIFEST.json \\\n  --repo wowtrust/trustdb \\\n  --signer-workflow wowtrust/trustdb/.github/workflows/release.yml \\\n  --source-digest \"$APPROVED_COMMIT\" \\\n  --deny-self-hosted-runners \\\n  --bundle trustdb-release/trustdb-release-attestation.sigstore.json \\\n  --custom-trusted-root /secure/trust-roots/github-public-good-trusted-root.json", body: ["Require the wowtrust/trustdb release workflow, an independently approved source digest, and a root outside the release directory. Root rotation is a separate approved change."] },
      { title: "2. Enforce the exact offline bundle", platformCode: {
        macos: "./trusted/trustdb release verify --dir ./trustdb-release",
        linux: "./trusted/trustdb release verify --dir ./trustdb-release",
        windows: ".\\trusted\\trustdb.exe release verify --dir .\\trustdb-release",
      }, bullets: ["Use a previously admitted verifier; do not let the new binary be its only trust authority", "The stable release derives media types from artifact names rather than the host MIME database, so macOS, Linux, and Windows enforce the same manifest rules", "Extra files, directories, symlinks, missing reports, duplicate checksums, and either digest mismatch fail", "Review version, source commit, policy digest, SBOM, and vulnerability result together"] },
      { title: "3. Export and import the OCI image", code: "DIGEST=\"$(jq -r .digest trustdb-release/TRUSTDB_CONTAINER_DIGESTS.json)\"\nskopeo copy --all \\\n  \"docker://ghcr.io/wowtrust/trustdb@${DIGEST}\" \\\n  oci-archive:trustdb-X.Y.Z.oci.tar\nskopeo inspect --format '{{.Digest}}' \\\n  oci-archive:trustdb-X.Y.Z.oci.tar", body: ["The inspected digest must equal DIGEST. Add the archive SHA-256 to controlled-media inventory and inspect it again before offline import."] },
      { title: "4. Mirror the admitted release artifacts", code: "DIGEST=\"$(jq -r .digest trustdb-release/TRUSTDB_CONTAINER_DIGESTS.json)\"\nskopeo copy --all \\\n  \"docker://ghcr.io/wowtrust/trustdb@${DIGEST}\" \\\n  \"docker://registry.internal.example/wowtrust/trustdb@${DIGEST}\"", body: ["An internal mirror changes distribution only and never rebuilds TrustDB. The target manifest digest must equal the release evidence; mirror Server/CLI archives byte-for-byte with both digests retained."] },
      { title: "5. Admit and rehearse", bullets: ["Transfer the release, trusted verifier, root, media inventory, and OCI archive", "Repeat provenance, dual-digest, and OCI verification offline", "Extract only the matching OS/architecture", "Run version, config validate, doctor, and a canary", "Export .sproof v2 and verify it with separate evidence trust roots", "Tamper package, manifest, attestation, root, OCI digest, and SBOM/policy and require staged failures"] },
    ], links: [["Full runbook", "https://github.com/wowtrust/trustdb/blob/main/docs/compliance/SUPPLY_CHAIN_RELEASES.md"], ["Operations", "/docs/operations"], ["Offline evidence verification", "/docs/offline-verification"], ["Downloads", "/downloads"]],
  },
  fiscoBCOS: {
    eyebrow: "Docs / Integrations / FISCO BCOS", title: "Anchor TrustDB STHs to FISCO BCOS", lead: "Qualify the exact topology, pin contract and chain trust, publish through quorum, then verify receipt inclusion and PBFT finality offline.", updated: "Updated 2026.07.25 · FISCO BCOS v3.16.3 / C SDK v3.6.0",
    summary: [["Admitted", "Air · Linux/amd64 · four nodes"], ["Modes", "independent standard and Guomi qualification"], ["Offline", "receipt inclusion + PBFT finality + exact STH binding"]],
    sections: [
      { title: "Check admission", body: ["Production admission currently covers four-node Air on Linux/amd64. macOS is development-only; Linux arm64 is artifact-only; Pro, Max, and containers require separate admission."], code: "python3 scripts/fisco-bcos/compatibility.py validate\npython3 scripts/fisco-bcos/compatibility.py check --deployment air --crypto standard --platform linux/amd64" },
      { title: "Choose the published capability boundary", code: "trustdb version\ntrustdb anchor plugin capabilities --endpoint unix:///run/trustdb/bcos-anchor.sock", body: ["The generic release verifies FISCO BCOS evidence offline. Real publication uses a separately qualified provider-enabled binary described only in the source-build guide; never improvise a build in this operations runbook. Match deployed runtime code to the mode-specific manifest digest."] },
      { title: "Run qualification", code: "scripts/fisco-bcos/smoke-air.sh --mode standard --qualification --work-dir /tmp/trustdb-bcos-standard --cache-dir /var/cache/trustdb/fisco-bcos\nscripts/fisco-bcos/smoke-air.sh --mode guomi --qualification --work-dir /tmp/trustdb-bcos-guomi --cache-dir /var/cache/trustdb/fisco-bcos", body: ["Standard and Guomi evidence are independent. The gate includes faults, transitions, durable replay, node shutdown, network isolation, and stage-specific tampering."] },
      { title: "Create TrustConfig", code: "trustdb anchor fisco-bcos trust-config create --input /etc/trustdb/fisco/trust-config.json --out /etc/trustdb/fisco/trust-config.cbor\ntrustdb anchor fisco-bcos trust-config inspect --input /etc/trustdb/fisco/trust-config.cbor", bullets: ["Pin chain/group/genesis/checkpoint", "Pin contract runtime hash", "At least two endpoints and read_quorum >= 2", "Pin provider, certificates, and validators", "Record the canonical config digest"] },
      { title: "Enable", code: "anchor:\n  sink: \"fisco-bcos\"\n  max_delay: \"5m\"\n  fisco_bcos:\n    trust_config_file: \"/etc/trustdb/fisco/trust-config.cbor\"", body: ["Production publisher keys belong in remote, PKCS#11, or SDF providers. Startup probes every endpoint identity, checkpoint, crypto mode, contract code, and conservative quorum height."] },
      { title: "Prove offline L5", bullets: ["Submit a canary and wait for the fixed anchor window", "Observe Pending/InFlight complete into an immutable result", "Export .sproof v2", "Supply verifier-local keys and canonical TrustConfig", "Stop TrustDB and BCOS nodes and verify offline", "Tamper receipt/block/finality/STH/TrustConfig and require the matching stage to fail"], note: "Evidence-carried keys and validators never authorize themselves. BCOS block time is not automatically a trusted timestamp." },
      { title: "Advance or disable", code: "trustdb anchor fisco-bcos trust-config advance --input /etc/trustdb/fisco/trust-config.cbor --evidence ./transition.sproof --expect-current-digest <digest> --out /etc/trustdb/fisco/trust-config.cbor", body: ["Checkpoint advancement requires a complete authenticated transition chain. To disable new anchoring, inspect unknown outcomes/InFlight first, then set anchor.sink=off and retain every historical trust and journal object."] },
    ], links: [["Full operator runbook", "https://github.com/wowtrust/trustdb/blob/main/docs/integrations/FISCO_BCOS_OPERATIONS.md"], ["Chinese repository guide", "https://github.com/wowtrust/trustdb/blob/main/docs/zh-CN/FISCO_BCOS.md"], ["Provider-enabled source build", "/docs/source-build"], ["Offline verification", "/docs/offline-verification"]],
  },
};

export function operationsGuides(locale) {
  return locale === "zh-CN" ? zhCN : en;
}
