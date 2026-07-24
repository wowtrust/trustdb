import { useEffect, useState } from "react";

const zhCN = {
  lang: "zh-CN",
  ui: {
    docs: "文档",
    home: "文档首页",
    updated: "更新于 2026.07.22",
    version: "适用于 TrustDB 1.0.0",
    duration: "预计用时",
    outcome: "完成后你将得到",
    prerequisites: "开始前准备",
    expected: "预期结果",
    checkpoint: "检查点",
    next: "下一步",
  },
  nav: {
    groups: [
      ["开始", [
        ["文档首页", "/docs"],
        ["理解 TrustDB", "/docs/concepts"],
        ["10 分钟快速开始", "/docs/quick-start"],
      ]],
      ["接入", [
        ["Go SDK 教程", "/docs/sdk"],
        ["NATS / JetStream 入口", "/docs/nats-ingress"],
        ["离线验证", "/docs/offline-verification"],
        ["CLI 参考", "/docs/cli"],
        ["桌面客户端", "/docs/desktop"],
      ]],
      ["运维", [
        ["生产部署", "/docs/server"],
        ["故障排查", "/docs/troubleshooting"],
      ]],
      ["参考", [
        ["安装桌面客户端", "/docs/desktop-install"],
        ["从源码构建", "/docs/source-build"],
        [".sproof v1", "/sproof"],
        ["性能基线", "/performance"],
      ]],
    ],
  },
  index: {
    eyebrow: "Documentation",
    title: ["从零开始，", "交付第一份可验证证据。"],
    lead: "先用 10 分钟完成本地 L3 验证，再按目标继续接入 Go SDK、部署服务或把 .sproof 交给验证方。每条路径都给出前置条件、可复制命令、预期输出和失败处理。",
    meta: "TrustDB 上手路径 · v1.0.0",
    primary: "开始 10 分钟教程",
    secondary: "先理解证据模型",
    chooseEyebrow: "Choose your outcome",
    chooseTitle: ["不用猜阅读顺序。", "从你的目标开始。"],
    chooseLead: "六条路径共享同一套证据语义；你可以先评估，再逐步进入业务接入和生产运维。",
    paths: [
      ["10 MIN", "本地跑通", "从空目录生成 L3 ProofBundle，并验证原文件未被修改。", "/docs/quick-start", "得到 example.tdproof"],
      ["BUILD", "接入 Go SDK", "启动本地服务，提交文件，等待 L4，导出并本地验证 .sproof。", "/docs/sdk", "得到可运行示例与 record.sproof"],
      ["STREAM", "接入 NATS 入口", "用 JetStream 耐久汇聚 signed claim，并在超时或重启后恢复不可变 L2 result。", "/docs/nats-ingress", "得到有界消息入口与恢复规则"],
      ["VERIFY", "验证收到的证据", "在服务关闭、网络断开的条件下，用独立取得的可信公钥复算证据。", "/docs/offline-verification", "得到离线验证结果"],
      ["OPERATE", "部署生产服务", "配置持久卷、密钥边界、网络保护、健康检查、备份与恢复演练。", "/docs/server", "得到上线检查清单"],
      ["RECOVER", "定位常见故障", "按症状排查权限、密钥、证明就绪、锚定、Pebble 锁和 schema 问题。", "/docs/troubleshooting", "得到安全修复步骤"],
    ],
    modelEyebrow: "Learning path",
    modelTitle: ["先看懂，再跑通，", "最后接入生产。"],
    modelSteps: [
      ["01", "理解", "明确 TrustDB 证明什么、不证明什么，以及 L1–L5 如何逐级增加可验证材料。"],
      ["02", "体验", "用 CLI 在本地生成密钥、声明和 L3 证明，亲手验证一次成功与一次篡改失败。"],
      ["03", "接入", "用 Go SDK 完成签名、提交和证明处理；需要耐久汇聚时选择可选 NATS / JetStream 写入口。"],
      ["04", "上线", "固定版本与配置，分离信任根，保护网络边界，并完成备份和恢复演练。"],
    ],
    boundaryTitle: "原文件可以不进入 TrustDB，验证也不依赖 TrustDB 在线。",
    boundaryBody: "核心服务接收签名摘要与所选元数据，再生成收据和证明。验证者必须从可信渠道取得客户端与服务端公钥；证据文件自带的信息不能自动成为信任根。",
  },
  quickStart: {
    title: "10 分钟快速开始",
    lead: "从空目录完成本地签名、L3 Merkle 提交、独立验证和篡改负向测试。无需启动服务器，也不需要 Go 工具链。",
    duration: "10 分钟",
    outcome: "example.tdproof 与一条重新计算得到的 L3 有效结果",
    prerequisites: ["macOS 或 Linux 终端（Windows 请使用下载页对应 ZIP 与 PowerShell）", "curl、tar、grep 与 shasum/sha256sum", "一个全新的练习目录；不要复用生产密钥目录"],
    downloadTitle: "1. 下载并先核对归档",
    downloadBody: "下载发布归档和统一校验清单。必须在解压前验证归档；下面以 Apple Silicon Mac 为例。",
    downloadExpected: "校验命令输出归档文件名和 OK。若不一致，停止操作并重新从 GitHub Release 下载。",
    allPlatforms: "选择其他平台",
    platformNoteTitle: "Linux 与 Windows",
    platformNoteBody: "Linux 使用 sha256sum -c。Windows 请下载对应 ZIP 和 SHA256SUMS，用 Get-FileHash -Algorithm SHA256 比对后解压。Windows 软件 envelope 持久化当前 fail closed，因此 PowerShell 练习显式使用仅限可丢弃数据的 plaintext-dev-v1；生产部署必须使用经批准的外部 signer。",
    linuxPathLabel: "Linux amd64：下载、校验与解压",
    windowsPathLabel: "Windows x86-64：完整 PowerShell 教程",
    extractTitle: "2. 解压并创建练习文件",
    extractBody: "进入发布目录后创建一个明确的输入文件。后续所有一次性状态都放在 .trustdb-dev 下。",
    extractExpected: "version 输出 1.0.0；example.txt 的内容为 hello TrustDB。",
    keysTitle: "3. 生成一次性客户端与服务端密钥",
    keysBody: "客户端私钥签名原文摘要，服务端私钥签发收据。默认私钥材料使用认证 SM4 envelope；开发口令只从环境变量或 owner-only secret file 读取，绝不能放进 argv。",
    keysWarning: "key generate 拒绝替换同名材料。只在新的练习目录执行一次；不要对已经签发过证据的身份重复运行，也不要把 KEK 与 envelope 放进同一备份范围。",
    keysExpected: ".trustdb-dev 中存在 client.key、client.pub、server.key 和 server.pub；私钥不得交给验证方。",
    claimTitle: "4. 在本地创建签名声明",
    claimBody: "CLI 流式计算 example.txt 的摘要并生成 .tdclaim。原文件不会被上传。",
    claimExpected: ".trustdb-dev/example.tdclaim 已生成；example.txt 仍只在本机。",
    commitTitle: "5. 提交到本地 Merkle 批次",
    commitBody: "本地 commit 使用独立的练习 WAL，并生成 L3 ProofBundle。它不会提交到正在运行的 TrustDB 服务器。",
    commitExpected: ".trustdb-dev/example.tdproof 已生成，proof inspect 可看到 record_id、batch_id 与 tree_size。",
    verifyTitle: "6. 独立验证",
    verifyBody: "验证器重新计算文件摘要、客户端签名、服务端收据和 Merkle 路径，不采信文件中自报的证明等级。",
    verifyExpected: "命令退出码为 0，JSON 中包含 \"valid\":true 和 \"proof_level\":\"L3\"。",
    tamperTitle: "7. 确认篡改会失败",
    tamperBody: "复制原文件并追加一行，再用同一份证明验证。这个命令必须以非零状态退出。",
    tamperExpected: "验证失败，证明只对应原始 example.txt；删除 tampered.txt 不影响原证据。",
    nextTitle: "下一步：把同一条证据链接入服务",
    nextBody: "本页只验证本地 L3。若要多人共享、异步批次、L4 全局透明日志或可选 L5 外部锚定，请继续 Go SDK 教程。",
  },
  sdk: {
    title: "Go SDK：提交、等待、导出、验证",
    lead: "运行一个完整可编译示例：检查服务健康、提交文件、等待 L4、写入 .sproof，再只用原文件和本地可信公钥验证。",
    duration: "20–30 分钟",
    outcome: "一个 record_id、一份至少 L4 的 record.sproof，以及本地验证结果",
    prerequisites: ["已经完成 10 分钟快速开始并保留 example.txt 与 .trustdb-dev 密钥", "Go 1.26.5 或兼容版本", "两个终端；服务仅绑定 127.0.0.1"],
    serverTitle: "1. 启动相对路径本地服务",
    serverBody: "这个命令不读取 production.yaml，所有可写状态都留在练习目录。Global Log 默认启用，因此记录会从 L2 异步升级到 L3，再到 L4。",
    serverExpected: "healthz 返回健康结果；保持这个终端运行。",
    projectTitle: "2. 创建隔离的 SDK 示例目录",
    projectBody: "在 .trustdb-dev 下建立独立 Go module；示例通过相对路径读取快速开始留下的文件和密钥。固定 v1.0.0，避免浮动依赖。",
    projectExpected: "go.mod 固定 github.com/wowtrust/trustdb v1.0.0；example.txt 与三把所需密钥仍保留在原练习位置。",
    codeTitle: "3. 运行经过编译检查的完整示例",
    codeBody: "展开下面的完整代码，复制并保存为当前目录的 main.go。仓库中的 examples/sdk-onboarding/main.go 是本页代码的唯一来源，并由 Go 测试编译；它使用超时上下文轮询证明，不会把刚提交的 L2 误报为 L4。",
    codeExpected: "输出 submitted record_id=… proof_level=L2（通常如此），随后输出 verified record_id=… proof_level=L4；当前目录生成 record.sproof。",
    sourceLabel: "查看经过编译检查的示例源码",
    asyncTitle: "为什么需要等待",
    asyncBody: "SubmitFile 在接收边界返回 L2。批次关闭和 Merkle 物化产生 L3，Global Log 发布产生 L4，精确匹配且成功的受支持 sink anchor result 产生 L5；只有真实外部 provider 才增加外部时间语义。示例等待 GlobalProof 非空，并在超时后明确失败。",
    idempotencyTitle: "生产重试不要重新构建声明",
    idempotencyBody: "快速示例让 SDK 生成随机幂等键。生产代码若要安全重试，应只调用一次 BuildSignedFileClaim，并在网络重试时重复提交同一个 SignedClaim；重新构建会改变 produced_at/nonce，不能配合同一个幂等键。",
    offlineTitle: "4. 停止服务，再验证一次",
    offlineBody: "在服务终端按 Ctrl+C，然后运行 CLI。这个过程不访问 TrustDB、锚定 provider 或网络。",
    offlineExpected: "服务关闭后仍返回 valid=true；证明等级按文件中的有效材料重新计算。",
  },
  offline: {
    title: "完全离线验证 .sproof",
    lead: "站在证据接收方视角，核对交付物、独立取得信任根，并在 TrustDB 与网络都不可用时重新计算证明。",
    duration: "5–10 分钟",
    outcome: "一条独立复算的 L3、L4 或 L5 结果，以及一次篡改失败记录",
    prerequisites: ["原始文件，例如 example.txt", "对应的单文件证据，例如 record.sproof", "通过可信渠道分别取得的客户端公钥与服务端公钥", "本机 TrustDB CLI；验证期间可断网并停止服务"],
    packageTitle: "1. 先核对交付包",
    packageBody: ".sproof 内嵌 ProofBundle，并可携带精确对应的 GlobalLogProof 和 AnchorResult。它不需要旁路查询服务器来补材料。",
    trustTitle: "证据不能自己指定谁值得信任",
    trustBody: "不要把 .sproof 内的信息直接当成信任根。客户端与服务端公钥应通过合同附件、受控配置库、线下指纹或其他独立渠道取得并固定。",
    verifyTitle: "2. 在断网环境运行验证",
    verifyBody: "验证器重新读取原文并校验每一层材料；输出等级来自实际通过的验证步骤。",
    verifyExpected: "valid=true。只有 ProofBundle 时最高 L3；有效 GlobalLogProof 产生 L4。L5 要求 TreeSize 与 RootHash 精确一致；NodeID/LogID 在证据双方都提供时必须一致；同时校验受支持的 sink 与确定性 anchor_id，OTS proof 还会校验结构和摘要。",
    levelTitle: "3. 正确解读等级",
    levels: [
      ["L3", "原文、签名、服务端收据和批次 Merkle 路径均有效。", "尚未证明该批次进入 Global Log。"],
      ["L4", "该批次属于文件内 Signed Tree Head 所覆盖的 Global Log。", "不等于存在外部时间锚。"],
      ["L5", "anchor result 与 STH 的 TreeSize、RootHash 精确匹配；非空身份字段、sink envelope 与 anchor_id 通过校验，OTS proof 另行校验。", "noop/file sink 也可形成 L5，但不应解释为独立外部时间。"],
    ],
    skipTitle: "只评估到 L4",
    skipBody: "--skip-anchor 会忽略文件中可用的 L5 材料，并在 Global Proof 有效时报告 L4。它不会让只有 L2/L3 的服务器记录自动获得 L4。",
    tamperTitle: "4. 做一次篡改负向测试",
    tamperBody: "修改原文、Merkle path、STH 签名、root、anchor_id，或 OTS 中受验证的 TreeSize、hash algorithm/digest、accepted timestamp，都应导致验证失败。file/noop 的 Proof 字段以及 OTS 的提交时间、calendar URL、状态码等诊断元数据不承载安全语义，不要把只修改这些字段当作篡改测试。先从最直观的原文变化开始。",
    tamperExpected: "命令非零退出。原文件与 record.sproof 保持不变时再次验证仍应成功。",
  },
  server: {
    title: "生产部署与恢复",
    lead: "从安全的本地单节点开始，明确二进制与 Docker 路径、持久化目录、密钥边界、网络保护、健康检查和备份恢复。",
    duration: "30–60 分钟，加一次恢复演练",
    outcome: "一个可监控、可备份、可恢复且边界明确的 TrustDB 单节点部署",
    prerequisites: ["已完成 10 分钟快速开始，并保留练习用 .trustdb-dev/server.key 与 client.pub", "已固定 TrustDB 版本和 SHA-256", "已决定二进制或 Docker 部署方式", "已规划持久数据、日志、密钥、key registry 与备份目录", "已规划反向代理、mTLS 或网络策略；不要把未保护的写入接口直接暴露到公网"],
    localTitle: "1. 先用相对路径完成冒烟测试",
    localBody: "下面的命令适合下载包与非 root 用户。它显式设置 WAL、Pebble 和 proof 目录，不会意外写入 /var/lib 或 /var/log。",
    localExpected: "healthz 成功，records 返回分页响应，metrics 返回 Prometheus 文本。",
    dockerTitle: "2. Docker 快速部署",
    dockerBody: "命名卷同时保存状态和首次启动生成的密钥。省略卷会在容器删除时丢失身份与证据状态。",
    dockerExpected: "容器处于 healthy/running；日志显示首次生成密钥；healthz 成功。",
    dockerBoundary: "示例只把环境变量名传给 Docker，口令值不会进入 argv。长期服务应使用 TRUSTDB_DEV_KEY_PASSPHRASE_FILE 指向数据卷之外、仅 owner 可读的 secret-manager mount。Docker 默认把演示客户端 envelope 与服务端状态放在同一卷，仅用于快速体验；生产环境应使用外部 signer 并分离客户端私钥。",
    templateTitle: "3. 再迁移到 production.yaml",
    templateBody: "发布包路径是 config/production.yaml，源码仓库路径是 configs/production.yaml。模板默认使用 /etc/trustdb、/var/lib/trustdb 和 /var/log/trustdb；创建目录、设置最小权限并替换密钥路径后再启动。run_profile 只是可观测标签，--data-dir 也不会自动重定位 WAL、proofstore、日志和密钥。",
    templatesLabel: "查看配置模板",
    profilesTitle: "存储与耐久性选择",
    profiles: [
      ["file", "轻量开发布局；适合本地实验，不是高吞吐生产基线。"],
      ["Pebble", "推荐的生产单节点 proofstore；服务运行时独占目录锁。"],
      ["TiKV", "多个计算节点可共享 TiKV 集群，但一个 proofstore namespace 只能属于一个逻辑 (node_id, log_id) 流；同 namespace active-active writer 尚不支持。"],
      ["fsync", "有效模式只有 strict、group、batch；生产默认优先 group。benchmark-extreme.yaml 是基准配置文件，不是 fsync mode。"],
    ],
    anchorTitle: "锚定边界",
    anchorBody: "Docker 默认 noop sink 只验证调度与证据管线，不提供独立外部时间。需要 L5 外部时间语义时配置受支持 provider，并确认返回的是与证据中 Signed Tree Head 精确匹配的 immutable result。",
    securityTitle: "网络与访问控制",
    securityBody: "TrustDB 的业务 HTTP/gRPC 接口不替代通用 TLS、身份认证或租户授权。生产环境应在受控网络内运行，并通过反向代理、mTLS、API gateway、防火墙或网络策略保护入口。Admin Web 默认关闭；启用时必须单独配置凭据、session secret 与 HTTPS cookie。",
    backupTitle: "4. 停服后创建并验证逻辑备份",
    backupBody: "Pebble 不允许备份进程与服务同时打开同一目录。先优雅停止写入服务，再创建、验证并恢复到新的路径。不要覆盖原目录进行第一次恢复演练。",
    backupBoundary: ".tdbackup 只包含 proofstore 的证据状态，包括 bundle、root、Global Log、STH、anchor result 与 scheduler state；它不包含 WAL、WAL checkpoint、配置、私钥、原始文件、key registry 或 registry 信任材料。应按同一恢复点分别备份这些材料；恢复后的 proofstore 只能配套匹配的 WAL 与 registry，不能混入任意旧状态。",
    checklistTitle: "上线检查清单",
    checklist: ["固定镜像 digest 或发布版本并保存 SHA-256", "客户端私钥与服务端私钥分离保管，公钥通过受控渠道分发", "所有持久路径和日志路径可写且有容量/权限监控", "写入接口只在受保护网络或 TLS/mTLS 入口后开放", "确认 anchor sink 的真实语义，不能把 noop 当成外部时间", "验证 healthz、records、metrics 与优雅关闭", "完成停服备份、backup verify 和独立目录恢复演练", "升级前阅读 release notes，并在副本上验证 schema 与证据"],
    apiTitle: "读取与集成入口",
    apiBody: "HTTP 写入使用确定性 CBOR，不是手写 JSON；gRPC 使用项目定义的确定性 CBOR codec。业务写入优先使用 Go SDK 或桌面客户端，curl 适合 health 与只读诊断。",
  },
  troubleshooting: {
    title: "故障排查",
    lead: "按症状找到最短诊断路径。所有修复都优先保留密钥、WAL、proofstore 和证据文件，不通过删除状态来掩盖错误。",
    duration: "每项 2–10 分钟",
    outcome: "明确的原因、可执行诊断命令和不会破坏证据边界的下一步",
    introTitle: "先保存现场",
    introBody: "记录版本、完整错误、启动参数和相关路径权限。不要重新运行 key generate、删除 Pebble/WAL、覆盖备份或把私钥贴到公开 issue。",
    diagnosticsTitle: "通用诊断",
    causeLabel: "可能原因",
    actionLabel: "安全处理",
    cards: [
      ["permission denied / 无法创建日志", "production.yaml 使用了 /var/lib、/var/log 或 /etc 下的路径，但当前用户没有权限。", "本地体验改用教程中的显式相对路径；生产部署创建专用用户和目录，再逐项设置 owner/mode。不要用 sudo 生成一部分状态后再切回普通用户。"],
      ["signature verification failed / key mismatch", "原文件变了，或验证者使用了错误的客户端/服务端公钥；也可能有人重新运行 key generate 覆盖了历史身份。", "核对原文件摘要与可信渠道保存的公钥指纹。保留现有文件，不要重新生成密钥来“修复”历史证据。"],
      ["proof not found / 只有 L2", "提交已被接收，但批次关闭或证明物化尚未完成。", "使用有界退避重试 GetProofBundle/ExportSingleProof。不要把 L2 当成失败，也不要无限无超时轮询。"],
      ["服务器验证要求 L4", "trustdb verify --server 会拉取 Global Log 证明；记录只有 L2/L3 时暂时无法满足。", "等待 L4 后重试，或先导出并验证已存在的 L3 ProofBundle。--skip-anchor 只忽略 L5，不会把 L3 升为 L4。"],
      ["一直没有 L5", "锚定被关闭、固定窗口尚未到期，或 provider 发布失败并正在重试。", "检查 anchor 配置、sink、max_delay、scheduler 与 provider 日志。noop/file 成功后也会形成 L5，但不提供独立外部时间；OTS calendar 首次接受即可形成 L5，后续 upgrade 只丰富证明。不要手工修改 proof_level。"],
      ["resource temporarily unavailable / LOCK", "运行中的 TrustDB 已独占打开 Pebble 目录，另一个 backup 或 server 进程无法同时打开。", "优雅停止服务，确认进程退出，再对同一路径执行 backup create。恢复时使用全新的目标目录。"],
      ["schema/version mismatch", "当前二进制拒绝打开不同 schema/format 版本的存储或备份。", "保留原件并核对创建它的 TrustDB 版本与 release notes。使用受支持的迁移路径或匹配版本先导出；不要删除版本标记或加入双读兼容。"],
    ],
    askTitle: "仍未解决？",
    askBody: "在 GitHub issue 中提供 TrustDB 版本、操作系统、复现步骤、脱敏后的配置字段、完整错误和已运行的诊断命令。不要上传真实私钥、token、生产地址、客户数据或未脱敏证据。",
    openIssueLabel: "提交 issue",
  },
};

const en = {
  ...zhCN,
  lang: "en",
  ui: {
    docs: "Docs", home: "Docs home", updated: "Updated 2026-07-22", version: "For TrustDB 1.0.0",
    duration: "Estimated time", outcome: "You will finish with", prerequisites: "Before you start",
    expected: "Expected result", checkpoint: "Checkpoint", next: "Next step",
  },
  nav: {
    groups: [
      ["Start", [["Docs home", "/docs"], ["Understand TrustDB", "/docs/concepts"], ["10-minute quick start", "/docs/quick-start"]]],
      ["Build", [["Go SDK tutorial", "/docs/sdk"], ["NATS / JetStream ingress", "/docs/nats-ingress"], ["Offline verification", "/docs/offline-verification"], ["CLI reference", "/docs/cli"], ["Desktop client", "/docs/desktop"]]],
      ["Operate", [["Production deployment", "/docs/server"], ["Troubleshooting", "/docs/troubleshooting"]]],
      ["Reference", [["Install the desktop client", "/docs/desktop-install"], ["Build from source", "/docs/source-build"], [".sproof v1", "/sproof"], ["Performance baseline", "/performance"]]],
    ],
  },
  index: {
    eyebrow: "Documentation", title: ["Start from zero.", "Deliver verifiable evidence."],
    lead: "Reach a locally verified L3 proof in ten minutes, then continue to the Go SDK, production deployment, or recipient-side .sproof verification. Every path includes prerequisites, copyable commands, expected output, and failure guidance.",
    meta: "TrustDB onboarding path · v1.0.0", primary: "Start the 10-minute tutorial", secondary: "Understand the evidence model first",
    chooseEyebrow: "Choose your outcome", chooseTitle: ["No reading-order puzzle.", "Start with your goal."],
    chooseLead: "Six paths share the same proof semantics. Evaluate locally, integrate into your application, then operate it safely.",
    paths: [
      ["10 MIN", "Run it locally", "Create an L3 ProofBundle from an empty directory and verify that the source file is unchanged.", "/docs/quick-start", "Produces example.tdproof"],
      ["BUILD", "Integrate the Go SDK", "Start a local server, submit a file, wait for L4, export .sproof, and verify it locally.", "/docs/sdk", "Produces a runnable example and record.sproof"],
      ["STREAM", "Add NATS ingress", "Durably fan signed claims into TrustDB through JetStream and recover immutable L2 results after timeout or restart.", "/docs/nats-ingress", "Produces a bounded broker path and recovery rules"],
      ["VERIFY", "Verify delivered evidence", "Recompute the proof with independently obtained trusted keys while the service and network are unavailable.", "/docs/offline-verification", "Produces an offline verification result"],
      ["OPERATE", "Deploy to production", "Plan persistent data, key boundaries, network protection, health checks, backup, and recovery rehearsal.", "/docs/server", "Produces a go-live checklist"],
      ["RECOVER", "Resolve common failures", "Diagnose permissions, keys, proof readiness, anchoring, Pebble locks, and schema failures by symptom.", "/docs/troubleshooting", "Produces safe recovery steps"],
    ],
    modelEyebrow: "Learning path", modelTitle: ["Understand it. Run it.", "Then take it to production."],
    modelSteps: [
      ["01", "Understand", "Learn what TrustDB proves, what it does not, and how L1–L5 add independently verifiable material."],
      ["02", "Experience", "Use the CLI to create keys, a claim, and an L3 proof, then observe one success and one tamper failure."],
      ["03", "Integrate", "Use the Go SDK for signing and proof handling; add the optional NATS / JetStream write path when durable fan-in is required."],
      ["04", "Operate", "Pin versions and configuration, separate trust roots, protect the network edge, and rehearse restore."],
    ],
    boundaryTitle: "The source file can stay outside TrustDB, and verification does not require TrustDB to be online.",
    boundaryBody: "The core service receives a signed digest and selected metadata, then produces receipts and proofs. Verifiers must obtain client and server public keys through trusted channels; data carried inside the evidence file does not become a trust root by itself.",
  },
  quickStart: {
    title: "10-minute quick start", lead: "From an empty directory, complete local signing, an L3 Merkle commit, independent verification, and a tamper-negative test. No server or Go toolchain is required.",
    duration: "10 minutes", outcome: "example.tdproof and a recomputed valid L3 result",
    prerequisites: ["A macOS or Linux terminal (use the matching ZIP and PowerShell on Windows)", "curl, tar, grep, and shasum/sha256sum", "A new practice directory; never reuse a production key directory"],
    downloadTitle: "1. Download and verify the archive first", downloadBody: "Download the release archive and checksum manifest. Verify before extracting; this example uses Apple Silicon macOS.", downloadExpected: "The checksum command prints the archive name followed by OK. Stop and download again from GitHub Releases if it differs.",
    allPlatforms: "Choose another platform", platformNoteTitle: "Linux and Windows", platformNoteBody: "Linux uses sha256sum -c. On Windows, download and verify the matching ZIP. Windows software-envelope persistence currently fails closed, so the PowerShell practice flow explicitly uses plaintext-dev-v1 only for disposable data; production deployments must use an approved external signer.",
    linuxPathLabel: "Linux amd64: download, verify, and extract", windowsPathLabel: "Windows x86-64: complete PowerShell walkthrough",
    extractTitle: "2. Extract and create the practice file", extractBody: "Enter the release directory and create an explicit input. All disposable state stays under .trustdb-dev.", extractExpected: "version prints 1.0.0 and example.txt contains hello TrustDB.",
    keysTitle: "3. Generate one-time client and server keys", keysBody: "The client private key signs the content digest and the server key signs receipts. Private material defaults to an authenticated SM4 envelope; its development passphrase comes only from an environment variable or owner-only secret file, never argv.", keysWarning: "key generate refuses to replace existing material. Run it once in a new practice directory, never rerun it for an identity that issued evidence, and keep the KEK outside the envelope backup boundary.", keysExpected: ".trustdb-dev contains client.key, client.pub, server.key, and server.pub. Never send private keys to a verifier.",
    claimTitle: "4. Create a signed claim locally", claimBody: "The CLI streams and hashes example.txt and creates a .tdclaim. The source file is not uploaded.", claimExpected: ".trustdb-dev/example.tdclaim exists and example.txt remains local.",
    commitTitle: "5. Commit to a local Merkle batch", commitBody: "The local commit uses a dedicated practice WAL and creates an L3 ProofBundle. It does not submit to a running TrustDB server.", commitExpected: ".trustdb-dev/example.tdproof exists; proof inspect shows record_id, batch_id, and tree_size.",
    verifyTitle: "6. Verify independently", verifyBody: "The verifier recomputes the file digest, client signature, server receipt, and Merkle path instead of trusting a claimed proof level.", verifyExpected: "The command exits 0 and JSON includes \"valid\":true and \"proof_level\":\"L3\".",
    tamperTitle: "7. Confirm tampering fails", tamperBody: "Copy the source file, append one line, and verify it with the same proof. This command must exit non-zero.", tamperExpected: "Verification fails. The proof matches only the original example.txt; deleting tampered.txt does not affect the evidence.",
    nextTitle: "Next: connect the same evidence chain to a service", nextBody: "This page stops at local L3. Continue to the Go SDK tutorial for shared ingestion, asynchronous batches, L4 Global Log, and optional L5 external anchoring.",
  },
  sdk: {
    title: "Go SDK: submit, wait, export, verify", lead: "Run a complete compilable example that checks health, submits a file, waits for L4, writes .sproof, and verifies it using only the source file and local trusted keys.",
    duration: "20–30 minutes", outcome: "A record_id, an L4-or-higher record.sproof, and a local verification result",
    prerequisites: ["Complete the 10-minute quick start and keep example.txt plus the .trustdb-dev keys", "Go 1.26.5 or a compatible release", "Two terminals; the service binds only to 127.0.0.1"],
    serverTitle: "1. Start a relative-path local server", serverBody: "This command does not load production.yaml; all writable state stays in the practice directory. Global Log is enabled, so a record advances asynchronously from L2 to L3 and then L4.", serverExpected: "healthz reports healthy; keep this terminal running.",
    projectTitle: "2. Create an isolated SDK example directory", projectBody: "Create a separate Go module under .trustdb-dev. The example reads the quick-start file and keys through relative paths. Pin v1.0.0 instead of a floating dependency.", projectExpected: "go.mod pins github.com/wowtrust/trustdb v1.0.0; example.txt and the three required keys remain in their original practice locations.",
    codeTitle: "3. Run the compile-checked complete example", codeBody: "Expand the complete source below, copy it, and save it as main.go in the current directory. examples/sdk-onboarding/main.go is the canonical source and is compiled by Go tests. It polls with a timeout and never reports the initial L2 response as L4.", codeExpected: "Output first includes submitted record_id=… proof_level=L2 in the usual case, then verified record_id=… proof_level=L4. record.sproof is created.",
    sourceLabel: "View the compile-checked example source",
    asyncTitle: "Why the example waits", asyncBody: "SubmitFile returns at the L2 acceptance boundary. Batch closure and Merkle materialization add L3, Global Log publication adds L4, and a successful exactly matching result from a supported sink adds L5; only a genuinely external provider adds external-time semantics. The example waits for a non-nil GlobalProof and fails clearly on timeout.",
    idempotencyTitle: "Do not rebuild a claim for production retries", idempotencyBody: "The quick example lets the SDK generate a random idempotency key. For safe production retries, call BuildSignedFileClaim once and resubmit the same SignedClaim after network errors. Rebuilding changes produced_at/nonce and cannot be paired with the same idempotency key.",
    offlineTitle: "4. Stop the service and verify again", offlineBody: "Press Ctrl+C in the server terminal, then run the CLI. This does not access TrustDB, an anchor provider, or the network.", offlineExpected: "Verification still returns valid=true while the service is stopped; the level is recomputed from valid material in the file.",
  },
  offline: {
    title: "Verify .sproof completely offline", lead: "Work as the recipient: check the delivery, acquire trust roots independently, and recompute the proof while TrustDB and the network are unavailable.",
    duration: "5–10 minutes", outcome: "An independently recomputed L3, L4, or L5 result plus a recorded tamper failure",
    prerequisites: ["The source file, such as example.txt", "Its single-file evidence, such as record.sproof", "Client and server public keys obtained separately through trusted channels", "A local TrustDB CLI; disconnect the network and stop the service during verification"],
    packageTitle: "1. Check the delivery package", packageBody: ".sproof embeds the ProofBundle and may carry an exactly corresponding GlobalLogProof and AnchorResult. It does not query the server for missing material.",
    trustTitle: "Evidence cannot appoint its own trust roots", trustBody: "Do not trust keys merely because they appear in or beside .sproof. Pin client and server public keys through a contract attachment, controlled configuration, offline fingerprint, or another independent channel.",
    verifyTitle: "2. Verify with the network disconnected", verifyBody: "The verifier rereads the source and checks every layer. The output level comes from checks that actually pass.", verifyExpected: "valid=true. ProofBundle alone tops out at L3; a valid GlobalLogProof yields L4. L5 requires exact TreeSize and RootHash; NodeID/LogID must match when both sides provide them; the supported sink and deterministic anchor_id are checked, and an OTS proof also undergoes structure and digest validation.",
    levelTitle: "3. Interpret the level correctly", levels: [["L3", "Source, signature, server receipt, and batch Merkle path are valid.", "Does not yet prove inclusion in Global Log."], ["L4", "The batch is included in the Global Log covered by the embedded Signed Tree Head.", "Does not imply an external time anchor."], ["L5", "TreeSize and RootHash match the STH exactly; non-empty identity fields, sink envelope, and anchor_id pass validation, with additional OTS proof checks.", "noop/file can produce L5 but are not independent external time."]],
    skipTitle: "Evaluate only through L4", skipBody: "--skip-anchor ignores available L5 material and reports L4 when Global Proof is valid. It does not promote an L2/L3 server record to L4.",
    tamperTitle: "4. Run a tamper-negative test", tamperBody: "Changing the source, Merkle path, STH signature, root, anchor_id, or verified OTS TreeSize, hash algorithm/digest, or accepted timestamp must fail. The file/noop Proof field and OTS diagnostic metadata such as submission time, calendar URL, and status code are not security-bearing; do not use changes to those fields alone as tamper tests. Start with the source file.", tamperExpected: "The command exits non-zero. Verification succeeds again when the original source and record.sproof are restored.",
  },
  server: {
    title: "Production deployment and recovery", lead: "Start with a safe local node, then make binary/Docker paths, persistent storage, key boundaries, network protection, health checks, backup, and recovery explicit.",
    duration: "30–60 minutes plus a restore rehearsal", outcome: "A monitored, backed-up, recoverable single-node TrustDB deployment with explicit boundaries",
    prerequisites: ["The 10-minute quick start completed, retaining the practice .trustdb-dev/server.key and client.pub", "A pinned TrustDB release and verified SHA-256", "A binary or Docker deployment decision", "Planned persistent data, log, key, key-registry, and backup locations", "A reverse proxy, mTLS, or network policy plan; do not expose an unprotected write endpoint to the public internet"],
    localTitle: "1. Begin with a relative-path smoke test", localBody: "This command works from a release archive as a non-root user. It explicitly locates WAL, Pebble, and proof data, avoiding accidental writes to /var/lib or /var/log.", localExpected: "healthz succeeds, records returns a page, and metrics returns Prometheus text.",
    dockerTitle: "2. Quick Docker deployment", dockerBody: "The named volume keeps state and first-run generated keys. Without it, deleting the container deletes its identity and evidence state.", dockerExpected: "The container is healthy/running, logs report first-run key generation, and healthz succeeds.",
    dockerBoundary: "The example forwards only the environment-variable name to Docker, so the value is absent from argv. Long-running services should use TRUSTDB_DEV_KEY_PASSPHRASE_FILE with an owner-only secret-manager mount outside the data volume. Keeping the demo client envelope beside server state is for evaluation only; production should use an external signer and separate client custody.",
    templateTitle: "3. Then migrate to production.yaml", templateBody: "The release archive uses config/production.yaml; the source tree uses configs/production.yaml. Defaults target /etc/trustdb, /var/lib/trustdb, and /var/log/trustdb. Create directories, set least privilege, and replace key paths first. run_profile is only an observability label, and --data-dir does not relocate WAL, proofstore, logs, and keys automatically.",
    templatesLabel: "View configuration templates",
    profilesTitle: "Choose storage and durability", profiles: [["file", "A lightweight development layout, not the high-throughput production baseline."], ["Pebble", "The recommended single-node production proofstore; the running service owns its directory lock."], ["TiKV", "Compute nodes may share a TiKV cluster, but one proofstore namespace belongs to one logical (node_id, log_id) stream; same-namespace active-active writers are not supported."], ["fsync", "The valid modes are strict, group, and batch; prefer group by default in production. benchmark-extreme.yaml is a benchmark profile, not an fsync mode."]],
    anchorTitle: "Anchoring boundary", anchorBody: "Docker defaults to the noop sink, which tests scheduling and evidence flow but does not provide independent external time. For L5 external-time semantics, configure a supported provider and require an immutable result that exactly matches the Signed Tree Head in the evidence.",
    securityTitle: "Network and access control", securityBody: "TrustDB business HTTP/gRPC endpoints do not replace general TLS, identity, or tenant authorization. Run inside a controlled network and protect ingress with a reverse proxy, mTLS, API gateway, firewall, or network policy. Admin Web is disabled by default; when enabled, configure credentials, a session secret, and secure HTTPS cookies.",
    backupTitle: "4. Stop the service, then create and verify a logical backup", backupBody: "Pebble cannot be opened by the service and backup process at the same time. Stop writes gracefully, then create, verify, and restore into a new path. Never overwrite the original directory during the first rehearsal.",
    backupBoundary: ".tdbackup contains only proofstore evidence state: bundles, roots, Global Log, STHs, anchor results, and scheduler state. It excludes WAL, WAL checkpoints, configuration, private keys, source files, the key registry, and registry trust material. Back those up separately at the same recovery point; pair a restored proofstore only with its matching WAL and registry, never arbitrary old state.",
    checklistTitle: "Go-live checklist", checklist: ["Pin an image digest or release version and retain SHA-256", "Separate client and server private keys; distribute public keys through controlled channels", "Monitor capacity and permissions for every persistent and log path", "Expose writes only behind a protected network or TLS/mTLS ingress", "Confirm the real anchor-sink semantics; never treat noop as external time", "Verify healthz, records, metrics, and graceful shutdown", "Complete stopped-service backup, backup verify, and restore into an independent path", "Read release notes before upgrades and validate schema/evidence on a copy"],
    apiTitle: "Read and integration endpoints", apiBody: "HTTP writes use deterministic CBOR, not handwritten JSON; gRPC uses the project's deterministic CBOR codec. Prefer the Go SDK or desktop client for business writes. curl is appropriate for health and read-only diagnostics.",
  },
  troubleshooting: {
    title: "Troubleshooting", lead: "Start with the symptom and take the shortest diagnostic path. Every fix preserves keys, WAL, proofstore, and evidence instead of hiding errors by deleting state.",
    duration: "2–10 minutes per item", outcome: "A known cause, an executable diagnostic, and a next step that preserves proof boundaries",
    introTitle: "Preserve the scene first", introBody: "Record the version, full error, startup arguments, and path permissions. Do not rerun key generate, delete Pebble/WAL, overwrite backups, or paste private keys into a public issue.", diagnosticsTitle: "Common diagnostics", causeLabel: "Likely cause", actionLabel: "Safe next step",
    cards: [
      ["permission denied / cannot create log", "production.yaml points into /var/lib, /var/log, or /etc without sufficient permissions.", "Use the tutorial's explicit relative paths locally. In production create a dedicated user and directories, then set owner/mode deliberately. Do not create half the state with sudo and continue as another user."],
      ["signature verification failed / key mismatch", "The source changed, the verifier has the wrong client/server key, or key generate replaced an identity that already issued evidence.", "Compare the source digest and fingerprints saved through trusted channels. Preserve current files; generating new keys cannot repair historical evidence."],
      ["proof not found / still L2", "The claim was accepted, but batch closure or proof materialization has not finished.", "Retry GetProofBundle/ExportSingleProof with bounded backoff. L2 is not a failure; never poll forever without a timeout."],
      ["server verification requires L4", "trustdb verify --server fetches Global Log proof, which an L2/L3 record cannot satisfy yet.", "Wait for L4, or verify an already exported L3 ProofBundle. --skip-anchor ignores L5 only; it does not upgrade L3 to L4."],
      ["L5 never appears", "Anchoring is disabled, the fixed window has not expired, or provider publication failed and is retrying.", "Check anchor configuration, sink, max_delay, scheduler, and provider logs. Successful noop/file results also produce L5 but not independent external time. Initial OTS calendar acceptance produces L5; later upgrades only enrich its proof. Never edit proof_level manually."],
      ["resource temporarily unavailable / LOCK", "The running service owns the Pebble directory, so another backup or server process cannot open it.", "Stop the service gracefully, confirm exit, then run backup create. Restore into a new target directory."],
      ["schema/version mismatch", "The binary refuses a store or backup with a different schema/format version.", "Keep the original and identify the TrustDB version that created it. Follow a supported migration or use the matching version to export first; never delete version markers or add dual-read compatibility."],
    ],
    askTitle: "Still blocked?", askBody: "Open a GitHub issue with the TrustDB version, operating system, reproduction steps, redacted configuration fields, full error, and diagnostics already run. Never upload real private keys, tokens, production addresses, customer data, or unredacted evidence.", openIssueLabel: "Open an issue",
  },
};

const copyByLocale = { "zh-CN": zhCN, en };
const pendingLocales = new Map();
const localeLoaders = {
  ru: () => import("./docsOnboarding.ru-ja").then(({ ru }) => ru),
  ja: () => import("./docsOnboarding.ru-ja").then(({ ja }) => ja),
  fr: () => import("./docsOnboarding.fr-ko").then(({ fr }) => fr),
  ko: () => import("./docsOnboarding.fr-ko").then(({ ko }) => ko),
};

function loadDocsOnboarding(locale) {
  if (copyByLocale[locale] || !localeLoaders[locale]) return Promise.resolve();
  let pending = pendingLocales.get(locale);
  if (!pending) {
    pending = localeLoaders[locale]()
      .then((copy) => { copyByLocale[locale] = copy; })
      .finally(() => { pendingLocales.delete(locale); });
    pendingLocales.set(locale, pending);
  }
  return pending;
}

export function docsOnboarding(locale = "zh-CN") {
  return copyByLocale[locale] || en;
}

export function useDocsOnboarding(locale = "zh-CN", enabled = true) {
  const [copy, setCopy] = useState(() => docsOnboarding(locale));

  useEffect(() => {
    let cancelled = false;
    let retryTimer;
    setCopy(docsOnboarding(locale));
    const load = (retriesLeft) => loadDocsOnboarding(locale)
      .then(() => { if (!cancelled) setCopy(docsOnboarding(locale)); })
      .catch((error) => {
        if (cancelled) return;
        if (retriesLeft > 0) {
          retryTimer = window.setTimeout(() => load(retriesLeft - 1), 1000);
          return;
        }
        console.error(`Unable to load TrustDB onboarding copy for ${locale}; showing English fallback.`, error);
        setCopy(en);
      });
    if (enabled) load(1);
    return () => {
      cancelled = true;
      window.clearTimeout(retryTimer);
    };
  }, [locale, enabled]);

  return copy;
}

export { en as docsOnboardingEnglish, zhCN as docsOnboardingChinese };
