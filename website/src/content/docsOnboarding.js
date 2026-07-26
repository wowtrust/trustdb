import { useEffect, useState } from "react";

const zhCN = {
  lang: "zh-CN",
  ui: {
    docs: "文档",
    home: "文档首页",
    updated: "更新于 2026.07.25",
    version: "适用于 TrustDB 当前 main（V2）",
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
        ["功能开关与配置", "/docs/features"],
        ["备份与恢复", "/docs/backup-recovery"],
        ["不可变安全审计", "/docs/security-audit"],
        ["发布验签与国产镜像", "/docs/supply-chain"],
        ["生产运维手册", "/docs/operations"],
        ["FISCO BCOS 锚定", "/docs/fisco-bcos"],
        ["故障排查", "/docs/troubleshooting"],
      ]],
      ["参考", [
        ["安装桌面客户端", "/docs/desktop-install"],
        ["从源码构建", "/docs/source-build"],
        [".sproof v2", "/sproof"],
        ["性能基线", "/performance"],
      ]],
    ],
  },
  index: {
    eyebrow: "Documentation",
    title: ["从零开始，", "交付第一份可验证证据。"],
    lead: "先用 10 分钟完成本地 L3 验证，再按目标继续接入 Go SDK、部署服务或把 .sproof 交给验证方。每条路径都给出前置条件、可复制命令、预期输出和失败处理。",
    meta: "TrustDB 上手路径 · 当前 main / V2",
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
    lead: "从空目录构建当前 V2 CLI，完成本地签名、L3 Merkle 提交、独立验证和篡改负向测试。无需启动服务器。",
    duration: "10 分钟",
    outcome: "example.tdproof 与一条重新计算得到的 L3 有效结果",
    prerequisites: ["macOS、Linux 或 Windows 终端", "Git 与 go.mod 指定的 Go 版本", "一个全新的练习目录；不要复用生产密钥目录"],
    downloadTitle: "1. 获取当前 V2 代码",
    downloadBody: "官网文档始终对应当前 main。选择操作系统后复制命令，浅克隆最新代码并记录实际 commit；不要拿旧 Release 二进制执行当前教程。",
    downloadExpected: "git rev-parse 输出当前 commit 短哈希，go version 满足仓库 go.mod。",
    allPlatforms: "完整源码构建说明",
    platformNoteTitle: "为什么不直接下载旧 Release",
    platformNoteBody: "当前 main 已进入 V2 密钥、模型、WAL、API 与 .sproof 代际，而 v1.0.0 发布包不包含这些命令和格式。教程以当前代码为准；生产部署应在验证后固定具体 commit，正式发布产物仍可在下载页获取。",
    linuxPathLabel: "Linux amd64：下载、校验与解压",
    windowsPathLabel: "Windows x86-64：完整 PowerShell 教程",
    extractTitle: "2. 构建 CLI 并创建练习文件",
    extractBody: "从当前源码构建本机 CLI，并创建一个明确的输入文件。后续所有一次性状态都放在 .trustdb-dev 下。",
    extractExpected: "version 输出当前平台与构建信息；源码构建未注入发布标签时 version 可显示 dev。example.txt 内容为 hello TrustDB。",
    keysTitle: "3. 生成一次性客户端与服务端密钥",
    keysBody: "客户端私钥签名原文摘要，服务端私钥签发收据。--out 指定文件写入的目录，不是上传地址；这里统一写入 .trustdb-dev。默认私钥材料使用认证 SM4 envelope；开发口令只从环境变量或 owner-only secret file 读取，绝不能放进 argv。",
    keysWarning: "key generate 拒绝替换同名材料。只在新的练习目录执行一次；不要对已经签发过证据的身份重复运行，也不要把 KEK 与 envelope 放进同一备份范围。",
    keysExpected: ".trustdb-dev 中存在 client.key、client.pub、client.material、server.key、server.pub 和 server.material；.key 是签名器描述，.pub 是验证器描述，.material 是受保护的私钥材料。目录中还可能出现用于原子更新协调的 .material.lock；它不是密钥或信任根。验证方只需要可信取得的公钥。",
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
    serverBody: "这个命令不读取 production.yaml，所有可写状态都留在练习目录。macOS/Linux 需要重新输入快速开始使用的软件密钥口令；Windows 练习继续使用可丢弃的 plaintext-dev-v1 密钥。Global Log 默认启用，因此记录会从 L2 异步升级到 L3，再到 L4。",
    serverExpected: "healthz 返回健康结果；保持这个终端运行。",
    projectTitle: "2. 创建隔离的 SDK 示例目录",
    projectBody: "在 .trustdb-dev 下建立独立 Go module，并用 replace 指向刚才克隆的同一份当前源码。这样 SDK 与 CLI 必然来自同一个 commit，不会意外解析到旧 Release。生产项目应改为固定经过验证的 tag 或 pseudo-version。",
    projectExpected: "go.mod 要求 github.com/wowtrust/trustdb v0.0.0，并通过 replace 指向 ../..；example.txt 与所需密钥仍保留在原练习位置。",
    codeTitle: "3. 运行经过编译检查的完整示例",
    codeBody: "展开下面的完整代码，复制并保存为当前目录的 main.go。仓库中的 examples/sdk-onboarding/main.go 是本页代码的唯一来源，并由 Go 测试编译；它使用超时上下文轮询证明，不会把刚提交的 L2 误报为 L4。macOS/Linux 的运行命令会再次读取客户端软件密钥口令，且在进程结束后清除环境变量。",
    codeExpected: "输出 submitted record_id=… proof_level=L2（通常如此），随后输出 verified record_id=… proof_level=L4；当前目录生成 record.sproof。",
    sourceLabel: "查看经过编译检查的示例源码",
    asyncTitle: "为什么需要等待",
    asyncBody: "SubmitFile 在接收边界返回 L2。批次关闭和 Merkle 物化产生 L3，Global Log 发布产生 L4，精确匹配且成功的受支持 sink anchor result 产生 L5；只有真实外部 provider 才增加外部时间语义。示例等待 GlobalProof 非空，并在超时后明确失败。",
    idempotencyTitle: "生产重试不要重新构建声明",
    idempotencyBody: "快速示例让 SDK 生成随机幂等键。生产代码若要安全重试，应只调用一次 BuildSignedFileClaim，并在网络重试时重复提交同一个 SignedClaim；重新构建会改变 produced_at/nonce，不能配合同一个幂等键。",
    offlineTitle: "4. 停止服务，再验证一次",
    offlineBody: "在服务终端按 Ctrl+C，然后运行 CLI。macOS/Linux 仍需解锁本地软件密钥 descriptor；Windows 练习使用之前的 plaintext-dev-v1 材料。这个过程不访问 TrustDB、锚定 provider 或网络。",
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
    prerequisites: ["已完成 10 分钟快速开始，并保留练习用 .trustdb-dev/server.key 与 client.pub", "已记录并固定验证通过的 main commit 或镜像 digest", "已决定二进制或 Docker 部署方式", "已规划持久数据、日志、密钥、key registry 与备份目录", "已规划反向代理、mTLS 或网络策略；不要把未保护的写入接口直接暴露到公网"],
    localTitle: "1. 先用相对路径完成冒烟测试",
    localBody: "下面的命令直接使用快速开始构建的当前 main 二进制，并适合非 root 用户。macOS/Linux 会重新读取软件密钥口令；Windows 练习沿用快速开始生成的可丢弃 plaintext-dev-v1 密钥。所有 WAL、Pebble 和 proof 数据都留在相对路径，不会意外写入 /var/lib 或 /var/log。",
    localExpected: "healthz 成功，records 返回分页响应，metrics 返回 Prometheus 文本。",
    dockerTitle: "2. 构建当前镜像，再按 mTLS 基线启动",
    dockerBody: "先从同一份 main 源码构建镜像并运行 version，确认镜像本身可执行。当前 configs/docker.yaml 是生产 mTLS 基线，不是无证书 HTTP demo；启动服务前必须准备服务器证书、客户端 CA、专用健康检查客户端证书，并确保服务器证书含 trustdb DNS SAN。下面的第二组命令只在这些资产齐全后执行。",
    dockerExpected: "镜像 version 命令成功；完整挂载配置、TLS 与密钥口令后，容器进入 healthy，带健康检查客户端证书的 HTTPS 请求返回成功。",
    dockerBoundary: "不要为了让容器看起来能启动而把生产监听器降级成明文。密钥口令通过数据卷之外的只读文件挂载进入容器，证明状态保存在命名卷；生产环境还应将客户端私钥移出服务端，使用业务侧 signer 与受信 key registry。",
    templateTitle: "3. 再迁移到 production.yaml",
    templateBody: "发布包路径是 config/production.yaml，源码仓库路径是 configs/production.yaml。模板默认使用 /etc/trustdb、/var/lib/trustdb 和 /var/log/trustdb；创建目录、设置最小权限并替换密钥路径后再启动。生产 profile 还强制要求独立审计 signer 和持续刷新的 synchronized time-reference；缺失时会在开放业务端口前 fail closed。run_profile 只是可观测标签，--data-dir 也不会自动重定位 WAL、proofstore、日志和密钥。",
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
    checklist: ["固定镜像 digest 或发布版本并保存 SHA-256", "客户端、服务端与审计私钥分离保管，公钥通过受控渠道分发", "审计 signer、protected audit path 和 synchronized time-reference 已验收", "所有持久路径和日志路径可写且有容量/权限监控", "写入接口只在受保护网络或 TLS/mTLS 入口后开放", "确认 anchor sink 的真实语义，不能把 noop 当成外部时间", "验证 healthz、records、metrics、audit status 与优雅关闭", "完成停服备份、backup verify、审计导出和独立目录恢复演练", "升级前阅读 release notes，并在副本上验证 schema 与证据"],
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
    docs: "Docs", home: "Docs home", updated: "Updated 2026-07-25", version: "For current TrustDB main (V2)",
    duration: "Estimated time", outcome: "You will finish with", prerequisites: "Before you start",
    expected: "Expected result", checkpoint: "Checkpoint", next: "Next step",
  },
  nav: {
    groups: [
      ["Start", [["Docs home", "/docs"], ["Understand TrustDB", "/docs/concepts"], ["10-minute quick start", "/docs/quick-start"]]],
      ["Build", [["Go SDK tutorial", "/docs/sdk"], ["NATS / JetStream ingress", "/docs/nats-ingress"], ["Offline verification", "/docs/offline-verification"], ["CLI reference", "/docs/cli"], ["Desktop client", "/docs/desktop"]]],
      ["Operate", [["Production deployment", "/docs/server"], ["Feature catalog", "/docs/features"], ["Backup and recovery", "/docs/backup-recovery"], ["Immutable security audit", "/docs/security-audit"], ["Release verification and mirrors", "/docs/supply-chain"], ["Operations handbook", "/docs/operations"], ["FISCO BCOS anchoring", "/docs/fisco-bcos"], ["Troubleshooting", "/docs/troubleshooting"]]],
      ["Reference", [["Install the desktop client", "/docs/desktop-install"], ["Build from source", "/docs/source-build"], [".sproof v2", "/sproof"], ["Performance baseline", "/performance"]]],
    ],
  },
  index: {
    eyebrow: "Documentation", title: ["Start from zero.", "Deliver verifiable evidence."],
    lead: "Reach a locally verified L3 proof in ten minutes, then continue to the Go SDK, production deployment, or recipient-side .sproof verification. Every path includes prerequisites, copyable commands, expected output, and failure guidance.",
    meta: "TrustDB onboarding path · current main / V2", primary: "Start the 10-minute tutorial", secondary: "Understand the evidence model first",
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
    title: "10-minute quick start", lead: "From an empty directory, build the current V2 CLI and complete local signing, an L3 Merkle commit, independent verification, and a tamper-negative test. No server is required.",
    duration: "10 minutes", outcome: "example.tdproof and a recomputed valid L3 result",
    prerequisites: ["A macOS, Linux, or Windows terminal", "Git and the Go version declared by go.mod", "A new practice directory; never reuse a production key directory"],
    downloadTitle: "1. Get the current V2 source", downloadBody: "The website documentation tracks current main. Select your operating system, shallow-clone the latest code, and record the exact commit; do not run this tutorial with an older release binary.", downloadExpected: "git rev-parse prints the checked-out commit and go version satisfies the repository go.mod.",
    allPlatforms: "Complete source-build guide", platformNoteTitle: "Why the tutorial does not download an old release", platformNoteBody: "Current main uses the V2 key, model, WAL, API, and .sproof generation. The v1.0.0 package does not contain those commands or formats. Validate current main, then pin an exact commit for production; stable historical assets remain on the downloads page.",
    linuxPathLabel: "Linux amd64: download, verify, and extract", windowsPathLabel: "Windows x86-64: complete PowerShell walkthrough",
    extractTitle: "2. Build the CLI and create the practice file", extractBody: "Build the native CLI from current source and create an explicit input. All disposable state stays under .trustdb-dev.", extractExpected: "version reports the current platform and build metadata; a source build may report dev when no release label is injected. example.txt contains hello TrustDB.",
    keysTitle: "3. Generate one-time client and server keys", keysBody: "The client private key signs the content digest and the server key signs receipts. --out is the directory where files are written, not an upload destination; this tutorial uses .trustdb-dev. Private material defaults to an authenticated SM4 envelope; its development passphrase comes only from an environment variable or owner-only secret file, never argv.", keysWarning: "key generate refuses to replace existing material. Run it once in a new practice directory, never rerun it for an identity that issued evidence, and keep the KEK outside the envelope backup boundary.", keysExpected: ".trustdb-dev contains client.key, client.pub, client.material, server.key, server.pub, and server.material. .key describes the signer, .pub describes the verifier, and .material contains protected private material. A .material.lock coordination file may also remain; it is not a key or trust root. A verifier needs only independently trusted public keys.",
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
    serverTitle: "1. Start a relative-path local server", serverBody: "This command does not load production.yaml; all writable state stays in the practice directory. macOS/Linux prompts again for the software-key passphrase used during quick start; the disposable Windows exercise keeps its plaintext-dev-v1 keys. Global Log is enabled, so a record advances asynchronously from L2 to L3 and then L4.", serverExpected: "healthz reports healthy; keep this terminal running.",
    projectTitle: "2. Create an isolated SDK example directory", projectBody: "Create a separate Go module under .trustdb-dev and replace the TrustDB module with the same current source checkout. CLI and SDK then come from one exact commit instead of resolving an older release. Production projects should pin a validated tag or pseudo-version.", projectExpected: "go.mod requires github.com/wowtrust/trustdb v0.0.0 and replaces it with ../..; example.txt and the required keys remain in their original practice locations.",
    codeTitle: "3. Run the compile-checked complete example", codeBody: "Expand the complete source below, copy it, and save it as main.go in the current directory. examples/sdk-onboarding/main.go is the canonical source and is compiled by Go tests. It polls with a timeout and never reports the initial L2 response as L4. On macOS/Linux the command prompts again for the client software-key passphrase and removes the environment variable afterward.", codeExpected: "Output first includes submitted record_id=… proof_level=L2 in the usual case, then verified record_id=… proof_level=L4. record.sproof is created.",
    sourceLabel: "View the compile-checked example source",
    asyncTitle: "Why the example waits", asyncBody: "SubmitFile returns at the L2 acceptance boundary. Batch closure and Merkle materialization add L3, Global Log publication adds L4, and a successful exactly matching result from a supported sink adds L5; only a genuinely external provider adds external-time semantics. The example waits for a non-nil GlobalProof and fails clearly on timeout.",
    idempotencyTitle: "Do not rebuild a claim for production retries", idempotencyBody: "The quick example lets the SDK generate a random idempotency key. For safe production retries, call BuildSignedFileClaim once and resubmit the same SignedClaim after network errors. Rebuilding changes produced_at/nonce and cannot be paired with the same idempotency key.",
    offlineTitle: "4. Stop the service and verify again", offlineBody: "Press Ctrl+C in the server terminal, then run the CLI. macOS/Linux still unlocks the local software-key descriptor; the Windows exercise uses its existing plaintext-dev-v1 material. This does not access TrustDB, an anchor provider, or the network.", offlineExpected: "Verification still returns valid=true while the service is stopped; the level is recomputed from valid material in the file.",
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
    prerequisites: ["The 10-minute quick start completed, retaining the practice .trustdb-dev/server.key and client.pub", "A tested main commit or image digest recorded and pinned", "A binary or Docker deployment decision", "Planned persistent data, log, key, key-registry, and backup locations", "A reverse proxy, mTLS, or network policy plan; do not expose an unprotected write endpoint to the public internet"],
    localTitle: "1. Begin with a relative-path smoke test", localBody: "Use the current-main binary built by the quick start as a non-root user. macOS/Linux prompts again for the software-key passphrase; the disposable Windows exercise keeps the plaintext-dev-v1 keys generated earlier. WAL, Pebble, and proof data stay in explicit relative paths instead of /var/lib or /var/log.", localExpected: "healthz succeeds, records returns a page, and metrics returns Prometheus text.",
    dockerTitle: "2. Build current main, then start the mTLS baseline", dockerBody: "Build the image from the same main checkout and run version first. Current configs/docker.yaml is a production mTLS baseline, not a certificate-free HTTP demo. Before starting the service, provide the server certificate, client CA, dedicated health-client certificate, and a trustdb DNS SAN on the server certificate. Run the second command block only after those assets exist.", dockerExpected: "The image version command succeeds. After configuration, TLS, and the key-passphrase file are mounted, the container becomes healthy and the certificate-authenticated HTTPS health request succeeds.",
    dockerBoundary: "Do not weaken the production listener to plaintext merely to make the container start. Mount the key passphrase as a read-only file outside the data volume and keep evidence state in the named volume. Production should also move client private keys out of the server and use an application-side signer with a trusted key registry.",
    templateTitle: "3. Then migrate to production.yaml", templateBody: "The release archive uses config/production.yaml; the source tree uses configs/production.yaml. Defaults target /etc/trustdb, /var/lib/trustdb, and /var/log/trustdb. Create directories, set least privilege, and replace key paths first. The production profile also requires a dedicated audit signer and a continuously refreshed synchronized time-reference; missing evidence fails closed before business listeners open. run_profile is only an observability label, and --data-dir does not relocate WAL, proofstore, logs, and keys automatically.",
    templatesLabel: "View configuration templates",
    profilesTitle: "Choose storage and durability", profiles: [["file", "A lightweight development layout, not the high-throughput production baseline."], ["Pebble", "The recommended single-node production proofstore; the running service owns its directory lock."], ["TiKV", "Compute nodes may share a TiKV cluster, but one proofstore namespace belongs to one logical (node_id, log_id) stream; same-namespace active-active writers are not supported."], ["fsync", "The valid modes are strict, group, and batch; prefer group by default in production. benchmark-extreme.yaml is a benchmark profile, not an fsync mode."]],
    anchorTitle: "Anchoring boundary", anchorBody: "Docker defaults to the noop sink, which tests scheduling and evidence flow but does not provide independent external time. For L5 external-time semantics, configure a supported provider and require an immutable result that exactly matches the Signed Tree Head in the evidence.",
    securityTitle: "Network and access control", securityBody: "TrustDB business HTTP/gRPC endpoints do not replace general TLS, identity, or tenant authorization. Run inside a controlled network and protect ingress with a reverse proxy, mTLS, API gateway, firewall, or network policy. Admin Web is disabled by default; when enabled, configure credentials, a session secret, and secure HTTPS cookies.",
    backupTitle: "4. Stop the service, then create and verify a logical backup", backupBody: "Pebble cannot be opened by the service and backup process at the same time. Stop writes gracefully, then create, verify, and restore into a new path. Never overwrite the original directory during the first rehearsal.",
    backupBoundary: ".tdbackup contains only proofstore evidence state: bundles, roots, Global Log, STHs, anchor results, and scheduler state. It excludes WAL, WAL checkpoints, configuration, private keys, source files, the key registry, and registry trust material. Back those up separately at the same recovery point; pair a restored proofstore only with its matching WAL and registry, never arbitrary old state.",
    checklistTitle: "Go-live checklist", checklist: ["Pin an image digest or release version and retain SHA-256", "Separate client, server, and audit private keys; distribute public keys through controlled channels", "Qualify the audit signer, protected audit paths, and synchronized time-reference", "Monitor capacity and permissions for every persistent and log path", "Expose writes only behind a protected network or TLS/mTLS ingress", "Confirm the real anchor-sink semantics; never treat noop as external time", "Verify healthz, records, metrics, audit status, and graceful shutdown", "Complete stopped-service backup, backup verify, audit export, and restore into an independent path", "Read release notes before upgrades and validate schema/evidence on a copy"],
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
