export const comparisonSources = [
  { name: "immudb", href: "https://docs.immudb.io/master/" },
  { name: "Sigstore Rekor", href: "https://docs.sigstore.dev/logging/overview/" },
  { name: "OpenTimestamps", href: "https://opentimestamps.org/" },
];

const content = {
  "zh-CN": {
    home: {
      hero: {
        eyebrow: "SIGN · RECORD · VERIFY",
        title: ["证据离开系统，", "依然可验证。"],
        copy: "TrustDB 将文件、日志和业务事件的摘要与身份签名，逐级组织为收据、Merkle 证明、全局透明日志和可选锚定，最终导出可携带的 .sproof。",
        primary: "10 分钟生成第一份证据",
        secondary: "查看离线验证",
        points: ["原文件无需上传", "单文件 .sproof", "自托管部署", "Go SDK · HTTP · gRPC"],
        index: "原文 + .sproof + 本地可信公钥，离开 TrustDB 仍可复算。",
      },
      problem: {
        eyebrow: "Why TrustDB",
        title: ["传统日志，", "要求别人相信你。", "TrustDB，", "让他们自己验证。"],
        copy: [
          "文件交付后可能被替换，日志可能被管理员改写，业务事件也常常只剩一张系统截图。争议发生时，查询结果不是证据，单方声明更无法让对方复算。",
          "TrustDB 是现有业务系统旁边的一层可验证证据基础设施：不迁移原始数据，只把摘要、身份和处理过程组织成可以交给客户、审计方或合作伙伴独立验证的材料。",
        ],
        artAlt: "文件交付、审计日志和业务事件从单方记录转化为可独立验证证据的三个场景",
        captions: ["文件交付后版本可验", "审计日志离开系统可验", "业务事件跨组织可验"],
        answerTitle: "一个 .sproof，就是一份可交付的证据包。",
        answerBody: "它携带签名、收据、Merkle 路径、Signed Tree Head 与可用锚定材料。验证者使用原文和本地可信公钥复算，不需要登录你的系统。",
        cta: "看懂 TrustDB 的证据模型",
      },
      capabilities: {
        eyebrow: "Why it wins",
        title: ["把整条证据链，", "装进一个文件。"],
        lead: "TrustDB 不只返回一个“已存证”状态。它把每一层可验证材料交付出去，让信任从服务器查询变成第三方可以重复执行的计算。",
        cards: [
          ["01", "原文留在你的系统", "客户端本地流式计算摘要并签名；核心服务接收摘要、所选元数据与签名，再生成收据和证明，不要求上传原始文件。"],
          ["02", "一条完整证据链", "身份签名、服务端收据、Merkle 包含证明、全局透明日志和可选锚定由同一套系统逐级生成。"],
          ["03", "服务下线仍可验证", "确定性 CBOR .sproof 携带完整证明材料；验证全程只读取原文、证据文件与验证者自己的信任根。"],
        ],
        benchmarkEyebrow: "Verified benchmark / explicit semantics",
        metrics: [["56,576", "L2 submit/s"], ["2,237", "full-index L4/s"], ["7,311,000", "当前版本提交"], ["0", "失败 / batch error"]],
        benchmarkCta: "查看环境、口径与完整结果",
      },
      proof: {
        eyebrow: "Proof model",
        title: ["从签名，", "到完整证据。"],
        lead: "L1–L5 不是服务端自报的状态标签。验证器根据实际携带的材料逐层复算，并停在能够通过的最高等级。",
        levels: [
          ["L1", "签名", "客户端在本地绑定内容摘要与身份。"],
          ["L2", "收据", "服务端验证声明并签发可验证收据。"],
          ["L3", "MERKLE", "记录进入批次树并获得包含证明。"],
          ["L4", "GLOBAL", "批次根被精确的 Signed Tree Head 覆盖。"],
          ["L5", "锚定", "保存与该树头精确匹配的锚定结果。"],
        ],
      },
      journey: {
        eyebrow: "How it works",
        title: ["三步，", "把证据交到", "客户手里。"],
        labels: [
          ["本地签名", "只提交摘要、所选元数据与签名"],
          ["逐级成证", "收据 → Merkle → Signed STH → 可选锚定"],
          ["离线交付", "原文 + .sproof + 本地信任根"],
        ],
        caption: "完整离线验证不访问 TrustDB、锚定服务或网络；证据等级由验证器重新计算。",
        artAlt: "文件和日志的摘要经过签名、透明日志与可选锚定后形成可离线交付证据的抽象数据场",
      },
      useCases: {
        eyebrow: "Built for evidence delivery",
        title: ["证据交付出去，", "仍然可以复算。"],
        lead: "不要求客户回到你的后台看一个状态，也不要求审计方先相信日志管理员。把原文和 .sproof 交出去，对方自己得到结论。",
        cards: [
          ["01 / FILE DELIVERY", "文件交付验真", "合同、报告、数据集或模型文件离开系统后，接收方可以验证是否仍是被签名并接收的同一版本。"],
          ["02 / AUDIT LOGS", "审计日志举证", "把关键日志条目的摘要与处理链导出为证据，审计方无需访问生产日志后端也能复算包含关系。"],
          ["03 / BUSINESS EVENTS", "跨组织事件确认", "为订单、结算、审批或数据交换事件绑定提交身份与证据链，让合作方拿到可长期保存的验证材料。"],
        ],
      },
    },
    server: { evidenceName: "组合证据", evidenceDescription: "获取覆盖该批次的精确 STH 与可用 anchor" },
    sdk: {
      exportComment: "// 或直接写入确定性 CBOR .sproof 文件",
      exportDescription: "SDK 先获取 L3 ProofBundle，再通过组合证据接口请求覆盖该 batch 的精确 Signed STH 与可用 anchor result。若不存在覆盖锚点，导出会诚实停在 L3 或 L4；不会用“更大的 TreeSize”放宽绑定，也不会伪造等级。",
      trustTitle: "离线信任根",
      trustDescription: "验证时仍要由调用方提供可信服务端公钥，以及客户端公钥或受信任密钥注册表。.sproof 自带的任何密钥都不能自动成为信任根。",
      evidenceDescription: "覆盖 batch 的 L4 证明与精确匹配的 L5 anchor",
    },
    comparison: {
      eyebrow: "Positioning / July 2026",
      title: "TrustDB 把证据链做完整。",
      lead: "从客户端身份签名、服务端收据，到 Merkle 证明、全局透明日志和外部时间锚定，TrustDB 将分散的环节整合为一套业务证据系统，最终输出可携带、可完全离线验证的 .sproof。",
      columns: ["系统", "主要任务", "形成什么证据", "如何验证", "优先选择它的情况"],
      products: [
        ["TrustDB", "业务证据工作流", "客户端签名、服务端收据、Merkle 包含证明、透明日志与可选外部锚定", "原文件 + .sproof + 本地信任公钥，完全离线复算", "需要自托管地为业务文件或日志生成可交付证据"],
        ["immudb", "不可变数据库", "数据库事务的密码学可验证历史", "客户端或审计器验证数据库状态与历史", "业务数据本身需要存进可查询的不可变数据库"],
        ["Sigstore Rekor", "软件供应链透明日志", "软件项目签名元数据的防篡改日志记录", "查询条目与包含证明，并审计日志一致性", "需要公开或私有的软件制品签名透明度"],
        ["OpenTimestamps", "区块链时间戳标准", "文档哈希的可升级时间戳证明", "用证明文件和区块链数据验证时间边界", "只需要证明某个摘要不晚于某个时间存在"],
      ],
      note: "TrustDB 的优势是端到端证据交付：原文无需进入透明日志，验证方也无需访问 TrustDB 服务，只凭原文件、.sproof 与可信公钥即可独立复算最高 L1–L5 证据等级。",
      sourceLabel: "比较依据：各项目官方文档（核对于 2026-07-22）",
      cta: "查看 TrustDB 如何完成整条证据链",
    },
    concepts: {
      title: "理解 TrustDB",
      summary: "先看懂系统边界、证据生命周期、L1–L5 与信任模型。",
      cta: "先理解系统",
      lead: "TrustDB 是一套可验证证据数据库：业务系统提交内容摘要和身份签名，服务端把它们组织成可审计的证明，验证方最终可以脱离服务器复算结果。",
      updated: "更新于 2026.07.22 · 适用于当前主分支",
      sections: {
        plain: {
          title: "先用一句话理解",
          body: "它不替你保存和展示原始业务文件，而是为“这份内容由谁在什么处理阶段提交、是否进入不可篡改结构、是否获得外部时间边界”生成证据。",
          exampleTitle: "以 invoice.pdf 为例",
          example: "发送方在本地计算哈希并签名，TrustDB 接收签名声明并逐级生成证明。交付时把原文件、.sproof 和可信公钥交给验证方；对方无需登录你的系统，也无需相信证据文件自带的结论。",
        },
        flow: {
          title: "一条记录怎样变成证据",
          steps: [
            ["01", "本地哈希与签名", "客户端读取原文件，生成内容哈希并用 Ed25519 身份密钥签名。原文件是否上传由业务集成决定；证明模型只要求服务端收到 SignedClaim。"],
            ["02", "接收与耐久收据", "服务端校验声明和身份，把已接受记录写入 WAL，并签发 AcceptedReceipt。fsync 策略决定 L2 的崩溃耐久边界。"],
            ["03", "批次 Merkle 证明", "后台把记录提交到 batch Merkle tree，生成 ProofBundle。验证器可重新计算叶子和路径，证明记录属于该批次根。"],
            ["04", "全局透明日志", "批次根进入只追加的 Global Log，并由 Signed Tree Head 覆盖。GlobalLogProof 证明该批次根属于指定 STH。"],
            ["05", "外部锚定与交付", "覆盖该记录的 STH 可发布到外部 anchor sink。最终 .sproof 把 L3、可选 L4 和可选 L5 材料装进一个确定性 CBOR 文件。"],
          ],
        },
        stored: {
          title: "保存什么，不保存什么",
          cards: [
            ["TrustDB 保存", "内容哈希、客户端签名、服务端记录与收据、Merkle 证明、STH、外部锚定结果，以及恢复这些状态所需的 WAL、proofstore 和逻辑备份。"],
            ["业务系统保留", "原文件、原始日志正文、业务权限、加密密钥和业务数据库。TrustDB 不要求把敏感原文放进透明日志。"],
            ["验证者自己提供", "服务端可信公钥，以及客户端公钥或受信任密钥注册表。证据文件中携带的公钥不能自动成为信任根。"],
            ["TrustDB 不判断", "内容是否真实、业务行为是否合法、签名者是否有业务授权。它证明密码学绑定和处理链，不替代访问控制、内容加密或法律判断。"],
          ],
        },
        levels: {
          title: "L1–L5 到底表示什么",
          intro: "等级是可验证材料的简称，不是服务端随意填写的状态。验证器会从现有材料重新计算最高等级。",
          rows: [
            ["L1", "客户端签名", "内容摘要、身份与声明绑定", "服务端尚未接收"],
            ["L2", "服务端收据", "服务端已经验证并接受声明", "记录尚未进入 batch Merkle tree"],
            ["L3", "批次证明", "记录包含于特定 batch root", "批次根尚未进入全局日志"],
            ["L4", "全局日志证明", "batch root 包含于指定 Signed STH", "该 STH 尚无外部时间锚点"],
            ["L5", "外部锚定", "同一 STH / global root 获得外部可验证时间边界", "不证明业务内容本身真实或合法"],
          ],
          headers: ["等级", "新增材料", "它证明", "它不证明"],
        },
        components: {
          title: "系统由哪些部分组成",
          cards: [
            ["CLI / Desktop / SDK", "在可信客户端侧计算哈希、管理身份、签名声明、提交记录、导出和验证证明。"],
            ["TrustDB Server", "验证请求、签发收据、批处理记录、维护 Global Log、调度外部锚定，并暴露 HTTP、gRPC 和指标。"],
            ["WAL + Proofstore", "WAL 保护已接受写入；file、Pebble 或 TiKV proofstore 保存可查询的记录与证明状态。两者是不同耐久边界。"],
            ["Offline Verifier", "只读取原文件、.sproof 和本地信任根，独立复算哈希、签名、Merkle path、STH 与 anchor 绑定。"],
          ],
        },
        paths: {
          title: "接下来读哪一篇",
          cards: [
            ["我想先验证概念", "快速开始", "/docs/quick-start", "10 分钟在本地生成 L3 证明并独立验证。"],
            ["我要部署服务", "服务器", "/docs/server", "理解配置、耐久边界、存储、Global Log、anchor 和运维。"],
            ["我要接入业务代码", "Go SDK", "/docs/sdk", "从签名提交到导出 .sproof，再到离线 VerifySingleProof。"],
            ["我要审核证据格式", ".sproof v1", "/sproof", "阅读字段、等级上限、绑定规则和完整验证算法。"],
          ],
        },
      },
    },
  },
  en: {
    home: {
      hero: {
        eyebrow: "SIGN · RECORD · VERIFY",
        title: ["Deliver evidence.", "Verify independently."],
        copy: "TrustDB turns signed digests for files, logs, and business events into receipts, Merkle proofs, a global transparency log, optional anchors, and one portable .sproof.",
        primary: "Create a proof in 10 minutes",
        secondary: "See offline verification",
        points: ["No source-file upload", "Single-file .sproof", "Self-hosted", "Go SDK · HTTP · gRPC"],
        index: "Original + .sproof + locally trusted keys: recompute the result without TrustDB.",
      },
      problem: {
        eyebrow: "Why TrustDB",
        title: ["Traditional logs", "demand trust.", "TrustDB lets", "others verify."],
        copy: [
          "Delivered files can be replaced, administrators can rewrite logs, and a business event often ends up as nothing more than a screenshot. When a dispute starts, a query result is not independently verifiable evidence.",
          "TrustDB adds a verifiable evidence layer beside the systems you already run. It leaves source data in place and packages digests, identities, and processing history for customers, auditors, and partners to verify independently.",
        ],
        artAlt: "Three scenarios turning file delivery, audit logs, and business events into independently verifiable evidence",
        captions: ["Verify delivered file versions", "Verify logs outside production", "Verify events across organizations"],
        answerTitle: "One .sproof is a deliverable evidence package.",
        answerBody: "It carries signatures, receipts, Merkle paths, Signed Tree Heads, and available anchor material. A verifier recomputes the result from the original and locally trusted keys—without logging into your system.",
        cta: "Understand the TrustDB evidence model",
      },
      capabilities: {
        eyebrow: "Why it wins",
        title: ["Put the complete evidence chain", "in one file."],
        lead: "TrustDB does more than return a “recorded” status. It delivers every verifiable layer, turning trust in a server query into a computation any recipient can repeat.",
        cards: [
          ["01", "Keep source data in your system", "The client streams, hashes, and signs locally. The core service accepts the digest, selected metadata, and signature, then issues receipts and proofs—never requiring the original file."],
          ["02", "Complete the evidence chain", "Identity signature, server receipt, Merkle inclusion, global transparency log, and optional anchoring are produced by one system, layer by layer."],
          ["03", "Verify after the service is gone", "A deterministic CBOR .sproof carries the proof material. Verification reads only the original, the evidence file, and the verifier's own trust roots."],
        ],
        benchmarkEyebrow: "Verified benchmark / explicit semantics",
        metrics: [["56,576", "L2 submit/s"], ["2,237", "full-index L4/s"], ["7,311,000", "current-version submissions"], ["0", "failures / batch errors"]],
        benchmarkCta: "See the environment, methodology, and full results",
      },
      proof: {
        eyebrow: "Proof model",
        title: ["Sign once.", "Build complete", "evidence."],
        lead: "L1–L5 are not server-reported badges. The verifier recomputes each layer from the material present and stops at the highest level that actually validates.",
        levels: [
          ["L1", "SIGNATURE", "Bind the content digest to a client identity locally."],
          ["L2", "RECEIPT", "Validate the claim and issue a signed server receipt."],
          ["L3", "MERKLE", "Include the record in a batch tree with an inclusion proof."],
          ["L4", "GLOBAL", "Cover the batch root with one exact Signed Tree Head."],
          ["L5", "ANCHOR", "Carry the anchor result exactly matching that tree head."],
        ],
      },
      journey: {
        eyebrow: "How it works",
        title: ["Three steps.", "Build the proof.", "Deliver the evidence."],
        labels: [
          ["Sign locally", "Submit only digest, selected metadata, and signature"],
          ["Build the chain", "Receipt → Merkle → Signed STH → optional anchor"],
          ["Deliver offline", "Original + .sproof + local trust roots"],
        ],
        caption: "Complete offline verification contacts no TrustDB server, anchor provider, or network; the verifier recomputes the evidence level.",
        artAlt: "Abstract data field showing file and log digests becoming portable offline evidence through signing, a transparency log, and optional anchoring",
      },
      useCases: {
        eyebrow: "Built for evidence delivery",
        title: ["Deliver evidence.", "Enable independent", "verification."],
        lead: "Do not send customers back to your dashboard for a status, or ask auditors to trust the log administrator. Deliver the original and .sproof so they can reach the result themselves.",
        cards: [
          ["01 / FILE DELIVERY", "Verify delivered files", "After a contract, report, dataset, or model leaves your system, the recipient can prove it is still the same version that was signed and accepted."],
          ["02 / AUDIT LOGS", "Export audit evidence", "Turn critical log entries and their processing chain into evidence an auditor can verify without access to the production log backend."],
          ["03 / BUSINESS EVENTS", "Confirm cross-company events", "Bind orders, settlements, approvals, or data exchanges to a submitting identity and deliver proof material that partners can retain long term."],
        ],
      },
    },
    server: { evidenceName: "Composed evidence", evidenceDescription: "Return the exact covering STH and available anchor for this batch" },
    sdk: {
      exportComment: "// Or write a deterministic CBOR .sproof file directly",
      exportDescription: "The SDK first fetches the L3 ProofBundle, then asks the composed-evidence endpoint for the exact Signed STH covering that batch and any matching anchor result. Without a covering anchor, export honestly stops at L3 or L4; it never loosens binding to a larger TreeSize or invents a level.",
      trustTitle: "Offline trust roots",
      trustDescription: "Verification still requires a trusted server public key and either client public keys or a trusted key registry supplied by the caller. Keys carried inside .sproof never become trust roots automatically.",
      evidenceDescription: "L4 proof covering the batch and its exactly matched L5 anchor",
    },
    comparison: {
      eyebrow: "Positioning / July 2026", title: "TrustDB completes the evidence chain.",
      lead: "TrustDB integrates client identity signatures, server receipts, Merkle proofs, a global transparency log, and external time anchoring into one business evidence system, producing a portable .sproof that can be verified fully offline.",
      columns: ["System", "Primary job", "Evidence produced", "Verification model", "Choose it when"],
      products: [
        ["TrustDB", "Business evidence workflow", "Client signatures, server receipts, Merkle inclusion, transparency log, and optional external anchoring", "Original content + .sproof + local trusted keys; fully offline", "You need self-hosted, deliverable evidence for business files or logs"],
        ["immudb", "Immutable database", "Cryptographically verifiable history of database transactions", "Clients or auditors verify database state and history", "The primary, queryable data should live in an immutable database"],
        ["Sigstore Rekor", "Software supply-chain transparency log", "Tamper-resistant log entries for signed software metadata", "Query entries and inclusion proofs; audit log consistency", "You need public or private signature transparency for software artifacts"],
        ["OpenTimestamps", "Blockchain timestamping standard", "Upgradable timestamp proofs for document hashes", "Verify a proof file against blockchain data", "You only need to prove a digest existed no later than a time boundary"],
      ],
      note: "TrustDB's advantage is end-to-end evidence delivery: source content never needs to enter the transparency log, and a verifier needs no TrustDB connection—only the original content, .sproof, and trusted public keys to recompute the highest valid L1–L5 level.",
      sourceLabel: "Compared against official project documentation (checked 2026-07-22)", cta: "See how TrustDB completes the evidence chain",
    },
    concepts: {
      title: "Understand TrustDB", summary: "Learn the system boundaries, evidence lifecycle, L1–L5, and trust model first.", cta: "Understand the system first", lead: "TrustDB is a verifiable evidence database: business systems submit content digests and identity signatures, the server organizes them into auditable proofs, and verifiers can recompute the result without the server.", updated: "Updated 2026.07.22 · Current main branch",
      sections: {
        plain: { title: "The one-sentence explanation", body: "It does not replace storage and presentation of your original business files. It creates evidence for who submitted a content digest, how it moved through the system, whether it entered tamper-evident structures, and whether it gained an external time boundary.", exampleTitle: "Take invoice.pdf", example: "The sender hashes and signs locally. TrustDB accepts the signed claim and progressively creates proof material. At delivery, the verifier receives the original file, .sproof, and trusted public keys—without logging into your system or trusting conclusions embedded in the evidence file." },
        flow: { title: "How one record becomes evidence", steps: [["01","Hash and sign locally","The client reads the original, creates its digest, and signs with an Ed25519 identity key. Uploading original content is an integration choice; the proof model only requires a SignedClaim."],["02","Accept and issue a durable receipt","The server validates identity and claim, writes the accepted record to WAL, and signs an AcceptedReceipt. The fsync policy defines the L2 crash-durability boundary."],["03","Create a batch Merkle proof","A background batch commits records into a Merkle tree and creates a ProofBundle. A verifier recomputes the leaf and path to prove membership in the batch root."],["04","Append to the global transparency log","The batch root enters the append-only Global Log and is covered by a Signed Tree Head. GlobalLogProof proves membership in that exact STH."],["05","Anchor and deliver","A covering STH can be published to an external anchor sink. The final .sproof carries L3 and optional L4/L5 material in one deterministic CBOR file."]] },
        stored: { title: "What is stored—and what is not", cards: [["TrustDB stores","Content digests, client signatures, server records and receipts, Merkle proofs, STHs, anchor results, plus WAL, proofstore, and logical backups needed for recovery."],["Your business system keeps","Original files, raw log bodies, permissions, encryption keys, and the business database. Sensitive source content does not need to enter the transparency log."],["The verifier supplies","A trusted server public key and either client public keys or a trusted key registry. Keys bundled in an evidence file do not become trust roots automatically."],["TrustDB does not decide","Whether content is truthful, an action is lawful, or a signer had business authorization. It proves cryptographic bindings and processing history; it does not replace access control, encryption, or legal judgment."]] },
        levels: { title: "What L1–L5 actually mean", intro: "Levels summarize verifiable material; they are not server-assigned labels. The verifier recomputes the highest valid level from the artifacts present.", headers: ["Level","New material","What it proves","What it does not prove"], rows: [["L1","Client signature","Digest, identity, and claim are bound","The server has accepted it"],["L2","Server receipt","The server validated and accepted the claim","The record is in a batch Merkle tree"],["L3","Batch proof","The record is included in a specific batch root","The batch root is in the Global Log"],["L4","Global log proof","The batch root is included in a specified Signed STH","That STH has an external time anchor"],["L5","External anchor","The same STH/global root has an externally verifiable time boundary","The business content itself is true or lawful"]] },
        components: { title: "System components", cards: [["CLI / Desktop / SDK","Hash on the trusted client side, manage identity, sign claims, submit records, and export or verify proofs."],["TrustDB Server","Validate requests, issue receipts, batch records, maintain the Global Log, schedule external anchors, and expose HTTP, gRPC, and metrics."],["WAL + Proofstore","WAL protects accepted writes; file, Pebble, or TiKV proofstores keep queryable records and proof state. They are distinct durability boundaries."],["Offline Verifier","Reads only the original content, .sproof, and local trust roots, then recomputes hashes, signatures, Merkle paths, STH, and anchor bindings."]] },
        paths: { title: "What to read next", cards: [["I want to test the idea","Quick start","/docs/quick-start","Create and independently verify an L3 proof locally in ten minutes."],["I need to deploy","Server","/docs/server","Understand configuration, durability, storage, Global Log, anchoring, and operations."],["I need application integration","Go SDK","/docs/sdk","Go from signed submission to .sproof export and offline VerifySingleProof."],["I need to audit the format",".sproof v1","/sproof","Review fields, level ceilings, binding rules, and the complete verification algorithm."]] },
      },
    },
  },
};

const cloneEnglish = (locale, overrides) => ({
  home: {
    ...content.en.home,
    ...(overrides.home || {}),
    hero: { ...content.en.home.hero, ...(overrides.home?.hero || {}) },
    problem: { ...content.en.home.problem, ...(overrides.home?.problem || {}) },
    capabilities: { ...content.en.home.capabilities, ...(overrides.home?.capabilities || {}) },
    proof: { ...content.en.home.proof, ...(overrides.home?.proof || {}) },
    journey: { ...content.en.home.journey, ...(overrides.home?.journey || {}) },
    useCases: { ...content.en.home.useCases, ...(overrides.home?.useCases || {}) },
  },
  server: { ...content.en.server, ...overrides.server },
  sdk: { ...content.en.sdk, ...overrides.sdk },
  comparison: { ...content.en.comparison, ...overrides.comparison },
  concepts: {
    ...content.en.concepts,
    ...overrides.concepts,
    sections: { ...content.en.concepts.sections, ...(overrides.concepts?.sections || {}) },
  },
  locale,
});

content.ru = cloneEnglish("ru", {
  home: {
    hero: {
      eyebrow: "ПОДПИСАТЬ · ЗАПИСАТЬ · ПРОВЕРИТЬ",
      title: ["Передавайте доказательства.", "Проверяйте независимо."],
      copy: "TrustDB превращает подписанные дайджесты файлов, журналов и бизнес-событий в квитанции, доказательства Merkle, глобальный журнал прозрачности, необязательные якоря и единый переносимый файл .sproof.",
      primary: "Создать доказательство за 10 минут",
      secondary: "Посмотреть офлайн-проверку",
      points: ["Без загрузки исходных файлов", "Один файл .sproof", "Развёртывание у себя", "Go SDK · HTTP · gRPC"],
      index: "Исходник + .sproof + локально доверенные ключи: пересчитайте результат без TrustDB.",
    },
    problem: {
      eyebrow: "Зачем TrustDB",
      title: ["Обычные журналы", "требуют доверия.", "TrustDB позволяет", "проверить всё самому."],
      copy: [
        "Переданный файл можно подменить, журнал — переписать с правами администратора, а от бизнес-события нередко остаётся лишь снимок экрана. Когда возникает спор, результат запроса не является независимо проверяемым доказательством.",
        "TrustDB добавляет слой проверяемых доказательств рядом с уже работающими системами. Исходные данные остаются на месте, а их дайджесты, идентификаторы и история обработки упаковываются так, чтобы клиенты, аудиторы и партнёры могли проверить их самостоятельно.",
      ],
      artAlt: "Три сценария, в которых передача файлов, журналы аудита и бизнес-события превращаются в независимо проверяемые доказательства",
      captions: ["Проверяйте версию переданного файла", "Проверяйте журналы вне production-среды", "Проверяйте события между организациями"],
      answerTitle: "Один .sproof — готовый к передаче пакет доказательств.",
      answerBody: "В нём находятся подписи, квитанции, пути Merkle, подписанные вершины дерева и доступные материалы якоря. Проверяющий пересчитывает результат по исходнику и локально доверенным ключам — без входа в вашу систему.",
      cta: "Разобраться в модели доказательств TrustDB",
    },
    capabilities: {
      eyebrow: "Преимущество TrustDB",
      title: ["Вся цепочка доказательств", "в одном файле."],
      lead: "TrustDB не ограничивается статусом «записано». Система передаёт каждый проверяемый слой и заменяет доверие к ответу сервера вычислением, которое может повторить любой получатель.",
      cards: [
        ["01", "Исходные данные остаются у вас", "Клиент потоково хеширует и подписывает данные локально. Основной сервис принимает дайджест, выбранные метаданные и подпись, затем создаёт квитанции и доказательства, не требуя исходный файл."],
        ["02", "Полная цепочка доказательств", "Подпись идентичности, серверная квитанция, включение Merkle, глобальный журнал прозрачности и необязательная привязка к внешнему якорю создаются одной системой, слой за слоем."],
        ["03", "Проверка даже после отключения сервиса", "Детерминированный CBOR-файл .sproof содержит весь материал доказательства. Для проверки нужны только исходник, файл доказательства и собственные корни доверия проверяющего."],
      ],
      benchmarkEyebrow: "Проверенный тест / явная семантика",
      metrics: [["56 576", "L2 отправок/с"], ["2 237", "L4/с с полным индексом"], ["7 311 000", "отправок текущей версии"], ["0", "сбоев / ошибок batch"]],
      benchmarkCta: "Посмотреть среду, методику и полные результаты",
    },
    proof: {
      eyebrow: "Модель доказательств",
      title: ["Подпишите один раз.", "Получите полную", "цепочку доказательств."],
      lead: "L1–L5 — не статусы, объявленные сервером. Проверяющий заново вычисляет каждый слой по имеющимся материалам и останавливается на самом высоком уровне, который действительно прошёл проверку.",
      levels: [
        ["L1", "ПОДПИСЬ", "Локально связать дайджест содержимого с идентичностью клиента."],
        ["L2", "КВИТАНЦИЯ", "Проверить заявление и выдать подписанную серверную квитанцию."],
        ["L3", "MERKLE", "Включить запись в дерево пакета и предоставить доказательство включения."],
        ["L4", "ГЛОБАЛЬНЫЙ ЖУРНАЛ", "Покрыть корень пакета одной точно соответствующей подписанной вершиной дерева."],
        ["L5", "ЯКОРЬ", "Приложить результат якоря, точно соответствующий этой вершине дерева."],
      ],
    },
    journey: {
      eyebrow: "Как это работает",
      title: ["Три шага.", "Постройте доказательство.", "Передайте результат."],
      labels: [
        ["Подпишите локально", "Отправьте только дайджест, выбранные метаданные и подпись"],
        ["Постройте цепочку", "Квитанция → Merkle → подписанная вершина дерева → необязательный якорь"],
        ["Передайте для офлайн-проверки", "Исходник + .sproof + локальные корни доверия"],
      ],
      caption: "Полная офлайн-проверка не обращается к TrustDB, поставщику якоря или сети; уровень доказательства заново вычисляет сам проверяющий.",
      artAlt: "Абстрактное поле данных, где дайджесты файлов и журналов через подпись, журнал прозрачности и необязательную привязку превращаются в переносимое офлайн-доказательство",
    },
    useCases: {
      eyebrow: "Создано для передачи доказательств",
      title: ["Передайте доказательство.", "Дайте получателю", "проверить его самому."],
      lead: "Не отправляйте клиента обратно в вашу панель за статусом и не просите аудитора верить администратору журналов. Передайте исходник и .sproof — получатель сам воспроизведёт результат.",
      cards: [
        ["01 / ПЕРЕДАЧА ФАЙЛОВ", "Проверка переданных файлов", "После того как договор, отчёт, набор данных или модель покинули вашу систему, получатель может доказать, что перед ним та же версия, которая была подписана и принята."],
        ["02 / ЖУРНАЛЫ АУДИТА", "Экспорт доказательств аудита", "Превратите критичные записи журнала и цепочку их обработки в доказательство, которое аудитор проверит без доступа к production-хранилищу журналов."],
        ["03 / БИЗНЕС-СОБЫТИЯ", "Подтверждение событий между компаниями", "Свяжите заказы, расчёты, согласования или обмен данными с идентичностью отправителя и передайте партнёрам материалы, пригодные для долгосрочного хранения."],
      ],
    },
  },
  comparison: { title: "TrustDB завершает всю цепочку доказательств.", lead: "TrustDB объединяет подписи клиентов, серверные квитанции, доказательства Merkle, глобальный журнал прозрачности и внешнюю временную привязку в единую систему с переносимым файлом .sproof для полной офлайн-проверки.", columns: ["Система","Основная задача","Результат","Проверка","Когда выбирать"], note: "Преимущество TrustDB — сквозная доставка доказательств: исходные данные не попадают в журнал прозрачности, а проверяющему достаточно оригинала, .sproof и доверенных открытых ключей для независимого вычисления уровня L1–L5.", sourceLabel: "Сопоставлено с официальной документацией проектов (22.07.2026)", cta: "Посмотреть полную цепочку TrustDB" },
  concepts: { title: "Как устроена TrustDB", summary: "Сначала разберитесь в границах системы, уровнях L1–L5 и модели доверия.", cta: "Сначала понять систему", lead: "TrustDB — база проверяемых доказательств: система получает хеш и подпись, строит проверяемые материалы, а получатель пересчитывает результат без сервера.", updated: "Обновлено 22.07.2026 · текущая ветка main", sections: {
    plain: { ...content.en.concepts.sections.plain, title: "Объяснение в одном предложении", body: "TrustDB не заменяет хранилище исходных файлов. Она доказывает, кто подписал хеш, как запись прошла обработку и получила ли внешний временной рубеж.", exampleTitle: "Пример: invoice.pdf" },
    flow: { ...content.en.concepts.sections.flow, title: "Как запись становится доказательством" }, stored: { ...content.en.concepts.sections.stored, title: "Что хранится, а что нет" }, levels: { ...content.en.concepts.sections.levels, title: "Что означают L1–L5", intro: "Уровень вычисляется по реально проверяемым материалам, а не принимается со слов сервера." }, components: { ...content.en.concepts.sections.components, title: "Компоненты системы" }, paths: { ...content.en.concepts.sections.paths, title: "Что читать дальше" },
  } },
});
content.ja = cloneEnglish("ja", {
  home: {
    hero: {
      eyebrow: "署名 · 記録 · 検証",
      title: ["証拠を届ける。", "受け手が独立検証。"],
      copy: "TrustDB は、ファイル、ログ、業務イベントの署名済みダイジェストを、受領証、Merkle 証明、グローバル透明性ログ、任意のアンカー、そして一つの持ち運べる .sproof に変換します。",
      primary: "10分で最初の証拠を作成",
      secondary: "オフライン検証を見る",
      points: ["元ファイルのアップロード不要", "一つの .sproof ファイル", "セルフホスト", "Go SDK · HTTP · gRPC"],
      index: "原本 + .sproof + ローカルで信頼した鍵だけで、TrustDB なしに結果を再計算できます。",
    },
    problem: {
      eyebrow: "TrustDB が必要な理由",
      title: ["従来のログは", "信頼を求める。", "TrustDB なら", "相手が自分で検証できる。"],
      copy: [
        "受け渡したファイルは差し替えられ、管理者はログを書き換えられます。業務イベントに残るものが画面キャプチャだけということもあります。紛争が起きたとき、検索結果だけでは独立検証可能な証拠になりません。",
        "TrustDB は、現在運用しているシステムの隣に検証可能な証拠レイヤーを加えます。元データはそのままに、ダイジェスト、識別情報、処理履歴を、顧客・監査人・取引先が独立検証できる形にまとめます。",
      ],
      artAlt: "ファイル受け渡し、監査ログ、業務イベントを独立検証可能な証拠へ変える三つの場面",
      captions: ["受け渡したファイルの版を検証", "本番環境の外でログを検証", "組織をまたぐイベントを検証"],
      answerTitle: "一つの .sproof が、そのまま渡せる証拠パッケージです。",
      answerBody: "署名、受領証、Merkle パス、署名済みツリーヘッド、利用可能なアンカー資料を内包します。検証者は原本とローカルで信頼した鍵から結果を再計算でき、あなたのシステムへログインする必要はありません。",
      cta: "TrustDB の証拠モデルを理解する",
    },
    capabilities: {
      eyebrow: "TrustDB が選ばれる理由",
      title: ["証拠チェーン全体を", "一つのファイルに。"],
      lead: "TrustDB は「記録済み」という状態を返すだけではありません。検証できる各層を受け手へ渡し、サーバーの検索結果への信頼を、誰でも繰り返せる計算へ置き換えます。",
      cards: [
        ["01", "元データは自社システムに保持", "クライアントがローカルでストリーム処理し、ハッシュ化して署名します。中核サービスが受け取るのはダイジェスト、選択したメタデータ、署名だけで、受領証と証明はサービス側で生成します。元ファイルは要求しません。"],
        ["02", "証拠チェーンを最後まで構築", "本人性を示す署名、サーバー受領証、Merkle 包含証明、グローバル透明性ログ、任意のアンカーを、一つのシステムが層ごとに生成します。"],
        ["03", "サービス停止後も検証可能", "決定論的 CBOR 形式の .sproof が証明資料を保持します。検証で読むのは原本、証拠ファイル、検証者自身の信頼の起点だけです。"],
      ],
      benchmarkEyebrow: "検証済み性能試験 / 明示的なセマンティクス",
      metrics: [["56,576", "L2 送信/秒"], ["2,237", "フルインデックス L4/秒"], ["7,311,000", "現行版の送信"], ["0", "失敗 / batch error"]],
      benchmarkCta: "環境、測定方法、全結果を見る",
    },
    proof: {
      eyebrow: "証拠モデル",
      title: ["署名は一度。", "証拠チェーンは", "最後まで。"],
      lead: "L1–L5 はサーバーが自己申告するバッジではありません。検証者が実際に含まれる資料から各層を再計算し、検証に成功した最高レベルで判定します。",
      levels: [
        ["L1", "署名", "内容ダイジェストとクライアント識別情報をローカルで結び付けます。"],
        ["L2", "受領証", "申告を検証し、サーバー署名付き受領証を発行します。"],
        ["L3", "MERKLE", "記録をバッチツリーへ入れ、包含証明を付与します。"],
        ["L4", "グローバル", "バッチルートを、厳密に対応する一つの署名済みツリーヘッドでカバーします。"],
        ["L5", "アンカー", "そのツリーヘッドに厳密に一致するアンカー結果を保持します。"],
      ],
    },
    journey: {
      eyebrow: "仕組み",
      title: ["三つの手順。", "証明を構築し、", "証拠を届ける。"],
      labels: [
        ["ローカルで署名", "送信するのはダイジェスト、選択したメタデータ、署名だけ"],
        ["チェーンを構築", "受領証 → Merkle → 署名済みツリーヘッド → 任意のアンカー"],
        ["オフラインで受け渡し", "原本 + .sproof + ローカルの信頼の起点"],
      ],
      caption: "完全なオフライン検証では TrustDB、アンカー提供者、ネットワークのいずれにも接続せず、証拠レベルは検証者が再計算します。",
      artAlt: "ファイルやログのダイジェストが、署名、透明性ログ、任意のアンカーを経て持ち運べるオフライン証拠になる抽象的なデータ空間",
    },
    useCases: {
      eyebrow: "証拠の受け渡しのために設計",
      title: ["証拠を届ける。", "相手が独立して", "検証できる。"],
      lead: "状態を確認するために顧客を管理画面へ戻したり、監査人にログ管理者を信じてもらったりする必要はありません。原本と .sproof を渡せば、相手自身が結論を再現できます。",
      cards: [
        ["01 / ファイル受け渡し", "受け渡したファイルを検証", "契約書、報告書、データセット、モデルがシステムを離れた後も、受け手は署名・受理されたものと同じ版かを証明できます。"],
        ["02 / 監査ログ", "監査証拠を出力", "重要なログ項目とその処理チェーンを、本番ログ基盤へアクセスせずに監査人が検証できる証拠へ変換します。"],
        ["03 / 業務イベント", "企業間イベントを確認", "注文、決済、承認、データ交換を送信者の識別情報と結び付け、取引先が長期保管できる証明資料を渡します。"],
      ],
    },
  },
  comparison: { title: "TrustDB は証拠チェーン全体を完成させます。", lead: "TrustDB はクライアント署名、サーバー受領証、Merkle 証明、グローバル透明性ログ、外部時刻アンカーを一つの業務証拠システムに統合し、完全にオフライン検証できる .sproof を出力します。", columns: ["システム","主な役割","生成する証拠","検証方法","選ぶ場面"], note: "TrustDB の強みはエンドツーエンドの証拠受け渡しです。原文を透明性ログへ入れず、検証者は元データ、.sproof、信頼済み公開鍵だけで L1–L5 の最高有効レベルを独立再計算できます。", sourceLabel: "各プロジェクトの公式文書を確認（2026-07-22）", cta: "TrustDB の完全な証拠チェーンを見る" },
  concepts: { title: "TrustDB を理解する", summary: "システム境界、証拠ライフサイクル、L1–L5、信頼モデルを先に理解します。", cta: "まずシステムを理解する", lead: "TrustDB は検証可能な証拠データベースです。内容のダイジェストと署名を受け取り、監査可能な証明を構成し、検証者はサーバーなしで再計算できます。", updated: "更新 2026.07.22 · 現在の main ブランチ", sections: {
    plain: { ...content.en.concepts.sections.plain, title: "一文で説明すると", body: "元の業務ファイルを保存・表示する仕組みの代わりではなく、誰が内容ハッシュを署名し、どの処理段階を通り、外部時刻境界を得たかを証明します。", exampleTitle: "invoice.pdf の例" },
    flow: { ...content.en.concepts.sections.flow, title: "1件の記録が証拠になるまで" }, stored: { ...content.en.concepts.sections.stored, title: "保存するもの・しないもの" }, levels: { ...content.en.concepts.sections.levels, title: "L1–L5 の意味", intro: "レベルはサーバーの自己申告ではなく、実際の検証可能な材料から再計算されます。" }, components: { ...content.en.concepts.sections.components, title: "システム構成" }, paths: { ...content.en.concepts.sections.paths, title: "次に読むページ" },
  } },
});
content.fr = cloneEnglish("fr", {
  home: {
    hero: {
      eyebrow: "SIGNER · CONSIGNER · VÉRIFIER",
      title: ["Livrez la preuve.", "Vérifiez-la indépendamment."],
      copy: "TrustDB transforme les empreintes signées de fichiers, journaux et événements métier en reçus, preuves Merkle, journal global de transparence, ancrages facultatifs et un unique fichier .sproof portable.",
      primary: "Créer une preuve en 10 minutes",
      secondary: "Voir la vérification hors ligne",
      points: ["Aucun envoi du fichier source", "Un seul fichier .sproof", "Auto-hébergé", "Go SDK · HTTP · gRPC"],
      index: "Original + .sproof + clés approuvées localement : recalculez le résultat sans TrustDB.",
    },
    problem: {
      eyebrow: "Pourquoi TrustDB",
      title: ["Les journaux classiques", "exigent votre confiance.", "TrustDB permet", "à chacun de vérifier."],
      copy: [
        "Un fichier livré peut être remplacé, un administrateur peut réécrire les journaux, et un événement métier ne laisse souvent qu’une capture d’écran. En cas de litige, le résultat d’une requête n’est pas une preuve vérifiable de façon indépendante.",
        "TrustDB ajoute une couche de preuves vérifiables à côté des systèmes que vous exploitez déjà. Les données sources restent en place ; leurs empreintes, identités et historiques de traitement sont regroupés pour que clients, auditeurs et partenaires puissent les vérifier eux-mêmes.",
      ],
      artAlt: "Trois scénarios où livraison de fichiers, journaux d’audit et événements métier deviennent des preuves vérifiables indépendamment",
      captions: ["Vérifier la version d’un fichier livré", "Vérifier les journaux hors production", "Vérifier les événements entre organisations"],
      answerTitle: "Un .sproof est un dossier de preuve prêt à transmettre.",
      answerBody: "Il contient signatures, reçus, chemins Merkle, têtes d’arbre signées et éléments d’ancrage disponibles. Le vérificateur recalcule le résultat depuis l’original et des clés approuvées localement, sans se connecter à votre système.",
      cta: "Comprendre le modèle de preuve TrustDB",
    },
    capabilities: {
      eyebrow: "L’avantage TrustDB",
      title: ["Toute la chaîne de preuve", "dans un seul fichier."],
      lead: "TrustDB ne renvoie pas un simple statut « consigné ». Chaque couche vérifiable est livrée, afin de remplacer la confiance dans une requête serveur par un calcul que tout destinataire peut reproduire.",
      cards: [
        ["01", "Conservez les sources dans votre système", "Le client traite le contenu en flux, calcule son empreinte et le signe localement. Le service central reçoit l’empreinte, les métadonnées choisies et la signature, puis produit les reçus et les preuves, sans jamais exiger le fichier original."],
        ["02", "Complétez toute la chaîne de preuve", "Signature d’identité, reçu serveur, inclusion Merkle, journal global de transparence et ancrage facultatif sont produits, couche après couche, par un seul système."],
        ["03", "Vérifiez même après l’arrêt du service", "Un .sproof CBOR déterministe transporte les éléments de preuve. La vérification ne lit que l’original, le fichier de preuve et les propres racines de confiance du vérificateur."],
      ],
      benchmarkEyebrow: "Mesures vérifiées / sémantique explicite",
      metrics: [["56 576", "soumissions L2/s"], ["2 237", "L4/s avec index complet"], ["7 311 000", "soumissions de la version actuelle"], ["0", "échec / erreur batch"]],
      benchmarkCta: "Voir l’environnement, la méthode et tous les résultats",
    },
    proof: {
      eyebrow: "Modèle de preuve",
      title: ["Signez une fois.", "Construisez une preuve", "complète."],
      lead: "L1–L5 ne sont pas des badges déclarés par le serveur. Le vérificateur recalcule chaque couche depuis les éléments présents et s’arrête au niveau le plus élevé dont la validation réussit réellement.",
      levels: [
        ["L1", "SIGNATURE", "Associer localement l’empreinte du contenu à l’identité du client."],
        ["L2", "REÇU", "Valider la déclaration et émettre un reçu signé par le serveur."],
        ["L3", "MERKLE", "Inclure l’enregistrement dans l’arbre d’un lot avec une preuve d’inclusion."],
        ["L4", "GLOBAL", "Couvrir la racine du lot par une tête d’arbre signée qui lui correspond exactement."],
        ["L5", "ANCRAGE", "Joindre le résultat d’ancrage correspondant exactement à cette tête d’arbre."],
      ],
    },
    journey: {
      eyebrow: "Fonctionnement",
      title: ["Trois étapes.", "Construisez la preuve.", "Livrez le dossier."],
      labels: [
        ["Signer localement", "N’envoyer que l’empreinte, les métadonnées choisies et la signature"],
        ["Construire la chaîne", "Reçu → Merkle → tête d’arbre signée → ancrage facultatif"],
        ["Livrer hors ligne", "Original + .sproof + racines de confiance locales"],
      ],
      caption: "La vérification hors ligne complète ne contacte ni TrustDB, ni le fournisseur d’ancrage, ni le réseau ; le vérificateur recalcule lui-même le niveau de preuve.",
      artAlt: "Champ de données abstrait où les empreintes de fichiers et journaux deviennent des preuves hors ligne portables grâce à la signature, au journal de transparence et à l’ancrage facultatif",
    },
    useCases: {
      eyebrow: "Conçu pour livrer la preuve",
      title: ["Livrez la preuve.", "Permettez à chacun", "de la vérifier."],
      lead: "Ne renvoyez pas vos clients vers votre tableau de bord pour consulter un statut et ne demandez pas aux auditeurs de croire l’administrateur des journaux. Livrez l’original et le .sproof : ils obtiendront eux-mêmes le résultat.",
      cards: [
        ["01 / LIVRAISON DE FICHIERS", "Vérifier les fichiers livrés", "Une fois qu’un contrat, rapport, jeu de données ou modèle a quitté votre système, le destinataire peut prouver qu’il s’agit toujours de la version signée et acceptée."],
        ["02 / JOURNAUX D’AUDIT", "Exporter les preuves d’audit", "Transformez les entrées critiques et leur chaîne de traitement en preuves qu’un auditeur peut vérifier sans accès à l’infrastructure de journaux de production."],
        ["03 / ÉVÉNEMENTS MÉTIER", "Confirmer les événements interentreprises", "Associez commandes, règlements, validations ou échanges de données à l’identité de l’émetteur, puis livrez des éléments de preuve que les partenaires peuvent conserver durablement."],
      ],
    },
  },
  comparison: { title: "TrustDB complète toute la chaîne de preuve.", lead: "TrustDB réunit signatures clientes, reçus serveur, preuves Merkle, journal global de transparence et ancrage temporel externe dans un seul système métier, avec un .sproof portable et entièrement vérifiable hors ligne.", columns: ["Système","Rôle principal","Preuve produite","Vérification","À choisir quand"], note: "L’avantage de TrustDB est la livraison de preuve de bout en bout : le contenu original n’entre pas dans le journal et le vérificateur n’a besoin que de l’original, du .sproof et de clés publiques fiables pour recalculer le niveau L1–L5 valide.", sourceLabel: "Comparaison fondée sur les documentations officielles (22/07/2026)", cta: "Voir la chaîne complète de TrustDB" },
  concepts: { title: "Comprendre TrustDB", summary: "Commencez par les limites du système, le cycle de preuve, L1–L5 et le modèle de confiance.", cta: "Comprendre d’abord le système", lead: "TrustDB est une base de preuves vérifiables : elle reçoit empreintes et signatures, construit des preuves auditables, puis permet au destinataire de tout recalculer sans serveur.", updated: "Mis à jour le 22/07/2026 · branche main actuelle", sections: {
    plain: { ...content.en.concepts.sections.plain, title: "L’explication en une phrase", body: "TrustDB ne remplace pas le stockage des fichiers métier : elle prouve qui a signé une empreinte, son parcours de traitement et l’existence éventuelle d’une limite temporelle externe.", exampleTitle: "Exemple : invoice.pdf" },
    flow: { ...content.en.concepts.sections.flow, title: "Comment un enregistrement devient une preuve" }, stored: { ...content.en.concepts.sections.stored, title: "Ce qui est stocké — ou non" }, levels: { ...content.en.concepts.sections.levels, title: "Ce que signifient L1–L5", intro: "Le niveau est recalculé depuis les éléments réellement vérifiables ; ce n’est pas une étiquette déclarée par le serveur." }, components: { ...content.en.concepts.sections.components, title: "Composants du système" }, paths: { ...content.en.concepts.sections.paths, title: "Que lire ensuite" },
  } },
});
content.ko = cloneEnglish("ko", {
  home: {
    hero: {
      eyebrow: "서명 · 기록 · 검증",
      title: ["증거를 전달하세요.", "상대가 독립 검증합니다."],
      copy: "TrustDB는 파일, 로그, 업무 이벤트의 서명된 다이제스트를 영수증, Merkle 증명, 글로벌 투명성 로그, 선택적 앵커와 하나의 휴대형 .sproof로 전환합니다.",
      primary: "10분 안에 첫 증거 만들기",
      secondary: "오프라인 검증 보기",
      points: ["원본 파일 업로드 불필요", "단일 .sproof 파일", "자체 호스팅", "Go SDK · HTTP · gRPC"],
      index: "원본 + .sproof + 로컬 신뢰 키만으로 TrustDB 없이 결과를 다시 계산합니다.",
    },
    problem: {
      eyebrow: "TrustDB가 필요한 이유",
      title: ["기존 로그는", "믿음을 요구합니다.", "TrustDB는", "직접 검증하게 합니다."],
      copy: [
        "전달된 파일은 바뀔 수 있고 관리자는 로그를 다시 쓸 수 있으며, 업무 이벤트에 화면 캡처 한 장만 남기도 합니다. 분쟁이 생겼을 때 조회 결과만으로는 독립 검증 가능한 증거가 되지 못합니다.",
        "TrustDB는 이미 운영 중인 시스템 옆에 검증 가능한 증거 계층을 추가합니다. 원본 데이터는 그대로 두고 다이제스트, 신원, 처리 이력을 고객, 감사인, 파트너가 독립 검증할 수 있는 형태로 묶습니다.",
      ],
      artAlt: "파일 전달, 감사 로그, 업무 이벤트를 독립 검증 가능한 증거로 바꾸는 세 가지 시나리오",
      captions: ["전달된 파일 버전 검증", "운영 환경 밖에서 로그 검증", "조직 간 이벤트 검증"],
      answerTitle: ".sproof 하나가 바로 전달 가능한 증거 패키지입니다.",
      answerBody: "서명, 영수증, Merkle 경로, 서명된 트리 헤드와 사용 가능한 앵커 자료를 담습니다. 검증자는 원본과 로컬 신뢰 키로 결과를 다시 계산하므로 귀사의 시스템에 로그인할 필요가 없습니다.",
      cta: "TrustDB 증거 모델 이해하기",
    },
    capabilities: {
      eyebrow: "TrustDB의 강점",
      title: ["증거 사슬 전체를", "파일 하나에 담습니다."],
      lead: "TrustDB는 단순한 ‘기록 완료’ 상태를 돌려주는 데 그치지 않습니다. 검증 가능한 모든 계층을 전달해 서버 조회 결과에 대한 믿음을 누구나 반복할 수 있는 계산으로 바꿉니다.",
      cards: [
        ["01", "원본 데이터는 기존 시스템에 유지", "클라이언트가 로컬에서 스트리밍 방식으로 해시하고 서명합니다. 핵심 서비스는 다이제스트, 선택한 메타데이터와 서명을 받은 뒤 영수증과 증명을 생성하며, 원본 파일을 요구하지 않습니다."],
        ["02", "완전한 증거 사슬", "신원 서명, 서버 영수증, Merkle 포함 증명, 글로벌 투명성 로그, 선택적 앵커를 하나의 시스템이 계층별로 생성합니다."],
        ["03", "서비스가 중단돼도 검증 가능", "결정론적 CBOR 형식의 .sproof가 증명 자료를 모두 담습니다. 검증에는 원본, 증거 파일, 검증자가 직접 신뢰하는 루트만 필요합니다."],
      ],
      benchmarkEyebrow: "검증된 성능 측정 / 명시적 의미",
      metrics: [["56,576", "L2 제출/초"], ["2,237", "전체 인덱스 L4/초"], ["7,311,000", "현재 버전 제출"], ["0", "실패 / batch error"]],
      benchmarkCta: "환경, 측정 방법, 전체 결과 보기",
    },
    proof: {
      eyebrow: "증거 모델",
      title: ["한 번 서명하고,", "완전한 증거를", "구축합니다."],
      lead: "L1–L5는 서버가 자체 선언하는 배지가 아닙니다. 검증자가 실제 포함된 자료에서 각 계층을 다시 계산하고, 검증을 통과한 가장 높은 단계에서 멈춥니다.",
      levels: [
        ["L1", "서명", "콘텐츠 다이제스트와 클라이언트 신원을 로컬에서 결합합니다."],
        ["L2", "영수증", "클레임을 검증하고 서버가 서명한 영수증을 발급합니다."],
        ["L3", "MERKLE", "레코드를 배치 트리에 포함하고 포함 증명을 제공합니다."],
        ["L4", "글로벌", "배치 루트를 정확히 일치하는 하나의 서명된 트리 헤드로 포괄합니다."],
        ["L5", "앵커", "해당 트리 헤드와 정확히 일치하는 앵커 결과를 담습니다."],
      ],
    },
    journey: {
      eyebrow: "작동 방식",
      title: ["세 단계로,", "증명을 만들고", "증거를 전달합니다."],
      labels: [
        ["로컬에서 서명", "다이제스트, 선택한 메타데이터, 서명만 제출"],
        ["증거 사슬 구축", "영수증 → Merkle → 서명된 트리 헤드 → 선택적 앵커"],
        ["오프라인 전달", "원본 + .sproof + 로컬 신뢰 루트"],
      ],
      caption: "완전한 오프라인 검증은 TrustDB, 앵커 제공자, 네트워크 어디에도 접속하지 않으며 검증자가 증거 등급을 다시 계산합니다.",
      artAlt: "파일과 로그 다이제스트가 서명, 투명성 로그, 선택적 앵커를 거쳐 휴대 가능한 오프라인 증거가 되는 추상 데이터 공간",
    },
    useCases: {
      eyebrow: "증거 전달을 위해 설계",
      title: ["증거를 전달하고,", "누구나 독립적으로", "검증하게 하세요."],
      lead: "상태를 확인하라며 고객을 대시보드로 돌려보내거나 감사인에게 로그 관리자를 믿으라고 요구하지 마세요. 원본과 .sproof를 전달하면 상대가 직접 결과를 얻습니다.",
      cards: [
        ["01 / 파일 전달", "전달된 파일 검증", "계약서, 보고서, 데이터셋, 모델이 시스템을 떠난 뒤에도 수신자는 서명되고 접수된 것과 동일한 버전인지 증명할 수 있습니다."],
        ["02 / 감사 로그", "감사 증거 내보내기", "중요 로그 항목과 처리 사슬을 운영 로그 백엔드에 접근하지 않고도 감사인이 검증할 수 있는 증거로 전환합니다."],
        ["03 / 업무 이벤트", "기업 간 이벤트 확인", "주문, 정산, 승인, 데이터 교환을 제출자 신원과 결합하고 파트너가 장기간 보관할 수 있는 증명 자료를 전달합니다."],
      ],
    },
  },
  comparison: { title: "TrustDB는 증거 사슬 전체를 완성합니다.", lead: "TrustDB는 클라이언트 신원 서명, 서버 영수증, Merkle 증명, 글로벌 투명성 로그, 외부 시간 앵커를 하나의 업무 증거 시스템으로 통합하고 완전한 오프라인 검증이 가능한 휴대형 .sproof를 출력합니다.", columns: ["시스템","주요 역할","생성 증거","검증 방식","선택할 때"], note: "TrustDB의 강점은 종단 간 증거 전달입니다. 원문을 투명성 로그에 넣지 않고도 검증자는 원본, .sproof, 신뢰 공개키만으로 유효한 최고 L1–L5 등급을 독립적으로 다시 계산할 수 있습니다.", sourceLabel: "각 프로젝트의 공식 문서 기준(2026-07-22 확인)", cta: "TrustDB의 완전한 증거 사슬 보기" },
  concepts: { title: "TrustDB 이해하기", summary: "시스템 경계, 증거 수명주기, L1–L5, 신뢰 모델을 먼저 이해합니다.", cta: "먼저 시스템 이해하기", lead: "TrustDB는 검증 가능한 증거 데이터베이스입니다. 콘텐츠 요약과 서명을 받아 감사 가능한 증명을 구성하고, 검증자는 서버 없이 결과를 다시 계산합니다.", updated: "2026.07.22 업데이트 · 현재 main 브랜치", sections: {
    plain: { ...content.en.concepts.sections.plain, title: "한 문장으로 설명하면", body: "원본 업무 파일 저장소를 대체하지 않습니다. 누가 콘텐츠 해시에 서명했고 어떤 처리 단계를 거쳤으며 외부 시간 경계를 얻었는지를 증명합니다.", exampleTitle: "invoice.pdf 예시" },
    flow: { ...content.en.concepts.sections.flow, title: "한 건의 기록이 증거가 되는 과정" }, stored: { ...content.en.concepts.sections.stored, title: "저장하는 것과 저장하지 않는 것" }, levels: { ...content.en.concepts.sections.levels, title: "L1–L5의 의미", intro: "등급은 서버가 주장하는 값이 아니라 실제 검증 가능한 자료에서 다시 계산됩니다." }, components: { ...content.en.concepts.sections.components, title: "시스템 구성 요소" }, paths: { ...content.en.concepts.sections.paths, title: "다음에 읽을 문서" },
  } },
});

export function productExplanation(locale) {
  return content[locale] || content["zh-CN"];
}
