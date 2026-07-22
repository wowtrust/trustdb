export const comparisonSources = [
  { name: "immudb", href: "https://docs.immudb.io/master/" },
  { name: "Sigstore Rekor", href: "https://docs.sigstore.dev/logging/overview/" },
  { name: "OpenTimestamps", href: "https://opentimestamps.org/" },
];

const content = {
  "zh-CN": {
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
  comparison: { title: "TrustDB завершает всю цепочку доказательств.", lead: "TrustDB объединяет подписи клиентов, серверные квитанции, доказательства Merkle, глобальный журнал прозрачности и внешнюю временную привязку в единую систему с переносимым файлом .sproof для полной офлайн-проверки.", columns: ["Система","Основная задача","Результат","Проверка","Когда выбирать"], note: "Преимущество TrustDB — сквозная доставка доказательств: исходные данные не попадают в журнал прозрачности, а проверяющему достаточно оригинала, .sproof и доверенных открытых ключей для независимого вычисления уровня L1–L5.", sourceLabel: "Сопоставлено с официальной документацией проектов (22.07.2026)", cta: "Посмотреть полную цепочку TrustDB" },
  concepts: { title: "Как устроена TrustDB", summary: "Сначала разберитесь в границах системы, уровнях L1–L5 и модели доверия.", cta: "Сначала понять систему", lead: "TrustDB — база проверяемых доказательств: система получает хеш и подпись, строит проверяемые материалы, а получатель пересчитывает результат без сервера.", updated: "Обновлено 22.07.2026 · текущая ветка main", sections: {
    plain: { ...content.en.concepts.sections.plain, title: "Объяснение в одном предложении", body: "TrustDB не заменяет хранилище исходных файлов. Она доказывает, кто подписал хеш, как запись прошла обработку и получила ли внешний временной рубеж.", exampleTitle: "Пример: invoice.pdf" },
    flow: { ...content.en.concepts.sections.flow, title: "Как запись становится доказательством" }, stored: { ...content.en.concepts.sections.stored, title: "Что хранится, а что нет" }, levels: { ...content.en.concepts.sections.levels, title: "Что означают L1–L5", intro: "Уровень вычисляется по реально проверяемым материалам, а не принимается со слов сервера." }, components: { ...content.en.concepts.sections.components, title: "Компоненты системы" }, paths: { ...content.en.concepts.sections.paths, title: "Что читать дальше" },
  } },
});
content.ja = cloneEnglish("ja", {
  comparison: { title: "TrustDB は証拠チェーン全体を完成させます。", lead: "TrustDB はクライアント署名、サーバー受領証、Merkle 証明、グローバル透明性ログ、外部時刻アンカーを一つの業務証拠システムに統合し、完全にオフライン検証できる .sproof を出力します。", columns: ["システム","主な役割","生成する証拠","検証方法","選ぶ場面"], note: "TrustDB の強みはエンドツーエンドの証拠受け渡しです。原文を透明性ログへ入れず、検証者は元データ、.sproof、信頼済み公開鍵だけで L1–L5 の最高有効レベルを独立再計算できます。", sourceLabel: "各プロジェクトの公式文書を確認（2026-07-22）", cta: "TrustDB の完全な証拠チェーンを見る" },
  concepts: { title: "TrustDB を理解する", summary: "システム境界、証拠ライフサイクル、L1–L5、信頼モデルを先に理解します。", cta: "まずシステムを理解する", lead: "TrustDB は検証可能な証拠データベースです。内容のダイジェストと署名を受け取り、監査可能な証明を構成し、検証者はサーバーなしで再計算できます。", updated: "更新 2026.07.22 · 現在の main ブランチ", sections: {
    plain: { ...content.en.concepts.sections.plain, title: "一文で説明すると", body: "元の業務ファイルを保存・表示する仕組みの代わりではなく、誰が内容ハッシュを署名し、どの処理段階を通り、外部時刻境界を得たかを証明します。", exampleTitle: "invoice.pdf の例" },
    flow: { ...content.en.concepts.sections.flow, title: "1件の記録が証拠になるまで" }, stored: { ...content.en.concepts.sections.stored, title: "保存するもの・しないもの" }, levels: { ...content.en.concepts.sections.levels, title: "L1–L5 の意味", intro: "レベルはサーバーの自己申告ではなく、実際の検証可能な材料から再計算されます。" }, components: { ...content.en.concepts.sections.components, title: "システム構成" }, paths: { ...content.en.concepts.sections.paths, title: "次に読むページ" },
  } },
});
content.fr = cloneEnglish("fr", {
  comparison: { title: "TrustDB complète toute la chaîne de preuve.", lead: "TrustDB réunit signatures clientes, reçus serveur, preuves Merkle, journal global de transparence et ancrage temporel externe dans un seul système métier, avec un .sproof portable et entièrement vérifiable hors ligne.", columns: ["Système","Rôle principal","Preuve produite","Vérification","À choisir quand"], note: "L’avantage de TrustDB est la livraison de preuve de bout en bout : le contenu original n’entre pas dans le journal et le vérificateur n’a besoin que de l’original, du .sproof et de clés publiques fiables pour recalculer le niveau L1–L5 valide.", sourceLabel: "Comparaison fondée sur les documentations officielles (22/07/2026)", cta: "Voir la chaîne complète de TrustDB" },
  concepts: { title: "Comprendre TrustDB", summary: "Commencez par les limites du système, le cycle de preuve, L1–L5 et le modèle de confiance.", cta: "Comprendre d’abord le système", lead: "TrustDB est une base de preuves vérifiables : elle reçoit empreintes et signatures, construit des preuves auditables, puis permet au destinataire de tout recalculer sans serveur.", updated: "Mis à jour le 22/07/2026 · branche main actuelle", sections: {
    plain: { ...content.en.concepts.sections.plain, title: "L’explication en une phrase", body: "TrustDB ne remplace pas le stockage des fichiers métier : elle prouve qui a signé une empreinte, son parcours de traitement et l’existence éventuelle d’une limite temporelle externe.", exampleTitle: "Exemple : invoice.pdf" },
    flow: { ...content.en.concepts.sections.flow, title: "Comment un enregistrement devient une preuve" }, stored: { ...content.en.concepts.sections.stored, title: "Ce qui est stocké — ou non" }, levels: { ...content.en.concepts.sections.levels, title: "Ce que signifient L1–L5", intro: "Le niveau est recalculé depuis les éléments réellement vérifiables ; ce n’est pas une étiquette déclarée par le serveur." }, components: { ...content.en.concepts.sections.components, title: "Composants du système" }, paths: { ...content.en.concepts.sections.paths, title: "Que lire ensuite" },
  } },
});
content.ko = cloneEnglish("ko", {
  comparison: { title: "TrustDB는 증거 사슬 전체를 완성합니다.", lead: "TrustDB는 클라이언트 신원 서명, 서버 영수증, Merkle 증명, 글로벌 투명성 로그, 외부 시간 앵커를 하나의 업무 증거 시스템으로 통합하고 완전한 오프라인 검증이 가능한 휴대형 .sproof를 출력합니다.", columns: ["시스템","주요 역할","생성 증거","검증 방식","선택할 때"], note: "TrustDB의 강점은 종단 간 증거 전달입니다. 원문을 투명성 로그에 넣지 않고도 검증자는 원본, .sproof, 신뢰 공개키만으로 유효한 최고 L1–L5 등급을 독립적으로 다시 계산할 수 있습니다.", sourceLabel: "각 프로젝트의 공식 문서 기준(2026-07-22 확인)", cta: "TrustDB의 완전한 증거 사슬 보기" },
  concepts: { title: "TrustDB 이해하기", summary: "시스템 경계, 증거 수명주기, L1–L5, 신뢰 모델을 먼저 이해합니다.", cta: "먼저 시스템 이해하기", lead: "TrustDB는 검증 가능한 증거 데이터베이스입니다. 콘텐츠 요약과 서명을 받아 감사 가능한 증명을 구성하고, 검증자는 서버 없이 결과를 다시 계산합니다.", updated: "2026.07.22 업데이트 · 현재 main 브랜치", sections: {
    plain: { ...content.en.concepts.sections.plain, title: "한 문장으로 설명하면", body: "원본 업무 파일 저장소를 대체하지 않습니다. 누가 콘텐츠 해시에 서명했고 어떤 처리 단계를 거쳤으며 외부 시간 경계를 얻었는지를 증명합니다.", exampleTitle: "invoice.pdf 예시" },
    flow: { ...content.en.concepts.sections.flow, title: "한 건의 기록이 증거가 되는 과정" }, stored: { ...content.en.concepts.sections.stored, title: "저장하는 것과 저장하지 않는 것" }, levels: { ...content.en.concepts.sections.levels, title: "L1–L5의 의미", intro: "등급은 서버가 주장하는 값이 아니라 실제 검증 가능한 자료에서 다시 계산됩니다." }, components: { ...content.en.concepts.sections.components, title: "시스템 구성 요소" }, paths: { ...content.en.concepts.sections.paths, title: "다음에 읽을 문서" },
  } },
});

export function productExplanation(locale) {
  return content[locale] || content["zh-CN"];
}
