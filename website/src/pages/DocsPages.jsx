import { ArrowRight, Desktop, DownloadSimple, HardDrives, Package, Wrench } from "@phosphor-icons/react";
import { CodeBlock, InlineLink, PageHero } from "../components/SiteChrome";
import { binaryDownloads, checksumsAsset, desktopDownloads, release } from "../lib/release";
import { Link } from "../router";

const docs = [
  ["快速开始", "/docs/quick-start", "10 分钟完成本地签名、提交与验证。"],
  ["服务器", "/docs/server", "部署、配置、存储、HTTP / gRPC 与运维。"],
  ["CLI", "/docs/cli", "密钥、声明、验证、备份和诊断命令。"],
  ["Go SDK", "/docs/sdk", "在应用内签名、提交、导出与离线验证。"],
  ["桌面客户端", "/docs/desktop", "身份初始化、存证、记录管理与证明导出。"],
  ["安装桌面客户端", "/docs/desktop-install", "在 macOS 与 Windows 安装自签名测试版。"],
  ["从源码构建", "/docs/source-build", "构建服务器、CLI 和桌面客户端。"],
];

const endpointGroups = [
  ["写入", "POST", "/v1/claims", "提交单个确定性 CBOR SignedClaim"],
  ["批量写入", "POST", "/v1/claims/batch", "批量提交签名声明"],
  ["记录", "GET", "/v1/records", "分页、条件检索与游标续读"],
  ["证明", "GET", "/v1/proofs/{record_id}", "获取 L3 ProofBundle"],
  ["透明日志", "GET", "/v1/global-log/inclusion/{batch_id}", "获取 L4 包含证明"],
  ["外部锚定", "GET", "/v1/anchors/sth/{tree_size}", "获取 L5 锚定状态或结果"],
  ["可观测性", "GET", "/metrics", "Prometheus 指标"],
];

const cliGroups = [
  ["密钥与身份", "keygen · key-register · key-revoke · key-list"],
  ["证据工作流", "claim-file · commit · commit-batch · verify · proof inspect"],
  ["服务与诊断", "serve · doctor · config · version"],
  ["透明日志与锚定", "global-log · anchor"],
  ["存储与恢复", "backup · wal · metastore"],
  ["性能", "bench"],
];

function DocsNav({ route }) {
  return (
    <aside className="docs-nav">
      <Link href="/docs" className={route === "/docs" ? "active" : ""}>文档首页</Link>
      {docs.map(([label, href]) => <Link key={href} href={href} className={route === href ? "active" : ""}>{label}</Link>)}
      <span />
      <Link href="/sproof">.sproof v1</Link>
      <Link href="/performance">性能基线</Link>
    </aside>
  );
}

function DocsShell({ route, children }) {
  return <div className="docs-shell section-shell"><DocsNav route={route} /><article className="docs-article">{children}</article></div>;
}

function ArticleTitle({ index, title, lead, updated = "2026.07.20", version = `适用于 TrustDB ${release.version}` }) {
  return (
    <header className="docs-title">
      <p>Docs / {index}</p>
      <h1>{title}</h1>
      <span>{lead}</span>
      <small>更新于 {updated} · {version}</small>
    </header>
  );
}

function Note({ tone = "info", title, children }) {
  return <aside className={`doc-note doc-note--${tone}`}><strong>{title}</strong><p>{children}</p></aside>;
}

export function DocsIndexPage() {
  return (
    <>
      <PageHero eyebrow="Documentation" title={<>从签名到验证，<br />一步一步完成。</>} lead="可以部署服务器，也可以用 CLI、Go SDK 或桌面客户端接入。文档从最简单的本地验证开始，再逐步介绍生产配置。" meta="TrustDB 中文文档">
        <div className="page-hero__actions"><Link className="button button--solid" href="/docs/quick-start">快速开始 <ArrowRight /></Link><Link className="button button--ghost" href="/sproof">查看格式规范</Link></div>
      </PageHero>
      <section className="docs-persuasion">
        <div className="section-shell docs-persuasion__layout">
          <div data-reveal><p>Before you begin</p><h2>这些麻烦，<br />你多半遇到过。</h2></div>
          <div data-reveal>
            <p>文件交给客户以后，怎样证明对方拿到的就是原版？审计日志由自己保管，第三方凭什么相信？数据集或自动报告出了问题，还能不能找回当时的输入？归根结底，都是同一件事：<strong>事情虽然发生过，证据却仍由一方说了算。</strong></p>
            <p>以前通常要靠人工公证、接入区块链、自建防篡改日志，或者把原始数据交给第三方。费用高，接入慢，还可能泄露隐私。TrustDB 只记录内容哈希、签名和证明，用普通服务器、CLI、SDK 或桌面客户端就能开始。</p>
            <p>验证方拿到原文件和 <code>.sproof</code> 后，可以自己检查签名、Merkle 证明、透明日志和外部时间锚定。过去只有少数项目做得起的事，现在从一台服务器和几行代码就能起步。</p>
          </div>
        </div>
        <div className="section-shell docs-persuasion__fit">
          <article data-reveal><span>适合</span><p>需要跨组织交付、第三方审计、文件/日志防静默改写、数据与模型版本举证。</p></article>
          <article data-reveal><span>不替代</span><p>访问控制、内容加密、业务授权、法律意见；TrustDB 证明的是内容与处理链，不判断业务是否合法。</p></article>
        </div>
      </section>
      <section className="docs-index section-shell">
        <div className="docs-index__intro" data-reveal><p>Choose a guide</p><h2>安装、使用、开发，<br />各有一章。</h2></div>
        <div className="docs-index__grid">
          {docs.map(([title, href, description], index) => (
            <Link className="docs-index-card" href={href} key={href} data-reveal>
              <span>0{index + 1}</span><h3>{title}</h3><p>{description}</p><ArrowRight />
            </Link>
          ))}
        </div>
      </section>
      <section className="docs-principle">
        <div className="section-shell" data-reveal><p>Independent verification</p><h2>原文件留在手中。<br />验证不求人。</h2><span>TrustDB 保存内容哈希、签名和证明。交换 .sproof 后，第三方不访问原服务也能验证。</span></div>
      </section>
    </>
  );
}

export function QuickStartPage({ route }) {
  const macDownload = binaryDownloads.find((asset) => asset.platform === "macOS" && asset.arch.includes("arm64"));
  const windowsDownload = binaryDownloads.find((asset) => asset.platform === "Windows" && asset.arch.includes("x86-64"));
  return (
    <DocsShell route={route}>
      <ArticleTitle index="01" title="快速开始" lead="下载已经编译好的 TrustDB，完成本地签名、提交与验证。使用二进制文件不需要 Go 工具链。" />
      <section className="doc-section" data-reveal><h2>1. 下载 TrustDB</h2><p>先选择与你的系统和处理器相符的服务器 / CLI 压缩包。下面以 Apple Silicon Mac 为例；其他平台可以从下载页直接选择。</p><CodeBlock>curl -LO {macDownload.primary.url}{"\n"}tar -xzf {macDownload.primary.filename}{"\n"}cd trustdb-{release.version}-darwin-arm64{"\n"}./bin/trustdb version</CodeBlock><div className="doc-download-links"><a href={macDownload.primary.url}><DownloadSimple />Apple Silicon Mac</a><a href={windowsDownload.primary.url}><DownloadSimple />Windows x86-64</a><Link href="/downloads">选择其他系统 <ArrowRight /></Link></div><Note title="Windows 命令">解压 ZIP 后，在 PowerShell 中把下文的 <code>./bin/trustdb</code> 改为 <code>.\bin\trustdb.exe</code>。</Note></section>
      <section className="doc-section"><h2>2. 核对下载文件</h2><p>下载统一校验清单，确认二进制文件与本次 GitHub Release 一致。</p><CodeBlock>curl -LO {checksumsAsset.url}{"\n"}shasum -a 256 {macDownload.primary.filename}{"\n"}grep "{macDownload.primary.filename}" SHA256SUMS</CodeBlock><InlineLink href={checksumsAsset.url}>下载 SHA256SUMS</InlineLink></section>
      <section className="doc-section"><h2>3. 生成客户端与服务端密钥</h2><p>TrustDB 使用 Ed25519。私钥只留在签名方；验证路径使用公钥。</p><CodeBlock>./bin/trustdb keygen --out .trustdb-dev --prefix client{"\n"}./bin/trustdb keygen --out .trustdb-dev --prefix server</CodeBlock></section>
      <section className="doc-section"><h2>4. 创建签名声明</h2><p>CLI 在本地计算内容哈希并生成 <code>.tdclaim</code>，原文件不会在这一步上传。</p><CodeBlock>./bin/trustdb claim-file \{"\n"}  --file ./example.txt \{"\n"}  --private-key .trustdb-dev/client.key \{"\n"}  --tenant default --client local-client --key-id client-key \{"\n"}  --out .trustdb-dev/example.tdclaim</CodeBlock></section>
      <section className="doc-section"><h2>5. 本地提交到 Merkle 批次</h2><p>本地 <code>commit</code> 生成 L3 ProofBundle。服务端路径使用相同的证明语义。</p><CodeBlock>./bin/trustdb commit \{"\n"}  --claim .trustdb-dev/example.tdclaim \{"\n"}  --server-private-key .trustdb-dev/server.key \{"\n"}  --client-public-key .trustdb-dev/client.pub \{"\n"}  --out .trustdb-dev/example.tdproof</CodeBlock></section>
      <section className="doc-section"><h2>6. 独立验证</h2><p>验证器会重新计算文件哈希、签名与证明路径；不会信任文件中自报的证明等级。</p><CodeBlock>./bin/trustdb verify \{"\n"}  --file ./example.txt \{"\n"}  --proof .trustdb-dev/example.tdproof \{"\n"}  --server-public-key .trustdb-dev/server.pub \{"\n"}  --client-public-key .trustdb-dev/client.pub</CodeBlock><Note title="接下来">需要多人共享、异步批次、L4 全局日志或 L5 外部锚定时，继续阅读服务器文档；优先交换单文件 <code>.sproof</code>。</Note></section>
      <div className="doc-next"><span>下一篇</span><Link href="/docs/server">部署服务器 <ArrowRight /></Link></div>
    </DocsShell>
  );
}

export function ServerDocsPage({ route }) {
  return (
    <DocsShell route={route}>
      <ArticleTitle index="02" title="服务器" lead="从开发机单节点到 Pebble / TiKV、全局透明日志与 OpenTimestamps 锚定。" />
      <section className="doc-section"><h2>启动服务</h2><p>发布包中的 <code>trustdb</code> 同时提供 HTTP ingest；可选 gRPC、Prometheus 指标与挂载于 <code>/admin</code> 的管理端。</p><CodeBlock>./bin/trustdb serve \{"\n"}  --config ./config/production.yaml \{"\n"}  --server-private-key .trustdb-dev/server.key \{"\n"}  --client-public-key .trustdb-dev/client.pub \{"\n"}  --listen 127.0.0.1:8080</CodeBlock><CodeBlock label="health">curl http://127.0.0.1:8080/healthz</CodeBlock><InlineLink href="/downloads">下载服务器与 CLI</InlineLink></section>
      <section className="doc-section"><h2>运行剖面</h2><div className="definition-grid"><div><strong>development</strong><p>文件 proofstore + noop 锚定，仅用于本地开发与演示。</p></div><div><strong>production</strong><p>Pebble、目录 WAL、group fsync、全局日志和 OTS 锚定的单节点基线。</p></div><div><strong>production-safe</strong><p>面向持久化 L4/L5 的性能验证配置，不等于你的业务容量承诺。</p></div><div><strong>production-guaranteed</strong><p>严格 fsync、完整索引与最保守的可恢复边界。</p></div></div><Note tone="warn" title="配置边界">benchmark-extreme 与 on_demand proof 模式是吞吐实验，不属于生产安全配置。性能页会把它们与生产结果分开展示。</Note></section>
      <section className="doc-section"><h2>HTTP API</h2><div className="endpoint-table">{endpointGroups.map(([name, method, path, desc]) => <div key={path}><span>{name}</span><b>{method}</b><code>{path}</code><p>{desc}</p></div>)}</div><p>此外实现了 STH 列表与指定树头、批次树节点/叶子、全局日志一致性证明、锚定列表等只读接口。</p></section>
      <section className="doc-section"><h2>存储与耐久性</h2><ul><li><strong>file</strong>：最轻量，本地文件布局。</li><li><strong>Pebble</strong>：生产单节点推荐基线。</li><li><strong>TiKV</strong>：多个计算节点共享持久 proofstore，保留 node_id 与 log_id 来源身份。</li></ul><p>WAL 支持 strict、group 与 batch fsync；默认生产建议 group。证据进入哪个耐久边界，决定服务端何时可以返回 L2 收据。</p></section>
      <section className="doc-section"><h2>运维入口</h2><CodeBlock>./bin/trustdb doctor --config ./config/production.yaml{"\n"}./bin/trustdb config validate --config ./config/production.yaml{"\n"}./bin/trustdb backup create --metastore pebble --metastore-path ./proofs --out trustdb.tdbackup{"\n"}./bin/trustdb backup verify --file trustdb.tdbackup</CodeBlock><InlineLink href="https://github.com/ryan-wong-coder/trustdb/tree/main/configs">查看全部配置模板</InlineLink></section>
      <div className="doc-next"><span>下一篇</span><Link href="/docs/cli">CLI 命令参考 <ArrowRight /></Link></div>
    </DocsShell>
  );
}

export function CliDocsPage({ route }) {
  return (
    <DocsShell route={route}>
      <ArticleTitle index="03" title="CLI" lead="trustdb 是服务器、验证器和运维工具的统一入口。" />
      <section className="doc-section"><h2>命令地图</h2><div className="cli-map">{cliGroups.map(([title, commands]) => <div key={title}><strong>{title}</strong><code>{commands}</code></div>)}</div><CodeBlock>trustdb --help{"\n"}trustdb verify --help{"\n"}trustdb serve --help</CodeBlock><p>如果没有把 <code>bin</code> 加入 PATH，请使用发布目录中的 <code>./bin/trustdb</code>。</p><InlineLink href="/downloads">下载 CLI</InlineLink></section>
      <section className="doc-section"><h2>验证模式</h2><p><strong>本地模式</strong>从 <code>.sproof</code> 或分离的 L3/L4/L5 文件验证；<strong>服务器模式</strong>按 record_id 拉取证明。两者都要求服务端公钥，以及客户端公钥或受信任密钥注册表。</p><CodeBlock>trustdb verify --file ./invoice.pdf --sproof ./invoice.sproof \{"\n"}  --server-public-key ./server.pub --client-public-key ./client.pub{"\n\n"}trustdb verify --file ./invoice.pdf --server http://127.0.0.1:8080 \{"\n"}  --record tr1example --server-public-key ./server.pub \{"\n"}  --key-registry ./registry.jsonl --registry-public-key ./registry.pub</CodeBlock><Note title="L5 规则">本地 <code>--anchor</code> 必须同时提供 <code>--global-proof</code>；<code>--skip-anchor</code> 会主动忽略可用的 L5 外部锚点。</Note></section>
      <section className="doc-section"><h2>全局标志</h2><p>每个命令都可接收 <code>--config</code>、<code>--data-dir</code> 与结构化日志配置。异步日志的缓冲区与 drop 策略会影响可观测性，不改变证明语义。</p><div className="flag-list"><code>--config</code><span>YAML 配置路径</span><code>--log-format</code><span>json / console / text</span><code>--log-output</code><span>stderr / file / both</span><code>--log-level</code><span>debug / info / warn / error</span></div></section>
      <section className="doc-section"><h2>Shell 补全</h2><CodeBlock>trustdb completion zsh &gt; "${'{'}fpath[1]{'}'}"/_trustdb{"\n"}trustdb completion bash &gt; /usr/local/etc/bash_completion.d/trustdb</CodeBlock></section>
      <div className="doc-next"><span>下一篇</span><Link href="/docs/sdk">Go SDK <ArrowRight /></Link></div>
    </DocsShell>
  );
}

export function SdkDocsPage({ route }) {
  return (
    <DocsShell route={route}>
      <ArticleTitle index="04" title="Go SDK" lead="在应用代码里构建签名声明、提交、查询证明、导出 .sproof 并本地验证。" />
      <section className="doc-section"><h2>安装</h2><p>当前公开测试版使用 SemVer 预发布标签。评估与集成项目应固定这个版本，不要依赖浮动的 <code>@latest</code>。</p><CodeBlock>go get github.com/ryan-wong-coder/trustdb@v1.0.0-beta.1</CodeBlock><Note tone="warn" title="版本状态"><code>v1.0.0-beta.1</code> 仍是测试版，升级前请阅读 Release 说明并重新运行集成测试。</Note></section>
      <section className="doc-section"><h2>创建客户端</h2><CodeBlock label="go">client, err := sdk.NewClient("http://127.0.0.1:8080"){"\n"}if err != nil {'{'} log.Fatal(err) {'}'}{"\n"}defer client.Close(){"\n\n"}if err := client.Health(ctx); err != nil {'{'}{"\n"}    log.Fatal(err){"\n"}{'}'}</CodeBlock><p>默认 HTTP 超时为 15 秒；高并发可通过 <code>NewHTTPClientForConcurrency</code> 与 <code>WithHTTPClient</code> 调整连接池。</p></section>
      <section className="doc-section"><h2>签名并提交文件</h2><CodeBlock label="go">result, err := client.SubmitFile(ctx, file, sdk.Identity{'{'}{"\n"}    TenantID: "tenant", ClientID: "desktop-1", KeyID: "ed25519-1",{"\n"}    PrivateKey: privateKey,{"\n"}{'}'}, sdk.FileClaimOptions{'{'}{"\n"}    EventType: "file.snapshot",{"\n"}    IdempotencyKey: "business-event-42",{"\n"}{'}'}){"\n"}fmt.Println(result.RecordID, result.ProofLevel)</CodeBlock><p>也可用 <code>BuildSignedFileClaim</code>、<code>BuildSignedJSONLogClaim</code> 先构建，再通过 HTTP / gRPC transport 提交；批量与 bounded stream 接口用于受控并发。</p></section>
      <section className="doc-section"><h2>导出单文件证明</h2><CodeBlock label="go">proof, err := client.ExportSingleProof(ctx, recordID){"\n"}// 或直接写入确定性 CBOR .sproof 文件{"\n"}err = client.WriteSingleProofFile(ctx, recordID, "record.sproof")</CodeBlock><p>SDK 会依次尝试加入 L3 ProofBundle、L4 GlobalLogProof 与 L5 AnchorResult。不可用的高等级材料不会伪造，导出结果按实际可验证材料封顶。</p></section>
      <section className="doc-section"><h2>查询面</h2><div className="method-list"><code>ListRecords</code><span>分页、方向、batch / tenant / client / level / query / hash / 时间过滤</span><code>GetProofBundle</code><span>L3 证明</span><code>GetGlobalProof</code><span>L4 全局日志包含证明</span><code>ListSTHs / GetSTH</code><span>透明日志树头</span><code>ListAnchors / GetAnchor</code><span>外部锚定状态</span><code>MetricsRaw</code><span>Prometheus 原始文本</span></div><InlineLink href="https://pkg.go.dev/github.com/ryan-wong-coder/trustdb/sdk">打开 Go package 文档</InlineLink></section>
      <div className="doc-next"><span>下一篇</span><Link href="/docs/desktop">桌面客户端 <ArrowRight /></Link></div>
    </DocsShell>
  );
}

export function DesktopDocsPage({ route }) {
  return (
    <DocsShell route={route}>
      <ArticleTitle index="05" title="桌面客户端" lead="Wails + Vue 原生桌面应用：本地身份、文件存证、记录索引、证明导出与离线验证。" />
      <section className="doc-section"><h2>当前能力</h2><div className="capability-grid"><div><Wrench /><strong>身份初始化</strong><p>配置 server URL、tenant、client、key ID 与本地 Ed25519 私钥。</p></div><div><HardDrives /><strong>文件存证</strong><p>本地哈希与签名，提交后保留本地 Pebble 索引。</p></div><div><Package /><strong>证明管理</strong><p>刷新等级，主推 .sproof，亦可导出分离的 L3/L4/L5 材料。</p></div><div><Desktop /><strong>离线验证</strong><p>把原文件与证明拖入客户端，不依赖服务端重新判断有效性。</p></div></div></section>
      <section className="doc-section"><h2>下载与安装</h2><p>选择与处理器相符的安装包。公开测试版采用自签名证书，首次启动时系统会要求你确认。</p><div className="doc-download-links"><InlineLink href="/downloads">选择桌面客户端</InlineLink><InlineLink href="/docs/desktop-install">查看自签名安装步骤</InlineLink></div></section>
      <section className="doc-section"><h2>推荐工作流</h2><ol><li>首次启动建立本地身份并确认服务器健康。</li><li>选择文件，确认内容哈希与元数据后提交。</li><li>记录页等待 L3 / L4 / L5 材料按服务器处理进度升级。</li><li>导出 <code>.sproof</code> 与原文件一起交付验证方。</li><li>验证方导入原文件与证明，查看重新计算后的等级与锚定结果。</li></ol></section>
      <div className="doc-next"><span>下一篇</span><Link href="/docs/desktop-install">安装桌面客户端 <ArrowRight /></Link></div>
    </DocsShell>
  );
}

export function DesktopInstallPage({ route }) {
  const macArm = desktopDownloads[0];
  const macIntel = desktopDownloads[1];
  const windowsArm = desktopDownloads[2];
  const windowsX64 = desktopDownloads[3];
  return (
    <DocsShell route={route}>
      <ArticleTitle index="06" title="安装桌面客户端" lead="先核对下载文件，再按系统确认一次自签名应用。无需导入根证书，也不要关闭整机安全功能。" />
      <section className="doc-section"><h2>选择安装包</h2><div className="doc-download-grid">{[macArm, macIntel, windowsArm, windowsX64].map((asset) => <a href={asset.primary.url} key={asset.primary.filename}><span>{asset.platform}</span><strong>{asset.arch}</strong><small>{asset.format}</small><DownloadSimple /></a>)}</div><p>macOS 推荐 DMG；Windows 推荐 Setup EXE。ZIP 和 MSI 等备选文件可在下载页取得。</p><InlineLink href="/downloads">查看全部格式、证书和指纹</InlineLink></section>
      <section className="doc-section"><h2>先核对 SHA-256</h2><p>校验和用于确认下载文件与 GitHub Release 上的文件一致。macOS 可用 <code>shasum</code>，Windows 可用 PowerShell 自带的 <code>Get-FileHash</code>。</p><CodeBlock label="macOS">shasum -a 256 {macArm.primary.filename}{"\n"}grep "{macArm.primary.filename}" SHA256SUMS</CodeBlock><CodeBlock label="Windows PowerShell">Get-FileHash .\{windowsX64.primary.filename} -Algorithm SHA256{"\n"}Select-String "{windowsX64.primary.filename}" .\SHA256SUMS</CodeBlock><InlineLink href={checksumsAsset.url}>下载 SHA256SUMS</InlineLink></section>
      <section className="doc-section"><h2>macOS 安装</h2><ol><li>打开 DMG，把 <strong>trustdb</strong> 拖入“应用程序”。</li><li>先在“应用程序”中尝试打开一次。macOS 会提示无法验证开发者。</li><li>打开“系统设置”→“隐私与安全性”，在安全性区域找到刚才被拦截的 trustdb，点“仍要打开”。</li><li>再次确认“打开”，以后可像普通应用一样启动。</li></ol><Note tone="warn" title="只为这个应用放行">“仍要打开”只为当前应用保存例外。不要关闭 Gatekeeper，也不要执行来源不明的 <code>xattr</code> 或 <code>spctl</code> 命令。</Note><InlineLink href="https://support.apple.com/en-gb/102445">Apple 官方说明</InlineLink></section>
      <section className="doc-section"><h2>Windows 安装</h2><ol><li>运行与处理器相符的 <code>-setup.exe</code>。</li><li>若出现“Windows 已保护你的电脑”，先确认上一步的 SHA-256 完全一致，再点“更多信息”查看发布者与文件名。</li><li>确认文件无误后点“仍要运行”，按安装向导完成安装。</li><li>如果单位策略或 Smart App Control 直接阻止运行且没有放行按钮，请联系设备管理员；不要为安装 TrustDB 关闭整机防护。</li></ol><Note title="证书文件有什么用">下载页提供的 <code>.cer</code> 和证书指纹用于核对本次发布使用的签名证书，不需要把它导入“受信任的根证书颁发机构”。自签名证书也不代表 Apple 或 Microsoft 已验证发布者身份。</Note><InlineLink href="https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation">Microsoft SmartScreen 说明</InlineLink></section>
      <div className="doc-next"><span>下一篇</span><Link href="/docs/source-build">从源码构建 <ArrowRight /></Link></div>
    </DocsShell>
  );
}

export function SourceBuildPage({ route }) {
  return (
    <DocsShell route={route}>
      <ArticleTitle index="07" title="从源码构建" lead="服务器、CLI 与桌面客户端的构建环境和命令。" version="适用于 v1.0.0-beta.1 源码标签" />
      <section className="doc-section"><h2>服务器与 CLI</h2><p>需要 Git 与 Go 1.26.5 或更高的兼容版本。固定源码标签，先测试，再生成单个 <code>trustdb</code> 二进制文件。</p><CodeBlock>git clone --branch v1.0.0-beta.1 --depth 1 https://github.com/ryan-wong-coder/trustdb.git{"\n"}cd trustdb{"\n"}go test ./...{"\n"}go build -trimpath -o ./bin/trustdb ./cmd/trustdb{"\n"}./bin/trustdb version</CodeBlock></section>
      <section className="doc-section"><h2>桌面客户端</h2><p>桌面端还需要 Node.js 24、平台原生编译工具和 Wails 2.12.0。先安装当前系统的 Wails 依赖，再构建前端与原生壳。</p><CodeBlock>go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0{"\n"}cd clients/desktop/frontend{"\n"}npm ci{"\n"}npm run build{"\n"}cd ..{"\n"}wails doctor{"\n"}wails build</CodeBlock><InlineLink href="https://wails.io/docs/gettingstarted/installation/">Wails 平台依赖</InlineLink></section>
      <section className="doc-section"><h2>开发运行</h2><p>从 <code>clients/desktop</code> 运行 <code>wails dev</code> 才能使用签名、文件选择和本地数据库等原生能力。只启动 Vite 适合检查界面，不等同于完整客户端。</p><CodeBlock>cd clients/desktop{"\n"}go test ./...{"\n"}wails dev</CodeBlock><InlineLink href="/downloads">下载预编译版本</InlineLink></section>
      <div className="doc-next"><span>继续阅读</span><Link href="/sproof">.sproof v1 格式 <ArrowRight /></Link></div>
    </DocsShell>
  );
}

export function MissingDocsPage() {
  return <PageHero eyebrow="404 / Documentation" title={<>这篇文档<br />还不存在。</>} lead="返回文档中心，选择已经发布的指南。"><div className="page-hero__actions"><Link className="button button--solid" href="/docs">文档中心 <ArrowRight /></Link></div></PageHero>;
}
