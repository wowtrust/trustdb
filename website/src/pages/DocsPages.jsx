import { ArrowRight, Desktop, DownloadSimple, HardDrives, Package, Wrench } from "@phosphor-icons/react";
import { useEffect, useRef } from "react";
import { CodeBlock, InlineLink, PageHero } from "../components/SiteChrome";
import { useDocsOnboarding } from "../content/docsOnboarding";
import { binaryDownloads, checksumsAsset, desktopDownloads, release } from "../lib/release";
import { natsIngressContent } from "../content/natsIngress";
import { productExplanation } from "../content/productExplanation";
import { useLocale } from "../i18n";
import { Link } from "../router";
import sdkOnboardingSource from "../../../examples/sdk-onboarding/main.go?raw";

const cliGroups = [
  ["密钥与身份", "key generate · key import · key rotate · key revoke · key compromise · key list · key inspect"],
  ["证据工作流", "claim-file · commit · commit-batch · verify · proof inspect"],
  ["服务与诊断", "serve · doctor · config · version"],
  ["透明日志与锚定", "global-log · anchor"],
  ["存储与恢复", "backup · wal · metastore"],
  ["性能", "bench"],
];

function DocsNav({ route }) {
  const locale = useLocale();
  const { lang, nav } = useDocsOnboarding(locale);
  const navRef = useRef(null);

  useEffect(() => {
    if (!window.matchMedia("(max-width: 900px)").matches) return;
    navRef.current?.querySelector('[aria-current="page"]')?.scrollIntoView({ block: "nearest", inline: "center" });
  }, [route, locale]);

  return (
    <nav className="docs-nav" ref={navRef} aria-label={nav.groups.map(([label]) => label).join(", ")} lang={lang} data-i18n-ignore>
      {nav.groups.map(([group, items]) => (
        <section className="docs-nav__group" key={group}>
          <strong>{group}</strong>
          {items.map(([label, href]) => {
            const active = route === href;
            return <Link key={href} href={href} className={active ? "active" : ""} aria-current={active ? "page" : undefined}>{label}</Link>;
          })}
        </section>
      ))}
    </nav>
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

function GuideSummary({ copy, duration, outcome, prerequisites }) {
  return (
    <section className="guide-summary" data-reveal>
      <div><span>{copy.duration}</span><strong>{duration}</strong></div>
      <div><span>{copy.outcome}</span><strong>{outcome}</strong></div>
      <div className="guide-summary__prerequisites"><span>{copy.prerequisites}</span><ul>{prerequisites.map((item) => <li key={item}>{item}</li>)}</ul></div>
    </section>
  );
}

function GuideTitle({ index, title, lead, copy }) {
  return (
    <header className="docs-title">
      <p>{copy.docs} / {index}</p>
      <h1>{title}</h1>
      <span>{lead}</span>
      <small>{copy.updated} · {copy.version}</small>
    </header>
  );
}

function ExpectedResult({ label, children }) {
  return <aside className="expected-result"><span>{label}</span><p>{children}</p></aside>;
}

export function DocsIndexPage() {
  const locale = useLocale();
  const { index, lang } = useDocsOnboarding(locale);
  return (
    <div lang={lang} data-i18n-ignore>
      <PageHero eyebrow={index.eyebrow} title={<>{index.title[0]}<br />{index.title[1]}</>} lead={index.lead} meta={index.meta}>
        <div className="page-hero__actions"><Link className="button button--solid" href="/docs/quick-start">{index.primary} <ArrowRight /></Link><Link className="button button--ghost" href="/docs/concepts">{index.secondary}</Link></div>
      </PageHero>
      <section className="docs-index section-shell">
        <div className="docs-index__intro" data-reveal><p>{index.chooseEyebrow}</p><h2>{index.chooseTitle[0]}<br />{index.chooseTitle[1]}</h2><span>{index.chooseLead}</span></div>
        <div className="docs-path-grid">
          {index.paths.map(([eyebrow, title, description, href, deliverable]) => (
            <Link className="docs-path-card" href={href} key={href} data-reveal>
              <span>{eyebrow}</span><h3>{title}</h3><p>{description}</p><small>{deliverable}</small><ArrowRight />
            </Link>
          ))}
        </div>
      </section>
      <section className="docs-learning section-shell">
        <header data-reveal><p>{index.modelEyebrow}</p><h2>{index.modelTitle[0]}<br />{index.modelTitle[1]}</h2></header>
        <div>{index.modelSteps.map(([number, title, description]) => <article key={number} data-reveal><span>{number}</span><h3>{title}</h3><p>{description}</p></article>)}</div>
      </section>
      <section className="docs-principle">
        <div className="section-shell" data-reveal><p>Independent verification</p><h2>{index.boundaryTitle}</h2><span>{index.boundaryBody}</span></div>
      </section>
    </div>
  );
}

export function ConceptsDocsPage({ route }) {
  const locale = useLocale();
  const { concepts } = productExplanation(locale);
  const { plain, flow, stored, levels, components, paths } = concepts.sections;

  return (
    <DocsShell route={route}>
      <div data-i18n-ignore>
        <header className="docs-title">
          <p>Docs / 01</p>
          <h1>{concepts.title}</h1>
          <span>{concepts.lead}</span>
          <small>{concepts.updated}</small>
        </header>
        <section className="doc-section concept-opening">
          <h2>{plain.title}</h2>
          <p className="concept-opening__lead">{plain.body}</p>
          <aside className="concept-example"><span>EXAMPLE</span><strong>{plain.exampleTitle}</strong><p>{plain.example}</p></aside>
        </section>
        <section className="doc-section">
          <h2>{flow.title}</h2>
          <div className="concept-flow">
            {flow.steps.map(([index, title, description]) => <article key={index}><span>{index}</span><div><h3>{title}</h3><p>{description}</p></div></article>)}
          </div>
        </section>
        <section className="doc-section">
          <h2>{stored.title}</h2>
          <div className="definition-grid concept-boundaries">
            {stored.cards.map(([title, description]) => <div key={title}><strong>{title}</strong><p>{description}</p></div>)}
          </div>
        </section>
        <section className="doc-section">
          <h2>{levels.title}</h2>
          <p>{levels.intro}</p>
          <div className="concept-levels" role="table">
            <div className="concept-levels__head" role="row">{levels.headers.map((header) => <span role="columnheader" key={header}>{header}</span>)}</div>
            {levels.rows.map(([level, material, proves, limit]) => <div role="row" key={level}><strong role="cell">{level}</strong><span role="cell">{material}</span><p role="cell">{proves}</p><p role="cell">{limit}</p></div>)}
          </div>
        </section>
        <section className="doc-section">
          <h2>{components.title}</h2>
          <div className="definition-grid concept-components">
            {components.cards.map(([title, description]) => <div key={title}><strong>{title}</strong><p>{description}</p></div>)}
          </div>
        </section>
        <section className="doc-section">
          <h2>{paths.title}</h2>
          <div className="concept-paths">
            {paths.cards.map(([need, title, href, description]) => <Link href={href} key={href}><span>{need}</span><strong>{title}</strong><p>{description}</p><ArrowRight /></Link>)}
          </div>
        </section>
      </div>
    </DocsShell>
  );
}

export function QuickStartPage({ route }) {
  const locale = useLocale();
  const { lang, ui, quickStart } = useDocsOnboarding(locale);
  const macDownload = binaryDownloads.find((asset) => asset.platform === "macOS" && asset.arch.includes("arm64"));
  const linuxDownload = binaryDownloads.find((asset) => asset.platform === "Linux" && asset.arch === "amd64");
  const windowsDownload = binaryDownloads.find((asset) => asset.platform === "Windows" && asset.arch.includes("x86-64"));
  const releaseDirectory = `trustdb-${release.version}-darwin-arm64`;
  const linuxReleaseDirectory = `trustdb-${release.version}-linux-amd64`;
  const windowsReleaseDirectory = `trustdb-${release.version}-windows-amd64`;
  const windowsQuickStart = [
    "$ErrorActionPreference = \"Stop\"",
    "$PSNativeCommandUseErrorActionPreference = $false",
    "function Invoke-TrustDB {",
    "  & .\\bin\\trustdb.exe @args",
    "  if ($LASTEXITCODE -ne 0) { throw \"trustdb.exe failed with exit code $LASTEXITCODE\" }",
    "}",
    `$Archive = "${windowsDownload.primary.filename}"`,
    "New-Item -ItemType Directory -Path trustdb-quickstart | Out-Null",
    "Set-Location trustdb-quickstart",
    `Invoke-WebRequest -Uri "${windowsDownload.primary.url}" -OutFile $Archive`,
    `Invoke-WebRequest -Uri "${checksumsAsset.url}" -OutFile SHA256SUMS`,
    "$Expected = ((Select-String -Path .\\SHA256SUMS -Pattern ([regex]::Escape($Archive) + '$')).Line -split '\\s+')[0]",
    "$Actual = (Get-FileHash -Path .\\$Archive -Algorithm SHA256).Hash",
    "if ($Actual -ne $Expected) { throw \"SHA-256 mismatch for $Archive\" }",
    "Expand-Archive -Path .\\$Archive -DestinationPath .",
    `Set-Location ${windowsReleaseDirectory}`,
    "Invoke-TrustDB version",
    "Set-Content -Path .\\example.txt -Value 'hello TrustDB' -Encoding ascii",
    "New-Item -ItemType Directory -Path .trustdb-dev | Out-Null",
    "# Windows encrypted software envelopes fail closed pending owner-only DACL qualification.",
    "# This explicit plaintext mode is only for disposable quick-start data.",
    "Invoke-TrustDB key generate --out .trustdb-dev --prefix client --protection plaintext-dev-v1",
    "Invoke-TrustDB key generate --out .trustdb-dev --prefix server --protection plaintext-dev-v1",
    "Invoke-TrustDB claim-file `",
    "  --file .\\example.txt `",
    "  --private-key .trustdb-dev\\client.key `",
    "  --tenant default `",
    "  --client local-client `",
    "  --key-id client-key `",
    "  --out .trustdb-dev\\example.tdclaim",
    "Invoke-TrustDB commit `",
    "  --claim .trustdb-dev\\example.tdclaim `",
    "  --server-private-key .trustdb-dev\\server.key `",
    "  --client-public-key .trustdb-dev\\client.pub `",
    "  --wal .trustdb-dev\\local-wal `",
    "  --out .trustdb-dev\\example.tdproof",
    "Invoke-TrustDB proof inspect --proof .trustdb-dev\\example.tdproof",
    "Invoke-TrustDB verify `",
    "  --file .\\example.txt `",
    "  --proof .trustdb-dev\\example.tdproof `",
    "  --server-public-key .trustdb-dev\\server.pub `",
    "  --client-public-key .trustdb-dev\\client.pub",
    "Copy-Item .\\example.txt .\\tampered.txt",
    "Add-Content -Path .\\tampered.txt -Value 'changed' -Encoding ascii",
    ".\\bin\\trustdb.exe verify `",
    "  --file .\\tampered.txt `",
    "  --proof .trustdb-dev\\example.tdproof `",
    "  --server-public-key .trustdb-dev\\server.pub `",
    "  --client-public-key .trustdb-dev\\client.pub",
    "if ($LASTEXITCODE -eq 0) { throw 'tamper check unexpectedly succeeded' }",
  ].join("\n");
  return (
    <DocsShell route={route}>
      <div lang={lang} data-i18n-ignore>
        <GuideTitle index="02" title={quickStart.title} lead={quickStart.lead} copy={ui} />
        <GuideSummary copy={ui} duration={quickStart.duration} outcome={quickStart.outcome} prerequisites={quickStart.prerequisites} />
        <section className="doc-section" data-reveal>
          <h2>{quickStart.downloadTitle}</h2><p>{quickStart.downloadBody}</p>
          <CodeBlock>{`mkdir trustdb-quickstart && cd trustdb-quickstart\ncurl -fLO ${macDownload.primary.url}\ncurl -fLO ${checksumsAsset.url}\ngrep '${macDownload.primary.filename}$' SHA256SUMS | shasum -a 256 -c -`}</CodeBlock>
          <ExpectedResult label={ui.expected}>{quickStart.downloadExpected}</ExpectedResult>
          <div className="doc-download-links"><a href={macDownload.primary.url}><DownloadSimple />Apple Silicon Mac</a><a href={windowsDownload.primary.url}><DownloadSimple />Windows x86-64</a><Link href="/downloads">{quickStart.allPlatforms} <ArrowRight /></Link></div>
          <Note title={quickStart.platformNoteTitle}>{quickStart.platformNoteBody}</Note>
          <details className="doc-source"><summary>{quickStart.linuxPathLabel}</summary><CodeBlock reveal={false}>{`mkdir trustdb-quickstart && cd trustdb-quickstart\ncurl -fLO ${linuxDownload.primary.url}\ncurl -fLO ${checksumsAsset.url}\ngrep '${linuxDownload.primary.filename}$' SHA256SUMS | sha256sum -c -\ntar -xzf ${linuxDownload.primary.filename}\ncd ${linuxReleaseDirectory}\n./bin/trustdb version\nprintf 'hello TrustDB\\n' > example.txt\nmkdir -p .trustdb-dev`}</CodeBlock></details>
          <details className="doc-source"><summary>{quickStart.windowsPathLabel}</summary><CodeBlock label="PowerShell" reveal={false}>{windowsQuickStart}</CodeBlock></details>
        </section>
        <section className="doc-section">
          <h2>{quickStart.extractTitle}</h2><p>{quickStart.extractBody}</p>
          <CodeBlock>{`tar -xzf ${macDownload.primary.filename}\ncd ${releaseDirectory}\n./bin/trustdb version\nprintf 'hello TrustDB\\n' > example.txt\nmkdir -p .trustdb-dev`}</CodeBlock>
          <ExpectedResult label={ui.expected}>{quickStart.extractExpected}</ExpectedResult>
        </section>
        <section className="doc-section">
          <h2>{quickStart.keysTitle}</h2><p>{quickStart.keysBody}</p>
          <CodeBlock>{`read -r -s -p 'Development key passphrase: ' TRUSTDB_DEV_KEY_PASSPHRASE\nexport TRUSTDB_DEV_KEY_PASSPHRASE\nprintf '\\n'\n./bin/trustdb key generate --out .trustdb-dev --prefix client\n./bin/trustdb key generate --out .trustdb-dev --prefix server\nls -l .trustdb-dev`}</CodeBlock>
          <Note tone="warn" title={ui.checkpoint}>{quickStart.keysWarning}</Note>
          <ExpectedResult label={ui.expected}>{quickStart.keysExpected}</ExpectedResult>
        </section>
        <section className="doc-section">
          <h2>{quickStart.claimTitle}</h2><p>{quickStart.claimBody}</p>
          <CodeBlock>{`./bin/trustdb claim-file \\\n  --file ./example.txt \\\n  --private-key .trustdb-dev/client.key \\\n  --tenant default \\\n  --client local-client \\\n  --key-id client-key \\\n  --out .trustdb-dev/example.tdclaim`}</CodeBlock>
          <ExpectedResult label={ui.expected}>{quickStart.claimExpected}</ExpectedResult>
        </section>
        <section className="doc-section">
          <h2>{quickStart.commitTitle}</h2><p>{quickStart.commitBody}</p>
          <CodeBlock>{`./bin/trustdb commit \\\n  --claim .trustdb-dev/example.tdclaim \\\n  --server-private-key .trustdb-dev/server.key \\\n  --client-public-key .trustdb-dev/client.pub \\\n  --wal .trustdb-dev/local-wal \\\n  --out .trustdb-dev/example.tdproof\n\n./bin/trustdb proof inspect \\\n  --proof .trustdb-dev/example.tdproof`}</CodeBlock>
          <ExpectedResult label={ui.expected}>{quickStart.commitExpected}</ExpectedResult>
        </section>
        <section className="doc-section">
          <h2>{quickStart.verifyTitle}</h2><p>{quickStart.verifyBody}</p>
          <CodeBlock>{`./bin/trustdb verify \\\n  --file ./example.txt \\\n  --proof .trustdb-dev/example.tdproof \\\n  --server-public-key .trustdb-dev/server.pub \\\n  --client-public-key .trustdb-dev/client.pub`}</CodeBlock>
          <ExpectedResult label={ui.expected}>{quickStart.verifyExpected}</ExpectedResult>
        </section>
        <section className="doc-section">
          <h2>{quickStart.tamperTitle}</h2><p>{quickStart.tamperBody}</p>
          <CodeBlock>{`cp example.txt tampered.txt\nprintf 'changed\\n' >> tampered.txt\n./bin/trustdb verify \\\n  --file ./tampered.txt \\\n  --proof .trustdb-dev/example.tdproof \\\n  --server-public-key .trustdb-dev/server.pub \\\n  --client-public-key .trustdb-dev/client.pub`}</CodeBlock>
          <ExpectedResult label={ui.expected}>{quickStart.tamperExpected}</ExpectedResult>
        </section>
        <section className="doc-completion" data-reveal><span>{ui.next}</span><h2>{quickStart.nextTitle}</h2><p>{quickStart.nextBody}</p><Link className="button button--solid" href="/docs/sdk">Go SDK <ArrowRight /></Link></section>
      </div>
    </DocsShell>
  );
}

export function ServerDocsPage({ route }) {
  const locale = useLocale();
  const { lang, ui, server, troubleshooting } = useDocsOnboarding(locale);
  const natsCopy = natsIngressContent(locale);
  const dockerImage = `${release.containerImage}:${release.version}`;
  return (
    <DocsShell route={route}>
      <div lang={lang} data-i18n-ignore>
        <GuideTitle index="05" title={server.title} lead={server.lead} copy={ui} />
        <GuideSummary copy={ui} duration={server.duration} outcome={server.outcome} prerequisites={server.prerequisites} />
        <section className="doc-section">
          <h2>{server.localTitle}</h2><p>{server.localBody}</p>
          <CodeBlock>{`./bin/trustdb serve \\\n  --server-private-key .trustdb-dev/server.key \\\n  --client-public-key .trustdb-dev/client.pub \\\n  --wal .trustdb-dev/server/wal \\\n  --metastore pebble \\\n  --metastore-path .trustdb-dev/server/pebble \\\n  --proof-dir .trustdb-dev/server/proofs \\\n  --listen 127.0.0.1:8080`}</CodeBlock>
          <CodeBlock label="health / read-only diagnostics">{`curl --fail --silent http://127.0.0.1:8080/healthz\ncurl --fail --silent 'http://127.0.0.1:8080/v1/records?limit=10&direction=desc'\ncurl --fail --silent http://127.0.0.1:8080/metrics`}</CodeBlock>
          <ExpectedResult label={ui.expected}>{server.localExpected}</ExpectedResult>
        </section>
        <section className="doc-section">
          <h2>{server.dockerTitle}</h2><p>{server.dockerBody}</p>
          <CodeBlock>{`read -r -s -p 'Development key passphrase: ' TRUSTDB_DEV_KEY_PASSPHRASE\nexport TRUSTDB_DEV_KEY_PASSPHRASE\nprintf '\\n'\ndocker run -d \\\n  --name trustdb \\\n  -e TRUSTDB_DEV_KEY_PASSPHRASE \\\n  -p 127.0.0.1:8080:8080 \\\n  -v trustdb-data:/var/lib/trustdb \\\n  ${dockerImage}\nunset TRUSTDB_DEV_KEY_PASSPHRASE\n\ndocker logs trustdb\ncurl --fail http://127.0.0.1:8080/healthz`}</CodeBlock>
          <ExpectedResult label={ui.expected}>{server.dockerExpected}</ExpectedResult>
          <Note tone="warn" title={ui.checkpoint}>{server.dockerBoundary}</Note>
          <InlineLink href={release.containerUrl}>GitHub Container Registry</InlineLink>
          <InlineLink href={release.dockerHubUrl}>Docker Hub</InlineLink>
        </section>
        <section className="doc-section">
          <h2>{server.templateTitle}</h2><p>{server.templateBody}</p>
          <CodeBlock>{`./bin/trustdb config validate --config ./config/production.yaml\n./bin/trustdb doctor --config ./config/production.yaml`}</CodeBlock>
          <InlineLink href="https://github.com/wowtrust/trustdb/tree/main/configs">{server.templatesLabel}</InlineLink>
        </section>
        <section className="doc-section">
          <h2>{server.profilesTitle}</h2>
          <div className="definition-grid">{server.profiles.map(([title, description]) => <div key={title}><strong>{title}</strong><p>{description}</p></div>)}</div>
          <Note tone="warn" title={server.anchorTitle}>{server.anchorBody}</Note>
        </section>
        <section className="doc-section"><h2>{server.securityTitle}</h2><p>{server.securityBody}</p><InlineLink href="/docs/nats-ingress">{natsCopy.serverLinkLabel}</InlineLink></section>
        <section className="doc-section">
          <h2>{server.backupTitle}</h2><p>{server.backupBody}</p>
          <CodeBlock>{`# Stop the service cleanly before opening the Pebble path.\n./bin/trustdb backup create \\\n  --metastore pebble \\\n  --metastore-path .trustdb-dev/server/pebble \\\n  --out .trustdb-dev/trustdb.tdbackup\n\n./bin/trustdb backup verify \\\n  --file .trustdb-dev/trustdb.tdbackup\n\n./bin/trustdb backup restore \\\n  --file .trustdb-dev/trustdb.tdbackup \\\n  --metastore pebble \\\n  --metastore-path .trustdb-dev/restore/pebble`}</CodeBlock>
          <Note tone="warn" title={ui.checkpoint}>{server.backupBoundary}</Note>
        </section>
        <section className="doc-section">
          <h2>{server.checklistTitle}</h2><ul className="doc-checklist">{server.checklist.map((item) => <li key={item}>{item}</li>)}</ul>
        </section>
        <section className="doc-section"><h2>{server.apiTitle}</h2><p>{server.apiBody}</p><CodeBlock label="read endpoints">{`GET  /healthz\nGET  /v1/records\nGET  /v1/proofs/{record_id}\nGET  /v1/global-log/evidence/{batch_id}\nGET  /v1/anchors/sth/{tree_size}\nGET  /metrics`}</CodeBlock></section>
        <div className="doc-next"><span>{ui.next}</span><Link href="/docs/troubleshooting">{troubleshooting.title} <ArrowRight /></Link></div>
      </div>
    </DocsShell>
  );
}

export function CliDocsPage({ route }) {
  return (
    <DocsShell route={route}>
      <ArticleTitle index="07" title="CLI" lead="trustdb 是服务器、验证器和运维工具的统一入口。" />
      <section className="doc-section"><h2>命令地图</h2><div className="cli-map">{cliGroups.map(([title, commands]) => <div key={title}><strong>{title}</strong><code>{commands}</code></div>)}</div><CodeBlock>trustdb --help{"\n"}trustdb verify --help{"\n"}trustdb serve --help</CodeBlock><p>如果没有把 <code>bin</code> 加入 PATH，请使用发布目录中的 <code>./bin/trustdb</code>。</p><InlineLink href="/downloads">下载 CLI</InlineLink></section>
      <section className="doc-section"><h2>验证模式</h2><p><strong>本地模式</strong>从 <code>.sproof</code> 或分离的 L3/L4/L5 文件验证；<strong>服务器模式</strong>按 record_id 拉取证明。两者都要求服务端公钥，以及客户端公钥或受信任密钥注册表。</p><CodeBlock>trustdb verify --file ./invoice.pdf --sproof ./invoice.sproof \{"\n"}  --server-public-key ./server.pub --client-public-key ./client.pub{"\n\n"}trustdb verify --file ./invoice.pdf --server http://127.0.0.1:8080 \{"\n"}  --record tr1example --server-public-key ./server.pub \{"\n"}  --key-registry ./clients.tdkeys --registry-public-key ./registry.pub</CodeBlock><Note title="L5 规则">本地 <code>--anchor</code> 必须同时提供 <code>--global-proof</code>；<code>--skip-anchor</code> 会主动忽略可用的 L5 anchor result。</Note></section>
      <section className="doc-section"><h2>全局标志</h2><p>每个命令都可接收 <code>--config</code>、<code>--data-dir</code> 与结构化日志配置。异步日志的缓冲区与 drop 策略会影响可观测性，不改变证明语义。</p><div className="flag-list"><code>--config</code><span>YAML 配置路径</span><code>--log-format</code><span>json / console / text</span><code>--log-output</code><span>stderr / file / both</span><code>--log-level</code><span>debug / info / warn / error</span></div></section>
      <section className="doc-section"><h2>Shell 补全</h2><CodeBlock>trustdb completion zsh &gt; "${'{'}fpath[1]{'}'}"/_trustdb{"\n"}trustdb completion bash &gt; /usr/local/etc/bash_completion.d/trustdb</CodeBlock></section>
      <div className="doc-next"><span>下一篇</span><Link href="/docs/desktop">桌面客户端 <ArrowRight /></Link></div>
    </DocsShell>
  );
}

export function SdkDocsPage({ route }) {
  const locale = useLocale();
  const { lang, ui, sdk, offline } = useDocsOnboarding(locale);
  const natsCopy = natsIngressContent(locale);
  return (
    <DocsShell route={route}>
      <div lang={lang} data-i18n-ignore>
        <GuideTitle index="03" title={sdk.title} lead={sdk.lead} copy={ui} />
        <GuideSummary copy={ui} duration={sdk.duration} outcome={sdk.outcome} prerequisites={sdk.prerequisites} />
        <section className="doc-section">
          <h2>{sdk.serverTitle}</h2><p>{sdk.serverBody}</p>
          <CodeBlock>{`./bin/trustdb serve \\\n  --server-private-key .trustdb-dev/server.key \\\n  --client-public-key .trustdb-dev/client.pub \\\n  --wal .trustdb-dev/server/wal \\\n  --metastore pebble \\\n  --metastore-path .trustdb-dev/server/pebble \\\n  --proof-dir .trustdb-dev/server/proofs \\\n  --batch-max-delay 100ms \\\n  --listen 127.0.0.1:8080`}</CodeBlock>
          <CodeBlock label="terminal 2">curl --fail --silent http://127.0.0.1:8080/healthz</CodeBlock>
          <ExpectedResult label={ui.expected}>{sdk.serverExpected}</ExpectedResult>
        </section>
        <section className="doc-section">
          <h2>{sdk.projectTitle}</h2><p>{sdk.projectBody}</p>
          <CodeBlock>{`mkdir -p .trustdb-dev/sdk-demo\ncd .trustdb-dev/sdk-demo\ngo mod init example.com/trustdb-sdk-demo\ngo get github.com/wowtrust/trustdb@v${release.version}`}</CodeBlock>
          <ExpectedResult label={ui.expected}>{sdk.projectExpected}</ExpectedResult>
        </section>
        <section className="doc-section">
          <h2>{sdk.codeTitle}</h2><p>{sdk.codeBody}</p>
          <details className="doc-source"><summary>main.go · {sdkOnboardingSource.split("\n").length} LOC</summary><CodeBlock label="go" reveal={false}>{sdkOnboardingSource}</CodeBlock></details>
          <CodeBlock>{`go run . \\\n  --server http://127.0.0.1:8080 \\\n  --file ../../example.txt \\\n  --client-private-key ../client.key \\\n  --client-public-key ../client.pub \\\n  --server-public-key ../server.pub \\\n  --output ./record.sproof`}</CodeBlock>
          <ExpectedResult label={ui.expected}>{sdk.codeExpected}</ExpectedResult>
          <InlineLink href="https://github.com/wowtrust/trustdb/tree/main/examples/sdk-onboarding">{sdk.sourceLabel}</InlineLink>
        </section>
        <section className="doc-section"><h2>{sdk.asyncTitle}</h2><p>{sdk.asyncBody}</p><Note title={ui.checkpoint}>{sdk.idempotencyTitle}: {sdk.idempotencyBody}</Note><InlineLink href="/docs/nats-ingress">{natsCopy.sdkLinkLabel}</InlineLink></section>
        <section className="doc-section">
          <h2>{sdk.offlineTitle}</h2><p>{sdk.offlineBody}</p>
          <CodeBlock>{`../../bin/trustdb verify \\\n  --file ../../example.txt \\\n  --sproof ./record.sproof \\\n  --server-public-key ../server.pub \\\n  --client-public-key ../client.pub`}</CodeBlock>
          <ExpectedResult label={ui.expected}>{sdk.offlineExpected}</ExpectedResult>
        </section>
        <div className="doc-next"><span>{ui.next}</span><Link href="/docs/offline-verification">{offline.title} <ArrowRight /></Link></div>
      </div>
    </DocsShell>
  );
}

export function NATSIngressDocsPage({ route }) {
  const locale = useLocale();
  const { ui } = useDocsOnboarding(locale);
  const natsCopy = natsIngressContent(locale);
  const guideCopy = { ...ui, updated: natsCopy.updated, version: natsCopy.version };
  const brokerCommand = [
    "docker volume create trustdb-nats-data",
    "docker run --rm --name trustdb-nats \\",
    "  -p 127.0.0.1:4222:4222 \\",
    "  -v trustdb-nats-data:/data \\",
    "  nats:2 -js -sd /data",
  ].join("\n");
  const configBlock = [
    "nats:",
    "  enabled: true",
    "  urls: [\"nats://127.0.0.1:4222\"]",
    "  provision: true",
  ].join("\n");
  const serverCommand = [
    "go build -o ./bin/trustdb ./cmd/trustdb",
    "./bin/trustdb --config ./trustdb.yaml config validate",
    "./bin/trustdb --config ./trustdb.yaml serve",
  ].join("\n");
  const sdkExample = [
    "cfg := sdk.DefaultNATSIngressConfig()",
    "cfg.URLs = []string{\"tls://nats.internal.example:4222\"}",
    "cfg.ConnectionOptions = []nats.Option{",
    "    nats.UserCredentials(\"/run/secrets/trustdb-nats.creds\"),",
    "    nats.RootCAs(\"/etc/trust/nats-ca.pem\"),",
    "}",
    "",
    "client, err := sdk.NewNATSIngressClient(ctx, cfg)",
    "if err != nil { return err }",
    "defer client.Close()",
    "",
    "submission, err := client.PublishSignedClaim(ctx, signed)",
    "if err != nil { return err }",
    "// Persist submission.MessageID and submission.SignedClaim together.",
    "result, err := client.WaitResult(ctx, submission)",
  ].join("\n");

  return (
    <DocsShell route={route}>
      <div lang={natsCopy.lang} data-i18n-ignore>
        <GuideTitle index="NATS" title={natsCopy.title} lead={natsCopy.lead} copy={guideCopy} />
        <GuideSummary copy={ui} duration={natsCopy.duration} outcome={natsCopy.outcome} prerequisites={natsCopy.prerequisites} />
        <section className="doc-section"><Note tone="warn" title={natsCopy.boundaryTitle}>{natsCopy.boundaryBody}</Note></section>
        <section className="doc-section">
          <h2>{natsCopy.ackTitle}</h2><p>{natsCopy.ackBody}</p>
          <div className="concept-flow">{natsCopy.ackSteps.map(([index, title, description]) => <article key={index}><span>{index}</span><div><h3>{title}</h3><p>{description}</p></div></article>)}</div>
        </section>
        <section className="doc-section">
          <h2>{natsCopy.localTitle}</h2><p>{natsCopy.localBody}</p>
          <CodeBlock label="terminal 1">{brokerCommand}</CodeBlock>
          <CodeBlock label="trustdb.yaml">{configBlock}</CodeBlock>
          <CodeBlock label="terminal 2">{serverCommand}</CodeBlock>
          <ExpectedResult label={ui.expected}>{natsCopy.localExpected}</ExpectedResult>
          <Note title={natsCopy.localNoteTitle}>{natsCopy.localNoteBody}</Note>
        </section>
        <section className="doc-section">
          <h2>{natsCopy.topologyTitle}</h2><p>{natsCopy.topologyBody}</p>
          <div className="definition-grid">{natsCopy.topologyRows.map(([title, description]) => <div key={title}><strong>{title}</strong><p>{description}</p></div>)}</div>
        </section>
        <section className="doc-section">
          <h2>{natsCopy.flowTitle}</h2><p>{natsCopy.flowBody}</p>
          <div className="definition-grid">{natsCopy.flowRows.map(([title, description]) => <div key={title}><strong>{title}</strong><p>{description}</p></div>)}</div>
        </section>
        <section className="doc-section">
          <h2>{natsCopy.sdkTitle}</h2><p>{natsCopy.sdkBody}</p>
          <CodeBlock label="Go">{sdkExample}</CodeBlock>
          <ExpectedResult label={ui.expected}>{natsCopy.sdkExpected}</ExpectedResult>
          <Note title={natsCopy.resumeTitle}>{natsCopy.resumeBody}</Note>
        </section>
        <section className="doc-section">
          <h2>{natsCopy.securityTitle}</h2><p>{natsCopy.securityBody}</p>
          <ul className="doc-checklist">{natsCopy.securityChecklist.map((item) => <li key={item}>{item}</li>)}</ul>
        </section>
        <section className="doc-section">
          <h2>{natsCopy.recoveryTitle}</h2><p>{natsCopy.recoveryBody}</p>
          <ul className="doc-checklist">{natsCopy.recoveryChecklist.map((item) => <li key={item}>{item}</li>)}</ul>
          <Note tone="warn" title={natsCopy.backupTitle}>{natsCopy.backupBody}</Note>
          <InlineLink href="https://github.com/wowtrust/trustdb/blob/main/docs/integrations/NATS_INGRESS.md">{natsCopy.fullGuideLabel}</InlineLink>
        </section>
        <div className="doc-next"><span>{ui.next}</span><Link href="/docs/server">{natsCopy.nextLabel} <ArrowRight /></Link></div>
      </div>
    </DocsShell>
  );
}

export function OfflineVerificationPage({ route }) {
  const locale = useLocale();
  const { lang, ui, offline, server } = useDocsOnboarding(locale);
  return (
    <DocsShell route={route}>
      <div lang={lang} data-i18n-ignore>
        <GuideTitle index="04" title={offline.title} lead={offline.lead} copy={ui} />
        <GuideSummary copy={ui} duration={offline.duration} outcome={offline.outcome} prerequisites={offline.prerequisites} />
        <section className="doc-section"><h2>{offline.packageTitle}</h2><p>{offline.packageBody}</p><Note tone="warn" title={offline.trustTitle}>{offline.trustBody}</Note></section>
        <section className="doc-section">
          <h2>{offline.verifyTitle}</h2><p>{offline.verifyBody}</p>
          <CodeBlock>{`# Run from the extracted TrustDB release directory.\n# The server may be stopped and the machine may be offline.\n./bin/trustdb verify \\\n  --file ./example.txt \\\n  --sproof ./.trustdb-dev/sdk-demo/record.sproof \\\n  --server-public-key ./.trustdb-dev/server.pub \\\n  --client-public-key ./.trustdb-dev/client.pub`}</CodeBlock>
          <ExpectedResult label={ui.expected}>{offline.verifyExpected}</ExpectedResult>
        </section>
        <section className="doc-section">
          <h2>{offline.levelTitle}</h2>
          <div className="offline-levels" role="table">
            {offline.levels.map(([level, proves, limit]) => <div role="row" key={level}><strong role="cell">{level}</strong><p role="cell">{proves}</p><p role="cell">{limit}</p></div>)}
          </div>
          <Note title={offline.skipTitle}>{offline.skipBody}</Note>
          <CodeBlock>{`./bin/trustdb verify \\\n  --file ./example.txt \\\n  --sproof ./.trustdb-dev/sdk-demo/record.sproof \\\n  --server-public-key ./.trustdb-dev/server.pub \\\n  --client-public-key ./.trustdb-dev/client.pub \\\n  --skip-anchor`}</CodeBlock>
        </section>
        <section className="doc-section">
          <h2>{offline.tamperTitle}</h2><p>{offline.tamperBody}</p>
          <CodeBlock>{`cp example.txt tampered.txt\nprintf 'changed\\n' >> tampered.txt\n./bin/trustdb verify \\\n  --file ./tampered.txt \\\n  --sproof ./.trustdb-dev/sdk-demo/record.sproof \\\n  --server-public-key ./.trustdb-dev/server.pub \\\n  --client-public-key ./.trustdb-dev/client.pub`}</CodeBlock>
          <ExpectedResult label={ui.expected}>{offline.tamperExpected}</ExpectedResult>
        </section>
        <div className="doc-next"><span>{ui.next}</span><Link href="/docs/server">{server.title} <ArrowRight /></Link></div>
      </div>
    </DocsShell>
  );
}

export function TroubleshootingPage({ route }) {
  const locale = useLocale();
  const { lang, ui, troubleshooting } = useDocsOnboarding(locale);
  return (
    <DocsShell route={route}>
      <div lang={lang} data-i18n-ignore>
        <GuideTitle index="06" title={troubleshooting.title} lead={troubleshooting.lead} copy={ui} />
        <GuideSummary copy={ui} duration={troubleshooting.duration} outcome={troubleshooting.outcome} prerequisites={[troubleshooting.introBody]} />
        <section className="doc-section"><h2>{troubleshooting.introTitle}</h2><p>{troubleshooting.introBody}</p><CodeBlock>{`./bin/trustdb version\n./bin/trustdb config validate --config ./config/production.yaml\n./bin/trustdb doctor --config ./config/production.yaml\ncurl --fail --silent http://127.0.0.1:8080/healthz`}</CodeBlock></section>
        <section className="doc-section">
          <h2>{troubleshooting.diagnosticsTitle}</h2>
          <div className="troubleshooting-list">{troubleshooting.cards.map(([symptom, cause, action], index) => <article key={symptom} data-reveal><span>{String(index + 1).padStart(2, "0")}</span><h3>{symptom}</h3><div><strong>{troubleshooting.causeLabel}</strong><p>{cause}</p><strong>{troubleshooting.actionLabel}</strong><p>{action}</p></div></article>)}</div>
        </section>
        <section className="doc-completion" data-reveal><span>GitHub</span><h2>{troubleshooting.askTitle}</h2><p>{troubleshooting.askBody}</p><a className="button button--solid" href="https://github.com/wowtrust/trustdb/issues/new/choose" target="_blank" rel="noreferrer">{troubleshooting.openIssueLabel} <ArrowRight /></a></section>
      </div>
    </DocsShell>
  );
}

export function DesktopDocsPage({ route }) {
  return (
    <DocsShell route={route}>
      <ArticleTitle index="08" title="桌面客户端" lead="Wails + Vue 原生桌面应用：本地身份、文件存证、记录索引、证明导出与离线验证。" />
      <section className="doc-section"><h2>当前能力</h2><div className="capability-grid"><div><Wrench /><strong>身份初始化</strong><p>配置 server URL、tenant、client、key ID 与本地 Ed25519 私钥。</p></div><div><HardDrives /><strong>文件存证</strong><p>本地哈希与签名，提交后保留本地 Pebble 索引。</p></div><div><Package /><strong>证明管理</strong><p>刷新等级，主推 .sproof，亦可导出分离的 L3/L4/L5 材料。</p></div><div><Desktop /><strong>离线验证</strong><p>把原文件与证明拖入客户端，不依赖服务端重新判断有效性。</p></div></div></section>
      <section className="doc-section"><h2>下载与安装</h2><p>选择与处理器相符的安装包。当前桌面客户端采用自签名证书，首次启动时系统会要求你确认。</p><div className="doc-download-links"><InlineLink href="/downloads">选择桌面客户端</InlineLink><InlineLink href="/docs/desktop-install">查看自签名安装步骤</InlineLink></div></section>
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
      <ArticleTitle index="09" title="安装桌面客户端" lead="先核对下载文件，再按系统确认一次自签名应用。无需导入根证书，也不要关闭整机安全功能。" />
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
      <ArticleTitle index="10" title="从源码构建" lead="服务器、CLI 与桌面客户端的构建环境和命令。" updated="2026.07.22" version="适用于 v1.0.0 源码标签" />
      <section className="doc-section"><h2>服务器与 CLI</h2><p>需要 Git 与 Go 1.26.5 或更高的兼容版本。固定源码标签，先测试，再生成单个 <code>trustdb</code> 二进制文件。</p><CodeBlock>git clone --branch v1.0.0 --depth 1 https://github.com/wowtrust/trustdb.git{"\n"}cd trustdb{"\n"}go test ./...{"\n"}go build -trimpath -o ./bin/trustdb ./cmd/trustdb{"\n"}./bin/trustdb version</CodeBlock></section>
      <section className="doc-section"><h2>桌面客户端</h2><p>桌面端还需要 Node.js 24、平台原生编译工具和 Wails 2.12.0。先安装当前系统的 Wails 依赖，再构建前端与原生壳。</p><CodeBlock>go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0{"\n"}cd clients/desktop/frontend{"\n"}npm ci{"\n"}npm run build{"\n"}cd ..{"\n"}wails doctor{"\n"}wails build</CodeBlock><InlineLink href="https://wails.io/docs/gettingstarted/installation/">Wails 平台依赖</InlineLink></section>
      <section className="doc-section"><h2>开发运行</h2><p>从 <code>clients/desktop</code> 运行 <code>wails dev</code> 才能使用签名、文件选择和本地数据库等原生能力。只启动 Vite 适合检查界面，不等同于完整客户端。</p><CodeBlock>cd clients/desktop{"\n"}go test ./...{"\n"}wails dev</CodeBlock><InlineLink href="/downloads">下载预编译版本</InlineLink></section>
      <div className="doc-next"><span>继续阅读</span><Link href="/sproof">.sproof v1 格式 <ArrowRight /></Link></div>
    </DocsShell>
  );
}

export function MissingDocsPage() {
  return <PageHero eyebrow="404 / Documentation" title={<>这篇文档<br />还不存在。</>} lead="返回文档中心，选择已经发布的指南。"><div className="page-hero__actions"><Link className="button button--solid" href="/docs">文档中心 <ArrowRight /></Link></div></PageHero>;
}
