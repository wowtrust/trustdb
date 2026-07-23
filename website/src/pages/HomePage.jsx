import { useEffect, useRef, useState } from "react";
import { ArrowRight, Check, Copy, DownloadSimple, GithubLogo, Package, ShieldCheck } from "@phosphor-icons/react";
import { Link } from "../router";
import { checksumsAsset, homeDownloadGroups, release } from "../lib/release";
import heroLandscape from "../assets/generated/trustdb-hero-landscape.webp";
import evidenceField from "../assets/generated/trustdb-evidence-field.webp";
import terminalLandscape from "../assets/generated/trustdb-terminal-landscape.webp";
import evidenceProblemLineart from "../assets/generated/trustdb-evidence-problem-lineart.webp";
import desktopZh from "../assets/client-locales/desktop-zh-CN.png";
import desktopEn from "../assets/client-locales/desktop-en.png";
import desktopRu from "../assets/client-locales/desktop-ru.png";
import desktopJa from "../assets/client-locales/desktop-ja.png";
import desktopFr from "../assets/client-locales/desktop-fr.png";
import desktopKo from "../assets/client-locales/desktop-ko.png";
import { useLocale } from "../i18n";
import { comparisonSources, productExplanation } from "../content/productExplanation";

const desktopProducts = {
  "zh-CN": desktopZh,
  en: desktopEn,
  ru: desktopRu,
  ja: desktopJa,
  fr: desktopFr,
  ko: desktopKo,
};

const knowledgeItems = [
  ["01", "文档中心", "从本地启动到服务部署、CLI、Go SDK 与桌面客户端。", "/docs"],
  ["02", "性能基线", "基于当前版本 731.1 万次提交的双机多语义评估。", "/performance"],
  ["03", ".sproof v1", "确定性 CBOR 单文件证据交换格式、等级上限与验证算法。", "/sproof"],
  ["04", "版本与下载", "查看 1.0.0 正式版的各平台构建产物与校验资料。", "/downloads"],
];

function FlowCanvas({ mode = "hero" }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas.getContext("2d");
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let raf = 0;
    let width = 0;
    let height = 0;
    let visible = true;

    const observer = new IntersectionObserver(([entry]) => { visible = entry.isIntersecting; }, { rootMargin: "120px" });
    observer.observe(canvas);

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      width = rect.width;
      height = rect.height;
      canvas.width = Math.max(1, Math.round(width * ratio));
      canvas.height = Math.max(1, Math.round(height * ratio));
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
    };

    const drawHero = (time) => {
      const progress = (Math.sin(time * 0.00042) + 1) / 2;
      const x1 = width * 0.045;
      const y1 = height * 0.70;
      const x2 = width * 0.77;
      const y2 = height * 0.88;
      const x = x1 + (x2 - x1) * progress;
      const y = y1 + (y2 - y1) * progress;
      const gradient = context.createLinearGradient(x1, y1, x2, y2);
      gradient.addColorStop(0, "rgba(151,255,112,.98)");
      gradient.addColorStop(0.58, "rgba(0,255,34,.82)");
      gradient.addColorStop(1, "rgba(0,255,34,.08)");
      context.save();
      context.lineCap = "round";
      context.shadowColor = "#00ff22";
      context.shadowBlur = 16;
      context.strokeStyle = gradient;
      context.lineWidth = 2;
      context.beginPath();
      context.moveTo(x1, y1);
      context.bezierCurveTo(width * .25, height * .44, width * .52, height * .69, x2, y2);
      context.stroke();
      context.shadowBlur = 25;
      context.fillStyle = "#d9ffc7";
      context.beginPath();
      context.arc(x, y, 3.4, 0, Math.PI * 2);
      context.fill();
      context.restore();
    };

    const drawJourney = (time) => {
      const t = time * 0.00012;
      context.save();
      for (let i = 0; i < 52; i += 1) {
        const phase = (i * 0.073 + t) % 1;
        const x = phase * width;
        const band = Math.sin(i * 2.17 + t * 7) * height * .16;
        const y = height * .53 + band * (0.35 + Math.sin(phase * Math.PI));
        const alpha = .13 + Math.sin(phase * Math.PI) * .38;
        context.fillStyle = `rgba(0,255,34,${alpha})`;
        context.fillRect(x, y, i % 8 === 0 ? 3 : 1.2, i % 8 === 0 ? 3 : 1.2);
      }
      context.restore();
    };

    const draw = (time) => {
      if (visible) {
        context.clearRect(0, 0, width, height);
        if (mode === "hero") drawHero(time);
        else drawJourney(time);
      }
      if (!reduced) raf = requestAnimationFrame(draw);
    };

    resize();
    window.addEventListener("resize", resize);
    draw(0);
    if (!reduced) raf = requestAnimationFrame(draw);
    return () => {
      observer.disconnect();
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, [mode]);

  return <canvas ref={canvasRef} className={`flow-canvas flow-canvas--${mode}`} aria-hidden="true" />;
}

export function HomePage() {
  const locale = useLocale();
  const { comparison, home } = productExplanation(locale);
  const [copied, setCopied] = useState(false);
  const command = "trustdb verify --file document.pdf --sproof document.sproof --server-public-key server.pub --client-public-key client.pub";

  const copyCommand = async () => {
    await navigator.clipboard.writeText(command);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <>
      <section className="hero" style={{ "--hero-image": `url(${heroLandscape})` }} data-i18n-ignore>
        <FlowCanvas mode="hero" />
        <div className="hero__content">
          <p className="hero__eyebrow"><ShieldCheck weight="fill" /> {home.hero.eyebrow}</p>
          <h1 className="hero__title" aria-label={home.hero.title.join(" ")}>{home.hero.title.map((line) => <span key={line}>{line}</span>)}</h1>
          <p className="hero__copy">{home.hero.copy}</p>
          <div className="hero__actions">
            <Link className="button button--solid" href="/docs/quick-start">{home.hero.primary} <ArrowRight /></Link>
            <Link className="button button--ghost" href="/sproof">{home.hero.secondary}</Link>
          </div>
          <ul className="hero__signals" aria-label={home.hero.points.join(" · ")}>
            {home.hero.points.map((point) => <li key={point}>{point}</li>)}
          </ul>
        </div>
        <p className="hero__index">01 / {home.hero.index}</p>
      </section>

      <section className="why-trustdb" data-i18n-ignore>
        <div className="section-shell why-trustdb__layout">
          <div className="why-trustdb__statement" data-reveal>
            <p>{home.problem.eyebrow}</p>
            <h2>{home.problem.title.map((line) => <span key={line}>{line}</span>)}</h2>
          </div>
          <div className="why-trustdb__copy" data-reveal>
            {home.problem.copy.map((paragraph) => <p key={paragraph}>{paragraph}</p>)}
          </div>
        </div>
        <figure className="why-trustdb__art section-shell" data-reveal>
          <img src={evidenceProblemLineart} width="1979" height="795" loading="lazy" decoding="async" alt={home.problem.artAlt} />
          <figcaption>{home.problem.captions.map((caption) => <span key={caption}>{caption}</span>)}</figcaption>
        </figure>
        <div className="why-trustdb__answer section-shell" data-reveal>
          <strong>{home.problem.answerTitle}</strong>
          <p>{home.problem.answerBody}</p>
          <Link href="/docs/concepts">{home.problem.cta} <ArrowRight /></Link>
        </div>
      </section>

      <section className="home-capabilities" id="capabilities" aria-labelledby="capabilities-title" data-i18n-ignore>
        <div className="section-shell">
          <header className="home-capabilities__heading" data-reveal>
            <p>{home.capabilities.eyebrow}</p>
            <h2 id="capabilities-title">{home.capabilities.title.map((line) => <span key={line}>{line}</span>)}</h2>
            <span>{home.capabilities.lead}</span>
          </header>
          <div className="home-capabilities__grid">
            {home.capabilities.cards.map(([index, title, description]) => (
              <article key={index} data-reveal><span>{index}</span><h3>{title}</h3><p>{description}</p></article>
            ))}
          </div>
          <div className="home-benchmark" data-reveal>
            <div className="home-benchmark__label"><span>{home.capabilities.benchmarkEyebrow}</span><Link href="/performance">{home.capabilities.benchmarkCta} <ArrowRight /></Link></div>
            <div className="home-benchmark__metrics">
              {home.capabilities.metrics.map(([value, label]) => <div key={label}><strong>{value}</strong><span>{label}</span></div>)}
            </div>
          </div>
        </div>
      </section>

      <section className="proof" id="proof-model" data-i18n-ignore>
        <div className="section-shell">
          <div className="section-heading" data-reveal>
            <p>{home.proof.eyebrow}</p>
            <h2>{home.proof.title.map((line) => <span key={line}>{line}</span>)}</h2>
            <span>{home.proof.lead}</span>
          </div>
          <div className="proof-rail">
            <div className="proof-rail__line" />
            {home.proof.levels.map(([level, label, description]) => (
              <article className="proof-step" key={level} tabIndex="0">
                <span className="proof-step__level">{level}</span>
                <span className="proof-step__node"><Check weight="bold" /></span>
                <strong>{label}</strong>
                <p>{description}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="journey" aria-labelledby="journey-title" data-i18n-ignore>
        <img className="journey__image" src={evidenceField} width="2048" height="1024" loading="lazy" decoding="async" alt={home.journey.artAlt} />
        <FlowCanvas mode="journey" />
        <div className="journey__heading" data-reveal>
          <p>{home.journey.eyebrow}</p>
          <h2 id="journey-title">{home.journey.title.map((line) => <span key={line}>{line}</span>)}</h2>
        </div>
        <div className="journey__labels" data-reveal>
          {home.journey.labels.map(([label, detail]) => <span key={label}>{label}<small>{detail}</small></span>)}
        </div>
        <p className="journey__caption" data-reveal>{home.journey.caption}</p>
      </section>

      <section className="home-use-cases" id="use-cases" aria-labelledby="use-cases-title" data-i18n-ignore>
        <div className="section-shell">
          <header className="home-use-cases__heading" data-reveal>
            <p>{home.useCases.eyebrow}</p>
            <h2 id="use-cases-title">{home.useCases.title.map((line) => <span key={line}>{line}</span>)}</h2>
            <span>{home.useCases.lead}</span>
          </header>
          <div className="home-use-cases__grid">
            {home.useCases.cards.map(([eyebrow, title, description]) => (
              <article key={eyebrow} data-reveal><span>{eyebrow}</span><h3>{title}</h3><p>{description}</p></article>
            ))}
          </div>
        </div>
      </section>

      <section className="comparison" id="comparison" aria-labelledby="comparison-title" data-i18n-ignore>
        <div className="section-shell">
          <header className="comparison__heading" data-reveal>
            <p>{comparison.eyebrow}</p>
            <h2 id="comparison-title">{comparison.title}</h2>
            <span>{comparison.lead}</span>
          </header>
          <div className="comparison__table" role="table" aria-label={comparison.title} data-reveal>
            <div className="comparison__row comparison__row--head" role="row">
              {comparison.columns.map((column) => <span role="columnheader" key={column}>{column}</span>)}
            </div>
            {comparison.products.map(([name, role, evidence, verification, choice], index) => (
              <div className={`comparison__row${index === 0 ? " comparison__row--trustdb" : ""}`} role="row" key={name}>
                {[name, role, evidence, verification, choice].map((value, cellIndex) => <div role="cell" key={comparison.columns[cellIndex]}><small>{comparison.columns[cellIndex]}</small>{cellIndex === 0 ? <strong>{value}</strong> : cellIndex === 1 ? <span>{value}</span> : <p>{value}</p>}</div>)}
              </div>
            ))}
          </div>
          <footer className="comparison__footer" data-reveal>
            <div><strong>{comparison.note}</strong><p>{comparison.sourceLabel}: {comparisonSources.map((source, index) => <span key={source.name}>{index > 0 ? " · " : ""}<a href={source.href} target="_blank" rel="noreferrer">{source.name}</a></span>)}</p></div>
            <Link href="/docs/concepts">{comparison.cta} <ArrowRight /></Link>
          </footer>
        </div>
      </section>

      <section className="ecosystem section-shell">
        <div className="ecosystem__heading" data-reveal><p>CLI · SDK · Desktop</p><h2>一套证据链，<br />适合不同用法。</h2><span>CLI 用于自动化，Go SDK 接入业务系统，桌面客户端处理日常文件。无论从哪里提交，都用同样的方法验证。</span></div>
        <div className="product-shot product-shot--desktop" data-reveal><div className="product-shot__bar"><span />TrustDB Desktop / Local proof workspace</div><img src={desktopProducts[locale] || desktopZh} width="1280" height="720" loading="lazy" decoding="async" alt="TrustDB Desktop 客户端概览界面" /></div>
        <div className="ecosystem__lower">
          <div className="ecosystem__tools">
            <article data-reveal><span>CLI</span><h3>自动化与离线验证</h3><p>密钥、声明、提交、验证、备份、诊断与性能测试，适合脚本和受控环境。</p><Link href="/docs/cli">CLI 文档 <ArrowRight /></Link></article>
            <article data-reveal><span>SDK</span><h3>嵌入你的业务</h3><p>Go SDK 在应用进程内完成签名、HTTP / gRPC 提交、证明导出与验证。</p><Link href="/docs/sdk">SDK 文档 <ArrowRight /></Link></article>
            <article data-reveal><span>DESKTOP</span><h3>无需学习命令</h3><p>面向文件工作流的原生客户端，让非研发用户也能存证、追踪与验证。</p><Link href="/docs/desktop">客户端文档 <ArrowRight /></Link></article>
          </div>
        </div>
      </section>

      <section className="home-downloads" id="downloads">
        <div className="section-shell">
          <header className="home-downloads__heading" data-reveal>
            <div><p>Release / {release.version}</p><h2>各平台<br />发布文件。</h2></div>
            <div><Package weight="duotone" /><p>桌面客户端、服务器与 CLI 已为常用系统和架构打包。所有文件来自同一次发布，并提供统一的 SHA-256 校验清单。</p></div>
          </header>
          <div className="home-downloads__grid">
            {homeDownloadGroups.map((group) => (
              <article className="home-download-card" key={group.eyebrow} data-reveal>
                <span>{group.eyebrow}</span>
                <h3>{group.title}</h3>
                <p>{group.description}</p>
                <div>
                  {group.downloads.map((download) => (
                    <a href={download.url} key={download.filename} title={download.filename}>
                      <span>{download.label}</span><DownloadSimple />
                    </a>
                  ))}
                </div>
              </article>
            ))}
          </div>
          <footer className="home-downloads__footer" data-reveal>
            <Link href="/downloads">查看全部发布产物 <ArrowRight /></Link>
            <a href={checksumsAsset.url}>下载 SHA256SUMS <DownloadSimple /></a>
          </footer>
        </div>
      </section>

      <section className="knowledge section-shell">
        <div className="knowledge__heading" data-reveal>
          <p>Learn more</p>
          <h2>文档、格式<br />与性能数据。</h2>
        </div>
        <div className="knowledge__grid">
          {knowledgeItems.map(([index, title, description, href]) => (
            <Link className="knowledge-card" href={href} key={title} data-reveal>
              <span>{index}</span><h3>{title}</h3><p>{description}</p><ArrowRight />
            </Link>
          ))}
        </div>
      </section>

      <section className="quick" style={{ "--quick-image": `url(${terminalLandscape})` }}>
        <div className="quick__copy" data-reveal>
          <p>Offline verification</p>
          <h2>开源 · 可审计<br />可离线验证</h2>
          <Link className="button button--solid" href="/docs/quick-start">进入快速开始 <ArrowRight /></Link>
        </div>
        <div className="terminal" data-reveal>
          <div className="terminal__chrome"><i /><i /><i /><span>trustdb / verify session</span></div>
          <button className="terminal__copy" type="button" onClick={copyCommand} aria-label={copied ? "命令已复制" : "复制命令"}>{copied ? <Check /> : <Copy />}</button>
          <pre><span className="prompt">$</span> trustdb verify --file document.pdf \{"\n"}  --sproof document.sproof \{"\n"}  --server-public-key server.pub \{"\n"}  --client-public-key client.pub{"\n"}<span className="success">✓ valid · proof level L5</span></pre>
        </div>
      </section>

      <section className="home-github">
        <div data-reveal><p>Open source / AGPL-3.0</p><h2>源码公开，<br />结论可验。</h2></div>
        <a className="button button--ghost" href="https://github.com/wowtrust/trustdb" target="_blank" rel="noreferrer"><GithubLogo weight="fill" /> GitHub <ArrowRight /></a>
      </section>
    </>
  );
}
