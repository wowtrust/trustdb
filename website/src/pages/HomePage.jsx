import { useEffect, useRef, useState } from "react";
import { ArrowRight, Check, Copy, GithubLogo, ShieldCheck } from "@phosphor-icons/react";
import { Link } from "../router";
import heroLandscape from "../assets/generated/trustdb-hero-landscape.png";
import evidenceField from "../assets/generated/trustdb-evidence-field.png";
import terminalLandscape from "../assets/generated/trustdb-terminal-landscape.png";
import evidenceProblemLineart from "../assets/generated/trustdb-evidence-problem-lineart.png";
import desktopProduct from "../../../design/qa/desktop-client-homepage.png";

const proofLevels = [
  ["L1", "签名", "客户端签名，锁定来源与内容。"],
  ["L2", "收据", "服务端接收并返回可验证收据。"],
  ["L3", "MERKLE", "进入批次树，获得包含证明。"],
  ["L4", "GLOBAL", "写入全局透明日志，持续可审计。"],
  ["L5", "锚定", "发布外部锚点，获得独立时间边界。"],
];

const knowledgeItems = [
  ["01", "文档中心", "从本地启动到服务部署、CLI、Go SDK 与桌面客户端。", "/docs"],
  ["02", "性能基线", "基于 267.5 万次有效提交的双机压测结果与适用边界。", "/performance"],
  ["03", ".sproof v1", "确定性 CBOR 单文件证据交换格式、等级上限与验证算法。", "/sproof"],
  ["04", "版本与下载", "查看 1.0.0-beta 变更记录，并获取各平台构建产物。", "/changelog"],
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
      const y1 = height * 0.36;
      const x2 = width * 0.77;
      const y2 = height * 0.78;
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
  const [copied, setCopied] = useState(false);
  const command = "trustdb verify --file document.pdf --sproof document.sproof --server-public-key server.pub --client-public-key client.pub";

  const copyCommand = async () => {
    await navigator.clipboard.writeText(command);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <>
      <section className="hero" style={{ "--hero-image": `url(${heroLandscape})` }}>
        <FlowCanvas mode="hero" />
        <div className="hero__content">
          <p className="hero__eyebrow"><ShieldCheck weight="fill" /> Verifiable evidence database</p>
          <h1 className="hero__title">有据可查</h1>
          <p className="hero__copy">为文件和日志生成可独立验证的证据。原文不必公开，验证也不必依赖 TrustDB 本身。</p>
          <div className="hero__actions">
            <Link className="button button--solid" href="/docs/quick-start">开始使用 <ArrowRight /></Link>
            <Link className="button button--ghost" href="/sproof">了解 .sproof</Link>
          </div>
        </div>
        <p className="hero__index">01 / 文件可以离开系统，证据仍然经得起验证。</p>
      </section>

      <section className="why-trustdb">
        <div className="section-shell why-trustdb__layout">
          <div className="why-trustdb__statement" data-reveal>
            <p>Why TrustDB</p>
            <h2>需求一直存在。<br />只是过去太贵。</h2>
          </div>
          <div className="why-trustdb__copy" data-reveal>
            <p>文件交付后可能被替换，日志也可能由单方改写。等到争议发生，双方都很难证明当时的事实。</p>
          </div>
        </div>
        <figure className="why-trustdb__art section-shell" data-reveal>
          <img src={evidenceProblemLineart} alt="三个线稿场景：交付后的文件版本不一致、管理员可以单方修改日志、争议双方缺少独立证据" />
          <figcaption><span>文件版本不一致</span><span>日志由单方保管</span><span>争议发生时无据可查</span></figcaption>
        </figure>
        <div className="why-trustdb__answer section-shell" data-reveal>
          <strong>现在，一台普通服务器就能开始。</strong>
          <p>TrustDB 保存签名、收据和证明。发送方不用交出原文件，验证方拿到 .sproof 后就能自行核验。</p>
          <Link href="/docs">为什么需要 TrustDB <ArrowRight /></Link>
        </div>
      </section>

      <section className="proof" id="proof-model">
        <div className="section-shell">
          <div className="section-heading" data-reveal>
            <p>Proof model</p>
            <h2>五级证明，<br />一条证据链。</h2>
            <span>同一份证据随系统处理逐级增强，不改变原始事实，只增加独立验证能力。</span>
          </div>
          <div className="proof-rail">
            <div className="proof-rail__line" />
            {proofLevels.map(([level, label, description]) => (
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

      <section className="journey" aria-labelledby="journey-title">
        <img className="journey__image" src={evidenceField} alt="由稀疏文件粒子汇入透明日志并汇聚到外部锚点的抽象数据场" />
        <FlowCanvas mode="journey" />
        <div className="journey__heading" data-reveal>
          <p>Independent verification</p>
          <h2 id="journey-title">证据如何穿过系统。</h2>
        </div>
        <div className="journey__labels" data-reveal>
          <span>文件<small>本地生成与签名</small></span>
          <span>透明日志<small>公开、可追溯、不可静默改写</small></span>
          <span>外部锚定<small>获得独立时间边界</small></span>
        </div>
        <p className="journey__caption" data-reveal>从文件产生到链下日志，再到链上锚定，构成可独立验证的完整结构。</p>
      </section>

      <section className="ecosystem section-shell">
        <div className="ecosystem__heading" data-reveal><p>CLI · SDK · Desktop</p><h2>一套证据链，<br />适合不同用法。</h2><span>CLI 用于自动化，Go SDK 接入业务系统，桌面客户端处理日常文件。无论从哪里提交，都用同样的方法验证。</span></div>
        <div className="product-shot product-shot--desktop" data-reveal><div className="product-shot__bar"><span />TrustDB Desktop / Local proof workspace</div><img src={desktopProduct} alt="TrustDB Desktop 客户端概览界面" /></div>
        <div className="ecosystem__lower">
          <div className="ecosystem__tools">
            <article data-reveal><span>CLI</span><h3>自动化与离线验证</h3><p>密钥、声明、提交、验证、备份、诊断与性能测试，适合脚本和受控环境。</p><Link href="/docs/cli">CLI 文档 <ArrowRight /></Link></article>
            <article data-reveal><span>SDK</span><h3>嵌入你的业务</h3><p>Go SDK 在应用进程内完成签名、HTTP / gRPC 提交、证明导出与验证。</p><Link href="/docs/sdk">SDK 文档 <ArrowRight /></Link></article>
            <article data-reveal><span>DESKTOP</span><h3>无需学习命令</h3><p>面向文件工作流的原生客户端，让非研发用户也能存证、追踪与验证。</p><Link href="/docs/desktop">客户端文档 <ArrowRight /></Link></article>
          </div>
        </div>
      </section>

      <section className="knowledge section-shell">
        <div className="knowledge__heading" data-reveal>
          <p>Learn more</p>
          <h2>按你的需要，<br />继续了解。</h2>
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
        <a className="button button--ghost" href="https://github.com/ryan-wong-coder/trustdb" target="_blank" rel="noreferrer"><GithubLogo weight="fill" /> GitHub <ArrowRight /></a>
      </section>
    </>
  );
}
