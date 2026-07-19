import { useEffect, useRef, useState } from "react";
import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import {
  ArrowRight,
  Check,
  Copy,
  GithubLogo,
  ShieldCheck,
} from "@phosphor-icons/react";
import heroLandscape from "./assets/generated/trustdb-hero-landscape.png";
import evidenceField from "./assets/generated/trustdb-evidence-field.png";
import terminalLandscape from "./assets/generated/trustdb-terminal-landscape.png";

gsap.registerPlugin(ScrollTrigger, useGSAP);

const proofLevels = [
  ["L1", "签名", "客户端签名，锁定来源与内容。"],
  ["L2", "收据", "服务端接收并返回可验证收据。"],
  ["L3", "MERKLE", "进入批次树，获得包含证明。"],
  ["L4", "GLOBAL", "写入全局透明日志，持续可审计。"],
  ["L5", "锚定", "发布外部锚点，获得独立时间边界。"],
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

    const observer = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
    }, { rootMargin: "120px" });
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

function Logo() {
  return (
    <a className="brand" href="#top" aria-label="TrustDB 首页">
      <span className="brand__name">TRUSTDB</span>
      <span className="brand__descriptor">可验证证据数据库</span>
    </a>
  );
}

export function App() {
  const root = useRef(null);
  const [copied, setCopied] = useState(false);

  useGSAP(() => {
    const media = gsap.matchMedia();
    media.add("(prefers-reduced-motion: no-preference)", () => {
      gsap.timeline({ defaults: { ease: "power3.out" } })
        .from(".site-header", { y: -24, opacity: 0, duration: .75 })
        .from(".hero__eyebrow, .hero__title, .hero__copy, .hero__actions", {
          y: 42,
          opacity: 0,
          duration: .9,
          stagger: .09,
        }, "-=.38");

      gsap.utils.toArray("[data-reveal]").forEach((element) => {
        gsap.from(element, {
          scrollTrigger: { trigger: element, start: "top 82%", once: true },
          y: 54,
          opacity: 0,
          duration: .95,
          ease: "power3.out",
        });
      });

      gsap.from(".proof-step", {
        scrollTrigger: { trigger: ".proof-rail", start: "top 76%", once: true },
        opacity: 0,
        y: 32,
        stagger: .12,
        duration: .72,
        ease: "power2.out",
      });

      gsap.to(".journey__image", {
        scrollTrigger: { trigger: ".journey", start: "top bottom", end: "bottom top", scrub: 1.1 },
        yPercent: 8,
        ease: "none",
      });
    });
    return () => media.revert();
  }, { scope: root });

  const copyCommand = async () => {
    await navigator.clipboard.writeText("trustdb prove document.pdf -o document.sproof");
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div ref={root} className="site" id="top">
      <header className="site-header">
        <Logo />
        <nav className="site-nav" aria-label="主导航">
          <a href="#proof-model">产品</a>
          <a href="#quick-start">文档</a>
          <a href="#proof-model">证明模型</a>
        </nav>
        <div className="online"><span />系统在线</div>
      </header>

      <main>
        <section className="hero" style={{ "--hero-image": `url(${heroLandscape})` }}>
          <FlowCanvas mode="hero" />
          <div className="hero__content">
            <p className="hero__eyebrow"><ShieldCheck weight="fill" /> Provable infrastructure</p>
            <h1 className="hero__title">PROVABLE</h1>
            <p className="hero__copy">让每一个文件，都有可独立验证的证据链。</p>
            <div className="hero__actions">
              <a className="button button--solid" href="#quick-start">开始验证 <ArrowRight /></a>
              <a className="button button--ghost" href="#proof-model">阅读 .sproof 格式</a>
            </div>
          </div>
          <p className="hero__index">01 / 信任不是承诺，是可以复算的结果。</p>
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

        <section className="quick" id="quick-start" style={{ "--quick-image": `url(${terminalLandscape})` }}>
          <div className="quick__copy" data-reveal>
            <p>几分钟上手</p>
            <h2>开源 · 可审计<br />可离线验证</h2>
            <a className="button button--solid" href="https://github.com/ryan-wong-coder/trustdb" target="_blank" rel="noreferrer"><GithubLogo weight="fill" /> GitHub <ArrowRight /></a>
          </div>
          <div className="terminal" data-reveal>
            <div className="terminal__chrome"><i /><i /><i /><span>trustdb / proof session</span></div>
            <button className="terminal__copy" type="button" onClick={copyCommand} aria-label={copied ? "命令已复制" : "复制命令"} title={copied ? "命令已复制" : "复制命令"}>{copied ? <Check /> : <Copy />}</button>
            <pre><span className="prompt">$</span> trustdb prove document.pdf -o document.sproof{"\n"}<span className="success">✓ proof generated</span>{"\n\n"}<span className="prompt">$</span> trustdb verify document.sproof{"\n"}<span className="success">✓ valid</span>{"\n"}<span className="dim">log index</span>      18,732,991{"\n"}<span className="dim">root</span>           a3f6c2d1...9e4b8f7c{"\n"}<span className="dim">anchor</span>         0x7ab4...e9f1c3</pre>
          </div>
        </section>
      </main>

      <footer className="site-footer">
        <Logo />
        <nav><a href="#proof-model">产品</a><a href="#quick-start">文档</a><a href="#proof-model">证明模型</a></nav>
        <div><span className="online"><i />系统在线</span><small>© 2026 TrustDB</small></div>
      </footer>
    </div>
  );
}
