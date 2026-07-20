import { ArrowUpRight, GithubLogo, List, X } from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { Link } from "../router";

const navItems = [
  ["产品", "/"],
  ["文档", "/docs"],
  ["性能", "/performance"],
  [".sproof", "/sproof"],
  ["版本", "/changelog"],
  ["下载", "/downloads"],
];

export function Logo() {
  return (
    <Link className="brand" href="/" aria-label="TrustDB 首页">
      <span className="brand__name">TRUSTDB</span>
      <span className="brand__descriptor">可验证证据数据库</span>
    </Link>
  );
}

export function SiteHeader({ route }) {
  const [open, setOpen] = useState(false);
  useEffect(() => setOpen(false), [route]);

  return (
    <>
      <header className="site-header">
        <Logo />
        <nav className="site-nav" aria-label="主导航">
          {navItems.map(([label, href]) => (
            <Link key={href} href={href} aria-current={route === href || (href !== "/" && route.startsWith(href)) ? "page" : undefined}>{label}</Link>
          ))}
        </nav>
        <div className="site-header__actions">
          <a className="header-github" href="https://github.com/ryan-wong-coder/trustdb" target="_blank" rel="noreferrer" aria-label="打开 TrustDB GitHub 仓库">
            <GithubLogo weight="fill" /><span>GitHub</span>
          </a>
          <button className="menu-toggle" type="button" onClick={() => setOpen((value) => !value)} aria-label={open ? "关闭导航" : "打开导航"} aria-expanded={open}>
            {open ? <X /> : <List />}
          </button>
        </div>
      </header>
      {open && (
        <nav className="mobile-menu" aria-label="移动导航">
          {navItems.map(([label, href], index) => <Link key={href} href={href}><span>0{index + 1}</span>{label}</Link>)}
        </nav>
      )}
    </>
  );
}

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="site-footer__lead">
        <Logo />
        <p>把信任从承诺，变成任何人都能复算的结果。</p>
      </div>
      <nav aria-label="页脚导航">
        <Link href="/docs">文档</Link>
        <Link href="/performance">性能</Link>
        <Link href="/sproof">.sproof</Link>
        <Link href="/changelog">开发日志</Link>
        <Link href="/downloads">下载</Link>
      </nav>
      <div className="site-footer__meta">
        <a href="https://github.com/ryan-wong-coder/trustdb" target="_blank" rel="noreferrer">源码 <ArrowUpRight /></a>
        <small>AGPL-3.0 · © 2026 TrustDB</small>
      </div>
    </footer>
  );
}

export function PageHero({ eyebrow, title, lead, meta, children }) {
  return (
    <section className="page-hero">
      <div className="page-hero__grid" aria-hidden="true" />
      <div className="page-hero__content">
        <p className="page-hero__eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p className="page-hero__lead">{lead}</p>
        {meta && <p className="page-hero__meta">{meta}</p>}
        {children}
      </div>
    </section>
  );
}

export function CodeBlock({ label = "shell", children }) {
  return (
    <div className="code-block" data-reveal>
      <div className="code-block__label"><span />{label}</div>
      <pre><code>{children}</code></pre>
    </div>
  );
}

export function InlineLink({ href, children }) {
  const external = href.startsWith("http");
  if (external) return <a className="inline-link" href={href} target="_blank" rel="noreferrer">{children}<ArrowUpRight /></a>;
  return <Link className="inline-link" href={href}>{children}<ArrowUpRight /></Link>;
}
