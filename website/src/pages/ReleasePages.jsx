import { ArrowRight, Bell, Check, DownloadSimple, GithubLogo, Package, WarningCircle } from "@phosphor-icons/react";
import { InlineLink, PageHero } from "../components/SiteChrome";
import { Link } from "../router";

const milestones = [
  ["2026.07.19", "UI modernization", "官网、Admin Web 与桌面客户端的视觉系统现代化，补齐多页面信息架构与响应式交互。", "In progress"],
  ["2026.07.18", "Proof level parsing", "修复证明等级解析路径，避免客户端和管理端显示与可验证材料不一致。", "#203"],
  ["2026.07.17", "CI & supply-chain security", "更新 Actions、依赖审计与自动化安全检查。", "#201 / #202"],
  ["2026.07.16", "Performance & official site", "完成双机性能报告、proof pipeline 优化说明与官网初始版本。", "#196 / #197 / #198"],
  ["2026.07.16", "Go crypto dependencies", "更新 Go 加密相关依赖并完成兼容验证。", "#199"],
];

export function ChangelogPage() {
  return (
    <>
      <PageHero eyebrow="Development log" title={<>正式发布之前，<br />我们做了什么。</>} lead="TrustDB 还没有发布正式版本。这里记录已经完成的重要改进；首个版本发布后，将继续补充升级说明和兼容性变化。" meta="开发日志 · 更新于 2026.07.19">
        <div className="page-hero__actions"><Link className="button button--solid" href="/downloads">下载状态 <ArrowRight /></Link><a className="button button--ghost" href="https://github.com/ryan-wong-coder/trustdb/commits/main" target="_blank" rel="noreferrer">全部提交</a></div>
      </PageHero>
      <section className="release-state section-shell" data-reveal><WarningCircle /><div><p>Release status</p><h2>首个正式版本正在准备</h2><span>发布时将同时提供版本号、升级说明、安全公告、各平台安装包和校验值。</span></div><Link href="/downloads">查看发布计划 <ArrowRight /></Link></section>
      <section className="timeline section-shell">
        <div className="timeline__heading" data-reveal><p>Development milestones</p><h2>最近完成了什么。</h2></div>
        <div className="timeline__list">{milestones.map(([date, title, description, ref], index) => <article key={`${date}-${title}`} data-reveal><span>{String(index + 1).padStart(2, "0")}</span><time>{date}</time><div><h3>{title}</h3><p>{description}</p></div><b>{ref}</b></article>)}</div>
      </section>
      <section className="release-policy"><div className="section-shell release-policy__layout"><div data-reveal><p>Release contract</p><h2>正式发版页会同时回答五件事。</h2></div><ol data-reveal><li><span>01</span>这个版本包含什么</li><li><span>02</span>兼容性与迁移要求</li><li><span>03</span>已知问题与安全边界</li><li><span>04</span>各平台下载与 SHA-256</li><li><span>05</span>源码、SBOM 与构建来源</li></ol></div></section>
    </>
  );
}

const plannedAssets = [
  ["macOS", "Apple Silicon / Universal", "DMG · ZIP", "签名与 notarization 待首个 Release"],
  ["Windows", "x86_64", "MSI / EXE", "签名安装包尚未发布"],
  ["Linux", "x86_64 / arm64", "AppImage / archive", "桌面包与 CLI archive 尚未发布"],
  ["CLI & checksums", "multi-platform", "tar.gz · SHA-256", "版本化二进制与校验清单尚未发布"],
];

export function DownloadsPage() {
  return (
    <>
      <PageHero eyebrow="Downloads" title={<>首个正式版本，<br />正在准备。</>} lead="安装包完成签名、公证和校验后，才会在这里发布。在此之前，可以从 GitHub 获取源码并自行构建。" meta="正式下载暂未开放">
        <div className="page-hero__actions"><a className="button button--solid" href="https://github.com/ryan-wong-coder/trustdb" target="_blank" rel="noreferrer"><GithubLogo weight="fill" /> 从源码开始 <ArrowRight /></a><a className="button button--ghost" href="https://github.com/ryan-wong-coder/trustdb/releases" target="_blank" rel="noreferrer">GitHub Releases</a></div>
      </PageHero>
      <section className="empty-release section-shell">
        <div className="empty-release__mark" data-reveal><DownloadSimple /></div>
        <div className="empty-release__copy" data-reveal><p>Release preparation</p><h2>先从源码开始。</h2><span>正式版本发布前，GitHub 仓库是唯一公开来源。需要评估 TrustDB 的团队可以先从源码构建并运行测试。</span></div>
        <a className="empty-release__watch" href="https://github.com/ryan-wong-coder/trustdb/subscription" target="_blank" rel="noreferrer"><Bell /> Watch 仓库获取通知 <ArrowRight /></a>
      </section>
      <section className="asset-plan">
        <div className="section-shell">
          <div className="asset-plan__heading" data-reveal><p>Planned release assets</p><h2>发布后，这里会有什么。</h2></div>
          <div className="asset-grid">{plannedAssets.map(([platform, arch, format, status]) => <article key={platform} data-reveal><Package /><span>PLANNED</span><h3>{platform}</h3><strong>{arch}</strong><code>{format}</code><p>{status}</p></article>)}</div>
        </div>
      </section>
      <section className="source-build section-shell">
        <div data-reveal><p>Build from source</p><h2>现在可以做什么。</h2></div>
        <div className="source-build__steps" data-reveal><p><span>01</span><strong>CLI / Server</strong><code>go build ./cmd/trustdb</code></p><p><span>02</span><strong>Desktop</strong><code>cd clients/desktop && wails build</code></p><p><span>03</span><strong>Verify</strong><code>go test ./...</code></p></div>
        <div className="source-build__note"><Check /><span>源码构建适合开发与评估；对外分发前仍应完成平台签名、SBOM、校验值与可重现构建验证。</span></div>
        <div className="source-build__links"><InlineLink href="/docs/quick-start">快速开始</InlineLink><InlineLink href="/docs/desktop">桌面客户端文档</InlineLink><InlineLink href="/changelog">开发日志</InlineLink></div>
      </section>
    </>
  );
}
