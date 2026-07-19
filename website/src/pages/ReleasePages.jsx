import { ArrowRight, Check, DownloadSimple, GithubLogo, Package, WarningCircle } from "@phosphor-icons/react";
import { InlineLink, PageHero } from "../components/SiteChrome";
import { Link } from "../router";

const milestones = [
  ["2026.07.20", "v1.0.0-beta", "首个公开测试版：跨平台服务器与 CLI、四种桌面客户端、自签名安装包、SHA-256 校验和多架构 Docker 镜像。", "Beta"],
  ["2026.07.19", "UI modernization", "官网、Admin Web 与桌面客户端的视觉系统现代化，补齐多页面信息架构与响应式交互。", "In progress"],
  ["2026.07.18", "Proof level parsing", "修复证明等级解析路径，避免客户端和管理端显示与可验证材料不一致。", "#203"],
  ["2026.07.17", "CI & supply-chain security", "更新 Actions、依赖审计与自动化安全检查。", "#201 / #202"],
  ["2026.07.16", "Performance & official site", "完成双机性能报告、proof pipeline 优化说明与官网初始版本。", "#196 / #197 / #198"],
  ["2026.07.16", "Go crypto dependencies", "更新 Go 加密相关依赖并完成兼容验证。", "#199"],
];

export function ChangelogPage() {
  return (
    <>
      <PageHero eyebrow="Development log" title={<>每次发布，<br />都说清楚改了什么。</>} lead="这里记录已经完成的重要改进、兼容性变化和发布边界。1.0.0-beta 是首个公开测试版，适合评估、集成和试运行。" meta="开发日志 · 更新于 2026.07.20">
        <div className="page-hero__actions"><Link className="button button--solid" href="/downloads">下载状态 <ArrowRight /></Link><a className="button button--ghost" href="https://github.com/ryan-wong-coder/trustdb/commits/main" target="_blank" rel="noreferrer">全部提交</a></div>
      </PageHero>
      <section className="release-state section-shell" data-reveal><WarningCircle /><div><p>Release status</p><h2>1.0.0-beta 已进入公开测试</h2><span>桌面客户端采用自签名证书，系统仍会提示未知开发者；请从 GitHub Release 下载并核对 SHA-256。</span></div><Link href="/downloads">查看全部产物 <ArrowRight /></Link></section>
      <section className="timeline section-shell">
        <div className="timeline__heading" data-reveal><p>Development milestones</p><h2>最近完成了什么。</h2></div>
        <div className="timeline__list">{milestones.map(([date, title, description, ref], index) => <article key={`${date}-${title}`} data-reveal><span>{String(index + 1).padStart(2, "0")}</span><time>{date}</time><div><h3>{title}</h3><p>{description}</p></div><b>{ref}</b></article>)}</div>
      </section>
      <section className="release-policy"><div className="section-shell release-policy__layout"><div data-reveal><p>Release contract</p><h2>每次发版都回答五件事。</h2></div><ol data-reveal><li><span>01</span>这个版本包含什么</li><li><span>02</span>兼容性与迁移要求</li><li><span>03</span>已知问题与安全边界</li><li><span>04</span>各平台下载与 SHA-256</li><li><span>05</span>源码、SBOM 与构建来源</li></ol></div></section>
    </>
  );
}

const releaseGroups = [
  {
    index: "01",
    title: "桌面客户端",
    description: "面向日常存证和离线验证的图形客户端。macOS 与 Windows 各架构独立发布。",
    assets: [
      ["macOS", "Apple Silicon · arm64", "DMG · ZIP · CER", "自签名客户端"],
      ["macOS", "Intel · x86_64", "DMG · ZIP · CER", "自签名客户端"],
      ["Windows", "ARM64", "MSI · SETUP.EXE · EXE · ZIP · CER", "自签名客户端"],
      ["Windows", "x86-64 · amd64", "MSI · SETUP.EXE · EXE · ZIP · CER", "自签名客户端"],
    ],
  },
  {
    index: "02",
    title: "服务器与 CLI",
    description: "同一份版本同时提供 trustdb 服务器和命令行工具，方便直接部署或集成到自动化任务。",
    assets: [
      ["Linux", "amd64", "tar.gz", "Server · CLI"],
      ["Linux", "arm64", "tar.gz", "Server · CLI"],
      ["macOS", "Apple Silicon · arm64", "tar.gz", "Server · CLI"],
      ["macOS", "Intel · x86_64", "tar.gz", "Server · CLI"],
      ["Windows", "ARM64", "ZIP", "Server · CLI"],
      ["Windows", "x86-64 · amd64", "ZIP", "Server · CLI"],
    ],
  },
  {
    index: "03",
    title: "容器与发布资料",
    description: "Docker Hub 多架构镜像、校验资料和构建溯源随版本一起发布。",
    assets: [
      ["Docker Hub", "linux/amd64 · linux/arm64", "wsy19990317/trustdb", "1.0.0-beta · beta"],
      ["校验与溯源", "全部下载产物", "SHA256SUMS", "版本 · 提交 · 架构"],
      ["容器供应链", "多架构镜像", "SBOM · provenance", "构建来源"],
    ],
  },
];

export function DownloadsPage() {
  return (
    <>
      <PageHero eyebrow="Downloads" title={<>1.0.0-beta，<br />开放下载。</>} lead="桌面客户端、服务器、CLI 和 Docker 镜像使用同一份版本与提交。桌面包采用自签名证书；下载后请先核对 SHA256SUMS。" meta="公开测试版 · 2026.07.20">
        <div className="page-hero__actions"><a className="button button--solid" href="https://github.com/ryan-wong-coder/trustdb/releases/tag/v1.0.0-beta" target="_blank" rel="noreferrer"><DownloadSimple /> 下载 1.0.0-beta <ArrowRight /></a><a className="button button--ghost" href="https://hub.docker.com/r/wsy19990317/trustdb" target="_blank" rel="noreferrer">Docker Hub</a></div>
      </PageHero>
      <section className="empty-release section-shell">
        <div className="empty-release__mark" data-reveal><DownloadSimple /></div>
        <div className="empty-release__copy" data-reveal><p>Public beta</p><h2>按系统选择，<br />不用自己编译。</h2><span>GitHub Release 提供全部安装包、服务端与 CLI 归档以及统一校验文件。Docker Hub 同步提供 amd64 与 arm64 镜像。</span></div>
        <a className="empty-release__watch" href="https://github.com/ryan-wong-coder/trustdb/releases/tag/v1.0.0-beta" target="_blank" rel="noreferrer"><GithubLogo weight="fill" /> 打开 GitHub Release <ArrowRight /></a>
      </section>
      <section className="asset-plan">
        <div className="section-shell">
          <div className="asset-plan__heading" data-reveal><p>Release assets</p><h2>客户端、服务端，<br />以及完整发布资料。</h2></div>
          <div className="release-groups">
            {releaseGroups.map((group) => (
              <section className="release-group" key={group.title} data-reveal>
                <header><span>{group.index}</span><div><Package /><h3>{group.title}</h3></div><p>{group.description}</p></header>
                <div className="asset-matrix">
                  <div className="asset-matrix__head"><span>系统 / 资源</span><span>架构</span><span>格式</span><span>包含</span></div>
                  {group.assets.map(([platform, arch, format, included]) => <div className="asset-matrix__row" key={`${platform}-${arch}`}><strong>{platform}</strong><span>{arch}</span><code>{format}</code><p>{included}</p><b>1.0.0-beta</b></div>)}
                </div>
              </section>
            ))}
          </div>
        </div>
      </section>
      <section className="source-build section-shell">
        <div data-reveal><p>Build from source</p><h2>现在可以做什么。</h2></div>
        <div className="source-build__steps" data-reveal><p><span>01</span><strong>CLI / Server</strong><code>go build ./cmd/trustdb</code></p><p><span>02</span><strong>Desktop</strong><code>cd clients/desktop && wails build</code></p><p><span>03</span><strong>Verify</strong><code>go test ./...</code></p></div>
        <div className="source-build__note"><Check /><span>公开测试版尚未取得 Apple 或 Microsoft 商业签名。自签名能校验文件是否被改动，但不会消除系统的未知开发者提示。</span></div>
        <div className="source-build__links"><InlineLink href="/docs/quick-start">快速开始</InlineLink><InlineLink href="/docs/desktop">桌面客户端文档</InlineLink><InlineLink href="/changelog">开发日志</InlineLink></div>
      </section>
    </>
  );
}
