import { ArrowRight, Check, DownloadSimple, GithubLogo, Package, WarningCircle } from "@phosphor-icons/react";
import { InlineLink, PageHero } from "../components/SiteChrome";
import { binaryDownloads, checksumsAsset, desktopDownloads, release } from "../lib/release";
import { Link } from "../router";

const milestones = [
  ["2026.07.20", "v1.0.0-beta.1", "第二个公开测试版：官网、桌面客户端与 Admin Web 支持六种语言，官网按语言展示真实客户端画面，并补齐页签图标。", "Beta.1"],
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
      <PageHero eyebrow="Development log" title={<>TrustDB<br />版本记录。</>} lead="按版本记录功能变化、兼容性要求、已知问题和下载信息。" meta="开发日志 · 更新于 2026.07.20">
        <div className="page-hero__actions"><Link className="button button--solid" href="/downloads">下载 1.0.0-beta.1 <ArrowRight /></Link><a className="button button--ghost" href="https://github.com/ryan-wong-coder/trustdb/commits/main" target="_blank" rel="noreferrer">全部提交</a></div>
      </PageHero>
      <section className="release-state section-shell" data-reveal><WarningCircle /><div><p>Release status</p><h2>1.0.0-beta.1 已进入公开测试</h2><span>桌面客户端采用自签名证书，系统仍会提示未知开发者；请从 GitHub Release 下载并核对 SHA-256。</span></div><Link href="/downloads">查看全部产物 <ArrowRight /></Link></section>
      <section className="timeline section-shell">
        <div className="timeline__heading" data-reveal><p>Development milestones</p><h2>版本变更</h2></div>
        <div className="timeline__list">{milestones.map(([date, title, description, ref], index) => <article key={`${date}-${title}`} data-reveal><span>{String(index + 1).padStart(2, "0")}</span><time>{date}</time><div><h3>{title}</h3><p>{description}</p></div><b>{ref}</b></article>)}</div>
      </section>
      <section className="release-policy"><div className="section-shell release-policy__layout"><div data-reveal><p>Release notes</p><h2>发布说明</h2></div><ol data-reveal><li><span>01</span>这个版本包含什么</li><li><span>02</span>兼容性与迁移要求</li><li><span>03</span>已知问题与安全边界</li><li><span>04</span>各平台下载与 SHA-256</li><li><span>05</span>源码、SBOM 与构建来源</li></ol></div></section>
    </>
  );
}

const releaseGroups = [
  {
    index: "01",
    title: "桌面客户端",
    description: "面向日常存证和离线验证的图形客户端。安装包采用自签名证书，证书与指纹可单独下载。",
    assets: desktopDownloads,
  },
  {
    index: "02",
    title: "服务器与 CLI",
    description: "压缩包同时包含 trustdb 二进制文件、生产配置和 Admin Web，无需安装 Go 工具链。",
    assets: binaryDownloads,
  },
];

export function DownloadsPage() {
  return (
    <>
      <PageHero eyebrow="Downloads" title={<>{release.version}，<br />开放下载。</>} lead="桌面客户端、服务器、CLI 和 Docker 镜像使用同一份版本与提交。按系统直接下载；安装前可用 SHA256SUMS 核对文件。" meta={`公开测试版 · ${release.published}`}>
        <div className="page-hero__actions"><a className="button button--solid" href={checksumsAsset.url}><DownloadSimple /> 下载 SHA256SUMS</a><a className="button button--ghost" href={release.dockerUrl} target="_blank" rel="noreferrer">Docker Hub</a></div>
      </PageHero>
      <section className="empty-release section-shell">
        <div className="empty-release__mark" data-reveal><DownloadSimple /></div>
        <div className="empty-release__copy" data-reveal><p>Public beta</p><h2>按系统选择。</h2><span>GitHub Release 提供全部安装包、服务端与 CLI 归档以及统一校验文件。Docker Hub 同步提供 amd64 与 arm64 镜像。</span></div>
        <a className="empty-release__watch" href={release.pageUrl} target="_blank" rel="noreferrer"><GithubLogo weight="fill" /> 打开 GitHub Release <ArrowRight /></a>
      </section>
      <section className="asset-plan" id="release-assets">
        <div className="section-shell">
          <div className="asset-plan__heading" data-reveal><p>Release assets</p><h2>客户端、服务端，<br />以及完整发布资料。</h2></div>
          <div className="release-groups">
            {releaseGroups.map((group) => (
              <section className="release-group" key={group.title} data-reveal>
                <header><span>{group.index}</span><div><Package /><h3>{group.title}</h3></div><p>{group.description}</p></header>
                <div className="asset-matrix">
                  <div className="asset-matrix__head"><span>系统</span><span>架构</span><span>格式</span><span>包含</span><span>下载与资料</span></div>
                  {group.assets.map((asset) => (
                    <div className="asset-matrix__row" key={`${asset.platform}-${asset.arch}`}>
                      <strong>{asset.platform}</strong><span>{asset.arch}</span><code>{asset.format}</code><p>{asset.description}</p>
                      <div className="asset-matrix__actions">
                        <a className="asset-matrix__primary" href={asset.primary.url} title={asset.primary.filename}>{asset.primary.label}<DownloadSimple /></a>
                        {asset.extras?.length > 0 && <div>{asset.extras.map((extra) => <a href={extra.url} key={extra.filename} title={extra.filename}>{extra.label}</a>)}</div>}
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            ))}
          </div>
          <section className="release-support" data-reveal>
            <div><span>03</span><Package /><h3>容器与校验资料</h3></div>
            <p>Docker Hub 提供 linux/amd64 与 linux/arm64 镜像；GitHub Release 提供所有文件的统一校验清单。</p>
            <div><a href={release.dockerUrl} target="_blank" rel="noreferrer">Docker Hub <ArrowRight /></a><a href={checksumsAsset.url}>SHA256SUMS <DownloadSimple /></a></div>
          </section>
        </div>
      </section>
      <section className="source-build section-shell">
        <div data-reveal><p>Build from source</p><h2>源码构建</h2></div>
        <div className="source-build__steps" data-reveal><p><span>01</span><strong>服务器与 CLI</strong><code>Go 1.26.5</code></p><p><span>02</span><strong>桌面客户端</strong><code>Wails 2.12.0 · Node.js 24</code></p><p><span>03</span><strong>测试</strong><code>go test ./...</code></p></div>
        <div className="source-build__note"><Check /><span>公开测试版尚未取得 Apple 或 Microsoft 商业签名。请用 SHA256SUMS 核对下载文件；随包提供的证书和指纹可用于核对本次发布所用的签名证书。</span></div>
        <div className="source-build__links"><InlineLink href="/docs/quick-start">快速开始</InlineLink><InlineLink href="/docs/desktop-install">安装桌面客户端</InlineLink><InlineLink href="/docs/source-build">从源码构建</InlineLink><InlineLink href="/changelog">开发日志</InlineLink></div>
      </section>
    </>
  );
}
