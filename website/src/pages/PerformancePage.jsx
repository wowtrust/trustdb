import { ArrowRight } from "@phosphor-icons/react";
import { PageHero } from "../components/SiteChrome";

export function PerformancePage() {
  return (
    <PageHero eyebrow="Performance / Sustained gRPC" title={<>60,528<small> QPS</small></>} lead="双机持续压测中，TrustDB 每秒完成 60,528 次有效提交。" meta="2026.07.16 · gRPC · 持续写入">
      <div className="page-hero__actions">
        <a className="button button--solid" href="https://github.com/ryan-wong-coder/trustdb/blob/main/docs/performance/trustdb-performance-report-2026-07-16.zh-CN.md" target="_blank" rel="noreferrer">查看完整报告 <ArrowRight /></a>
      </div>
      <div className="performance-proofline" aria-label="测试概况">
        <div><strong>2,675,000</strong><span>有效提交</span></div>
        <div><strong>0</strong><span>失败</span></div>
        <div><strong>60,528/s</strong><span>持续 gRPC</span></div>
      </div>
    </PageHero>
  );
}
