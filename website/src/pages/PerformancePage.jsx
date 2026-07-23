import { ArrowRight } from "@phosphor-icons/react";
import { PageHero } from "../components/SiteChrome";

export function PerformancePage() {
  return (
    <PageHero eyebrow="Performance / Evidence paths" title={<>56,576<small> submit/s</small></>} lead="同一份双机评估同时给出瞬时 L2、持续 L3、完整索引 L4 与 covering-anchor L5，让吞吐数字始终对应明确的证据语义。" meta="2026.07.23 · current main · dual host">
      <div className="page-hero__actions">
        <a className="button button--solid" href="https://github.com/wowtrust/trustdb/blob/main/docs/performance/trustdb-sustained-stream-persistence-assessment-2026-07-23.zh-CN.md" target="_blank" rel="noreferrer">查看唯一性能口径 <ArrowRight /></a>
      </div>
      <div className="performance-proofline" aria-label="测试概况">
        <div><strong>7,311,000</strong><span>当前版本提交</span></div>
        <div><strong>5,473/s</strong><span>500k gRPC L3</span></div>
        <div><strong>2,237/s</strong><span>500k full-index L4</span></div>
      </div>
    </PageHero>
  );
}
