import { ArrowRight, Gauge, HardDrives } from "@phosphor-icons/react";
import { InlineLink, PageHero } from "../components/SiteChrome";
import { Link } from "../router";

const transportMetrics = [
  ["gRPC · submit", 60528, "60,528 /s", "HTTP / gRPC 同证明语义"],
  ["HTTP · submit", 55125, "55,125 /s", "持续提交吞吐"],
  ["gRPC · L3", 20127, "20,127 /s", "证明已物化"],
  ["HTTP · L3", 14797, "14,797 /s", "证明已物化"],
];

const profiles = [
  ["balanced", "37,443", "6,377 L4/s", "group fsync · 平衡写入与证明"],
  ["production-safe", "23,562", "4,569 L4/s", "持久化 L4/L5 端到端基线"],
  ["production-guaranteed", "1,043", "1,033 L4/s", "strict fsync · 完整索引"],
  ["strict + real OTS", "—", "143.7 L5/s", "汇总树根锚定；10 / 10 成功"],
];

export function PerformancePage() {
  const max = Math.max(...transportMetrics.map(([, value]) => value));
  return (
    <>
      <PageHero eyebrow="Performance / Sustained gRPC" title={<>60,528<small> QPS</small></>} lead="双机持续压测中，TrustDB 每秒完成 60,528 次有效提交；2,675,000 次提交，0 次失败。" meta="2026.07.16 · gRPC · 持续写入">
        <div className="page-hero__actions"><a className="button button--solid" href="https://github.com/ryan-wong-coder/trustdb/blob/main/docs/performance/trustdb-performance-report-2026-07-16.zh-CN.md" target="_blank" rel="noreferrer">完整报告 <ArrowRight /></a><Link className="button button--ghost" href="/docs/server">部署文档</Link></div>
      </PageHero>

      <section className="perf-report section-shell">
        <div className="perf-report__heading" data-reveal><p>Executive summary</p><h2>六个维度，<br />一起读。</h2><span>任何单一 QPS 都无法描述一个证据数据库。下面的结论共享同一批双机实验背景，但适用配置不同。</span></div>
        <div className="perf-report__grid">
          <article data-reveal><span>INGEST</span><strong>60,528/s</strong><h3>持续提交</h3><p>gRPC 最高持续 submit；HTTP 为 55,125/s。</p></article>
          <article data-reveal><span>PROOF READY</span><strong>20,127/s</strong><h3>L3 物化</h3><p>gRPC 下证明已经生成并可读取，不只拿到 L2 收据。</p></article>
          <article data-reveal><span>DURABILITY</span><strong>1,043/s</strong><h3>严格写盘配置</h3><p>strict fsync 与完整索引下 1,033 L4/s。</p></article>
          <article data-reveal><span>TRANSPARENCY</span><strong>6,377/s</strong><h3>平衡 L4</h3><p>balanced 配置下进入全局透明日志的证明吞吐。</p></article>
          <article data-reveal><span>EXTERNAL TIME</span><strong>143.7/s</strong><h3>汇总树根锚定</h3><p>处理的是已经汇总过的少量树根，不是逐个处理原始文件。</p></article>
          <article data-reveal><span>STORAGE</span><strong>40 tiles</strong><h3>历史树压缩</h3><p>8192 叶批次从约 24,575 个历史对象降至 40 个。</p></article>
        </div>
        <aside className="perf-report__note" data-reveal><strong>为什么 143.7/s 不能和写入吞吐直接相比？</strong><p>大量记录会先汇总成批次根，再汇总成全局树根，最后才交给 OpenTimestamps。这个数字衡量的是汇总结果的锚定速度，不是原始文件的处理上限。</p></aside>
      </section>

      <section className="perf-overview section-shell">
        <div className="perf-overview__heading" data-reveal><p>Sustained throughput</p><h2>吞吐与证明，<br />分开衡量。</h2><span>提交成功并不代表高等级证明已经可读。这里把 submit 与 L3 materialized 分列。</span></div>
        <div className="metric-bars" data-reveal>
          {transportMetrics.map(([label, value, display, note]) => (
            <div className="metric-bar" key={label}>
              <div><strong>{label}</strong><b>{display}</b></div>
              <div className="metric-bar__track"><i className="metric-bar__fill" style={{ "--metric-scale": value / max }} /></div>
              <span>{note}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="perf-proof">
        <div className="section-shell">
          <div className="perf-stat-grid">
            <article data-reveal><span>01</span><strong>2,675,000</strong><p>有效提交样本</p><small>所有统计均来自完整报告中的双机实验。</small></article>
            <article data-reveal><span>02</span><strong>0</strong><p>提交失败</p><small>报告覆盖的有效工作负载中没有失败提交。</small></article>
            <article data-reveal><span>03</span><strong>40</strong><p>8192 叶批次的历史 tiles</p><small>从约 24,575 个历史对象降到 40 个。</small></article>
            <article data-reveal><span>04</span><strong>143.7/s</strong><p>汇总树根锚定</p><small>数据已经逐级汇总；10 / 10 锚定成功。</small></article>
          </div>
        </div>
      </section>

      <section className="profile-section section-shell">
        <div className="profile-section__heading" data-reveal><p>Operational profiles</p><h2>你选择的耐久性，<br />决定数字的含义。</h2></div>
        <div className="profile-table" data-reveal>
          <div className="profile-table__head"><span>配置</span><span>提交吞吐</span><span>证明吞吐</span><span>适用场景</span></div>
          {profiles.map(([name, submit, proof, note]) => <div key={name}><strong>{name}</strong><b>{submit}</b><b>{proof}</b><p>{note}</p></div>)}
        </div>
      </section>

      <section className="pipeline-report">
        <div className="section-shell pipeline-report__layout">
          <div className="pipeline-report__heading" data-reveal><HardDrives /><p>Implementation report</p><h2>瓶颈被拆成了<br />可调的流水线。</h2></div>
          <div className="pipeline-report__steps">
            <article data-reveal><span>01</span><h3>Plan</h3><p>接收记录先安全写入，再安排批次，避免证明计算拖慢所有请求。</p></article>
            <article data-reveal><span>02</span><h3>Materialize</h3><p>有界 worker 异步生成 Merkle proofs，manifest 让任务可恢复。</p></article>
            <article data-reveal><span>03</span><h3>Global log</h3><p>批次根成组进入透明日志，history tiles 控制对象数量与读放大。</p></article>
            <article data-reveal><span>04</span><h3>Anchor</h3><p>独立 OTS workers 发布与升级锚定，不把公共日历网络延迟扩散到 ingest。</p></article>
          </div>
        </div>
      </section>

      <section className="testbed section-shell">
        <div className="testbed__title" data-reveal><Gauge /><p>Test environment</p><h2>基准环境</h2></div>
        <div className="testbed__facts" data-reveal><div><strong>32 vCPU</strong><span>计算节点</span></div><div><strong>61 GiB</strong><span>内存</span></div><div><strong>Go 1.26.3</strong><span>运行时</span></div><div><strong>0.158 ms</strong><span>VPC RTT</span></div><div><strong>70 GiB</strong><span>云盘</span></div><div><strong>OpenCloudOS 9.6</strong><span>系统</span></div></div>
        <div className="testbed__links"><InlineLink href="https://github.com/ryan-wong-coder/trustdb/blob/main/docs/performance/trustdb-performance-report-2026-07-16.zh-CN.md">完整测试报告</InlineLink><InlineLink href="https://github.com/ryan-wong-coder/trustdb/blob/main/docs/performance/trustdb-performance-optimization-2026-07.zh-CN.md">实现与优化说明</InlineLink></div>
      </section>
    </>
  );
}
