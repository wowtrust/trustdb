import { ArrowRight, BracketsCurly, CheckCircle, FileLock, ShieldCheck } from "@phosphor-icons/react";
import { CodeBlock, InlineLink, PageHero } from "../components/SiteChrome";
import { Link } from "../router";

const schemaFields = [
  ["schema_version", "text", "固定为 trustdb.sproof.v1", "required"],
  ["format_version", "uint", "固定为 1", "required"],
  ["record_id", "text", "证据记录标识", "required"],
  ["proof_level", "text", "声明等级；验证器必须复算", "required"],
  ["node_id / log_id", "text", "分布式来源身份", "optional"],
  ["proof_bundle", "map", "L3 ProofBundle", "required"],
  ["global_proof", "map", "L4 GlobalLogProof", "optional"],
  ["anchor_result", "map", "L5 STHAnchorResult", "optional"],
  ["exported_at", "int", "导出时间，不参与等级提升", "optional"],
];

const validationSteps = ["解码并限制输入不超过 16 MiB", "校验 schema_version 与 format_version", "验证 record_id 一致性", "验证客户端签名与密钥状态", "验证服务端收据签名", "重新计算 L3 Merkle 包含证明", "若存在，验证 L4 全局日志证明与 STH", "若存在，验证 L5 锚定结果", "按实际材料重新计算证明等级", "拒绝结构冲突、悬空 anchor 或自报升级"];

export function SproofPage() {
  return (
    <>
      <PageHero eyebrow="Stable exchange format / v1" title={<><span className="acid">.</span>sproof</>} lead="把 L3、L4 与 L5 材料装进一个确定性 CBOR 文件，让证据离开 TrustDB 服务后仍能独立复算。" meta="schema: trustdb.sproof.v1 · format_version: 1 · max decode: 16 MiB">
        <div className="page-hero__actions"><a className="button button--solid" href="https://github.com/wowtrust/trustdb/blob/main/formats/SPROOF_V1.md" target="_blank" rel="noreferrer">查看规范原文 <ArrowRight /></a><Link className="button button--ghost" href="/docs/cli">CLI 验证</Link></div>
      </PageHero>

      <section className="format-intro section-shell">
        <div data-reveal><p>One file / independently verifiable</p><h2>容器不决定等级。<br />材料决定。</h2></div>
        <div className="format-stack" data-reveal>
          <div><span>L5</span><strong>anchor_result</strong><small>外部时间边界</small></div>
          <div><span>L4</span><strong>global_proof</strong><small>全局透明日志</small></div>
          <div><span>L3</span><strong>proof_bundle</strong><small>批次 Merkle 包含证明</small></div>
          <i aria-hidden="true" />
        </div>
      </section>

      <section className="grade-rules">
        <div className="section-shell">
          <div className="grade-rules__heading" data-reveal><p>Grade caps</p><h2>等级上限是验证结果，<br />不是输入字段。</h2></div>
          <div className="grade-rules__grid">
            <article data-reveal><span>L3</span><h3>Bundle only</h3><p>仅有 proof_bundle，最高为 L3。</p></article>
            <article data-reveal><span>L4</span><h3>Bundle + global</h3><p>有效 GlobalLogProof 与 STH 将上限提升到 L4。</p></article>
            <article data-reveal><span>L5</span><h3>Bundle + global + anchor</h3><p>有效外部锚定覆盖同一 STH / global root，才能得到 L5。</p></article>
            <article className="invalid" data-reveal><span>×</span><h3>Anchor without global</h3><p>anchor_result 没有对应 global_proof 时结构无效，必须拒绝。</p></article>
          </div>
        </div>
      </section>

      <section className="schema-section section-shell">
        <div className="schema-section__heading" data-reveal><BracketsCurly /><p>Top-level schema</p><h2>字段结构</h2></div>
        <div className="schema-table" data-reveal>{schemaFields.map(([name, type, desc, required]) => <div key={name}><code>{name}</code><b>{type}</b><p>{desc}</p><span className={required}>{required}</span></div>)}</div>
      </section>

      <section className="validation-section">
        <div className="section-shell validation-section__layout">
          <div className="validation-section__heading" data-reveal><ShieldCheck weight="fill" /><p>Verifier algorithm</p><h2>十步复算，<br />拒绝自报等级。</h2></div>
          <ol className="validation-list">{validationSteps.map((step, index) => <li key={step} data-reveal><span>{String(index + 1).padStart(2, "0")}</span><p>{step}</p><CheckCircle /></li>)}</ol>
        </div>
      </section>

      <section className="format-cli section-shell">
        <div className="format-cli__copy" data-reveal><FileLock /><p>Offline verification</p><h2>离开服务端，<br />仍然成立。</h2><span>原文件、.sproof、客户端与服务端公钥足以完成本地验证；密钥注册表可替代显式客户端公钥。</span></div>
        <div><CodeBlock>trustdb verify \{"\n"}  --file ./document.pdf \{"\n"}  --sproof ./document.sproof \{"\n"}  --server-public-key ./server.pub \{"\n"}  --client-public-key ./client.pub</CodeBlock><CodeBlock label="test vector">sha256  test/vectors/sproof-v1-l3.cbor{"\n"}# 规范仓库包含可复算的 L3 测试向量</CodeBlock></div>
      </section>

      <section className="format-links section-shell"><InlineLink href="https://github.com/wowtrust/trustdb/blob/main/formats/SPROOF_V1.md">完整 v1 规范</InlineLink><InlineLink href="https://github.com/wowtrust/trustdb/tree/main/test/vectors">测试向量</InlineLink><InlineLink href="/docs/sdk">SDK 导出接口</InlineLink></section>
    </>
  );
}
