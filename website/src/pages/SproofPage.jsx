import { ArrowRight, BracketsCurly, CheckCircle, FileLock, ShieldCheck } from "@phosphor-icons/react";
import { CodeBlock, InlineLink, PageHero } from "../components/SiteChrome";
import { Link } from "../router";

const schemaFields = [
  ["schema_version", "text", "固定为 trustdb.sproof.v2", "required"],
  ["format_version", "uint", "固定为 2", "required"],
  ["crypto_suite", "text", "INTL_V1 或 CN_SM_V1", "required"],
  ["record_id", "text", "证据记录标识", "required"],
  ["proof_level", "text", "声明等级；验证器必须复算", "required"],
  ["node_id / log_id", "text", "所有嵌套对象必须精确匹配", "required"],
  ["proof_bundle", "map", "L3 ProofBundle", "required"],
  ["global_proof", "map", "L4 GlobalLogProof", "optional"],
  ["anchor_result", "map", "L5 STHAnchorResult", "optional"],
  ["identity_evidence", "array", "有界公开身份与状态证据", "optional"],
  ["exported_at_unix_nano", "int", "导出时间，不参与等级提升", "optional"],
];

const validationSteps = ["解码前限制完整输入不超过 24 MiB", "校验 v2 schema、format 与 canonical CBOR", "要求整条证据只使用一个 crypto suite", "验证 NodeID、LogID 与 record_id 精确绑定", "验证客户端签名、证书状态与密钥生命周期", "验证服务端 accepted/committed receipt", "重新计算 L3 Merkle 包含证明", "若存在，验证 L4 全局日志证明与精确 STH", "若存在，离线验证精确匹配的 L5 锚定结果", "按实际材料重新计算证明等级", "拒绝旧 v1、混合 suite、悬空 anchor 或自报升级"];

export function SproofPage() {
  return (
    <>
      <PageHero eyebrow="Current exchange format / v2" title={<><span className="acid">.</span>sproof</>} lead="把 suite-bound L1–L5 材料和可选身份状态证据装进一个确定性 CBOR 文件，让证据离开 TrustDB 服务后仍能独立复算。" meta="schema: trustdb.sproof.v2 · format_version: 2 · max decode: 24 MiB">
        <div className="page-hero__actions"><a className="button button--solid" href="https://github.com/wowtrust/trustdb/blob/main/formats/SPROOF_V2.md" target="_blank" rel="noreferrer">查看规范原文 <ArrowRight /></a><Link className="button button--ghost" href="/docs/cli">CLI 验证</Link></div>
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
          <div className="validation-section__heading" data-reveal><ShieldCheck weight="fill" /><p>Verifier algorithm</p><h2>十一阶段复算，<br />拒绝自报等级。</h2></div>
          <ol className="validation-list">{validationSteps.map((step, index) => <li key={step} data-reveal><span>{String(index + 1).padStart(2, "0")}</span><p>{step}</p><CheckCircle /></li>)}</ol>
        </div>
      </section>

      <section className="format-cli section-shell">
        <div className="format-cli__copy" data-reveal><FileLock /><p>Offline verification</p><h2>离开服务端，<br />仍然成立。</h2><span>原文件、.sproof 与验证者本地取得的可信公钥、CA、registry 或 anchor TrustConfig 完成本地验证；文件自带材料不能授权自己。</span></div>
        <div><CodeBlock>trustdb verify \{"\n"}  --file ./document.pdf \{"\n"}  --sproof ./document.sproof \{"\n"}  --server-public-key ./server.pub \{"\n"}  --client-public-key ./client.pub</CodeBlock><CodeBlock label="format tests">go test ./internal/sproof ./internal/verify{"\n"}# v2 reader 只接受 schema/version 2，并拒绝旧 v1 回退</CodeBlock></div>
      </section>

      <section className="format-links section-shell"><InlineLink href="https://github.com/wowtrust/trustdb/blob/main/formats/SPROOF_V2.md">完整 v2 规范</InlineLink><InlineLink href="https://github.com/wowtrust/trustdb/tree/main/test/vectors">密码套件向量</InlineLink><InlineLink href="/docs/sdk">SDK 导出接口</InlineLink></section>
    </>
  );
}
