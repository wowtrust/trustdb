# TrustDB UI 全量现代化落地说明

## 目标

在保留 TrustDB 黑色底、荧光绿色、可验证证据链这一核心识别的前提下，完成三套可运行界面：

1. 桌面客户端：证据链工作台与当前存证检查器。
2. Web 管理端：实时证明流水线与异常批次控制台。
3. 官方网站：低信息密度、高留白的产品叙事与快速上手入口。

视觉参考以 Datalands 的暗色数据场、超大排版、绿色信号线和克制的工业界面为基础，但所有页面均按 TrustDB 的产品语义重新组织。

## 最终截图

- 客户端：[`design/qa/desktop-implementation-final.png`](qa/desktop-implementation-final.png)
- Web 管理端：[`design/qa/admin-implementation-final.png`](qa/admin-implementation-final.png)
- 官网首屏：[`design/qa/website-implementation-hero-final.png`](qa/website-implementation-hero-final.png)
- 官网证明模型：[`design/qa/website-implementation-proof-final.png`](qa/website-implementation-proof-final.png)
- 官网证据旅程：[`design/qa/website-implementation-journey-final.png`](qa/website-implementation-journey-final.png)
- 官网快速上手：[`design/qa/website-implementation-quick-final.png`](qa/website-implementation-quick-final.png)
- 官网移动端：[`design/qa/website-implementation-mobile.png`](qa/website-implementation-mobile.png)

## 视觉系统

### 色彩

- 主背景：`#010302` / `#020302`
- 主品牌绿：`#00ff22`
- 官网高光绿：`#84ff5c`
- 主文字：`#f1f4ed`
- 次级文字：低饱和灰绿
- 异常状态：橙色，仅用于异常批次、延迟和待处理状态

### 排版与空间

- 设备名、系统状态与官网主标题使用超大无衬线排版，避免传统卡片堆叠。
- 客户端 `DESKTOP-1` 使用纵向透明度渐隐；客户端与管理端主画布都取消绿色点阵/扫描纹理，回归纯黑空间。
- 官网以完整视口为叙事单位，证明模型和证据旅程之间保留大量呼吸空间。
- 表格、证明阶段和检查器采用精细发丝线分区，不使用厚重圆角卡片。

### 图标与图像

- 客户端和管理端的功能图标使用 Lucide，同一套线宽与视觉尺寸。
- 官网操作图标使用 Phosphor Icons。
- 官网三张数据场视觉由 ImageGen 生成，并按各自插槽比例直接使用：
  - `website/src/assets/generated/trustdb-hero-landscape.png`
  - `website/src/assets/generated/trustdb-evidence-field.png`
  - `website/src/assets/generated/trustdb-terminal-landscape.png`

## 动效系统

静态美术由 ImageGen 提供；需要持续运动和实时反馈的部分使用代码绘制。

- 官网首屏：Canvas 贝塞尔信号线与移动验证节点。
- 官网证据旅程：Canvas 粒子流与 ImageGen 数据场叠加。
- 官网滚动：GSAP ScrollTrigger 完成分段揭示、视差和证明等级错峰进入。
- 客户端：GSAP 驱动 L1–L5 信号节点、当前等级呼吸环和光点沿证明链移动。
- 管理端：GSAP 驱动实时流水线光点、异常 BATCH 呼吸环和首屏序列入场。
- 所有界面均包含 `prefers-reduced-motion` 降级逻辑；客户端在后台标签页跳过透明度入场，避免页面被浏览器节流后停在不可见状态。

## 关键交互

### 客户端

- 侧栏主路由可用。
- 最近存证行可选择，并联动右侧文件、证明等级、阶段时间线和事件。
- L5 已锚定记录会显示完整完成态，L1–L4 保留进行中语义。
- 原生 Wails 桥接不存在时使用安全浏览器演示态；原生运行时继续加载真实设置、身份和记录。

### Web 管理端

- 顶部导航可切换指标、记录、批次、全局树和系统设置。
- “检查异常”可触发真实刷新；演示模式不请求未启动的本地后端。
- 异常批次、流水线、最新记录与证明等级共享同一实时状态语义。

### 官网

- 主导航和 CTA 使用锚点平滑滚动。
- GitHub 按钮指向当前项目仓库。
- 终端命令支持复制，并提供“命令已复制”的可访问反馈。

## 运行方式

```bash
# 官网
cd website
npm install
npm run dev

# Web 管理端演示
cd clients/web
npm install
VITE_TRUSTDB_DEMO=1 npm run dev

# 客户端浏览器演示（原生桌面仍按现有 Wails 流程运行）
cd clients/desktop/frontend
npm install
VITE_TRUSTDB_DEMO=1 npm run dev
```

当前本地验收地址：

- 官网：<http://localhost:4173/>
- Web 管理端：<http://localhost:4174/admin/dashboard>
- 客户端 UI：<http://localhost:4175/#/dashboard>

## 主要代码位置

- 官网：`website/src/App.jsx`、`website/src/styles.css`
- 客户端：`clients/desktop/frontend/src/pages/Dashboard.vue`、`clients/desktop/frontend/src/style.css`
- Web 管理端：`clients/web/src/pages/Dashboard.vue`、`clients/web/src/components/AdminHeader.vue`、`clients/web/src/style.css`

## 验证

- 官网生产构建通过。
- 客户端生产构建通过。
- Web 管理端生产构建通过。
- Web 管理端 9 个测试文件、23 个单元测试通过。
- Go 全仓测试通过。
- 详细视觉对比与交互验收见项目根目录 [`design-qa.md`](../design-qa.md)。
