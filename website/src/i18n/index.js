import { useSyncExternalStore } from "react";

export const localeOptions = [
  { code: "zh-CN", label: "简体中文", short: "中" },
  { code: "en", label: "English", short: "EN" },
  { code: "ru", label: "Русский", short: "RU" },
  { code: "ja", label: "日本語", short: "日" },
  { code: "fr", label: "Français", short: "FR" },
  { code: "ko", label: "한국어", short: "한" },
];

const manualMessages = {
  en: {
    "可验证证据数据库": "Verifiable evidence database",
    "产品": "Product", "文档": "Docs", "性能": "Performance", "版本": "Releases", "下载": "Download",
    "文档中心": "Documentation", "版本与下载": "Releases & downloads", "源码": "Source", "参与贡献": "Contribute",
    "GitHub Release 提供安装包、服务端与 CLI 归档以及统一校验文件；WowTrust GHCR 提供 amd64 与 arm64 组织镜像。": "GitHub Releases provide installers, server and CLI archives, and unified checksums; WowTrust GHCR provides the organization-owned amd64 and arm64 images.",
    "WowTrust GHCR 是默认组织镜像，Docker Hub 同步保留同版本的 linux/amd64 与 linux/arm64 镜像。": "WowTrust GHCR is the primary organization registry; Docker Hub mirrors the same linux/amd64 and linux/arm64 versions.",
    "开始使用": "Get started", "返回首页": "Back home", "开发日志": "Changelog",
    "打开 TrustDB GitHub 仓库": "Open the TrustDB GitHub repository",
    "感谢 LINUX DO 社区": "Thanks to the LINUX DO community", "访问 LINUX DO 社区": "Visit the LINUX DO community",
    "主导航": "Main navigation", "移动导航": "Mobile navigation", "页脚导航": "Footer navigation",
    "语言": "Language",
    "有据可查": "Evidence you can verify.", "五级证明，": "Five proof levels,", "一条证据链。": "one evidence chain.",
    "签名": "Signature", "收据": "Receipt", "锚定": "Anchoring", "外部锚定": "External anchoring",
    "查看 1.0.0 正式版的各平台构建产物与校验资料。": "View builds and checksums for the stable 1.0.0 release.",
    "首个正式版：新 Go module 路径、持久化 STH 合并锚定、完整离线证据、存储 schema v4 与逻辑备份。": "First stable release: new Go module path, durable coalesced STH anchoring, complete offline evidence, storage schema v4, and logical backups.",
    "下载 1.0.0": "Download 1.0.0", "1.0.0 正式版已发布": "1.0.0 stable is now available", "正式版 ·": "Stable ·",
    "服务端、CLI、SDK 与证据格式进入首个稳定版本；桌面客户端仍采用自签名证书，请从 GitHub Release 下载并核对 SHA-256。": "The server, CLI, SDK, and evidence formats have reached their first stable release. Desktop packages remain self-signed; download them from GitHub Releases and verify SHA-256.",
    "在 macOS 与 Windows 安装自签名桌面客户端。": "Install the self-signed desktop client on macOS and Windows.",
    "TrustDB v1.0.0 使用 WowTrust 组织下的正式 Go module 路径。生产项目应固定具体版本，保证依赖解析与构建可复现。": "TrustDB v1.0.0 uses the official Go module path under the WowTrust organization. Pin an exact version in production for reproducible dependency resolution and builds.",
    "v1.0.0 是新 module 路径下的首个正式标签，可直接写入 go.mod；无需继续使用迁移期 pseudo-version。": "v1.0.0 is the first stable tag under the new module path and can be used directly in go.mod; the migration pseudo-version is no longer needed.",
    "适用于 v1.0.0 源码标签": "For the v1.0.0 source tag",
    "查看 1.0.0-beta.1 的各平台构建产物与校验资料。": "View builds and checksums for 1.0.0-beta.1.",
    "第二个公开测试版：官网、桌面客户端与 Admin Web 支持六种语言，官网按语言展示真实客户端画面，并补齐页签图标。": "Second public beta: six-language support for the website, desktop client, and Admin Web; real client previews in the selected language; and a TrustDB favicon.",
    "下载 1.0.0-beta.1": "Download 1.0.0-beta.1",
    "1.0.0-beta.1 已进入公开测试": "1.0.0-beta.1 is now in public beta",
    "适用于 v1.0.0-beta.1 源码标签": "For the v1.0.0-beta.1 source tag",
    "TrustDB 主分支已迁移到 WowTrust 组织并使用新的 Go module 路径。下一个新路径版本标签发布前，请固定迁移后的 canonical pseudo-version，避免分支查询缓存和浮动版本。": "TrustDB's main branch has moved to the WowTrust organization and uses the new Go module path. Until a tag with the new path is published, pin the canonical post-migration pseudo-version to avoid stale branch-query caches and floating versions.",
    "v1.0.0-beta.1 发布于迁移前，仍保留旧 module identity。评估项目应固定 go.mod 解析出的 pseudo-version；新路径标签发布后再固定到该标签。": "v1.0.0-beta.1 predates the migration and retains the previous module identity. Evaluation projects should pin the pseudo-version resolved in go.mod, then switch to a fixed new-path tag after it is released.",
  },
  ru: {
    "可验证证据数据库": "База проверяемых доказательств",
    "产品": "Продукт", "文档": "Документация", "性能": "Производительность", "版本": "Версии", "下载": "Скачать",
    "文档中心": "Документация", "版本与下载": "Версии и загрузки", "源码": "Исходный код", "参与贡献": "Участвовать",
    "GitHub Release 提供安装包、服务端与 CLI 归档以及统一校验文件；WowTrust GHCR 提供 amd64 与 arm64 组织镜像。": "GitHub Releases содержит установщики, архивы сервера и CLI, а также единые контрольные суммы; WowTrust GHCR предоставляет образы amd64 и arm64 организации.",
    "WowTrust GHCR 是默认组织镜像，Docker Hub 同步保留同版本的 linux/amd64 与 linux/arm64 镜像。": "WowTrust GHCR — основной реестр организации; Docker Hub зеркалирует те же версии linux/amd64 и linux/arm64.",
    "开始使用": "Начать", "返回首页": "На главную", "开发日志": "История изменений",
    "打开 TrustDB GitHub 仓库": "Открыть репозиторий TrustDB на GitHub",
    "感谢 LINUX DO 社区": "Спасибо сообществу LINUX DO", "访问 LINUX DO 社区": "Посетить сообщество LINUX DO",
    "主导航": "Главная навигация", "移动导航": "Мобильная навигация", "页脚导航": "Навигация внизу",
    "语言": "Язык",
    "有据可查": "Доказательства, которые можно проверить.", "五级证明，": "Пять уровней доказательств,", "一条证据链。": "одна цепочка доказательств.",
    "签名": "Подпись", "收据": "Квитанция", "锚定": "Привязка", "外部锚定": "Внешняя привязка",
    "查看 1.0.0 正式版的各平台构建产物与校验资料。": "Сборки и контрольные суммы стабильной версии 1.0.0.",
    "首个正式版：新 Go module 路径、持久化 STH 合并锚定、完整离线证据、存储 schema v4 与逻辑备份。": "Первый стабильный выпуск: новый путь Go module, надёжное объединённое закрепление STH, полные офлайн-доказательства, схема хранилища v4 и логические резервные копии.",
    "下载 1.0.0": "Скачать 1.0.0", "1.0.0 正式版已发布": "Стабильная версия 1.0.0 опубликована", "正式版 ·": "Стабильная версия ·",
    "服务端、CLI、SDK 与证据格式进入首个稳定版本；桌面客户端仍采用自签名证书，请从 GitHub Release 下载并核对 SHA-256。": "Сервер, CLI, SDK и форматы доказательств достигли первой стабильной версии. Настольные пакеты остаются самоподписанными; загружайте их из GitHub Releases и проверяйте SHA-256.",
    "在 macOS 与 Windows 安装自签名桌面客户端。": "Установите самоподписанный настольный клиент на macOS или Windows.",
    "TrustDB v1.0.0 使用 WowTrust 组织下的正式 Go module 路径。生产项目应固定具体版本，保证依赖解析与构建可复现。": "TrustDB v1.0.0 использует официальный путь Go module организации WowTrust. Для воспроизводимых сборок закрепляйте точную версию.",
    "v1.0.0 是新 module 路径下的首个正式标签，可直接写入 go.mod；无需继续使用迁移期 pseudo-version。": "v1.0.0 — первый стабильный тег нового пути модуля; его можно напрямую указать в go.mod без миграционной pseudo-version.",
    "适用于 v1.0.0 源码标签": "Для исходного тега v1.0.0",
    "查看 1.0.0-beta.1 的各平台构建产物与校验资料。": "Сборки и контрольные суммы для 1.0.0-beta.1.",
    "第二个公开测试版：官网、桌面客户端与 Admin Web 支持六种语言，官网按语言展示真实客户端画面，并补齐页签图标。": "Второй публичный бета-релиз: шесть языков на сайте, в настольном клиенте и Admin Web; снимки реального клиента на выбранном языке; значок сайта TrustDB.",
    "下载 1.0.0-beta.1": "Скачать 1.0.0-beta.1",
    "1.0.0-beta.1 已进入公开测试": "1.0.0-beta.1 доступна для публичного бета-тестирования",
    "适用于 v1.0.0-beta.1 源码标签": "Для исходного тега v1.0.0-beta.1",
    "TrustDB 主分支已迁移到 WowTrust 组织并使用新的 Go module 路径。下一个新路径版本标签发布前，请固定迁移后的 canonical pseudo-version，避免分支查询缓存和浮动版本。": "Основная ветка TrustDB перенесена в организацию WowTrust и использует новый путь Go module. До публикации тега с новым путём закрепите каноническую pseudo-version после миграции, чтобы избежать устаревшего кэша запросов ветки и плавающих версий.",
    "v1.0.0-beta.1 发布于迁移前，仍保留旧 module identity。评估项目应固定 go.mod 解析出的 pseudo-version；新路径标签发布后再固定到该标签。": "v1.0.0-beta.1 выпущена до миграции и сохраняет прежнюю идентичность модуля. Для тестовых проектов закрепите pseudo-version, записанную в go.mod, а после выпуска нового тега закрепите этот тег.",
  },
  ja: {
    "可验证证据数据库": "検証可能な証拠データベース",
    "产品": "製品", "文档": "ドキュメント", "性能": "性能", "版本": "リリース", "下载": "ダウンロード",
    "文档中心": "ドキュメント", "版本与下载": "リリースとダウンロード", "源码": "ソースコード", "参与贡献": "コントリビュート",
    "GitHub Release 提供安装包、服务端与 CLI 归档以及统一校验文件；WowTrust GHCR 提供 amd64 与 arm64 组织镜像。": "GitHub Releases ではインストーラー、サーバーと CLI のアーカイブ、統一チェックサムを提供し、WowTrust GHCR では組織所有の amd64 / arm64 イメージを提供します。",
    "WowTrust GHCR 是默认组织镜像，Docker Hub 同步保留同版本的 linux/amd64 与 linux/arm64 镜像。": "WowTrust GHCR を組織の標準レジストリとし、Docker Hub に同じ linux/amd64 / linux/arm64 バージョンをミラーします。",
    "开始使用": "始める", "返回首页": "ホームへ戻る", "开发日志": "変更履歴",
    "打开 TrustDB GitHub 仓库": "TrustDB の GitHub リポジトリを開く",
    "感谢 LINUX DO 社区": "LINUX DO コミュニティに感謝", "访问 LINUX DO 社区": "LINUX DO コミュニティを訪問",
    "主导航": "メインナビゲーション", "移动导航": "モバイルナビゲーション", "页脚导航": "フッターナビゲーション",
    "语言": "言語",
    "有据可查": "検証できる証拠。", "五级证明，": "5段階の証明、", "一条证据链。": "ひとつの証拠チェーン。",
    "签名": "署名", "收据": "受領証", "锚定": "アンカー", "外部锚定": "外部アンカー",
    "查看 1.0.0 正式版的各平台构建产物与校验资料。": "安定版 1.0.0 の各プラットフォーム向けビルドとチェックサムを確認できます。",
    "首个正式版：新 Go module 路径、持久化 STH 合并锚定、完整离线证据、存储 schema v4 与逻辑备份。": "初の安定版：新しい Go module パス、永続的な STH 集約アンカー、完全なオフライン証拠、ストレージ schema v4、論理バックアップ。",
    "下载 1.0.0": "1.0.0 をダウンロード", "1.0.0 正式版已发布": "1.0.0 安定版を公開しました", "正式版 ·": "安定版 ·",
    "服务端、CLI、SDK 与证据格式进入首个稳定版本；桌面客户端仍采用自签名证书，请从 GitHub Release 下载并核对 SHA-256。": "サーバー、CLI、SDK、証拠形式が初の安定版になりました。デスクトップ版は引き続き自己署名のため、GitHub Releases から取得して SHA-256 を確認してください。",
    "在 macOS 与 Windows 安装自签名桌面客户端。": "自己署名のデスクトップクライアントを macOS または Windows にインストールします。",
    "TrustDB v1.0.0 使用 WowTrust 组织下的正式 Go module 路径。生产项目应固定具体版本，保证依赖解析与构建可复现。": "TrustDB v1.0.0 は WowTrust 組織の正式な Go module パスを使用します。再現可能な依存解決とビルドのため、正確なバージョンを固定してください。",
    "v1.0.0 是新 module 路径下的首个正式标签，可直接写入 go.mod；无需继续使用迁移期 pseudo-version。": "v1.0.0 は新しい module パスの最初の安定タグで、go.mod に直接指定できます。移行用 pseudo-version は不要です。",
    "适用于 v1.0.0 源码标签": "v1.0.0 ソースタグ向け",
    "查看 1.0.0-beta.1 的各平台构建产物与校验资料。": "1.0.0-beta.1 の各プラットフォーム向けビルドとチェックサムを確認できます。",
    "第二个公开测试版：官网、桌面客户端与 Admin Web 支持六种语言，官网按语言展示真实客户端画面，并补齐页签图标。": "第2回公開ベータ：公式サイト、デスクトップクライアント、Admin Web が6言語に対応。実際のクライアント画面も選択言語で表示し、TrustDB のファビコンを追加しました。",
    "下载 1.0.0-beta.1": "1.0.0-beta.1 をダウンロード",
    "1.0.0-beta.1 已进入公开测试": "1.0.0-beta.1 を公開ベータとして提供中",
    "适用于 v1.0.0-beta.1 源码标签": "v1.0.0-beta.1 ソースタグ向け",
    "TrustDB 主分支已迁移到 WowTrust 组织并使用新的 Go module 路径。下一个新路径版本标签发布前，请固定迁移后的 canonical pseudo-version，避免分支查询缓存和浮动版本。": "TrustDB の main ブランチは WowTrust 組織へ移行し、新しい Go module パスを使用しています。新しいパスのタグが公開されるまでは、移行後の canonical pseudo-version を固定し、古いブランチクエリのキャッシュや浮動バージョンを避けてください。",
    "v1.0.0-beta.1 发布于迁移前，仍保留旧 module identity。评估项目应固定 go.mod 解析出的 pseudo-version；新路径标签发布后再固定到该标签。": "v1.0.0-beta.1 は移行前に公開されたため、以前の module identity を保持しています。評価プロジェクトでは go.mod に解決された pseudo-version を固定し、新しいパスのタグ公開後にそのタグへ切り替えてください。",
  },
  fr: {
    "可验证证据数据库": "Base de preuves vérifiables",
    "产品": "Produit", "文档": "Documentation", "性能": "Performances", "版本": "Versions", "下载": "Télécharger",
    "文档中心": "Documentation", "版本与下载": "Versions et téléchargements", "源码": "Code source", "参与贡献": "Contribuer",
    "GitHub Release 提供安装包、服务端与 CLI 归档以及统一校验文件；WowTrust GHCR 提供 amd64 与 arm64 组织镜像。": "GitHub Releases fournit les installateurs, les archives serveur et CLI ainsi que les sommes de contrôle unifiées ; WowTrust GHCR fournit les images amd64 et arm64 de l’organisation.",
    "WowTrust GHCR 是默认组织镜像，Docker Hub 同步保留同版本的 linux/amd64 与 linux/arm64 镜像。": "WowTrust GHCR est le registre principal de l’organisation ; Docker Hub conserve un miroir des mêmes versions linux/amd64 et linux/arm64.",
    "开始使用": "Commencer", "返回首页": "Retour à l’accueil", "开发日志": "Journal des versions",
    "打开 TrustDB GitHub 仓库": "Ouvrir le dépôt GitHub de TrustDB",
    "感谢 LINUX DO 社区": "Merci à la communauté LINUX DO", "访问 LINUX DO 社区": "Visiter la communauté LINUX DO",
    "主导航": "Navigation principale", "移动导航": "Navigation mobile", "页脚导航": "Navigation de pied de page",
    "语言": "Langue",
    "有据可查": "Des preuves vérifiables.", "五级证明，": "Cinq niveaux de preuve,", "一条证据链。": "une seule chaîne de preuves.",
    "签名": "Signature", "收据": "Reçu", "锚定": "Ancrage", "外部锚定": "Ancrage externe",
    "查看 1.0.0 正式版的各平台构建产物与校验资料。": "Consultez les builds et les sommes de contrôle de la version stable 1.0.0.",
    "首个正式版：新 Go module 路径、持久化 STH 合并锚定、完整离线证据、存储 schema v4 与逻辑备份。": "Première version stable : nouveau chemin Go module, ancrage STH regroupé et durable, preuves hors ligne complètes, schéma de stockage v4 et sauvegardes logiques.",
    "下载 1.0.0": "Télécharger 1.0.0", "1.0.0 正式版已发布": "La version stable 1.0.0 est disponible", "正式版 ·": "Version stable ·",
    "服务端、CLI、SDK 与证据格式进入首个稳定版本；桌面客户端仍采用自签名证书，请从 GitHub Release 下载并核对 SHA-256。": "Le serveur, la CLI, le SDK et les formats de preuve atteignent leur première version stable. Les paquets de bureau restent auto-signés ; téléchargez-les depuis GitHub Releases et vérifiez le SHA-256.",
    "在 macOS 与 Windows 安装自签名桌面客户端。": "Installez le client de bureau auto-signé sur macOS ou Windows.",
    "TrustDB v1.0.0 使用 WowTrust 组织下的正式 Go module 路径。生产项目应固定具体版本，保证依赖解析与构建可复现。": "TrustDB v1.0.0 utilise le chemin Go module officiel de l’organisation WowTrust. Épinglez une version précise en production pour des builds reproductibles.",
    "v1.0.0 是新 module 路径下的首个正式标签，可直接写入 go.mod；无需继续使用迁移期 pseudo-version。": "v1.0.0 est le premier tag stable du nouveau chemin de module et peut être utilisé directement dans go.mod ; la pseudo-version de migration n’est plus nécessaire.",
    "适用于 v1.0.0 源码标签": "Pour le tag source v1.0.0",
    "查看 1.0.0-beta.1 的各平台构建产物与校验资料。": "Consultez les builds et les sommes de contrôle de 1.0.0-beta.1.",
    "第二个公开测试版：官网、桌面客户端与 Admin Web 支持六种语言，官网按语言展示真实客户端画面，并补齐页签图标。": "Deuxième bêta publique : six langues sur le site, le client de bureau et l’Admin Web ; aperçus du client réel dans la langue choisie ; favicon TrustDB.",
    "下载 1.0.0-beta.1": "Télécharger 1.0.0-beta.1",
    "1.0.0-beta.1 已进入公开测试": "1.0.0-beta.1 est disponible en bêta publique",
    "适用于 v1.0.0-beta.1 源码标签": "Pour le tag source v1.0.0-beta.1",
    "TrustDB 主分支已迁移到 WowTrust 组织并使用新的 Go module 路径。下一个新路径版本标签发布前，请固定迁移后的 canonical pseudo-version，避免分支查询缓存和浮动版本。": "La branche main de TrustDB a été transférée dans l’organisation WowTrust et utilise le nouveau chemin de module Go. Jusqu’à la publication d’un tag avec ce nouveau chemin, figez la pseudo-version canonique post-migration afin d’éviter les caches obsolètes de requêtes de branche et les versions flottantes.",
    "v1.0.0-beta.1 发布于迁移前，仍保留旧 module identity。评估项目应固定 go.mod 解析出的 pseudo-version；新路径标签发布后再固定到该标签。": "v1.0.0-beta.1 est antérieure à la migration et conserve l’ancienne identité de module. Les projets d’évaluation doivent figer la pseudo-version résolue dans go.mod, puis passer à un tag fixe utilisant le nouveau chemin dès sa publication.",
  },
  ko: {
    "可验证证据数据库": "검증 가능한 증거 데이터베이스",
    "产品": "제품", "文档": "문서", "性能": "성능", "版本": "릴리스", "下载": "다운로드",
    "文档中心": "문서", "版本与下载": "릴리스 및 다운로드", "源码": "소스 코드", "参与贡献": "기여하기",
    "GitHub Release 提供安装包、服务端与 CLI 归档以及统一校验文件；WowTrust GHCR 提供 amd64 与 arm64 组织镜像。": "GitHub Releases는 설치 프로그램, 서버 및 CLI 아카이브와 통합 체크섬을 제공하며 WowTrust GHCR은 조직 소유의 amd64 및 arm64 이미지를 제공합니다.",
    "WowTrust GHCR 是默认组织镜像，Docker Hub 同步保留同版本的 linux/amd64 与 linux/arm64 镜像。": "WowTrust GHCR을 조직의 기본 레지스트리로 사용하고 Docker Hub에는 같은 linux/amd64 및 linux/arm64 버전을 미러링합니다.",
    "开始使用": "시작하기", "返回首页": "홈으로", "开发日志": "변경 기록",
    "打开 TrustDB GitHub 仓库": "TrustDB GitHub 저장소 열기",
    "感谢 LINUX DO 社区": "LINUX DO 커뮤니티에 감사드립니다", "访问 LINUX DO 社区": "LINUX DO 커뮤니티 방문",
    "主导航": "주요 탐색", "移动导航": "모바일 탐색", "页脚导航": "바닥글 탐색",
    "语言": "언어",
    "有据可查": "검증할 수 있는 증거.", "五级证明，": "다섯 단계의 증명,", "一条证据链。": "하나의 증거 사슬.",
    "签名": "서명", "收据": "영수증", "锚定": "앵커링", "外部锚定": "외부 앵커링",
    "查看 1.0.0 正式版的各平台构建产物与校验资料。": "안정 버전 1.0.0의 플랫폼별 빌드와 체크섬을 확인합니다.",
    "首个正式版：新 Go module 路径、持久化 STH 合并锚定、完整离线证据、存储 schema v4 与逻辑备份。": "첫 안정 릴리스: 새 Go module 경로, 내구성 있는 STH 병합 앵커링, 완전한 오프라인 증거, 스토리지 schema v4 및 논리 백업.",
    "下载 1.0.0": "1.0.0 다운로드", "1.0.0 正式版已发布": "1.0.0 안정 버전 출시", "正式版 ·": "안정 버전 ·",
    "服务端、CLI、SDK 与证据格式进入首个稳定版本；桌面客户端仍采用自签名证书，请从 GitHub Release 下载并核对 SHA-256。": "서버, CLI, SDK와 증거 형식이 첫 안정 버전에 도달했습니다. 데스크톱 패키지는 자체 서명이므로 GitHub Releases에서 내려받아 SHA-256을 확인하세요.",
    "在 macOS 与 Windows 安装自签名桌面客户端。": "macOS 또는 Windows에 자체 서명된 데스크톱 클라이언트를 설치합니다.",
    "TrustDB v1.0.0 使用 WowTrust 组织下的正式 Go module 路径。生产项目应固定具体版本，保证依赖解析与构建可复现。": "TrustDB v1.0.0은 WowTrust 조직의 공식 Go module 경로를 사용합니다. 재현 가능한 의존성 해석과 빌드를 위해 정확한 버전을 고정하세요.",
    "v1.0.0 是新 module 路径下的首个正式标签，可直接写入 go.mod；无需继续使用迁移期 pseudo-version。": "v1.0.0은 새 module 경로의 첫 안정 태그이며 go.mod에 직접 사용할 수 있습니다. 마이그레이션 pseudo-version은 더 이상 필요하지 않습니다.",
    "适用于 v1.0.0 源码标签": "v1.0.0 소스 태그용",
    "查看 1.0.0-beta.1 的各平台构建产物与校验资料。": "1.0.0-beta.1의 플랫폼별 빌드와 체크섬 자료를 확인합니다.",
    "第二个公开测试版：官网、桌面客户端与 Admin Web 支持六种语言，官网按语言展示真实客户端画面，并补齐页签图标。": "두 번째 공개 베타: 공식 웹사이트, 데스크톱 클라이언트, Admin Web 6개 언어 지원, 선택한 언어의 실제 클라이언트 화면, TrustDB 파비콘.",
    "下载 1.0.0-beta.1": "1.0.0-beta.1 다운로드",
    "1.0.0-beta.1 已进入公开测试": "1.0.0-beta.1 공개 베타 배포 중",
    "适用于 v1.0.0-beta.1 源码标签": "v1.0.0-beta.1 소스 태그용",
    "TrustDB 主分支已迁移到 WowTrust 组织并使用新的 Go module 路径。下一个新路径版本标签发布前，请固定迁移后的 canonical pseudo-version，避免分支查询缓存和浮动版本。": "TrustDB의 main 브랜치는 WowTrust 조직으로 이전되었으며 새 Go module 경로를 사용합니다. 새 경로의 태그가 게시되기 전까지 마이그레이션 후 canonical pseudo-version을 고정해 오래된 브랜치 쿼리 캐시와 부동 버전을 피하세요.",
    "v1.0.0-beta.1 发布于迁移前，仍保留旧 module identity。评估项目应固定 go.mod 解析出的 pseudo-version；新路径标签发布后再固定到该标签。": "v1.0.0-beta.1은 이전 전에 출시되어 기존 module identity를 유지합니다. 평가 프로젝트에서는 go.mod에 해석된 pseudo-version을 고정하고, 새 경로 태그가 출시되면 해당 태그로 전환하세요.",
  },
};

const storageKey = "trustdb.locale";
const supported = new Set(localeOptions.map(({ code }) => code));
const listeners = new Set();
const generatedMessageLoaders = {
  en: () => import("virtual:trustdb-messages/en"),
  ru: () => import("virtual:trustdb-messages/ru"),
  ja: () => import("virtual:trustdb-messages/ja"),
  fr: () => import("virtual:trustdb-messages/fr"),
  ko: () => import("virtual:trustdb-messages/ko"),
};

function normalizeLocale(value) {
  const locale = String(value || "").toLowerCase();
  if (locale.startsWith("zh")) return "zh-CN";
  if (locale.startsWith("ru")) return "ru";
  if (locale.startsWith("ja")) return "ja";
  if (locale.startsWith("fr")) return "fr";
  if (locale.startsWith("ko")) return "ko";
  if (locale.startsWith("en")) return "en";
  return "zh-CN";
}

function initialLocale() {
  try {
    const saved = localStorage.getItem(storageKey);
    if (saved && supported.has(saved)) return saved;
  } catch { /* local storage can be unavailable in embedded shells */ }
  return normalizeLocale(navigator.languages?.[0] || navigator.language);
}

let currentLocale = initialLocale();
document.documentElement.lang = currentLocale;

const messages = Object.fromEntries(localeOptions.map(({ code }) => [code, { ...(manualMessages[code] || {}) }]));
const loadedLocales = new Set(["zh-CN"]);
const localeLoads = new Map();
let sortedEntries = [];

function rebuildEntries() {
  sortedEntries = Object.entries(messages[currentLocale] || {}).sort(([a], [b]) => b.length - a.length);
}
rebuildEntries();

async function loadLocaleMessages(locale) {
  if (loadedLocales.has(locale)) return;
  let pending = localeLoads.get(locale);
  if (!pending) {
    const loader = generatedMessageLoaders[locale];
    pending = loader().then(({ default: generated }) => {
      messages[locale] = { ...(generated || {}), ...(manualMessages[locale] || {}) };
      loadedLocales.add(locale);
    });
    localeLoads.set(locale, pending);
  }
  try {
    await pending;
  } catch (error) {
    localeLoads.delete(locale);
    throw error;
  }
}

export async function initializeLocaleMessages() {
  try {
    await loadLocaleMessages(currentLocale);
  } catch {
    currentLocale = "zh-CN";
    document.documentElement.lang = currentLocale;
  }
  rebuildEntries();
}

export function getLocale() { return currentLocale; }
export function subscribeLocale(listener) { listeners.add(listener); return () => listeners.delete(listener); }
export function useLocale() { return useSyncExternalStore(subscribeLocale, getLocale, getLocale); }

let localeRequest = 0;

export async function setLocale(locale) {
  const next = normalizeLocale(locale);
  const request = ++localeRequest;
  if (next === currentLocale) return;
  try {
    await loadLocaleMessages(next);
  } catch {
    return;
  }
  if (request !== localeRequest) return;
  currentLocale = next;
  rebuildEntries();
  document.documentElement.lang = next;
  try { localStorage.setItem(storageKey, next); } catch { /* ignore */ }
  listeners.forEach((listener) => listener());
}

export function t(source, variables = {}) {
  let value = (messages[currentLocale]?.[source] || source);
  for (const [key, replacement] of Object.entries(variables)) {
    value = value.replaceAll(`{${key}}`, String(replacement));
  }
  return value;
}

function translateValue(source) {
  if (!source || currentLocale === "zh-CN") return source;
  const leading = source.match(/^\s*/)?.[0] || "";
  const trailing = source.match(/\s*$/)?.[0] || "";
  const trimmed = source.trim();
  const exact = messages[currentLocale]?.[trimmed];
  if (exact) return `${leading}${exact}${trailing}`;
  let output = source;
  for (const [original, translated] of sortedEntries) {
    if (original.length > 1 && output.includes(original)) output = output.split(original).join(translated);
  }
  return output;
}

export function installDomTranslations(root = document.documentElement) {
  const textOriginals = new WeakMap();
  const textApplied = new WeakMap();
  const attributeOriginals = new WeakMap();
  const attributeApplied = new WeakMap();
  const translatedAttributes = ["aria-label", "alt", "placeholder", "title"];

  const ignored = (element) => element?.closest?.("script, style, pre, code, [data-i18n-ignore]");
  const translateTextNode = (node) => {
    if (!node.data?.trim() || ignored(node.parentElement)) return;
    const known = textOriginals.get(node);
    const lastApplied = textApplied.get(node);
    const original = known && node.data === lastApplied ? known : node.data;
    textOriginals.set(node, original);
    const next = translateValue(original);
    textApplied.set(node, next);
    if (node.data !== next) node.data = next;
  };
  const translateElement = (element) => {
    if (ignored(element)) return;
    let originals = attributeOriginals.get(element);
    if (!originals) { originals = {}; attributeOriginals.set(element, originals); }
    let applied = attributeApplied.get(element);
    if (!applied) { applied = {}; attributeApplied.set(element, applied); }
    for (const attribute of translatedAttributes) {
      if (!element.hasAttribute(attribute)) continue;
      const current = element.getAttribute(attribute) || "";
      const previous = originals[attribute];
      if (!previous || current !== applied[attribute]) originals[attribute] = current;
      const next = translateValue(originals[attribute]);
      applied[attribute] = next;
      if (current !== next) element.setAttribute(attribute, next);
    }
  };
  const visit = (node) => {
    if (node.nodeType === Node.TEXT_NODE) { translateTextNode(node); return; }
    if (!(node instanceof Element) || ignored(node)) return;
    translateElement(node);
    node.childNodes.forEach(visit);
  };
  const refresh = () => visit(root);
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === "characterData") translateTextNode(mutation.target);
      else if (mutation.type === "attributes") translateElement(mutation.target);
      else mutation.addedNodes.forEach(visit);
    }
  });
  observer.observe(root, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: translatedAttributes });
  const unsubscribe = subscribeLocale(refresh);
  refresh();
  return () => { observer.disconnect(); unsubscribe(); };
}
