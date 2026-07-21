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
    "文档中心": "Documentation", "版本与下载": "Releases & downloads", "源码": "Source",
    "开始使用": "Get started", "返回首页": "Back home", "开发日志": "Changelog",
    "打开 TrustDB GitHub 仓库": "Open the TrustDB GitHub repository",
    "感谢 LINUX DO 社区": "Thanks to the LINUX DO community", "访问 LINUX DO 社区": "Visit the LINUX DO community",
    "主导航": "Main navigation", "移动导航": "Mobile navigation", "页脚导航": "Footer navigation",
    "语言": "Language",
    "有据可查": "Evidence you can verify.", "五级证明，": "Five proof levels,", "一条证据链。": "one evidence chain.",
    "签名": "Signature", "收据": "Receipt", "锚定": "Anchoring", "外部锚定": "External anchoring",
    "查看 1.0.0-beta.1 的各平台构建产物与校验资料。": "View builds and checksums for 1.0.0-beta.1.",
    "第二个公开测试版：官网、桌面客户端与 Admin Web 支持六种语言，官网按语言展示真实客户端画面，并补齐页签图标。": "Second public beta: six-language support for the website, desktop client, and Admin Web; real client previews in the selected language; and a TrustDB favicon.",
    "下载 1.0.0-beta.1": "Download 1.0.0-beta.1",
    "1.0.0-beta.1 已进入公开测试": "1.0.0-beta.1 is now in public beta",
    "适用于 v1.0.0-beta.1 源码标签": "For the v1.0.0-beta.1 source tag",
  },
  ru: {
    "可验证证据数据库": "База проверяемых доказательств",
    "产品": "Продукт", "文档": "Документация", "性能": "Производительность", "版本": "Версии", "下载": "Скачать",
    "文档中心": "Документация", "版本与下载": "Версии и загрузки", "源码": "Исходный код",
    "开始使用": "Начать", "返回首页": "На главную", "开发日志": "История изменений",
    "打开 TrustDB GitHub 仓库": "Открыть репозиторий TrustDB на GitHub",
    "感谢 LINUX DO 社区": "Спасибо сообществу LINUX DO", "访问 LINUX DO 社区": "Посетить сообщество LINUX DO",
    "主导航": "Главная навигация", "移动导航": "Мобильная навигация", "页脚导航": "Навигация внизу",
    "语言": "Язык",
    "有据可查": "Доказательства, которые можно проверить.", "五级证明，": "Пять уровней доказательств,", "一条证据链。": "одна цепочка доказательств.",
    "签名": "Подпись", "收据": "Квитанция", "锚定": "Привязка", "外部锚定": "Внешняя привязка",
    "查看 1.0.0-beta.1 的各平台构建产物与校验资料。": "Сборки и контрольные суммы для 1.0.0-beta.1.",
    "第二个公开测试版：官网、桌面客户端与 Admin Web 支持六种语言，官网按语言展示真实客户端画面，并补齐页签图标。": "Второй публичный бета-релиз: шесть языков на сайте, в настольном клиенте и Admin Web; снимки реального клиента на выбранном языке; значок сайта TrustDB.",
    "下载 1.0.0-beta.1": "Скачать 1.0.0-beta.1",
    "1.0.0-beta.1 已进入公开测试": "1.0.0-beta.1 доступна для публичного бета-тестирования",
    "适用于 v1.0.0-beta.1 源码标签": "Для исходного тега v1.0.0-beta.1",
  },
  ja: {
    "可验证证据数据库": "検証可能な証拠データベース",
    "产品": "製品", "文档": "ドキュメント", "性能": "性能", "版本": "リリース", "下载": "ダウンロード",
    "文档中心": "ドキュメント", "版本与下载": "リリースとダウンロード", "源码": "ソースコード",
    "开始使用": "始める", "返回首页": "ホームへ戻る", "开发日志": "変更履歴",
    "打开 TrustDB GitHub 仓库": "TrustDB の GitHub リポジトリを開く",
    "感谢 LINUX DO 社区": "LINUX DO コミュニティに感謝", "访问 LINUX DO 社区": "LINUX DO コミュニティを訪問",
    "主导航": "メインナビゲーション", "移动导航": "モバイルナビゲーション", "页脚导航": "フッターナビゲーション",
    "语言": "言語",
    "有据可查": "検証できる証拠。", "五级证明，": "5段階の証明、", "一条证据链。": "ひとつの証拠チェーン。",
    "签名": "署名", "收据": "受領証", "锚定": "アンカー", "外部锚定": "外部アンカー",
    "查看 1.0.0-beta.1 的各平台构建产物与校验资料。": "1.0.0-beta.1 の各プラットフォーム向けビルドとチェックサムを確認できます。",
    "第二个公开测试版：官网、桌面客户端与 Admin Web 支持六种语言，官网按语言展示真实客户端画面，并补齐页签图标。": "第2回公開ベータ：公式サイト、デスクトップクライアント、Admin Web が6言語に対応。実際のクライアント画面も選択言語で表示し、TrustDB のファビコンを追加しました。",
    "下载 1.0.0-beta.1": "1.0.0-beta.1 をダウンロード",
    "1.0.0-beta.1 已进入公开测试": "1.0.0-beta.1 を公開ベータとして提供中",
    "适用于 v1.0.0-beta.1 源码标签": "v1.0.0-beta.1 ソースタグ向け",
  },
  fr: {
    "可验证证据数据库": "Base de preuves vérifiables",
    "产品": "Produit", "文档": "Documentation", "性能": "Performances", "版本": "Versions", "下载": "Télécharger",
    "文档中心": "Documentation", "版本与下载": "Versions et téléchargements", "源码": "Code source",
    "开始使用": "Commencer", "返回首页": "Retour à l’accueil", "开发日志": "Journal des versions",
    "打开 TrustDB GitHub 仓库": "Ouvrir le dépôt GitHub de TrustDB",
    "感谢 LINUX DO 社区": "Merci à la communauté LINUX DO", "访问 LINUX DO 社区": "Visiter la communauté LINUX DO",
    "主导航": "Navigation principale", "移动导航": "Navigation mobile", "页脚导航": "Navigation de pied de page",
    "语言": "Langue",
    "有据可查": "Des preuves vérifiables.", "五级证明，": "Cinq niveaux de preuve,", "一条证据链。": "une seule chaîne de preuves.",
    "签名": "Signature", "收据": "Reçu", "锚定": "Ancrage", "外部锚定": "Ancrage externe",
    "查看 1.0.0-beta.1 的各平台构建产物与校验资料。": "Consultez les builds et les sommes de contrôle de 1.0.0-beta.1.",
    "第二个公开测试版：官网、桌面客户端与 Admin Web 支持六种语言，官网按语言展示真实客户端画面，并补齐页签图标。": "Deuxième bêta publique : six langues sur le site, le client de bureau et l’Admin Web ; aperçus du client réel dans la langue choisie ; favicon TrustDB.",
    "下载 1.0.0-beta.1": "Télécharger 1.0.0-beta.1",
    "1.0.0-beta.1 已进入公开测试": "1.0.0-beta.1 est disponible en bêta publique",
    "适用于 v1.0.0-beta.1 源码标签": "Pour le tag source v1.0.0-beta.1",
  },
  ko: {
    "可验证证据数据库": "검증 가능한 증거 데이터베이스",
    "产品": "제품", "文档": "문서", "性能": "성능", "版本": "릴리스", "下载": "다운로드",
    "文档中心": "문서", "版本与下载": "릴리스 및 다운로드", "源码": "소스 코드",
    "开始使用": "시작하기", "返回首页": "홈으로", "开发日志": "변경 기록",
    "打开 TrustDB GitHub 仓库": "TrustDB GitHub 저장소 열기",
    "感谢 LINUX DO 社区": "LINUX DO 커뮤니티에 감사드립니다", "访问 LINUX DO 社区": "LINUX DO 커뮤니티 방문",
    "主导航": "주요 탐색", "移动导航": "모바일 탐색", "页脚导航": "바닥글 탐색",
    "语言": "언어",
    "有据可查": "검증할 수 있는 증거.", "五级证明，": "다섯 단계의 증명,", "一条证据链。": "하나의 증거 사슬.",
    "签名": "서명", "收据": "영수증", "锚定": "앵커링", "外部锚定": "외부 앵커링",
    "查看 1.0.0-beta.1 的各平台构建产物与校验资料。": "1.0.0-beta.1의 플랫폼별 빌드와 체크섬 자료를 확인합니다.",
    "第二个公开测试版：官网、桌面客户端与 Admin Web 支持六种语言，官网按语言展示真实客户端画面，并补齐页签图标。": "두 번째 공개 베타: 공식 웹사이트, 데스크톱 클라이언트, Admin Web 6개 언어 지원, 선택한 언어의 실제 클라이언트 화면, TrustDB 파비콘.",
    "下载 1.0.0-beta.1": "1.0.0-beta.1 다운로드",
    "1.0.0-beta.1 已进入公开测试": "1.0.0-beta.1 공개 베타 배포 중",
    "适用于 v1.0.0-beta.1 源码标签": "v1.0.0-beta.1 소스 태그용",
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
