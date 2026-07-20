import { readonly, ref, watch } from 'vue'
import generatedMessages from './messages.generated'

export const localeOptions = [
  { code: 'zh-CN', label: '简体中文', short: '中' },
  { code: 'en', label: 'English', short: 'EN' },
  { code: 'ru', label: 'Русский', short: 'RU' },
  { code: 'ja', label: '日本語', short: '日' },
  { code: 'fr', label: 'Français', short: 'FR' },
  { code: 'ko', label: '한국어', short: '한' },
] as const

type LocaleCode = typeof localeOptions[number]['code']
type Messages = Record<string, Record<string, string>>

const manualMessages: Messages = {
  en: {
    '客户端': 'Desktop', '客户端导航': 'Desktop navigation', '客户端端点': 'Server endpoint', '复制端点': 'Copy endpoint',
    '概览': 'Overview', '新建存证': 'New evidence', '存证记录': 'Evidence records', '验证证据': 'Verify evidence',
    '指标面板': 'Metrics', '身份密钥': 'Identity & keys', '设置': 'Settings', '服务指标': 'Service metrics',
    '系统在线': 'System online', '离线模式': 'Offline mode', '语言': 'Language',
    '入门向导': 'Getting started', '跳过向导': 'Skip setup', '上一步': 'Back', '下一步': 'Next', '完成': 'Finish',
    '欢迎使用 TrustDB 存证': 'Welcome to TrustDB', '连接到 TrustDB 服务': 'Connect to TrustDB',
    '生成你的签名身份': 'Create your signing identity', '让服务器信任这把公钥': 'Register your public key',
    '设置已保存': 'Settings saved', '保存失败': 'Save failed', '保存': 'Save', '还原': 'Reset',
  },
  ru: {
    '客户端': 'Клиент', '客户端导航': 'Навигация клиента', '客户端端点': 'Адрес сервера', '复制端点': 'Копировать адрес',
    '概览': 'Обзор', '新建存证': 'Новая запись', '存证记录': 'Записи доказательств', '验证证据': 'Проверка доказательств',
    '指标面板': 'Метрики', '身份密钥': 'Идентификация и ключи', '设置': 'Настройки', '服务指标': 'Метрики сервиса',
    '系统在线': 'Система доступна', '离线模式': 'Автономный режим', '语言': 'Язык',
    '入门向导': 'Начальная настройка', '跳过向导': 'Пропустить', '上一步': 'Назад', '下一步': 'Далее', '完成': 'Готово',
    '欢迎使用 TrustDB 存证': 'Добро пожаловать в TrustDB', '连接到 TrustDB 服务': 'Подключение к TrustDB',
    '生成你的签名身份': 'Создание подписывающей личности', '让服务器信任这把公钥': 'Регистрация открытого ключа',
    '设置已保存': 'Настройки сохранены', '保存失败': 'Ошибка сохранения', '保存': 'Сохранить', '还原': 'Сбросить',
  },
  ja: {
    '客户端': 'デスクトップ', '客户端导航': 'クライアントナビゲーション', '客户端端点': 'サーバー接続先', '复制端点': '接続先をコピー',
    '概览': '概要', '新建存证': '証拠を作成', '存证记录': '証拠記録', '验证证据': '証拠を検証',
    '指标面板': 'メトリクス', '身份密钥': 'ID と鍵', '设置': '設定', '服务指标': 'サービスメトリクス',
    '系统在线': 'システム稼働中', '离线模式': 'オフラインモード', '语言': '言語',
    '入门向导': '初期設定', '跳过向导': 'スキップ', '上一步': '戻る', '下一步': '次へ', '完成': '完了',
    '欢迎使用 TrustDB 存证': 'TrustDB へようこそ', '连接到 TrustDB 服务': 'TrustDB に接続',
    '生成你的签名身份': '署名 ID を作成', '让服务器信任这把公钥': '公開鍵を登録',
    '设置已保存': '設定を保存しました', '保存失败': '保存に失敗しました', '保存': '保存', '还原': 'リセット',
  },
  fr: {
    '客户端': 'Bureau', '客户端导航': 'Navigation du client', '客户端端点': 'Adresse du serveur', '复制端点': 'Copier l’adresse',
    '概览': 'Vue d’ensemble', '新建存证': 'Nouvelle preuve', '存证记录': 'Registres de preuve', '验证证据': 'Vérifier une preuve',
    '指标面板': 'Métriques', '身份密钥': 'Identité et clés', '设置': 'Paramètres', '服务指标': 'Métriques du service',
    '系统在线': 'Système en ligne', '离线模式': 'Mode hors ligne', '语言': 'Langue',
    '入门向导': 'Configuration initiale', '跳过向导': 'Ignorer', '上一步': 'Retour', '下一步': 'Suivant', '完成': 'Terminer',
    '欢迎使用 TrustDB 存证': 'Bienvenue dans TrustDB', '连接到 TrustDB 服务': 'Connexion à TrustDB',
    '生成你的签名身份': 'Créer votre identité de signature', '让服务器信任这把公钥': 'Enregistrer votre clé publique',
    '设置已保存': 'Paramètres enregistrés', '保存失败': 'Échec de l’enregistrement', '保存': 'Enregistrer', '还原': 'Réinitialiser',
  },
  ko: {
    '客户端': '데스크톱', '客户端导航': '클라이언트 탐색', '客户端端点': '서버 주소', '复制端点': '주소 복사',
    '概览': '개요', '新建存证': '새 증거', '存证记录': '증거 기록', '验证证据': '증거 검증',
    '指标面板': '메트릭', '身份密钥': 'ID 및 키', '设置': '설정', '服务指标': '서비스 메트릭',
    '系统在线': '시스템 온라인', '离线模式': '오프라인 모드', '语言': '언어',
    '入门向导': '시작 설정', '跳过向导': '건너뛰기', '上一步': '이전', '下一步': '다음', '完成': '완료',
    '欢迎使用 TrustDB 存证': 'TrustDB에 오신 것을 환영합니다', '连接到 TrustDB 服务': 'TrustDB 연결',
    '生成你的签名身份': '서명 ID 만들기', '让服务器信任这把公钥': '공개 키 등록',
    '设置已保存': '설정을 저장했습니다', '保存失败': '저장하지 못했습니다', '保存': '저장', '还原': '초기화',
  },
}

const adminMessages: Messages = {
  en: {
    '管理端导航': 'Admin navigation', '运维': 'Operations', '指标': 'Metrics', '记录': 'Records', '批次': 'Batches',
    '全局树': 'Global tree', '系统设置': 'System settings', '服务在线': 'Service online', '服务不可达': 'Service unavailable',
    '用户名': 'Username', '密码': 'Password', '登录': 'Sign in', '退出': 'Sign out', '退出登录': 'Sign out',
    '最后更新：{time}': 'Updated: {time}', '证明等级 · 最近 {count} 条': 'Proof levels · Latest {count}',
  },
  ru: {
    '管理端导航': 'Навигация администратора', '运维': 'Эксплуатация', '指标': 'Метрики', '记录': 'Записи', '批次': 'Пакеты',
    '全局树': 'Глобальное дерево', '系统设置': 'Настройки системы', '服务在线': 'Сервис доступен', '服务不可达': 'Сервис недоступен',
    '用户名': 'Имя пользователя', '密码': 'Пароль', '登录': 'Войти', '退出': 'Выйти', '退出登录': 'Выйти',
    '最后更新：{time}': 'Обновлено: {time}', '证明等级 · 最近 {count} 条': 'Уровни доказательств · Последние {count}',
  },
  ja: {
    '管理端导航': '管理画面ナビゲーション', '运维': '運用', '指标': 'メトリクス', '记录': '記録', '批次': 'バッチ',
    '全局树': 'グローバルツリー', '系统设置': 'システム設定', '服务在线': 'サービス稼働中', '服务不可达': 'サービスに接続できません',
    '用户名': 'ユーザー名', '密码': 'パスワード', '登录': 'ログイン', '退出': 'ログアウト', '退出登录': 'ログアウト',
    '最后更新：{time}': '更新: {time}', '证明等级 · 最近 {count} 条': '証明レベル · 最新 {count} 件',
  },
  fr: {
    '管理端导航': 'Navigation d’administration', '运维': 'Exploitation', '指标': 'Métriques', '记录': 'Enregistrements', '批次': 'Lots',
    '全局树': 'Arbre global', '系统设置': 'Paramètres système', '服务在线': 'Service en ligne', '服务不可达': 'Service indisponible',
    '用户名': 'Nom d’utilisateur', '密码': 'Mot de passe', '登录': 'Se connecter', '退出': 'Se déconnecter', '退出登录': 'Se déconnecter',
    '最后更新：{time}': 'Mis à jour : {time}', '证明等级 · 最近 {count} 条': 'Niveaux de preuve · {count} derniers',
  },
  ko: {
    '管理端导航': '관리자 탐색', '运维': '운영', '指标': '메트릭', '记录': '기록', '批次': '배치',
    '全局树': '전역 트리', '系统设置': '시스템 설정', '服务在线': '서비스 온라인', '服务不可达': '서비스 연결 불가',
    '用户名': '사용자 이름', '密码': '비밀번호', '登录': '로그인', '退出': '로그아웃', '退出登录': '로그아웃',
    '最后更新：{time}': '업데이트: {time}', '证明等级 · 最近 {count} 条': '증명 단계 · 최근 {count}건',
  },
}

const storageKey = 'trustdb.locale'
const generated = generatedMessages as Messages
const supported = new Set(localeOptions.map((option) => option.code))

function normalizeLocale(value: unknown): LocaleCode {
  const candidate = String(value || '').toLowerCase()
  if (candidate.startsWith('zh')) return 'zh-CN'
  if (candidate.startsWith('ru')) return 'ru'
  if (candidate.startsWith('ja')) return 'ja'
  if (candidate.startsWith('fr')) return 'fr'
  if (candidate.startsWith('ko')) return 'ko'
  if (candidate.startsWith('en')) return 'en'
  return 'zh-CN'
}

function initialLocale(): LocaleCode {
  try {
    const saved = localStorage.getItem(storageKey)
    if (saved && supported.has(saved as LocaleCode)) return saved as LocaleCode
  } catch { /* embedded shells may restrict local storage */ }
  return normalizeLocale(globalThis.navigator?.languages?.[0] || globalThis.navigator?.language)
}

const current = ref<LocaleCode>(initialLocale())
export const locale = readonly(current)
const messages: Messages = Object.fromEntries(localeOptions.map(({ code }) => [
  code,
  { ...(generated[code] || {}), ...(manualMessages[code] || {}), ...(adminMessages[code] || {}) },
]))
let sortedEntries: [string, string][] = []

function rebuildEntries() {
  sortedEntries = Object.entries(messages[current.value] || {}).sort(([a], [b]) => b.length - a.length)
}
rebuildEntries()

export function setLocale(value: unknown) {
  const next = normalizeLocale(value)
  if (next === current.value) return
  current.value = next
  rebuildEntries()
  document.documentElement.lang = next
  try { localStorage.setItem(storageKey, next) } catch { /* ignore */ }
}

export function t(source: string, variables: Record<string, string | number> = {}) {
  let value = messages[current.value]?.[source] || source
  for (const [key, replacement] of Object.entries(variables)) value = value.replaceAll(`{${key}}`, String(replacement))
  return value
}

function translateValue(source: string) {
  if (!source || current.value === 'zh-CN') return source
  const leading = source.match(/^\s*/)?.[0] || ''
  const trailing = source.match(/\s*$/)?.[0] || ''
  const trimmed = source.trim()
  const exact = messages[current.value]?.[trimmed]
  if (exact) return `${leading}${exact}${trailing}`
  let output = source
  for (const [original, translated] of sortedEntries) {
    if (original.length > 1 && output.includes(original)) output = output.split(original).join(translated)
  }
  return output
}

export function installDomTranslations(root: Element = document.documentElement) {
  document.documentElement.lang = current.value
  const textOriginals = new WeakMap<Text, string>()
  const textApplied = new WeakMap<Text, string>()
  const attributeOriginals = new WeakMap<Element, Record<string, string>>()
  const attributeApplied = new WeakMap<Element, Record<string, string>>()
  const translatedAttributes = ['aria-label', 'alt', 'placeholder', 'title']
  const ignored = (element: Element | null) => element?.closest('script, style, pre, code, [data-i18n-ignore]')

  const translateTextNode = (node: Text) => {
    if (!node.data?.trim() || ignored(node.parentElement)) return
    const known = textOriginals.get(node)
    const lastApplied = textApplied.get(node)
    const original = known && node.data === lastApplied ? known : node.data
    textOriginals.set(node, original)
    const next = translateValue(original)
    textApplied.set(node, next)
    if (node.data !== next) node.data = next
  }
  const translateElement = (element: Element) => {
    if (ignored(element)) return
    let originals = attributeOriginals.get(element)
    if (!originals) { originals = {}; attributeOriginals.set(element, originals) }
    let applied = attributeApplied.get(element)
    if (!applied) { applied = {}; attributeApplied.set(element, applied) }
    for (const attribute of translatedAttributes) {
      if (!element.hasAttribute(attribute)) continue
      const value = element.getAttribute(attribute) || ''
      const previous = originals[attribute]
      if (!previous || value !== applied[attribute]) originals[attribute] = value
      const next = translateValue(originals[attribute])
      applied[attribute] = next
      if (value !== next) element.setAttribute(attribute, next)
    }
  }
  const visit = (node: Node) => {
    if (node.nodeType === Node.TEXT_NODE) { translateTextNode(node as Text); return }
    if (!(node instanceof Element) || ignored(node)) return
    translateElement(node)
    node.childNodes.forEach(visit)
  }
  const refresh = () => visit(root)
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === 'characterData') translateTextNode(mutation.target as Text)
      else if (mutation.type === 'attributes') translateElement(mutation.target as Element)
      else mutation.addedNodes.forEach(visit)
    }
  })
  observer.observe(root, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: translatedAttributes })
  const stop = watch(current, () => queueMicrotask(refresh), { flush: 'post' })
  refresh()
  return () => { observer.disconnect(); stop() }
}
