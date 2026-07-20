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
    '当前存证详情': 'Current evidence details', '测试存证.txt': 'sample-evidence.txt', '最近存证': 'Recent evidence',
    '证明链状态': 'Proof status', '存证 ID': 'Evidence ID', '复制存证 ID': 'Copy evidence ID', '创建时间': 'Created', '文件名': 'File', '操作': 'Action', '查看详情': 'View details',
    '第 {current} / {total} 步': 'Step {current} of {total}',
    '三分钟完成首次配置，立即可签、可存、可验': 'Set up in three minutes, then sign, preserve and verify evidence.',
    'TrustDB 是一套面向可审计存证的客户端 / 服务器系统，内核只有三件事：': 'TrustDB is a client/server system for auditable evidence. Its core does three things:',
    '签署、批处理、出证': 'sign, batch and issue proofs',
    '。 这个向导会在几分钟内带你走完必要的配置，之后你就可以拖拽任意文件进来完成真实的存证。': '. This guide covers the required setup in a few minutes. After that, drag in any file to preserve it as verifiable evidence.',
    '连接服务': 'Connect to a server', '配置服务地址与公钥': 'Set the server address and public key',
    '生成身份': 'Create an identity', 'Ed25519 密钥，仅存本机': 'An Ed25519 key stored only on this device',
    '注册公钥': 'Register the public key', '一行命令让服务器信任': 'One command adds it to the server trust list',
    '已经配置过？可以随时点击右上角「跳过向导」。': 'Already configured? You can skip this guide from the upper-right corner.',
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
    '当前存证详情': 'Текущее доказательство', '测试存证.txt': 'пример-доказательства.txt', '最近存证': 'Недавние доказательства',
    '证明链状态': 'Статус доказательства', '存证 ID': 'ID доказательства', '复制存证 ID': 'Копировать ID доказательства', '创建时间': 'Создано', '文件名': 'Файл', '操作': 'Действие', '查看详情': 'Подробнее',
    '第 {current} / {total} 步': 'Шаг {current} из {total}',
    '三分钟完成首次配置，立即可签、可存、可验': 'Настройте систему за три минуты, затем подписывайте, сохраняйте и проверяйте доказательства.',
    'TrustDB 是一套面向可审计存证的客户端 / 服务器系统，内核只有三件事：': 'TrustDB — клиент-серверная система для проверяемых доказательств. В её основе три операции:',
    '签署、批处理、出证': 'подписание, пакетная обработка и выпуск доказательств',
    '。 这个向导会在几分钟内带你走完必要的配置，之后你就可以拖拽任意文件进来完成真实的存证。': '. Этот мастер выполнит необходимую настройку за несколько минут. После этого перетащите любой файл, чтобы сохранить проверяемое доказательство.',
    '连接服务': 'Подключить сервер', '配置服务地址与公钥': 'Укажите адрес сервера и открытый ключ',
    '生成身份': 'Создать идентификатор', 'Ed25519 密钥，仅存本机': 'Ключ Ed25519 хранится только на этом устройстве',
    '注册公钥': 'Зарегистрировать ключ', '一行命令让服务器信任': 'Одна команда добавит ключ в список доверенных',
    '已经配置过？可以随时点击右上角「跳过向导」。': 'Уже всё настроено? Мастер можно пропустить в правом верхнем углу.',
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
    '当前存证详情': '現在の証拠', '测试存证.txt': 'サンプル証拠.txt', '最近存证': '最近の証拠',
    '证明链状态': '証明ステータス', '存证 ID': '証拠 ID', '复制存证 ID': '証拠 ID をコピー', '创建时间': '作成日時', '文件名': 'ファイル', '操作': '操作', '查看详情': '詳細を見る',
    '第 {current} / {total} 步': 'ステップ {current} / {total}',
    '三分钟完成首次配置，立即可签、可存、可验': '3分で初期設定を終え、証拠の署名・保存・検証を始められます。',
    'TrustDB 是一套面向可审计存证的客户端 / 服务器系统，内核只有三件事：': 'TrustDB は監査可能な証拠を扱うクライアント／サーバーシステムです。中核となる処理は3つです：',
    '签署、批处理、出证': '署名、バッチ処理、証明の発行',
    '。 这个向导会在几分钟内带你走完必要的配置，之后你就可以拖拽任意文件进来完成真实的存证。': '。このガイドで必要な設定を数分で済ませた後は、任意のファイルをドラッグして検証可能な証拠として保存できます。',
    '连接服务': 'サーバーに接続', '配置服务地址与公钥': 'サーバーのアドレスと公開鍵を設定',
    '生成身份': 'ID を作成', 'Ed25519 密钥，仅存本机': 'この端末だけに保存する Ed25519 鍵',
    '注册公钥': '公開鍵を登録', '一行命令让服务器信任': '1行のコマンドで信頼リストに登録',
    '已经配置过？可以随时点击右上角「跳过向导」。': '設定済みの場合は、右上からいつでもこのガイドをスキップできます。',
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
    '当前存证详情': 'Preuve actuelle', '测试存证.txt': 'exemple-preuve.txt', '最近存证': 'Preuves récentes',
    '证明链状态': 'État de la preuve', '存证 ID': 'ID de preuve', '复制存证 ID': 'Copier l’ID de preuve', '创建时间': 'Créé le', '文件名': 'Fichier', '操作': 'Action', '查看详情': 'Voir le détail',
    '第 {current} / {total} 步': 'Étape {current} sur {total}',
    '三分钟完成首次配置，立即可签、可存、可验': 'Configurez le client en trois minutes, puis signez, conservez et vérifiez vos preuves.',
    'TrustDB 是一套面向可审计存证的客户端 / 服务器系统，内核只有三件事：': 'TrustDB est un système client-serveur destiné aux preuves auditables. Son cœur réalise trois opérations :',
    '签署、批处理、出证': 'signer, regrouper et produire les preuves',
    '。 这个向导会在几分钟内带你走完必要的配置，之后你就可以拖拽任意文件进来完成真实的存证。': '. Ce guide réalise la configuration nécessaire en quelques minutes. Vous pourrez ensuite déposer n’importe quel fichier pour en conserver une preuve vérifiable.',
    '连接服务': 'Connecter un serveur', '配置服务地址与公钥': 'Indiquez l’adresse du serveur et sa clé publique',
    '生成身份': 'Créer une identité', 'Ed25519 密钥，仅存本机': 'Une clé Ed25519 conservée uniquement sur cet appareil',
    '注册公钥': 'Enregistrer la clé publique', '一行命令让服务器信任': 'Une commande suffit pour l’ajouter aux clés approuvées',
    '已经配置过？可以随时点击右上角「跳过向导」。': 'Déjà configuré ? Vous pouvez ignorer ce guide depuis le coin supérieur droit.',
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
    '当前存证详情': '현재 증거', '测试存证.txt': '샘플-증거.txt', '最近存证': '최근 증거',
    '证明链状态': '증명 상태', '存证 ID': '증거 ID', '复制存证 ID': '증거 ID 복사', '创建时间': '생성 시간', '文件名': '파일', '操作': '작업', '查看详情': '상세 보기',
    '第 {current} / {total} 步': '{total}단계 중 {current}단계',
    '三分钟完成首次配置，立即可签、可存、可验': '3분 안에 설정하고 증거 서명·보존·검증을 시작하세요.',
    'TrustDB 是一套面向可审计存证的客户端 / 服务器系统，内核只有三件事：': 'TrustDB는 감사 가능한 증거를 위한 클라이언트/서버 시스템입니다. 핵심 기능은 세 가지입니다:',
    '签署、批处理、出证': '서명, 일괄 처리, 증명 발급',
    '。 这个向导会在几分钟内带你走完必要的配置，之后你就可以拖拽任意文件进来完成真实的存证。': '. 이 안내를 따라 몇 분 안에 설정을 마치면 어떤 파일이든 끌어다 놓아 검증 가능한 증거로 보존할 수 있습니다.',
    '连接服务': '서버 연결', '配置服务地址与公钥': '서버 주소와 공개 키 설정',
    '生成身份': 'ID 만들기', 'Ed25519 密钥，仅存本机': '이 장치에만 저장되는 Ed25519 키',
    '注册公钥': '공개 키 등록', '一行命令让服务器信任': '명령 한 줄로 신뢰 목록에 등록',
    '已经配置过？可以随时点击右上角「跳过向导」。': '이미 설정했다면 오른쪽 위에서 언제든 이 안내를 건너뛸 수 있습니다.',
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
  { ...(generated[code] || {}), ...(manualMessages[code] || {}) },
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
