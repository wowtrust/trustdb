// Thin typed facade over the Wails-generated bindings. Everything in
// the rest of the app imports from here, which keeps the "magical"
// `wailsjs/...` path in exactly one file and gives us a place to
// add wrappers (logging / retries / mock fallback) later.

import * as App from '@wails/go/main/App'
import { anchor, main, model } from '@wails/go/models'

type WailsWindow = Window & {
  go?: {
    main?: {
      App?: Record<string, unknown>
    }
  }
}

// The Vite preview is intentionally usable without the native Wails shell.
// Keep that distinction explicit so browser QA never leaks an implementation
// error such as `window.go.main is undefined` into the product UI.
export function hasNativeBridge(): boolean {
  if (typeof window === 'undefined') return false
  return Boolean((window as WailsWindow).go?.main?.App)
}

export type IdentityView       = main.IdentityView
export type Settings           = main.Settings
export type FileInfo           = main.FileInfo
export type LocalRecord        = main.LocalRecord
export type SubmitRequest      = main.SubmitRequest
export type SubmitResult       = main.SubmitResult
export type BatchItemResult    = main.BatchItemResult
export type VerifyRequest      = main.VerifyRequest
export type VerifyResponse     = main.VerifyResponse
export type HealthStatus       = main.HealthStatus
export type Metric             = main.Metric
export interface RecordPageOptions {
  limit?: number
  offset?: number
  cursor?: string
  direction?: string
  query?: string
  level?: string
  batch_id?: string
  tenant_id?: string
  client_id?: string
}
export interface RecordPage {
  items: LocalRecord[]
  total: number
  limit: number
  offset: number
  has_more: boolean
  next_cursor?: string
  source?: string
  total_exact?: boolean
  error?: string
}
export type BatchRoot          = model.BatchRoot
export type ProofBundle        = model.ProofBundle
export type GlobalLogProof     = model.GlobalLogProof
export type AnchorResult       = model.STHAnchorResult
export type AnchorSystem       = model.AnchorSystem
export type AnchorSystemStatus = model.AnchorSystemStatus
export type AnchorSystemResource = model.AnchorSystemResource
export type AnchorSystemResourcePage = model.AnchorSystemResourcePage
export type OtsUpgradeSummary  = anchor.OtsUpgradeSummary
export type OtsUpgradeResult   = anchor.OtsUpgradeResult

export const api = {
  version:             () => App.Version(),
  // identity
  getIdentity:         () => App.GetIdentity(),
  generateIdentity:    (tenant: string, client: string, keyID: string) => App.GenerateIdentity(tenant, client, keyID),
  rotateIdentity:      (newKeyID: string) => App.RotateIdentity(newKeyID),
  importIdentity:      (tenant: string, client: string, keyID: string, priv: string) => App.ImportIdentity(tenant, client, keyID, priv),
  exportPrivateKey:    () => App.ExportPrivateKey(),
  clearIdentity:       () => App.ClearIdentity(),
  // settings
  getSettings:         () => App.GetSettings(),
  saveSettings:        (s: Settings) => App.SaveSettings(s),
  // files
  chooseFiles:         () => App.ChooseFiles(),
  describeFiles:       (paths: string[]) => App.DescribeFiles(paths),
  startHashing:        (paths: string[]) => App.StartHashing(paths),
  cancelHashing:       (jobID: string) => App.CancelHashing(jobID),
  chooseSavePath:      (title: string, defaultName: string) => App.ChooseSavePath(title, defaultName),
  chooseOpenPath:      (title: string) => App.ChooseOpenPath(title),
  // records / submit
  listRecords:         () => App.ListRecords(),
  listRecordsPage:     (opts: RecordPageOptions) => App.ListRecordsPage(new main.RecordPageOptions({
    limit: opts.limit ?? 50,
    offset: opts.offset ?? 0,
    cursor: opts.cursor ?? '',
    direction: opts.direction ?? '',
    query: opts.query ?? '',
    level: opts.level ?? '',
    batch_id: opts.batch_id ?? '',
    tenant_id: opts.tenant_id ?? '',
    client_id: opts.client_id ?? '',
  })) as Promise<RecordPage>,
  listRemoteRecordsPage: (opts: RecordPageOptions) => App.ListRemoteRecordsPage(new main.RecordPageOptions({
    limit: opts.limit ?? 50,
    offset: opts.offset ?? 0,
    cursor: opts.cursor ?? '',
    direction: opts.direction ?? 'desc',
    query: opts.query ?? '',
    level: opts.level ?? '',
    batch_id: opts.batch_id ?? '',
    tenant_id: opts.tenant_id ?? '',
    client_id: opts.client_id ?? '',
  })) as Promise<RecordPage>,
  deleteRecord:        (id: string) => App.DeleteRecord(id),
  submitFile:          (r: SubmitRequest) => App.SubmitFile(r),
  submitBatch:         (rs: SubmitRequest[]) => App.SubmitBatch(rs),
  refreshRecord:       (id: string) => App.RefreshRecord(id),
  getProofBundle:      (id: string) => App.GetProofBundle(id),
  exportSingleProof:   (id: string, outPath: string) => App.ExportSingleProof(id, outPath),
  exportProofBundle:   (id: string, outPath: string) => App.ExportProofBundle(id, outPath),
  exportGlobalProof:   (id: string, outPath: string) => App.ExportGlobalProof(id, outPath),
  exportAnchorResult:  (id: string, outPath: string) => App.ExportAnchorResult(id, outPath),
  upgradeOtsAnchor:    (id: string) => App.UpgradeOtsAnchor(id),
  listAnchorSystems:   () => App.ListAnchorSystems(),
  getAnchorSystemStatus: (systemID: string) => App.GetAnchorSystemStatus(systemID),
  listAnchorSystemResources: (systemID: string, kind: string, limit = 100, cursor = '') => App.ListAnchorSystemResources(systemID, kind, limit, cursor),
  getAnchorSystemResource: (systemID: string, kind: string, resourceID: string) => App.GetAnchorSystemResource(systemID, kind, resourceID),
  // server / verify
  serverHealth:        () => App.ServerHealth(),
  latestRoot:          () => App.LatestRoot(),
  listRoots:           (limit: number) => App.ListRoots(limit),
  serverMetrics:       () => App.ServerMetrics(),
  verifyProof:         (r: VerifyRequest) => App.VerifyProof(r),
}
