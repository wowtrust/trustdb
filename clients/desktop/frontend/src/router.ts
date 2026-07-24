import { createRouter, createWebHashHistory, RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [
  { path: '/', redirect: '/dashboard' },
  { path: '/dashboard', name: 'dashboard', component: () => import('./pages/Dashboard.vue'), meta: { title: '概览' } },
  { path: '/attest',    name: 'attest',    component: () => import('./pages/Attest.vue'),    meta: { title: '新建存证' } },
  { path: '/records',   name: 'records',   component: () => import('./pages/Records.vue'),   meta: { title: '存证记录' } },
  { path: '/verify',    name: 'verify',    component: () => import('./pages/Verify.vue'),    meta: { title: '验证证据' } },
  { path: '/anchors',   name: 'anchors',   component: () => import('./pages/AnchorSystems.vue'), meta: { title: '锚系统' } },
  { path: '/keys',      name: 'keys',      component: () => import('./pages/Keys.vue'),      meta: { title: '身份与密钥' } },
  { path: '/metrics',   name: 'metrics',   component: () => import('./pages/Metrics.vue'),   meta: { title: '服务指标' } },
  { path: '/settings',  name: 'settings',  component: () => import('./pages/Settings.vue'),  meta: { title: '设置' } },
]

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
})
