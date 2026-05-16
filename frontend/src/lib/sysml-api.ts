export type SysmlRole = 'admin' | 'author' | 'reader'

export type Identity = {
  username: string
  role: SysmlRole
  display?: string
  token?: string
  exp?: number
}

export type Project = {
  id: string
  name: string
  description?: string
  organization?: string
  updated_at?: string
}

export type Branch = {
  name: string
  head?: string
  created_at?: string
}

export type Relation = {
  type: string
  target: string
}

export type SysmlElement = {
  id: string
  type: string
  name: string
  stereotype?: string
  description?: string
  owner?: string
  attributes?: Record<string, unknown>
  relations?: Relation[]
}

export type Metamodel = {
  types: Record<
    string,
    {
      stereotype?: string
      required_attributes?: string[]
      relations?: Record<string, string[]>
    }
  >
  type_prefix: Record<string, string>
  type_labels: Record<string, string>
  relation_labels: Record<string, string>
  diagram_types: Record<
    string,
    {
      label: string
      types: string[]
      relations: string[]
    }
  >
}

export type ValidationIssue = {
  severity: 'error' | 'warning' | 'info'
  element_id: string
  message: string
}

export type ValidationPayload = {
  summary: {
    errors: number
    warnings: number
    infos: number
    elements: number
  }
  issues: ValidationIssue[]
}

export type DiagramNode = {
  id: string
  name: string
  type: string
  label: string
  x: number
  y: number
  width: number
  height: number
}

export type DiagramEdge = {
  source: string
  target: string
  type: string
  label: string
}

export type DiagramPayload = {
  type: string
  label: string
  nodes: DiagramNode[]
  edges: DiagramEdge[]
}

export type TraceRef = {
  id: string
  name: string
  type: string
}

export type TraceabilityRow = {
  requirement: TraceRef
  satisfied_by: TraceRef[]
  verified_by: TraceRef[]
  refined_by?: TraceRef[]
  constrained_by?: TraceRef[]
  status: 'closed' | 'partial' | 'open'
}

export type Commit = {
  id: string
  branch: string
  message: string
  author: string
  created_at: string
  element_count: number
}

export type AuditEvent = {
  action: string
  branch_name?: string
  actor: string
  created_at: string
  element_id?: string
  detail?: Record<string, unknown>
}

export type DiffPayload = {
  from: string
  to: string
  summary: {
    added: number
    removed: number
    modified: number
  }
  added: SysmlElement[]
  removed: SysmlElement[]
  modified: {
    id: string
    name: string
    changes: { field: string }[]
  }[]
}

export type DocumentRecord = {
  id: string
  title?: string
  created_at: string
  model_hash: string
  html?: string
  markdown?: string
  pdf_base64?: string
}

type ApiOptions = RequestInit & {
  identity?: Identity | null
  role?: SysmlRole
}

const apiBase = (import.meta.env.VITE_SYSML_API_BASE || '').replace(/\/$/, '')

const identityStorageKey = 'sysml_identity'
const tokenStorageKey = 'sysml_token'

export function loadIdentity(): Identity | null {
  const stored = window.localStorage.getItem(identityStorageKey)
  if (!stored) return null
  try {
    return JSON.parse(stored) as Identity
  } catch {
    window.localStorage.removeItem(identityStorageKey)
    window.localStorage.removeItem(tokenStorageKey)
    return null
  }
}

export function saveIdentity(identity: Identity | null) {
  if (!identity) {
    window.localStorage.removeItem(identityStorageKey)
    window.localStorage.removeItem(tokenStorageKey)
    return
  }
  window.localStorage.setItem(identityStorageKey, JSON.stringify(identity))
  if (identity.token) {
    window.localStorage.setItem(tokenStorageKey, identity.token)
  }
}

export async function api<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const identity = options.identity ?? loadIdentity()
  const headers = new Headers(options.headers)
  headers.set('Content-Type', headers.get('Content-Type') || 'application/json')
  headers.set('X-User', identity?.username || 'engineer')
  headers.set('X-Role', identity?.role || options.role || 'author')

  const token = identity?.token || window.localStorage.getItem(tokenStorageKey)
  if (token) headers.set('Authorization', `Bearer ${token}`)

  const response = await fetch(`${apiBase}${path}`, {
    ...options,
    headers,
  })

  if (!response.ok) {
    let message = response.statusText
    try {
      const payload = await response.json()
      message = payload.error || payload.detail || message
    } catch {
      message = await response.text()
    }
    throw new Error(message || '请求失败')
  }

  const contentType = response.headers.get('Content-Type') || ''
  if (contentType.includes('application/json')) {
    return response.json() as Promise<T>
  }
  return response.text() as T
}

export async function login(username: string, password: string) {
  return api<{ identity: Identity }>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
    identity: null,
  })
}

export function defaultElement(
  type: string,
  metamodel: Metamodel | null
): SysmlElement {
  const modelType = metamodel?.types[type]
  const attributes = Object.fromEntries(
    (modelType?.required_attributes || []).map((key) => [key, ''])
  )
  return {
    id: '',
    type,
    name: '',
    stereotype: modelType?.stereotype || type.toLowerCase(),
    owner: '',
    description: '',
    attributes,
    relations: [],
  }
}
