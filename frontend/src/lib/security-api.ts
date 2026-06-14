export type SecuritySeverity = 'critical' | 'high' | 'medium' | 'low'

export type VexStatus = 'affected' | 'not_affected' | 'under_investigation' | 'fixed'

export type SecurityModule = {
  key: string
  name: string
  status: string
  score: number
  signals: number
  description: string
}

export type SecurityFinding = {
  id: string
  title: string
  module: string
  severity: SecuritySeverity
  score: number
  asset: string
  evidence: string
  first_seen: string
  owner: string
  status: string
}

export type CodeAuditFinding = {
  id: string
  rule_id: string
  title: string
  category: string
  severity: SecuritySeverity
  score: number
  risk_file: string
  line: number
  end_line?: number | null
  evidence: string
  recommendation: string
  scanner: string
  confidence: string
  cwe?: string | null
  fingerprint: string
}

export type CodeAuditScanner = {
  name: string
  available: boolean
  command: string
  version?: string | null
  error?: string | null
  state?: 'ok' | 'skipped' | 'missing' | 'fallback' | 'partial' | 'failed' | string
}

export type CodeAuditResult = {
  scan_id: string | null
  generated_at?: string
  target_path?: string
  target?: {
    importId?: string
    projectName?: string
    sourceType?: string
  }
  summary: {
    total: number
    critical?: number
    high?: number
    medium?: number
    low?: number
    by_category?: Record<string, number>
    target?: {
      importId?: string
      projectName?: string
      sourceType?: string
    }
    tools?: Array<{
      name: string
      available: boolean
      version?: string | null
      error?: string | null
      state?: string
    }>
    duration_seconds?: number
    timeout_seconds?: number
    target_key?: string
    ignored?: number
    ignored_total?: number
    baseline_exists?: boolean
    baseline_total?: number
    baseline_created_at?: string | null
    new?: number
    fixed?: number
    trend?: CodeAuditTrendPoint[]
  }
  findings: CodeAuditFinding[]
  scanners?: CodeAuditScanner[]
  errors?: string[]
  report: string
  sarif?: Record<string, unknown>
}

export type GitHubCodeScanningUploadPayload = {
  owner: string
  repo: string
  ref: string
  commit_sha?: string
  checkout_uri?: string
  token?: string
}

export type GitHubCodeScanningUploadResult = {
  repository: string
  ref: string
  commit_sha: string
  sarif_id?: string | null
  url?: string | null
  status: string
  raw?: Record<string, unknown>
}

export type GitHubCodeScanningStatusPayload = {
  owner: string
  repo: string
  sarif_id: string
  token?: string
}

export type GitHubCodeScanningStatusResult = {
  repository: string
  sarif_id: string
  status?: string | null
  analyses_url?: string | null
  errors: string[]
  raw?: Record<string, unknown>
}

export type CodeAuditTrendPoint = {
  scan_id: string
  generated_at: string
  target_key: string
  projectName?: string
  total: number
  critical: number
  high: number
  medium: number
  low: number
  new: number
  fixed: number
  ignored: number
  tools?: string[]
}

export type CodeAuditState = {
  target_key?: string | null
  ignored: Array<Record<string, unknown>>
  baseline?: Record<string, unknown> | null
  baselines?: Record<string, unknown>
  trend: CodeAuditTrendPoint[]
}

export type SecurityDependency = {
  name: string
  version: string
  ecosystem: string
  scope?: string
  source_file?: string
  manifest_type?: string
  license: string
  purl?: string
  risk: number
  signals: string[]
  requested_version?: string | null
  version_source?: 'manifest' | 'lockfile' | 'environment' | 'sbom' | 'osv' | string
  dependency_type?: 'direct' | 'transitive' | string
  resolved?: boolean
  vulnerabilities?: Array<{
    id: string
    source: string
    severity: SecuritySeverity
    affected: string
    summary: string
    confidence: string
    fixed_versions?: string[]
    vex?: VexStatement
    analysis?: {
      state?: string
      justification?: string
      response?: string[]
      detail?: string
    }
  }>
  reachability?: DependencyReachability
  vex?: VexStatement[]
  recommendation: string
}

export type DependencyReachability = {
  imported?: boolean
  called?: boolean
  attack_surface?: boolean
  runtime_trace?: boolean
  confidence?: number
  import_candidates?: string[]
  code_evidence?: ReachabilityEvidence[]
  call_evidence?: ReachabilityEvidence[]
  attack_surface_evidence?: ReachabilityEvidence[]
  runtime_evidence?: ReachabilityEvidence[]
}

export type ReachabilityEvidence = {
  path?: string
  line?: number
  snippet?: string
  kind?: string
  id?: string
  rule_id?: string
  severity?: string
  time?: string
  source?: string
  event?: string
  evidence?: string
}

export type VexStatement = {
  id: string
  source?: string
  dependency?: string
  purl?: string
  status: VexStatus
  cyclonedx_state?: string
  justification?: string
  response?: string[]
  detail?: string
  confidence?: string
  severity?: SecuritySeverity | string
  fixed_versions?: string[]
  reachability?: DependencyReachability & {
    nearby_high_signal?: boolean
  }
}

export type DependencyAuditFinding = {
  id: string
  title: string
  severity: SecuritySeverity
  score: number
  dependency: string
  ecosystem: string
  source_file: string
  evidence: string
  recommendation: string
  fingerprint: string
}

export type DependencyAuditResult = {
  scan_id: string | null
  generated_at?: string
  target_path?: string
  target?: {
    importId?: string
    projectName?: string
    sourceType?: string
  }
  summary: {
    total_dependencies: number
    manifest_count: number
    finding_count: number
    risk_score: number
    risk_level: SecuritySeverity
    critical: number
    high: number
    medium: number
    low: number
    ecosystems: Record<string, number>
    version_sources?: Record<string, number>
    unknown_licenses: number
    vulnerable_dependencies: number
    osv_matches?: number
    suspicious_names: number
    exact_versions?: number
    transitive_dependencies?: number
    lockfile_count?: number
    vex?: {
      statement_count: number
      component_count: number
      affected: number
      not_affected: number
      under_investigation: number
      fixed: number
      actionable: number
      noise_reduced: number
      false_positive_reduction_percent: number
      states?: Record<VexStatus, number>
    }
    reachability?: {
      imported_dependencies: number
      called_dependencies: number
      attack_surface_dependencies: number
      runtime_trace_dependencies: number
      source_files_scanned: number
      source_files_skipped: number
      service_exposed: boolean
      service_hints: string[]
      runtime_log_findings: number
      runtime_log_events: number
      runtime_categories: Record<string, number>
    }
    tools?: DependencyAuditToolStatus[]
    duration_seconds?: number
  }
  dependencies: SecurityDependency[]
  findings: DependencyAuditFinding[]
  sbom: Record<string, unknown>
  vex?: Record<string, unknown>
  report: string
  warnings: string[]
  tools?: DependencyAuditToolStatus[]
}

export type CICDAuditFinding = {
  id: string
  rule_id: string
  title: string
  severity: SecuritySeverity
  score: number
  workflow: string
  job_id?: string | null
  job_name?: string | null
  step_index?: number | null
  step_name?: string | null
  line: number
  evidence: string
  reason: string
  recommendation: string
  fingerprint: string
  scanner?: string
  confidence?: string
}

export type CICDAuditResult = {
  scan_id: string | null
  generated_at?: string
  target_path?: string
  target?: {
    importId?: string
    projectName?: string
    sourceType?: string
  }
  workflows: string[]
  summary: {
    workflow_count: number
    job_count: number
    total_steps: number
    finding_count: number
    risk_score: number
    risk_level: SecuritySeverity
    critical: number
    high: number
    medium: number
    low: number
    by_rule?: Record<string, number>
    duration_seconds?: number
    tools?: Array<{
      name: string
      available: boolean
      version?: string | null
      error?: string | null
      state?: string
    }>
    ignored?: number
    ignored_total?: number
    baseline_exists?: boolean
    baseline_total?: number
    baseline_created_at?: string | null
    new?: number
    fixed?: number
  }
  findings: CICDAuditFinding[]
  scanners?: CodeAuditScanner[]
  sarif?: Record<string, unknown>
  state?: CodeAuditState
  report: string
  warnings: string[]
}

export type ArtifactTrustCheckStatus = 'pass' | 'fail' | 'warn' | 'missing' | 'skipped' | string

export type ArtifactTrustCheck = {
  name: string
  status: ArtifactTrustCheckStatus
  evidence?: string
  severity?: SecuritySeverity | string
  score?: number
}

export type ArtifactTrustFinding = {
  id: string
  title: string
  severity: SecuritySeverity
  score: number
  evidence: string
  recommendation: string
  check: string
  fingerprint: string
}

export type ArtifactTrustResult = {
  scan_id: string | null
  generated_at?: string
  artifact: string
  artifact_path?: string
  attestation_path?: string
  digest: string
  trustScore?: number
  trust_score: number
  level: string
  checks: ArtifactTrustCheck[]
  findings: ArtifactTrustFinding[]
  provenance: {
    subject_name?: string
    subject_digest?: string
    predicateType?: string
    predicate_type?: string
    builder_id?: string
    build_type?: string
    source_repo?: string
    commit?: string
    workflow?: string
    ref?: string
    runner_environment?: string
    invocation_id?: string
    created_at?: string
    envelope_signature_count?: number
    has_envelope?: boolean
  }
  policy: Record<string, unknown>
  tools: CodeAuditScanner[]
  graphEvidence?: {
    nodes?: Array<Record<string, unknown>>
    edges?: Array<Record<string, unknown>>
  }
  graph_evidence?: {
    nodes?: Array<Record<string, unknown>>
    edges?: Array<Record<string, unknown>>
  }
  summary: {
    check_count: number
    finding_count: number
    trust_score: number
    level: string
    risk_score: number
    risk_level: SecuritySeverity
    passed: number
    failed: number
    warnings: number
    missing: number
    skipped: number
    critical?: number
    high?: number
    medium?: number
    low?: number
    duration_seconds?: number
  }
  report: string
  warnings: string[]
}

export type ArtifactTrustScanOptions = {
  workspaceId?: string
  artifactPath?: string
  attestationPath?: string
  policyArtifact?: string
  expectedRepo?: string
  expectedCommit?: string
  allowedBranches?: string[]
  allowedWorkflows?: string[]
  allowedBuilders?: string[]
  requireSignature?: boolean
  requireProvenance?: boolean
  allowSelfHostedRunner?: boolean
  maxAgeHours?: number
}

export type ArtifactTrustUploadOptions = Omit<ArtifactTrustScanOptions, 'artifactPath' | 'attestationPath'> & {
  artifact: File
  attestation: File
}

export type DependencyAuditToolStatus = {
  name: string
  available: boolean
  command: string
  version?: string | null
  state: 'ok' | 'missing' | 'failed' | 'partial' | string
  error?: string | null
}

export type SecurityPipelineStep = {
  step: string
  name: string
  status: string
  detail: string
  actor: string
  time: string
}

export type SecurityLogEvent = {
  time: string
  source: string
  event: string
  severity: SecuritySeverity
  signal: string
  confidence: number
}

export type LogAuditFinding = {
  id: string
  rule_id: string
  title: string
  severity: SecuritySeverity
  score: number
  time: string
  source: string
  event: string
  signal: string
  confidence: number
  evidence: string
  src_ip?: string | null
  dst_ip?: string | null
  user?: string | null
  path?: string | null
  count?: number | null
  fingerprint: string
}

export type LogAuditResult = {
  scan_id: string | null
  generated_at?: string
  files: Array<{
    filename: string
    source: string
    size_bytes: number
    total_lines: number
    parsed_lines: number
    skipped_lines: number
  }>
  summary: {
    file_count: number
    total_lines: number
    total_events: number
    parsed_events: number
    skipped_lines: number
    finding_count: number
    risk_score: number
    risk_level: SecuritySeverity
    critical: number
    high: number
    medium: number
    low: number
    by_rule?: Record<string, number>
    by_source?: Record<string, number>
    rule_count?: number
    duration_seconds?: number
  }
  events: Array<Record<string, unknown>>
  findings: LogAuditFinding[]
  report: string
  warnings: string[]
}

export type MultimodalSourceType = 'audio' | 'image' | 'video'

export type MultimodalToolStatus = {
  name: string
  available: boolean
  command: string
  version?: string | null
  state: 'ok' | 'missing' | 'failed' | 'partial' | string
  error?: string | null
}

export type MultimodalDerivedArtifact = {
  kind: string
  path: string
  relative_path: string
  mime_type: string
  size_bytes: number
  created_at: string
  tool: string
}

export type MultimodalRecognition = {
  source_type: MultimodalSourceType
  recognized_text: string
  confidence: number
  evidence_type: 'audio_asr' | 'visual_ocr' | string
  engine: string
  source_path: string
  language?: string | null
  created_at: string
  segments: Array<Record<string, unknown>>
}

export type MultimodalEntity = {
  type: string
  value: string
  normalized: string
  start: number
  end: number
  confidence: number
  source: string
  evidence: string
}

export type MultimodalFinding = {
  id: string
  rule_id: string
  title: string
  severity: SecuritySeverity
  score: number
  evidence_id: string
  source_type: MultimodalSourceType
  source_name: string
  evidence_type: string
  matched_keywords: string[]
  entities: MultimodalEntity[]
  evidence: string
  confidence: number
  recommendation: string
  references: string[]
  tags: string[]
  first_seen: string
  fingerprint: string
}

export type MultimodalEvidence = {
  evidence_id: string
  filename: string
  original_filename: string
  file_path: string
  relative_path: string
  source_type: MultimodalSourceType
  mime_type: string
  size_bytes: number
  sha256: string
  uploaded_at: string
  metadata: Record<string, unknown>
  derived: MultimodalDerivedArtifact[]
  recognitions: MultimodalRecognition[]
  entities: MultimodalEntity[]
  findings: MultimodalFinding[]
  risk_score: number
  risk_level: SecuritySeverity
}

export type MultimodalAuditResult = {
  scan_id: string | null
  generated_at?: string | null
  evidence: MultimodalEvidence[]
  tools: MultimodalToolStatus[]
  summary: {
    evidence_count: number
    audio: number
    image: number
    video: number
    derived_count: number
    recognition_count: number
    asr_count: number
    ocr_count: number
    entity_count: number
    finding_count: number
    risk_score: number
    risk_level: SecuritySeverity
    critical: number
    high: number
    medium: number
    low: number
    by_entity_type?: Record<string, number>
    by_rule?: Record<string, number>
    total_size_bytes: number
    storage_dir: string
    storage_relative_dir: string
    duration_seconds?: number
  }
  report: string
  warnings: string[]
}

export type RealtimeLogEvent = {
  time: string
  source: string
  log_type?: string
  filename?: string
  line_number?: number
  src_ip?: string | null
  dst_ip?: string | null
  user?: string | null
  method?: string | null
  path?: string | null
  status?: number | null
  message?: string
  raw?: string
}

export type RealtimeLogTrendPoint = {
  bucket: string
  events: number
  findings: number
  critical: number
  high: number
  medium: number
  low: number
}

export type RealtimeLogPayload = {
  mode: 'realtime'
  accepted?: number
  storage?: {
    events: string
    findings: string
    state: string
  }
  summary: {
    event_count: number
    stored_finding_count: number
    finding_count: number
    risk_score: number
    risk_level: SecuritySeverity
    critical: number
    high: number
    medium: number
    low: number
    by_source?: Record<string, number>
    by_rule?: Record<string, number>
  }
  events: RealtimeLogEvent[]
  findings: Array<LogAuditFinding & {
    dedupe_key?: string
    last_seen?: string
    occurrences?: number
    ignored?: boolean
    baseline?: boolean
  }>
  trend: RealtimeLogTrendPoint[]
  state: {
    ignored_count: number
    baseline?: {
      created_at?: string
      note?: string
      finding_count?: number
    } | null
    runs: Array<Record<string, unknown>>
  }
  warnings: string[]
}

export type SecurityGraphNode = {
  id: string
  label: string
  type: string
  risk: string
  description: string
  score?: number
  source?: string
  source_model?: string
  evidence_ids?: string[]
  properties?: Record<string, unknown>
  position?: {
    x: number
    y: number
  }
}

export type SecurityGraphEdge = {
  id: string
  source: string
  target: string
  type?: string
  label: string
  confidence?: number
  reason?: string
  evidence_ids?: string[]
  properties?: Record<string, unknown>
}

export type SecurityAttackPath = {
  id: string
  title: string
  category: string
  severity: SecuritySeverity
  score: number
  description: string
  conclusion?: string
  verdict?: string
  confidence?: number
  entry_node_id?: string
  target_node_id?: string
  node_ids?: string[]
  edge_ids?: string[]
  evidence_ids?: string[]
  recommendation: string
  path_steps?: Array<{
    index?: number
    source?: string
    source_type?: string
    target?: string
    target_type?: string
    relationship?: string
    edge_type?: string
    confidence?: number
    why_abusable?: string
    trust_basis?: string
    model?: string
    evidence_ids?: string[]
  }>
  evidence_summary?: Array<{
    id?: string
    kind?: string
    title?: string
    detail?: string
    source?: string
    source_model?: string
    time?: string
    confidence?: number
  }>
  trust_chain?: Array<{
    model?: string
    claim?: string
    subject?: string
    status?: string
    basis?: string
  }>
  checks?: Array<{
    id?: string
    name?: string
    label?: string
    status?: ArtifactTrustCheckStatus
    value?: string
    evidence?: string
    severity?: SecuritySeverity | string
    score?: number
  }>
  trust_score?: number
  gaps?: string[]
  choke_points?: Array<{
    node_id?: string
    label?: string
    action?: string
  }>
  mappings?: Array<Record<string, unknown>>
  references?: string[]
}

export type SecurityFactAsset = {
  id: string
  type: string
  label: string
  source: string
  source_model: string
  risk_score?: number
  risk_level?: SecuritySeverity | string
  locator?: Record<string, unknown>
  properties?: Record<string, unknown>
}

export type SecurityFactEvidence = {
  id: string
  source: string
  source_model: string
  kind: string
  title: string
  detail: string
  asset_id?: string
  time?: string
  locator?: Record<string, unknown>
  confidence?: number
  properties?: Record<string, unknown>
}

export type SecurityFactFinding = {
  id: string
  title: string
  severity: SecuritySeverity
  score: number
  source: string
  source_model: string
  asset_ids: string[]
  evidence_ids: string[]
  fingerprint: string
  recommendation: string
  category?: string
  first_seen?: string
  status?: string
  properties?: Record<string, unknown>
}

export type SecurityFacts = {
  schema_version: string
  generated_at: string
  references: Array<{
    name: string
    url: string
    used_for: string[]
  }>
  summary: {
    asset_count: number
    evidence_count: number
    finding_count: number
    risk_score: number
    risk_level: SecuritySeverity
    critical: number
    high: number
    medium: number
    low: number
    asset_types: Record<string, number>
    sources: Record<string, number>
    source_models: Record<string, number>
  }
  assets: SecurityFactAsset[]
  evidence: SecurityFactEvidence[]
  findings: SecurityFactFinding[]
}

export type SecurityAssistantPayload = {
  default_question: string
  answer: string
  retrieval: string[]
  next_actions: string[]
}

export type SecurityWorkspace = {
  workspaceId?: string
  workspace_id?: string
  generated_at: string
  workspace: {
    workspaceId?: string
    importId?: string
    preset?: string
    name: string
    repository: string
    branch: string
    commit: string
    build: string
    runtime: string
    mode: string
  }
  summary: {
    risk_score: number
    risk_level: string
    open_findings: number
    critical_findings: number
    repositories: number
    dependencies: number
    build_steps: number
    log_events: number
    multimodal_evidence?: number
    attack_paths: number
    mean_triage_minutes: number
  }
  modules: SecurityModule[]
  trend: Array<{
    day: string
    code: number
    dependency: number
    build: number
    runtime: number
  }>
  findings: SecurityFinding[]
  dependencies: SecurityDependency[]
  pipeline: SecurityPipelineStep[]
  logs: SecurityLogEvent[]
  graph?: {
    schema_version?: string
    generated_at?: string
    references?: Array<{
      name: string
      url: string
      used_for: string[]
    }>
    summary?: {
      node_count: number
      edge_count: number
      attack_path_count: number
      actionable_attack_path_count?: number
      real_attack_path_count?: number
      path_verdicts?: Record<string, number>
      average_path_confidence?: number
      risk_score: number
      risk_level: SecuritySeverity
      node_types: Record<string, number>
      edge_types: Record<string, number>
    }
    nodes?: SecurityGraphNode[]
    edges?: SecurityGraphEdge[]
    attack_paths?: SecurityAttackPath[]
  } | null
  facts: SecurityFacts | null
  assistant?: SecurityAssistantPayload | null
  integrations: Array<{
    name: string
    status: string
    records: number
  }>
  code_audit?: CodeAuditResult | null
  dependency_audit?: DependencyAuditResult | null
  cicd_audit?: CICDAuditResult | null
  artifact_trust?: ArtifactTrustResult | null
  log_audit?: LogAuditResult | null
  multimodal_audit?: MultimodalAuditResult | null
  guidance?: {
    currentStep: string
    currentStepLabel: string
    defenseNotice: string
    steps: Array<{
      id: string
      label: string
      description: string
      done: boolean
      target: string
    }>
    nextActions: Array<{
      title: string
      description: string
      target: string
    }>
  }
  evidence?: Array<Record<string, unknown>>
  normalized_findings?: Array<Record<string, unknown>>
  report_html?: string | null
  report?: string | null
}

export type SecurityAssistantResponse = {
  question: string
  answer: string
  retrieval: string[]
  next_actions: string[]
  model: string
}

export type AgentRunStepStatus = 'pending' | 'running' | 'success' | 'skipped' | 'failed'
export type AgentJobStatus = 'idle' | 'queued' | 'running' | 'success' | 'partial' | 'failed' | 'cancelled' | string
export type AgentActionKind =
  | 'open_evidence_gap'
  | 'open_module'
  | 'scan_logs'
  | 'rerun_artifact_trust'
  | 'review_high_risk_dependencies'
  | 'generate_defense_brief'
  | 'export_evidence_package'
  | 'copy_keywords'
  | 'show_examples'
  | string

export type AgentRunStep = {
  id: string
  name: string
  description: string
  status: AgentRunStepStatus
  durationSeconds: number
  input: Record<string, unknown>
  summary: Record<string, unknown>
  error: string
}

export type AgentRunEvent = {
  id: string
  stepId: string
  kind: string
  level: 'info' | 'warning' | 'error' | string
  message: string
  createdAt: string
}

export type AgentEvidenceGap = {
  id: string
  module: string
  severity: SecuritySeverity
  question?: string
  missingItems?: string[]
  reason: string
  whereToFind: string[]
  uploadTo: string
  proves: string
  keywords: string[]
  examplePaths?: string[]
  actionButtons?: Array<{
    label: string
    actionKind: AgentActionKind
    targetModule?: string
  }>
}

export type AgentNextAction = {
  priority: 'high' | 'medium' | 'low'
  title: string
  action: string
  targetModule: string
  keywords: string[]
  actionKind?: AgentActionKind
  payload?: Record<string, unknown>
}

export type AgentRunRequest = {
  workspaceId?: string
  importId?: string
  targetPath?: string
  artifactPath?: string
  attestationPath?: string
  expectedRepo?: string
  expectedCommit?: string
  allowedWorkflows?: string[]
  allowedBuilders?: string[]
  allowSelfHostedRunner?: boolean
  requireSignature?: boolean
  logPaths?: string[]
  includeCodeAudit?: boolean
  includeDependencyAudit?: boolean
  includeCicdAudit?: boolean
  includeArtifactTrust?: boolean
  includeLogAudit?: boolean
  timeoutSeconds?: number
}

export type AgentRunResult = {
  runId: string | null
  status: AgentJobStatus
  startedAt?: string
  durationSeconds?: number
  input?: AgentRunRequest
  steps: AgentRunStep[]
  events?: AgentRunEvent[]
  summary: {
    stepCount: number
    success: number
    skipped: number
    failed: number
    evidenceGapCount: number
    riskScore: number
    riskLevel: SecuritySeverity
  }
  evidenceGaps: AgentEvidenceGap[]
  nextActions: AgentNextAction[]
  narrative?: {
    summary: string
    timeline: string[]
    verdict: string
    confidence: number
    keyEvidence: string[]
    defenseBrief: string
  }
  workspace?: SecurityWorkspace
  report?: string
  error?: string
}

const apiBase = (import.meta.env.VITE_SECURITY_API_BASE || '').replace(/\/$/, '')

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  headers.set('Content-Type', headers.get('Content-Type') || 'application/json')

  const response = await fetch(`${apiBase}${path}`, {
    ...options,
    headers,
  })

  if (!response.ok) {
    let message = response.statusText
    const errorText = await response.text()
    try {
      const payload = JSON.parse(errorText)
      message = payload.error || payload.detail || message
    } catch {
      message = errorText
    }
    throw new Error(message || 'Request failed')
  }

  return response.json() as Promise<T>
}

export async function loadSecurityWorkspace() {
  return api<SecurityWorkspace>('/api/security/workspace')
}

export async function createSecurityWorkspace(options: {
  importId?: string
  preset?: string
  name?: string
}) {
  return api<SecurityWorkspace>('/api/security/workspaces', {
    method: 'POST',
    body: JSON.stringify(options),
  })
}

export async function loadSecurityWorkspaceById(workspaceId: string) {
  return api<SecurityWorkspace>(`/api/security/workspaces/${encodeURIComponent(workspaceId)}`)
}

export async function runWorkspaceScanSuite(workspaceId: string, options: AgentRunRequest = {}) {
  const timeoutSeconds = options.timeoutSeconds ?? 180
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), (timeoutSeconds + 120) * 1000)
  try {
    return await api<SecurityWorkspace>(`/api/security/workspaces/${encodeURIComponent(workspaceId)}/scan-suite`, {
      method: 'POST',
      signal: controller.signal,
      body: JSON.stringify({ ...options, timeoutSeconds }),
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new Error('一键溯源超时，请切换分步模式或缩小扫描范围后重试')
    }
    throw error
  } finally {
    clearTimeout(timeoutId)
  }
}

export async function downloadWorkspaceEvidencePackage(workspaceId: string) {
  const response = await fetch(`${apiBase}/api/security/workspaces/${encodeURIComponent(workspaceId)}/evidence-package`)
  if (!response.ok) {
    throw new Error((await response.text()) || '工作空间证据包导出失败')
  }
  return response.blob()
}

export async function askSecurityAssistant(question: string) {
  return api<SecurityAssistantResponse>('/api/security/assistant', {
    method: 'POST',
    body: JSON.stringify({ question }),
  })
}

export async function runSecurityAgent(options: AgentRunRequest) {
  const timeoutSeconds = options.timeoutSeconds ?? 180
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), (timeoutSeconds + 90) * 1000)
  try {
    return await api<AgentRunResult>('/api/security/agent/run', {
      method: 'POST',
      signal: controller.signal,
      body: JSON.stringify(options),
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new Error('Agent 智能溯源超时，请缩小扫描范围或关闭部分扫描模块后重试')
    }
    throw error
  } finally {
    clearTimeout(timeoutId)
  }
}

export async function loadLatestSecurityAgentRun() {
  return api<AgentRunResult>('/api/security/agent/latest')
}

export async function createSecurityAgentJob(options: AgentRunRequest) {
  return api<AgentRunResult>('/api/security/agent/jobs', {
    method: 'POST',
    body: JSON.stringify(options),
  })
}

export async function loadSecurityAgentJob(runId: string) {
  return api<AgentRunResult>(`/api/security/agent/jobs/${encodeURIComponent(runId)}`)
}

export async function loadLatestSecurityAgentJob() {
  return api<AgentRunResult>('/api/security/agent/jobs/latest')
}

export async function downloadAgentEvidencePackage(runId: string) {
  const response = await fetch(`${apiBase}/api/security/agent/jobs/${encodeURIComponent(runId)}/evidence-package`)
  if (!response.ok) {
    throw new Error((await response.text()) || '证据包导出失败')
  }
  return response.blob()
}

export type CodeAuditScanOptions = {
  workspaceId?: string
  importId?: string
  targetPath?: string
  includeCheckov?: boolean
  timeoutSeconds?: number
}

export async function runCodeAuditScan(options: CodeAuditScanOptions = {}) {
  const controller = new AbortController()
  const timeoutSeconds = options.timeoutSeconds
  const timeoutId =
    timeoutSeconds === undefined
      ? undefined
      : setTimeout(() => controller.abort(), (timeoutSeconds + 20) * 1000)

  try {
    return await api<CodeAuditResult>('/api/security/code-audit/scan', {
      method: 'POST',
      signal: controller.signal,
      body: JSON.stringify({
        ...(options.importId ? { importId: options.importId } : {}),
        ...(options.workspaceId ? { workspaceId: options.workspaceId } : {}),
        ...(options.targetPath ? { target_path: options.targetPath } : {}),
        ...(options.includeCheckov === undefined ? {} : { include_checkov: options.includeCheckov }),
        ...(timeoutSeconds === undefined ? {} : { timeout_seconds: timeoutSeconds }),
      }),
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new Error('扫描超时，请缩小扫描范围后重试')
    }
    throw error
  } finally {
    if (timeoutId !== undefined) clearTimeout(timeoutId)
  }
}

export async function ignoreCodeAuditFinding(fingerprint: string, reason = 'false-positive') {
  return api<{ state: CodeAuditState; code_audit: CodeAuditResult | null }>('/api/security/code-audit/ignore', {
    method: 'POST',
    body: JSON.stringify({ fingerprint, reason }),
  })
}

export async function createCodeAuditBaseline(note = '') {
  return api<{ state: CodeAuditState; code_audit: CodeAuditResult | null }>('/api/security/code-audit/baseline', {
    method: 'POST',
    body: JSON.stringify({ note }),
  })
}

export async function loadCodeAuditState() {
  return api<CodeAuditState>('/api/security/code-audit/state')
}

export async function loadCodeAuditSarif() {
  return api<Record<string, unknown>>('/api/security/code-audit/sarif')
}

export type DependencyAuditScanOptions = {
  workspaceId?: string
  importId?: string
  targetPath?: string
  includeDev?: boolean
  includeOsv?: boolean
  includeCdxgen?: boolean
  includeCyclonedxPy?: boolean
  mode?: 'auto' | 'manifest' | 'lockfile' | 'sbom'
}

export async function runDependencyAuditScan(options: DependencyAuditScanOptions = {}) {
  return api<DependencyAuditResult>('/api/security/dependencies/scan', {
    method: 'POST',
    body: JSON.stringify({
      ...(options.importId ? { importId: options.importId } : {}),
      ...(options.workspaceId ? { workspaceId: options.workspaceId } : {}),
      ...(options.targetPath ? { targetPath: options.targetPath } : {}),
      ...(options.includeDev === undefined ? {} : { includeDev: options.includeDev }),
      ...(options.includeOsv === undefined ? {} : { includeOsv: options.includeOsv }),
      ...(options.includeCdxgen === undefined ? {} : { includeCdxgen: options.includeCdxgen }),
      ...(options.includeCyclonedxPy === undefined ? {} : { includeCyclonedxPy: options.includeCyclonedxPy }),
      ...(options.mode === undefined ? {} : { mode: options.mode }),
    }),
  })
}

export async function loadDependencyAuditSbom() {
  return api<Record<string, unknown>>('/api/security/dependencies/sbom')
}

export async function loadDependencyAuditVex() {
  return api<Record<string, unknown>>('/api/security/dependencies/vex')
}

export type CICDAuditScanOptions = {
  workspaceId?: string
  importId?: string
  targetPath?: string
}

export async function runCICDAuditScan(options: CICDAuditScanOptions = {}) {
  return api<CICDAuditResult>('/api/security/cicd/scan', {
    method: 'POST',
    body: JSON.stringify({
      ...(options.importId ? { importId: options.importId } : {}),
      ...(options.workspaceId ? { workspaceId: options.workspaceId } : {}),
      ...(options.targetPath ? { targetPath: options.targetPath } : {}),
    }),
  })
}

export async function loadCICDAuditSarif() {
  return api<Record<string, unknown>>('/api/security/cicd/sarif')
}

export async function runArtifactTrustScan(options: ArtifactTrustScanOptions = {}) {
  return api<ArtifactTrustResult>('/api/security/artifact-trust/scan', {
    method: 'POST',
    body: JSON.stringify(options),
  })
}

export async function uploadArtifactTrustScan(options: ArtifactTrustUploadOptions) {
  const formData = new FormData()
  formData.set('artifact', options.artifact)
  formData.set('attestation', options.attestation)
  if (options.expectedRepo) formData.set('expectedRepo', options.expectedRepo)
  if (options.expectedCommit) formData.set('expectedCommit', options.expectedCommit)
  if (options.allowedBranches?.length) formData.set('allowedBranches', options.allowedBranches.join(','))
  if (options.allowedWorkflows?.length) formData.set('allowedWorkflows', options.allowedWorkflows.join(','))
  if (options.allowedBuilders?.length) formData.set('allowedBuilders', options.allowedBuilders.join(','))
  if (options.requireSignature !== undefined) formData.set('requireSignature', String(options.requireSignature))
  if (options.requireProvenance !== undefined) formData.set('requireProvenance', String(options.requireProvenance))
  if (options.allowSelfHostedRunner !== undefined) formData.set('allowSelfHostedRunner', String(options.allowSelfHostedRunner))
  if (options.maxAgeHours !== undefined) formData.set('maxAgeHours', String(options.maxAgeHours))
  if (options.workspaceId) formData.set('workspaceId', options.workspaceId)

  const response = await fetch(`${apiBase}/api/security/artifact-trust/upload`, {
    method: 'POST',
    body: formData,
  })

  if (!response.ok) {
    let message = response.statusText
    const errorText = await response.text()
    try {
      const payload = JSON.parse(errorText)
      message = payload.error || payload.detail || message
    } catch {
      message = errorText
    }
    throw new Error(message || '产物可信验证失败')
  }

  return response.json() as Promise<ArtifactTrustResult>
}

export async function loadArtifactTrustReport() {
  return api<{ format: string; content: string }>('/api/security/artifact-trust/report')
}

export async function ignoreCICDAuditFinding(fingerprint: string, reason = 'false-positive') {
  return api<{ state: CodeAuditState; cicd_audit: CICDAuditResult | null }>('/api/security/cicd/ignore', {
    method: 'POST',
    body: JSON.stringify({ fingerprint, reason }),
  })
}

export async function createCICDAuditBaseline(note = '') {
  return api<{ state: CodeAuditState; cicd_audit: CICDAuditResult | null }>('/api/security/cicd/baseline', {
    method: 'POST',
    body: JSON.stringify({ note }),
  })
}

export async function uploadCICDAuditToGitHubCodeScanning(payload: GitHubCodeScanningUploadPayload) {
  return api<GitHubCodeScanningUploadResult>('/api/security/cicd/github/code-scanning', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export type LogAuditSource = 'web' | 'app' | 'auth' | 'auto'

export type LogAuditScanOptions = {
  files: File[]
  source?: LogAuditSource
  workspaceId?: string
}

export async function runLogAuditScan({ files, source = 'auto', workspaceId }: LogAuditScanOptions) {
  const formData = new FormData()
  files.forEach((file) => formData.append('files', file))
  if (source !== 'auto') formData.set('source', source)
  if (workspaceId) formData.set('workspaceId', workspaceId)

  const response = await fetch(`${apiBase}/api/security/logs/scan`, {
    method: 'POST',
    body: formData,
  })

  if (!response.ok) {
    let message = response.statusText
    const errorText = await response.text()
    try {
      const payload = JSON.parse(errorText)
      message = payload.error || payload.detail || message
    } catch {
      message = errorText
    }
    throw new Error(message || '日志扫描失败')
  }

  return response.json() as Promise<LogAuditResult>
}

export async function runMultimodalEvidenceScan(files: File[], workspaceId?: string) {
  const formData = new FormData()
  files.forEach((file) => formData.append('files', file))
  if (workspaceId) formData.set('workspaceId', workspaceId)

  const response = await fetch(`${apiBase}/api/security/multimodal/scan`, {
    method: 'POST',
    body: formData,
  })

  if (!response.ok) {
    let message = response.statusText
    const errorText = await response.text()
    try {
      const payload = JSON.parse(errorText)
      message = payload.error || payload.detail || message
    } catch {
      message = errorText
    }
    throw new Error(message || '多模态证据上传失败')
  }

  return response.json() as Promise<MultimodalAuditResult>
}

export type MultimodalTextAnalyzeOptions = {
  workspaceId?: string
  recognizedText: string
  sourceType?: MultimodalSourceType
  evidenceType?: string
  sourceName?: string
  confidence?: number
}

export async function analyzeMultimodalRecognizedText(options: MultimodalTextAnalyzeOptions) {
  return api<MultimodalAuditResult>('/api/security/multimodal/analyze-text', {
    method: 'POST',
    body: JSON.stringify({
      recognized_text: options.recognizedText,
      ...(options.workspaceId ? { workspaceId: options.workspaceId } : {}),
      source_type: options.sourceType ?? 'image',
      evidence_type: options.evidenceType ?? ((options.sourceType ?? 'image') === 'audio' ? 'audio_asr' : 'visual_ocr'),
      source_name: options.sourceName ?? 'manual-recognized-text.txt',
      confidence: options.confidence ?? 0.9,
    }),
  })
}

export async function loadMultimodalEvidenceLatest(limit = 100) {
  return api<MultimodalAuditResult>(`/api/security/multimodal/latest?limit=${limit}`)
}

export async function ingestRealtimeLogs(payload: Record<string, unknown> | Array<Record<string, unknown>>) {
  return api<RealtimeLogPayload>('/api/security/logs/ingest', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export async function loadRealtimeLogEvents(limit = 200) {
  return api<RealtimeLogPayload>(`/api/security/logs/events?limit=${limit}`)
}

export async function loadRealtimeLogTrend(granularity: 'minute' | 'hour' = 'minute', buckets = 60) {
  return api<{ granularity: 'minute' | 'hour'; trend: RealtimeLogTrendPoint[]; state: RealtimeLogPayload['state'] }>(
    `/api/security/logs/trend?granularity=${granularity}&buckets=${buckets}`
  )
}

export async function createRealtimeLogBaseline(note = '') {
  return api<RealtimeLogPayload>('/api/security/logs/baseline', {
    method: 'POST',
    body: JSON.stringify({ note }),
  })
}

export async function ignoreRealtimeLogFinding(fingerprint: string, reason = '') {
  return api<RealtimeLogPayload>('/api/security/logs/ignore', {
    method: 'POST',
    body: JSON.stringify({ fingerprint, reason }),
  })
}

export async function uploadCodeAuditToGitHubCodeScanning(payload: GitHubCodeScanningUploadPayload) {
  return api<GitHubCodeScanningUploadResult>('/api/security/code-audit/github/code-scanning', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export async function loadGitHubCodeScanningUploadStatus(payload: GitHubCodeScanningStatusPayload) {
  return api<GitHubCodeScanningStatusResult>('/api/security/code-audit/github/code-scanning/status', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}
