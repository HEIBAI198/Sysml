import {
  useEffect,
  useMemo,
  useState,
  type FormEvent,
  type ReactNode,
} from 'react'
import {
  AlertCircle,
  Archive,
  Boxes,
  Braces,
  CheckCircle2,
  Code2,
  Download,
  FileText,
  GitBranch,
  GitCommitHorizontal,
  GitCompare,
  GitMerge,
  LayoutDashboard,
  Loader2,
  LogIn,
  LogOut,
  Network,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Search,
  ShieldCheck,
  Trash2,
  Workflow,
} from 'lucide-react'
import { toast } from 'sonner'
import {
  api,
  defaultElement,
  loadIdentity,
  login,
  saveIdentity,
  type AuditEvent,
  type Branch,
  type Commit,
  type DiagramPayload,
  type DiffPayload,
  type DocumentRecord,
  type Identity,
  type Metamodel,
  type Project,
  type Relation,
  type SysmlElement,
  type TraceabilityRow,
  type ValidationPayload,
} from '@/lib/sysml-api'
import { cn } from '@/lib/utils'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import { ConfigDrawer } from '@/components/config-drawer'
import { Header } from '@/components/layout/header'
import { Main } from '@/components/layout/main'
import { ThemeSwitch } from '@/components/theme-switch'

const defaultTemplate = `# {{model:summary}}

## Requirements
{{table:requirements}}

## Blocks
{{table:blocks}}

## Interfaces
{{table:interfaces}}

## Constraints
{{table:constraints}}

## Tests
{{table:tests}}

## Traceability
{{trace:matrix}}

## Validation
{{validation:issues}}
`

const typeNames: Record<string, string> = {
  Requirement: '需求',
  Block: '模块',
  Activity: '活动',
  Interface: '接口',
  Port: '端口',
  Constraint: '约束',
  State: '状态',
  TestCase: '测试',
  View: '视图',
}

const diagramNames: Record<string, string> = {
  requirements: '需求追踪图',
  structure: '结构与接口图',
  behavior: '行为状态图',
  all: '全模型图',
}

const relationNames: Record<string, string> = {
  satisfy: '满足',
  verify: '验证',
  refine: '细化',
  compose: '组成',
  expose: '暴露端口',
  connect: '连接',
  allocate: '分配',
  flow: '流转',
  transition: '迁移',
  constrain: '约束',
}

const severityNames = {
  error: '错误',
  warning: '警告',
  info: '提示',
}

export function SysmlWorkbench() {
  const [identity, setIdentity] = useState<Identity | null>(() => loadIdentity())
  const [loginForm, setLoginForm] = useState({
    username: identity?.username || 'engineer',
    password: 'engineer123',
  })
  const [role, setRole] = useState(identity?.role || 'author')
  const [projects, setProjects] = useState<Project[]>([])
  const [projectId, setProjectId] = useState('')
  const [branches, setBranches] = useState<Branch[]>([])
  const [branch, setBranch] = useState('main')
  const [metamodel, setMetamodel] = useState<Metamodel | null>(null)
  const [elements, setElements] = useState<SysmlElement[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [form, setForm] = useState<SysmlElement>(() =>
    defaultElement('Requirement', null)
  )
  const [attributesText, setAttributesText] = useState('{}')
  const [relationsText, setRelationsText] = useState('[]')
  const [validation, setValidation] = useState<ValidationPayload | null>(null)
  const [diagramType, setDiagramType] = useState('requirements')
  const [diagram, setDiagram] = useState<DiagramPayload | null>(null)
  const [traceability, setTraceability] = useState<TraceabilityRow[]>([])
  const [commits, setCommits] = useState<Commit[]>([])
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([])
  const [diff, setDiff] = useState<DiffPayload | null>(null)
  const [diffFrom, setDiffFrom] = useState('working')
  const [diffTo, setDiffTo] = useState('working')
  const [rollbackCommit, setRollbackCommit] = useState('')
  const [newBranch, setNewBranch] = useState('')
  const [mergeSource, setMergeSource] = useState('')
  const [forceMerge, setForceMerge] = useState(false)
  const [template, setTemplate] = useState(defaultTemplate)
  const [documents, setDocuments] = useState<DocumentRecord[]>([])
  const [currentDocument, setCurrentDocument] = useState<DocumentRecord | null>(
    null
  )
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState('')

  const project = projects.find((item) => item.id === projectId)
  const types = Object.keys(metamodel?.types || {})
  const relationTypes = Object.keys(metamodel?.relation_labels || {})
  const selectedElement = elements.find((item) => item.id === selectedId)
  const elementCounts = useMemo(() => countBy(elements, (item) => item.type), [
    elements,
  ])

  useEffect(() => {
    bootstrap()
  }, [])

  useEffect(() => {
    if (!projectId) return
    loadProjectBranches(projectId)
  }, [projectId])

  useEffect(() => {
    if (!projectId || !branch) return
    loadElements()
  }, [projectId, branch, typeFilter, query])

  useEffect(() => {
    if (!selectedElement) return
    setForm(selectedElement)
    setAttributesText(JSON.stringify(selectedElement.attributes || {}, null, 2))
    setRelationsText(JSON.stringify(selectedElement.relations || [], null, 2))
  }, [selectedElement?.id])

  useEffect(() => {
    if (!projectId || !branch) return
    loadDiagram()
  }, [diagramType, projectId, branch])

  async function bootstrap() {
    setLoading(true)
    try {
      const [metamodelPayload, projectsPayload] = await Promise.all([
        api<Metamodel>('/api/metamodel', { identity, role }),
        api<{ projects: Project[] }>('/api/projects', { identity, role }),
      ])
      setMetamodel(metamodelPayload)
      setProjects(projectsPayload.projects)
      setProjectId(projectsPayload.projects[0]?.id || '')
    } catch (error) {
      notifyError(error)
    } finally {
      setLoading(false)
    }
  }

  async function loadProjectBranches(nextProjectId = projectId) {
    if (!nextProjectId) return
    try {
      const payload = await api<{ branches: Branch[] }>(
        `/api/projects/${encodeURIComponent(nextProjectId)}/branches`,
        { identity, role }
      )
      setBranches(payload.branches)
      const nextBranch = payload.branches.some((item) => item.name === branch)
        ? branch
        : payload.branches[0]?.name || 'main'
      setBranch(nextBranch)
      setMergeSource(
        payload.branches.find((item) => item.name !== nextBranch)?.name || ''
      )
    } catch (error) {
      notifyError(error)
    }
  }

  async function loadElements() {
    if (!projectId || !branch) return
    try {
      const params = new URLSearchParams()
      if (typeFilter !== 'all') params.set('type', typeFilter)
      if (query.trim()) params.set('q', query.trim())
      const payload = await api<{ elements: SysmlElement[] }>(
        `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/elements?${params}`,
        { identity, role }
      )
      setElements(payload.elements)
      const nextId = payload.elements.some((item) => item.id === selectedId)
        ? selectedId
        : payload.elements[0]?.id || ''
      setSelectedId(nextId)
      if (!nextId) startNewElement()
      await Promise.all([loadValidation(), loadDiagram()])
    } catch (error) {
      notifyError(error)
    }
  }

  async function loadValidation() {
    if (!projectId || !branch) return
    try {
      const payload = await api<ValidationPayload>(
        `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/validate`,
        { identity, role }
      )
      setValidation(payload)
    } catch (error) {
      notifyError(error)
    }
  }

  async function loadDiagram() {
    if (!projectId || !branch) return
    try {
      const payload = await api<{ diagram: DiagramPayload }>(
        `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/diagram?type=${diagramType}`,
        { identity, role }
      )
      setDiagram(payload.diagram)
    } catch (error) {
      notifyError(error)
    }
  }

  async function loadTraceability() {
    if (!projectId || !branch) return
    setBusy('trace')
    try {
      const payload = await api<{ traceability: TraceabilityRow[] }>(
        `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/traceability`,
        { identity, role }
      )
      setTraceability(payload.traceability)
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  async function loadVersionData() {
    if (!projectId) return
    setBusy('version')
    try {
      const [commitPayload, auditPayload] = await Promise.all([
        api<{ commits: Commit[] }>(
          `/api/projects/${encodeURIComponent(projectId)}/commits`,
          { identity, role }
        ),
        api<{ events: AuditEvent[] }>(
          `/api/projects/${encodeURIComponent(projectId)}/audit?limit=80`,
          { identity, role }
        ),
      ])
      setCommits(commitPayload.commits)
      setAuditEvents(auditPayload.events)
      setRollbackCommit(commitPayload.commits[0]?.id || '')
      setDiffFrom(commitPayload.commits[1]?.id || commitPayload.commits[0]?.id || 'working')
      setDiffTo('working')
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  async function loadDocuments() {
    if (!projectId || !branch) return
    setBusy('documents')
    try {
      const payload = await api<{ documents: DocumentRecord[] }>(
        `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/documents`,
        { identity, role }
      )
      setDocuments(payload.documents)
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  async function handleLogin() {
    setBusy('login')
    try {
      const payload = await login(loginForm.username.trim(), loginForm.password)
      setIdentity(payload.identity)
      setRole(payload.identity.role)
      saveIdentity(payload.identity)
      toast.success(`已登录：${payload.identity.display || payload.identity.username}`)
      await bootstrap()
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  function handleLogout() {
    setIdentity(null)
    saveIdentity(null)
    setRole('author')
    toast.success('已退出登录')
  }

  function startNewElement(type = form.type || 'Requirement') {
    const next = defaultElement(type, metamodel)
    setSelectedId('')
    setForm(next)
    setAttributesText(JSON.stringify(next.attributes || {}, null, 2))
    setRelationsText(JSON.stringify(next.relations || [], null, 2))
  }

  function updateForm<K extends keyof SysmlElement>(
    key: K,
    value: SysmlElement[K]
  ) {
    setForm((current) => ({ ...current, [key]: value }))
  }

  function handleTypeChange(type: string) {
    const defaults = defaultElement(type, metamodel)
    setForm((current) => ({
      ...current,
      type,
      stereotype: current.id
        ? current.stereotype
        : defaults.stereotype || current.stereotype,
      attributes: current.id ? current.attributes : defaults.attributes,
    }))
    if (!form.id) {
      setAttributesText(JSON.stringify(defaults.attributes || {}, null, 2))
    }
  }

  async function saveElement(event: FormEvent) {
    event.preventDefault()
    if (!projectId || !branch) return
    setBusy('save-element')
    try {
      const payload = {
        ...form,
        id: form.id.trim(),
        name: form.name.trim(),
        owner: form.owner?.trim() || '',
        stereotype: form.stereotype?.trim() || '',
        description: form.description?.trim() || '',
        attributes: parseJson<Record<string, unknown>>(attributesText, '属性 JSON', {}),
        relations: parseJson<Relation[]>(relationsText, '关系 JSON', []),
      }
      const isUpdate = Boolean(payload.id)
      const path = isUpdate
        ? `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/elements/${encodeURIComponent(payload.id)}`
        : `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/elements`
      const result = await api<{ element: SysmlElement }>(path, {
        method: isUpdate ? 'PUT' : 'POST',
        body: JSON.stringify(payload),
        identity,
        role,
      })
      setSelectedId(result.element.id)
      await loadElements()
      toast.success('模型元素已保存')
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  async function deleteElement() {
    if (!projectId || !branch || !selectedElement) return
    if (!window.confirm(`确认删除 ${selectedElement.id} ${selectedElement.name}？`)) {
      return
    }
    setBusy('delete-element')
    try {
      await api(
        `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/elements/${encodeURIComponent(selectedElement.id)}`,
        { method: 'DELETE', identity, role }
      )
      setSelectedId('')
      await loadElements()
      toast.success('模型元素已删除')
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  async function addRelation() {
    if (!form.id || !elements.length || !relationTypes.length) return
    const target = elements.find((item) => item.id !== form.id)?.id || elements[0]?.id
    const next = [...(parseJsonSafe<Relation[]>(relationsText, []) || [])]
    next.push({ type: relationTypes[0], target })
    setRelationsText(JSON.stringify(next, null, 2))
  }

  async function commitBranch() {
    if (!projectId || !branch) return
    const message = window.prompt('提交说明', 'Update SysML model')
    if (message === null) return
    setBusy('commit')
    try {
      const result = await api<{ commit: Commit }>(
        `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/commit`,
        {
          method: 'POST',
          body: JSON.stringify({ message }),
          identity,
          role,
        }
      )
      await loadProjectBranches()
      toast.success(`已提交 ${result.commit.id}`)
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  async function exportModel(format: 'json' | 'xmi') {
    if (!projectId || !branch) return
    setBusy(`export-${format}`)
    try {
      const payload = await api<unknown>(
        `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/export?format=${format}`,
        { identity, role }
      )
      if (format === 'xmi') {
        downloadText(`${projectId}-${branch}.xmi`, String(payload), 'application/xml')
      } else {
        downloadText(
          `${projectId}-${branch}.json`,
          JSON.stringify(payload, null, 2),
          'application/json'
        )
      }
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  async function runDiff() {
    if (!projectId || !branch) return
    setBusy('diff')
    try {
      const params = new URLSearchParams({ from: diffFrom, to: diffTo })
      const payload = await api<DiffPayload>(
        `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/diff?${params}`,
        { identity, role }
      )
      setDiff(payload)
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  async function createBranch() {
    if (!projectId || !newBranch.trim()) return
    setBusy('branch')
    try {
      await api(`/api/projects/${encodeURIComponent(projectId)}/branches`, {
        method: 'POST',
        body: JSON.stringify({ name: newBranch.trim(), source: branch }),
        identity,
        role,
      })
      setBranch(newBranch.trim())
      setNewBranch('')
      await loadProjectBranches()
      await loadElements()
      toast.success('分支已创建')
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  async function rollback() {
    if (!projectId || !branch || !rollbackCommit) return
    if (!window.confirm(`确认回滚到 ${rollbackCommit}？`)) return
    setBusy('rollback')
    try {
      await api(
        `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/rollback`,
        {
          method: 'POST',
          body: JSON.stringify({ commit: rollbackCommit }),
          identity,
          role,
        }
      )
      await loadProjectBranches()
      await loadElements()
      await loadVersionData()
      toast.success('回滚已完成')
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  async function mergeBranch() {
    if (!projectId || !branch || !mergeSource || mergeSource === branch) return
    setBusy('merge')
    try {
      const result = await api<{
        merged: boolean
        conflicts?: { id: string }[]
        additions?: string[]
      }>(
        `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/merge`,
        {
          method: 'POST',
          body: JSON.stringify({ source: mergeSource, force: forceMerge }),
          identity,
          role,
        }
      )
      if (!result.merged) {
        toast.error(`存在 ${result.conflicts?.length || 0} 个冲突`)
        return
      }
      await loadProjectBranches()
      await loadElements()
      await loadVersionData()
      toast.success('分支合并完成')
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  async function generateDocument() {
    if (!projectId || !branch) return
    setBusy('generate-document')
    try {
      const result = await api<{ document: DocumentRecord }>(
        `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/documents`,
        {
          method: 'POST',
          body: JSON.stringify({ template, format: 'html' }),
          identity,
          role,
        }
      )
      setCurrentDocument(result.document)
      await loadDocuments()
      toast.success('文档已生成')
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  async function openDocument(documentId: string) {
    if (!projectId || !branch) return
    setBusy(`document-${documentId}`)
    try {
      const payload = await api<{ document: DocumentRecord }>(
        `/api/projects/${encodeURIComponent(projectId)}/branches/${encodeURIComponent(branch)}/documents/${encodeURIComponent(documentId)}`,
        { identity, role }
      )
      setCurrentDocument(payload.document)
    } catch (error) {
      notifyError(error)
    } finally {
      setBusy('')
    }
  }

  function downloadCurrent(format: 'html' | 'markdown' | 'pdf') {
    if (!currentDocument) {
      toast.error('请先生成或打开一个文档')
      return
    }
    if (format === 'markdown') {
      downloadText(
        `${currentDocument.id}.md`,
        currentDocument.markdown || '',
        'text/markdown'
      )
      return
    }
    if (format === 'pdf') {
      if (!currentDocument.pdf_base64) {
        toast.error('当前文档没有 PDF 内容')
        return
      }
      downloadBase64(
        `${currentDocument.id}.pdf`,
        currentDocument.pdf_base64,
        'application/pdf'
      )
      return
    }
    downloadText(
      `${currentDocument.id}.html`,
      currentDocument.html || '',
      'text/html'
    )
  }

  const stats = [
    {
      label: '模型元素',
      value: elements.length,
      detail: `${Object.keys(elementCounts).length} 类 SysML 元素`,
      icon: Boxes,
    },
    {
      label: '需求',
      value: elementCounts.Requirement || 0,
      detail: 'Requirement',
      icon: ShieldCheck,
    },
    {
      label: '模块',
      value: elementCounts.Block || 0,
      detail: 'Block',
      icon: Archive,
    },
    {
      label: '验证问题',
      value:
        (validation?.summary.errors || 0) + (validation?.summary.warnings || 0),
      detail: `${validation?.summary.errors || 0} 错误 / ${validation?.summary.warnings || 0} 警告`,
      icon: AlertCircle,
    },
  ]

  return (
    <>
      <Header fixed>
        <div className='me-auto min-w-0'>
          <div className='flex items-center gap-2'>
            <span className='truncate text-sm font-semibold'>
              SysML DocGen
            </span>
            <Badge variant='outline' className='hidden sm:inline-flex'>
              FastAPI + Shadcn Admin
            </Badge>
          </div>
          <p className='mt-0.5 hidden text-xs text-muted-foreground sm:block'>
            MMS / VE / MDK / DocGen integrated workbench
          </p>
        </div>
        <ThemeSwitch />
        <ConfigDrawer />
      </Header>

      <Main fluid className='space-y-5'>
        {loading ? (
          <div className='flex min-h-[520px] items-center justify-center'>
            <div className='flex items-center gap-3 text-sm text-muted-foreground'>
              <Loader2 className='size-4 animate-spin' />
              正在加载 SysML 工作台
            </div>
          </div>
        ) : (
          <>
            <section className='grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]'>
              <div className='space-y-4'>
                <div className='flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between'>
                  <div className='min-w-0'>
                    <h1 className='truncate text-2xl font-bold tracking-tight'>
                      {project?.name || 'SysML 项目'}
                    </h1>
                    <p className='mt-1 text-sm text-muted-foreground'>
                      {project?.organization || '当前项目'} / {branch} /{' '}
                      {branches.find((item) => item.name === branch)?.head ||
                        'working'}
                    </p>
                  </div>
                  <div className='flex flex-wrap gap-2'>
                    <Button
                      variant='outline'
                      onClick={() => exportModel('json')}
                      disabled={busy === 'export-json'}
                    >
                      <Download className='size-4' />
                      JSON
                    </Button>
                    <Button
                      variant='outline'
                      onClick={() => exportModel('xmi')}
                      disabled={busy === 'export-xmi'}
                    >
                      <Code2 className='size-4' />
                      XMI
                    </Button>
                    <Button onClick={commitBranch} disabled={busy === 'commit'}>
                      <GitCommitHorizontal className='size-4' />
                      提交
                    </Button>
                  </div>
                </div>

                <div className='grid gap-3 sm:grid-cols-2 xl:grid-cols-4'>
                  {stats.map((item) => (
                    <Card key={item.label}>
                      <CardHeader className='flex flex-row items-center justify-between space-y-0 pb-2'>
                        <CardTitle className='text-sm font-medium'>
                          {item.label}
                        </CardTitle>
                        <item.icon className='size-4 text-muted-foreground' />
                      </CardHeader>
                      <CardContent>
                        <div className='text-2xl font-bold'>{item.value}</div>
                        <p className='mt-1 text-xs text-muted-foreground'>
                          {item.detail}
                        </p>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle className='text-base'>会话与项目</CardTitle>
                  <CardDescription>
                    登录身份会影响写入、提交和版本操作权限
                  </CardDescription>
                </CardHeader>
                <CardContent className='space-y-4'>
                  <div className='grid gap-2 sm:grid-cols-2 xl:grid-cols-1'>
                    <Field label='用户名'>
                      <Input
                        value={loginForm.username}
                        onChange={(event) =>
                          setLoginForm((current) => ({
                            ...current,
                            username: event.target.value,
                          }))
                        }
                      />
                    </Field>
                    <Field label='密码'>
                      <Input
                        type='password'
                        value={loginForm.password}
                        onChange={(event) =>
                          setLoginForm((current) => ({
                            ...current,
                            password: event.target.value,
                          }))
                        }
                      />
                    </Field>
                  </div>
                  <div className='flex flex-wrap gap-2'>
                    <Button onClick={handleLogin} disabled={busy === 'login'}>
                      {busy === 'login' ? (
                        <Loader2 className='size-4 animate-spin' />
                      ) : (
                        <LogIn className='size-4' />
                      )}
                      登录
                    </Button>
                    <Button variant='outline' onClick={handleLogout}>
                      <LogOut className='size-4' />
                      退出
                    </Button>
                    <Badge variant='secondary'>
                      {identity?.display || identity?.username || '未登录'} /{' '}
                      {identity?.role || role}
                    </Badge>
                  </div>
                  <Separator />
                  <div className='grid gap-3'>
                    <Field label='项目'>
                      <Select value={projectId} onValueChange={setProjectId}>
                        <SelectTrigger className='w-full'>
                          <SelectValue placeholder='选择项目' />
                        </SelectTrigger>
                        <SelectContent>
                          {projects.map((item) => (
                            <SelectItem key={item.id} value={item.id}>
                              {item.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </Field>
                    <Field label='分支'>
                      <Select value={branch} onValueChange={setBranch}>
                        <SelectTrigger className='w-full'>
                          <SelectValue placeholder='选择分支' />
                        </SelectTrigger>
                        <SelectContent>
                          {branches.map((item) => (
                            <SelectItem key={item.name} value={item.name}>
                              {item.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </Field>
                    <Field label='请求角色'>
                      <Select
                        value={role}
                        onValueChange={(value) =>
                          setRole(value as 'admin' | 'author' | 'reader')
                        }
                      >
                        <SelectTrigger className='w-full'>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value='author'>author</SelectItem>
                          <SelectItem value='reader'>reader</SelectItem>
                          <SelectItem value='admin'>admin</SelectItem>
                        </SelectContent>
                      </Select>
                    </Field>
                  </div>
                </CardContent>
              </Card>
            </section>

            <Tabs defaultValue='model' className='space-y-4'>
              <div className='overflow-x-auto pb-1'>
                <TabsList>
                  <TabsTrigger value='model'>
                    <LayoutDashboard className='size-4' />
                    模型
                  </TabsTrigger>
                  <TabsTrigger value='diagram'>
                    <Network className='size-4' />
                    图谱
                  </TabsTrigger>
                  <TabsTrigger value='trace' onClick={loadTraceability}>
                    <Workflow className='size-4' />
                    追踪
                  </TabsTrigger>
                  <TabsTrigger value='version' onClick={loadVersionData}>
                    <GitBranch className='size-4' />
                    版本
                  </TabsTrigger>
                  <TabsTrigger value='docgen' onClick={loadDocuments}>
                    <FileText className='size-4' />
                    文档
                  </TabsTrigger>
                </TabsList>
              </div>

              <TabsContent value='model'>
                <ModelTab
                  elements={elements}
                  selectedId={selectedId}
                  setSelectedId={setSelectedId}
                  typeFilter={typeFilter}
                  setTypeFilter={setTypeFilter}
                  query={query}
                  setQuery={setQuery}
                  types={types}
                  form={form}
                  updateForm={updateForm}
                  handleTypeChange={handleTypeChange}
                  attributesText={attributesText}
                  setAttributesText={setAttributesText}
                  relationsText={relationsText}
                  setRelationsText={setRelationsText}
                  validation={validation}
                  onNew={() => startNewElement(types[0] || 'Requirement')}
                  onDelete={deleteElement}
                  onSave={saveElement}
                  onAddRelation={addRelation}
                  busy={busy}
                />
              </TabsContent>

              <TabsContent value='diagram'>
                <DiagramTab
                  diagram={diagram}
                  diagramType={diagramType}
                  setDiagramType={setDiagramType}
                  metamodel={metamodel}
                  elements={elements}
                  selectedId={selectedId}
                  setSelectedId={setSelectedId}
                  onRefresh={loadDiagram}
                />
              </TabsContent>

              <TabsContent value='trace'>
                <TraceTab
                  traceability={traceability}
                  busy={busy}
                  onRefresh={loadTraceability}
                />
              </TabsContent>

              <TabsContent value='version'>
                <VersionTab
                  branches={branches}
                  commits={commits}
                  auditEvents={auditEvents}
                  diff={diff}
                  diffFrom={diffFrom}
                  setDiffFrom={setDiffFrom}
                  diffTo={diffTo}
                  setDiffTo={setDiffTo}
                  rollbackCommit={rollbackCommit}
                  setRollbackCommit={setRollbackCommit}
                  newBranch={newBranch}
                  setNewBranch={setNewBranch}
                  mergeSource={mergeSource}
                  setMergeSource={setMergeSource}
                  forceMerge={forceMerge}
                  setForceMerge={setForceMerge}
                  onRefresh={loadVersionData}
                  onDiff={runDiff}
                  onRollback={rollback}
                  onCreateBranch={createBranch}
                  onMerge={mergeBranch}
                  busy={busy}
                />
              </TabsContent>

              <TabsContent value='docgen'>
                <DocgenTab
                  template={template}
                  setTemplate={setTemplate}
                  documents={documents}
                  currentDocument={currentDocument}
                  onReset={() => setTemplate(defaultTemplate)}
                  onGenerate={generateDocument}
                  onOpen={openDocument}
                  onDownload={downloadCurrent}
                  busy={busy}
                />
              </TabsContent>
            </Tabs>
          </>
        )}
      </Main>
    </>
  )
}

type ModelTabProps = {
  elements: SysmlElement[]
  selectedId: string
  setSelectedId: (id: string) => void
  typeFilter: string
  setTypeFilter: (type: string) => void
  query: string
  setQuery: (query: string) => void
  types: string[]
  form: SysmlElement
  updateForm: <K extends keyof SysmlElement>(
    key: K,
    value: SysmlElement[K]
  ) => void
  handleTypeChange: (type: string) => void
  attributesText: string
  setAttributesText: (value: string) => void
  relationsText: string
  setRelationsText: (value: string) => void
  validation: ValidationPayload | null
  onNew: () => void
  onDelete: () => void
  onSave: (event: FormEvent) => void
  onAddRelation: () => void
  busy: string
}

function ModelTab(props: ModelTabProps) {
  return (
    <div className='grid gap-4 xl:grid-cols-[minmax(320px,0.42fr)_minmax(520px,0.58fr)]'>
      <Card>
        <CardHeader className='space-y-3'>
          <div className='flex items-center justify-between gap-3'>
            <div>
              <CardTitle>模型元素</CardTitle>
              <CardDescription>按类型筛选、搜索并选择元素</CardDescription>
            </div>
            <Button size='sm' onClick={props.onNew}>
              <Plus className='size-4' />
              新建
            </Button>
          </div>
          <div className='grid gap-2 sm:grid-cols-[150px_1fr]'>
            <Select value={props.typeFilter} onValueChange={props.setTypeFilter}>
              <SelectTrigger className='w-full'>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value='all'>全部类型</SelectItem>
                {props.types.map((type) => (
                  <SelectItem key={type} value={type}>
                    {labelType(type)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <div className='relative'>
              <Search className='absolute left-3 top-2.5 size-4 text-muted-foreground' />
              <Input
                className='pl-9'
                placeholder='搜索 ID、名称或描述'
                value={props.query}
                onChange={(event) => props.setQuery(event.target.value)}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent className='p-0'>
          <ScrollArea className='h-[560px]'>
            {props.elements.length ? (
              <div className='divide-y'>
                {props.elements.map((element) => (
                  <button
                    key={element.id}
                    className={cn(
                      'grid w-full gap-1 px-4 py-3 text-left transition-colors hover:bg-muted/60',
                      props.selectedId === element.id && 'bg-muted'
                    )}
                    type='button'
                    onClick={() => props.setSelectedId(element.id)}
                  >
                    <div className='flex items-center justify-between gap-3'>
                      <span className='font-mono text-sm font-semibold'>
                        {element.id}
                      </span>
                      <Badge variant='secondary'>{labelType(element.type)}</Badge>
                    </div>
                    <div className='truncate text-sm font-medium'>
                      {element.name || '未命名元素'}
                    </div>
                    <p className='line-clamp-2 text-xs text-muted-foreground'>
                      {element.description || '暂无描述'}
                    </p>
                  </button>
                ))}
              </div>
            ) : (
              <EmptyState title='没有元素' description='当前筛选条件下没有模型元素' />
            )}
          </ScrollArea>
        </CardContent>
      </Card>

      <div className='space-y-4'>
        <Card>
          <CardHeader>
            <div className='flex items-start justify-between gap-3'>
              <div>
                <CardTitle>元素编辑器</CardTitle>
                <CardDescription>属性与关系字段使用 JSON 格式</CardDescription>
              </div>
              <Button
                variant='destructive'
                size='sm'
                onClick={props.onDelete}
                disabled={!props.form.id || props.busy === 'delete-element'}
              >
                <Trash2 className='size-4' />
                删除
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <form className='grid gap-4' onSubmit={props.onSave}>
              <div className='grid gap-4 md:grid-cols-2'>
                <Field label='ID'>
                  <Input
                    value={props.form.id}
                    onChange={(event) =>
                      props.updateForm('id', event.target.value)
                    }
                    placeholder='留空可由后端生成'
                  />
                </Field>
                <Field label='类型'>
                  <Select
                    value={props.form.type}
                    onValueChange={props.handleTypeChange}
                  >
                    <SelectTrigger className='w-full'>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {props.types.map((type) => (
                        <SelectItem key={type} value={type}>
                          {labelType(type)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
                <Field label='名称'>
                  <Input
                    required
                    value={props.form.name}
                    onChange={(event) =>
                      props.updateForm('name', event.target.value)
                    }
                  />
                </Field>
                <Field label='负责人'>
                  <Input
                    value={props.form.owner || ''}
                    onChange={(event) =>
                      props.updateForm('owner', event.target.value)
                    }
                  />
                </Field>
                <Field label='构造型'>
                  <Input
                    value={props.form.stereotype || ''}
                    onChange={(event) =>
                      props.updateForm('stereotype', event.target.value)
                    }
                  />
                </Field>
              </div>
              <Field label='描述'>
                <Textarea
                  rows={3}
                  value={props.form.description || ''}
                  onChange={(event) =>
                    props.updateForm('description', event.target.value)
                  }
                />
              </Field>
              <div className='grid gap-4 lg:grid-cols-2'>
                <Field label='属性 JSON'>
                  <Textarea
                    className='min-h-[220px] font-mono text-xs'
                    value={props.attributesText}
                    onChange={(event) => props.setAttributesText(event.target.value)}
                  />
                </Field>
                <Field label='关系 JSON'>
                  <Textarea
                    className='min-h-[220px] font-mono text-xs'
                    value={props.relationsText}
                    onChange={(event) => props.setRelationsText(event.target.value)}
                  />
                </Field>
              </div>
              <div className='flex flex-wrap justify-end gap-2'>
                <Button type='button' variant='outline' onClick={props.onAddRelation}>
                  <Plus className='size-4' />
                  添加关系
                </Button>
                <Button
                  type='submit'
                  disabled={props.busy === 'save-element'}
                >
                  {props.busy === 'save-element' ? (
                    <Loader2 className='size-4 animate-spin' />
                  ) : (
                    <Save className='size-4' />
                  )}
                  保存元素
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>

        <ValidationPanel validation={props.validation} />
      </div>
    </div>
  )
}

function ValidationPanel({ validation }: { validation: ValidationPayload | null }) {
  if (!validation) return null
  return (
    <Card>
      <CardHeader>
        <div className='flex items-center justify-between gap-3'>
          <div>
            <CardTitle>语义校验</CardTitle>
            <CardDescription>
              {validation.summary.elements} 个元素，{validation.summary.errors} 个错误，
              {validation.summary.warnings} 个警告
            </CardDescription>
          </div>
          <Badge
            variant={validation.summary.errors ? 'destructive' : 'secondary'}
          >
            {validation.summary.errors ? '需处理' : '可发布'}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        {validation.issues.length ? (
          <div className='space-y-2'>
            {validation.issues.slice(0, 8).map((issue, index) => (
              <Alert
                key={`${issue.element_id}-${index}`}
                variant={issue.severity === 'error' ? 'destructive' : 'default'}
              >
                <AlertCircle className='size-4' />
                <AlertTitle>
                  {severityNames[issue.severity]} / {issue.element_id}
                </AlertTitle>
                <AlertDescription>{issue.message}</AlertDescription>
              </Alert>
            ))}
          </div>
        ) : (
          <div className='flex items-center gap-2 text-sm text-muted-foreground'>
            <CheckCircle2 className='size-4 text-emerald-600' />
            未发现校验问题
          </div>
        )}
      </CardContent>
    </Card>
  )
}

type DiagramTabProps = {
  diagram: DiagramPayload | null
  diagramType: string
  setDiagramType: (type: string) => void
  metamodel: Metamodel | null
  elements: SysmlElement[]
  selectedId: string
  setSelectedId: (id: string) => void
  onRefresh: () => void
}

function DiagramTab(props: DiagramTabProps) {
  return (
    <div className='grid gap-4 xl:grid-cols-[340px_1fr]'>
      <Card>
        <CardHeader>
          <CardTitle>图谱设置</CardTitle>
          <CardDescription>按不同 SysML 视角查看关系网络</CardDescription>
        </CardHeader>
        <CardContent className='space-y-4'>
          <Field label='图谱类型'>
            <Select value={props.diagramType} onValueChange={props.setDiagramType}>
              <SelectTrigger className='w-full'>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.keys(props.metamodel?.diagram_types || {}).map((type) => (
                  <SelectItem key={type} value={type}>
                    {diagramNames[type] || type}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Button variant='outline' onClick={props.onRefresh}>
            <RefreshCw className='size-4' />
            刷新图谱
          </Button>
          <Separator />
          <div className='grid gap-2'>
            <p className='text-sm font-medium'>当前元素</p>
            <ScrollArea className='h-[360px] rounded-md border'>
              <div className='divide-y'>
                {props.elements.map((element) => (
                  <button
                    key={element.id}
                    type='button'
                    onClick={() => props.setSelectedId(element.id)}
                    className={cn(
                      'flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-sm hover:bg-muted',
                      props.selectedId === element.id && 'bg-muted'
                    )}
                  >
                    <span className='truncate font-mono'>{element.id}</span>
                    <Badge variant='outline'>{labelType(element.type)}</Badge>
                  </button>
                ))}
              </div>
            </ScrollArea>
          </div>
        </CardContent>
      </Card>

      <Card className='overflow-hidden'>
        <CardHeader>
          <div className='flex items-center justify-between gap-3'>
            <div>
              <CardTitle>{diagramNames[props.diagramType] || '模型图谱'}</CardTitle>
              <CardDescription>
                {props.diagram?.nodes.length || 0} 节点 / {props.diagram?.edges.length || 0} 关系
              </CardDescription>
            </div>
            <Badge variant='secondary'>SVG</Badge>
          </div>
        </CardHeader>
        <CardContent className='p-0'>
          <ScrollArea orientation='horizontal' className='h-[650px] bg-muted/30'>
            <DiagramCanvas
              diagram={props.diagram}
              selectedId={props.selectedId}
              onSelect={props.setSelectedId}
            />
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  )
}

function DiagramCanvas({
  diagram,
  selectedId,
  onSelect,
}: {
  diagram: DiagramPayload | null
  selectedId: string
  onSelect: (id: string) => void
}) {
  if (!diagram || !diagram.nodes.length) {
    return <EmptyState title='暂无图谱' description='当前模型没有可绘制的节点' />
  }
  const width = Math.max(...diagram.nodes.map((node) => node.x + node.width)) + 100
  const height = Math.max(...diagram.nodes.map((node) => node.y + node.height)) + 100
  const nodeMap = new Map(diagram.nodes.map((node) => [node.id, node]))

  return (
    <svg
      className='min-h-full min-w-full'
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role='img'
      aria-label={diagramNames[diagram.type] || diagram.label}
    >
      <defs>
        <marker
          id='sysml-arrow'
          markerHeight='10'
          markerWidth='10'
          orient='auto'
          refX='9'
          refY='3'
        >
          <path d='M0,0 L0,6 L9,3 z' fill='var(--muted-foreground)' />
        </marker>
      </defs>
      {diagram.edges.map((edge, index) => {
        const source = nodeMap.get(edge.source)
        const target = nodeMap.get(edge.target)
        if (!source || !target) return null
        const x1 = source.x + source.width
        const y1 = source.y + source.height / 2
        const x2 = target.x
        const y2 = target.y + target.height / 2
        const midX = (x1 + x2) / 2
        return (
          <g key={`${edge.source}-${edge.target}-${edge.type}-${index}`}>
            <path
              d={`M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`}
              fill='none'
              stroke='var(--muted-foreground)'
              strokeWidth='1.5'
              markerEnd='url(#sysml-arrow)'
            />
            <text
              x={midX}
              y={(y1 + y2) / 2 - 6}
              textAnchor='middle'
              className='fill-muted-foreground text-[12px]'
              paintOrder='stroke'
              stroke='var(--background)'
              strokeWidth='5'
            >
              {labelRelation(edge.type)}
            </text>
          </g>
        )
      })}
      {diagram.nodes.map((node) => (
        <g
          key={node.id}
          role='button'
          tabIndex={0}
          onClick={() => onSelect(node.id)}
          className='cursor-pointer'
        >
          <rect
            x={node.x}
            y={node.y}
            width={node.width}
            height={node.height}
            rx='8'
            className={cn(
              'fill-background stroke-border drop-shadow-sm',
              selectedId === node.id && 'stroke-primary'
            )}
            strokeWidth={selectedId === node.id ? 2 : 1}
          />
          <text
            x={node.x + 14}
            y={node.y + 24}
            className='fill-foreground font-mono text-[13px] font-semibold'
          >
            {node.id}
          </text>
          <text
            x={node.x + 14}
            y={node.y + 45}
            className='fill-foreground text-[13px]'
          >
            {truncate(node.name || '未命名', 14)}
          </text>
          <text
            x={node.x + node.width - 12}
            y={node.y + 24}
            textAnchor='end'
            className='fill-muted-foreground text-[11px]'
          >
            {labelType(node.type)}
          </text>
        </g>
      ))}
    </svg>
  )
}

function TraceTab({
  traceability,
  busy,
  onRefresh,
}: {
  traceability: TraceabilityRow[]
  busy: string
  onRefresh: () => void
}) {
  return (
    <Card>
      <CardHeader>
        <div className='flex items-center justify-between gap-3'>
          <div>
            <CardTitle>需求追踪矩阵</CardTitle>
            <CardDescription>查看需求到模块、测试、约束的闭环情况</CardDescription>
          </div>
          <Button variant='outline' onClick={onRefresh} disabled={busy === 'trace'}>
            {busy === 'trace' ? (
              <Loader2 className='size-4 animate-spin' />
            ) : (
              <RefreshCw className='size-4' />
            )}
            刷新
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {traceability.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>需求</TableHead>
                <TableHead>满足元素</TableHead>
                <TableHead>验证元素</TableHead>
                <TableHead>约束</TableHead>
                <TableHead>状态</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {traceability.map((row) => (
                <TableRow key={row.requirement.id}>
                  <TableCell>
                    <div className='font-mono font-medium'>
                      {row.requirement.id}
                    </div>
                    <div className='text-muted-foreground'>
                      {row.requirement.name}
                    </div>
                  </TableCell>
                  <TableCell>{formatRefs(row.satisfied_by)}</TableCell>
                  <TableCell>{formatRefs(row.verified_by)}</TableCell>
                  <TableCell>{formatRefs(row.constrained_by || [])}</TableCell>
                  <TableCell>
                    <TraceBadge status={row.status} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <EmptyState title='暂无追踪数据' description='点击刷新加载追踪矩阵' />
        )}
      </CardContent>
    </Card>
  )
}

type VersionTabProps = {
  branches: Branch[]
  commits: Commit[]
  auditEvents: AuditEvent[]
  diff: DiffPayload | null
  diffFrom: string
  setDiffFrom: (value: string) => void
  diffTo: string
  setDiffTo: (value: string) => void
  rollbackCommit: string
  setRollbackCommit: (value: string) => void
  newBranch: string
  setNewBranch: (value: string) => void
  mergeSource: string
  setMergeSource: (value: string) => void
  forceMerge: boolean
  setForceMerge: (value: boolean) => void
  onRefresh: () => void
  onDiff: () => void
  onRollback: () => void
  onCreateBranch: () => void
  onMerge: () => void
  busy: string
}

function VersionTab(props: VersionTabProps) {
  const commitOptions = [
    { id: 'working', label: 'working' },
    ...props.commits.map((commit) => ({
      id: commit.id,
      label: `${commit.id} / ${commit.message}`,
    })),
  ]
  return (
    <div className='grid gap-4 xl:grid-cols-[380px_1fr]'>
      <Card>
        <CardHeader>
          <div className='flex items-center justify-between'>
            <div>
              <CardTitle>版本操作</CardTitle>
              <CardDescription>分支、Diff、回滚和合并</CardDescription>
            </div>
            <Button variant='outline' size='sm' onClick={props.onRefresh}>
              <RefreshCw className='size-4' />
            </Button>
          </div>
        </CardHeader>
        <CardContent className='space-y-5'>
          <div className='grid gap-3'>
            <div className='grid gap-3 sm:grid-cols-2 xl:grid-cols-1'>
              <Field label='Diff From'>
                <Select value={props.diffFrom} onValueChange={props.setDiffFrom}>
                  <SelectTrigger className='w-full'>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {commitOptions.map((item) => (
                      <SelectItem key={item.id} value={item.id}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
              <Field label='Diff To'>
                <Select value={props.diffTo} onValueChange={props.setDiffTo}>
                  <SelectTrigger className='w-full'>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {commitOptions.map((item) => (
                      <SelectItem key={item.id} value={item.id}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
            </div>
            <Button onClick={props.onDiff} disabled={props.busy === 'diff'}>
              <GitCompare className='size-4' />
              运行 Diff
            </Button>
          </div>
          <Separator />
          <div className='grid gap-3'>
            <Field label='回滚提交'>
              <Select
                value={props.rollbackCommit}
                onValueChange={props.setRollbackCommit}
              >
                <SelectTrigger className='w-full'>
                  <SelectValue placeholder='选择提交' />
                </SelectTrigger>
                <SelectContent>
                  {props.commits.map((commit) => (
                    <SelectItem key={commit.id} value={commit.id}>
                      {commit.id} / {commit.message}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Button variant='destructive' onClick={props.onRollback}>
              <RotateCcw className='size-4' />
              回滚
            </Button>
          </div>
          <Separator />
          <div className='grid gap-3'>
            <Field label='新分支'>
              <Input
                placeholder='dev-power'
                value={props.newBranch}
                onChange={(event) => props.setNewBranch(event.target.value)}
              />
            </Field>
            <Button variant='outline' onClick={props.onCreateBranch}>
              <GitBranch className='size-4' />
              创建分支
            </Button>
          </div>
          <Separator />
          <div className='grid gap-3'>
            <Field label='合并来源'>
              <Select value={props.mergeSource} onValueChange={props.setMergeSource}>
                <SelectTrigger className='w-full'>
                  <SelectValue placeholder='选择分支' />
                </SelectTrigger>
                <SelectContent>
                  {props.branches.map((item) => (
                    <SelectItem key={item.name} value={item.name}>
                      {item.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <label className='flex items-center gap-2 text-sm'>
              <Checkbox
                checked={props.forceMerge}
                onCheckedChange={(checked) => props.setForceMerge(Boolean(checked))}
              />
              强制合并冲突
            </label>
            <Button variant='outline' onClick={props.onMerge}>
              <GitMerge className='size-4' />
              合并
            </Button>
          </div>
        </CardContent>
      </Card>

      <div className='space-y-4'>
        <Card>
          <CardHeader>
            <div className='flex items-center justify-between gap-3'>
              <div>
                <CardTitle>Diff 结果</CardTitle>
                <CardDescription>
                  {props.diff
                    ? `+${props.diff.summary.added} -${props.diff.summary.removed} ~${props.diff.summary.modified}`
                    : '尚未运行 Diff'}
                </CardDescription>
              </div>
              {props.diff && (
                <Badge variant='secondary'>
                  {props.diff.from} → {props.diff.to}
                </Badge>
              )}
            </div>
          </CardHeader>
          <CardContent>
            {props.diff ? (
              <div className='grid gap-4 md:grid-cols-3'>
                <DiffGroup title='新增' items={props.diff.added} />
                <DiffGroup title='删除' items={props.diff.removed} />
                <div className='rounded-md border p-3'>
                  <h3 className='mb-2 text-sm font-semibold'>修改</h3>
                  <div className='space-y-2 text-sm'>
                    {props.diff.modified.length ? (
                      props.diff.modified.map((item) => (
                        <div key={item.id} className='rounded-md bg-muted p-2'>
                          <div className='font-mono font-medium'>{item.id}</div>
                          <p className='text-xs text-muted-foreground'>
                            {item.changes.map((change) => change.field).join(', ')}
                          </p>
                        </div>
                      ))
                    ) : (
                      <p className='text-muted-foreground'>无</p>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <EmptyState title='等待 Diff' description='选择两个版本后运行 Diff' />
            )}
          </CardContent>
        </Card>

        <div className='grid gap-4 xl:grid-cols-2'>
          <Card>
            <CardHeader>
              <CardTitle>提交记录</CardTitle>
              <CardDescription>{props.commits.length} 条提交</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className='h-[320px]'>
                <div className='space-y-3'>
                  {props.commits.map((commit) => (
                    <div key={commit.id} className='rounded-md border p-3'>
                      <div className='font-mono text-sm font-semibold'>
                        {commit.id}
                      </div>
                      <p className='mt-1 text-sm'>{commit.message}</p>
                      <p className='mt-1 text-xs text-muted-foreground'>
                        {commit.branch} / {commit.author} / {commit.created_at} /{' '}
                        {commit.element_count} elements
                      </p>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>审计日志</CardTitle>
              <CardDescription>{props.auditEvents.length} 条事件</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className='h-[320px]'>
                <div className='space-y-3'>
                  {props.auditEvents.map((event, index) => (
                    <div key={`${event.created_at}-${index}`} className='rounded-md border p-3'>
                      <div className='text-sm font-semibold'>{event.action}</div>
                      <p className='mt-1 text-xs text-muted-foreground'>
                        {event.branch_name || '-'} / {event.actor} / {event.created_at}
                      </p>
                      {event.element_id && (
                        <p className='mt-1 font-mono text-xs'>{event.element_id}</p>
                      )}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}

function DiffGroup({ title, items }: { title: string; items: SysmlElement[] }) {
  return (
    <div className='rounded-md border p-3'>
      <h3 className='mb-2 text-sm font-semibold'>{title}</h3>
      <div className='space-y-2 text-sm'>
        {items.length ? (
          items.map((item) => (
            <div key={item.id} className='rounded-md bg-muted p-2'>
              <div className='font-mono font-medium'>{item.id}</div>
              <p className='truncate text-xs text-muted-foreground'>
                {labelType(item.type)} / {item.name}
              </p>
            </div>
          ))
        ) : (
          <p className='text-muted-foreground'>无</p>
        )}
      </div>
    </div>
  )
}

type DocgenTabProps = {
  template: string
  setTemplate: (value: string) => void
  documents: DocumentRecord[]
  currentDocument: DocumentRecord | null
  onReset: () => void
  onGenerate: () => void
  onOpen: (id: string) => void
  onDownload: (format: 'html' | 'markdown' | 'pdf') => void
  busy: string
}

function DocgenTab(props: DocgenTabProps) {
  return (
    <div className='grid gap-4 xl:grid-cols-[minmax(360px,0.42fr)_minmax(560px,0.58fr)]'>
      <Card>
        <CardHeader>
          <div className='flex items-center justify-between gap-3'>
            <div>
              <CardTitle>DocGen 模板</CardTitle>
              <CardDescription>使用占位符生成 HTML / Markdown / PDF</CardDescription>
            </div>
            <Button variant='outline' size='sm' onClick={props.onReset}>
              <RotateCcw className='size-4' />
            </Button>
          </div>
        </CardHeader>
        <CardContent className='space-y-4'>
          <Textarea
            className='min-h-[360px] font-mono text-xs'
            value={props.template}
            onChange={(event) => props.setTemplate(event.target.value)}
          />
          <div className='flex flex-wrap gap-2'>
            <Button
              onClick={props.onGenerate}
              disabled={props.busy === 'generate-document'}
            >
              {props.busy === 'generate-document' ? (
                <Loader2 className='size-4 animate-spin' />
              ) : (
                <FileText className='size-4' />
              )}
              生成
            </Button>
            <Button variant='outline' onClick={() => props.onDownload('markdown')}>
              Markdown
            </Button>
            <Button variant='outline' onClick={() => props.onDownload('html')}>
              HTML
            </Button>
            <Button variant='outline' onClick={() => props.onDownload('pdf')}>
              PDF
            </Button>
          </div>
          <Separator />
          <div>
            <h3 className='mb-2 text-sm font-semibold'>历史文档</h3>
            <ScrollArea className='h-[220px] rounded-md border'>
              {props.documents.length ? (
                <div className='divide-y'>
                  {props.documents.map((document) => (
                    <button
                      key={document.id}
                      type='button'
                      onClick={() => props.onOpen(document.id)}
                      className='grid w-full gap-1 px-3 py-2 text-left text-sm hover:bg-muted'
                    >
                      <span className='font-mono font-semibold'>{document.id}</span>
                      <span className='text-xs text-muted-foreground'>
                        {document.created_at} / {document.model_hash}
                      </span>
                    </button>
                  ))}
                </div>
              ) : (
                <EmptyState title='暂无文档' description='生成后会出现在这里' />
              )}
            </ScrollArea>
          </div>
        </CardContent>
      </Card>

      <Card className='overflow-hidden'>
        <CardHeader>
          <div className='flex items-center justify-between gap-3'>
            <div>
              <CardTitle>文档预览</CardTitle>
              <CardDescription>
                {props.currentDocument?.id || '尚未生成文档'}
              </CardDescription>
            </div>
            {props.currentDocument && <Badge variant='secondary'>HTML</Badge>}
          </div>
        </CardHeader>
        <CardContent className='p-0'>
          {props.currentDocument?.html ? (
            <iframe
              title='文档预览'
              srcDoc={props.currentDocument.html}
              className='h-[720px] w-full border-0 bg-background'
            />
          ) : (
            <div className='h-[720px]'>
              <EmptyState title='等待生成' description='点击生成按钮预览文档' />
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function Field({
  label,
  children,
}: {
  label: string
  children: ReactNode
}) {
  return (
    <div className='grid gap-2'>
      <Label>{label}</Label>
      {children}
    </div>
  )
}

function EmptyState({
  title,
  description,
}: {
  title: string
  description: string
}) {
  return (
    <div className='flex min-h-[180px] flex-col items-center justify-center gap-2 p-8 text-center'>
      <Braces className='size-8 text-muted-foreground' />
      <div className='font-medium'>{title}</div>
      <p className='max-w-sm text-sm text-muted-foreground'>{description}</p>
    </div>
  )
}

function TraceBadge({ status }: { status: TraceabilityRow['status'] }) {
  const classes = {
    closed: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300',
    partial: 'bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-300',
    open: 'bg-rose-100 text-rose-700 dark:bg-rose-950 dark:text-rose-300',
  }
  const labels = {
    closed: '闭环',
    partial: '部分',
    open: '未闭环',
  }
  return (
    <span className={cn('inline-flex rounded-md px-2 py-1 text-xs font-medium', classes[status])}>
      {labels[status]}
    </span>
  )
}

function formatRefs(refs: { id: string; name: string }[]) {
  if (!refs.length) return <span className='text-muted-foreground'>-</span>
  return (
    <div className='space-y-1'>
      {refs.map((ref) => (
        <div key={ref.id}>
          <span className='font-mono font-medium'>{ref.id}</span>{' '}
          <span className='text-muted-foreground'>{ref.name}</span>
        </div>
      ))}
    </div>
  )
}

function labelType(type: string) {
  return typeNames[type] || type
}

function labelRelation(type: string) {
  return relationNames[type] || type
}

function countBy<T>(items: T[], getKey: (item: T) => string) {
  return items.reduce<Record<string, number>>((acc, item) => {
    const key = getKey(item)
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {})
}

function parseJson<T>(value: string, label: string, fallback: T): T {
  try {
    return (value.trim() ? JSON.parse(value) : fallback) as T
  } catch {
    throw new Error(`${label} 格式不正确`)
  }
}

function parseJsonSafe<T>(value: string, fallback: T): T {
  try {
    return (value.trim() ? JSON.parse(value) : fallback) as T
  } catch {
    return fallback
  }
}

function notifyError(error: unknown) {
  const message = error instanceof Error ? error.message : String(error)
  toast.error(message)
}

function truncate(value: string, length: number) {
  return value.length > length ? `${value.slice(0, length - 1)}…` : value
}

function downloadText(filename: string, text: string, type: string) {
  const blob = new Blob([text], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

function downloadBase64(filename: string, base64Text: string, type: string) {
  const binary = atob(base64Text)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  const blob = new Blob([bytes], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}
