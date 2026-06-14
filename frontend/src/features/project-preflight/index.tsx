import { useEffect, useMemo, useState } from 'react'
import type { LucideIcon } from 'lucide-react'
import {
  AlertTriangle,
  CheckCircle2,
  Code2,
  FileCode2,
  FileText,
  FolderOpen,
  Layers3,
  Loader2,
  PackageCheck,
  Play,
  ScanSearch,
  ShieldCheck,
  Workflow,
} from 'lucide-react'
import { useNavigate } from '@tanstack/react-router'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { toast } from 'sonner'
import {
  loadLatestProjectImport,
  startProjectScan,
  type ProjectImportRecord,
  type ScanJob,
} from '@/lib/import-api'
import { createSecurityWorkspace, runWorkspaceScanSuite } from '@/lib/security-api'
import { cn } from '@/lib/utils'
import {
  demoPresets,
  presetKeyFromProject,
  type DemoPresetKey,
} from '@/features/project-import/demo-presets'
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
import { Header } from '@/components/layout/header'
import { Main } from '@/components/layout/main'
import { Search } from '@/components/search'
import { ThemeSwitch } from '@/components/theme-switch'

type CoverageState = 'ready' | 'partial' | 'missing'

type CoverageRow = {
  name: string
  found: CoverageState
  usable: CoverageState
  gap: CoverageState
  note: string
}

type KeyFilePurpose = {
  file: string
  type: string
  purpose: string
  icon: LucideIcon
}

const chartColors = ['#0891b2', '#10b981', '#f59e0b', '#6366f1', '#64748b']

export function ProjectPreflightPage() {
  const navigate = useNavigate()
  const [record, setRecord] = useState<ProjectImportRecord | null>(null)
  const [scanJob, setScanJob] = useState<ScanJob | null>(null)
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)

  useEffect(() => {
    let ignore = false
    loadLatestProjectImport()
      .then((nextRecord) => {
        if (!ignore) setRecord(nextRecord)
      })
      .catch((error) => {
        if (!ignore) toast.error(error instanceof Error ? error.message : '加载预检资产失败')
      })
      .finally(() => {
        if (!ignore) setLoading(false)
      })
    return () => {
      ignore = true
    }
  }, [])

  const presetKey = useMemo(
    () => presetKeyFromProject(record?.projectName, record?.sourcePath) as DemoPresetKey | null,
    [record]
  )

  async function runTraceScan() {
    if (!record) return
    setScanning(true)
    try {
      const nextJob = await startProjectScan(record.importId, record.summary.scanScope)
      const preset = presetKey ? demoPresets[presetKey] : null
      const workspace = await createSecurityWorkspace({
        importId: record.importId,
        preset: presetKey ?? 'custom',
        name: record.projectName,
      })
      const workspaceId = workspace.workspaceId || workspace.workspace?.workspaceId
      if (!workspaceId) throw new Error('工作空间创建失败，未返回 workspaceId')
      const nextWorkspace = await runWorkspaceScanSuite(workspaceId, {
        importId: record.importId,
        artifactPath: preset?.artifactPath,
        attestationPath: preset?.attestationPath,
        expectedRepo: preset?.expectedRepo,
        expectedCommit: preset?.expectedCommit,
        allowedWorkflows: preset?.allowedWorkflows,
        allowedBuilders: preset?.allowedBuilders,
        allowSelfHostedRunner: preset?.allowSelfHostedRunner,
        requireSignature: false,
        logPaths: preset?.logPaths ?? [],
        timeoutSeconds: 180,
      })
      setScanJob(nextJob)
      toast.success(
        `供应链溯源完成：综合风险 ${nextWorkspace.summary.risk_score}/100，攻击路径 ${nextWorkspace.summary.attack_paths} 条`
      )
      void navigate({ to: '/', hash: 'overview' })
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '供应链溯源启动失败')
    } finally {
      setScanning(false)
    }
  }

  if (loading) {
    return (
      <div className='flex min-h-svh items-center justify-center gap-3 text-muted-foreground'>
        <Loader2 className='size-5 animate-spin' />
        正在加载预检资产
      </div>
    )
  }

  if (!record) {
    return (
      <Main>
        <Alert variant='destructive'>
          <AlertTriangle />
          <AlertTitle>还没有可预检的项目</AlertTitle>
          <AlertDescription>
            请先完成第 1 步，选择比赛案例或导入一个自定义项目。
          </AlertDescription>
        </Alert>
        <Button className='mt-4' onClick={() => void navigate({ to: '/project-import' })}>
          <FolderOpen />
          去选择案例
        </Button>
      </Main>
    )
  }

  const summary = record.summary
  const preset = presetKey ? demoPresets[presetKey] : null
  const source = sourceLabel(record)
  const completeness = preflightCompleteness(record)
  const readiness = preflightReadiness(record, presetKey)
  const keyFiles = keyFilePurposes(record, presetKey)
  const coverageRows = materialCoverageRows(record, Boolean(preset))
  const missing = missingMaterials(record, Boolean(preset))
  const funnelItems = scanFunnelItems(record)

  return (
    <div className='min-h-svh bg-background'>
      <Header fixed>
        <div className='flex min-w-0 flex-1 items-center justify-between gap-4'>
          <div className='min-w-0'>
            <div className='truncate text-sm font-semibold'>预检资产</div>
            <div className='truncate text-xs text-muted-foreground'>
              第 2 步 · 资产体检报告
            </div>
          </div>
          <div className='flex shrink-0 items-center gap-2'>
            <Search />
            <ThemeSwitch />
          </div>
        </div>
      </Header>

      <Main fluid className='space-y-5'>
        <div className='space-y-2'>
          <Badge variant='outline' className='rounded-md border-cyan-200 bg-cyan-50 text-cyan-700'>
            Step 2 · Preflight Report
          </Badge>
          <h1 className='text-2xl font-semibold tracking-normal sm:text-3xl'>
            资产预检报告
          </h1>
          <p className='max-w-3xl text-sm leading-6 text-muted-foreground'>
            这一步回答：项目有哪些可用于供应链溯源的材料，哪些材料已经具备，下一步应该优先检查什么。
          </p>
        </div>

        <section className='rounded-md border border-cyan-200 bg-cyan-50/60 p-4 dark:border-cyan-900 dark:bg-cyan-950/20'>
          <div className='grid gap-5 xl:grid-cols-[minmax(0,1fr)_220px_320px]'>
            <div className='space-y-4'>
              <div className='flex flex-wrap items-center gap-2'>
                <Badge variant='outline' className='rounded-md border-emerald-200 bg-emerald-50 text-emerald-700'>
                  预检完成
                </Badge>
                <Badge variant='outline' className='rounded-md bg-background'>
                  {presetKey ? '比赛案例' : '自定义项目'}
                </Badge>
                <Badge variant='outline' className='rounded-md bg-background'>
                  {sourceTypeLabel(record.sourceType)}
                </Badge>
              </div>
              <div>
                <h2 className='text-2xl font-semibold tracking-normal'>{record.projectName}</h2>
                <p className='mt-1 truncate text-sm text-muted-foreground'>{source}</p>
              </div>
              <div className='grid gap-2 sm:grid-cols-3'>
                {readiness.map((item) => (
                  <div key={item.label} className='rounded-md border bg-background p-3'>
                    <div className='flex items-center gap-2 text-sm font-medium'>
                      <item.icon className={cn('size-4', item.ok ? 'text-emerald-600' : 'text-orange-600')} />
                      {item.label}
                    </div>
                    <div className='mt-1 text-xs text-muted-foreground'>{item.description}</div>
                  </div>
                ))}
              </div>
            </div>

            <ReadinessRing score={completeness.score} passed={completeness.passed} total={completeness.total} />

            <div className='rounded-md border bg-background p-4'>
              <div className='text-sm font-medium'>建议下一步</div>
              <p className='mt-2 text-sm leading-6 text-muted-foreground'>
                先生成 SBOM 与 VEX，确认组件风险；随后检查 CI/CD、产物可信和运行日志是否能互相印证。
              </p>
              <Button className='mt-4 w-full' onClick={() => void runTraceScan()} disabled={scanning}>
                {scanning ? <Loader2 className='animate-spin' /> : <Play />}
                进入供应链风险发现
              </Button>
            </div>
          </div>
        </section>

        <section className='grid gap-3 md:grid-cols-2 xl:grid-cols-4'>
          <PreflightMetric icon={FileText} label='总文件' value={summary.fileStats.total} detail='项目内发现的全部文件' />
          <PreflightMetric icon={ScanSearch} label='参与扫描' value={summary.fileStats.scannable} detail='可用于静态分析的文件' />
          <PreflightMetric icon={PackageCheck} label='依赖入口' value={summary.dependencyFiles.length} detail='package、lockfile、requirements' />
          <PreflightMetric icon={Workflow} label='CI/CD 入口' value={summary.ciFiles.length} detail='workflow、runner 和构建入口' />
        </section>

        <section className='grid gap-4 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,0.95fr)_minmax(360px,0.7fr)]'>
          <Card className='rounded-md'>
            <CardHeader>
              <CardTitle className='flex items-center gap-2 text-base'>
                <Code2 className='size-4 text-emerald-600' />
                语言构成图
              </CardTitle>
              <CardDescription>判断后续扫描需要覆盖的生态和规则</CardDescription>
            </CardHeader>
            <CardContent>
              <LanguageBarChart record={record} />
            </CardContent>
          </Card>

          <Card className='rounded-md'>
            <CardHeader>
              <CardTitle className='flex items-center gap-2 text-base'>
                <Layers3 className='size-4 text-cyan-600' />
                扫描漏斗
              </CardTitle>
              <CardDescription>从项目文件收敛到可用于溯源的关键入口</CardDescription>
            </CardHeader>
            <CardContent>
              <ScanFunnel items={funnelItems} />
            </CardContent>
          </Card>

          <Card className='rounded-md'>
            <CardHeader>
              <CardTitle className='flex items-center gap-2 text-base'>
                <ShieldCheck className='size-4 text-emerald-600' />
                预检判断
              </CardTitle>
              <CardDescription>已具备、仍缺少、建议动作</CardDescription>
            </CardHeader>
            <CardContent className='space-y-3'>
              <JudgementItem
                title='已具备'
                tone='emerald'
                items={[
                  `${summary.fileStats.scannable} 个文件可参与扫描`,
                  `${summary.dependencyFiles.length} 个依赖入口`,
                  `${summary.ciFiles.length} 个 CI/CD 入口`,
                ]}
              />
              <JudgementItem title='仍缺少' tone='orange' items={missing} />
              <JudgementItem
                title='建议动作'
                tone='cyan'
                items={['生成 SBOM 与 VEX', '检查构建链污染', '执行产物可信门禁']}
              />
            </CardContent>
          </Card>
        </section>

        <section className='grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]'>
          <Card className='rounded-md'>
            <CardHeader>
              <CardTitle className='flex items-center gap-2 text-base'>
                <ShieldCheck className='size-4 text-cyan-600' />
                材料覆盖矩阵
              </CardTitle>
              <CardDescription>展示材料是否已发现、是否可用于溯源、还存在哪些缺口</CardDescription>
            </CardHeader>
            <CardContent>
              <CoverageMatrix rows={coverageRows} />
            </CardContent>
          </Card>

          <Card className='rounded-md'>
            <CardHeader>
              <CardTitle className='flex items-center gap-2 text-base'>
                <FileCode2 className='size-4 text-cyan-600' />
                关键文件与作用清单
              </CardTitle>
              <CardDescription>说明每个入口文件会支撑哪类溯源判断</CardDescription>
            </CardHeader>
            <CardContent>
              <KeyFilePurposeList files={keyFiles} />
            </CardContent>
          </Card>
        </section>

        {summary.warnings.length ? (
          <Alert className='rounded-md'>
            <AlertTriangle className='size-4' />
            <AlertTitle>预检提示</AlertTitle>
            <AlertDescription>
              <div className='mt-2 grid gap-2'>
                {summary.warnings.map((warning) => (
                  <div key={warning}>{warning}</div>
                ))}
              </div>
            </AlertDescription>
          </Alert>
        ) : null}

        {scanJob ? (
          <Alert className='rounded-md border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/35 dark:text-emerald-200'>
            <CheckCircle2 className='size-4' />
            <AlertTitle>供应链溯源工作空间已创建</AlertTitle>
            <AlertDescription>
              {scanJob.scanId} · 已进入调查工作台，可继续查看攻击路径和溯源报告。
            </AlertDescription>
          </Alert>
        ) : null}
      </Main>
    </div>
  )
}

function ReadinessRing({
  score,
  passed,
  total,
}: {
  score: number
  passed: number
  total: number
}) {
  const data = [
    { name: '已具备', value: score },
    { name: '缺口', value: Math.max(0, 100 - score) },
  ]
  return (
    <div className='rounded-md border bg-background p-4'>
      <div className='text-sm font-medium'>预检完整度</div>
      <div className='relative mt-3 h-36'>
        <ResponsiveContainer width='100%' height='100%'>
          <PieChart>
            <Pie
              data={data}
              dataKey='value'
              innerRadius={46}
              outerRadius={62}
              startAngle={90}
              endAngle={-270}
              stroke='none'
            >
              <Cell fill='#0891b2' />
              <Cell fill='#e2e8f0' />
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className='absolute inset-0 grid place-items-center text-center'>
          <div>
            <div className='text-3xl font-semibold tracking-normal'>{score}%</div>
            <div className='text-xs text-muted-foreground'>{passed}/{total} 项具备</div>
          </div>
        </div>
      </div>
    </div>
  )
}

function PreflightMetric({
  icon: Icon,
  label,
  value,
  detail,
}: {
  icon: LucideIcon
  label: string
  value: number
  detail: string
}) {
  return (
    <Card className='rounded-md'>
      <CardContent className='p-4'>
        <div className='flex items-center justify-between gap-3'>
          <div className='text-sm text-muted-foreground'>{label}</div>
          <Icon className='size-4 text-cyan-600' />
        </div>
        <div className='mt-2 text-2xl font-semibold tracking-normal'>{formatNumber(value)}</div>
        <div className='mt-1 text-xs text-muted-foreground'>{detail}</div>
      </CardContent>
    </Card>
  )
}

function LanguageBarChart({ record }: { record: ProjectImportRecord }) {
  const data = record.summary.languages.slice(0, 6).map((language, index) => ({
    name: language.name,
    percent: language.percent,
    files: language.files,
    fill: chartColors[index % chartColors.length],
  }))
  if (!data.length) {
    return (
      <ActionableEmpty
        title='未识别到主要语言'
        description='仍可继续检查依赖文件和 CI 文件，后续扫描会保留 partial 结果。'
      />
    )
  }
  return (
    <div className='h-72'>
      <ResponsiveContainer width='100%' height='100%'>
        <BarChart data={data} layout='vertical' margin={{ left: 12, right: 36, top: 8, bottom: 8 }}>
          <CartesianGrid strokeDasharray='3 3' horizontal={false} />
          <XAxis type='number' domain={[0, 100]} tickFormatter={(value) => `${value}%`} />
          <YAxis dataKey='name' type='category' width={96} />
          <Tooltip
            formatter={(value, _name, item) => [
              `${value}% · ${item.payload.files} files`,
              '占比',
            ]}
          />
          <Bar dataKey='percent' radius={[0, 6, 6, 0]}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={entry.fill} />
            ))}
            <LabelList dataKey='percent' position='right' formatter={(value) => `${value}%`} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

function ScanFunnel({ items }: { items: Array<{ label: string; value: number; detail: string }> }) {
  const max = Math.max(...items.map((item) => item.value), 1)
  return (
    <div className='space-y-3'>
      {items.map((item, index) => {
        const width = Math.max(18, (item.value / max) * 100)
        return (
          <div key={item.label} className='rounded-md border p-3'>
            <div className='flex items-center justify-between gap-3 text-sm'>
              <div className='font-medium'>{item.label}</div>
              <div className='text-muted-foreground'>{formatNumber(item.value)}</div>
            </div>
            <div className='mt-2 h-3 overflow-hidden rounded-full bg-muted'>
              <div
                className={cn(
                  'h-full rounded-full',
                  index === 0 && 'bg-slate-500',
                  index === 1 && 'bg-cyan-600',
                  index === 2 && 'bg-emerald-600',
                  index === 3 && 'bg-amber-500'
                )}
                style={{ width: `${width}%` }}
              />
            </div>
            <div className='mt-1 text-xs text-muted-foreground'>{item.detail}</div>
          </div>
        )
      })}
    </div>
  )
}

function CoverageMatrix({ rows }: { rows: CoverageRow[] }) {
  return (
    <div className='overflow-hidden rounded-md border'>
      <div className='grid grid-cols-[1.2fr_0.8fr_0.8fr_0.8fr_1.4fr] bg-muted/60 px-3 py-2 text-xs font-medium text-muted-foreground'>
        <div>材料</div>
        <div>已发现</div>
        <div>可用于溯源</div>
        <div>缺口</div>
        <div>说明</div>
      </div>
      {rows.map((row) => (
        <div key={row.name} className='grid grid-cols-[1.2fr_0.8fr_0.8fr_0.8fr_1.4fr] items-center border-t px-3 py-3 text-sm'>
          <div className='font-medium'>{row.name}</div>
          <MatrixState state={row.found} />
          <MatrixState state={row.usable} />
          <MatrixState state={row.gap} mode='gap' />
          <div className='text-xs leading-5 text-muted-foreground'>{row.note}</div>
        </div>
      ))}
    </div>
  )
}

function MatrixState({
  state,
  mode = 'normal',
}: {
  state: CoverageState
  mode?: 'normal' | 'gap'
}) {
  const labels: Record<'normal' | 'gap', Record<CoverageState, string>> = {
    normal: {
      ready: '是',
      partial: '部分',
      missing: '缺少',
    },
    gap: {
      ready: '无',
      partial: '待补',
      missing: '缺少',
    },
  }
  return (
    <div className='flex items-center gap-1.5 text-xs'>
      <span
        className={cn(
          'size-2 rounded-full',
          state === 'ready' && 'bg-emerald-500',
          state === 'partial' && 'bg-amber-500',
          state === 'missing' && 'bg-slate-300'
        )}
      />
      <span className='text-muted-foreground'>{labels[mode][state]}</span>
    </div>
  )
}

function KeyFilePurposeList({ files }: { files: KeyFilePurpose[] }) {
  if (!files.length) {
    return (
      <ActionableEmpty
        title='还没有发现关键入口文件'
        description='可以返回第 1 步补充项目材料，或继续用代码和日志做有限溯源。'
      />
    )
  }
  return (
    <div className='space-y-2'>
      {files.map((item) => (
        <div key={`${item.type}-${item.file}`} className='grid gap-3 rounded-md border p-3 md:grid-cols-[180px_minmax(0,1fr)_220px]'>
          <div className='flex items-center gap-2 text-sm font-medium'>
            <item.icon className='size-4 text-cyan-600' />
            {item.type}
          </div>
          <div className='truncate font-mono text-xs'>{item.file}</div>
          <div className='text-xs leading-5 text-muted-foreground'>{item.purpose}</div>
        </div>
      ))}
    </div>
  )
}

function ActionableEmpty({ title, description }: { title: string; description: string }) {
  return (
    <div className='rounded-md border border-dashed p-6 text-center'>
      <div className='mx-auto grid size-10 place-items-center rounded-md bg-muted'>
        <ScanSearch className='size-5 text-muted-foreground' />
      </div>
      <div className='mt-3 text-sm font-medium'>{title}</div>
      <div className='mt-1 text-xs leading-5 text-muted-foreground'>{description}</div>
    </div>
  )
}

function JudgementItem({
  title,
  items,
  tone,
}: {
  title: string
  items: string[]
  tone: 'emerald' | 'orange' | 'cyan'
}) {
  const toneClass = {
    emerald: 'border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-200',
    orange: 'border-orange-200 bg-orange-50 text-orange-800 dark:border-orange-900 dark:bg-orange-950/30 dark:text-orange-200',
    cyan: 'border-cyan-200 bg-cyan-50 text-cyan-800 dark:border-cyan-900 dark:bg-cyan-950/30 dark:text-cyan-200',
  }[tone]
  return (
    <div className={cn('rounded-md border p-3', toneClass)}>
      <div className='text-sm font-medium'>{title}</div>
      <div className='mt-2 space-y-1 text-xs leading-5'>
        {items.map((item) => (
          <div key={item}>· {item}</div>
        ))}
      </div>
    </div>
  )
}

function preflightCompleteness(record: ProjectImportRecord) {
  const checks = [
    record.summary.fileStats.scannable > 0,
    record.summary.languages.length > 0,
    record.summary.dependencyFiles.length > 0,
    record.summary.ciFiles.length > 0,
    record.summary.warnings.length === 0,
  ]
  const passed = checks.filter(Boolean).length
  return {
    passed,
    total: checks.length,
    score: Math.round((passed / checks.length) * 100),
  }
}

function preflightReadiness(record: ProjectImportRecord, presetKey: DemoPresetKey | null) {
  return [
    {
      label: '依赖入口',
      ok: record.summary.dependencyFiles.length > 0,
      description: record.summary.dependencyFiles.length
        ? '可以生成 SBOM 与 VEX'
        : '未发现依赖文件，组件分析会受限',
      icon: PackageCheck,
    },
    {
      label: '构建入口',
      ok: record.summary.ciFiles.length > 0,
      description: record.summary.ciFiles.length
        ? '可以检查 workflow 与 runner'
        : '未发现 CI 文件，可稍后补充',
      icon: Workflow,
    },
    {
      label: '案例证据',
      ok: Boolean(presetKey),
      description: presetKey
        ? '已带入产物证明和日志线索'
        : '自定义项目可继续补充产物和日志',
      icon: ShieldCheck,
    },
  ]
}

function scanFunnelItems(record: ProjectImportRecord) {
  return [
    { label: '总文件', value: record.summary.fileStats.total, detail: '项目目录中发现的全部文件' },
    { label: '可扫描文件', value: record.summary.fileStats.scannable, detail: '可进入静态分析和规则扫描' },
    { label: '依赖入口', value: record.summary.dependencyFiles.length, detail: '用于生成 SBOM 与 VEX' },
    { label: 'CI/CD 入口', value: record.summary.ciFiles.length, detail: '用于检查构建链污染' },
  ]
}

function materialCoverageRows(record: ProjectImportRecord, hasPresetEvidence: boolean): CoverageRow[] {
  const hasDependencies = record.summary.dependencyFiles.length > 0
  const hasCi = record.summary.ciFiles.length > 0
  const hasCode = record.summary.fileStats.scannable > 0
  return [
    {
      name: '依赖材料',
      found: hasDependencies ? 'ready' : 'missing',
      usable: hasDependencies ? 'ready' : 'missing',
      gap: hasDependencies ? 'ready' : 'partial',
      note: hasDependencies ? '可生成 SBOM/VEX。' : '缺少依赖入口，组件风险可信度会下降。',
    },
    {
      name: 'CI/CD 材料',
      found: hasCi ? 'ready' : 'missing',
      usable: hasCi ? 'ready' : 'missing',
      gap: hasCi ? 'ready' : 'partial',
      note: hasCi ? '可检查 workflow、Action 与 runner。' : '缺少构建入口，构建链印证会受限。',
    },
    {
      name: '代码材料',
      found: hasCode ? 'ready' : 'missing',
      usable: hasCode ? 'ready' : 'partial',
      gap: hasCode ? 'ready' : 'partial',
      note: hasCode ? '可作为可达性佐证。' : '缺少可扫描代码，仅能做材料级判断。',
    },
    {
      name: '产物证明',
      found: hasPresetEvidence ? 'ready' : 'missing',
      usable: hasPresetEvidence ? 'ready' : 'partial',
      gap: hasPresetEvidence ? 'ready' : 'partial',
      note: hasPresetEvidence ? '案例已带入 artifact 与 attestation。' : '自定义项目可稍后上传产物和证明。',
    },
    {
      name: '运行日志',
      found: hasPresetEvidence ? 'ready' : 'missing',
      usable: hasPresetEvidence ? 'ready' : 'partial',
      gap: hasPresetEvidence ? 'ready' : 'partial',
      note: hasPresetEvidence ? '案例已带入运行期日志线索。' : '可稍后上传日志印证真实触发。',
    },
  ]
}

function keyFilePurposes(record: ProjectImportRecord, presetKey: DemoPresetKey | null): KeyFilePurpose[] {
  const dependencyFiles = record.summary.dependencyFiles.map((file) => ({
    file,
    type: '依赖入口',
    purpose: dependencyPurpose(file),
    icon: PackageCheck,
  }))
  const ciFiles = record.summary.ciFiles.map((file) => ({
    file,
    type: 'CI/CD 入口',
    purpose: '检查 workflow、Action 版本、runner 和发布链路。',
    icon: Workflow,
  }))
  const preset = presetKey ? demoPresets[presetKey] : null
  const presetFiles: KeyFilePurpose[] = preset
    ? [
        {
          file: preset.artifactPath,
          type: '产物样本',
          purpose: '用于计算 digest 并验证发布物是否可信。',
          icon: FileText,
        },
        {
          file: preset.attestationPath,
          type: '产物证明',
          purpose: '用于核对 SLSA provenance、commit、workflow 和 builder。',
          icon: ShieldCheck,
        },
        ...preset.logPaths.map((file) => ({
          file,
          type: '运行日志',
          purpose: '用于印证风险是否在运行期真实触发。',
          icon: FileCode2,
        })),
      ]
    : []
  return [...dependencyFiles, ...ciFiles, ...presetFiles].slice(0, 14)
}

function dependencyPurpose(file: string) {
  const lower = file.toLowerCase()
  if (lower.includes('lock')) return '生成精确 SBOM，确认实际安装版本。'
  if (lower.includes('requirements')) return '识别 Python 依赖面和版本约束。'
  if (lower.includes('package')) return '识别 npm 依赖、脚本和潜在混淆风险。'
  return '识别依赖生态、版本和供应链风险入口。'
}

function missingMaterials(record: ProjectImportRecord, hasPresetEvidence: boolean) {
  const items: string[] = []
  if (!record.summary.dependencyFiles.length) items.push('缺少依赖文件，SBOM 可信度会下降')
  if (!record.summary.ciFiles.length) items.push('缺少 CI 文件，构建链印证会受限')
  if (!record.summary.languages.length) items.push('缺少语言识别结果，代码侧佐证会受限')
  if (!hasPresetEvidence) items.push('缺少产物证明和日志，可稍后补充')
  return items.length ? items : ['核心预检材料已具备，可进入供应链风险发现']
}

function sourceLabel(record: ProjectImportRecord) {
  if (record.sourceType === 'git') {
    const ref = record.sourceRef.ref ? ` · ${record.sourceRef.ref}` : ''
    return `${record.sourceRef.url ?? ''}${ref}`
  }
  if (record.sourceType === 'upload') return String(record.sourceRef.filename ?? '')
  return String(record.sourceRef.path ?? record.sourcePath ?? '')
}

function sourceTypeLabel(type: ProjectImportRecord['sourceType']) {
  if (type === 'git') return 'Git 仓库'
  if (type === 'upload') return '压缩包'
  return '本地目录'
}

function formatNumber(value: number) {
  return new Intl.NumberFormat('zh-CN').format(value)
}
