import { useEffect, useState } from 'react'
import {
  AlertTriangle,
  Archive,
  CheckCircle2,
  FolderOpen,
  GitBranch,
  Loader2,
  Play,
  ShieldCheck,
  Upload,
} from 'lucide-react'
import { useNavigate } from '@tanstack/react-router'
import { toast } from 'sonner'
import {
  checkImportApiReady,
  importGitProject,
  importLocalProject,
  uploadProjectArchive,
} from '@/lib/import-api'
import { cn } from '@/lib/utils'
import { demoPresets, type DemoPresetKey } from './demo-presets'
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
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Header } from '@/components/layout/header'
import { Main } from '@/components/layout/main'
import { Search } from '@/components/search'
import { ThemeSwitch } from '@/components/theme-switch'

type BusyState = DemoPresetKey | 'upload' | 'git' | 'local' | null

export function ProjectImportPage() {
  const navigate = useNavigate()
  const [apiReady, setApiReady] = useState<boolean | null>(null)
  const [apiError, setApiError] = useState('')
  const [busy, setBusy] = useState<BusyState>(null)
  const [archive, setArchive] = useState<File | null>(null)
  const [gitUrl, setGitUrl] = useState('')
  const [gitRef, setGitRef] = useState('')
  const [localPath, setLocalPath] = useState('')
  const [projectName, setProjectName] = useState('')

  useEffect(() => {
    let ignore = false
    checkImportApiReady()
      .then(() => {
        if (ignore) return
        setApiReady(true)
        setApiError('')
      })
      .catch((error) => {
        if (ignore) return
        setApiReady(false)
        setApiError(error instanceof Error ? error.message : '后端服务不可用')
      })
    return () => {
      ignore = true
    }
  }, [])

  async function importDemo(presetKey: DemoPresetKey) {
    const preset = demoPresets[presetKey]
    setBusy(presetKey)
    try {
      await importLocalProject({
        path: preset.localPath,
        projectName: preset.projectName,
      })
      toast.success('案例已选择，预检资产已生成')
      void navigate({ to: '/project-preflight' })
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '案例导入失败')
    } finally {
      setBusy(null)
    }
  }

  async function importArchive() {
    if (!archive) {
      toast.error('请选择 .zip、.tar.gz 或 .tgz 文件')
      return
    }
    setBusy('upload')
    try {
      await uploadProjectArchive(archive)
      toast.success('压缩包已导入，预检资产已生成')
      void navigate({ to: '/project-preflight' })
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '压缩包导入失败')
    } finally {
      setBusy(null)
    }
  }

  async function importGit() {
    if (!gitUrl.trim()) {
      toast.error('请输入 Git 仓库地址')
      return
    }
    setBusy('git')
    try {
      await importGitProject({
        url: gitUrl.trim(),
        ref: gitRef.trim() || undefined,
        projectName: projectName.trim() || undefined,
      })
      toast.success('Git 仓库已导入，预检资产已生成')
      void navigate({ to: '/project-preflight' })
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Git 仓库导入失败')
    } finally {
      setBusy(null)
    }
  }

  async function importLocal() {
    if (!localPath.trim()) {
      toast.error('请输入服务端可访问的本地目录')
      return
    }
    setBusy('local')
    try {
      await importLocalProject({
        path: localPath.trim(),
        projectName: projectName.trim() || undefined,
      })
      toast.success('本地目录已导入，预检资产已生成')
      void navigate({ to: '/project-preflight' })
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '本地目录导入失败')
    } finally {
      setBusy(null)
    }
  }

  const disabled = busy !== null || apiReady === false

  return (
    <div className='min-h-svh bg-background'>
      <Header fixed>
        <div className='flex min-w-0 flex-1 items-center justify-between gap-4'>
          <div className='min-w-0'>
            <div className='truncate text-sm font-semibold'>选择调查对象</div>
            <div className='truncate text-xs text-muted-foreground'>
              第 1 步 · 选择案例或代码项目
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
            Step 1 · Case Selection
          </Badge>
          <h1 className='text-2xl font-semibold tracking-normal sm:text-3xl'>
            选择要调查的项目
          </h1>
          <p className='max-w-3xl text-sm leading-6 text-muted-foreground'>
            这一步只做一件事：确定本次供应链溯源的调查对象。选择后系统会立即完成资产预检，并进入第 2 步查看材料体检结果。
          </p>
        </div>

        {apiReady === false ? (
          <Alert variant='destructive' className='rounded-md'>
            <AlertTriangle className='size-4' />
            <AlertTitle>后端服务未连接</AlertTitle>
            <AlertDescription>
              请先启动 FastAPI 后端。当前错误：{apiError}
            </AlertDescription>
          </Alert>
        ) : null}

        <section className='grid gap-4 xl:grid-cols-3'>
          {(Object.entries(demoPresets) as Array<[DemoPresetKey, (typeof demoPresets)[DemoPresetKey]]>).map(([key, preset]) => (
            <Card
              key={key}
              className={cn(
                'rounded-md transition hover:border-cyan-300 hover:shadow-sm',
                busy === key && 'border-cyan-300 bg-cyan-50/60 dark:bg-cyan-950/20'
              )}
            >
              <CardHeader>
                <div className='flex items-start justify-between gap-3'>
                  <div className='grid size-11 place-items-center rounded-md bg-cyan-50 text-cyan-700 dark:bg-cyan-950 dark:text-cyan-300'>
                    <ShieldCheck className='size-5' />
                  </div>
                  <Badge variant='outline' className='rounded-md border-emerald-200 bg-emerald-50 text-emerald-700'>
                    防御性仿真
                  </Badge>
                </div>
                <CardTitle className='text-lg'>{preset.label}</CardTitle>
                <CardDescription className='min-h-10'>{preset.description}</CardDescription>
              </CardHeader>
              <CardContent>
                <Button className='w-full' onClick={() => void importDemo(key)} disabled={disabled}>
                  {busy === key ? <Loader2 className='animate-spin' /> : <Play />}
                  选择并预检
                </Button>
              </CardContent>
            </Card>
          ))}

          <Card className='rounded-md transition hover:border-cyan-300 hover:shadow-sm xl:col-span-1'>
            <CardHeader>
              <div className='grid size-11 place-items-center rounded-md bg-slate-100 text-slate-700 dark:bg-slate-900 dark:text-slate-200'>
                <FolderOpen className='size-5' />
              </div>
              <CardTitle className='text-lg'>自定义项目</CardTitle>
              <CardDescription>
                支持压缩包、Git 仓库或服务端本地目录，适合比赛自带样例和真实项目预检。
              </CardDescription>
            </CardHeader>
            <CardContent className='space-y-4'>
              <div className='space-y-2'>
                <Label htmlFor='project-name'>项目名称</Label>
                <Input
                  id='project-name'
                  value={projectName}
                  onChange={(event) => setProjectName(event.target.value)}
                  placeholder='可选，留空则自动识别'
                />
              </div>

              <div className='rounded-md border p-3'>
                <div className='mb-2 flex items-center gap-2 text-sm font-medium'>
                  <Archive className='size-4 text-cyan-600' />
                  压缩包
                </div>
                <Input
                  type='file'
                  accept='.zip,.tar,.tar.gz,.tgz,application/zip,application/gzip'
                  onChange={(event) => setArchive(event.target.files?.[0] ?? null)}
                />
                <Button
                  variant='outline'
                  className='mt-3 w-full'
                  onClick={() => void importArchive()}
                  disabled={disabled}
                >
                  {busy === 'upload' ? <Loader2 className='animate-spin' /> : <Upload />}
                  上传并预检
                </Button>
              </div>

              <div className='rounded-md border p-3'>
                <div className='mb-2 flex items-center gap-2 text-sm font-medium'>
                  <GitBranch className='size-4 text-cyan-600' />
                  Git 仓库
                </div>
                <div className='grid gap-2'>
                  <Input
                    value={gitUrl}
                    onChange={(event) => setGitUrl(event.target.value)}
                    placeholder='https://github.com/org/repo.git'
                  />
                  <Input
                    value={gitRef}
                    onChange={(event) => setGitRef(event.target.value)}
                    placeholder='分支 / Tag，可选'
                  />
                </div>
                <Button
                  variant='outline'
                  className='mt-3 w-full'
                  onClick={() => void importGit()}
                  disabled={disabled}
                >
                  {busy === 'git' ? <Loader2 className='animate-spin' /> : <GitBranch />}
                  拉取并预检
                </Button>
              </div>

              <div className='rounded-md border p-3'>
                <div className='mb-2 flex items-center gap-2 text-sm font-medium'>
                  <FolderOpen className='size-4 text-cyan-600' />
                  本地目录
                </div>
                <Input
                  value={localPath}
                  onChange={(event) => setLocalPath(event.target.value)}
                  placeholder='C:/Users/86189/Desktop/my-project'
                />
                <Button
                  variant='outline'
                  className='mt-3 w-full'
                  onClick={() => void importLocal()}
                  disabled={disabled}
                >
                  {busy === 'local' ? <Loader2 className='animate-spin' /> : <FolderOpen />}
                  导入并预检
                </Button>
              </div>
            </CardContent>
          </Card>
        </section>

        <Alert className='rounded-md border-cyan-200 bg-cyan-50 text-cyan-900 dark:border-cyan-900 dark:bg-cyan-950/30 dark:text-cyan-100'>
          <CheckCircle2 className='size-4' />
          <AlertTitle>当前页面只负责选对象</AlertTitle>
          <AlertDescription>
            选择完成后会进入独立的“预检资产”页面，那里会展示文件、语言、依赖、CI 文件、缺失材料和下一步建议。
          </AlertDescription>
        </Alert>
      </Main>
    </div>
  )
}
