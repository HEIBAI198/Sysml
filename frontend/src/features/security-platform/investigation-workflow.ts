export const platformTabs = [
  'overview',
  'supply',
  'pipeline',
  'artifact',
  'logs',
  'graph',
  'report',
  'code',
  'multimodal',
  'copilot',
] as const

export type PlatformTab = (typeof platformTabs)[number]

export type InvestigationStepId =
  | 'case'
  | 'preflight'
  | 'risk'
  | 'corroboration'
  | 'path'
  | 'report'

export type InvestigationStepChild = {
  id: string
  title: string
  description: string
  target: PlatformTab | 'project-import-select' | 'project-preflight'
}

export type InvestigationStep = {
  id: InvestigationStepId
  order: number
  title: string
  shortTitle: string
  description: string
  defaultTarget: InvestigationStepChild['target']
  children: InvestigationStepChild[]
}

export const investigationSteps: InvestigationStep[] = [
  {
    id: 'case',
    order: 1,
    title: '选择案例',
    shortTitle: '案例',
    description: '选择比赛案例、Git 仓库、本地目录或压缩包',
    defaultTarget: 'project-import-select',
    children: [
      {
        id: 'case-entry',
        title: '选择调查对象',
        description: '确定本次供应链溯源要调查哪个项目',
        target: 'project-import-select',
      },
    ],
  },
  {
    id: 'preflight',
    order: 2,
    title: '预检资产',
    shortTitle: '预检',
    description: '查看项目材料体检结果，确认依赖、CI 文件和扫描范围',
    defaultTarget: 'project-preflight',
    children: [
      {
        id: 'preflight-report',
        title: '资产预检报告',
        description: '展示文件、语言、依赖、CI 入口、缺失材料和下一步建议',
        target: 'project-preflight',
      },
    ],
  },
  {
    id: 'risk',
    order: 3,
    title: '发现供应链风险',
    shortTitle: '风险',
    description: '生成 SBOM/VEX，定位异常依赖和混淆信号',
    defaultTarget: 'supply',
    children: [
      {
        id: 'supply-risk-discovery',
        title: '供应链风险发现',
        description: '统一查看依赖清单、SBOM/VEX、选中依赖详情和处置建议',
        target: 'supply',
      },
      {
        id: 'reachability',
        title: '可达性佐证',
        description: '用代码路径辅助判断风险是否可触达',
        target: 'code',
      },
    ],
  },
  {
    id: 'corroboration',
    order: 4,
    title: '证据印证',
    shortTitle: '印证',
    description: '用构建链、产物可信、运行日志和外部告警交叉验证',
    defaultTarget: 'pipeline',
    children: [
      {
        id: 'pipeline',
        title: 'CI/CD 构建链',
        description: '检查 workflow、Action、runner 和构建步骤',
        target: 'pipeline',
      },
      {
        id: 'artifact',
        title: '产物可信',
        description: '验证 digest、provenance、commit 和 builder',
        target: 'artifact',
      },
      {
        id: 'logs',
        title: '日志印证',
        description: '确认运行期异常外联和敏感接口访问',
        target: 'logs',
      },
      {
        id: 'external-alerts',
        title: '外部告警证据',
        description: '接入截图、语音、视频和告警文本',
        target: 'multimodal',
      },
    ],
  },
  {
    id: 'path',
    order: 5,
    title: '生成攻击路径',
    shortTitle: '路径',
    description: '把证据串成污染入口、传播环节和受影响资产',
    defaultTarget: 'graph',
    children: [
      {
        id: 'attack-chain-map',
        title: '攻击链地图',
        description: '用可读链路串联入口、传播、印证和影响资产',
        target: 'graph',
      },
      {
        id: 'agent',
        title: '供应链溯源 Agent',
        description: '自动研判路径、缺口和处置动作',
        target: 'copilot',
      },
    ],
  },
  {
    id: 'report',
    order: 6,
    title: '导出报告',
    shortTitle: '报告',
    description: '交付溯源结论、证据包和答辩讲解',
    defaultTarget: 'report',
    children: [],
  },
]

export const workspaceTabTitles: Record<PlatformTab, string> = {
  overview: '调查总览',
  supply: '供应链风险发现',
  pipeline: 'CI/CD 构建链',
  artifact: '产物可信',
  logs: '日志印证',
  graph: '攻击链地图',
  report: '溯源报告',
  code: '可达性佐证',
  multimodal: '外部告警证据',
  copilot: '供应链溯源 Agent',
}

export const workspaceTabStepIds: Record<PlatformTab, InvestigationStepId> = {
  overview: 'risk',
  supply: 'risk',
  pipeline: 'corroboration',
  artifact: 'corroboration',
  logs: 'corroboration',
  graph: 'path',
  report: 'report',
  code: 'risk',
  multimodal: 'corroboration',
  copilot: 'path',
}

export function isPlatformTab(value: string): value is PlatformTab {
  return platformTabs.includes(value as PlatformTab)
}

export function normalizeWorkbenchHash(hash: string): PlatformTab {
  const value = hash.replace(/^#/, '')
  return isPlatformTab(value) ? value : 'overview'
}
