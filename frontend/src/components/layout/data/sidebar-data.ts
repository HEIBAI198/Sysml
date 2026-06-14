import {
  Bot,
  ClipboardList,
  FileArchive,
  FileSearch,
  FileText,
  FolderOpen,
  Network,
  Radar,
  Route,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Workflow,
} from 'lucide-react'
import { type SidebarData } from '../types'

export const sidebarData: SidebarData = {
  user: {
    name: 'security-analyst',
    email: 'soc / appsec',
    avatar: '',
  },
  teams: [
    {
      name: 'SupplyGuard KG',
      logo: ShieldAlert,
      plan: 'LLM + Knowledge Graph',
    },
    {
      name: 'Security Operations',
      logo: Radar,
      plan: 'Code / SBOM / Logs',
    },
    {
      name: 'Evidence Graph',
      logo: Network,
      plan: 'Attack Path / Report',
    },
  ],
  navGroups: [
    {
      title: 'APT 供应链溯源流程',
      items: [
        {
          title: '1 选择案例',
          url: '/project-import',
          icon: FolderOpen,
          badge: '入口',
        },
        {
          title: '2 预检资产',
          url: '/project-preflight',
          icon: ScanSearch,
          badge: '材料',
        },
        {
          title: '3 发现供应链风险',
          icon: Radar,
          badge: '风险',
          items: [
            {
              title: '供应链风险发现',
              url: '/#supply',
              icon: FileSearch,
            },
            {
              title: '可达性佐证',
              url: '/#code',
              icon: Route,
            },
          ],
        },
        {
          title: '4 证据印证',
          icon: ShieldCheck,
          badge: '印证',
          items: [
            {
              title: 'CI/CD 构建链',
              url: '/#pipeline',
              icon: Workflow,
            },
            {
              title: '产物可信',
              url: '/#artifact',
              icon: ShieldCheck,
            },
            {
              title: '日志印证',
              url: '/#logs',
              icon: FileText,
            },
            {
              title: '外部告警证据',
              url: '/#multimodal',
              icon: FileSearch,
            },
          ],
        },
        {
          title: '5 生成攻击路径',
          icon: Network,
          badge: '路径',
          items: [
            {
              title: '攻击链地图',
              url: '/#graph',
              icon: Network,
            },
            {
              title: '供应链溯源 Agent',
              url: '/#copilot',
              icon: Bot,
            },
          ],
        },
        {
          title: '6 导出报告',
          icon: FileText,
          badge: '交付',
          items: [
            {
              title: '溯源报告',
              url: '/#report',
              icon: FileText,
            },
            {
              title: '证据包',
              url: '/#report',
              icon: FileArchive,
            },
            {
              title: '答辩讲解',
              url: '/#report',
              icon: ClipboardList,
            },
          ],
        },
      ],
    },
  ],
}
