import {
  Archive,
  BookOpenText,
  Boxes,
  Braces,
  ChartNoAxesCombined,
  FileText,
  LayoutDashboard,
  Network,
  NotebookTabs,
  ShieldCheck,
  Waypoints,
  Workflow,
} from 'lucide-react'
import { type SidebarData } from '../types'

export const sidebarData: SidebarData = {
  user: {
    name: 'engineer',
    email: 'engineer / author',
    avatar: '',
  },
  teams: [
    {
      name: 'SysML DocGen',
      logo: Braces,
      plan: 'MMS / VE / MDK / DocGen',
    },
    {
      name: 'Satellite Power',
      logo: Boxes,
      plan: 'Sample project',
    },
    {
      name: 'FastAPI Backend',
      logo: Archive,
      plan: 'Local API',
    },
  ],
  navGroups: [
    {
      title: 'Workbench',
      items: [
        {
          title: '总览工作台',
          url: '/',
          icon: LayoutDashboard,
        },
        {
          title: '工程流程',
          icon: Workflow,
          items: [
            {
              title: 'MMS 模型库',
              url: '/',
              icon: Boxes,
            },
            {
              title: 'VE 图谱视图',
              url: '/',
              icon: Network,
            },
            {
              title: 'DocGen 文档',
              url: '/',
              icon: FileText,
            },
          ],
        },
      ],
    },
    {
      title: 'Reference',
      items: [
        {
          title: '接口与文档',
          icon: ShieldCheck,
          items: [
            {
              title: 'OpenAPI',
              url: '/docs',
              icon: NotebookTabs,
            },
            {
              title: 'API 文档',
              url: '/api.md',
              icon: BookOpenText,
            },
            {
              title: 'MDK 指南',
              url: '/mdk.md',
              icon: Waypoints,
            },
          ],
        },
        {
          title: '示例页面',
          icon: ChartNoAxesCombined,
          items: [
            {
              title: '任务模板',
              url: '/tasks',
            },
            {
              title: '用户模板',
              url: '/users',
            },
            {
              title: '应用模板',
              url: '/apps',
            },
          ],
        },
      ],
    },
  ],
}
