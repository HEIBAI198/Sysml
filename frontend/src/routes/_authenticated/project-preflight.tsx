import { createFileRoute } from '@tanstack/react-router'
import { ProjectPreflightPage } from '@/features/project-preflight'

export const Route = createFileRoute('/_authenticated/project-preflight')({
  component: ProjectPreflightPage,
})
