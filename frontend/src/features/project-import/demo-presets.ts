export type DemoPresetKey = '3cx' | 'solarwinds'

export type DemoPreset = {
  label: string
  description: string
  projectName: string
  localPath: string
  artifactPath: string
  attestationPath: string
  expectedRepo: string
  expectedCommit: string
  allowedWorkflows: string[]
  allowedBuilders: string[]
  logPaths: string[]
  allowSelfHostedRunner: boolean
}

export const demoPresets: Record<DemoPresetKey, DemoPreset> = {
  '3cx': {
    label: '3CX X_TRADER replay',
    description: '演示依赖包、构建链、产物可信和运行期外联如何互相印证。',
    projectName: '3CX X_TRADER replay',
    localPath: 'cases/3cx-supply-chain/sample-repo',
    artifactPath: 'cases/3cx-supply-chain/artifacts/3cx-desktop-app.tar.gz',
    attestationPath: 'cases/3cx-supply-chain/artifacts/3cx-desktop-app.intoto.jsonl',
    expectedRepo: 'https://github.com/3cx/desktop-app',
    expectedCommit: '8f42c19',
    allowedWorkflows: ['.github/workflows/desktop-release.yml'],
    allowedBuilders: ['https://github.com/actions/runner'],
    logPaths: [
      'cases/3cx-supply-chain/logs/build-runner.jsonl',
      'cases/3cx-supply-chain/logs/customer-endpoint.jsonl',
    ],
    allowSelfHostedRunner: false,
  },
  solarwinds: {
    label: 'SolarWinds SUNBURST replay',
    description: '演示构建/更新链污染、产物来源异常和运行期外联证据。',
    projectName: 'SolarWinds SUNBURST replay',
    localPath: 'cases/solarwinds-sunburst/sample-repo',
    artifactPath: 'cases/solarwinds-sunburst/artifacts/orion-update.tar.gz',
    attestationPath: 'cases/solarwinds-sunburst/artifacts/orion-update.intoto.jsonl',
    expectedRepo: 'https://github.com/solarwinds/orion-platform',
    expectedCommit: '8f42c19',
    allowedWorkflows: ['.github/workflows/release.yml'],
    allowedBuilders: ['https://github.com/actions/runner'],
    logPaths: [
      'cases/solarwinds-sunburst/logs/build-runner.jsonl',
      'cases/solarwinds-sunburst/logs/orion-runtime.jsonl',
    ],
    allowSelfHostedRunner: false,
  },
}

export function presetKeyFromProject(projectName?: string, sourcePath?: string) {
  const value = `${projectName || ''} ${sourcePath || ''}`.toLowerCase()
  if (value.includes('3cx') || value.includes('x_trader')) return '3cx'
  if (value.includes('solarwinds') || value.includes('sunburst')) return 'solarwinds'
  return null
}
