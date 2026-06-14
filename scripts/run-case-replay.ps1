param(
  [ValidateSet('solarwinds', '3cx', 'all')]
  [string]$Case = 'all',
  [string]$BaseUrl = 'http://127.0.0.1:8000'
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Invoke-JsonPost {
  param(
    [string]$Uri,
    [object]$Body
  )
  Invoke-RestMethod -Method Post -Uri $Uri -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 20)
}

function Save-Json {
  param(
    [object]$Value,
    [string]$Path
  )
  [System.IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 80), [System.Text.UTF8Encoding]::new($false))
}

function Invoke-LogUpload {
  param(
    [string]$Uri,
    [System.IO.FileInfo[]]$Files,
    [string]$WorkspaceId = ''
  )
  Add-Type -AssemblyName System.Net.Http
  $client = [System.Net.Http.HttpClient]::new()
  $content = [System.Net.Http.MultipartFormDataContent]::new()
  $streams = @()
  try {
    foreach ($file in $Files) {
      $stream = [System.IO.File]::OpenRead($file.FullName)
      $streams += $stream
      $fileContent = [System.Net.Http.StreamContent]::new($stream)
      $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('text/plain')
      $content.Add($fileContent, 'files', $file.Name)
    }
    if ($WorkspaceId) {
      $content.Add([System.Net.Http.StringContent]::new($WorkspaceId), 'workspaceId')
    }
    $response = $client.PostAsync($Uri, $content).GetAwaiter().GetResult()
    $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    if (-not $response.IsSuccessStatusCode) {
      throw "Log upload failed: $($response.StatusCode) $body"
    }
    return $body | ConvertFrom-Json
  } finally {
    foreach ($stream in $streams) {
      $stream.Dispose()
    }
    $content.Dispose()
    $client.Dispose()
  }
}

function Join-TopTitles {
  param(
    [object[]]$Items,
    [int]$Limit = 6
  )
  $titles = @()
  foreach ($item in @($Items)) {
    if ($null -eq $item) {
      continue
    }
    $title = $item.PSObject.Properties['title'].Value
    $ruleId = $item.PSObject.Properties['rule_id'].Value
    if ($title) {
      $titles += "- $title"
    } elseif ($ruleId) {
      $titles += "- $ruleId"
    }
  }
  if (-not $titles.Count) {
    return "- 暂无"
  }
  return ($titles | Select-Object -First $Limit) -join "`n"
}

function Get-JsonValue {
  param(
    [object]$Object,
    [string[]]$Path,
    [object]$Default = '-'
  )
  $current = $Object
  foreach ($segment in $Path) {
    if ($null -eq $current) {
      return $Default
    }
    $property = $current.PSObject.Properties[$segment]
    if ($null -eq $property) {
      return $Default
    }
    $current = $property.Value
  }
  if ($null -eq $current) {
    return $Default
  }
  return $current
}

function Write-CaseSummary {
  param(
    [string]$CaseKey,
    [hashtable]$Config,
    [object]$Dependency,
    [object]$Cicd,
    [object]$Trust,
    [object]$Logs,
    [object]$Workspace,
    [string]$Path
  )

  $depTitles = Join-TopTitles -Items @($Dependency.findings)
  $cicdTitles = Join-TopTitles -Items @($Cicd.findings)
  $trustTitles = Join-TopTitles -Items @($Trust.findings)
  $logTitles = Join-TopTitles -Items @($Logs.findings)
  $projectName = [string]$Config.ProjectName
  $attackPathCount = Get-JsonValue -Object $Workspace -Path @('summary', 'attack_paths') -Default 0
  $riskScore = Get-JsonValue -Object $Workspace -Path @('summary', 'risk_score') -Default '-'
  $riskLevel = Get-JsonValue -Object $Workspace -Path @('summary', 'risk_level') -Default '-'
  $depFindingCount = Get-JsonValue -Object $Dependency -Path @('summary', 'finding_count') -Default 0
  $cicdFindingCount = Get-JsonValue -Object $Cicd -Path @('summary', 'finding_count') -Default 0
  $trustFindingCount = Get-JsonValue -Object $Trust -Path @('summary', 'finding_count') -Default 0
  $logFindingCount = Get-JsonValue -Object $Logs -Path @('summary', 'finding_count') -Default 0

  $content = @"
# $projectName 案例复现摘要

## 结论

本案例为防御性安全仿真，未包含真实恶意代码。SupplyGuard KG 已完成组件、CI/CD、产物可信和日志证据扫描，并生成工作台图谱与溯源报告。

- 综合风险：$riskLevel / $riskScore
- 依赖风险：$depFindingCount
- CI/CD 风险：$cicdFindingCount
- 产物可信风险：$trustFindingCount
- 日志风险：$logFindingCount
- 攻击路径：$attackPathCount

## 关键发现

### 供应链组件

$depTitles

### CI/CD 构建链

$cicdTitles

### 产物可信

$trustTitles

### 日志印证

$logTitles

## 页面查看

打开 http://127.0.0.1:8000 ，重点查看：

- 溯源总览
- 供应链组件
- CI/CD 构建链
- 产物可信
- 日志印证
- 攻击路径图谱
- 溯源报告

"@
  [System.IO.File]::WriteAllText($Path, $content, [System.Text.UTF8Encoding]::new($false))
}

function New-TarGzArtifact {
  param(
    [string]$CaseDir,
    [string]$Name
  )
  $artifactPath = Join-Path $CaseDir "artifacts\$Name"
  $payloadPath = Join-Path $CaseDir 'artifacts\payload.txt'
  [System.IO.File]::WriteAllText($payloadPath, "SIMULATION ONLY artifact for $Name generated at $(Get-Date -Format o)", [System.Text.UTF8Encoding]::new($false))
  if (Test-Path $artifactPath) {
    Remove-Item -LiteralPath $artifactPath -Force
  }
  tar -czf $artifactPath -C (Join-Path $CaseDir 'artifacts') payload.txt
  Remove-Item -LiteralPath $payloadPath -Force
  return $artifactPath
}

function Write-Attestation {
  param(
    [string]$Path,
    [string]$SubjectName,
    [string]$ClaimedSha,
    [string]$Repo,
    [string]$Ref,
    [string]$Workflow,
    [string]$Commit,
    [string]$Runner,
    [string]$Builder,
    [string]$InvocationId
  )
  $statement = [ordered]@{
    '_type' = 'https://in-toto.io/Statement/v1'
    subject = @(
      [ordered]@{
        name = $SubjectName
        digest = [ordered]@{ sha256 = $ClaimedSha }
      }
    )
    predicateType = 'https://slsa.dev/provenance/v1'
    predicate = [ordered]@{
      buildDefinition = [ordered]@{
        buildType = 'https://github.com/actions/runner/github-hosted'
        externalParameters = [ordered]@{
          workflow = [ordered]@{
            repository = $Repo
            ref = $Ref
            path = $Workflow
          }
          event_name = 'push'
        }
        internalParameters = [ordered]@{
          github = [ordered]@{
            repository = $Repo.Replace('https://github.com/', '')
            workflow_ref = "$($Repo.Replace('https://github.com/', ''))/$Workflow@$Ref"
            sha = $Commit
            runner_environment = $Runner
          }
        }
      }
      runDetails = [ordered]@{
        builder = [ordered]@{ id = $Builder }
        metadata = [ordered]@{
          invocationId = $InvocationId
          startedOn = '2026-06-11T10:00:00Z'
          finishedOn = '2026-06-11T10:04:00Z'
        }
      }
    }
  }
  [System.IO.File]::WriteAllText($Path, ($statement | ConvertTo-Json -Depth 30 -Compress), [System.Text.UTF8Encoding]::new($false))
}

function Invoke-CaseReplay {
  param(
    [string]$CaseKey
  )

  $caseMap = @{
    solarwinds = @{
      Dir = 'cases\solarwinds-sunburst'
      ProjectName = 'SolarWinds SUNBURST replay'
      Artifact = 'orion-update.tar.gz'
      Attestation = 'orion-update.intoto.jsonl'
      Repo = 'https://github.com/solarwinds/orion-platform'
      ExpectedRepo = 'https://github.com/solarwinds/orion-platform'
      Workflow = '.github/workflows/release.yml'
      Commit = '1111111111111111111111111111111111111111'
      ExpectedCommit = '8f42c19'
      Runner = 'github-hosted'
      Builder = 'https://github.com/actions/runner'
      Invocation = 'github-actions/orion-release-20260611'
    }
    '3cx' = @{
      Dir = 'cases\3cx-supply-chain'
      ProjectName = '3CX X_TRADER replay'
      Artifact = '3cx-desktop-app.tar.gz'
      Attestation = '3cx-desktop-app.intoto.jsonl'
      Repo = 'https://github.com/3cx/desktop-app'
      ExpectedRepo = 'https://github.com/3cx/desktop-app'
      Workflow = '.github/workflows/desktop-release.yml'
      Commit = '2222222222222222222222222222222222222222'
      ExpectedCommit = '8f42c19'
      Runner = 'self-hosted'
      Builder = 'https://github.com/actions/runner/self-hosted'
      Invocation = 'github-actions/desktop-release-20260611'
    }
  }

  $cfg = $caseMap[$CaseKey]
  $caseDir = Join-Path $RepoRoot $cfg.Dir
  $sampleRepo = Join-Path $caseDir 'sample-repo'
  $resultsDir = Join-Path $caseDir 'results'
  New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null

  Write-Host "==> Replaying $CaseKey"

  $artifactPath = New-TarGzArtifact -CaseDir $caseDir -Name $cfg.Artifact
  $attestationPath = Join-Path $caseDir "artifacts\$($cfg.Attestation)"
  Write-Attestation `
    -Path $attestationPath `
    -SubjectName $cfg.Artifact `
    -ClaimedSha '0000000000000000000000000000000000000000000000000000000000000000' `
    -Repo $cfg.Repo `
    -Ref 'refs/heads/main' `
    -Workflow $cfg.Workflow `
    -Commit $cfg.Commit `
    -Runner $cfg.Runner `
    -Builder $cfg.Builder `
    -InvocationId $cfg.Invocation

  $import = Invoke-JsonPost "$BaseUrl/api/imports/local" @{
    path = $sampleRepo
    projectName = $cfg.ProjectName
  }
  Save-Json $import (Join-Path $resultsDir '01-import.json')

  $importId = $import.importId
  $scan = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/imports/$importId/scan" -ContentType 'application/json' -Body (@{ scope = '.' } | ConvertTo-Json)
  Save-Json $scan (Join-Path $resultsDir '02-scan-job.json')

  $workspace = Invoke-JsonPost "$BaseUrl/api/security/workspaces" @{
    importId = $importId
    preset = $CaseKey
    name = $cfg.ProjectName
  }
  $workspaceId = $workspace.workspaceId
  if (-not $workspaceId) {
    throw "Workspace creation failed: workspaceId was not returned."
  }

  $code = Invoke-JsonPost "$BaseUrl/api/security/code-audit/scan" @{ importId = $importId; workspaceId = $workspaceId; timeoutSeconds = 180 }
  Save-Json $code (Join-Path $resultsDir '03-code-audit.json')

  $logFiles = @(Get-ChildItem -LiteralPath (Join-Path $caseDir 'logs') -File)
  $logs = Invoke-LogUpload "$BaseUrl/api/security/logs/scan" $logFiles $workspaceId
  Save-Json $logs (Join-Path $resultsDir '07-logs.json')

  $runtimeLogPaths = @($logFiles | ForEach-Object { $_.FullName })
  $dep = Invoke-JsonPost "$BaseUrl/api/security/dependencies/scan" @{
    importId = $importId
    workspaceId = $workspaceId
    runtimeLogPaths = $runtimeLogPaths
    includeOsv = $true
    includeCdxgen = $false
    includeCyclonedxPy = $false
    mode = 'auto'
  }
  Save-Json $dep (Join-Path $resultsDir '04-dependencies.json')

  $cicd = Invoke-JsonPost "$BaseUrl/api/security/cicd/scan" @{ importId = $importId; workspaceId = $workspaceId; includeZizmor = $false; includeActionlint = $false }
  Save-Json $cicd (Join-Path $resultsDir '05-cicd.json')

  $trust = Invoke-JsonPost "$BaseUrl/api/security/artifact-trust/scan" @{
    workspaceId = $workspaceId
    artifactPath = $artifactPath
    attestationPath = $attestationPath
    expectedRepo = $cfg.ExpectedRepo
    expectedCommit = $cfg.ExpectedCommit
    allowedBranches = @('refs/heads/main')
    allowedWorkflows = @($cfg.Workflow)
    allowedBuilders = @('https://github.com/actions/runner')
    requireSignature = $false
    requireProvenance = $true
    allowSelfHostedRunner = $false
    maxAgeHours = 8760
  }
  Save-Json $trust (Join-Path $resultsDir '06-artifact-trust.json')

  $workspace = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/security/workspaces/$workspaceId"
  Save-Json $workspace (Join-Path $resultsDir '08-workspace.json')

  $report = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/security/workspaces/$workspaceId/report"
  [System.IO.File]::WriteAllText((Join-Path $resultsDir 'report.md'), $report.content, [System.Text.UTF8Encoding]::new($false))
  Write-CaseSummary `
    -CaseKey $CaseKey `
    -Config $cfg `
    -Dependency $dep `
    -Cicd $cicd `
    -Trust $trust `
    -Logs $logs `
    -Workspace $workspace `
    -Path (Join-Path $resultsDir 'case-summary.md')

  Write-Host "Done: $CaseKey results -> $resultsDir"
}

try {
  Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/ready" | Out-Null
} catch {
  throw "SupplyGuard backend is not ready at $BaseUrl. Start it with: python server.py --host 127.0.0.1 --port 8000"
}

$targets = if ($Case -eq 'all') { @('solarwinds', '3cx') } else { @($Case) }
foreach ($target in $targets) {
  Invoke-CaseReplay -CaseKey $target
}

Write-Host "Replay complete. Open $BaseUrl and review overview / attack graph / report."
