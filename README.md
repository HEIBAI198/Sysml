# SupplyGuard KG

大模型与安全知识图谱驱动的软件供应链攻击检测平台。项目把代码审计、依赖/SBOM 风险、CI/CD 构建链路、产物可信验证、运行日志、多模态证据、知识图谱和安全 Copilot 放在同一个工作台里，用一条可追溯证据链解释“风险从哪里来、影响到哪里、应该先修什么”。

## 项目定位

SupplyGuard KG 面向软件供应链安全和应用安全运营场景，目标不是只输出单点漏洞列表，而是把多源安全信号归一化为资产、证据、发现和攻击路径：

- 代码层：发现 SQL 拼接、命令执行、硬编码密钥、基础设施配置风险等问题。
- 依赖层：生成 CycloneDX SBOM，识别漏洞依赖、依赖混淆、typosquatting、安装脚本、许可证和版本锁定风险。
- 构建层：扫描 GitHub Actions 工作流中的未固定 Action、过宽权限、远程脚本、明文凭据和可疑下载。
- 产物层：校验 artifact SHA256、in-toto/SLSA provenance、builder、workflow、commit、runner、签名和策略。
- 运行层：分析 access/auth/app 日志，发现敏感接口访问、异常外联、暴力破解、SQL 注入探测等行为。
- 证据层：接入截图、音频、视频帧等多模态材料，通过 OCR/ASR 抽取 IP、CVE、包名、服务名、API 路径等安全实体。
- 图谱层：把仓库、提交、依赖包、构建任务、产物、服务、日志事件和攻击阶段串成攻击路径。
- 助手层：DeepSeek 在线大模型或离线 RAG 演示助手，基于工作台上下文回答风险原因、误报判断和修复优先级。

## 比赛命题适配

本项目面向全国大学生信息安全作品赛命题 **APT 供应链攻击检测与溯源系统**。比赛版展示主线聚焦“案例/项目导入 → 组件异常 → CI/CD 构建链污染 → 产物可信异常 → 运行日志印证 → 知识图谱溯源 → 报告导出”，用于说明被污染环节、受影响资产和攻击路径。

| 赛题要求 | 系统对应能力 |
| --- | --- |
| 识别组件版本异常 | 依赖清单解析、lockfile 精确版本、CycloneDX SBOM、purl、许可证、版本来源和风险评分 |
| 识别依赖混淆 | 私有包名冲突、typosquatting、公共源高版本、install/postinstall 脚本和异常外联信号 |
| 识别构建环境篡改 | GitHub Actions 未固定 Action、过宽 permissions、远程脚本、可疑下载、明文凭据和构建链 SARIF |
| 识别产物污染 | artifact SHA256、in-toto/SLSA provenance、builder、workflow、commit、runner、签名和策略校验 |
| 还原攻击路径 | 将依赖、CI/CD、产物、日志、证据和攻击阶段写入知识图谱，输出污染入口、被污染环节、受影响资产和路径 verdict |
| 形成复现报告 | 自动生成 Markdown 报告，汇总风险等级、证据链、影响范围、攻击路径和修复建议 |

代码审计和多模态能力在比赛版中作为辅助证据保留：代码审计用于判断风险可达性和应用侧影响，多模态用于把外部告警截图、语音或视频帧转换成可关联证据；它们不替代供应链检测主链路。

## 技术栈

### 后端

- Python 3.10+
- FastAPI + Uvicorn
- Pydantic v2
- httpx
- PyYAML
- pymongo，可通过 Docker Compose 接 MongoDB 7
- NetworkX，用于图谱路径和风险关系建模
- 本地 `storage/` 文件存储，用于 SBOM、日志状态、上传产物、多模态证据和导入项目缓存

### 安全与分析工具接入

项目内置或适配了下面这些工具和数据模型：

| 类型 | 工具/模型 | 用途 |
| --- | --- | --- |
| 代码审计 | Semgrep CE | 自定义规则和通用代码风险扫描，输出统一 finding 和 SARIF |
| 代码审计 | Gitleaks | 密钥、Token、凭据泄露检测 |
| Python 安全 | Bandit | Python 代码安全检查 |
| IaC/配置 | Checkov | Dockerfile、Kubernetes、Terraform、CI 配置等风险检测 |
| CI/CD | GitHub Actions 静态规则 | 未固定 Action、过宽 permissions、远程脚本、危险凭据等 |
| CI/CD 可选 | zizmor、actionlint | 如果环境中已安装，会作为外部 GitHub Actions 扫描器补充结果 |
| 依赖/SBOM | CycloneDX | 生成 SBOM 和 VEX，统一组件、漏洞、可达性与降噪结果 |
| 依赖/SBOM 可选 | cdxgen、cyclonedx-py | 如果环境中已安装，可导入外部 SBOM 事实 |
| 漏洞数据可选 | OSV-Scanner | 如果环境中已安装，可关联 OSV 漏洞记录 |
| 产物可信 | in-toto / SLSA provenance | 校验 artifact subject digest、builder、workflow、commit、来源仓库等 |
| 产物验签可选 | GitHub CLI、cosign | 如果环境中已安装，可补充 attestation/signature 验证 |
| 日志管道可选 | Vector | `deploy/vector/supplyguard-vector.toml` 可把样例日志推送到实时日志接口 |
| 多模态 | OpenCV、imageio-ffmpeg | 图片预处理、视频帧抽取和媒体处理 |
| ASR | faster-whisper | 音频告警转写 |
| OCR | PaddleOCR，Tesseract 可选 | 截图、视频帧文字识别 |
| 大模型 | DeepSeek Chat Completions API | 安全 Copilot 在线分析；未配置密钥时自动回退到离线 RAG 演示回答 |
| 图谱参考 | GUAC、MITRE ATT&CK、BloodHound 风格路径 | 归一化供应链关系、攻击阶段和可操作路径展示 |
| 结果集成 | SARIF / GitHub Code Scanning | 代码审计和 CI/CD 审计结果可导出或上传到 GitHub Code Scanning |

Docker 镜像会自动安装 `semgrep`、`bandit`、`checkov` 和 `gitleaks`。其他外部扫描器属于可选增强，未安装时系统会降级运行，并在页面中显示工具状态。

## 功能模块

### 1. APT 溯源总览

默认首页是供应链攻击溯源总览，围绕污染入口、被污染环节、受影响资产、攻击路径、证据演进和优先处置建议组织展示。

访问入口：

```text
http://127.0.0.1:8000
```

### 2. 项目导入与预检

支持三种代码来源：

- 上传 `.zip`、`.tar`、`.tar.gz`、`.tgz` 压缩包
- 拉取 Git 仓库
- 读取服务端本地目录

导入后会进行预检：

- 识别项目名称
- 统计文件数量、可扫描文件、忽略文件、二进制文件
- 识别语言分布
- 检测依赖文件，如 `package.json`、`package-lock.json`、`requirements.txt`、`pyproject.toml`
- 检测 CI/CD 文件，如 `.github/workflows/*.yml`

页面入口：

```text
http://127.0.0.1:8000/project-import
```

### 3. 代码与应用安全审计

后端会调用 Semgrep、Gitleaks、Bandit、Checkov，并统一为：

- 风险等级与评分
- 文件位置和代码证据
- 修复建议
- scanner 状态
- baseline、ignore 和趋势
- SARIF 结果
- GitHub Code Scanning 上传结果

### 4. 供应链依赖检测

依赖扫描覆盖：

- npm 与 Python 依赖清单
- lockfile 精确版本
- transitive dependency
- purl
- license
- 本地漏洞建议库
- OSV 可选关联
- typosquatting 和依赖混淆启发式信号
- install/postinstall 脚本风险
- CycloneDX SBOM
- CycloneDX VEX
- 结合代码 import、调用证据、服务暴露面和运行日志做 VEX 降噪

### 5. CI/CD 构建链路监测

重点检查 GitHub Actions：

- 第三方 Action 未固定到 commit SHA
- `permissions: write-all` 或过宽写权限
- workflow 中的 curl/bash 远程脚本
- 明文 GitHub Token 或云凭据
- 可疑下载、构建产物发布和 release 链路
- SARIF 导出和 GitHub Code Scanning 上传

策略文件：

```text
.supplyguard/cicd.yml
```

### 6. 产物可信验证门

支持样例或上传 artifact + attestation 进行验证：

- artifact SHA256
- attestation subject digest
- SLSA provenance predicate
- 来源仓库
- commit/ref
- workflow
- builder id
- runner environment
- attestation 新鲜度
- 策略匹配
- 签名验证状态

策略文件：

```text
.supplyguard/trust-policy.yml
```

样例文件：

```text
storage/samples/artifacts/checkout-api.tar.gz
storage/samples/attestations/checkout-api.intoto.jsonl
```

### 7. 日志风险识别

支持上传日志文件，也支持实时 ingest：

- access log
- auth log
- app JSONL
- NDJSON

系统会识别：

- 敏感管理接口访问
- 敏感导出路径
- SQL 注入探测
- 暴力破解/401 峰值
- 异常外联 IP
- 拒绝响应突增

日志规则目录：

```text
supplyguard/rules/logs/
```

Vector 示例配置：

```text
deploy/vector/supplyguard-vector.toml
```

### 8. 多模态证据接入

支持上传音频、截图和视频材料：

- 音频通过 faster-whisper 转写
- 图片通过 PaddleOCR/Tesseract OCR
- 视频通过 FFmpeg/OpenCV 抽帧后识别
- 识别 IP、域名、CVE、依赖包、API 路径、服务名、行为关键词
- 通过规则命中形成多模态 finding
- 与代码、依赖、CI/CD、日志共同进入知识图谱

样例文件：

```text
storage/samples/multimodal/alert.wav
storage/samples/multimodal/cicd-error.png
storage/samples/multimodal/incident-alert.png
```

### 9. 安全知识图谱

系统把扫描结果统一为 `Asset / Evidence / Finding`，再构建图谱节点和边：

- CodeFile
- DependencyPackage
- Vulnerability
- CIWorkflow / CIStep
- BuildArtifact
- Attestation
- TrustedBuilder
- SourceCommit
- RuntimeService
- LogEvent
- MultimodalEvidence
- AttackStage
- Finding

图谱会给出攻击路径 verdict，例如：

- `likely-real-attack-path`
- `plausible-attack-path`
- `provenance-risk-path`
- `verified-provenance-chain`
- `cross-modal-corroborated-path`
- `insufficient-evidence`

### 10. 安全 Copilot

Copilot 会读取当前工作台上下文，回答：

- 这条攻击链先封堵哪里？
- 哪些证据证明不是误报？
- 这个依赖是否应该替换？
- 今天能做的修复动作有哪些？

配置了 DeepSeek API Key 时使用在线模型；没有配置时使用离线 RAG 演示回答，保证项目可以无外网密钥运行。

## 目录结构

```text
.
├── supplyguard/                 # FastAPI 后端与安全分析模块
│   ├── app.py                   # 应用入口与静态前端挂载
│   ├── code_audit.py            # Semgrep/Gitleaks/Bandit/Checkov 代码审计
│   ├── dependency_audit.py      # 依赖、SBOM、VEX、OSV 适配
│   ├── cicd_audit.py            # GitHub Actions 风险扫描
│   ├── artifact_trust.py        # artifact + in-toto/SLSA provenance 可信校验
│   ├── log_audit.py             # 日志批量扫描与实时 ingest
│   ├── multimodal_audit.py      # 音频/图片/视频证据识别
│   ├── knowledge_graph.py       # 统一事实层和知识图谱构建
│   ├── llm_assistant.py         # DeepSeek / 离线 RAG 安全助手
│   ├── project_imports.py       # 上传、Git、本地项目导入预检
│   ├── routes/                  # API 路由
│   └── rules/                   # Semgrep、日志、多模态规则
├── frontend/                    # React + Vite 前端
├── storage/                     # 样例、扫描结果、SBOM、日志、多模态证据、模型缓存
├── deploy/vector/               # Vector 日志接入示例
├── .supplyguard/                # CI/CD 和产物可信策略
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── pyproject.toml
└── server.py
```

## 环境要求

本地开发建议：

- Python 3.10 或更高版本，推荐 3.12
- Node.js 20 或更高版本，Dockerfile 使用 Node 24
- npm
- Git
- Windows、Linux、macOS 均可运行

可选工具：

- Docker Desktop，用于容器化部署
- Vector，用于日志实时接入演示
- GitHub CLI / cosign，用于增强 artifact attestation 验签
- OSV-Scanner、cdxgen、cyclonedx-py、zizmor、actionlint，用于增强扫描结果

## 配置环境变量

在项目根目录创建 `.env`：

```text
DEEPSEEK_API_KEY=你的 DeepSeek API Key
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-flash
DEEPSEEK_TIMEOUT_SECONDS=30

# 可选：上传 SARIF 到 GitHub Code Scanning 时使用
GITHUB_TOKEN=你的 GitHub token

# 可选：前端构建产物目录
SUPPLYGUARD_FRONTEND_DIST=frontend/dist

# 可选：项目导入工作目录
SUPPLYGUARD_IMPORT_WORKSPACE=storage/imports

# 可选：多模态模型参数
SUPPLYGUARD_WHISPER_MODEL=tiny
SUPPLYGUARD_WHISPER_DEVICE=cpu
SUPPLYGUARD_WHISPER_COMPUTE_TYPE=int8
SUPPLYGUARD_OCR_LANG=ch
SUPPLYGUARD_TESSERACT_LANG=chi_sim+eng
```

`DEEPSEEK_API_KEY` 不是必填项。未配置时，安全 Copilot 会使用内置离线回答。

## 本地安装与运行

### 1. 安装后端依赖

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

如果希望本地获得和 Docker 镜像相同的代码扫描能力，继续安装：

```powershell
python -m pip install semgrep bandit checkov
```

Windows 下 Gitleaks 可以单独下载安装，并确保 `gitleaks` 在 `PATH` 中。Docker 部署会自动安装 Gitleaks。

### 2. 安装前端依赖并构建

```powershell
cd frontend
npm install
npm run build
cd ..
```

### 3. 启动后端服务

```powershell
python server.py --host 127.0.0.1 --port 8000
```

启动后访问：

```text
http://127.0.0.1:8000
```

健康检查：

```text
http://127.0.0.1:8000/api/ready
http://127.0.0.1:8000/api/health
```

## 前后端分离开发

后端：

```powershell
python server.py --host 127.0.0.1 --port 8000 --reload
```

前端：

```powershell
cd frontend
npm run dev
```

Vite 默认会把 `/api` 代理到 `http://127.0.0.1:8000`。如果后端端口不同，可以设置：

```powershell
$env:VITE_SYSML_API_BASE="http://127.0.0.1:8002"
npm run dev
```

## Docker 部署

项目已经提供 Dockerfile 和 Docker Compose。Compose 会启动：

- `mongo`：MongoDB 7
- `api`：SupplyGuard KG 后端 + 已构建前端静态文件

启动：

```powershell
docker compose up --build
```

后台运行：

```powershell
docker compose up --build -d
```

停止：

```powershell
docker compose down
```

清理 MongoDB 数据卷：

```powershell
docker compose down -v
```

服务地址：

```text
http://127.0.0.1:8000
```

Docker 环境中默认配置：

```text
SYSML_STORAGE=mongodb
SYSML_MONGO_STRICT=true
MONGO_URL=mongodb://mongo:27017
SUPPLYGUARD_FRONTEND_DIST=/app/frontend/dist
```

## 常用 API

### 运行状态

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/ready` | 服务就绪检查 |
| GET | `/api/health` | 服务健康状态和模块列表 |

### 项目导入

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/imports/upload` | 上传项目压缩包 |
| POST | `/api/imports/git` | 导入 Git 仓库 |
| POST | `/api/imports/local` | 导入服务端本地目录 |
| GET | `/api/imports/latest` | 获取最近一次导入 |
| GET | `/api/imports/{import_id}/status` | 查询导入状态 |
| GET | `/api/imports/{import_id}/summary` | 查询导入预检摘要 |
| POST | `/api/imports/{import_id}/scan` | 创建扫描任务 |
| POST | `/api/scans` | 按 importId 创建扫描 |

### 安全工作台

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/security/workspace` | 获取完整安全态势、图谱、扫描结果和报告 |
| GET | `/api/security/report` | 获取 Markdown 安全报告 |
| POST | `/api/security/assistant` | 安全 Copilot 问答 |

### 代码审计

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/security/code-audit/scan` | 运行代码审计 |
| GET | `/api/security/code-audit/latest` | 获取最近一次结果 |
| GET | `/api/security/code-audit/report` | 获取 Markdown 报告 |
| GET | `/api/security/code-audit/sarif` | 获取 SARIF |
| GET | `/api/security/code-audit/state` | 获取 ignore、baseline、trend 状态 |
| POST | `/api/security/code-audit/ignore` | 忽略 finding |
| DELETE | `/api/security/code-audit/ignore/{fingerprint}` | 取消忽略 |
| POST | `/api/security/code-audit/baseline` | 创建 baseline |
| POST | `/api/security/code-audit/github/code-scanning` | 上传 SARIF 到 GitHub Code Scanning |
| POST | `/api/security/code-audit/github/code-scanning/status` | 查询 SARIF 上传状态 |

### 依赖与 SBOM

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/security/dependencies/scan` | 运行依赖扫描 |
| GET | `/api/security/dependencies/latest` | 获取最近一次结果 |
| GET | `/api/security/dependencies/sbom` | 获取 CycloneDX SBOM |
| GET | `/api/security/dependencies/vex` | 获取 CycloneDX VEX |
| GET | `/api/security/dependencies/report` | 获取 Markdown 报告 |

### CI/CD

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/security/cicd/scan` | 扫描 GitHub Actions workflow |
| GET | `/api/security/cicd/latest` | 获取最近一次结果 |
| GET | `/api/security/cicd/report` | 获取 Markdown 报告 |
| GET | `/api/security/cicd/sarif` | 获取 SARIF |
| GET | `/api/security/cicd/state` | 获取 ignore、baseline 状态 |
| POST | `/api/security/cicd/ignore` | 忽略 finding |
| DELETE | `/api/security/cicd/ignore/{fingerprint}` | 取消忽略 |
| POST | `/api/security/cicd/baseline` | 创建 baseline |
| POST | `/api/security/cicd/github/code-scanning` | 上传 CI/CD SARIF 到 GitHub Code Scanning |

### 产物可信

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/security/artifact-trust/scan` | 使用路径运行 artifact 可信验证 |
| POST | `/api/security/artifact-trust/upload` | 上传 artifact 和 attestation 验证 |
| GET | `/api/security/artifact-trust/latest` | 获取最近一次结果 |
| GET | `/api/security/artifact-trust/report` | 获取 Markdown 报告 |

### 日志识别

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/security/logs/scan` | 上传日志文件批量扫描 |
| GET | `/api/security/logs/latest` | 获取最近一次批量扫描 |
| GET | `/api/security/logs/report` | 获取 Markdown 报告 |
| POST | `/api/security/logs/ingest` | 实时写入 JSON/NDJSON 日志 |
| GET | `/api/security/logs/events` | 查看实时日志事件 |
| GET | `/api/security/logs/trend` | 查看实时日志趋势 |
| POST | `/api/security/logs/baseline` | 创建实时日志 baseline |
| POST | `/api/security/logs/ignore` | 忽略实时日志 finding |

### 多模态证据

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/security/multimodal/scan` | 上传音频、图片、视频证据 |
| POST | `/api/security/multimodal/analyze-text` | 直接分析 OCR/ASR 文本 |
| GET | `/api/security/multimodal/latest` | 获取最近多模态证据 |
| GET | `/api/security/multimodal/report` | 获取 Markdown 报告 |

## 示例操作

### 扫描当前工作区代码

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/api/security/code-audit/scan `
  -ContentType "application/json" `
  -Body '{"target_path":"."}'
```

### 运行依赖扫描并生成 SBOM/VEX

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/api/security/dependencies/scan `
  -ContentType "application/json" `
  -Body '{"targetPath":".","includeOsv":true,"mode":"auto"}'
```

### 扫描样例日志

```powershell
$files = Get-ChildItem storage/samples/logs/*.log
$form = @{ files = $files }
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/security/logs/scan -Form $form
```

### 使用 Vector 推送实时日志

先启动后端，再运行：

```powershell
vector --config deploy/vector/supplyguard-vector.toml
```

默认配置会读取：

```text
storage/samples/logs/*.log
storage/samples/logs/*.jsonl
```

并推送到：

```text
http://127.0.0.1:8011/api/security/logs/ingest
```

如果你的后端运行在 8000 端口，请把 `deploy/vector/supplyguard-vector.toml` 中的 `uri` 改为：

```text
http://127.0.0.1:8000/api/security/logs/ingest
```

## 测试与质量检查

前端测试：

```powershell
cd frontend
npm run test
```

前端 lint：

```powershell
cd frontend
npm run lint
```

前端格式化检查：

```powershell
cd frontend
npm run format:check
```

后端可以通过启动服务并访问 `/api/ready`、`/api/health`、`/api/security/workspace` 做基本验证。

## 项目亮点

- 多源证据链：把静态代码、依赖、CI/CD、产物、日志、多模态材料合并到同一个证据模型里。
- 攻击路径优先：不止展示漏洞列表，还会输出从依赖入口到构建、产物、服务、日志的路径判断。
- 可信产物门禁：内置 in-toto/SLSA provenance 校验，能解释 artifact 是否来自可信仓库、可信 workflow 和可信 builder。
- VEX 降噪：依赖风险不只看 CVE，还结合代码可达性、服务暴露面和运行日志，区分 affected、not affected、under investigation、fixed。
- 多模态安全证据：把告警音频、CI 截图、事故截图和视频帧纳入 OCR/ASR 识别，并与图谱证据互相印证。
- 可落地集成：支持 SARIF 导出、GitHub Code Scanning 上传、Vector 日志接入、Docker Compose 部署。
- 可演示也可扩展：没有外部密钥时能跑离线样例；安装外部扫描器和配置 DeepSeek 后可增强为更完整的安全分析平台。
- 工具状态透明：扫描器缺失或失败不会让整个平台不可用，页面会展示可用、降级、跳过或失败状态。
- 报告自动生成：每个模块和总工作台都能导出 Markdown 报告，包含风险摘要、证据链、影响范围和修复建议。

## 常见问题

### 前端访问 503

说明后端没有找到 `frontend/dist/index.html`。先构建前端：

```powershell
cd frontend
npm install
npm run build
cd ..
python server.py --host 127.0.0.1 --port 8000
```

### 安全 Copilot 显示离线 RAG

这是正常行为。配置 `DEEPSEEK_API_KEY` 后会调用 DeepSeek API；未配置时使用内置离线演示回答。

### 某些扫描器显示未安装

本地运行时需要自己安装对应 CLI。Docker 镜像已经包含 Semgrep、Bandit、Checkov 和 Gitleaks；OSV-Scanner、cdxgen、cyclonedx-py、zizmor、actionlint、cosign 等是可选增强。

### PaddleOCR 或 faster-whisper 安装慢

多模态依赖体积较大，首次安装会比较久。只体验代码、依赖、CI/CD、日志和图谱功能时，可以先用 Docker 镜像或已有虚拟环境运行。

### 本地上传 GitHub Code Scanning 失败

确认：

- 已配置 `GITHUB_TOKEN` 或在页面弹窗中填写 token
- token 有对应仓库的 code scanning/Security 写入权限
- 请求中的 owner、repo、ref、commit SHA 与仓库一致

## 后续可扩展方向

- 接入真实漏洞源同步任务，如 NVD、OSV、GitHub Advisory Database。
- 把图谱存储迁移到 Neo4j、NebulaGraph 或 GUAC 后端。
- 使用 Kafka、Vector、OpenSearch 替换本地日志文件存储。
- 接入 Trivy、Grype、Syft、Dependency-Track、DefectDojo 等企业安全工具。
- 加入认证、权限、租户隔离和审计日志，适配企业内部部署。
- 将扫描任务异步化，加入队列、worker、任务重试和历史结果管理。
