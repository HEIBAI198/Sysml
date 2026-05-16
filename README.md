# 基于 SysML 模型的文档自动生成系统

本项目是一个课程设计级 MBSE 原型，用于演示如何以 SysML 风格模型作为单一可信源，自动生成一致、可追溯的工程文档。系统围绕 MMS、VE、MDK、DocGen 四个组件组织，实现“模型一次编辑，文档处处复用”的闭环。

## 核心功能

- `MMS` 模型管理：项目、分支、元素 CRUD、提交快照、标签、差异比较、回滚、合并、审计日志。
- `VE` 视图编辑器：浏览器内查看和编辑 SysML 元素，展示需求图、结构图、行为图和追踪矩阵。
- `MDK` 工具集成：提供可复用 Python 客户端、命令行入口、Cameo XMI、Jupyter Notebook 和 MATLAB 分析脚本适配器。
- `DocGen` 文档生成：按模板生成 Markdown、HTML、PDF，并写入模型指纹、来源分支、来源提交和追踪矩阵。
- 权限控制：演示用户分为 `admin`、`author`、`reader`，并结合项目 `roles` 做读写控制。

## 快速运行

```powershell
pip install -r requirements.txt
python server.py --host 127.0.0.1 --port 8000
```

打开：

```text
http://127.0.0.1:8000
```

OpenAPI 文档：

```text
http://127.0.0.1:8000/docs
```

演示账号：

| 用户 | 密码 | 角色 |
| --- | --- | --- |
| `teacher` | `teacher123` | admin |
| `engineer` | `engineer123` | author |
| `reviewer` | `reviewer123` | reader |

## 典型流程

1. 使用 `engineer / engineer123` 登录 VE。
2. 在“模型仓库”中创建或修改 Requirement、Block、Interface、Port、Constraint、Activity、State、TestCase。
3. 在“图形建模”中查看关系图，或添加 `satisfy`、`verify`、`refine`、`connect` 等关系。
4. 点击“保存快照”，将当前模型提交到 MMS。
5. 在“追踪矩阵”和“SysML 语义校验”中检查需求闭环。
6. 在”文档生成”中编辑 DocGen 模板并生成 HTML、Markdown、PDF、Word (DOCX)。
7. 使用导出或 `tools/mdk_sync.py` 与外部工具交换 JSON/XMI 模型。

## MDK 命令行示例

```powershell
python tools/mdk_sync.py parse --file data/import_example.json --tool json
python tools/mdk_sync.py push --file data/import_example.json --tool json --commit --validate
python tools/mdk_sync.py push --file mdk/jupyter/example_analysis.ipynb --tool jupyter --commit --validate
python tools/mdk_sync.py push --file mdk/matlab/example_analysis.m --tool matlab --commit --validate
python tools/mdk_sync.py pull --format json --out data/exported_model.json
python tools/mdk_sync.py pull --format xmi --out data/exported_model.xmi
python tools/mdk_sync.py generate --format pdf --out data/generated_document.pdf
python tools/mdk_sync.py generate --format docx --out data/generated_document.docx
```

更多外部工具集成方式见 [docs/mdk.md](docs/mdk.md)。

## DocGen 模板标记

| 标记 | 作用 |
| --- | --- |
| `{{element:REQ-001.name}}` | 引用指定模型元素字段 |
| `{{element:REQ-001.attributes.text}}` | 引用元素扩展属性 |
| `{{model:summary}}` | 生成模型统计摘要 |
| `{{table:requirements}}` | 生成需求表 |
| `{{table:blocks}}` | 生成结构块表 |
| `{{table:interfaces}}` | 生成接口与端口表 |
| `{{table:constraints}}` | 生成约束表 |
| `{{table:tests}}` | 生成验证表 |
| `{{trace:matrix}}` | 生成需求追踪矩阵 |
| `{{validation:issues}}` | 生成语义校验结果 |

## 目录说明

```text
server.py                  FastAPI 启动入口
sysml_docgen/app.py        REST API：MMS / VE / MDK / DocGen
sysml_docgen/store.py      SQLite 模型仓库、版本和审计
sysml_docgen/metamodel.py  SysML 元模型、校验和图数据
sysml_docgen/docgen.py     模板渲染、追踪矩阵和文档输出（基于 Pandoc）
sysml_docgen/mdk.py        MDK 客户端和工具适配器
sysml_docgen/xmi.py        JSON/XMI 交换
static/                    Web VE
tools/mdk_sync.py          MDK 风格同步客户端
mdk/jupyter/               Jupyter 集成 helper 和示例
mdk/matlab/                MATLAB 集成函数和示例
data/sample_project.json   卫星电源系统示例模型
outputs/                   运行时生成的文档输出
tests/                     单元测试与接口测试
```

## 测试

```powershell
python -B -m unittest discover -s tests
```

## Docker

```powershell
docker compose up --build
```

Docker Compose 使用 MongoDB 存储；本地直接运行默认使用 SQLite。可通过以下环境变量调整：

```text
SYSML_STORAGE=sqlite|mongodb
SYSML_OUTPUT_DIR=outputs
SYSML_FRONTEND_DIST=static
SYSML_MAX_MODEL_BYTES=10485760
SYSML_PANDOC_PATH=           # 可选，Pandoc 路径
SYSML_PDF_ENGINE=pandoc|wkhtmltopdf|builtin-fallback
SYSML_DOCX_REFERENCE=        # 可选，Word 参考模板 .docx
```

PDF 生成默认支持内置 fallback，不依赖系统安装 `wkhtmltopdf`。如果运行环境中存在 `wkhtmltopdf`，系统会自动优先使用它。

### 提升输出质量（推荐）

安装 [Pandoc](https://pandoc.org/) 可显著提升 HTML/PDF/Word 输出质量（参考 [Quarto](https://quarto.org/) 的技术架构）：

```powershell
# Windows (推荐方式)
winget install pandoc

# 或使用 Chocolatey
choco install pandoc

# 高质量 PDF 引擎（可选，三选一）
pip install weasyprint              # 轻量 HTML/CSS → PDF
winget install MiKTeX.MiKTeX       # LaTeX → PDF（功能最强）
winget install wkhtmltopdf          # WebKit → PDF
```

安装 Pandoc 后，系统将自动启用：
- **HTML**：语法高亮、智能排版、更丰富的 CSS（斑马纹表格、响应式、打印优化）
- **PDF**：多引擎支持（WeasyPrint / LaTeX / wkhtmltopdf）
- **Word (DOCX)**：新增格式，支持参考模板自定义样式（`SYSML_DOCX_REFERENCE`）
