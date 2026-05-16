# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

基于 SysML 模型的文档自动生成系统（MBSE 课程设计原型）。核心理念："模型一次编辑，文档处处复用"。四个组件：**MMS**（模型管理/版本控制）、**VE**（Web 视图编辑器）、**MDK**（工具集成套件）、**DocGen**（文档生成引擎）。

## 常用命令

### 后端（Python/FastAPI）

```bash
# 安装依赖
pip install -r requirements.txt

# 启动开发服务器（SQLite 模式）
python server.py --host 127.0.0.1 --port 8000

# 启动开发服务器（热重载）
python server.py --host 127.0.0.1 --port 8000 --reload

# 运行所有测试
python -B -m unittest discover -s tests -v

# 运行单个测试文件
python -B -m unittest tests.test_docgen -v

# 编译检查（CI 中也会执行）
python -m py_compile server.py sysml_docgen/app.py sysml_docgen/auth.py sysml_docgen/config.py sysml_docgen/repository.py sysml_docgen/store.py sysml_docgen/docgen.py sysml_docgen/metamodel.py sysml_docgen/xmi.py tools/mdk_sync.py
```

### MDK 命令行

```bash
python tools/mdk_sync.py parse --file data/import_example.json --tool json
python tools/mdk_sync.py push --file data/import_example.json --tool json --commit --validate
python tools/mdk_sync.py push --file mdk/jupyter/example_analysis.ipynb --tool jupyter --commit --validate
python tools/mdk_sync.py push --file mdk/matlab/example_analysis.m --tool matlab --commit --validate
python tools/mdk_sync.py pull --format json --out data/exported_model.json
python tools/mdk_sync.py pull --format xmi --out data/exported_model.xmi
python tools/mdk_sync.py generate --format pdf --out data/generated_document.pdf
```

### 前端（React/Vite）

```bash
cd frontend
pnpm install
pnpm dev              # 启动 Vite 开发服务器
pnpm build            # TypeScript 编译 + Vite 构建
pnpm test             # Vitest 单元测试
pnpm lint             # ESLint 检查
pnpm format           # Prettier 格式化
```

### Docker

```bash
docker compose up --build    # MongoDB 模式启动
docker build -t sysml-docgen:ci .   # 仅构建镜像
```

## 架构要点

### 数据流

```
Cameo/Jupyter/MATLAB --(MDK)--> MMS (SQLite/MongoDB) --(REST API)--> VE (React前端)
                                                       |
                                                  DocGen --> HTML/MD/PDF
```

### 后端模块依赖

- `sysml_docgen/app.py` — FastAPI 应用入口，注册所有路由（MMS/VE/MDK/DocGen），CORS、权限中间件、错误处理
- `sysml_docgen/store.py` — 核心数据层。`ModelStore` 封装 SQLite，管理 projects/branches/elements/commits/tags/audit_log。`MongoModelStore` 实现相同接口用于 Docker 部署
- `sysml_docgen/metamodel.py` — SysML 元模型定义（9 种元素类型、关系规则、中文标签）、模型校验、图数据生成
- `sysml_docgen/docgen.py` — 模板引擎（`{{token:expression}}` 语法）、追踪矩阵生成、HTML/MD/PDF 输出
- `sysml_docgen/auth.py` — HMAC-SHA256 token 认证，三个演示用户（teacher/admin, engineer/author, reviewer/reader）
- `sysml_docgen/xmi.py` — JSON ↔ XMI 格式双向转换
- `sysml_docgen/mdk.py` — MDK 客户端：解析 Jupyter/JSON/XMI/MATLAB 文件，push/pull 到 MMS
- `sysml_docgen/repository.py` — `create_model_store()` 工厂，根据 `SYSML_STORAGE` 选择后端
- `sysml_docgen/config.py` — 环境变量驱动的路径和限制配置

### 前端架构

- `frontend/src/features/sysml-workbench/index.tsx` — 核心 MBSE 工作台（93KB），集成 ReactFlow 图编辑
- `frontend/src/features/sysml-workbench/docgen-template-editor.tsx` — Monaco 编辑器的 DocGen 模板编辑
- 路由使用 TanStack Router（文件系统路由，`routeTree.gen.ts` 自动生成）
- 状态管理：Zustand（全局状态）+ TanStack React Query（服务端状态）
- UI 组件：shadcn/ui（Radix + Tailwind CSS v4）

### 存储后端切换

- 本地开发默认 SQLite（`data/store.sqlite3`），自动从 `data/sample_project.json` 初始化
- Docker Compose 使用 MongoDB：设置 `SYSML_STORAGE=mongodb` + `SYSML_MONGO_STRICT=true`
- `ModelStore` 和 `MongoModelStore` 实现相同接口，`create_model_store()` 负责选择

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SYSML_STORAGE` | `sqlite` | `sqlite` 或 `mongodb` |
| `SYSML_OUTPUT_DIR` | `outputs/` | DocGen 输出目录 |
| `SYSML_FRONTEND_DIST` | `frontend/dist` | React 构建产物路径 |
| `SYSML_MAX_MODEL_BYTES` | `10485760` | 模型导入大小上限 |
| `MONGO_URL` | `mongodb://127.0.0.1:27017` | MongoDB 连接串 |
| `SYSML_PDF_ENGINE` | `builtin-fallback` | PDF 引擎 |

### 元模型核心概念

9 种 SysML 元素类型：Requirement, Block, Activity, Interface, Port, Constraint, State, TestCase, View。每种有 `stereotype`、`attributes`、`relations`。关系类型：satisfy, verify, refine, compose, expose, connect, allocate, flow, transition, constrain。中文标签和校验规则定义在 `metamodel.py`。

### 认证机制

演示系统用 HMAC-SHA256 签名 token（8 小时过期）。也支持简化头 `X-User` / `X-Role`。生产使用需替换 `auth.py` 中的硬编码密钥和用户。

### 前端静态文件服务

后端自动检测：如果 `frontend/dist/index.html` 存在则服务 React SPA，否则回退到 `static/`（传统 VE）。因此部署前需先 `cd frontend && pnpm build`。
