# 后端分层重构记录

## 一、重构背景

随着功能持续增加，后端核心逻辑逐渐集中在几个较大的文件中：

- `sysml_docgen/app.py`
- `sysml_docgen/store.py`
- `sysml_docgen/docgen.py`

这种结构带来的问题主要有：

1. 路由、业务逻辑、数据访问、文档生成耦合度较高
2. 单个文件过大，阅读和维护成本上升
3. 后续新增功能时容易继续往单体文件中堆积
4. 测试、扩展和替换底层实现的难度较大

因此，本次重构的目标不是改变外部行为，而是在尽量保持现有接口稳定的前提下，对后端进行分层整理。

## 二、重构目标

本次重构的目标是将后端逐步拆分为以下几层：

- `web-api`
- `mms-core`
- `docgen-service`
- `integration-service`
- `repository`
- `document-engine`

这样做的目的是让不同职责分别落到独立模块中，避免继续将能力堆叠到单一入口文件中。

## 三、已完成的内容

### 1. Web API 层

原来集中在单个入口文件中的路由已经拆分到独立模块中：

- `sysml_docgen/api/routes/system.py`
- `sysml_docgen/api/routes/mms.py`
- `sysml_docgen/api/routes/docgen.py`
- `sysml_docgen/api/routes/integration.py`

同时新增了统一依赖注入文件：

- `sysml_docgen/api/deps.py`

重构后，`sysml_docgen/app.py` 主要负责以下内容：

- 创建 FastAPI 应用
- 注册中间件
- 注册异常处理
- 组装并挂载各类路由
- 挂载前端静态资源

也就是说，`app.py` 已经从“既接请求又写业务”的大文件，转变为更纯粹的应用装配层。

### 2. Service 层

核心业务逻辑已经下沉到独立 service 模块：

- `sysml_docgen/services/system_service.py`
- `sysml_docgen/services/mms_service.py`
- `sysml_docgen/services/docgen_service.py`
- `sysml_docgen/services/integration_service.py`

职责划分如下：

- `system_service`
  - 健康检查
  - ready 检查
  - metrics 输出
  - 登录辅助逻辑

- `mms_service`
  - 项目管理
  - 分支管理
  - 提交管理
  - 元素 CRUD
  - diff / rollback / tag / audit
  - diagram / traceability

- `docgen_service`
  - 文档生成
  - HTML / Markdown / PDF / DOCX 输出封装
  - DocGen 配置读取

- `integration_service`
  - MDK 对接
  - JSON / XMI 导入导出
  - 外部模型解析与同步

这一步完成后，路由层负责“接收请求并调用 service”，而不再直接承担大量业务逻辑。

### 3. Repository 层

新增了 `repository` 包结构：

- `sysml_docgen/repository/base.py`
- `sysml_docgen/repository/factory.py`
- `sysml_docgen/repository/sqlite_store.py`
- `sysml_docgen/repository/mongo_store.py`
- `sysml_docgen/repository/__init__.py`

这表示后端已经开始从“单文件存储层”过渡到“包结构存储层”。

同时，为了兼容现有导入方式，保留了兼容入口：

- `sysml_docgen/repository.py`
- `sysml_docgen/store.py`

这样可以在不破坏现有使用方式的情况下，逐步把存储实现迁移到新的目录结构中。

### 4. Repository Contract

新增了仓储协议文件：

- `sysml_docgen/repository_contract.py`

它的作用是让 service 层依赖“仓储能力接口”，而不是直接依赖某一个具体的存储实现类。

这样做的意义在于：

- 更容易替换 SQLite / MongoDB 实现
- 更容易做 mock 测试
- 更符合后续继续拆层的方向

### 5. 文档引擎模块化

`docgen.py` 已经开始拆分为多个内部子模块：

- `sysml_docgen/document_engine/utils.py`
- `sysml_docgen/document_engine/docx_builtin.py`
- `sysml_docgen/document_engine/template.py`
- `sysml_docgen/document_engine/traceability.py`

当前已拆出的职责包括：

- `utils.py`
  - 时间戳
  - 稳定哈希计算

- `docx_builtin.py`
  - 内建 DOCX 生成逻辑
  - DOCX 打包和表格/段落处理辅助函数

- `template.py`
  - 模板渲染
  - 模型摘要生成
  - Markdown 表格生成
  - 默认文档模板

- `traceability.py`
  - 追踪矩阵生成
  - 追踪状态计算
  - 校验结果 Markdown 输出

目前 `sysml_docgen/docgen.py` 仍保留为对外兼容门面，因此现有代码仍可继续通过原有导入方式调用文档生成相关函数。

## 四、运行时影响

本次重构的原则是：**尽量不改变现有外部行为**。

因此，运行时预期保持不变：

- 现有 HTTP 路由仍然可用
- 前端页面行为不变
- 文档生成能力不变
- SQLite / MongoDB 选择逻辑保持兼容

用户侧不会明显感知到“新界面”或“新按钮”，变化主要体现在后端结构上：

- 更容易定位代码
- 更容易扩展模块
- 更容易继续拆分大型文件
- 更容易维护和测试

## 五、测试验证

本次重构完成后，使用现有测试集进行了回归验证：

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests
```

测试结果：

- `28 tests, OK`

说明当前分层重构在保持原有功能的同时，没有破坏现有测试覆盖到的行为。

## 六、当前仍保留的兼容入口

为了确保重构过程稳定推进，以下文件仍然作为兼容入口保留：

- `sysml_docgen/store.py`
- `sysml_docgen/repository.py`
- `sysml_docgen/docgen.py`

这些文件的作用是：

1. 维持现有导入路径稳定
2. 让新结构逐步接管旧实现
3. 避免一次性激进拆分导致系统不稳定

也就是说，虽然系统已经完成了核心分层，但仍然保留了少量 façade 文件作为过渡层。

## 七、后续可继续推进的方向

后续如果继续优化，可以重点推进以下几件事：

1. 继续将 `docgen.py` 中剩余的 PDF / HTML 渲染逻辑拆到独立子模块
2. 继续将 `store.py` 中的 SQLite 实现逐步迁移到 `repository` 包内部
3. 增加架构图和模块依赖说明文档
4. 补充更细粒度的单元测试，覆盖各 service 和 repository 子模块

## 八、总结

本次重构已经完成了后端分层建议中的核心目标：

- `web-api`
- `mms-core`
- `docgen-service`
- `integration-service`
- `repository`

并且已经开始将文档引擎从大文件拆分为多个内部模块。

整体上，这次重构把后端从“继续往单体堆功能”的方向，推进到了“按职责分层、按模块组织”的方向，同时保持了现有系统的可运行性与测试通过状态。
