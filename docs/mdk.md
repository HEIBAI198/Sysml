# MDK 集成说明

MDK（Model Development Kit）的目标不是单纯读取文件，而是让工程师在真实工具中工作时，把模型或分析结果同步到 MMS。当前项目提供三层能力：

- 共享客户端：`sysml_docgen.mdk.MdkClient` 负责调用 MMS REST API。
- 命令行适配：`tools/mdk_sync.py` 用于 JSON、XMI、Notebook、MATLAB 文件的导入导出。
- 工具内接入：`mdk/jupyter/sysml_docgen_notebook.py` 提供 Jupyter Notebook 内的同步 API 和 IPython magic。

## Jupyter 真接入

Jupyter 接入不是在外部运行演示脚本，而是在 Notebook 单元格里直接同步模型元素。演示闭环如下：

1. 启动 SysML DocGen 服务。

```powershell
pip install -e .[jupyter]
python server.py --host 127.0.0.1 --port 8000
```

2. 在另一个终端启动 Jupyter。

```powershell
jupyter notebook
```

3. 在 Notebook 第一格加载 MDK 扩展并连接 MMS。

```python
%load_ext mdk.jupyter.sysml_docgen_notebook
%sysml_config --server http://127.0.0.1:8000 --project satellite-power --branch main --user engineer
%sysml_health
```

4. 在 Notebook 中新建或修改一个需求，然后执行单元格。

```python
%%sysml_requirement REQ-JUP-010 "电池能量余量需求" --owner 分析组 --satisfy BLK-BATTERY
电池在最大负载工况下，SOC 应保持不低于 30%。
```

执行后，扩展会把这个需求转换成 SysML 元素，并调用 `/api/mdk/push` 写入 MMS。

5. 再同步一个仿真测试用例。

```python
%%sysml_test TST-JUP-010 "SOC 最坏工况仿真" --owner 分析组 --criterion "SOC_min >= 30%" --verifies REQ-JUP-010
使用 Notebook 运行能量平衡仿真，检查最坏工况下 SOC 最小值。
```

6. 在 Notebook 或网页端验证变化。

```python
%sysml_validate
```

然后打开：

```text
http://127.0.0.1:8000
```

在 VE 中查看元素列表、追溯矩阵和文档生成结果。此时 Notebook 中修改过的需求文本会反映到系统里。

## Jupyter Python API

如果不想使用 magic，也可以用普通 Python 函数，这更适合把仿真结果变量写入模型。

```python
from mdk.jupyter.sysml_docgen_notebook import configure, requirement, test_case

configure(project="satellite-power", branch="main", username="engineer")

soc_min = 0.32
requirement(
    "REQ-JUP-011",
    "Notebook 仿真派生需求",
    f"仿真结果显示 SOC 最小值为 {soc_min:.0%}，系统应保持不低于 30%。",
    owner="分析组",
    relations=[{"type": "satisfy", "target": "BLK-BATTERY"}],
)

test_case(
    "TST-JUP-011",
    "Notebook SOC 仿真",
    method="Python energy balance simulation",
    criterion="SOC_min >= 30%",
    verifies="REQ-JUP-011",
)
```

这种方式体现了“工具内集成”：分析人员在 Jupyter 中得到结果后，直接把结果同步为 MMS 中的 Requirement 或 TestCase。

## 命令行适配

命令行仍然保留，用于批量导入、调试和没有插件环境时的备用流程。

```powershell
python tools/mdk_sync.py parse --file mdk/jupyter/example_analysis.ipynb --tool jupyter
python tools/mdk_sync.py push --file mdk/jupyter/example_analysis.ipynb --tool jupyter --commit --validate
python tools/mdk_sync.py pull --format json --out data/exported_model.json
python tools/mdk_sync.py generate --format html --out outputs/from-mdk.html
```

## MATLAB

MATLAB 当前提供 `mdk/matlab/sysml_docgen_sync.m`，可在 MATLAB 内部通过 `webwrite` 调用 MMS。

```matlab
elements = struct("id", "REQ-MAT-003", "name", "MATLAB 同步需求", "type", "Requirement");
sysml_docgen_sync(elements);
```

## Cameo

Cameo/MagicDraw 的完整深度集成需要 Java 插件和 Cameo OpenAPI。当前仓库提供：

- `mdk/cameo-plugin/`：Java 插件 scaffold。
- XMI 同步流程：从 Cameo 导出 XMI 后，通过 `tools/mdk_sync.py push --tool cameo` 导入 MMS。

如果课程需要继续深化 Cameo，可在插件中增加“Sync to MMS”菜单按钮，并监听模型保存事件，把 Cameo 元素转换成 `/api/mdk/push` 所需的 JSON/XMI。
