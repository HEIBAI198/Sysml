# APT 供应链防御复盘案例

本目录存放 SupplyGuard KG 的防御性复盘案例，用于支撑比赛命题
`APT 供应链攻击检测与溯源系统` 的演示、评测和答辩讲解。

这些案例不包含真实恶意代码、真实漏洞利用载荷或可连接的攻击基础设施。所有脚本、域名和 IP 均为安全模拟数据，目标是验证系统在供应链风险检测、证据融合、知识图谱溯源和报告生成方面的能力。

## 案例列表

| 案例 | 公开参考 | 模拟重点 |
| --- | --- | --- |
| `solarwinds-sunburst` | CISA SolarWinds 通报、MITRE C0024 | 构建/更新链污染、产物可信异常、运行期外联印证 |
| `3cx-supply-chain` | Mandiant 3CX 报告、MITRE C0057 | X_TRADER 到 3CX 的级联供应链风险、桌面端产物异常、终端外联印证 |

## 一键复盘

先启动后端：

```powershell
python server.py --host 127.0.0.1 --port 8000
```

运行单个案例：

```powershell
.\scripts\run-case-replay.ps1 -Case solarwinds
.\scripts\run-case-replay.ps1 -Case 3cx
```

运行全部案例：

```powershell
.\scripts\run-case-replay.ps1 -Case all
```

脚本会把各模块 JSON 扫描结果、案例摘要和 Markdown 溯源报告写入对应案例的 `results/` 目录。

## 手动界面复盘

打开：

```text
http://127.0.0.1:8000/project-import
```

导入以下本地目录之一：

```text
cases/solarwinds-sunburst/sample-repo
cases/3cx-supply-chain/sample-repo
```

然后重点查看：

- 溯源总览
- 供应链组件
- CI/CD 构建链
- 产物可信
- 日志印证
- 攻击路径图谱
- 溯源报告

产物可信和日志模块需要配合使用对应案例的 `artifacts/` 和 `logs/` 目录。

## 安全边界

- 域名使用 `example.invalid` 或文档示例域名，不连接真实攻击基础设施。
- IP 地址使用测试网段或安全模拟指标，仅用于检测规则验证。
- payload 文件均为文本占位内容，不包含真实恶意功能。
- 可疑脚本只输出模拟行为，用于验证检测和溯源链路。
- 案例目标是防御性检测、证据融合和路径解释，不复现入侵行为。
