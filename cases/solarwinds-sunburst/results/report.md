# SolarWinds / SUNBURST 供应链攻击防御复盘报告

生成时间：2026-06-12 03:10:04 UTC

## 风险总览

- 综合风险评分：100 / 100
- 综合风险等级：critical
- 图谱节点数量：165
- 图谱边数量：257
- 归一化资产：174 个
- 证据数量：315 条
- 发现数量：580 条
- 攻击路径数量：4 条
- 平均路径置信度：74%
- 主要路径判定：`cross-modal-corroborated-path`、`likely-real-attack-path`、`provenance-risk-path`

## 案例结论

系统将组件版本异常、依赖安装脚本信号、CI/CD 构建链风险、产物 provenance 不匹配和运行期日志证据串联为可解释的供应链风险路径。该案例用于演示防御性检测与溯源，不包含真实攻击代码。

## 关键攻击路径

### 1. 多模态证据印证供应链投毒到运行期异常路径

- 路径判定：`cross-modal-corroborated-path`
- 综合置信度：90%
- 严重级别：critical
- 路径评分：100 / 100
- 影响资产：`cicd-error.png -> package:@acme/payments-helper -> pypi:pip@24.0.0 -> CI 构建步骤 -> orion-update.tar.gz -> checkout-api.prod -> /admin/export`
- 修复优先级：P0

证据链：

- 多模态证据中识别到安装脚本、外联、凌晨异常和敏感接口关键词。
- 依赖节点与构建链存在可达关系。
- 构建链生成 `orion-update.tar.gz`。
- 产物部署到 `checkout-api.prod`。
- 运行日志出现 `/admin/export` 敏感路径访问。

### 2. 依赖与 CI/CD 风险后出现运行期异常路径

- 路径判定：`likely-real-attack-path`
- 综合置信度：83%
- 严重级别：critical
- 路径评分：100 / 100
- 修复优先级：P0

该路径说明依赖风险、构建链风险、产物发布和运行期行为之间存在连续证据。系统建议优先隔离相关构建环境，重新构建并复核所有发布产物。

### 3. 构建链完整性受损路径

- 路径判定：`provenance-risk-path`
- 综合置信度：73%
- 严重级别：high
- 修复优先级：P1

该路径指向远程脚本管道执行、Action 可变引用和构建链权限过宽问题，需要通过最小权限、固定 Action 和可信 runner 策略进行治理。

### 4. 产物可信链路验证路径

- 路径判定：`provenance-risk-path`
- 严重级别：critical
- 修复优先级：P0

产物 `orion-update.tar.gz` 的 digest 与 attestation subject 不一致，说明发布门禁应阻断该产物，并要求重新生成可信 provenance。

## 关联高危问题

| 类型 | 风险 | 证据 |
| --- | --- | --- |
| 依赖 | `orion-build-utils` 存在安装脚本信号 | `sample-repo/node_modules/orion-build-utils/install.js` |
| CI/CD | `GITHUB_TOKEN` 权限过宽 | `.github/workflows/release.yml` |
| CI/CD | 远程脚本直接管道执行 | release workflow |
| CI/CD | Action 使用可变引用或未固定到完整 commit SHA | release workflow |
| 产物可信 | artifact digest 与 attestation subject 不一致 | `artifacts/orion-update.intoto.jsonl` |
| 日志 | 敏感导出路径访问和可疑外联 | `logs/orion-runtime.jsonl` |

## 修复建议

- P0：阻断当前可疑产物发布，使用可信 runner 重新构建。
- P0：复核 artifact SHA256、attestation subject、builder、workflow、commit 和签名状态。
- P0：隔离出现运行期异常的服务实例，保留日志、镜像和构建产物证据。
- P1：禁止远程脚本直接管道执行。
- P1：将第三方 Action 固定到完整 commit SHA。
- P1：为高风险依赖建立可达性分析、VEX 降噪和私有源优先策略。

## 安全边界

本报告基于防御性模拟数据生成，不包含真实恶意代码、真实攻击基础设施或可执行攻击载荷。
