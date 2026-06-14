# SolarWinds / SUNBURST 防御复盘摘要

## 结论

本案例为防御性安全仿真，不包含真实恶意代码。SupplyGuard KG 已完成组件、CI/CD、产物可信和日志证据扫描，并生成工作台图谱与溯源报告。

- 综合风险：critical / 100
- 依赖风险：5 项
- CI/CD 风险：4 项
- 产物可信风险：3 项
- 日志风险：2 项
- 攻击路径：4 条

## 关键发现

### 供应链组件

- `orion-build-utils` 存在 install/postinstall 脚本风险信号。
- `express`、`fastapi`、`starlette` 存在可利用 VEX 上下文。
- `pip`、`setuptools` 漏洞需要结合代码可达性和运行日志复核。

### CI/CD 构建链

- `GITHUB_TOKEN` 权限过宽。
- 第三方 Action 使用可变引用，未固定到完整 commit SHA。
- 远程脚本被直接管道执行，存在构建链污染风险。
- 发布流水线需要补充最小权限和 Action 固定策略。

### 产物可信

- 产物 digest 与 attestation subject 不一致或缺失。
- 产物来源 commit 不符合预期。
- 产物签名验签未通过。

### 日志印证

- 运行期日志出现敏感导出或配置路径访问。
- 更新服务日志出现可疑外联证据。

## 页面查看

打开 `http://127.0.0.1:8000`，重点查看：

- 溯源总览
- 供应链组件
- CI/CD 构建链
- 产物可信
- 日志印证
- 攻击路径图谱
- 溯源报告
