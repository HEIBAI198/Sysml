# SolarWinds / SUNBURST 防御性复盘案例

本案例安全模拟公开 SolarWinds 供应链事件中的典型模式：受信任的软件更新/构建链被污染，产物可信校验失败，运行期遥测日志进一步印证可疑外联行为。

## 公开参考

- CISA SolarWinds Supply Chain Compromise: https://www.cisa.gov/news-events/alerts/2021/01/07/supply-chain-compromise
- MITRE SolarWinds Campaign C0024: https://attack.mitre.org/campaigns/C0024/
- MITRE T1195 Supply Chain Compromise: https://attack.mitre.org/techniques/T1195/

## 预期触发点

- `package.json` / `package-lock.json` 中存在组件版本异常和安装脚本证据。
- `.github/workflows/release.yml` 中存在 CI/CD 构建链风险。
- `artifacts/orion-update.intoto.jsonl` 中存在 artifact provenance 不匹配。
- `logs/orion-runtime.jsonl` 中存在运行期可疑外联证据。

## 复盘命令

```powershell
.\scripts\run-case-replay.ps1 -Case solarwinds
```

手动导入路径：

```text
cases/solarwinds-sunburst/sample-repo
```

本案例仅使用无害占位脚本和 `example.invalid` 域名，不包含真实恶意代码。
