# 3CX / X_TRADER 防御性复盘案例

本案例安全模拟公开 3CX 供应链事件中的级联风险模式：早期 X_TRADER 类软件包留下构建节点信号，随后桌面端发布流水线产生带有 provenance 风险的产物，终端遥测日志进一步印证可疑外联行为。

## 公开参考

- Mandiant 3CX Software Supply Chain Compromise: https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise/
- MITRE 3CX Supply Chain Attack C0057: https://attack.mitre.org/campaigns/C0057/
- MITRE T1195 Supply Chain Compromise: https://attack.mitre.org/techniques/T1195/

## 预期触发点

- `x-trader-codec` 组件存在安装脚本风险信号。
- `.github/workflows/desktop-release.yml` 中存在 CI/CD 风险。
- `artifacts/3cx-desktop-app.intoto.jsonl` 中存在产物可信校验失败。
- `logs/customer-endpoint.jsonl` 中存在运行期可疑外联证据。

## 复盘命令

```powershell
.\scripts\run-case-replay.ps1 -Case 3cx
```

手动导入路径：

```text
cases/3cx-supply-chain/sample-repo
```

本案例仅使用无害占位脚本和 `example.invalid` 域名，不包含真实恶意代码。
