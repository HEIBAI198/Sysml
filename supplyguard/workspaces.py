"""本地 JSON 工作空间仓储。"""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from html import escape
import json
from pathlib import Path
import re
import uuid
import zipfile
from typing import Any

from .config import ROOT


WORKSPACE_STORAGE_DIR = ROOT / "storage" / "workspaces"
LATEST_FILE = WORKSPACE_STORAGE_DIR / "latest.json"


def new_workspace_id() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    return f"ws_{stamp}_{uuid.uuid4().hex[:8]}"


def workspace_dir(workspace_id: str) -> Path:
    safe_id = validate_workspace_id(workspace_id)
    return WORKSPACE_STORAGE_DIR / safe_id


def validate_workspace_id(workspace_id: str) -> str:
    value = workspace_id.strip()
    if not re.fullmatch(r"ws_[A-Za-z0-9_\-]+", value):
        raise ValueError("workspaceId 格式不正确")
    return value


def create_workspace(
    *,
    base_payload: dict[str, Any],
    import_record: dict[str, Any] | None = None,
    preset: str | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    workspace_id = new_workspace_id()
    payload = normalize_workspace_payload(
        deepcopy(base_payload),
        workspace_id=workspace_id,
        import_record=import_record,
        preset=preset,
        name=name,
    )
    save_workspace(payload, modules={})
    set_latest_workspace_id(workspace_id)
    return payload


def normalize_workspace_payload(
    payload: dict[str, Any],
    *,
    workspace_id: str,
    import_record: dict[str, Any] | None = None,
    preset: str | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    payload = deepcopy(payload)
    payload["workspaceId"] = workspace_id
    payload["workspace_id"] = workspace_id
    payload["generated_at"] = datetime.now(UTC).isoformat()
    payload["mode"] = payload.get("mode") or "guided-investigation"
    workspace_meta = payload.setdefault("workspace", {})
    workspace_meta["workspaceId"] = workspace_id
    workspace_meta["preset"] = preset or workspace_meta.get("preset") or "custom"
    if name:
        workspace_meta["name"] = name
    if import_record:
        workspace_meta["importId"] = import_record.get("importId")
        workspace_meta["name"] = name or import_record.get("projectName") or workspace_meta.get("name")
        workspace_meta["sourceType"] = import_record.get("sourceType")
        source_ref = import_record.get("sourceRef") if isinstance(import_record.get("sourceRef"), dict) else {}
        source = import_record.get("source") if isinstance(import_record.get("source"), dict) else {}
        source_path = (
            source.get("url")
            or source_ref.get("url")
            or source_ref.get("path")
            or import_record.get("sourcePath")
            or import_record.get("path")
        )
        workspace_meta["source"] = source_ref or source or {"path": source_path}
        workspace_meta["repository"] = source_path or workspace_meta.get("repository")
        payload["import"] = import_record
    payload["guidance"] = build_guidance(payload)
    payload["evidence"] = build_evidence(payload)
    payload["normalized_findings"] = build_normalized_findings(payload)
    payload["attack_paths"] = payload.get("graph", {}).get("attack_paths", []) if isinstance(payload.get("graph"), dict) else []
    payload["report_html"] = markdown_to_html(payload.get("report") or "")
    return payload


def save_workspace(payload: dict[str, Any], modules: dict[str, Any] | None = None) -> None:
    workspace_id = validate_workspace_id(str(payload.get("workspaceId") or payload.get("workspace_id") or ""))
    directory = workspace_dir(workspace_id)
    directory.mkdir(parents=True, exist_ok=True)
    normalized = normalize_workspace_payload(payload, workspace_id=workspace_id)
    write_json(directory / "workspace.json", normalized)
    write_json(directory / "evidence.json", normalized.get("evidence") or [])
    write_json(directory / "findings.json", normalized.get("normalized_findings") or [])
    graph = normalized.get("graph") if isinstance(normalized.get("graph"), dict) else {}
    write_json(directory / "attack-paths.json", graph.get("attack_paths") or normalized.get("attack_paths") or [])
    (directory / "report.md").write_text(normalized.get("report") or "", encoding="utf-8")
    (directory / "report.html").write_text(normalized.get("report_html") or markdown_to_html(normalized.get("report") or ""), encoding="utf-8")
    if modules is not None:
        modules_dir = directory / "modules"
        modules_dir.mkdir(exist_ok=True)
        for key, value in modules.items():
            write_json(modules_dir / f"{key}.json", value)
    set_latest_workspace_id(workspace_id)


def save_workspace_snapshot(payload: dict[str, Any], *, workspace_id: str | None = None, module_key: str | None = None, module_payload: Any = None) -> dict[str, Any]:
    target_id = workspace_id or latest_workspace_id() or new_workspace_id()
    normalized = normalize_workspace_payload(payload, workspace_id=target_id)
    modules: dict[str, Any] = {}
    if module_key and module_payload is not None:
        modules[module_key] = module_payload
    save_workspace(normalized, modules=modules)
    return normalized


def load_workspace(workspace_id: str) -> dict[str, Any]:
    path = workspace_dir(workspace_id) / "workspace.json"
    if not path.exists():
        raise FileNotFoundError("工作空间不存在")
    return json.loads(path.read_text(encoding="utf-8"))


def latest_workspace_id() -> str | None:
    if not LATEST_FILE.exists():
        return None
    try:
        payload = json.loads(LATEST_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    value = payload.get("workspaceId")
    return str(value) if value else None


def load_latest_workspace() -> dict[str, Any] | None:
    workspace_id = latest_workspace_id()
    if not workspace_id:
        return None
    try:
        return load_workspace(workspace_id)
    except FileNotFoundError:
        return None


def set_latest_workspace_id(workspace_id: str) -> None:
    WORKSPACE_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    write_json(LATEST_FILE, {"workspaceId": validate_workspace_id(workspace_id), "updatedAt": datetime.now(UTC).isoformat()})


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f"{path.suffix}.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def build_guidance(payload: dict[str, Any]) -> dict[str, Any]:
    dependency_audit = payload.get("dependency_audit") if isinstance(payload.get("dependency_audit"), dict) else {}
    cicd_audit = payload.get("cicd_audit") if isinstance(payload.get("cicd_audit"), dict) else {}
    artifact_trust = payload.get("artifact_trust") if isinstance(payload.get("artifact_trust"), dict) else {}
    log_audit = payload.get("log_audit") if isinstance(payload.get("log_audit"), dict) else {}
    dependency_done = bool(dependency_audit.get("scan_id"))
    cicd_done = bool(cicd_audit.get("scan_id"))
    artifact_done = bool(artifact_trust.get("scan_id"))
    logs_done = bool(log_audit.get("scan_id")) or bool(payload.get("logs"))
    graph_paths = int(payload.get("summary", {}).get("attack_paths") or 0)
    report_done = bool(payload.get("report"))
    steps = [
        step("case", "选择案例", "选择要调查的案例或项目", True, "project-import"),
        step("preflight", "预检资产", "确认语言、依赖文件、CI 文件和可扫描范围", bool(payload.get("import") or payload.get("code_audit")), "project-import"),
        step("supply", "发现供应链风险", "生成 SBOM/VEX，定位异常依赖与依赖混淆信号", dependency_done, "supply"),
        step("corroborate", "印证构建/产物/日志", "检查构建链、产物可信和运行期日志是否互相印证", cicd_done and (artifact_done or logs_done), "pipeline"),
        step("graph", "生成攻击路径", "把证据串成污染入口、传播环节和受影响资产", graph_paths > 0, "graph"),
        step("report", "导出报告", "交付溯源结论、证据链和处置建议", report_done, "report"),
    ]
    next_action = next((item for item in steps if not item["done"]), steps[-1])
    suggestions = build_next_actions(payload, dependency_done, cicd_done, artifact_done, logs_done, graph_paths)
    return {
        "currentStep": next_action["id"],
        "currentStepLabel": next_action["label"],
        "steps": steps,
        "nextActions": suggestions,
        "defenseNotice": "当前案例为防御性安全仿真，不包含真实恶意代码、真实攻击载荷或可用攻击基础设施。",
    }


def step(identifier: str, label: str, description: str, done: bool, target: str) -> dict[str, Any]:
    return {"id": identifier, "label": label, "description": description, "done": done, "target": target}


def build_next_actions(
    payload: dict[str, Any],
    dependency_done: bool,
    cicd_done: bool,
    artifact_done: bool,
    logs_done: bool,
    graph_paths: int,
) -> list[dict[str, str]]:
    if not dependency_done:
        return [action("生成 SBOM 与 VEX", "先确认组件风险、漏洞命中和依赖混淆信号。", "supply")]
    if not cicd_done:
        return [action("检查构建链污染", "验证异常依赖是否进入 workflow、runner 或发布链路。", "pipeline")]
    if not artifact_done:
        return [action("执行产物可信门禁", "核对 artifact digest、commit、workflow、builder 和 runner。", "artifact")]
    if not logs_done:
        return [action("上传日志印证", "用运行期外联、敏感接口访问等证据确认风险是否真实触发。", "logs")]
    if graph_paths <= 0:
        return [action("生成攻击路径", "把依赖、构建、产物和日志证据串成可解释路径。", "graph")]
    return [action("导出溯源报告", "交付结论、证据链、复现步骤和处置优先级。", "report")]


def action(title: str, description: str, target: str) -> dict[str, str]:
    return {"title": title, "description": description, "target": target}


def build_evidence(payload: dict[str, Any]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for module_key, audit_key in [
        ("dependency", "dependency_audit"),
        ("cicd", "cicd_audit"),
        ("artifact", "artifact_trust"),
        ("logs", "log_audit"),
        ("code", "code_audit"),
        ("multimodal", "multimodal_audit"),
    ]:
        audit = payload.get(audit_key)
        if not isinstance(audit, dict):
            continue
        for index, finding in enumerate(audit.get("findings") or [], start=1):
            if not isinstance(finding, dict):
                continue
            evidence.append(
                {
                    "id": f"ev-{module_key}-{index:04d}",
                    "type": module_key,
                    "source": audit_key,
                    "asset": finding.get("dependency") or finding.get("asset") or finding.get("workflow") or finding.get("source") or "-",
                    "summary": finding.get("evidence") or finding.get("title") or finding.get("reason") or "-",
                    "confidence": finding.get("confidence") or finding.get("score") or 60,
                    "findingId": finding.get("id"),
                    "createdAt": audit.get("generated_at") or payload.get("generated_at"),
                }
            )
    return evidence


def build_normalized_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings = payload.get("findings") if isinstance(payload.get("findings"), list) else []
    normalized = []
    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            continue
        normalized.append(
            {
                "id": finding.get("id") or f"finding-{index:04d}",
                "module": finding.get("module") or "unknown",
                "title": finding.get("title") or "未命名风险",
                "severity": finding.get("severity") or "medium",
                "score": finding.get("score") or 0,
                "asset": finding.get("asset") or "-",
                "recommendation": finding.get("status") or finding.get("recommendation") or "继续补充证据后研判。",
                "status": finding.get("status") or "open",
            }
        )
    return normalized


def markdown_to_html(markdown: str) -> str:
    body = []
    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()
        if line.startswith("# "):
            body.append(f"<h1>{escape(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{escape(line[3:])}</h2>")
        elif line.startswith("### "):
            body.append(f"<h3>{escape(line[4:])}</h3>")
        elif line.startswith("- "):
            body.append(f"<p class=\"bullet\">• {escape(line[2:])}</p>")
        elif line:
            body.append(f"<p>{escape(line)}</p>")
        else:
            body.append("")
    return "\n".join(
        [
            "<!doctype html>",
            "<html lang=\"zh-CN\">",
            "<head><meta charset=\"utf-8\"><title>SupplyGuard KG 溯源报告</title>",
            "<style>body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:980px;margin:40px auto;line-height:1.7;color:#0f172a}h1,h2,h3{line-height:1.3}.bullet{margin-left:1rem}code{background:#f1f5f9;padding:2px 4px;border-radius:4px}</style>",
            "</head><body>",
            *body,
            "</body></html>",
        ]
    )


def write_evidence_package(workspace_id: str, destination: Path) -> Path:
    workspace = load_workspace(workspace_id)
    directory = workspace_dir(workspace_id)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for filename in ["workspace.json", "evidence.json", "findings.json", "attack-paths.json", "report.md", "report.html"]:
            path = directory / filename
            if path.exists():
                archive.write(path, filename)
        modules_dir = directory / "modules"
        if modules_dir.exists():
            for path in modules_dir.glob("*.json"):
                archive.write(path, f"modules/{path.name}")
        archive.writestr("README.txt", f"SupplyGuard KG 工作空间证据包：{workspace_id}\n项目：{workspace.get('workspace', {}).get('name', '-')}\n")
    return destination
