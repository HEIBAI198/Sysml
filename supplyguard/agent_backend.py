"""同步编排型 Agent 后端。

本模块只负责把现有扫描能力按供应链溯源主线串起来，不替代具体扫描器。
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import time
from typing import Any, Callable
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from .artifact_trust import ArtifactTrustRequest, ArtifactTrustResult, run_artifact_trust_scan
from .cicd_audit import CICDAuditRequest, CICDAuditResult, run_cicd_audit
from .code_audit import CodeAuditRequest, CodeAuditResult, run_code_audit
from .config import ROOT
from .dependency_audit import DependencyAuditRequest, DependencyAuditResult, run_dependency_audit
from .log_audit import LogAuditResult, LogFileInput, run_log_audit


AGENT_RUN_STORAGE_DIR = ROOT / "storage" / "agent_runs"


class AgentRunRequest(BaseModel):
    """Agent 编排入口参数。"""

    model_config = ConfigDict(populate_by_name=True)

    import_id: str | None = Field(default=None, alias="importId")
    target_path: str | None = Field(default=None, alias="targetPath")
    artifact_path: str | None = Field(default=None, alias="artifactPath")
    attestation_path: str | None = Field(default=None, alias="attestationPath")
    expected_repo: str | None = Field(default=None, alias="expectedRepo")
    expected_commit: str | None = Field(default=None, alias="expectedCommit")
    allowed_workflows: list[str] | None = Field(default=None, alias="allowedWorkflows")
    allowed_builders: list[str] | None = Field(default=None, alias="allowedBuilders")
    allow_self_hosted_runner: bool | None = Field(default=None, alias="allowSelfHostedRunner")
    require_signature: bool | None = Field(default=None, alias="requireSignature")
    log_paths: list[str] = Field(default_factory=list, alias="logPaths")
    include_code_audit: bool = Field(default=True, alias="includeCodeAudit")
    include_dependency_audit: bool = Field(default=True, alias="includeDependencyAudit")
    include_cicd_audit: bool = Field(default=True, alias="includeCicdAudit")
    include_artifact_trust: bool = Field(default=True, alias="includeArtifactTrust")
    include_log_audit: bool = Field(default=True, alias="includeLogAudit")
    timeout_seconds: int = Field(default=180, alias="timeoutSeconds", ge=10, le=600)


@dataclass
class AgentInternalResults:
    code_audit: CodeAuditResult | None = None
    dependency_audit: DependencyAuditResult | None = None
    cicd_audit: CICDAuditResult | None = None
    artifact_trust: ArtifactTrustResult | None = None
    log_audit: LogAuditResult | None = None


@dataclass
class AgentRunBundle:
    payload: dict[str, Any]
    results: AgentInternalResults


AgentProgressCallback = Callable[[dict[str, Any]], None]


def run_agent_backend(
    request: AgentRunRequest,
    run_id: str | None = None,
    progress: AgentProgressCallback | None = None,
) -> AgentRunBundle:
    """执行一次同步 Agent 编排。"""

    started_at = time.monotonic()
    started_at_iso = datetime.now(UTC).isoformat()
    run_id = run_id or new_agent_run_id()
    results = AgentInternalResults()
    steps: list[dict[str, Any]] = [
        new_step("code_audit", "代码可达性", "扫描代码、密钥和配置风险"),
        new_step("dependency_audit", "供应链组件", "生成 SBOM/VEX 并识别依赖风险"),
        new_step("cicd_audit", "CI/CD 构建链", "检查 workflow、权限、Action 引用和构建链路"),
        new_step("artifact_trust", "产物可信", "校验 artifact、provenance、commit、workflow 和 builder"),
        new_step("log_audit", "日志印证", "用运行期日志印证可疑行为"),
        new_step("workspace_report", "图谱与报告汇总", "汇总工作台、攻击路径和溯源报告"),
    ]
    step_map = {step["id"]: step for step in steps}
    evidence_gaps: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []

    target_input = shared_target_input(request)

    def publish(status: str = "running") -> None:
        if progress is None:
            return
        progress(
            build_agent_run_payload(
                run_id=run_id,
                status=status,
                started_at=started_at_iso,
                started_at_monotonic=started_at,
                request=request,
                steps=steps,
                events=events,
                evidence_gaps=evidence_gaps,
                results=results,
            )
        )

    def start_step(step_id: str, message: str) -> None:
        step_map[step_id]["status"] = "running"
        append_agent_event(events, step_id, "step_started", message)
        publish("running")

    def finish_step(step_id: str) -> None:
        step = step_map[step_id]
        if step["status"] == "success":
            append_agent_event(events, step_id, "step_succeeded", step_success_message(step))
        elif step["status"] == "skipped":
            append_agent_event(events, step_id, "step_skipped", step.get("error") or "该阶段已跳过。", "warning")
        elif step["status"] == "failed":
            append_agent_event(events, step_id, "step_failed", step.get("error") or "该阶段执行失败。", "error")
        publish("running")

    append_agent_event(events, "agent", "job_started", "Agent 已创建任务，开始按供应链溯源主线调查。")
    publish("running")

    if request.include_code_audit:
        start_step("code_audit", "正在扫描代码可达性、密钥泄露和配置风险。")
        results.code_audit = run_step(
            step_map["code_audit"],
            lambda: run_code_audit(
                CodeAuditRequest(
                    **target_input,
                    timeout_seconds=request.timeout_seconds,
                ),
                timeout_seconds=request.timeout_seconds,
            ),
            summarize_code_audit,
        )
        finish_step("code_audit")
    else:
        skip_step(step_map["code_audit"], "请求中关闭代码可达性扫描。")
        finish_step("code_audit")

    if request.include_dependency_audit:
        start_step("dependency_audit", "正在解析 package-lock、requirements 等清单并生成 SBOM/VEX。")
        results.dependency_audit = run_step(
            step_map["dependency_audit"],
            lambda: run_dependency_audit(
                DependencyAuditRequest(
                    **target_input,
                    include_osv=True,
                    include_cdxgen=False,
                    include_cyclonedx_py=False,
                    mode="auto",
                )
            ),
            summarize_dependency_audit,
        )
        finish_step("dependency_audit")
    else:
        skip_step(step_map["dependency_audit"], "请求中关闭供应链组件扫描。")
        finish_step("dependency_audit")

    if request.include_cicd_audit:
        start_step("cicd_audit", "正在分析 workflow、GITHUB_TOKEN 权限、Action 固定版本和 runner 风险。")
        results.cicd_audit = run_step(
            step_map["cicd_audit"],
            lambda: run_cicd_audit(
                CICDAuditRequest(
                    **target_input,
                    include_zizmor=False,
                    include_actionlint=False,
                    timeout_seconds=min(120, max(10, request.timeout_seconds)),
                )
            ),
            summarize_cicd_audit,
        )
        finish_step("cicd_audit")
    else:
        skip_step(step_map["cicd_audit"], "请求中关闭 CI/CD 构建链扫描。")
        finish_step("cicd_audit")

    if request.include_artifact_trust:
        artifact_gap = artifact_trust_gap(request)
        if artifact_gap is None:
            start_step("artifact_trust", "正在校验 artifact hash、provenance、commit、workflow、builder 和签名。")
            results.artifact_trust = run_step(
                step_map["artifact_trust"],
                lambda: run_artifact_trust_scan(build_artifact_request(request)),
                summarize_artifact_trust,
            )
            finish_step("artifact_trust")
        else:
            skip_step(step_map["artifact_trust"], artifact_gap["reason"])
            evidence_gaps.append(artifact_gap)
            finish_step("artifact_trust")
    else:
        skip_step(step_map["artifact_trust"], "请求中关闭产物可信验证。")
        finish_step("artifact_trust")

    if request.include_log_audit:
        log_gap = log_audit_gap(request)
        if log_gap is None:
            start_step("log_audit", "正在读取构建日志和运行期日志，匹配外联、敏感接口和异常行为。")
            results.log_audit = run_step(
                step_map["log_audit"],
                lambda: run_log_audit(load_log_inputs(request.log_paths)),
                summarize_log_audit,
            )
            finish_step("log_audit")
        else:
            skip_step(step_map["log_audit"], log_gap["reason"])
            evidence_gaps.append(log_gap)
            finish_step("log_audit")
    else:
        skip_step(step_map["log_audit"], "请求中关闭日志印证。")
        finish_step("log_audit")

    start_step("workspace_report", "正在汇总组件、构建链、产物和日志证据，生成攻击路径与溯源报告。")
    finish_workspace_step(step_map["workspace_report"])
    finish_step("workspace_report")
    evidence_gaps.extend(gaps_from_step_failures(steps))
    next_actions = build_agent_next_actions(steps, evidence_gaps, results)
    status = "success" if all(step["status"] in {"success", "skipped"} for step in steps) else "partial"
    append_agent_event(events, "agent", "job_finished", "Agent 调查完成，已形成阶段摘要、证据缺口和下一步动作。")
    payload = build_agent_run_payload(
        run_id=run_id,
        status=status,
        started_at=started_at_iso,
        started_at_monotonic=started_at,
        request=request,
        steps=steps,
        events=events,
        evidence_gaps=evidence_gaps,
        results=results,
        next_actions=next_actions,
    )
    persist_agent_run(payload)
    publish(status)
    return AgentRunBundle(payload=payload, results=results)


def new_agent_run_id() -> str:
    return f"agent-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:8]}"


def build_agent_run_payload(
    *,
    run_id: str,
    status: str,
    started_at: str,
    started_at_monotonic: float,
    request: AgentRunRequest,
    steps: list[dict[str, Any]],
    events: list[dict[str, Any]],
    evidence_gaps: list[dict[str, Any]],
    results: AgentInternalResults,
    next_actions: list[dict[str, Any]] | None = None,
    workspace: dict[str, Any] | None = None,
    report: str | None = None,
) -> dict[str, Any]:
    actions = next_actions if next_actions is not None else build_agent_next_actions(steps, evidence_gaps, results)
    payload = {
        "runId": run_id,
        "status": status,
        "startedAt": started_at,
        "durationSeconds": round(time.monotonic() - started_at_monotonic, 2),
        "input": request.model_dump(by_alias=True),
        "steps": deepcopy(steps),
        "events": deepcopy(events),
        "summary": summarize_agent_run(steps, evidence_gaps, results),
        "evidenceGaps": deepcopy(evidence_gaps),
        "nextActions": deepcopy(actions),
        "narrative": build_agent_narrative(steps, evidence_gaps, results),
    }
    if workspace is not None:
        payload["workspace"] = workspace
    if report is not None:
        payload["report"] = report
    return payload


def append_agent_event(
    events: list[dict[str, Any]],
    step_id: str,
    kind: str,
    message: str,
    level: str = "info",
) -> None:
    events.append(
        {
            "id": f"evt-{len(events) + 1:04d}",
            "stepId": step_id,
            "kind": kind,
            "level": level,
            "message": message,
            "createdAt": datetime.now(UTC).isoformat(),
        }
    )


def step_success_message(step: dict[str, Any]) -> str:
    summary = step.get("summary") if isinstance(step.get("summary"), dict) else {}
    if step.get("id") == "dependency_audit":
        return f"依赖解析完成：识别 {summary.get('dependencies', 0)} 个依赖，发现 {summary.get('findings', 0)} 个风险。"
    if step.get("id") == "cicd_audit":
        return f"CI/CD 分析完成：发现 {summary.get('workflows', 0)} 个 workflow、{summary.get('steps', 0)} 个 step、{summary.get('findings', 0)} 项风险。"
    if step.get("id") == "artifact_trust":
        return f"产物可信校验完成：可信评分 {summary.get('trustScore', 0)}/100，发现 {summary.get('findings', 0)} 项异常。"
    if step.get("id") == "log_audit":
        return f"日志印证完成：解析 {summary.get('events', 0)} 条事件，命中 {summary.get('findings', 0)} 个风险。"
    if step.get("id") == "workspace_report":
        return "图谱与报告汇总完成，攻击路径和溯源报告已更新。"
    if step.get("id") == "code_audit":
        return f"代码可达性扫描完成：发现 {summary.get('total', 0)} 项风险。"
    return f"{step.get('name')}完成。"


def new_step(step_id: str, name: str, description: str) -> dict[str, Any]:
    return {
        "id": step_id,
        "name": name,
        "description": description,
        "status": "pending",
        "durationSeconds": 0,
        "input": {},
        "summary": {},
        "error": "",
    }


def run_step(
    step: dict[str, Any],
    action: Callable[[], Any],
    summarize: Callable[[Any], dict[str, Any]],
) -> Any | None:
    started = time.monotonic()
    step["status"] = "running"
    try:
        result = action()
    except Exception as exc:  # noqa: BLE001 - Agent 需要把单步失败收敛成状态。
        step["status"] = "failed"
        step["error"] = str(exc)
        step["durationSeconds"] = round(time.monotonic() - started, 2)
        return None
    step["status"] = "success"
    step["summary"] = summarize(result)
    step["durationSeconds"] = round(time.monotonic() - started, 2)
    return result


def skip_step(step: dict[str, Any], reason: str) -> None:
    step["status"] = "skipped"
    step["error"] = reason
    step["summary"] = {"reason": reason}


def finish_workspace_step(step: dict[str, Any]) -> None:
    step["status"] = "success"
    step["summary"] = {"message": "扫描结果已交给工作台聚合，接口会返回 workspace 和 report。"}


def shared_target_input(request: AgentRunRequest) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if request.import_id:
        payload["import_id"] = request.import_id
    if request.target_path:
        payload["target_path"] = request.target_path
    return payload


def build_artifact_request(request: AgentRunRequest) -> ArtifactTrustRequest:
    return ArtifactTrustRequest(
        artifact_path=request.artifact_path or "",
        attestation_path=request.attestation_path or "",
        expected_repo=request.expected_repo,
        expected_commit=request.expected_commit,
        allowed_workflows=request.allowed_workflows,
        allowed_builders=request.allowed_builders,
        allow_self_hosted_runner=request.allow_self_hosted_runner,
        require_signature=request.require_signature,
        timeout_seconds=min(120, max(5, request.timeout_seconds)),
    )


def artifact_trust_gap(request: AgentRunRequest) -> dict[str, Any] | None:
    missing: list[str] = []
    if not request.artifact_path:
        missing.append("构建产物 artifact")
    elif not resolve_local_path(request.artifact_path).is_file():
        missing.append(f"构建产物不存在：{request.artifact_path}")
    if not request.attestation_path:
        missing.append("provenance/attestation 文件")
    elif not resolve_local_path(request.attestation_path).is_file():
        missing.append(f"attestation 不存在：{request.attestation_path}")
    if not missing:
        return None
    return {
        "id": "artifact-trust-input-missing",
        "module": "产物可信",
        "severity": "high",
        "question": "我还不能判断发布产物是否被替换，因为缺少 release artifact 或 provenance/attestation。",
        "missingItems": missing,
        "reason": "缺少产物可信验证材料：" + "；".join(missing),
        "whereToFind": ["release artifact", "GitHub Actions artifacts", "SLSA provenance", "cosign/gh attestation"],
        "uploadTo": "产物可信",
        "proves": "证明发布产物是否来自预期仓库、commit、workflow 和 builder，判断产物是否被替换或来源不明。",
        "keywords": compact_keywords([request.expected_repo, request.expected_commit, request.target_path]),
        "examplePaths": artifact_gap_examples(request),
        "actionButtons": [
            {"label": "去产物可信上传", "actionKind": "open_module", "targetModule": "产物可信"},
            {"label": "复制检索关键词", "actionKind": "copy_keywords"},
            {"label": "查看样例文件", "actionKind": "show_examples"},
        ],
    }


def log_audit_gap(request: AgentRunRequest) -> dict[str, Any] | None:
    if not request.log_paths:
        return {
            "id": "runtime-log-input-missing",
            "module": "日志印证",
            "severity": "medium",
            "question": "我还不能确认风险是否真的触发，因为缺少运行期或构建期日志。",
            "missingItems": ["运行期日志", "构建日志或部署日志"],
            "reason": "未提供运行期日志，无法验证构建或依赖风险是否在运行环境触发。",
            "whereToFind": ["Nginx/access log", "应用日志", "K8s pod log", "EDR/WAF", "DNS/VPC Flow Log"],
            "uploadTo": "日志印证",
            "proves": "证明可疑依赖、外联 IP、敏感接口访问或异常登录是否真实发生。",
            "keywords": compact_keywords([request.expected_repo, request.target_path]),
            "examplePaths": log_gap_examples(request),
            "actionButtons": [
                {"label": "去日志印证", "actionKind": "open_module", "targetModule": "日志印证"},
                {"label": "复制检索关键词", "actionKind": "copy_keywords"},
                {"label": "查看样例文件", "actionKind": "show_examples"},
            ],
        }
    missing = [item for item in request.log_paths if not resolve_local_path(item).is_file()]
    if not missing:
        return None
    return {
        "id": "runtime-log-file-missing",
        "module": "日志印证",
        "severity": "medium",
        "question": "我找不到你提供的部分日志文件，需要重新选择或导出这些日志。",
        "missingItems": missing[:6],
        "reason": "部分日志文件不存在：" + "；".join(missing[:4]),
        "whereToFind": ["本地日志目录", "日志平台导出文件", "案例 logs 目录"],
        "uploadTo": "日志印证",
        "proves": "补齐日志后可验证运行期异常是否与供应链风险同源。",
        "keywords": compact_keywords(missing),
        "examplePaths": log_gap_examples(request),
        "actionButtons": [
            {"label": "去日志印证", "actionKind": "open_module", "targetModule": "日志印证"},
            {"label": "复制检索关键词", "actionKind": "copy_keywords"},
            {"label": "查看样例文件", "actionKind": "show_examples"},
        ],
    }


def artifact_gap_examples(request: AgentRunRequest) -> list[str]:
    target = str(request.target_path or "").lower()
    if "3cx" in target:
        return [
            "cases/3cx-supply-chain/artifacts/3cx-desktop-app.tar.gz",
            "cases/3cx-supply-chain/artifacts/3cx-desktop-app.intoto.jsonl",
        ]
    if "solarwinds" in target or "sunburst" in target:
        return [
            "cases/solarwinds-sunburst/artifacts/orion-update.tar.gz",
            "cases/solarwinds-sunburst/artifacts/orion-update.intoto.jsonl",
        ]
    return ["release artifact", "provenance/attestation JSON 或 JSONL"]


def log_gap_examples(request: AgentRunRequest) -> list[str]:
    target = str(request.target_path or "").lower()
    if "3cx" in target:
        return [
            "cases/3cx-supply-chain/logs/build-runner.jsonl",
            "cases/3cx-supply-chain/logs/customer-endpoint.jsonl",
        ]
    if "solarwinds" in target or "sunburst" in target:
        return [
            "cases/solarwinds-sunburst/logs/orion-build-runner.log",
            "cases/solarwinds-sunburst/logs/orion-runtime.jsonl",
        ]
    return ["Nginx/access log", "应用日志", "K8s pod log", "EDR/WAF/DNS 日志"]


def load_log_inputs(log_paths: list[str]) -> list[LogFileInput]:
    inputs: list[LogFileInput] = []
    for raw_path in log_paths:
        path = resolve_local_path(raw_path)
        inputs.append(LogFileInput(filename=path.name, content=path.read_bytes()))
    return inputs


def resolve_local_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def summarize_code_audit(result: CodeAuditResult) -> dict[str, Any]:
    return {
        "scanId": result.scan_id,
        "target": result.target,
        "total": result.summary.get("total", 0),
        "critical": result.summary.get("critical", 0),
        "high": result.summary.get("high", 0),
        "riskScore": result.summary.get("risk_score", 0),
    }


def summarize_dependency_audit(result: DependencyAuditResult) -> dict[str, Any]:
    return {
        "scanId": result.scan_id,
        "target": result.target,
        "dependencies": result.summary.get("total_dependencies", 0),
        "findings": result.summary.get("finding_count", 0),
        "riskScore": result.summary.get("risk_score", 0),
        "riskLevel": result.summary.get("risk_level", "low"),
    }


def summarize_cicd_audit(result: CICDAuditResult) -> dict[str, Any]:
    return {
        "scanId": result.scan_id,
        "target": result.target,
        "workflows": result.summary.get("workflow_count", 0),
        "steps": result.summary.get("total_steps", 0),
        "findings": result.summary.get("finding_count", 0),
        "riskScore": result.summary.get("risk_score", 0),
        "riskLevel": result.summary.get("risk_level", "low"),
    }


def summarize_artifact_trust(result: ArtifactTrustResult) -> dict[str, Any]:
    return {
        "scanId": result.scan_id,
        "artifact": result.artifact,
        "digest": result.digest,
        "trustScore": result.trust_score,
        "level": result.level,
        "checks": result.summary.get("check_count", 0),
        "findings": result.summary.get("finding_count", 0),
    }


def summarize_log_audit(result: LogAuditResult) -> dict[str, Any]:
    return {
        "scanId": result.scan_id,
        "files": len(result.files),
        "events": result.summary.get("total_events", 0),
        "findings": result.summary.get("finding_count", 0),
        "riskScore": result.summary.get("risk_score", 0),
        "riskLevel": result.summary.get("risk_level", "low"),
    }


def gaps_from_step_failures(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for step in steps:
        if step.get("status") != "failed":
            continue
        gaps.append(
            {
                "id": f"{step.get('id')}-failed",
                "module": step.get("name"),
                "severity": "medium",
                "question": f"{step.get('name')}没有执行成功，需要先修复该阶段输入或运行环境。",
                "missingItems": ["可用输入路径", "扫描工具运行环境", "后端错误日志"],
                "reason": f"{step.get('name')} 执行失败：{step.get('error')}",
                "whereToFind": ["检查输入路径", "检查依赖工具", "查看后端日志"],
                "uploadTo": step.get("name"),
                "proves": "修复失败项后才能补齐该模块证据。",
                "keywords": compact_keywords([step.get("id"), step.get("error")]),
                "examplePaths": [],
                "actionButtons": [
                    {"label": "复制检索关键词", "actionKind": "copy_keywords"},
                    {"label": "查看对应模块", "actionKind": "open_module", "targetModule": step.get("name")},
                ],
            }
        )
    return gaps


def build_agent_next_actions(
    steps: list[dict[str, Any]],
    evidence_gaps: list[dict[str, Any]],
    results: AgentInternalResults,
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for gap in evidence_gaps:
        actions.append(
            {
                "priority": "high" if gap.get("severity") == "high" else "medium",
                "title": f"补充{gap.get('module')}证据",
                "action": gap.get("reason"),
                "targetModule": gap.get("uploadTo"),
                "keywords": gap.get("keywords", []),
                "actionKind": "open_evidence_gap",
                "payload": {"gapId": gap.get("id")},
            }
        )
    if results.artifact_trust is not None and results.artifact_trust.trust_score < 70:
        actions.append(
            {
                "priority": "high",
                "title": "阻断低可信产物发布",
                "action": "重新生成 artifact 和 provenance，核对 digest、仓库、commit、workflow、builder 与 runner 策略。",
                "targetModule": "产物可信",
                "keywords": compact_keywords([results.artifact_trust.artifact, results.artifact_trust.digest]),
                "actionKind": "rerun_artifact_trust",
                "payload": {
                    "artifact": results.artifact_trust.artifact,
                    "digest": results.artifact_trust.digest,
                },
            }
        )
    if results.dependency_audit is not None and int(results.dependency_audit.summary.get("finding_count") or 0) > 0:
        actions.append(
            {
                "priority": "medium",
                "title": "复核高风险依赖",
                "action": "优先确认高风险依赖是否被代码 import、是否进入构建产物、是否在运行日志中出现。",
                "targetModule": "供应链组件",
                "keywords": compact_keywords([finding.dependency for finding in results.dependency_audit.findings[:5]]),
                "actionKind": "review_high_risk_dependencies",
                "payload": {"findingCount": results.dependency_audit.summary.get("finding_count", 0)},
            }
        )
    actions.append(
        {
            "priority": "medium",
            "title": "生成答辩讲解",
            "action": "把当前调查结论整理成案例背景、检测流程、关键证据、攻击路径和处置建议。",
            "targetModule": "智能研判",
            "keywords": [],
            "actionKind": "generate_defense_brief",
            "payload": {},
        }
    )
    actions.append(
        {
            "priority": "low",
            "title": "导出证据包",
            "action": "导出本次 Agent 任务、workspace、溯源报告、证据缺口和调查叙事，便于复现和答辩。",
            "targetModule": "溯源报告",
            "keywords": [],
            "actionKind": "export_evidence_package",
            "payload": {},
        }
    )
    if not actions:
        actions.append(
            {
                "priority": "low",
                "title": "生成溯源报告",
                "action": "当前 Agent 流程已完成，可查看攻击路径图谱和溯源报告。",
                "targetModule": "溯源报告",
                "keywords": [],
                "actionKind": "generate_defense_brief",
                "payload": {},
            }
        )
    return actions[:8]


def build_agent_narrative(
    steps: list[dict[str, Any]],
    evidence_gaps: list[dict[str, Any]],
    results: AgentInternalResults,
) -> dict[str, Any]:
    dep_findings = int((results.dependency_audit.summary if results.dependency_audit else {}).get("finding_count") or 0)
    dep_count = int((results.dependency_audit.summary if results.dependency_audit else {}).get("total_dependencies") or 0)
    cicd_findings = int((results.cicd_audit.summary if results.cicd_audit else {}).get("finding_count") or 0)
    artifact_score = int((results.artifact_trust.summary if results.artifact_trust else {}).get("trust_score") or 0)
    artifact_findings = int((results.artifact_trust.summary if results.artifact_trust else {}).get("finding_count") or 0)
    log_findings = int((results.log_audit.summary if results.log_audit else {}).get("finding_count") or 0)
    risk_score = int(summarize_agent_run(steps, evidence_gaps, results).get("riskScore") or 0)
    confidence = narrative_confidence(dep_findings, cicd_findings, artifact_score, artifact_findings, log_findings, evidence_gaps)

    timeline = [
        dependency_narrative(dep_count, dep_findings),
        cicd_narrative(cicd_findings),
        artifact_narrative(results.artifact_trust is not None, artifact_score, artifact_findings),
        log_narrative(results.log_audit is not None, log_findings),
        path_narrative(confidence, evidence_gaps),
    ]
    key_evidence = [item for item in timeline if "待补证" not in item]
    verdict = narrative_verdict(confidence, risk_score, evidence_gaps)
    summary = f"{verdict}：{' → '.join(timeline)}"
    gap_summary = "；".join(str(gap.get("reason")) for gap in evidence_gaps[:3]) or "当前未发现阻断调查的核心证据缺口。"
    defense_brief = (
        "【案例背景】本次 Agent 围绕软件供应链攻击检测与溯源展开，重点核查依赖、构建链、产物可信和运行期证据。\n\n"
        f"【检测流程】系统按顺序完成依赖异常、CI/CD 构建风险、产物可信异常、日志印证和攻击路径生成。综合风险评分为 {risk_score}/100。\n\n"
        f"【关键证据】{'；'.join(key_evidence[:4]) or '当前关键证据仍需补充。'}\n\n"
        f"【攻击路径】{summary}\n\n"
        f"【处置建议】{gap_summary} 建议先补齐高优先级证据，再阻断低可信产物发布、复核高风险依赖并导出证据包。"
    )
    return {
        "summary": summary,
        "timeline": timeline,
        "verdict": verdict,
        "confidence": confidence,
        "keyEvidence": key_evidence[:6],
        "defenseBrief": defense_brief,
    }


def dependency_narrative(dep_count: int, finding_count: int) -> str:
    if finding_count > 0:
        return f"解析 {dep_count} 个依赖并发现 {finding_count} 个供应链风险"
    if dep_count > 0:
        return f"解析 {dep_count} 个依赖，暂未发现高风险依赖"
    return "依赖证据待补证"


def cicd_narrative(finding_count: int) -> str:
    if finding_count > 0:
        return f"CI/CD 检出 {finding_count} 项构建链风险"
    return "CI/CD 构建链暂未发现高危配置"


def artifact_narrative(has_result: bool, trust_score: int, finding_count: int) -> str:
    if not has_result:
        return "产物可信待补证"
    if trust_score < 70 or finding_count > 0:
        return f"产物可信校验异常，可信评分 {trust_score}/100"
    return f"产物可信校验通过，可信评分 {trust_score}/100"


def log_narrative(has_result: bool, finding_count: int) -> str:
    if not has_result:
        return "运行期日志待补证"
    if finding_count > 0:
        return f"运行日志命中 {finding_count} 个异常行为"
    return "运行日志暂未发现异常印证"


def path_narrative(confidence: int, evidence_gaps: list[dict[str, Any]]) -> str:
    if evidence_gaps:
        return f"形成待补证攻击路径，当前可信度约 {confidence}%"
    return f"形成可解释攻击路径，当前可信度约 {confidence}%"


def narrative_confidence(
    dep_findings: int,
    cicd_findings: int,
    artifact_score: int,
    artifact_findings: int,
    log_findings: int,
    evidence_gaps: list[dict[str, Any]],
) -> int:
    score = 35
    if dep_findings > 0:
        score += 15
    if cicd_findings > 0:
        score += 15
    if artifact_score and artifact_score < 70:
        score += 15
    if artifact_findings > 0:
        score += 10
    if log_findings > 0:
        score += 15
    score -= min(20, len(evidence_gaps) * 8)
    return max(0, min(95, score))


def narrative_verdict(confidence: int, risk_score: int, evidence_gaps: list[dict[str, Any]]) -> str:
    if confidence >= 80 and risk_score >= 80 and not evidence_gaps:
        return "高可信供应链攻击路径"
    if confidence >= 70:
        return "较高可信供应链攻击路径"
    if evidence_gaps:
        return "待补证供应链攻击路径"
    return "可疑供应链风险路径"


def summarize_agent_run(
    steps: list[dict[str, Any]],
    evidence_gaps: list[dict[str, Any]],
    results: AgentInternalResults,
) -> dict[str, Any]:
    success_count = sum(1 for step in steps if step["status"] == "success")
    skipped_count = sum(1 for step in steps if step["status"] == "skipped")
    failed_count = sum(1 for step in steps if step["status"] == "failed")
    risk_score = max(
        int((results.code_audit.summary if results.code_audit else {}).get("risk_score") or 0),
        int((results.dependency_audit.summary if results.dependency_audit else {}).get("risk_score") or 0),
        int((results.cicd_audit.summary if results.cicd_audit else {}).get("risk_score") or 0),
        int((results.artifact_trust.summary if results.artifact_trust else {}).get("risk_score") or 0),
        int((results.log_audit.summary if results.log_audit else {}).get("risk_score") or 0),
    )
    return {
        "stepCount": len(steps),
        "success": success_count,
        "skipped": skipped_count,
        "failed": failed_count,
        "evidenceGapCount": len(evidence_gaps),
        "riskScore": risk_score,
        "riskLevel": risk_level(risk_score),
    }


def risk_level(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 55:
        return "medium"
    return "low"


def compact_keywords(values: list[Any]) -> list[str]:
    keywords: list[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            keywords.extend(compact_keywords(list(value)))
            continue
        text = str(value).strip()
        if text and text not in keywords:
            keywords.append(text[:160])
    return keywords[:12]


def persist_agent_run(payload: dict[str, Any]) -> None:
    AGENT_RUN_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    path = AGENT_RUN_STORAGE_DIR / f"{payload['runId']}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
