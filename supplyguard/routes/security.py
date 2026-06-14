"""Security platform demonstration routes."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import hashlib
import io
import json
from pathlib import Path
from threading import Lock, Thread
from typing import Any
from urllib.parse import quote
import zipfile

import httpx
from fastapi import APIRouter, File, Form, HTTPException, Query, Request, Response, UploadFile
from pydantic import BaseModel, Field

from ..code_audit import (
    CodeAuditRequest,
    CodeAuditResult,
    DEFAULT_SCAN_TIMEOUT_SECONDS,
    GitHubCodeScanningStatusRequest,
    GitHubCodeScanningUploadRequest,
    add_ignored_finding,
    audit_state_payload,
    code_scanning_sarif_status,
    create_audit_baseline,
    git_checkout_uri,
    git_current_commit,
    git_current_ref,
    github_request,
    github_token,
    refresh_audit_result,
    remove_ignored_finding,
    run_code_audit,
    sarif_upload_content,
    upload_code_scanning_sarif,
)
from ..cicd_audit import (
    CICDAuditRequest,
    CICDAuditResult,
    add_ignored_finding as add_cicd_ignored_finding,
    audit_state_payload as cicd_audit_state_payload,
    build_cicd_sarif,
    create_audit_baseline as create_cicd_audit_baseline,
    empty_cicd_audit_payload,
    refresh_audit_result as refresh_cicd_audit_result,
    remove_ignored_finding as remove_cicd_ignored_finding,
    run_cicd_audit,
    serialize_cicd_audit,
)
from ..artifact_trust import (
    ArtifactTrustRequest,
    ArtifactTrustResult,
    empty_artifact_trust_payload,
    run_artifact_trust_scan,
    save_upload_file,
    serialize_artifact_trust,
)
from ..agent_backend import AgentRunRequest, new_agent_run_id, run_agent_backend
from ..dependency_audit import (
    DependencyAuditRequest,
    DependencyAuditResult,
    empty_dependency_audit_payload,
    run_dependency_audit,
    serialize_dependency,
    serialize_dependency_audit,
)
from ..log_audit import (
    LogAuditResult,
    LogFileInput,
    create_realtime_log_baseline,
    empty_log_audit_payload,
    ignore_realtime_log_finding,
    ingest_realtime_logs,
    realtime_log_events,
    realtime_log_trend,
    run_log_audit,
    serialize_log_audit,
)
from ..multimodal_audit import (
    MultimodalAuditResult,
    MultimodalFileInput,
    MultimodalTextInput,
    latest_multimodal_payload,
    run_multimodal_audit,
    run_multimodal_text_audit,
    serialize_multimodal_audit,
)
from ..knowledge_graph import build_knowledge_graph, build_unified_facts
from ..llm_assistant import ask_deepseek_security_assistant
from ..project_imports import ImportErrorDetail, load_import
from ..workspaces import (
    create_workspace,
    latest_workspace_id,
    load_latest_workspace,
    load_workspace,
    markdown_to_html,
    save_workspace_snapshot,
    write_evidence_package,
)


router = APIRouter(prefix="/api/security", tags=["Security Platform"])
LAST_CODE_AUDIT: CodeAuditResult | None = None
LAST_DEPENDENCY_AUDIT: DependencyAuditResult | None = None
LAST_CICD_AUDIT: CICDAuditResult | None = None
LAST_LOG_AUDIT: LogAuditResult | None = None
LAST_ARTIFACT_TRUST: ArtifactTrustResult | None = None
LAST_MULTIMODAL_AUDIT: MultimodalAuditResult | None = None
LAST_AGENT_RUN: dict[str, Any] | None = None
LAST_AGENT_JOB_ID: str | None = None
AGENT_JOBS: dict[str, dict[str, Any]] = {}
AGENT_JOB_LOCK = Lock()


class AssistantQuestion(BaseModel):
    question: str = Field(min_length=1, max_length=600)


class IgnoreFindingRequest(BaseModel):
    fingerprint: str = Field(min_length=8, max_length=128)
    reason: str = Field(default="", max_length=300)


class BaselineRequest(BaseModel):
    note: str = Field(default="", max_length=300)


class LogIgnoreRequest(BaseModel):
    fingerprint: str = Field(min_length=8, max_length=128)
    reason: str = Field(default="", max_length=300)


class MultimodalTextAnalyzeRequest(BaseModel):
    recognized_text: str = Field(min_length=1, max_length=20000)
    source_type: str = Field(default="image", pattern="^(audio|image|video)$")
    evidence_type: str = Field(default="visual_ocr", max_length=80)
    source_name: str = Field(default="manual-recognized-text.txt", max_length=180)
    confidence: float = Field(default=0.9, ge=0, le=1)
    engine: str = Field(default="manual-asr-ocr-text", max_length=120)
    language: str | None = Field(default="zh-CN", max_length=40)


class WorkspaceCreateRequest(BaseModel):
    import_id: str | None = Field(default=None, alias="importId")
    preset: str | None = Field(default=None, max_length=80)
    name: str | None = Field(default=None, max_length=200)


class ScanSuiteRequest(BaseModel):
    import_id: str | None = Field(default=None, alias="importId")
    artifact_path: str | None = Field(default=None, alias="artifactPath")
    attestation_path: str | None = Field(default=None, alias="attestationPath")
    expected_repo: str | None = Field(default=None, alias="expectedRepo")
    expected_commit: str | None = Field(default=None, alias="expectedCommit")
    allowed_workflows: list[str] | None = Field(default=None, alias="allowedWorkflows")
    allowed_builders: list[str] | None = Field(default=None, alias="allowedBuilders")
    allow_self_hosted_runner: bool = Field(default=False, alias="allowSelfHostedRunner")
    require_signature: bool = Field(default=False, alias="requireSignature")
    log_paths: list[str] = Field(default_factory=list, alias="logPaths")
    include_code_audit: bool = Field(default=True, alias="includeCodeAudit")
    include_dependency_audit: bool = Field(default=True, alias="includeDependencyAudit")
    include_cicd_audit: bool = Field(default=True, alias="includeCicdAudit")
    include_artifact_trust: bool = Field(default=True, alias="includeArtifactTrust")
    include_log_audit: bool = Field(default=True, alias="includeLogAudit")
    timeout_seconds: int = Field(default=180, alias="timeoutSeconds", ge=10, le=600)


SECURITY_WORKSPACE: dict[str, Any] = {
    "workspace": {
        "name": "Acme Retail Cloud",
        "repository": "git@github.com:acme/checkout-service.git",
        "branch": "main",
        "commit": "8f42c19",
        "build": "github-actions/deploy-prod-2481",
        "runtime": "checkout-api.prod",
        "mode": "offline-demo-knowledge-base",
    },
    "summary": {
        "risk_score": 87,
        "risk_level": "critical",
        "open_findings": 28,
        "critical_findings": 4,
        "repositories": 8,
        "dependencies": 314,
        "build_steps": 42,
        "log_events": 1842300,
        "attack_paths": 3,
        "mean_triage_minutes": 11,
    },
    "modules": [
        {
            "key": "code_audit",
            "name": "代码与应用安全审计",
            "status": "high",
            "score": 78,
            "signals": 12,
            "description": "检测 SQL 拼接、命令执行、危险反序列化、XSS、硬编码密钥和不安全配置，并生成修复建议。",
        },
        {
            "key": "supply_chain",
            "name": "软件供应链安全检测",
            "status": "critical",
            "score": 91,
            "signals": 9,
            "description": "生成 SBOM，关联许可证、漏洞、维护者、安装脚本和依赖混淆风险。",
        },
        {
            "key": "cicd",
            "name": "CI/CD 构建链路监测",
            "status": "high",
            "score": 84,
            "signals": 5,
            "description": "分析 GitHub Actions 权限、未固定 Action、外部下载和构建产物链路。",
        },
        {
            "key": "artifact_trust",
            "name": "产物可信验证门",
            "status": "warning",
            "score": 82,
            "signals": 6,
            "description": "验证 artifact digest、SLSA provenance、builder、workflow、commit、runner 和签名结果。",
        },
        {
            "key": "logs",
            "name": "海量日志风险识别",
            "status": "medium",
            "score": 69,
            "signals": 17,
            "description": "结合规则与异常检测识别异常登录、敏感接口访问和可疑外联。",
        },
        {
            "key": "multimodal",
            "name": "多模态证据接入层",
            "status": "observed",
            "score": 58,
            "signals": 0,
            "description": "上传音频、截图和视频帧，统一落盘为可追溯证据来源，并记录 FFmpeg/OpenCV 处理状态。",
        },
        {
            "key": "knowledge_graph",
            "name": "安全知识图谱",
            "status": "critical",
            "score": 89,
            "signals": 3,
            "description": "将仓库、依赖、漏洞、构建任务、日志事件和攻击阶段串成证据链。",
        },
        {
            "key": "copilot",
            "name": "大模型安全分析助手",
            "status": "active",
            "score": 82,
            "signals": 6,
            "description": "基于 RAG 检索漏洞库、规则、代码片段和日志上下文，解释风险并排序修复。",
        },
    ],
    "trend": [
        {"day": "05-26", "code": 14, "dependency": 22, "build": 8, "runtime": 19},
        {"day": "05-27", "code": 16, "dependency": 24, "build": 9, "runtime": 21},
        {"day": "05-28", "code": 18, "dependency": 31, "build": 13, "runtime": 25},
        {"day": "05-29", "code": 17, "dependency": 42, "build": 18, "runtime": 37},
        {"day": "05-30", "code": 21, "dependency": 54, "build": 24, "runtime": 49},
        {"day": "05-31", "code": 22, "dependency": 61, "build": 27, "runtime": 66},
        {"day": "06-01", "code": 24, "dependency": 68, "build": 31, "runtime": 72},
    ],
    "findings": [
        {
            "id": "SC-2026-0041",
            "title": "疑似依赖混淆包在构建阶段执行安装脚本",
            "module": "供应链",
            "severity": "critical",
            "score": 96,
            "asset": "npm package @acme/payments-helper",
            "evidence": "包名与内部私有包相同，公共源版本号更高，并包含 postinstall 外联行为。",
            "first_seen": "2026-05-30 02:14",
            "owner": "platform-security",
            "status": "需要隔离",
        },
        {
            "id": "CI-2026-0019",
            "title": "GitHub Actions 使用未固定版本并授予写权限",
            "module": "CI/CD",
            "severity": "high",
            "score": 88,
            "asset": ".github/workflows/release.yml",
            "evidence": "uses: third-party/setup@main，permissions: contents: write，发布任务可修改产物。",
            "first_seen": "2026-05-29 21:37",
            "owner": "devops",
            "status": "等待修复",
        },
        {
            "id": "APP-2026-0077",
            "title": "订单查询接口存在 SQL 拼接风险",
            "module": "代码审计",
            "severity": "high",
            "score": 82,
            "asset": "src/orders/query.py:118",
            "evidence": "用户可控 order_by 字段进入 SQL 字符串拼接，缺少白名单映射。",
            "first_seen": "2026-05-28 16:09",
            "owner": "checkout-team",
            "status": "修复建议已生成",
        },
        {
            "id": "LOG-2026-0133",
            "title": "构建后服务出现异常外联和敏感接口探测",
            "module": "日志风险",
            "severity": "critical",
            "score": 93,
            "asset": "checkout-api.prod",
            "evidence": "上线 18 分钟后出现到 185.199.108.153 的周期性请求，随后 admin/export 被高频访问。",
            "first_seen": "2026-05-30 03:06",
            "owner": "soc",
            "status": "关联到攻击链",
        },
    ],
    "dependencies": [
        {
            "name": "@acme/payments-helper",
            "version": "9.9.2",
            "ecosystem": "npm",
            "license": "UNKNOWN",
            "risk": 96,
            "signals": ["依赖混淆", "postinstall 外联", "维护者异常", "发布频率突增"],
            "recommendation": "立即锁定内部源，撤销缓存包并重新构建产物。",
        },
        {
            "name": "serialize-javascript",
            "version": "3.1.0",
            "ecosystem": "npm",
            "license": "BSD-3-Clause",
            "risk": 74,
            "signals": ["已知漏洞命中", "版本过旧"],
            "recommendation": "升级到受支持版本，并回归测试模板渲染链路。",
        },
        {
            "name": "pyjwt",
            "version": "1.7.1",
            "ecosystem": "PyPI",
            "license": "MIT",
            "risk": 63,
            "signals": ["版本过旧", "认证组件"],
            "recommendation": "升级到 2.x，并检查算法白名单与密钥轮换策略。",
        },
        {
            "name": "left-pad-plus",
            "version": "1.0.8",
            "ecosystem": "npm",
            "license": "MIT",
            "risk": 58,
            "signals": ["typosquatting 相似度 0.91", "下载量异常"],
            "recommendation": "替换为标准库实现或可信维护包。",
        },
    ],
    "pipeline": [
        {
            "step": "commit",
            "name": "提交 8f42c19",
            "status": "observed",
            "detail": "引入 checkout coupon 优化，同时更新 lockfile。",
            "actor": "li.chen",
            "time": "2026-05-30 01:58",
        },
        {
            "step": "resolve",
            "name": "依赖解析",
            "status": "critical",
            "detail": "公共 npm 源解析到更高版本 @acme/payments-helper@9.9.2。",
            "actor": "npm ci",
            "time": "2026-05-30 02:14",
        },
        {
            "step": "build",
            "name": "构建脚本执行",
            "status": "critical",
            "detail": "postinstall 执行 curl 下载脚本，产物哈希与基线不一致。",
            "actor": "GitHub Actions",
            "time": "2026-05-30 02:17",
        },
        {
            "step": "deploy",
            "name": "产物发布",
            "status": "high",
            "detail": "release.yml 使用第三方 Action @main 且拥有 contents: write。",
            "actor": "deploy-prod-2481",
            "time": "2026-05-30 02:42",
        },
        {
            "step": "runtime",
            "name": "运行期异常",
            "status": "critical",
            "detail": "服务上线后出现周期性外联、敏感导出接口探测和异常 401 峰值。",
            "actor": "checkout-api.prod",
            "time": "2026-05-30 03:06",
        },
    ],
    "logs": [
        {
            "time": "2026-05-30 03:06:18",
            "source": "nginx",
            "event": "POST /admin/export",
            "severity": "critical",
            "signal": "敏感接口异常访问",
            "confidence": 0.94,
        },
        {
            "time": "2026-05-30 03:07:04",
            "source": "egress",
            "event": "checkout-api -> 185.199.108.153:443",
            "severity": "critical",
            "signal": "未知域名外联",
            "confidence": 0.91,
        },
        {
            "time": "2026-05-30 03:11:44",
            "source": "auth",
            "event": "admin user 401 burst from runner subnet",
            "severity": "high",
            "signal": "暴力破解/令牌探测",
            "confidence": 0.87,
        },
        {
            "time": "2026-05-30 03:18:02",
            "source": "waf",
            "event": "order_by payload contains sleep(5)",
            "severity": "high",
            "signal": "SQL 注入探测",
            "confidence": 0.82,
        },
    ],
    "graph": {
        "nodes": [
            {"id": "repo", "label": "checkout-service", "type": "代码仓库", "risk": "high", "description": "主业务仓库，包含订单、支付和优惠券模块。"},
            {"id": "commit", "label": "commit 8f42c19", "type": "提交", "risk": "medium", "description": "更新 lockfile，引入异常依赖版本。"},
            {"id": "package", "label": "@acme/payments-helper", "type": "依赖包", "risk": "critical", "description": "疑似依赖混淆，postinstall 阶段触发外联。"},
            {"id": "script", "label": "postinstall script", "type": "安装脚本", "risk": "critical", "description": "下载并执行远程脚本，污染构建环境。"},
            {"id": "build", "label": "deploy-prod-2481", "type": "构建任务", "risk": "high", "description": "未固定 Action 版本，构建权限过宽。"},
            {"id": "artifact", "label": "checkout-api:20260530", "type": "构建产物", "risk": "critical", "description": "产物哈希偏离基线，疑似被植入外联逻辑。"},
            {"id": "service", "label": "checkout-api.prod", "type": "运行资产", "risk": "critical", "description": "生产服务出现外联与敏感接口异常访问。"},
            {"id": "log", "label": "egress anomaly", "type": "日志事件", "risk": "critical", "description": "外联、401 峰值和敏感导出接口访问相互印证。"},
            {"id": "apt", "label": "APT 供应链阶段", "type": "攻击阶段", "risk": "critical", "description": "符合依赖混淆投毒到运行期回连的攻击链。"},
        ],
        "edges": [
            {"id": "e1", "source": "repo", "target": "commit", "label": "引入"},
            {"id": "e2", "source": "commit", "target": "package", "label": "解析到"},
            {"id": "e3", "source": "package", "target": "script", "label": "包含"},
            {"id": "e4", "source": "script", "target": "build", "label": "执行于"},
            {"id": "e5", "source": "build", "target": "artifact", "label": "生成"},
            {"id": "e6", "source": "artifact", "target": "service", "label": "部署为"},
            {"id": "e7", "source": "service", "target": "log", "label": "产生"},
            {"id": "e8", "source": "log", "target": "apt", "label": "映射到"},
        ],
    },
    "assistant": {
        "default_question": "这条供应链攻击链路应该优先修哪里？",
        "answer": "优先隔离 @acme/payments-helper@9.9.2 并回滚 deploy-prod-2481 产物。证据链显示风险从依赖解析进入构建阶段，postinstall 脚本污染构建环境，随后生产服务出现外联和敏感接口异常访问。",
        "retrieval": [
            "SBOM: @acme/payments-helper@9.9.2 risk=96",
            "CI/CD: release.yml uses third-party/setup@main",
            "Runtime: checkout-api -> 185.199.108.153:443",
            "Rule: dependency-confusion-with-install-script",
        ],
        "next_actions": [
            "将私有包解析固定到内部制品库，并启用 lockfile 完整性校验。",
            "撤销 deploy-prod-2481，使用干净 runner 和可信依赖重新构建。",
            "把 GitHub Actions 权限收敛为只读，第三方 Action 固定到 commit SHA。",
            "审查 src/orders/query.py 的 order_by 白名单，合并参数化查询补丁。",
        ],
    },
    "integrations": [
        {"name": "OSV", "status": "离线缓存", "records": 12840},
        {"name": "NVD/CVE", "status": "离线缓存", "records": 56310},
        {"name": "规则引擎", "status": "启用", "records": 146},
        {"name": "RAG 知识库", "status": "启用", "records": 932},
    ],
}

def build_security_report() -> str:
    summary = SECURITY_WORKSPACE["summary"]
    findings = SECURITY_WORKSPACE["findings"]
    pipeline = SECURITY_WORKSPACE["pipeline"]
    assistant = SECURITY_WORKSPACE["assistant"]
    finding_rows = "\n".join(
        f"| {item['id']} | {item['severity']} | {item['score']} | {item['title']} | {item['status']} |"
        for item in findings
    )
    pipeline_rows = "\n".join(
        f"| {item['time']} | {item['name']} | {item['status']} | {item['detail']} |"
        for item in pipeline
    )
    actions = "\n".join(f"- {action}" for action in assistant["next_actions"])
    return f"""# 供应链攻击检测与应用安全审计报告

生成时间：{datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")}

## 风险摘要

- 综合风险评分：{summary['risk_score']} / 100
- 风险等级：{summary['risk_level']}
- 打开风险：{summary['open_findings']} 项，其中严重风险 {summary['critical_findings']} 项
- 关联仓库：{summary['repositories']} 个
- 依赖包：{summary['dependencies']} 个
- 已识别攻击路径：{summary['attack_paths']} 条

## 关键发现

| 编号 | 等级 | 评分 | 风险 | 状态 |
| --- | --- | ---: | --- | --- |
{finding_rows}

## 证据链

| 时间 | 阶段 | 状态 | 证据 |
| --- | --- | --- | --- |
{pipeline_rows}

## 大模型分析结论

{assistant['answer']}

## 优先修复建议

{actions}
"""


def build_security_report_from_payload(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    graph = payload.get("graph") if isinstance(payload.get("graph"), dict) else {}
    facts = payload.get("facts") if isinstance(payload.get("facts"), dict) else {}
    findings = top_graph_findings(payload, limit=12)
    attack_paths = graph.get("attack_paths") if isinstance(graph.get("attack_paths"), list) else []
    evidence = facts.get("evidence") if isinstance(facts.get("evidence"), list) else []
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
    edges = graph.get("edges") if isinstance(graph.get("edges"), list) else []
    graph_summary = graph.get("summary") if isinstance(graph.get("summary"), dict) else {}
    fact_summary = facts.get("summary") if isinstance(facts.get("summary"), dict) else {}
    finding_rows = "\n".join(
        "| {id} | {severity} | {score} | {title} | {asset} | {source} |".format(
            id=markdown_cell(item.get("id") or "-"),
            severity=markdown_cell(item.get("severity") or "-"),
            score=int(item.get("score") or 0),
            title=markdown_cell(item.get("title") or "-"),
            asset=markdown_cell(item.get("asset") or "-"),
            source=markdown_cell(item.get("source") or item.get("module") or "-"),
        )
        for item in findings
    )
    attack_path_sections = "\n\n".join(
        render_attack_path_section(path, nodes, edges, evidence, index)
        for index, path in enumerate(attack_paths[:5], start=1)
        if isinstance(path, dict)
    )
    evidence_rows = "\n".join(
        render_evidence_row(item, nodes, index)
        for index, item in enumerate(evidence_for_report(attack_paths, evidence), start=1)
    )
    multimodal_section = render_multimodal_fusion_section(payload)
    actions = "\n".join(render_recommendation(item, index) for index, item in enumerate(attack_paths[:8], start=1))
    if not actions:
        actions = "\n".join(f"- {action}" for action in payload["assistant"]["next_actions"])
    appendices = render_report_appendices(payload)
    actionable_paths = graph_summary.get("actionable_attack_path_count", 0)
    real_paths = graph_summary.get("real_attack_path_count", 0)
    average_confidence = graph_summary.get("average_path_confidence", 0)
    verdict_summary = ", ".join(
        f"{key}={value}"
        for key, value in (graph_summary.get("path_verdicts") or {}).items()
    )
    return f"""# 知识图谱驱动的真实攻击路径研判报告

生成时间：{datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")}

## 风险摘要

- 综合风险评分：{summary['risk_score']} / 100
- 风险等级：{summary['risk_level']}
- 打开风险：{summary['open_findings']} 项，其中严重风险 {summary['critical_findings']} 项
- 图谱节点：{graph_summary.get('node_count', 0)} 个
- 图谱关系：{graph_summary.get('edge_count', 0)} 条
- 统一资产：{fact_summary.get('asset_count', 0)} 个
- 证据片段：{fact_summary.get('evidence_count', 0)} 条
- 运行期日志事件：{summary['log_events']} 条
- 已识别攻击路径：{summary['attack_paths']} 条
- 可行动攻击路径：{actionable_paths} 条
- 高度可信真实路径：{real_paths} 条
- 平均路径置信度：{round(float(average_confidence or 0) * 100)}%
- 路径判定分布：{verdict_summary or '-'}
- 参考模型：GUAC 软件树/证据树可达性、OpenCTI observable 关系与置信度、NetworkX 路径评分、in-toto/SLSA 可信证据链、BloodHound 式入口到目标路径呈现

## 路径判定

本报告不再只列“发现了哪些漏洞”，而是判断这些证据能否串成一次真实攻击路径。

## 攻击路径

{attack_path_sections or '暂未形成可验证攻击路径。'}

## 关联高危问题

| 编号 | 等级 | 评分 | 风险 | 影响资产 | 来源 |
| --- | --- | ---: | --- | --- | --- |
{finding_rows or '| - | - | - | 未发现风险 | - |'}

## 证据链

| 序号 | 时间 | 证据类型 | 关联资产 | 证据摘要 | 来源模型 |
| ---: | --- | --- | --- | --- | --- |
{evidence_rows or '| 1 | - | - | - | 暂无证据 | - |'}

## 多模态证据融合

{multimodal_section}

## 修复建议

{actions}

## 附录

{appendices}
"""


def markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|")


def top_graph_findings(payload: dict[str, Any], *, limit: int) -> list[dict[str, Any]]:
    graph = payload.get("graph") if isinstance(payload.get("graph"), dict) else {}
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
    graph_findings = [
        {
            "id": node.get("id"),
            "title": node.get("label"),
            "severity": node.get("risk"),
            "score": node.get("score"),
            "asset": graph_finding_asset(node, nodes),
            "source": node.get("source_model") or node.get("source"),
        }
        for node in nodes
        if isinstance(node, dict) and node.get("type") in {"Finding", "MultimodalFinding"}
    ]
    if graph_findings:
        return sorted(graph_findings, key=lambda item: (-int(item.get("score") or 0), str(item.get("title") or "")))[:limit]
    return sorted(payload.get("findings", []), key=lambda item: -int(item.get("score") or 0))[:limit]


def graph_finding_asset(finding_node: dict[str, Any], nodes: list[dict[str, Any]]) -> str:
    properties = finding_node.get("properties") if isinstance(finding_node.get("properties"), dict) else {}
    raw_properties = properties.get("properties") if isinstance(properties.get("properties"), dict) else {}
    for key in ("dependency", "workflow", "path", "module"):
        value = raw_properties.get(key)
        if value:
            return str(value)
    return str(finding_node.get("source") or "-")


def render_multimodal_fusion_section(payload: dict[str, Any]) -> str:
    multimodal = payload.get("multimodal_audit") if isinstance(payload.get("multimodal_audit"), dict) else {}
    summary = multimodal.get("summary") if isinstance(multimodal.get("summary"), dict) else {}
    evidence = [item for item in multimodal.get("evidence", []) if isinstance(item, dict)]
    if not evidence:
        return "暂无多模态证据。"
    rows: list[str] = []
    for item in evidence[:8]:
        entities = [
            str(entity.get("value") or "")
            for entity in item.get("entities", [])
            if isinstance(entity, dict) and entity.get("value")
        ]
        rules = [
            str(finding.get("rule_id") or "")
            for finding in item.get("findings", [])
            if isinstance(finding, dict) and finding.get("rule_id")
        ]
        text = ""
        recognitions = item.get("recognitions") if isinstance(item.get("recognitions"), list) else []
        if recognitions and isinstance(recognitions[0], dict):
            text = str(recognitions[0].get("recognized_text") or "")
        rows.append(
            "| {id} | {type} | {risk} | {entities} | {rules} | {text} |".format(
                id=markdown_cell(item.get("evidence_id") or "-"),
                type=markdown_cell(item.get("source_type") or "-"),
                risk=markdown_cell(f"{item.get('risk_level') or 'low'} / {item.get('risk_score') or 0}"),
                entities=markdown_cell(", ".join(stable_unique_text(entities)[:8]) or "-"),
                rules=markdown_cell(", ".join(stable_unique_text(rules)[:5]) or "-"),
                text=markdown_cell(short_text(text, 120) or "-"),
            )
        )
    return f"""- 多模态证据：{summary.get('evidence_count', 0)} 条
- 安全实体：{summary.get('entity_count', 0)} 个
- 规则命中：{summary.get('finding_count', 0)} 条
- 多模态风险：{summary.get('risk_level', 'low')} / {summary.get('risk_score', 0)}
- 参考模型：GUAC 负责软件供应链可达关系，OpenCTI 负责 observable/置信度/first seen 语义，NetworkX 负责路径评分和多源证据连通性。

| Evidence ID | 类型 | 风险 | 关联实体 | 命中规则 | 识别文本摘要 |
| --- | --- | --- | --- | --- | --- |
{chr(10).join(rows) or '| - | - | - | - | - | - |'}"""


def render_attack_path_section(
    path: dict[str, Any],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    index: int,
) -> str:
    node_map = {str(node.get("id")): node for node in nodes if isinstance(node, dict)}
    edge_map = {str(edge.get("id")): edge for edge in edges if isinstance(edge, dict)}
    node_ids = [str(node_id) for node_id in path.get("node_ids", []) if node_id]
    edge_ids = [str(edge_id) for edge_id in path.get("edge_ids", []) if edge_id]
    impact_assets = [
        node_label(node_map[node_id])
        for node_id in node_ids
        if node_id in node_map and node_map[node_id].get("type") not in {"AttackStage", "Finding", "MultimodalFinding"}
    ]
    mermaid = render_mermaid_path(node_ids, edge_ids, node_map, edge_map)
    evidence_rows = "\n".join(
        "- {title}：{detail}".format(
            title=markdown_cell(item.get("title") or item.get("kind") or "证据"),
            detail=markdown_cell(short_text(item.get("detail") or "", 120)),
        )
        for item in evidence_items_for_ids(path.get("evidence_ids", []), evidence)[:5]
    )
    path_step_rows = "\n".join(
        "- {source} --{relationship}--> {target}（{model}，置信度 {confidence}%）：{why}".format(
            source=markdown_cell(step.get("source") or "-"),
            relationship=markdown_cell(step.get("relationship") or "关联"),
            target=markdown_cell(step.get("target") or "-"),
            model=markdown_cell(step.get("model") or step.get("edge_type") or "evidence"),
            confidence=round(float(step.get("confidence") or 0) * 100),
            why=markdown_cell(short_text(step.get("why_abusable") or step.get("trust_basis") or "", 120)),
        )
        for step in path.get("path_steps", [])
        if isinstance(step, dict)
    )
    trust_rows = "\n".join(
        "- {model}：{claim}；主体={subject}；状态={status}".format(
            model=markdown_cell(item.get("model") or "-"),
            claim=markdown_cell(item.get("claim") or "-"),
            subject=markdown_cell(item.get("subject") or "-"),
            status=markdown_cell(item.get("status") or "-"),
        )
        for item in path.get("trust_chain", [])
        if isinstance(item, dict)
    )
    gap_rows = "\n".join(f"- {markdown_cell(gap)}" for gap in path.get("gaps", []) if gap)
    choke_rows = "\n".join(
        "- {label}：{action}".format(
            label=markdown_cell(item.get("label") or "-"),
            action=markdown_cell(item.get("action") or "-"),
        )
        for item in path.get("choke_points", [])
        if isinstance(item, dict)
    )
    mappings = ", ".join(
        str(item.get("technique") or item.get("name") or item)
        for item in path.get("mappings", [])
        if isinstance(item, dict)
    )
    references = ", ".join(str(item) for item in path.get("references", []))
    priority = "P0" if str(path.get("severity")) == "critical" else "P1"
    return f"""### {index}. {markdown_cell(path.get('title') or '攻击路径')}

一句话结论：{markdown_cell(path.get('conclusion') or path.get('description') or '')}

```mermaid
{mermaid}
```

- 路径判定：{markdown_cell(path.get('verdict') or '-')}
- 综合置信度：{round(float(path.get('confidence') or 0) * 100)}%
- 严重级别：{path.get('severity', '-')}
- 路径评分：{path.get('score', 0)} / 100
- 影响资产：{markdown_cell(' -> '.join(impact_assets) or '-')}
- 修复优先级：{priority}
- 攻击映射：{markdown_cell(mappings or '-')}
- 参考模型：{markdown_cell(references or '-')}

路径步骤：
{path_step_rows or '- 暂无路径步骤。'}

可信证据链：
{trust_rows or '- 暂无可信链声明。'}

证据缺口：
{gap_rows or '- 当前路径未发现明显证据缺口。'}

关键封堵点：
{choke_rows or '- 暂无封堵点。'}

证据摘要：
{evidence_rows or '- 暂无证据。'}"""


def render_mermaid_path(
    node_ids: list[str],
    edge_ids: list[str],
    node_map: dict[str, dict[str, Any]],
    edge_map: dict[str, dict[str, Any]],
) -> str:
    lines = ["flowchart LR"]
    aliases: dict[str, str] = {}
    for index, node_id in enumerate(node_ids, start=1):
        node = node_map.get(node_id, {"label": node_id, "type": "Asset"})
        alias = f"N{index}"
        aliases[node_id] = alias
        label = mermaid_label(f"{node.get('type', 'Asset')}: {node_label(node)}")
        lines.append(f"  {alias}[\"{label}\"]")
    for index, (source, target) in enumerate(zip(node_ids, node_ids[1:])):
        edge = edge_map.get(edge_ids[index]) if index < len(edge_ids) else None
        edge = best_render_edge(source, target, edge_map, edge if isinstance(edge, dict) else None)
        label = mermaid_label(edge.get("label") if isinstance(edge, dict) else "关联")
        lines.append(f"  {aliases[source]} -->|{label}| {aliases[target]}")
    return "\n".join(lines)


def best_render_edge(
    source: str,
    target: str,
    edge_map: dict[str, dict[str, Any]],
    fallback: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    matches = [
        item for item in edge_map.values()
        if isinstance(item, dict)
        and (
            (str(item.get("source")) == source and str(item.get("target")) == target)
            or (str(item.get("source")) == target and str(item.get("target")) == source)
        )
    ]
    if fallback and fallback not in matches:
        matches.append(fallback)
    if not matches:
        return None
    priority = {
        "MULTIMODAL_TRIGGERS_RULE": 0,
        "MULTIMODAL_FINDING_REFERENCES_ENTITY": 1,
        "MULTIMODAL_EXTRACTS_ENTITY": 2,
        "ENTITY_CORRELATES_DEPENDENCY": 3,
        "ENTITY_CORRELATES_LOG": 3,
        "ENTITY_OBSERVED_IN_BUILD": 4,
        "DEPENDENCY_REACHES_BUILD": 5,
        "STEP_PRODUCES_ARTIFACT": 6,
        "ARTIFACT_DEPLOYED_AS": 7,
        "SERVICE_EMITS_LOG": 8,
        "FINDING_AFFECTS": 20,
    }
    return sorted(
        matches,
        key=lambda item: (
            priority.get(str(item.get("type") or ""), 10),
            0 if str(item.get("source")) == source and str(item.get("target")) == target else 1,
            str(item.get("id") or ""),
        ),
    )[0]


def node_label(node: dict[str, Any]) -> str:
    return str(node.get("label") or node.get("id") or "-")


def mermaid_label(value: Any) -> str:
    return str(value or "").replace('"', "'").replace("\n", " ")[:80]


def evidence_items_for_ids(evidence_ids: Any, evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    wanted = {str(item) for item in evidence_ids if item}
    if not wanted:
        return []
    return [item for item in evidence if isinstance(item, dict) and str(item.get("id")) in wanted]


def evidence_for_report(attack_paths: list[Any], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    wanted: list[str] = []
    for path in attack_paths:
        if isinstance(path, dict):
            wanted.extend(str(item) for item in path.get("evidence_ids", []) if item)
    selected = evidence_items_for_ids(wanted, evidence)
    if selected:
        return selected[:18]
    return evidence[:18]


def render_evidence_row(item: dict[str, Any], nodes: list[dict[str, Any]], index: int) -> str:
    asset_id = str(item.get("asset_id") or "")
    asset = next((node for node in nodes if isinstance(node, dict) and str(node.get("id")) == asset_id), None)
    return "| {index} | {time} | {kind} | {asset} | {detail} | {source_model} |".format(
        index=index,
        time=markdown_cell(item.get("time") or "-"),
        kind=markdown_cell(item.get("kind") or "-"),
        asset=markdown_cell(node_label(asset) if asset else asset_id or "-"),
        detail=markdown_cell(short_text(item.get("detail") or item.get("title") or "-", 180)),
        source_model=markdown_cell(item.get("source_model") or item.get("source") or "-"),
    )


def render_recommendation(path: dict[str, Any], index: int) -> str:
    severity = str(path.get("severity") or "")
    priority = "P0" if severity == "critical" else "P1" if severity == "high" else "P2"
    return "- **{priority} · {title}**：{recommendation}".format(
        priority=priority,
        title=markdown_cell(path.get("title") or f"攻击路径 {index}"),
        recommendation=markdown_cell(path.get("recommendation") or "结合图谱证据复核并处置。"),
    )


def render_report_appendices(payload: dict[str, Any]) -> str:
    dependency_audit = payload.get("dependency_audit") if isinstance(payload.get("dependency_audit"), dict) else {}
    code_audit = payload.get("code_audit") if isinstance(payload.get("code_audit"), dict) else {}
    cicd_audit = payload.get("cicd_audit") if isinstance(payload.get("cicd_audit"), dict) else {}
    artifact_trust = payload.get("artifact_trust") if isinstance(payload.get("artifact_trust"), dict) else {}
    log_audit = payload.get("log_audit") if isinstance(payload.get("log_audit"), dict) else {}
    graph = payload.get("graph") if isinstance(payload.get("graph"), dict) else {}
    facts = payload.get("facts") if isinstance(payload.get("facts"), dict) else {}
    graph_refs = graph.get("references") if isinstance(graph.get("references"), list) else []
    fact_refs = facts.get("references") if isinstance(facts.get("references"), list) else []
    references = graph_refs + fact_refs
    reference_rows = "\n".join(
        f"- {markdown_cell(item.get('name'))}: {markdown_cell(item.get('url'))}"
        for item in references
        if isinstance(item, dict)
    )
    sbom_components = len(dependency_audit.get("dependencies") or [])
    dependency_summary = dependency_audit.get("summary") if isinstance(dependency_audit.get("summary"), dict) else {}
    vex_summary = dependency_summary.get("vex") if isinstance(dependency_summary.get("vex"), dict) else {}
    reachability_summary = dependency_summary.get("reachability") if isinstance(dependency_summary.get("reachability"), dict) else {}
    sarif_results = count_sarif_results(code_audit.get("sarif")) + count_sarif_results(cicd_audit.get("sarif"))
    log_findings = len(log_audit.get("findings") or [])
    return f"""### SBOM / Dependency-Track 风险摘要

- SBOM 组件数量：{sbom_components}
- 依赖风险数量：{dependency_summary.get('finding_count', 0)}
- 最高依赖风险：{dependency_summary.get('risk_score', 0)} / 100
- VEX statement：{vex_summary.get('statement_count', 0)}
- VEX affected / under investigation：{int(vex_summary.get('affected', 0)) + int(vex_summary.get('under_investigation', 0))}
- VEX not affected / fixed：{int(vex_summary.get('not_affected', 0)) + int(vex_summary.get('fixed', 0))}
- 代码可达依赖：{reachability_summary.get('imported_dependencies', 0)}
- 运行期日志命中：{reachability_summary.get('runtime_trace_dependencies', 0)}

### SARIF / DefectDojo 风险摘要

- SARIF 结果数量：{sarif_results}
- 代码风险数量：{code_audit.get('summary', {}).get('total', 0) if isinstance(code_audit.get('summary'), dict) else 0}
- CI/CD 风险数量：{cicd_audit.get('summary', {}).get('finding_count', 0) if isinstance(cicd_audit.get('summary'), dict) else 0}

### 产物可信验证摘要

- 产物：{artifact_trust.get('artifact') or '-'}
- SHA256：{artifact_trust.get('digest') or '-'}
- 可信评分：{artifact_trust.get('trust_score') or artifact_trust.get('trustScore') or 0} / 100
- 检查项数量：{artifact_trust.get('summary', {}).get('check_count', 0) if isinstance(artifact_trust.get('summary'), dict) else 0}
- 产物可信风险：{artifact_trust.get('summary', {}).get('finding_count', 0) if isinstance(artifact_trust.get('summary'), dict) else 0}

### 日志证据摘要

- 日志风险数量：{log_findings}
- 图谱证据数量：{facts.get('summary', {}).get('evidence_count', 0) if isinstance(facts.get('summary'), dict) else 0}

### 开源参考

{reference_rows or '- DefectDojo, GUAC, Dependency-Track'}
"""


def count_sarif_results(sarif: Any) -> int:
    if not isinstance(sarif, dict):
        return 0
    total = 0
    runs = sarif.get("runs") if isinstance(sarif.get("runs"), list) else []
    for run in runs:
        if isinstance(run, dict) and isinstance(run.get("results"), list):
            total += len(run["results"])
    return total


def short_text(value: Any, limit: int) -> str:
    text = str(value).replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return f"{text[: max(20, limit - 3)]}..."


def build_workspace_payload(
    *,
    include_global_multimodal: bool = True,
    workspace_override: dict[str, Any] | None = None,
    import_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = deepcopy(SECURITY_WORKSPACE)
    if workspace_override:
        payload.setdefault("workspace", {}).update(deepcopy(workspace_override))
    if import_record:
        payload["import"] = deepcopy(import_record)
    payload["generated_at"] = datetime.now(UTC).isoformat()
    payload["code_audit"] = serialize_code_audit(LAST_CODE_AUDIT)
    payload["dependency_audit"] = serialize_dependency_audit(LAST_DEPENDENCY_AUDIT)
    payload["cicd_audit"] = serialize_cicd_audit(LAST_CICD_AUDIT)
    payload["artifact_trust"] = serialize_artifact_trust(LAST_ARTIFACT_TRUST)
    payload["log_audit"] = serialize_log_audit(LAST_LOG_AUDIT)
    payload["multimodal_audit"] = latest_multimodal_payload() if include_global_multimodal else None

    if LAST_CODE_AUDIT is not None:
        app_findings = [finding for finding in payload["findings"] if finding.get("module") != "代码审计"]
        payload["findings"] = code_audit_to_workspace_findings(LAST_CODE_AUDIT) + app_findings
        code_module = next((module for module in payload["modules"] if module["key"] == "code_audit"), None)
        if code_module is not None:
            total = LAST_CODE_AUDIT.summary["total"]
            critical = LAST_CODE_AUDIT.summary["critical"]
            high = LAST_CODE_AUDIT.summary["high"]
            code_module["signals"] = total
            code_module["status"] = "critical" if critical else "high" if high else "active"
            code_module["score"] = min(98, 45 + critical * 12 + high * 8 + LAST_CODE_AUDIT.summary["medium"] * 4)
            code_module["description"] = (
                "已接入 Semgrep CE、Gitleaks、Bandit 与 Checkov，覆盖应用代码、Python、密钥和 Docker/CI/IaC 配置风险。"
            )
        payload["summary"]["open_findings"] = len(payload["findings"])
        payload["summary"]["critical_findings"] = sum(
            1 for finding in payload["findings"] if finding.get("severity") == "critical"
        )

    if LAST_DEPENDENCY_AUDIT is not None:
        payload["dependencies"] = dependency_audit_to_workspace_dependencies(LAST_DEPENDENCY_AUDIT)
        non_supply_findings = [
            finding
            for finding in payload["findings"]
            if not is_supply_chain_workspace_finding(finding)
        ]
        payload["findings"] = dependency_audit_to_workspace_findings(LAST_DEPENDENCY_AUDIT) + non_supply_findings
        supply_module = next((module for module in payload["modules"] if module["key"] == "supply_chain"), None)
        if supply_module is not None:
            summary = LAST_DEPENDENCY_AUDIT.summary
            supply_module["signals"] = summary["finding_count"]
            supply_module["status"] = summary["risk_level"] if summary["risk_level"] != "low" else "active"
            supply_module["score"] = summary["risk_score"]
            supply_module["description"] = (
                "Direct dependency scan supports package.json and requirements.txt, "
                "CycloneDX SBOM, licenses, local advisories, typosquatting, and risk scoring."
            )
        payload["summary"]["dependencies"] = LAST_DEPENDENCY_AUDIT.summary["total_dependencies"]
        payload["summary"]["open_findings"] = len(payload["findings"])
        payload["summary"]["critical_findings"] = sum(
            1 for finding in payload["findings"] if finding.get("severity") == "critical"
        )
        payload["summary"]["risk_score"] = max(
            payload["summary"]["risk_score"],
            LAST_DEPENDENCY_AUDIT.summary["risk_score"],
        )

    if LAST_CICD_AUDIT is not None:
        non_cicd_findings = [
            finding
            for finding in payload["findings"]
            if not is_cicd_workspace_finding(finding)
        ]
        payload["findings"] = cicd_audit_to_workspace_findings(LAST_CICD_AUDIT) + non_cicd_findings
        cicd_module = next((module for module in payload["modules"] if module["key"] == "cicd"), None)
        if cicd_module is not None:
            summary = LAST_CICD_AUDIT.summary
            cicd_module["signals"] = summary["finding_count"]
            cicd_module["status"] = summary["risk_level"] if summary["risk_level"] != "low" else "active"
            cicd_module["score"] = summary["risk_score"]
            cicd_module["description"] = (
                "已接入 GitHub Actions workflow 静态扫描，覆盖未固定 Action、过宽权限、远程脚本执行和明文凭据。"
            )
        payload["summary"]["build_steps"] = LAST_CICD_AUDIT.summary["total_steps"]
        payload["summary"]["open_findings"] = len(payload["findings"])
        payload["summary"]["critical_findings"] = sum(
            1 for finding in payload["findings"] if finding.get("severity") == "critical"
        )
        payload["summary"]["risk_score"] = max(
            payload["summary"]["risk_score"],
            LAST_CICD_AUDIT.summary["risk_score"],
        )
        generated_pipeline = cicd_audit_to_pipeline(LAST_CICD_AUDIT)
        if generated_pipeline:
            payload["pipeline"] = generated_pipeline

    if LAST_ARTIFACT_TRUST is not None:
        non_artifact_findings = [
            finding
            for finding in payload["findings"]
            if not is_artifact_trust_workspace_finding(finding)
        ]
        payload["findings"] = artifact_trust_to_workspace_findings(LAST_ARTIFACT_TRUST) + non_artifact_findings
        artifact_module = next((module for module in payload["modules"] if module["key"] == "artifact_trust"), None)
        if artifact_module is not None:
            summary = LAST_ARTIFACT_TRUST.summary
            artifact_module["signals"] = summary["check_count"]
            artifact_module["status"] = artifact_trust_module_status(LAST_ARTIFACT_TRUST.level)
            artifact_module["score"] = LAST_ARTIFACT_TRUST.trust_score
            artifact_module["description"] = (
                "已接入发布前/部署前产物可信门，验证 SHA256、SLSA provenance、来源仓库、commit、workflow、builder、runner 与签名。"
            )
        payload["summary"]["open_findings"] = len(payload["findings"])
        payload["summary"]["critical_findings"] = sum(
            1 for finding in payload["findings"] if finding.get("severity") == "critical"
        )
        payload["summary"]["risk_score"] = max(
            payload["summary"]["risk_score"],
            int(LAST_ARTIFACT_TRUST.summary.get("risk_score") or 0),
        )
        append_artifact_trust_pipeline(payload, LAST_ARTIFACT_TRUST)

    if LAST_LOG_AUDIT is not None:
        payload["logs"] = log_audit_to_workspace_logs(LAST_LOG_AUDIT)
        non_log_findings = [
            finding
            for finding in payload["findings"]
            if not is_log_workspace_finding(finding)
        ]
        payload["findings"] = log_audit_to_workspace_findings(LAST_LOG_AUDIT) + non_log_findings
        logs_module = next((module for module in payload["modules"] if module["key"] == "logs"), None)
        if logs_module is not None:
            summary = LAST_LOG_AUDIT.summary
            logs_module["signals"] = summary["finding_count"]
            logs_module["status"] = summary["risk_level"] if summary["risk_level"] != "low" else "active"
            logs_module["score"] = summary["risk_score"]
            logs_module["description"] = (
                "已接入日志上传批处理，覆盖 Web access log、app log、auth log 的认证异常、敏感路径、SQL 注入、外联和暴力破解。"
            )
        payload["summary"]["log_events"] = LAST_LOG_AUDIT.summary["total_events"]
        payload["summary"]["open_findings"] = len(payload["findings"])
        payload["summary"]["critical_findings"] = sum(
            1 for finding in payload["findings"] if finding.get("severity") == "critical"
        )
        payload["summary"]["risk_score"] = max(
            payload["summary"]["risk_score"],
            LAST_LOG_AUDIT.summary["risk_score"],
        )

    multimodal_summary = payload["multimodal_audit"].get("summary") if isinstance(payload.get("multimodal_audit"), dict) else {}
    multimodal_count = int(multimodal_summary.get("evidence_count") or 0) if isinstance(multimodal_summary, dict) else 0
    if multimodal_count > 0:
        multimodal_findings = multimodal_payload_to_workspace_findings(payload["multimodal_audit"])
        if multimodal_findings:
            payload["findings"] = multimodal_findings + [
                finding for finding in payload["findings"] if not is_multimodal_workspace_finding(finding)
            ]
        multimodal_module = next((module for module in payload["modules"] if module["key"] == "multimodal"), None)
        if multimodal_module is not None:
            derived_count = int(multimodal_summary.get("derived_count") or 0)
            finding_count = int(multimodal_summary.get("finding_count") or 0)
            risk_score = int(multimodal_summary.get("risk_score") or 0)
            multimodal_module["signals"] = max(multimodal_count, finding_count)
            multimodal_module["status"] = (
                multimodal_summary.get("risk_level")
                if finding_count and multimodal_summary.get("risk_level") != "low"
                else "active"
            )
            multimodal_module["score"] = max(risk_score, min(92, 58 + multimodal_count * 3 + derived_count * 2))
            multimodal_module["description"] = (
                "已接入音频、截图/图像和视频证据上传，使用 Sigma 风格 YAML 规则抽取实体并生成 Wazuh 风格风险告警。"
            )
        payload["summary"]["multimodal_evidence"] = multimodal_count
        payload["summary"]["open_findings"] = len(payload["findings"])
        payload["summary"]["critical_findings"] = sum(
            1 for finding in payload["findings"] if finding.get("severity") == "critical"
        )
        payload["summary"]["risk_score"] = max(
            payload["summary"]["risk_score"],
            int(multimodal_summary.get("risk_score") or 0),
        )
        augment_assistant_with_multimodal(payload)

    realtime_logs = {"events": [], "findings": [], "summary": {"event_count": 0, "finding_count": 0}}
    if LAST_LOG_AUDIT is None:
        realtime_logs = realtime_log_events(limit=200)
    realtime_summary = realtime_logs.get("summary") if isinstance(realtime_logs.get("summary"), dict) else {}
    if int(realtime_summary.get("event_count") or 0) > 0:
        realtime_workspace_logs = realtime_log_payload_to_workspace_logs(realtime_logs)
        realtime_workspace_findings = realtime_log_payload_to_workspace_findings(realtime_logs)
        existing_log_findings = [finding for finding in payload["findings"] if is_log_workspace_finding(finding)]
        non_log_findings = [finding for finding in payload["findings"] if not is_log_workspace_finding(finding)]
        payload["logs"] = (realtime_workspace_logs + payload.get("logs", []))[:120]
        payload["findings"] = dedupe_workspace_findings(
            realtime_workspace_findings + existing_log_findings + non_log_findings
        )
        logs_module = next((module for module in payload["modules"] if module["key"] == "logs"), None)
        if logs_module is not None:
            logs_module["signals"] = int(realtime_summary.get("finding_count") or 0) + (
                LAST_LOG_AUDIT.summary["finding_count"] if LAST_LOG_AUDIT is not None else 0
            )
            logs_module["status"] = (
                realtime_summary.get("risk_level")
                if realtime_summary.get("risk_level") != "low"
                else logs_module.get("status", "active")
            )
            logs_module["score"] = max(int(logs_module.get("score") or 0), int(realtime_summary.get("risk_score") or 0))
            logs_module["description"] = (
                "已接入日志上传批处理与 Vector/HTTP 实时接入，实时检测认证异常、敏感路径、SQL 注入、外联和暴力破解。"
            )
        uploaded_events = LAST_LOG_AUDIT.summary["total_events"] if LAST_LOG_AUDIT is not None else 0
        payload["summary"]["log_events"] = uploaded_events + int(realtime_summary.get("event_count") or 0)
        payload["summary"]["open_findings"] = len(payload["findings"])
        payload["summary"]["critical_findings"] = sum(
            1 for finding in payload["findings"] if finding.get("severity") == "critical"
        )
        payload["summary"]["risk_score"] = max(
            payload["summary"]["risk_score"],
            int(realtime_summary.get("risk_score") or 0),
        )

    apply_runtime_correlations(payload)
    payload["summary"]["risk_level"] = workspace_risk_level(int(payload["summary"].get("risk_score") or 0))
    payload["facts"] = build_unified_facts(
        payload,
        code_audit=LAST_CODE_AUDIT,
        dependency_audit=LAST_DEPENDENCY_AUDIT,
        cicd_audit=LAST_CICD_AUDIT,
        artifact_trust=LAST_ARTIFACT_TRUST,
        log_audit=LAST_LOG_AUDIT,
        realtime_logs=realtime_logs,
    )
    payload["graph"] = build_knowledge_graph(payload["facts"], payload)
    payload["summary"]["attack_paths"] = max(
        int(payload["summary"].get("attack_paths") or 0),
        int(payload["graph"].get("summary", {}).get("attack_path_count") or 0),
    )
    if is_imported_workspace_payload(payload):
        payload["assistant"] = build_imported_workspace_assistant(payload)
    payload["report"] = build_security_report_from_payload(payload)
    return payload


def is_imported_workspace_payload(payload: dict[str, Any]) -> bool:
    workspace = payload.get("workspace") if isinstance(payload.get("workspace"), dict) else {}
    return bool(payload.get("import") or workspace.get("importId"))


def build_imported_workspace_assistant(payload: dict[str, Any]) -> dict[str, Any]:
    workspace = payload.get("workspace") if isinstance(payload.get("workspace"), dict) else {}
    project_name = str(workspace.get("name") or payload.get("import", {}).get("projectName") or "当前项目")
    dependencies = sorted(
        [item for item in payload.get("dependencies", []) if isinstance(item, dict)],
        key=lambda item: int(item.get("risk") or 0),
        reverse=True,
    )
    top_dependency = dependencies[0] if dependencies else {}
    logs = [item for item in payload.get("logs", []) if isinstance(item, dict)]
    runtime_hint = next(
        (
            str(item.get("dstIp") or item.get("dst_ip") or item.get("event") or item.get("signal"))
            for item in logs
            if item.get("dstIp") or item.get("dst_ip") or item.get("event") or item.get("signal")
        ),
        "暂无运行期日志命中",
    )
    path = primary_attack_path(payload)
    path_title = str(path.get("title") or "供应链风险路径") if path else "供应链风险路径"
    recommendation = str(path.get("recommendation") or "先隔离高风险依赖和可疑构建产物，再补齐 provenance、日志和代码可达性证据。") if path else "先隔离高风险依赖和可疑构建产物，再补齐 provenance、日志和代码可达性证据。"
    dependency_name = str(top_dependency.get("name") or "高风险依赖")
    dependency_risk = int(top_dependency.get("risk") or 0)
    return {
        "default_question": f"{project_name} 这条供应链风险链路应该优先修哪里？",
        "answer": (
            f"建议先处理 {project_name} 的最高风险链路“{path_title}”。"
            f"当前依赖侧首要对象是 {dependency_name}，风险分 {dependency_risk}；"
            f"运行期证据指向 {runtime_hint}。处置建议：{recommendation}"
        ),
        "retrieval": stable_unique_text(
            [
                f"Project: {project_name}",
                f"SBOM: {dependency_name} risk={dependency_risk}",
                f"Runtime: {runtime_hint}",
                f"Repository: {workspace.get('repository') or '-'}",
            ]
        ),
        "next_actions": [
            "先冻结或替换受影响依赖，并重新生成 SBOM 与 VEX。",
            "复核代码 import、入口路径和运行期日志，确认 affected 与待判研项。",
            "使用干净 runner 重新构建产物，校验 digest、builder、workflow 和 provenance。",
            "把已证实路径加入攻击链图谱，并在报告中标出证据缺口和处置优先级。",
        ],
    }


async def workspace_id_from_request(request: Request) -> str | None:
    query_value = request.query_params.get("workspaceId") or request.query_params.get("workspace_id")
    if query_value:
        return query_value
    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type:
        return None
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - 非 JSON 或空请求体时不影响旧接口。
        return None
    if isinstance(body, dict):
        value = body.get("workspaceId") or body.get("workspace_id")
        return str(value) if value else None
    return None


def persist_current_workspace(workspace_id: str | None = None, *, module_key: str | None = None, module_payload: Any = None) -> dict[str, Any]:
    existing: dict[str, Any] = {}
    if workspace_id:
        try:
            existing = load_workspace(workspace_id)
        except (FileNotFoundError, ValueError):
            existing = {}
    existing_workspace = existing.get("workspace") if isinstance(existing.get("workspace"), dict) else {}
    imported_workspace = bool(existing.get("import") or existing_workspace.get("importId"))
    existing_import = existing.get("import") if isinstance(existing.get("import"), dict) else None
    payload = build_workspace_payload(
        include_global_multimodal=(not imported_workspace or module_key == "multimodal_audit"),
        workspace_override=existing_workspace,
        import_record=existing_import,
    )
    if workspace_id:
        existing_workspace = existing.get("workspace") if isinstance(existing.get("workspace"), dict) else {}
        if existing_workspace:
            payload["workspace"] = deepcopy(existing_workspace)
        if isinstance(existing.get("import"), dict):
            payload["import"] = deepcopy(existing["import"])
        payload["workspaceId"] = workspace_id
        payload["workspace_id"] = workspace_id
    return save_workspace_snapshot(payload, workspace_id=workspace_id, module_key=module_key, module_payload=module_payload)


def workspace_or_current(workspace_id: str | None = None) -> dict[str, Any]:
    if workspace_id:
        try:
            return load_workspace(workspace_id)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="工作空间不存在") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    latest = load_latest_workspace()
    return latest or persist_current_workspace(latest_workspace_id())


def is_supply_chain_workspace_finding(finding: dict[str, Any]) -> bool:
    module = str(finding.get("module") or "")
    return "供应链" in module or module == "Supply Chain"


def is_cicd_workspace_finding(finding: dict[str, Any]) -> bool:
    module = str(finding.get("module") or "")
    return module == "CI/CD" or "CI/CD" in module


def is_artifact_trust_workspace_finding(finding: dict[str, Any]) -> bool:
    module = str(finding.get("module") or "")
    return module == "产物可信" or "产物可信" in module


def is_log_workspace_finding(finding: dict[str, Any]) -> bool:
    module = str(finding.get("module") or "")
    return module == "日志风险" or "日志" in module


def is_multimodal_workspace_finding(finding: dict[str, Any]) -> bool:
    module = str(finding.get("module") or "")
    return module == "多模态证据" or "多模态" in module


def workspace_risk_level(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 55:
        return "medium"
    return "low"


def serialize_code_audit(result: CodeAuditResult | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "scan_id": result.scan_id,
        "generated_at": result.generated_at,
        "target_path": result.target_path,
        "target": result.target,
        "summary": result.summary,
        "findings": [
            {
                "id": finding.id,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity,
                "score": finding.score,
                "risk_file": finding.risk_file,
                "line": finding.line,
                "end_line": finding.end_line,
                "evidence": finding.evidence,
                "recommendation": finding.recommendation,
                "scanner": finding.scanner,
                "confidence": finding.confidence,
                "cwe": finding.cwe,
                "fingerprint": finding.fingerprint,
            }
            for finding in result.findings
        ],
        "scanners": [
            {
                "name": scanner.name,
                "available": scanner.available,
                "command": scanner.command,
                "version": scanner.version,
                "error": scanner.error,
                "state": scanner.state,
            }
            for scanner in result.scanners
        ],
        "errors": result.errors,
        "report": result.report,
        "sarif": result.sarif,
    }


def code_audit_to_workspace_findings(result: CodeAuditResult) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for finding in result.findings[:20]:
        findings.append(
            {
                "id": finding.id,
                "title": f"{finding.category}：{finding.title}",
                "module": "代码审计",
                "severity": finding.severity,
                "score": finding.score,
                "asset": f"{finding.risk_file}:{finding.line}",
                "evidence": finding.evidence,
                "first_seen": result.generated_at[:16].replace("T", " "),
                "owner": "appsec",
                "status": finding.recommendation,
            }
        )
    return findings


def dependency_audit_to_workspace_dependencies(result: DependencyAuditResult) -> list[dict[str, Any]]:
    return [serialize_dependency(dependency) for dependency in result.dependencies]


def dependency_audit_to_workspace_findings(result: DependencyAuditResult) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for finding in result.findings[:20]:
        findings.append(
            {
                "id": finding.id,
                "title": finding.title,
                "module": "供应链",
                "severity": finding.severity,
                "score": finding.score,
                "asset": f"{finding.ecosystem}:{finding.dependency} ({finding.source_file})",
                "evidence": finding.evidence,
                "first_seen": result.generated_at[:16].replace("T", " "),
                "owner": "appsec",
                "status": finding.recommendation,
            }
        )
    return findings


def cicd_audit_to_workspace_findings(result: CICDAuditResult) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for finding in result.findings[:20]:
        location = f"{finding.workflow}:{finding.line}"
        if finding.job_id:
            location = f"{location} ({finding.job_id})"
        if finding.step_name:
            location = f"{location} / {finding.step_name}"
        findings.append(
            {
                "id": finding.id,
                "title": finding.title,
                "module": "CI/CD",
                "severity": finding.severity,
                "score": finding.score,
                "asset": location,
                "evidence": finding.evidence,
                "first_seen": result.generated_at[:16].replace("T", " "),
                "owner": "devops",
                "status": finding.recommendation,
            }
        )
    return findings


def log_audit_to_workspace_logs(result: LogAuditResult) -> list[dict[str, Any]]:
    return [
        {
            "time": finding.time,
            "source": finding.source,
            "event": finding.event,
            "severity": finding.severity,
            "signal": finding.signal,
            "confidence": finding.confidence,
        }
        for finding in result.findings[:80]
    ]


def log_audit_to_workspace_findings(result: LogAuditResult) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for finding in result.findings[:20]:
        asset_parts = [finding.source]
        if finding.src_ip:
            asset_parts.append(f"src={finding.src_ip}")
        if finding.dst_ip:
            asset_parts.append(f"dst={finding.dst_ip}")
        if finding.path:
            asset_parts.append(f"path={finding.path}")
        findings.append(
            {
                "id": finding.id,
                "title": f"{finding.signal}：{finding.title}",
                "module": "日志风险",
                "severity": finding.severity,
                "score": finding.score,
                "asset": " / ".join(asset_parts),
                "evidence": finding.evidence,
                "first_seen": finding.time[:16],
                "owner": "soc",
                "status": f"置信度 {round(finding.confidence * 100)}%，建议结合源 IP、账号和时间窗口复核。",
            }
        )
    return findings


def multimodal_payload_to_workspace_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    evidence_items = payload.get("evidence") if isinstance(payload.get("evidence"), list) else []
    for item in evidence_items:
        if not isinstance(item, dict):
            continue
        evidence_id = str(item.get("evidence_id") or "")
        source_name = str(item.get("original_filename") or item.get("filename") or evidence_id)
        findings = item.get("findings") if isinstance(item.get("findings"), list) else []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            entities = finding.get("entities") if isinstance(finding.get("entities"), list) else []
            entity_values = [
                str(entity.get("value") or entity.get("normalized") or "")
                for entity in entities
                if isinstance(entity, dict) and (entity.get("value") or entity.get("normalized"))
            ]
            results.append(
                {
                    "id": finding.get("id") or stable_fallback_id("MMF", evidence_id, finding.get("rule_id")),
                    "title": finding.get("title") or "多模态规则命中",
                    "module": "多模态证据",
                    "severity": finding.get("severity") or "medium",
                    "score": int(finding.get("score") or 0),
                    "asset": f"{source_name} ({evidence_id})",
                    "evidence": (
                        f"命中规则 {finding.get('rule_id') or '-'}；"
                        f"关键词：{', '.join(str(value) for value in (finding.get('matched_keywords') or [])) or '-'}；"
                        f"关联实体：{', '.join(entity_values[:8]) or '-'}。"
                    ),
                    "first_seen": str(finding.get("first_seen") or payload.get("generated_at") or "")[:16].replace("T", " "),
                    "owner": "soc",
                    "status": finding.get("recommendation") or "复核该多模态证据，并与日志、CI/CD 和 SBOM 证据交叉验证。",
                }
            )
    return sorted(results, key=lambda value: (-int(value.get("score") or 0), str(value.get("id") or "")))[:20]


def stable_fallback_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(part or "") for part in parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"


def augment_assistant_with_multimodal(payload: dict[str, Any]) -> None:
    assistant = payload.get("assistant") if isinstance(payload.get("assistant"), dict) else {}
    multimodal = payload.get("multimodal_audit") if isinstance(payload.get("multimodal_audit"), dict) else {}
    summary = multimodal.get("summary") if isinstance(multimodal.get("summary"), dict) else {}
    if not assistant or int(summary.get("evidence_count") or 0) <= 0:
        return
    evidence = [item for item in multimodal.get("evidence", []) if isinstance(item, dict)]
    entity_values: list[str] = []
    rule_values: list[str] = []
    for item in evidence:
        for entity in item.get("entities", []) if isinstance(item.get("entities"), list) else []:
            if isinstance(entity, dict) and entity.get("value"):
                entity_values.append(str(entity["value"]))
        for finding in item.get("findings", []) if isinstance(item.get("findings"), list) else []:
            if isinstance(finding, dict) and finding.get("rule_id"):
                rule_values.append(str(finding["rule_id"]))
    retrieval = list(assistant.get("retrieval") or [])
    retrieval.extend(
        [
            f"Multimodal: evidence={summary.get('evidence_count', 0)} entities={summary.get('entity_count', 0)} findings={summary.get('finding_count', 0)}",
            f"Multimodal entities: {', '.join(stable_unique_text(entity_values)[:8]) or '-'}",
            f"Multimodal rules: {', '.join(stable_unique_text(rule_values)[:5]) or '-'}",
        ]
    )
    assistant["retrieval"] = stable_unique_text(retrieval)
    next_actions = list(assistant.get("next_actions") or [])
    next_actions.insert(0, "将 OCR/ASR 识别到的依赖包、外联 IP、服务名和接口与 SBOM、CI/CD、日志同时间窗复核。")
    assistant["next_actions"] = stable_unique_text(next_actions)[:8]


def stable_unique_text(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        key = value.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result


def realtime_log_payload_to_workspace_logs(payload: dict[str, Any]) -> list[dict[str, Any]]:
    findings = payload.get("findings") if isinstance(payload.get("findings"), list) else []
    return [
        {
            "time": str(finding.get("time") or ""),
            "source": str(finding.get("source") or "app"),
            "event": str(finding.get("event") or finding.get("title") or "runtime log finding"),
            "severity": str(finding.get("severity") or "low"),
            "signal": str(finding.get("signal") or finding.get("title") or "日志风险"),
            "confidence": float(finding.get("confidence") or 0),
        }
        for finding in findings[:80]
        if isinstance(finding, dict)
    ]


def realtime_log_payload_to_workspace_findings(payload: dict[str, Any]) -> list[dict[str, Any]]:
    items = payload.get("findings") if isinstance(payload.get("findings"), list) else []
    findings: list[dict[str, Any]] = []
    for item in items[:20]:
        if not isinstance(item, dict):
            continue
        asset_parts = [str(item.get("source") or "app")]
        if item.get("src_ip"):
            asset_parts.append(f"src={item['src_ip']}")
        if item.get("dst_ip"):
            asset_parts.append(f"dst={item['dst_ip']}")
        if item.get("path"):
            asset_parts.append(f"path={item['path']}")
        confidence = float(item.get("confidence") or 0)
        findings.append(
            {
                "id": item.get("id") or f"LOGRT-{str(item.get('fingerprint') or '')[:8].upper()}",
                "title": f"{item.get('signal') or '日志风险'}：{item.get('title') or item.get('event') or '实时日志风险'}",
                "module": "日志风险",
                "severity": item.get("severity") or "low",
                "score": int(item.get("score") or 0),
                "asset": " / ".join(asset_parts),
                "evidence": item.get("evidence") or "",
                "first_seen": str(item.get("time") or "")[:16],
                "owner": "soc",
                "status": f"实时接入，置信度 {round(confidence * 100)}%，可建立基线或标记误报。",
            }
        )
    return findings


def apply_runtime_correlations(payload: dict[str, Any]) -> None:
    correlations = runtime_correlation_findings()
    if not correlations:
        return

    payload["findings"] = correlations + payload["findings"]
    payload["logs"] = boost_correlated_log_confidence(payload["logs"])
    payload["summary"]["open_findings"] = len(payload["findings"])
    payload["summary"]["critical_findings"] = sum(
        1 for finding in payload["findings"] if finding.get("severity") == "critical"
    )
    payload["summary"]["attack_paths"] = max(payload["summary"].get("attack_paths", 0), len(correlations))
    payload["summary"]["risk_score"] = max(
        payload["summary"].get("risk_score", 0),
        max(int(finding["score"]) for finding in correlations),
    )
    append_runtime_pipeline(payload, correlations)
    append_runtime_graph(payload, correlations)


def runtime_correlation_findings() -> list[dict[str, Any]]:
    log_findings = current_runtime_log_findings()
    if not log_findings:
        return []

    log_rule_ids = {str(finding.get("rule_id") or "") for finding in log_findings}
    high_log = next(
        (finding for finding in log_findings if finding.get("severity") in {"critical", "high"}),
        None,
    )
    first_seen = str(
        (high_log or {}).get("time")
        or (LAST_LOG_AUDIT.generated_at[:16].replace("T", " ") if LAST_LOG_AUDIT is not None else "")
    )
    runtime_compromise = bool(
        log_rule_ids & {"runtime.suspicious-egress-ip", "runtime.sensitive-export-path", "runtime.sensitive-admin-path"}
    )
    sqli_probe = "runtime.sql-injection-probe" in log_rule_ids
    credential_attack = {"runtime.401-403-burst", "runtime.brute-force"}.issubset(log_rule_ids)

    has_cicd_high = LAST_CICD_AUDIT is not None and LAST_CICD_AUDIT.summary.get("risk_level") in {"critical", "high"}
    has_dependency_high = (
        LAST_DEPENDENCY_AUDIT is not None
        and LAST_DEPENDENCY_AUDIT.summary.get("risk_level") in {"critical", "high"}
    )
    has_sql_code_risk = LAST_CODE_AUDIT is not None and any(
        "sql" in finding.rule_id.lower() or "SQL" in finding.category
        for finding in LAST_CODE_AUDIT.findings
    )

    correlations: list[dict[str, Any]] = []
    if runtime_compromise and has_cicd_high and has_dependency_high:
        correlations.append(
            make_correlation_finding(
                title="依赖与 CI/CD 风险后出现运行期外联/敏感接口访问",
                severity="critical",
                score=97,
                asset="dependency -> cicd -> runtime-log",
                evidence="依赖或构建链路存在高危信号，运行期日志随后命中异常外联或敏感接口访问，符合供应链投毒后的行为链。",
                first_seen=first_seen,
            )
        )
    elif runtime_compromise and has_cicd_high:
        correlations.append(
            make_correlation_finding(
                title="CI/CD 高危构建风险与运行期异常日志关联",
                severity="critical",
                score=94,
                asset="cicd -> runtime-log",
                evidence="CI/CD 扫描存在高危构建链路风险，运行期日志命中外联或敏感路径访问，应优先核查构建产物与发布窗口。",
                first_seen=first_seen,
            )
        )

    if sqli_probe and has_sql_code_risk:
        correlations.append(
            make_correlation_finding(
                title="代码 SQL 风险被运行期 SQL 注入探测命中",
                severity="high",
                score=89,
                asset="code-audit -> web-log",
                evidence="代码审计发现 SQL 拼接/注入相关风险，同时 access/app 日志出现 SQL 注入探测，说明静态风险已有真实攻击流量触达。",
                first_seen=first_seen,
            )
        )

    if credential_attack:
        correlations.append(
            make_correlation_finding(
                title="401/403 峰值与暴力破解形成凭据攻击链",
                severity="high",
                score=86,
                asset="auth-log -> web-log",
                evidence="短时间 401/403 暴增与认证失败聚合同时出现，符合凭据爆破或令牌探测场景。",
                first_seen=first_seen,
            )
        )

    return dedupe_workspace_findings(correlations)


def current_runtime_log_findings() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if LAST_LOG_AUDIT is not None:
        findings.extend(serialize_runtime_log_finding(finding) for finding in LAST_LOG_AUDIT.findings)
    realtime_payload = realtime_log_events(limit=50)
    realtime_findings = realtime_payload.get("findings")
    if isinstance(realtime_findings, list):
        findings.extend(item for item in realtime_findings if isinstance(item, dict))
    return findings


def serialize_runtime_log_finding(finding: Any) -> dict[str, Any]:
    return {
        "rule_id": getattr(finding, "rule_id", ""),
        "severity": getattr(finding, "severity", "low"),
        "time": getattr(finding, "time", ""),
        "signal": getattr(finding, "signal", ""),
        "evidence": getattr(finding, "evidence", ""),
    }


def make_correlation_finding(
    *,
    title: str,
    severity: str,
    score: int,
    asset: str,
    evidence: str,
    first_seen: str,
) -> dict[str, Any]:
    fingerprint = hashlib.sha1(f"{title}|{asset}|{evidence}".encode("utf-8")).hexdigest()[:8].upper()
    return {
        "id": f"CORR-{fingerprint}",
        "title": title,
        "module": "证据链",
        "severity": severity,
        "score": score,
        "asset": asset,
        "evidence": evidence,
        "first_seen": first_seen[:16],
        "owner": "soc",
        "status": "已跨模块关联，建议按证据链优先级处置。",
    }


def dedupe_workspace_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for finding in findings:
        finding_id = str(finding.get("id") or "")
        if finding_id in seen:
            continue
        seen.add(finding_id)
        result.append(finding)
    return result


def artifact_trust_module_status(level: str) -> str:
    if level == "trusted":
        return "active"
    if level == "warning":
        return "medium"
    if level == "danger":
        return "high"
    if level == "critical":
        return "critical"
    return "observed"


def artifact_trust_to_workspace_findings(result: ArtifactTrustResult) -> list[dict[str, Any]]:
    first_seen = result.generated_at[:16].replace("T", " ")
    return [
        {
            "id": finding.id,
            "title": finding.title,
            "module": "产物可信",
            "severity": finding.severity,
            "score": finding.score,
            "asset": result.artifact,
            "evidence": finding.evidence,
            "first_seen": first_seen,
            "owner": "release-engineering",
            "status": finding.recommendation,
        }
        for finding in result.findings
    ]


def append_artifact_trust_pipeline(payload: dict[str, Any], result: ArtifactTrustResult) -> None:
    provenance = result.provenance
    generated_at = result.generated_at[:16].replace("T", " ")
    chain = [
        {
            "step": "commit",
            "name": f"提交 {provenance.get('commit') or '-'}",
            "status": "observed",
            "detail": f"来源仓库 {provenance.get('source_repo') or '-'}，ref={provenance.get('ref') or '-'}。",
            "actor": "SLSA provenance",
            "time": generated_at,
        },
        {
            "step": "workflow",
            "name": provenance.get("workflow") or "release workflow",
            "status": check_status_for_pipeline(result, "workflow_allowed"),
            "detail": "产物 provenance 声明的 GitHub Actions workflow。",
            "actor": "GitHub Actions",
            "time": generated_at,
        },
        {
            "step": "build",
            "name": provenance.get("builder_id") or "builder",
            "status": check_status_for_pipeline(result, "builder_trusted"),
            "detail": f"builder.id={provenance.get('builder_id') or '-'}，runner={provenance.get('runner_environment') or '-'}。",
            "actor": "SLSA builder",
            "time": generated_at,
        },
        {
            "step": "artifact",
            "name": result.artifact,
            "status": check_status_for_pipeline(result, "artifact_digest_matches_subject"),
            "detail": f"{result.digest}，可信评分 {result.trust_score}/100。",
            "actor": "SupplyGuard Artifact Trust",
            "time": generated_at,
        },
        {
            "step": "attestation",
            "name": "provenance attestation",
            "status": check_status_for_pipeline(result, "signature_verified"),
            "detail": f"predicateType={provenance.get('predicateType') or provenance.get('predicate_type') or '-'}。",
            "actor": "gh/cosign",
            "time": generated_at,
        },
    ]
    payload["pipeline"] = chain + [step for step in payload.get("pipeline", []) if step.get("step") not in {"artifact", "attestation"}]


def check_status_for_pipeline(result: ArtifactTrustResult, check_name: str) -> str:
    check = next((item for item in result.checks if item.name == check_name), None)
    if check is None:
        return "observed"
    if check.status == "pass":
        return "active"
    if check.status in {"fail", "missing"}:
        return check.severity if check.severity != "low" else "medium"
    if check.status == "warn":
        return "medium"
    return "observed"


def parse_form_list(value: str | None) -> list[str] | None:
    if value is None:
        return None
    result = [
        item.strip()
        for item in value.replace("\n", ",").split(",")
        if item.strip()
    ]
    return result


def boost_correlated_log_confidence(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    boosted: list[dict[str, Any]] = []
    for log in logs:
        next_log = dict(log)
        if str(log.get("signal")) in {"异常外联 IP", "敏感路径访问", "SQL 注入探测", "暴力破解", "401/403 暴增"}:
            next_log["confidence"] = min(0.98, round(float(log.get("confidence") or 0) + 0.08, 2))
        boosted.append(next_log)
    return boosted


def append_runtime_pipeline(payload: dict[str, Any], correlations: list[dict[str, Any]]) -> None:
    if any(step.get("step") == "runtime-correlation" for step in payload["pipeline"]):
        return
    top = correlations[0]
    payload["pipeline"].append(
        {
            "step": "runtime-correlation",
            "name": "运行期证据关联",
            "status": top["severity"],
            "detail": top["evidence"],
            "actor": "SupplyGuard Correlation Engine",
            "time": top["first_seen"],
        }
    )


def append_runtime_graph(payload: dict[str, Any], correlations: list[dict[str, Any]]) -> None:
    graph = payload.get("graph") or {}
    nodes = graph.setdefault("nodes", [])
    edges = graph.setdefault("edges", [])
    existing_nodes = {node.get("id") for node in nodes}
    existing_edges = {edge.get("id") for edge in edges}

    if "attack_runtime" not in existing_nodes:
        nodes.append(
            {
                "id": "attack_runtime",
                "label": "运行期攻击阶段",
                "type": "攻击阶段",
                "risk": correlations[0]["severity"],
                "description": "由日志与代码、依赖、CI/CD 结果跨模块关联生成。",
            }
        )

    for index, finding in enumerate(current_runtime_log_findings()[:3], start=1):
        node_id = f"log_event_{index}"
        if node_id not in existing_nodes:
            nodes.append(
                {
                    "id": node_id,
                    "label": finding.get("signal") or "日志风险",
                    "type": "日志事件",
                    "risk": finding.get("severity") or "low",
                    "description": finding.get("evidence") or "",
                }
            )
        service_edge = f"runtime-service-log-{index}"
        attack_edge = f"runtime-log-attack-{index}"
        if service_edge not in existing_edges:
            edges.append({"id": service_edge, "source": "service", "target": node_id, "label": "产生"})
        if attack_edge not in existing_edges:
            edges.append({"id": attack_edge, "source": node_id, "target": "attack_runtime", "label": "映射到"})

    if any("cicd" in str(item.get("asset", "")).lower() for item in correlations):
        edge_id = "runtime-build-log-correlation"
        if edge_id not in existing_edges:
            edges.append({"id": edge_id, "source": "build", "target": "attack_runtime", "label": "关联到"})


def cicd_audit_to_pipeline(result: CICDAuditResult) -> list[dict[str, Any]]:
    if not result.workflows:
        return []

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top_findings = sorted(
        result.findings,
        key=lambda item: (-severity_order.get(item.severity, 0), -item.score, item.workflow, item.line),
    )[:4]
    generated_at = result.generated_at[:16].replace("T", " ")
    pipeline = [
        {
            "step": "workflow",
            "name": f"Workflow 扫描 {result.summary['workflow_count']} 个",
            "status": result.summary["risk_level"] if result.summary["finding_count"] else "observed",
            "detail": (
                f"识别 {result.summary['job_count']} 个 job、{result.summary['total_steps']} 个 step，"
                f"发现 {result.summary['finding_count']} 项构建流程风险。"
            ),
            "actor": "SupplyGuard CI/CD Audit",
            "time": generated_at,
        }
    ]
    for index, finding in enumerate(top_findings, start=1):
        pipeline.append(
            {
                "step": f"cicd-{index}",
                "name": finding.step_name or finding.job_name or finding.workflow,
                "status": finding.severity,
                "detail": f"{finding.workflow}:{finding.line} - {finding.reason}",
                "actor": finding.job_id or "workflow",
                "time": generated_at,
            }
        )
    return pipeline


@router.post("/workspaces")
@router.post("/workspaces/")
async def security_workspace_create(payload: WorkspaceCreateRequest) -> dict[str, Any]:
    import_record: dict[str, Any] | None = None
    if payload.import_id:
        try:
            import_record = load_import(payload.import_id)
        except ImportErrorDetail as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    workspace_override = workspace_override_from_import_record(import_record, preset=payload.preset, name=payload.name)
    return create_workspace(
        base_payload=build_workspace_payload(
            include_global_multimodal=import_record is None,
            workspace_override=workspace_override,
            import_record=import_record,
        ),
        import_record=import_record,
        preset=payload.preset,
        name=payload.name,
    )


def workspace_override_from_import_record(
    import_record: dict[str, Any] | None,
    *,
    preset: str | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    if not import_record:
        return {}
    source_ref = import_record.get("sourceRef") if isinstance(import_record.get("sourceRef"), dict) else {}
    source = import_record.get("source") if isinstance(import_record.get("source"), dict) else {}
    source_path = (
        source.get("url")
        or source_ref.get("url")
        or source_ref.get("path")
        or import_record.get("sourcePath")
        or import_record.get("path")
    )
    override = {
        "importId": import_record.get("importId"),
        "name": name or import_record.get("projectName"),
        "preset": preset,
        "sourceType": import_record.get("sourceType"),
        "source": source_ref or source or {"path": source_path},
        "repository": source_path,
        "build": f"{name or import_record.get('projectName') or 'workspace'} build",
        "runtime": f"{name or import_record.get('projectName') or 'workspace'} runtime",
    }
    return {key: value for key, value in override.items() if value not in (None, "")}


@router.get("/workspaces/latest")
@router.get("/workspaces/latest/")
async def security_workspace_latest() -> dict[str, Any]:
    return workspace_or_current()


@router.get("/workspaces/{workspace_id}")
@router.get("/workspaces/{workspace_id}/")
async def security_workspace_by_id(workspace_id: str) -> dict[str, Any]:
    return workspace_or_current(workspace_id)


@router.get("/workspace")
async def security_workspace() -> dict[str, Any]:
    return workspace_or_current()


@router.get("/report")
async def security_report() -> dict[str, str]:
    workspace = workspace_or_current()
    return {"format": "markdown", "content": workspace.get("report") or ""}


@router.get("/workspaces/{workspace_id}/report")
@router.get("/workspaces/{workspace_id}/report/")
async def security_workspace_report(workspace_id: str, format: str = Query(default="markdown", pattern="^(markdown|html)$")) -> dict[str, str]:
    workspace = workspace_or_current(workspace_id)
    if format == "html":
        content = workspace.get("report_html") or markdown_to_html(workspace.get("report") or "")
    else:
        content = workspace.get("report") or ""
    return {"format": format, "content": content}


@router.get("/workspaces/{workspace_id}/evidence-package")
@router.get("/workspaces/{workspace_id}/evidence-package/")
async def security_workspace_evidence_package(workspace_id: str) -> Response:
    package_path = Path("storage") / "workspaces" / workspace_id / f"{workspace_id}-evidence-package.zip"
    try:
        write_evidence_package(workspace_id, package_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="工作空间不存在") from exc
    return Response(
        content=package_path.read_bytes(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{workspace_id}-evidence-package.zip"'},
    )


@router.post("/workspaces/{workspace_id}/scan-suite")
@router.post("/workspaces/{workspace_id}/scan-suite/")
async def security_workspace_scan_suite(workspace_id: str, payload: ScanSuiteRequest) -> dict[str, Any]:
    """按比赛演示主线执行一轮供应链溯源扫描。"""

    global LAST_CODE_AUDIT
    global LAST_DEPENDENCY_AUDIT
    global LAST_CICD_AUDIT
    global LAST_ARTIFACT_TRUST
    global LAST_LOG_AUDIT

    errors: list[dict[str, str]] = []
    import_id = payload.import_id
    if import_id is None:
        existing = workspace_or_current(workspace_id)
        import_id = existing.get("workspace", {}).get("importId") or existing.get("import", {}).get("importId")

    if payload.include_code_audit:
        try:
            LAST_CODE_AUDIT = run_code_audit(
                CodeAuditRequest(importId=import_id, timeoutSeconds=payload.timeout_seconds),
                timeout_seconds=payload.timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - 一键溯源需要保留 partial 结果。
            errors.append({"module": "code_audit", "message": str(exc)})

    if payload.include_dependency_audit:
        try:
            LAST_DEPENDENCY_AUDIT = run_dependency_audit(
                DependencyAuditRequest(importId=import_id, includeOsv=True, includeCdxgen=False, includeCyclonedxPy=False)
            )
        except Exception as exc:  # noqa: BLE001
            errors.append({"module": "dependency_audit", "message": str(exc)})

    if payload.include_cicd_audit:
        try:
            LAST_CICD_AUDIT = run_cicd_audit(CICDAuditRequest(importId=import_id, includeZizmor=False, includeActionlint=False))
        except Exception as exc:  # noqa: BLE001
            errors.append({"module": "cicd_audit", "message": str(exc)})

    if payload.include_artifact_trust and payload.artifact_path and payload.attestation_path:
        try:
            LAST_ARTIFACT_TRUST = run_artifact_trust_scan(
                ArtifactTrustRequest(
                    artifactPath=payload.artifact_path,
                    attestationPath=payload.attestation_path,
                    expectedRepo=payload.expected_repo,
                    expectedCommit=payload.expected_commit,
                    allowedWorkflows=payload.allowed_workflows,
                    allowedBuilders=payload.allowed_builders,
                    allowSelfHostedRunner=payload.allow_self_hosted_runner,
                    requireSignature=payload.require_signature,
                    requireProvenance=True,
                    maxAgeHours=8760,
                )
            )
        except Exception as exc:  # noqa: BLE001
            errors.append({"module": "artifact_trust", "message": str(exc)})

    if payload.include_log_audit and payload.log_paths:
        try:
            log_inputs = []
            for path_text in payload.log_paths:
                path = Path(path_text)
                if not path.is_absolute():
                    path = Path.cwd() / path
                log_inputs.append(LogFileInput(filename=path.name, content=path.read_bytes(), source="auto"))
            LAST_LOG_AUDIT = run_log_audit(log_inputs)
        except Exception as exc:  # noqa: BLE001
            errors.append({"module": "log_audit", "message": str(exc)})

    workspace = persist_current_workspace(
        workspace_id,
        module_key="scan_suite",
        module_payload={
            "completedAt": datetime.now(UTC).isoformat(),
            "errors": errors,
            "partial": bool(errors),
        },
    )
    workspace["scanSuite"] = {"status": "partial" if errors else "completed", "errors": errors}
    save_workspace_snapshot(workspace, workspace_id=workspace_id, module_key="scan_suite", module_payload=workspace["scanSuite"])
    return workspace


def store_agent_job(run_id: str, payload: dict[str, Any]) -> None:
    with AGENT_JOB_LOCK:
        AGENT_JOBS[run_id] = deepcopy(payload)


def load_agent_job(run_id: str) -> dict[str, Any] | None:
    with AGENT_JOB_LOCK:
        job = AGENT_JOBS.get(run_id)
        return deepcopy(job) if job is not None else None


def latest_agent_job_payload() -> dict[str, Any] | None:
    with AGENT_JOB_LOCK:
        if LAST_AGENT_JOB_ID and LAST_AGENT_JOB_ID in AGENT_JOBS:
            return deepcopy(AGENT_JOBS[LAST_AGENT_JOB_ID])
        return None


def empty_agent_job_payload() -> dict[str, Any]:
    return {
        "runId": None,
        "status": "idle",
        "steps": [],
        "events": [],
        "summary": {
            "stepCount": 0,
            "success": 0,
            "skipped": 0,
            "failed": 0,
            "evidenceGapCount": 0,
            "riskScore": 0,
            "riskLevel": "low",
        },
        "evidenceGaps": [],
        "nextActions": [],
        "narrative": {
            "summary": "尚未执行 Agent 调查。",
            "timeline": [],
            "verdict": "等待执行",
            "confidence": 0,
            "keyEvidence": [],
            "defenseBrief": "",
        },
    }


def apply_agent_results(bundle: Any, workspace_id: str | None = None) -> dict[str, Any]:
    global LAST_CODE_AUDIT
    global LAST_DEPENDENCY_AUDIT
    global LAST_CICD_AUDIT
    global LAST_ARTIFACT_TRUST
    global LAST_LOG_AUDIT
    global LAST_AGENT_RUN

    if bundle.results.code_audit is not None:
        LAST_CODE_AUDIT = bundle.results.code_audit
    if bundle.results.dependency_audit is not None:
        LAST_DEPENDENCY_AUDIT = bundle.results.dependency_audit
    if bundle.results.cicd_audit is not None:
        LAST_CICD_AUDIT = bundle.results.cicd_audit
    if bundle.results.artifact_trust is not None:
        LAST_ARTIFACT_TRUST = bundle.results.artifact_trust
    if bundle.results.log_audit is not None:
        LAST_LOG_AUDIT = bundle.results.log_audit

    workspace = build_workspace_payload()
    result = {
        **bundle.payload,
        "workspace": workspace,
        "report": workspace.get("report") or "",
    }
    if workspace_id:
        result["workspaceId"] = workspace_id
        result["workspace"] = save_workspace_snapshot(
            workspace,
            workspace_id=workspace_id,
            module_key="agent",
            module_payload=bundle.payload,
        )
    LAST_AGENT_RUN = result
    return result


def run_agent_job_thread(run_id: str, payload: AgentRunRequest, workspace_id: str | None = None) -> None:
    def progress(snapshot: dict[str, Any]) -> None:
        if workspace_id:
            snapshot["workspaceId"] = workspace_id
        store_agent_job(run_id, snapshot)

    try:
        bundle = run_agent_backend(payload, run_id=run_id, progress=progress)
        result = apply_agent_results(bundle, workspace_id=workspace_id)
        store_agent_job(run_id, result)
    except Exception as exc:  # noqa: BLE001 - 任务接口需要把异常收敛成可查询状态。
        current = load_agent_job(run_id) or empty_agent_job_payload()
        current.update(
            {
                "runId": run_id,
                "status": "failed",
                "error": str(exc),
                "events": [
                    *(current.get("events") or []),
                    {
                        "id": f"evt-{len(current.get('events') or []) + 1:04d}",
                        "stepId": "agent",
                        "kind": "job_failed",
                        "level": "error",
                        "message": f"Agent 任务异常终止：{exc}",
                        "createdAt": datetime.now(UTC).isoformat(),
                    },
                ],
            }
        )
        store_agent_job(run_id, current)


@router.post("/agent/jobs")
@router.post("/agent/jobs/")
async def security_agent_create_job(payload: AgentRunRequest, request: Request) -> dict[str, Any]:
    """创建一个可轮询的 Agent 调查任务。"""

    global LAST_AGENT_JOB_ID
    workspace_id = await workspace_id_from_request(request)
    run_id = new_agent_run_id()
    LAST_AGENT_JOB_ID = run_id
    job = {
        **empty_agent_job_payload(),
        "runId": run_id,
        "workspaceId": workspace_id,
        "status": "queued",
        "startedAt": datetime.now(UTC).isoformat(),
        "input": payload.model_dump(by_alias=True),
        "events": [
            {
                "id": "evt-0001",
                "stepId": "agent",
                "kind": "job_queued",
                "level": "info",
                "message": "Agent 任务已进入队列，准备开始供应链溯源调查。",
                "createdAt": datetime.now(UTC).isoformat(),
            }
        ],
    }
    store_agent_job(run_id, job)
    worker = Thread(target=run_agent_job_thread, args=(run_id, payload, workspace_id), daemon=True)
    worker.start()
    return job


@router.get("/agent/jobs/latest")
@router.get("/agent/jobs/latest/")
async def security_agent_latest_job() -> dict[str, Any]:
    return latest_agent_job_payload() or empty_agent_job_payload()


@router.get("/agent/jobs/{run_id}")
@router.get("/agent/jobs/{run_id}/")
async def security_agent_job(run_id: str) -> dict[str, Any]:
    job = load_agent_job(run_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Agent 任务不存在")
    return job


@router.get("/agent/jobs/{run_id}/evidence-package")
@router.get("/agent/jobs/{run_id}/evidence-package/")
async def security_agent_evidence_package(run_id: str) -> Response:
    job = load_agent_job(run_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Agent 任务不存在")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("agent-run.json", json.dumps(job, ensure_ascii=False, indent=2, default=str))
        archive.writestr("evidence-gaps.json", json.dumps(job.get("evidenceGaps") or [], ensure_ascii=False, indent=2, default=str))
        archive.writestr("narrative.md", render_agent_narrative_markdown(job))
        archive.writestr("report.md", job.get("report") or build_workspace_payload().get("report") or "")
        workspace = job.get("workspace") if isinstance(job.get("workspace"), dict) else build_workspace_payload()
        archive.writestr("workspace.json", json.dumps(workspace, ensure_ascii=False, indent=2, default=str))
    buffer.seek(0)
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{run_id}-evidence-package.zip"'},
    )


def render_agent_narrative_markdown(job: dict[str, Any]) -> str:
    narrative = job.get("narrative") if isinstance(job.get("narrative"), dict) else {}
    timeline = narrative.get("timeline") if isinstance(narrative.get("timeline"), list) else []
    key_evidence = narrative.get("keyEvidence") if isinstance(narrative.get("keyEvidence"), list) else []
    return "\n".join(
        [
            "# Agent 调查叙事",
            "",
            f"- 任务：{job.get('runId') or '-'}",
            f"- 状态：{job.get('status') or '-'}",
            f"- 判断：{narrative.get('verdict') or '-'}",
            f"- 可信度：{narrative.get('confidence') or 0}%",
            "",
            "## 一句话结论",
            str(narrative.get("summary") or "暂无调查结论。"),
            "",
            "## 调查时间线",
            *(f"{index}. {item}" for index, item in enumerate(timeline, start=1)),
            "",
            "## 关键证据",
            *(f"- {item}" for item in key_evidence),
            "",
            "## 答辩讲解",
            str(narrative.get("defenseBrief") or ""),
        ]
    )


@router.post("/agent/run")
@router.post("/agent/run/")
async def security_agent_run(payload: AgentRunRequest, request: Request) -> dict[str, Any]:
    """同步执行 Agent 编排，并把成功结果写回当前工作台。"""

    workspace_id = await workspace_id_from_request(request)
    bundle = run_agent_backend(payload)
    return apply_agent_results(bundle, workspace_id=workspace_id)


@router.get("/agent/latest")
@router.get("/agent/latest/")
async def security_agent_latest() -> dict[str, Any]:
    if LAST_AGENT_RUN is None:
        return {
            "runId": None,
            "status": "idle",
            "steps": [],
            "summary": {
                "stepCount": 0,
                "success": 0,
                "skipped": 0,
                "failed": 0,
                "evidenceGapCount": 0,
                "riskScore": 0,
                "riskLevel": "low",
            },
            "evidenceGaps": [],
            "nextActions": [],
        }
    return LAST_AGENT_RUN


@router.post("/code-audit/scan")
async def code_audit_scan(payload: CodeAuditRequest, request: Request) -> dict[str, Any]:
    global LAST_CODE_AUDIT
    workspace_id = await workspace_id_from_request(request)
    try:
        LAST_CODE_AUDIT = run_code_audit(payload, timeout_seconds=DEFAULT_SCAN_TIMEOUT_SECONDS)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = serialize_code_audit(LAST_CODE_AUDIT) or {}
    if workspace_id:
        persist_current_workspace(workspace_id, module_key="code_audit", module_payload=result)
    return result


@router.get("/code-audit/latest")
async def code_audit_latest() -> dict[str, Any]:
    if LAST_CODE_AUDIT is None:
        return {"scan_id": None, "findings": [], "summary": {"total": 0}, "report": ""}
    return serialize_code_audit(LAST_CODE_AUDIT) or {}


@router.get("/code-audit/report")
async def code_audit_report() -> dict[str, str]:
    if LAST_CODE_AUDIT is None:
        return {"format": "markdown", "content": "# 代码安全审计报告\n\n尚未执行扫描。"}
    return {"format": "markdown", "content": LAST_CODE_AUDIT.report}


@router.get("/code-audit/sarif")
async def code_audit_sarif() -> dict[str, Any]:
    if LAST_CODE_AUDIT is None:
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "SupplyGuard Code Audit", "rules": []}},
                    "results": [],
                }
            ],
        }
    return LAST_CODE_AUDIT.sarif


@router.post("/dependencies/scan")
async def dependency_audit_scan(request: Request, payload: DependencyAuditRequest | None = None) -> dict[str, Any]:
    global LAST_DEPENDENCY_AUDIT
    workspace_id = await workspace_id_from_request(request)
    try:
        LAST_DEPENDENCY_AUDIT = run_dependency_audit(payload or DependencyAuditRequest())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = serialize_dependency_audit(LAST_DEPENDENCY_AUDIT) or {}
    if workspace_id:
        persist_current_workspace(workspace_id, module_key="dependency_audit", module_payload=result)
    return result


@router.get("/dependencies/latest")
async def dependency_audit_latest() -> dict[str, Any]:
    return serialize_dependency_audit(LAST_DEPENDENCY_AUDIT) or empty_dependency_audit_payload()


@router.get("/dependencies/sbom")
async def dependency_audit_sbom() -> dict[str, Any]:
    if LAST_DEPENDENCY_AUDIT is None:
        return empty_dependency_audit_payload()["sbom"]
    return LAST_DEPENDENCY_AUDIT.sbom


@router.get("/dependencies/vex")
async def dependency_audit_vex() -> dict[str, Any]:
    if LAST_DEPENDENCY_AUDIT is None:
        return empty_dependency_audit_payload()["vex"]
    return LAST_DEPENDENCY_AUDIT.vex


@router.get("/dependencies/report")
async def dependency_audit_report() -> dict[str, str]:
    if LAST_DEPENDENCY_AUDIT is None:
        return {"format": "markdown", "content": empty_dependency_audit_payload()["report"]}
    return {"format": "markdown", "content": LAST_DEPENDENCY_AUDIT.report}


@router.post("/cicd/scan")
@router.post("/cicd/scan/")
async def cicd_audit_scan(request: Request, payload: CICDAuditRequest | None = None) -> dict[str, Any]:
    global LAST_CICD_AUDIT
    workspace_id = await workspace_id_from_request(request)
    try:
        LAST_CICD_AUDIT = run_cicd_audit(payload or CICDAuditRequest())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = serialize_cicd_audit(LAST_CICD_AUDIT) or {}
    if workspace_id:
        persist_current_workspace(workspace_id, module_key="cicd_audit", module_payload=result)
    return result


@router.get("/cicd/scan")
@router.get("/cicd/scan/")
async def cicd_audit_scan_get() -> dict[str, Any]:
    # Compatibility for browser/form GETs; the UI still uses POST.
    global LAST_CICD_AUDIT
    LAST_CICD_AUDIT = run_cicd_audit(CICDAuditRequest())
    return serialize_cicd_audit(LAST_CICD_AUDIT) or {}


@router.get("/cicd/latest")
async def cicd_audit_latest() -> dict[str, Any]:
    return serialize_cicd_audit(LAST_CICD_AUDIT) or empty_cicd_audit_payload()


@router.get("/cicd/report")
async def cicd_audit_report() -> dict[str, str]:
    if LAST_CICD_AUDIT is None:
        return {"format": "markdown", "content": empty_cicd_audit_payload()["report"]}
    return {"format": "markdown", "content": LAST_CICD_AUDIT.report}


@router.get("/cicd/sarif")
async def cicd_audit_sarif() -> dict[str, Any]:
    if LAST_CICD_AUDIT is None:
        return build_cicd_sarif([], {"projectName": "workspace"})
    return LAST_CICD_AUDIT.sarif


@router.post("/artifact-trust/scan")
@router.post("/artifact-trust/scan/")
async def artifact_trust_scan(request: Request, payload: ArtifactTrustRequest | None = None) -> dict[str, Any]:
    global LAST_ARTIFACT_TRUST
    workspace_id = await workspace_id_from_request(request)
    try:
        LAST_ARTIFACT_TRUST = run_artifact_trust_scan(payload or ArtifactTrustRequest())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = serialize_artifact_trust(LAST_ARTIFACT_TRUST) or {}
    if workspace_id:
        persist_current_workspace(workspace_id, module_key="artifact_trust", module_payload=result)
    return result


@router.post("/artifact-trust/upload")
@router.post("/artifact-trust/upload/")
async def artifact_trust_upload(
    artifact: UploadFile = File(...),
    attestation: UploadFile = File(...),
    expectedRepo: str | None = Form(default=None),
    expectedCommit: str | None = Form(default=None),
    allowedBranches: str | None = Form(default=None),
    allowedWorkflows: str | None = Form(default=None),
    allowedBuilders: str | None = Form(default=None),
    requireSignature: bool | None = Form(default=None),
    requireProvenance: bool | None = Form(default=None),
    allowSelfHostedRunner: bool | None = Form(default=None),
    maxAgeHours: int | None = Form(default=None),
    workspaceId: str | None = Form(default=None),
) -> dict[str, Any]:
    global LAST_ARTIFACT_TRUST
    try:
        artifact_path = save_upload_file(artifact.filename or "artifact.bin", await artifact.read(), prefix="artifact")
        attestation_path = save_upload_file(
            attestation.filename or "attestation.jsonl",
            await attestation.read(),
            prefix="attestation",
        )
        LAST_ARTIFACT_TRUST = run_artifact_trust_scan(
            ArtifactTrustRequest(
                artifactPath=str(artifact_path),
                attestationPath=str(attestation_path),
                expectedRepo=expectedRepo,
                expectedCommit=expectedCommit,
                allowedBranches=parse_form_list(allowedBranches),
                allowedWorkflows=parse_form_list(allowedWorkflows),
                allowedBuilders=parse_form_list(allowedBuilders),
                requireSignature=requireSignature,
                requireProvenance=requireProvenance,
                allowSelfHostedRunner=allowSelfHostedRunner,
                maxAgeHours=maxAgeHours,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = serialize_artifact_trust(LAST_ARTIFACT_TRUST) or {}
    if workspaceId:
        persist_current_workspace(workspaceId, module_key="artifact_trust", module_payload=result)
    return result


@router.get("/artifact-trust/latest")
@router.get("/artifact-trust/latest/")
async def artifact_trust_latest() -> dict[str, Any]:
    return serialize_artifact_trust(LAST_ARTIFACT_TRUST) or empty_artifact_trust_payload()


@router.get("/artifact-trust/report")
@router.get("/artifact-trust/report/")
async def artifact_trust_report() -> dict[str, str]:
    if LAST_ARTIFACT_TRUST is None:
        return {"format": "markdown", "content": empty_artifact_trust_payload()["report"]}
    return {"format": "markdown", "content": LAST_ARTIFACT_TRUST.report}


@router.post("/multimodal/scan")
@router.post("/multimodal/scan/")
async def multimodal_audit_scan(
    files: list[UploadFile] | None = File(default=None),
    file: UploadFile | None = File(default=None),
    workspaceId: str | None = Form(default=None),
) -> dict[str, Any]:
    global LAST_MULTIMODAL_AUDIT
    uploads = list(files or [])
    if file is not None:
        uploads.append(file)
    try:
        inputs = [
            MultimodalFileInput(
                filename=upload.filename or f"multimodal-{index + 1}.bin",
                content=await upload.read(),
                content_type=upload.content_type,
            )
            for index, upload in enumerate(uploads)
        ]
        LAST_MULTIMODAL_AUDIT = run_multimodal_audit(inputs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = latest_multimodal_payload(limit=500)
    if workspaceId:
        persist_current_workspace(workspaceId, module_key="multimodal_audit", module_payload=result)
    return result


@router.post("/multimodal/analyze-text")
@router.post("/multimodal/analyze-text/")
async def multimodal_text_analyze(payload: MultimodalTextAnalyzeRequest, request: Request) -> dict[str, Any]:
    global LAST_MULTIMODAL_AUDIT
    workspace_id = await workspace_id_from_request(request)
    evidence_type = payload.evidence_type or ("audio_asr" if payload.source_type == "audio" else "visual_ocr")
    try:
        LAST_MULTIMODAL_AUDIT = run_multimodal_text_audit(
            [
                MultimodalTextInput(
                    recognized_text=payload.recognized_text,
                    source_type=payload.source_type,
                    evidence_type=evidence_type,
                    source_name=payload.source_name,
                    confidence=payload.confidence,
                    engine=payload.engine,
                    language=payload.language,
                )
            ]
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = latest_multimodal_payload(limit=500)
    if workspace_id:
        persist_current_workspace(workspace_id, module_key="multimodal_audit", module_payload=result)
    return result


@router.get("/multimodal/latest")
@router.get("/multimodal/latest/")
async def multimodal_audit_latest(limit: int = Query(default=100, ge=1, le=500)) -> dict[str, Any]:
    return latest_multimodal_payload(limit=limit)


@router.get("/multimodal/report")
@router.get("/multimodal/report/")
async def multimodal_audit_report() -> dict[str, str]:
    return {"format": "markdown", "content": latest_multimodal_payload()["report"]}


@router.get("/cicd/state")
async def cicd_audit_state() -> dict[str, Any]:
    return cicd_audit_state_payload(LAST_CICD_AUDIT.target if LAST_CICD_AUDIT is not None else None)


@router.post("/cicd/ignore")
async def cicd_audit_ignore(payload: IgnoreFindingRequest) -> dict[str, Any]:
    global LAST_CICD_AUDIT
    finding = None
    if LAST_CICD_AUDIT is not None:
        finding = next((item for item in LAST_CICD_AUDIT.findings if item.fingerprint == payload.fingerprint), None)
    state = add_cicd_ignored_finding(
        payload.fingerprint,
        reason=payload.reason,
        target_info=LAST_CICD_AUDIT.target if LAST_CICD_AUDIT is not None else None,
        finding=finding,
    )
    if LAST_CICD_AUDIT is not None:
        LAST_CICD_AUDIT = refresh_cicd_audit_result(LAST_CICD_AUDIT)
    return {"state": state, "cicd_audit": serialize_cicd_audit(LAST_CICD_AUDIT)}


@router.delete("/cicd/ignore/{fingerprint}")
async def cicd_audit_unignore(fingerprint: str) -> dict[str, Any]:
    global LAST_CICD_AUDIT
    state = remove_cicd_ignored_finding(
        fingerprint,
        target_info=LAST_CICD_AUDIT.target if LAST_CICD_AUDIT is not None else None,
    )
    if LAST_CICD_AUDIT is not None:
        LAST_CICD_AUDIT = refresh_cicd_audit_result(LAST_CICD_AUDIT)
    return {"state": state, "cicd_audit": serialize_cicd_audit(LAST_CICD_AUDIT)}


@router.post("/cicd/baseline")
async def cicd_audit_baseline(payload: BaselineRequest) -> dict[str, Any]:
    global LAST_CICD_AUDIT
    if LAST_CICD_AUDIT is None:
        raise HTTPException(status_code=400, detail="Run a CI/CD scan before creating a baseline.")
    state = create_cicd_audit_baseline(LAST_CICD_AUDIT, note=payload.note)
    LAST_CICD_AUDIT = refresh_cicd_audit_result(LAST_CICD_AUDIT)
    return {"state": state, "cicd_audit": serialize_cicd_audit(LAST_CICD_AUDIT)}


@router.post("/cicd/github/code-scanning")
async def cicd_audit_github_code_scanning(payload: GitHubCodeScanningUploadRequest) -> dict[str, Any]:
    if LAST_CICD_AUDIT is None:
        raise HTTPException(status_code=400, detail="Run a CI/CD scan before uploading SARIF.")
    try:
        return upload_cicd_sarif_to_github(LAST_CICD_AUDIT, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def upload_cicd_sarif_to_github(
    result: CICDAuditResult,
    payload: GitHubCodeScanningUploadRequest,
) -> dict[str, Any]:
    commit_sha = payload.commit_sha or git_current_commit()
    if not commit_sha:
        raise ValueError("Unable to resolve commit SHA. Provide commit_sha in the request.")
    request_payload: dict[str, Any] = {
        "commit_sha": commit_sha,
        "ref": payload.ref or git_current_ref(),
        "sarif": sarif_upload_content(result.sarif),
        "checkout_uri": payload.checkout_uri or git_checkout_uri(),
        "tool_name": "SupplyGuard CI/CD Audit",
        "started_at": result.generated_at,
    }
    request_payload = {key: value for key, value in request_payload.items() if value is not None}
    token = github_token(payload.token)
    owner = quote(payload.owner, safe="")
    repo = quote(payload.repo, safe="")
    response = github_request("POST", f"/repos/{owner}/{repo}/code-scanning/sarifs", token, request_payload)
    return {
        "repository": f"{payload.owner}/{payload.repo}",
        "ref": request_payload["ref"],
        "commit_sha": commit_sha,
        "sarif_id": response.get("id"),
        "url": response.get("url"),
        "status": response.get("processing_status") or "pending",
        "raw": response,
    }


@router.post("/logs/scan")
@router.post("/logs/scan/")
async def log_audit_scan(
    files: list[UploadFile] = File(...),
    source: str | None = Form(default=None),
    sources: list[str] | None = Form(default=None),
    workspaceId: str | None = Form(default=None),
) -> dict[str, Any]:
    global LAST_LOG_AUDIT
    try:
        inputs: list[LogFileInput] = []
        for index, upload in enumerate(files):
            content = await upload.read()
            item_source = source
            if sources and index < len(sources):
                item_source = sources[index]
            inputs.append(
                LogFileInput(
                    filename=upload.filename or f"log-{index + 1}.log",
                    content=content,
                    source=item_source,
                )
            )
        LAST_LOG_AUDIT = run_log_audit(inputs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = serialize_log_audit(LAST_LOG_AUDIT) or {}
    if workspaceId:
        persist_current_workspace(workspaceId, module_key="log_audit", module_payload=result)
    return result


@router.get("/logs/scan")
@router.get("/logs/scan/")
async def log_audit_scan_get() -> dict[str, Any]:
    payload = serialize_log_audit(LAST_LOG_AUDIT) or empty_log_audit_payload()
    warnings = list(payload.get("warnings") or [])
    warnings.append("日志扫描需要使用 POST multipart/form-data 上传 files 字段。")
    payload["warnings"] = warnings
    return payload


@router.get("/logs/latest")
async def log_audit_latest() -> dict[str, Any]:
    return serialize_log_audit(LAST_LOG_AUDIT) or empty_log_audit_payload()


@router.get("/logs/report")
async def log_audit_report() -> dict[str, str]:
    if LAST_LOG_AUDIT is None:
        return {"format": "markdown", "content": empty_log_audit_payload()["report"]}
    return {"format": "markdown", "content": LAST_LOG_AUDIT.report}


@router.post("/logs/ingest")
@router.post("/logs/ingest/")
async def log_realtime_ingest(request: Request) -> dict[str, Any]:
    try:
        payload = await parse_log_ingest_request(request)
        return ingest_realtime_logs(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def parse_log_ingest_request(request: Request) -> Any:
    raw = await request.body()
    if not raw:
        raise ValueError("Log ingest body is empty.")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass

    text = raw.decode("utf-8", errors="replace")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON or NDJSON at line {line_number}: {exc.msg}.") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"NDJSON line {line_number} must be a JSON object.")
        records.append(payload)
    return records


@router.get("/logs/events")
@router.get("/logs/events/")
async def log_realtime_events(
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict[str, Any]:
    return realtime_log_events(limit=limit)


@router.get("/logs/trend")
@router.get("/logs/trend/")
async def log_realtime_trend(
    granularity: str = Query(default="minute", pattern="^(minute|hour)$"),
    buckets: int = Query(default=60, ge=1, le=168),
) -> dict[str, Any]:
    return realtime_log_trend(granularity=granularity, buckets=buckets)


@router.post("/logs/baseline")
@router.post("/logs/baseline/")
async def log_realtime_baseline(payload: BaselineRequest) -> dict[str, Any]:
    return create_realtime_log_baseline(payload.note)


@router.post("/logs/ignore")
@router.post("/logs/ignore/")
async def log_realtime_ignore(payload: LogIgnoreRequest) -> dict[str, Any]:
    try:
        return ignore_realtime_log_finding(payload.fingerprint, payload.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/code-audit/github/code-scanning")
async def code_audit_github_code_scanning(payload: GitHubCodeScanningUploadRequest) -> dict[str, Any]:
    if LAST_CODE_AUDIT is None:
        raise HTTPException(status_code=400, detail="Run a code audit scan before uploading SARIF.")
    try:
        return upload_code_scanning_sarif(LAST_CODE_AUDIT, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/code-audit/github/code-scanning/status")
async def code_audit_github_code_scanning_status(payload: GitHubCodeScanningStatusRequest) -> dict[str, Any]:
    try:
        return code_scanning_sarif_status(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/code-audit/state")
async def code_audit_state() -> dict[str, Any]:
    return audit_state_payload(LAST_CODE_AUDIT.target if LAST_CODE_AUDIT is not None else None)


@router.get("/code-audit/trend")
async def code_audit_trend() -> dict[str, Any]:
    state = audit_state_payload(LAST_CODE_AUDIT.target if LAST_CODE_AUDIT is not None else None)
    return {"trend": state["trend"]}


@router.post("/code-audit/ignore")
async def code_audit_ignore(payload: IgnoreFindingRequest) -> dict[str, Any]:
    global LAST_CODE_AUDIT
    finding = None
    if LAST_CODE_AUDIT is not None:
        finding = next(
            (item for item in LAST_CODE_AUDIT.findings if item.fingerprint == payload.fingerprint),
            None,
        )
    state = add_ignored_finding(
        payload.fingerprint,
        reason=payload.reason,
        target_info=LAST_CODE_AUDIT.target if LAST_CODE_AUDIT is not None else None,
        finding=finding,
    )
    if LAST_CODE_AUDIT is not None:
        LAST_CODE_AUDIT = refresh_audit_result(LAST_CODE_AUDIT)
    return {"state": state, "code_audit": serialize_code_audit(LAST_CODE_AUDIT)}


@router.delete("/code-audit/ignore/{fingerprint}")
async def code_audit_unignore(fingerprint: str) -> dict[str, Any]:
    global LAST_CODE_AUDIT
    state = remove_ignored_finding(
        fingerprint,
        target_info=LAST_CODE_AUDIT.target if LAST_CODE_AUDIT is not None else None,
    )
    if LAST_CODE_AUDIT is not None:
        LAST_CODE_AUDIT = refresh_audit_result(LAST_CODE_AUDIT)
    return {"state": state, "code_audit": serialize_code_audit(LAST_CODE_AUDIT)}


@router.post("/code-audit/baseline")
async def code_audit_baseline(payload: BaselineRequest) -> dict[str, Any]:
    global LAST_CODE_AUDIT
    if LAST_CODE_AUDIT is None:
        raise HTTPException(status_code=400, detail="Run a code audit scan before creating a baseline.")
    state = create_audit_baseline(LAST_CODE_AUDIT, note=payload.note)
    LAST_CODE_AUDIT = refresh_audit_result(LAST_CODE_AUDIT)
    return {"state": state, "code_audit": serialize_code_audit(LAST_CODE_AUDIT)}


@router.post("/assistant")
async def security_assistant(payload: AssistantQuestion) -> dict[str, Any]:
    question = payload.question.strip()
    workspace = build_workspace_payload()
    base = workspace["assistant"]
    try:
        deepseek_answer = await ask_deepseek_security_assistant(question, workspace, base["retrieval"])
    except (httpx.HTTPError, ValueError):
        deepseek_answer = None

    if deepseek_answer is not None:
        return {
            "question": question,
            "answer": deepseek_answer["answer"],
            "retrieval": base["retrieval"],
            "next_actions": base["next_actions"],
            "model": deepseek_answer["model"],
        }

    answer = fallback_assistant_answer(question, base["answer"], workspace)

    return {
        "question": question,
        "answer": answer,
        "retrieval": base["retrieval"],
        "next_actions": base["next_actions"],
        "model": "demo-rag-security-analyst",
    }


def fallback_assistant_answer(question: str, default_answer: str, workspace: dict[str, Any] | None = None) -> str:
    lower_question = question.lower()
    path = primary_attack_path(workspace or {})
    if path:
        conclusion = str(path.get("conclusion") or path.get("description") or "")
        confidence = round(float(path.get("confidence") or 0) * 100)
        gaps = path.get("gaps") if isinstance(path.get("gaps"), list) else []
        gap_text = "；".join(str(item) for item in gaps[:2]) or "当前路径未发现明显证据缺口。"
        steps = path.get("path_steps") if isinstance(path.get("path_steps"), list) else []
        step_text = " -> ".join(
            str(step.get("source") or step.get("target") or "")
            for step in steps
            if isinstance(step, dict)
        )

    multimodal_answer = multimodal_corroboration_answer(question, workspace or {})
    if multimodal_answer and (
        "误报" in question
        or "不是误报" in question
        or "多模态" in question
        or "截图" in question
        or "语音" in question
        or "ocr" in lower_question
        or "asr" in lower_question
    ):
        return multimodal_answer

    if "误报" in question or "false" in lower_question:
        dependency_audit = workspace.get("dependency_audit") if isinstance(workspace.get("dependency_audit"), dict) else {}
        dependency_summary = dependency_audit.get("summary") if isinstance(dependency_audit.get("summary"), dict) else {}
        vex_summary = dependency_summary.get("vex") if isinstance(dependency_summary.get("vex"), dict) else {}
        if vex_summary:
            affected = int(vex_summary.get("affected") or 0)
            not_affected = int(vex_summary.get("not_affected") or 0)
            fixed = int(vex_summary.get("fixed") or 0)
            investigation = int(vex_summary.get("under_investigation") or 0)
            return (
                f"当前 VEX 降噪结论：affected {affected} 条，under_investigation {investigation} 条，"
                f"not_affected/fixed {not_affected + fixed} 条。建议优先处理 affected；"
                "not_affected 需要保留代码不可达、服务未暴露或日志无痕迹的证据，代码 import/路由/日志变化后重新生成 VEX。"
            )
        if path:
            return f"误报概率取决于证据缺口。当前路径判定为 {path.get('verdict')}，置信度 {confidence}%。{conclusion} 需要重点复核：{gap_text}"
        return "误报概率需要结合路径证据判断：至少要有入口、可达关系、运行期行为或 provenance 证据。当前还没有足够图谱路径可判定。"
    elif "替换" in question or "依赖" in question or "package" in lower_question:
        if path:
            return f"先处理路径入口中的高风险依赖或构建步骤。当前首要路径是“{path.get('title')}”，置信度 {confidence}%。处置建议：{path.get('recommendation')}"
        return "建议替换或隔离 @acme/payments-helper@9.9.2。短期把解析源固定到内部制品库，中期启用包名保留、scope 强制和 SBOM 准入策略。"
    elif "攻击链" in question or "链路" in question or "path" in lower_question:
        if path:
            return f"{conclusion} 路径大致为：{step_text or '入口 -> 构建 -> 产物 -> 运行期目标'}。证据缺口：{gap_text}"
        return "当前证据还不能串成真实攻击路径。需要补齐 GUAC 式软件依赖可达关系、in-toto/SLSA 构建 provenance，以及运行期日志或目标资产触达证据。"
    return default_answer


def multimodal_corroboration_answer(question: str, workspace: dict[str, Any]) -> str | None:
    multimodal = workspace.get("multimodal_audit") if isinstance(workspace.get("multimodal_audit"), dict) else {}
    summary = multimodal.get("summary") if isinstance(multimodal.get("summary"), dict) else {}
    if int(summary.get("evidence_count") or 0) <= 0:
        return None
    evidence = [item for item in multimodal.get("evidence", []) if isinstance(item, dict)]
    entities_by_type: dict[str, list[str]] = {}
    rules: list[str] = []
    source_types: set[str] = set()
    for item in evidence:
        source_types.add(str(item.get("source_type") or "multimodal"))
        for entity in item.get("entities", []) if isinstance(item.get("entities"), list) else []:
            if isinstance(entity, dict) and entity.get("value"):
                entities_by_type.setdefault(str(entity.get("type") or "entity"), []).append(str(entity["value"]))
        for finding in item.get("findings", []) if isinstance(item.get("findings"), list) else []:
            if isinstance(finding, dict) and finding.get("rule_id"):
                rules.append(str(finding["rule_id"]))
    ip_values = stable_unique_text(entities_by_type.get("ip", []))
    package_values = stable_unique_text(entities_by_type.get("package", []))
    service_values = stable_unique_text(entities_by_type.get("service", []))
    api_values = stable_unique_text(entities_by_type.get("api_path", []))
    action_values = stable_unique_text(entities_by_type.get("action", []))
    log_hits = [
        log for log in workspace.get("logs", [])
        if isinstance(log, dict)
        and any(value and value in str(log.get("event") or "") for value in ip_values + api_values + service_values)
    ]
    source_label = "、".join(sorted(source_types)) or "多模态"
    log_text = "运行日志中也出现相同 IP、服务或接口。" if log_hits else "当前多模态证据已成链，但还需要补充同时间窗运行日志来进一步降低误报。"
    return (
        f"不是只靠一段文字下结论。当前 {source_label} 证据共 {summary.get('evidence_count', 0)} 条，"
        f"抽取到 {summary.get('entity_count', 0)} 个安全实体，命中 {summary.get('finding_count', 0)} 条规则，"
        f"最高风险 {summary.get('risk_score', 0)}。"
        f"OCR/ASR 证据显示构建阶段存在 {', '.join(action_values[:4]) or '可疑行为'}，"
        f"关联依赖 {', '.join(package_values[:3]) or '-'}，"
        f"外联目标 {', '.join(ip_values[:3]) or '-'}，"
        f"服务/接口 {', '.join((service_values + api_values)[:4]) or '-'}。"
        f"{log_text} "
        f"因此它更像跨模态证据互相印证的供应链攻击路径，而不是单点 OCR/ASR 误报。"
        f"命中规则：{', '.join(stable_unique_text(rules)[:5]) or '-'}。"
    )


def primary_attack_path(workspace: dict[str, Any]) -> dict[str, Any] | None:
    graph = workspace.get("graph") if isinstance(workspace.get("graph"), dict) else {}
    paths = graph.get("attack_paths") if isinstance(graph.get("attack_paths"), list) else []
    for path in paths:
        if isinstance(path, dict):
            return path
    return None
