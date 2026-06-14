"""Unified fact input layer for the SupplyGuard knowledge graph.

This module implements step 1 of the knowledge-graph pipeline: normalize all
scanner results into a small Asset / Evidence / Finding model.

The mapping intentionally follows common open-source security data shapes:
- CycloneDX-style assets for components, services, dependencies, and SBOM facts.
- SARIF-style findings for rules, locations, fingerprints, and recommendations.
- DefectDojo-style triage fields for severity, status, source, and evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
from typing import Any, Iterable

from .artifact_trust import ArtifactTrustResult
from .cicd_audit import CICDAuditResult
from .code_audit import CodeAuditResult
from .dependency_audit import DependencyAuditResult
from .log_audit import LogAuditResult


SCHEMA_VERSION = "supplyguard.fact-input.v1"
GRAPH_SCHEMA_VERSION = "supplyguard.knowledge-graph.v1"

REFERENCE_MODELS: list[dict[str, Any]] = [
    {
        "name": "CycloneDX",
        "url": "https://cyclonedx.org/specification/overview/",
        "used_for": ["DependencyPackage", "BuildArtifact", "SBOM component and dependency evidence"],
    },
    {
        "name": "SARIF",
        "url": "https://www.oasis-open.org/standard/sarif-v2-1-0/",
        "used_for": ["CodeFile finding location", "CI/CD finding location", "fingerprint"],
    },
    {
        "name": "OWASP Dependency-Track",
        "url": "https://dependencytrack.org/",
        "used_for": ["SBOM-first component risk inventory", "dependency vulnerability triage"],
    },
    {
        "name": "DefectDojo",
        "url": "https://docs.defectdojo.com/",
        "used_for": ["Finding import", "deduplication", "prioritized triage", "reporting"],
    },
    {
        "name": "FFmpeg",
        "url": "https://www.ffmpeg.org/index.html",
        "used_for": ["audio normalization", "video frame extraction", "multimodal evidence metadata"],
    },
    {
        "name": "OpenCV",
        "url": "https://opencv.org/about/",
        "used_for": ["image preprocessing", "video frame metadata", "multimodal evidence enrichment"],
    },
]

GRAPH_REFERENCE_MODELS: list[dict[str, Any]] = [
    {
        "name": "GUAC",
        "url": "https://docs.guac.sh/guac/",
        "used_for": ["software tree / evidence tree / actor tree", "reachable supply-chain attack paths"],
    },
    {
        "name": "GUAC Ontology",
        "url": "https://docs.guac.sh/guac/guac-ontology/",
        "used_for": ["supply-chain node and edge semantics"],
    },
    {
        "name": "MITRE ATT&CK STIX Data",
        "url": "https://github.com/mitre-attack/attack-stix-data",
        "used_for": ["AttackStage mapping", "technique/tactic context"],
    },
    {
        "name": "SLSA",
        "url": "https://slsa.dev/spec/v1.2/provenance",
        "used_for": ["provenance predicate", "subject / materials / builder trust checks"],
    },
    {
        "name": "in-toto",
        "url": "https://github.com/in-toto/in-toto",
        "used_for": ["layout / link metadata", "materials to products evidence chain"],
    },
    {
        "name": "BloodHound CE",
        "url": "https://specterops.io/bloodhound-community-edition/",
        "used_for": ["attack-path style source-to-target presentation", "abusable relationship prioritization"],
    },
    {
        "name": "NetworkX",
        "url": "https://networkx.org/",
        "used_for": ["MVP path-scoring model and future graph algorithms"],
    },
    {
        "name": "React Flow",
        "url": "https://reactflow.dev/",
        "used_for": ["interactive frontend node-edge visualization"],
    },
]

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
NODE_TYPE_RANK = {
    "CodeFile": 0,
    "DependencyPackage": 1,
    "Vulnerability": 2,
    "CIWorkflow": 3,
    "CIStep": 3,
    "BuildArtifact": 4,
    "Attestation": 5,
    "TrustedBuilder": 6,
    "Workflow": 3,
    "SourceCommit": 2,
    "TrustFinding": 8,
    "RuntimeService": 7,
    "LogEvent": 8,
    "AudioEvidence": 8,
    "VisualEvidence": 8,
    "MultimodalEvidence": 8,
    "MultimodalFinding": 8,
    "RecognizedEntity": 8,
    "AttackStage": 9,
    "Finding": 8,
    "EvidenceChain": 10,
    "Asset": 11,
}


@dataclass
class FactAsset:
    id: str
    type: str
    label: str
    source: str
    source_model: str
    risk_score: int = 0
    risk_level: str = "low"
    locator: dict[str, Any] = field(default_factory=dict)
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class FactEvidence:
    id: str
    source: str
    source_model: str
    kind: str
    title: str
    detail: str
    asset_id: str | None = None
    time: str | None = None
    locator: dict[str, Any] = field(default_factory=dict)
    confidence: float | None = None
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class FactFinding:
    id: str
    title: str
    severity: str
    score: int
    source: str
    source_model: str
    asset_ids: list[str]
    evidence_ids: list[str]
    fingerprint: str
    recommendation: str
    category: str = ""
    first_seen: str = ""
    status: str = ""
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphNode:
    id: str
    label: str
    type: str
    risk: str
    description: str
    score: int = 0
    source: str = ""
    source_model: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)
    position: dict[str, int] = field(default_factory=dict)


@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    type: str
    label: str
    confidence: float = 0.75
    reason: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    id: str
    title: str
    category: str
    severity: str
    score: int
    description: str
    conclusion: str
    verdict: str
    confidence: float
    entry_node_id: str
    target_node_id: str
    node_ids: list[str]
    edge_ids: list[str]
    evidence_ids: list[str]
    recommendation: str
    path_steps: list[dict[str, Any]] = field(default_factory=list)
    evidence_summary: list[dict[str, Any]] = field(default_factory=list)
    trust_chain: list[dict[str, Any]] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)
    trust_score: int | None = None
    gaps: list[str] = field(default_factory=list)
    choke_points: list[dict[str, Any]] = field(default_factory=list)
    mappings: list[dict[str, Any]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


class FactBuilder:
    def __init__(self) -> None:
        self.assets: dict[str, FactAsset] = {}
        self.evidence: dict[str, FactEvidence] = {}
        self.findings: dict[str, FactFinding] = {}

    def add_asset(self, asset: FactAsset) -> str:
        existing = self.assets.get(asset.id)
        if existing is not None:
            existing.risk_score = max(existing.risk_score, asset.risk_score)
            existing.risk_level = strongest_severity(existing.risk_level, asset.risk_level)
            existing.properties.update({key: value for key, value in asset.properties.items() if value not in (None, "")})
            if not existing.locator:
                existing.locator = asset.locator
            return existing.id
        self.assets[asset.id] = asset
        return asset.id

    def add_evidence(self, evidence: FactEvidence) -> str:
        if evidence.id not in self.evidence:
            self.evidence[evidence.id] = evidence
        return evidence.id

    def add_finding(self, finding: FactFinding) -> str:
        existing = self.findings.get(finding.id)
        if existing is not None:
            existing.score = max(existing.score, finding.score)
            existing.severity = strongest_severity(existing.severity, finding.severity)
            existing.asset_ids = stable_unique(existing.asset_ids + finding.asset_ids)
            existing.evidence_ids = stable_unique(existing.evidence_ids + finding.evidence_ids)
            if not existing.recommendation and finding.recommendation:
                existing.recommendation = finding.recommendation
            existing.properties.update({key: value for key, value in finding.properties.items() if value not in (None, "")})
            return existing.id
        self.findings[finding.id] = finding
        return finding.id

    def payload(self) -> dict[str, Any]:
        assets = sorted(self.assets.values(), key=lambda item: (-item.risk_score, item.type, item.label))
        evidence = sorted(self.evidence.values(), key=lambda item: (item.source, item.kind, item.title))
        findings = sorted(self.findings.values(), key=lambda item: (-item.score, item.source, item.title))
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(UTC).isoformat(),
            "references": REFERENCE_MODELS,
            "summary": build_summary(assets, evidence, findings),
            "assets": [dataclass_to_public(asset) for asset in assets],
            "evidence": [dataclass_to_public(item) for item in evidence],
            "findings": [dataclass_to_public(finding) for finding in findings],
        }


def build_unified_facts(
    workspace_payload: dict[str, Any],
    *,
    code_audit: CodeAuditResult | None = None,
    dependency_audit: DependencyAuditResult | None = None,
    cicd_audit: CICDAuditResult | None = None,
    artifact_trust: ArtifactTrustResult | None = None,
    log_audit: LogAuditResult | None = None,
    realtime_logs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    builder = FactBuilder()
    if code_audit is not None:
        add_code_audit_facts(builder, code_audit)
    if dependency_audit is not None:
        add_dependency_audit_facts(builder, dependency_audit)
    if cicd_audit is not None:
        add_cicd_audit_facts(builder, cicd_audit)
    if artifact_trust is not None:
        add_artifact_trust_facts(builder, artifact_trust)
    if log_audit is not None:
        add_log_audit_facts(builder, log_audit)
    if realtime_logs:
        add_realtime_log_facts(builder, realtime_logs)

    # Keep the demo/offline workspace visible as facts before a scanner has run.
    add_workspace_fallback_facts(builder, workspace_payload)
    return builder.payload()


class GraphBuilder:
    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, GraphEdge] = {}
        self.attack_paths: list[AttackPath] = []

    def add_node(self, node: GraphNode) -> str:
        existing = self.nodes.get(node.id)
        if existing is not None:
            existing.score = max(existing.score, node.score)
            existing.risk = strongest_severity(existing.risk, node.risk)
            existing.evidence_ids = stable_unique(existing.evidence_ids + node.evidence_ids)
            existing.properties.update({key: value for key, value in node.properties.items() if value not in (None, "")})
            if not existing.position and node.position:
                existing.position = node.position
            return existing.id
        self.nodes[node.id] = node
        return node.id

    def add_edge(self, edge: GraphEdge) -> str:
        existing = self.edges.get(edge.id)
        if existing is not None:
            existing.confidence = max(existing.confidence, edge.confidence)
            existing.evidence_ids = stable_unique(existing.evidence_ids + edge.evidence_ids)
            existing.properties.update({key: value for key, value in edge.properties.items() if value not in (None, "")})
            return existing.id
        self.edges[edge.id] = edge
        return edge.id

    def add_attack_path(self, path: AttackPath) -> None:
        if not any(existing.id == path.id for existing in self.attack_paths):
            self.attack_paths.append(path)

    def payload(self) -> dict[str, Any]:
        assign_node_positions(self.nodes)
        nodes = sorted(
            self.nodes.values(),
            key=lambda item: (NODE_TYPE_RANK.get(item.type, 99), item.position.get("y", 0), -item.score, item.label),
        )
        edges = sorted(self.edges.values(), key=lambda item: (item.source, item.target, item.type))
        attack_paths = sorted(self.attack_paths, key=lambda item: (-item.score, item.title))
        return {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "generated_at": datetime.now(UTC).isoformat(),
            "references": GRAPH_REFERENCE_MODELS,
            "summary": build_graph_summary(nodes, edges, attack_paths),
            "nodes": [dataclass_to_public(node) for node in nodes],
            "edges": [dataclass_to_public(edge) for edge in edges],
            "attack_paths": [dataclass_to_public(path) for path in attack_paths],
        }


def build_knowledge_graph(facts: dict[str, Any], workspace_payload: dict[str, Any]) -> dict[str, Any]:
    """Build a rule-driven supply-chain knowledge graph from normalized facts."""
    builder = GraphBuilder()
    assets = ensure_dicts(facts.get("assets"))
    evidence = ensure_dicts(facts.get("evidence"))
    findings = ensure_dicts(facts.get("findings"))

    evidence_by_id = {str(item.get("id")): item for item in evidence}
    evidence_by_asset: dict[str, list[dict[str, Any]]] = {}
    findings_by_asset: dict[str, list[dict[str, Any]]] = {}
    for item in evidence:
        asset_id = str(item.get("asset_id") or "")
        if asset_id:
            evidence_by_asset.setdefault(asset_id, []).append(item)
    for finding in findings:
        for asset_id in ensure_string_list(finding.get("asset_ids")):
            findings_by_asset.setdefault(asset_id, []).append(finding)

    for asset in choose_graph_assets(assets):
        builder.add_node(asset_to_graph_node(asset, evidence_by_asset.get(str(asset.get("id")), [])))

    for finding in choose_graph_findings(findings):
        finding_id = finding_node_id(finding)
        builder.add_node(finding_to_graph_node(finding))
        for asset_id in ensure_string_list(finding.get("asset_ids")):
            if asset_id in builder.nodes:
                builder.add_edge(
                    GraphEdge(
                        id=stable_id("edge", "FINDING_AFFECTS", finding_id, asset_id),
                        source=finding_id,
                        target=asset_id,
                        type="FINDING_AFFECTS",
                        label="影响资产",
                        confidence=0.86,
                        reason="Finding references the normalized asset by asset_id.",
                        evidence_ids=ensure_string_list(finding.get("evidence_ids")),
                    )
                )
        map_finding_to_attack_stage(builder, finding)

    add_vulnerability_nodes(builder, facts)
    add_virtual_artifact_and_service(builder, workspace_payload)
    add_rule_edges_and_attack_paths(builder, facts, workspace_payload, evidence_by_id, findings_by_asset)
    return builder.payload()


def add_code_audit_facts(builder: FactBuilder, result: CodeAuditResult) -> None:
    source = "code_audit"
    source_model = "SARIF"
    first_seen = trim_time(result.generated_at)
    for finding in result.findings:
        asset_id = builder.add_asset(
            FactAsset(
                id=stable_id("asset", "code", finding.risk_file),
                type="CodeFile",
                label=finding.risk_file,
                source=source,
                source_model=source_model,
                risk_score=finding.score,
                risk_level=finding.severity,
                locator={"path": finding.risk_file, "line": finding.line, "end_line": finding.end_line},
                properties={
                    "category": finding.category,
                    "scanner": finding.scanner,
                    "cwe": finding.cwe,
                },
            )
        )
        evidence_id = builder.add_evidence(
            FactEvidence(
                id=stable_id("evidence", source, finding.fingerprint or finding.id),
                source=source,
                source_model=source_model,
                kind="static-analysis-result",
                title=finding.title,
                detail=finding.evidence,
                asset_id=asset_id,
                time=first_seen,
                locator={"path": finding.risk_file, "line": finding.line, "end_line": finding.end_line},
                properties={
                    "rule_id": finding.rule_id,
                    "scanner": finding.scanner,
                    "confidence": finding.confidence,
                    "cwe": finding.cwe,
                },
            )
        )
        builder.add_finding(
            FactFinding(
                id=finding.id,
                title=f"{finding.category}: {finding.title}",
                severity=finding.severity,
                score=finding.score,
                source=source,
                source_model=source_model,
                asset_ids=[asset_id],
                evidence_ids=[evidence_id],
                fingerprint=finding.fingerprint or stable_id("finding", source, finding.id),
                recommendation=finding.recommendation,
                category=finding.category,
                first_seen=first_seen,
                status="open",
                properties={"rule_id": finding.rule_id, "scanner": finding.scanner, "cwe": finding.cwe},
            )
        )


def add_dependency_audit_facts(builder: FactBuilder, result: DependencyAuditResult) -> None:
    source = "dependency_audit"
    source_model = "CycloneDX"
    first_seen = trim_time(result.generated_at)
    dependency_assets: dict[tuple[str, str], str] = {}

    for dependency in result.dependencies:
        key = dependency_key(getattr(dependency, "ecosystem", ""), getattr(dependency, "name", ""))
        asset_id = builder.add_asset(
            FactAsset(
                id=dependency_asset_id(dependency),
                type="DependencyPackage",
                label=dependency_label(dependency),
                source=source,
                source_model=source_model,
                risk_score=int(getattr(dependency, "risk", 0) or 0),
                risk_level=severity_from_score(int(getattr(dependency, "risk", 0) or 0)),
                locator={"source_file": getattr(dependency, "source_file", "")},
                properties={
                    "name": getattr(dependency, "name", ""),
                    "version": getattr(dependency, "version", ""),
                    "ecosystem": getattr(dependency, "ecosystem", ""),
                    "scope": getattr(dependency, "scope", ""),
                    "license": getattr(dependency, "license", ""),
                    "purl": getattr(dependency, "purl", ""),
                    "manifest_type": getattr(dependency, "manifest_type", ""),
                    "version_source": getattr(dependency, "version_source", ""),
                    "dependency_type": getattr(dependency, "dependency_type", ""),
                    "signals": list(getattr(dependency, "signals", []) or []),
                    "vulnerabilities": list(getattr(dependency, "vulnerabilities", []) or []),
                },
            )
        )
        dependency_assets[key] = asset_id

        signals = list(getattr(dependency, "signals", []) or [])
        vulnerabilities = list(getattr(dependency, "vulnerabilities", []) or [])
        if signals or vulnerabilities:
            builder.add_evidence(
                FactEvidence(
                    id=stable_id("evidence", source, asset_id),
                    source=source,
                    source_model=source_model,
                    kind="sbom-component-risk",
                    title=dependency_label(dependency),
                    detail="; ".join(signals) or vulnerability_summary(vulnerabilities),
                    asset_id=asset_id,
                    time=first_seen,
                    locator={"source_file": getattr(dependency, "source_file", "")},
                    properties={"signals": signals, "vulnerabilities": vulnerabilities},
                )
            )

    for finding in result.findings:
        asset_id = dependency_assets.get(dependency_key(finding.ecosystem, finding.dependency))
        if asset_id is None:
            asset_id = builder.add_asset(
                FactAsset(
                    id=stable_id("asset", "dependency", finding.ecosystem, finding.dependency),
                    type="DependencyPackage",
                    label=f"{finding.ecosystem}:{finding.dependency}",
                    source=source,
                    source_model=source_model,
                    risk_score=finding.score,
                    risk_level=finding.severity,
                    locator={"source_file": finding.source_file},
                    properties={"ecosystem": finding.ecosystem, "name": finding.dependency},
                )
            )
        evidence_id = builder.add_evidence(
            FactEvidence(
                id=stable_id("evidence", source, finding.fingerprint or finding.id),
                source=source,
                source_model=source_model,
                kind="dependency-risk-finding",
                title=finding.title,
                detail=finding.evidence,
                asset_id=asset_id,
                time=first_seen,
                locator={"source_file": finding.source_file},
                properties={"ecosystem": finding.ecosystem, "dependency": finding.dependency},
            )
        )
        builder.add_finding(
            FactFinding(
                id=finding.id,
                title=finding.title,
                severity=finding.severity,
                score=finding.score,
                source=source,
                source_model=source_model,
                asset_ids=[asset_id],
                evidence_ids=[evidence_id],
                fingerprint=finding.fingerprint or stable_id("finding", source, finding.id),
                recommendation=finding.recommendation,
                category="dependency-risk",
                first_seen=first_seen,
                status="open",
                properties={"ecosystem": finding.ecosystem, "dependency": finding.dependency},
            )
        )


def add_cicd_audit_facts(builder: FactBuilder, result: CICDAuditResult) -> None:
    source = "cicd_audit"
    source_model = "SARIF"
    first_seen = trim_time(result.generated_at)

    for workflow in result.workflows:
        builder.add_asset(
            FactAsset(
                id=stable_id("asset", "workflow", workflow),
                type="CIWorkflow",
                label=workflow,
                source=source,
                source_model=source_model,
                locator={"path": workflow},
                properties={"workflow": workflow},
            )
        )

    for finding in result.findings:
        asset_type = "CIStep" if finding.step_name or finding.step_index is not None else "CIWorkflow"
        asset_label = finding.step_name or finding.job_name or finding.workflow
        asset_id = builder.add_asset(
            FactAsset(
                id=stable_id("asset", "ci", finding.workflow, finding.job_id, finding.step_index, asset_label),
                type=asset_type,
                label=asset_label,
                source=source,
                source_model=source_model,
                risk_score=finding.score,
                risk_level=finding.severity,
                locator={
                    "path": finding.workflow,
                    "line": finding.line,
                    "job_id": finding.job_id,
                    "step_index": finding.step_index,
                },
                properties={
                    "workflow": finding.workflow,
                    "job_id": finding.job_id,
                    "job_name": finding.job_name,
                    "step_name": finding.step_name,
                    "scanner": finding.scanner,
                },
            )
        )
        evidence_id = builder.add_evidence(
            FactEvidence(
                id=stable_id("evidence", source, finding.fingerprint or finding.id),
                source=source,
                source_model=source_model,
                kind="workflow-risk-finding",
                title=finding.title,
                detail=f"{finding.reason} Evidence: {finding.evidence}",
                asset_id=asset_id,
                time=first_seen,
                locator={"path": finding.workflow, "line": finding.line},
                properties={"rule_id": finding.rule_id, "scanner": finding.scanner, "confidence": finding.confidence},
            )
        )
        builder.add_finding(
            FactFinding(
                id=finding.id,
                title=finding.title,
                severity=finding.severity,
                score=finding.score,
                source=source,
                source_model=source_model,
                asset_ids=[asset_id],
                evidence_ids=[evidence_id],
                fingerprint=finding.fingerprint or stable_id("finding", source, finding.id),
                recommendation=finding.recommendation,
                category="cicd-risk",
                first_seen=first_seen,
                status="open",
                properties={
                    "rule_id": finding.rule_id,
                    "workflow": finding.workflow,
                    "job_id": finding.job_id,
                    "step_name": finding.step_name,
                    "scanner": finding.scanner,
                },
            )
        )


def add_artifact_trust_facts(builder: FactBuilder, result: ArtifactTrustResult) -> None:
    source = "artifact_trust"
    source_model = "SLSA/in-toto"
    first_seen = trim_time(result.generated_at)
    provenance = result.provenance
    artifact_id = builder.add_asset(
        FactAsset(
            id=stable_id("asset", "artifact-trust", result.digest or result.artifact),
            type="BuildArtifact",
            label=result.artifact,
            source=source,
            source_model=source_model,
            risk_score=max(0, 100 - result.trust_score),
            risk_level=severity_from_score(max(0, 100 - result.trust_score)),
            locator={"path": result.artifact_path, "digest": result.digest},
            properties={
                "artifact": result.artifact,
                "digest": result.digest,
                "trust_score": result.trust_score,
                "level": result.level,
            },
        )
    )
    attestation_id = builder.add_asset(
        FactAsset(
            id=stable_id("asset", "attestation", result.attestation_path, result.digest),
            type="Attestation",
            label=provenance.get("subject_name") or "provenance attestation",
            source=source,
            source_model=source_model,
            risk_score=max(0, 100 - result.trust_score),
            risk_level=severity_from_score(max(0, 100 - result.trust_score)),
            locator={"path": result.attestation_path},
            properties={
                "predicateType": provenance.get("predicateType") or provenance.get("predicate_type"),
                "subject_digest": provenance.get("subject_digest"),
                "signature_count": provenance.get("envelope_signature_count"),
                "created_at": provenance.get("created_at"),
            },
        )
    )
    builder.add_evidence(
        FactEvidence(
            id=stable_id("evidence", source, "attestation", result.digest),
            source=source,
            source_model=source_model,
            kind="artifact-provenance",
            title="Artifact provenance attestation",
            detail=(
                f"{result.artifact} {result.digest}; "
                f"repo={provenance.get('source_repo') or '-'}; "
                f"commit={provenance.get('commit') or '-'}; "
                f"workflow={provenance.get('workflow') or '-'}; "
                f"builder={provenance.get('builder_id') or '-'}"
            ),
            asset_id=artifact_id,
            time=first_seen,
            locator={"artifact": result.artifact_path, "attestation": result.attestation_path},
            confidence=0.88,
            properties={"attestation_asset_id": attestation_id, "checks": [check.__dict__ for check in result.checks]},
        )
    )

    if provenance.get("builder_id"):
        builder.add_asset(
            FactAsset(
                id=stable_id("asset", "trusted-builder", provenance.get("builder_id")),
                type="TrustedBuilder",
                label=str(provenance.get("builder_id")),
                source=source,
                source_model=source_model,
                risk_score=0,
                risk_level="low",
                properties={"builder_id": provenance.get("builder_id"), "runner_environment": provenance.get("runner_environment")},
            )
        )
    if provenance.get("workflow"):
        builder.add_asset(
            FactAsset(
                id=stable_id("asset", "workflow", provenance.get("workflow")),
                type="Workflow",
                label=str(provenance.get("workflow")),
                source=source,
                source_model=source_model,
                risk_score=0,
                risk_level="low",
                locator={"path": provenance.get("workflow")},
                properties={"workflow": provenance.get("workflow"), "ref": provenance.get("ref")},
            )
        )
    if provenance.get("commit") or provenance.get("source_repo"):
        builder.add_asset(
            FactAsset(
                id=stable_id("asset", "source-commit", provenance.get("source_repo"), provenance.get("commit") or provenance.get("ref")),
                type="SourceCommit",
                label=f"commit {provenance.get('commit')}" if provenance.get("commit") else str(provenance.get("ref") or "source"),
                source=source,
                source_model=source_model,
                risk_score=0,
                risk_level="low",
                properties={
                    "source_repo": provenance.get("source_repo"),
                    "commit": provenance.get("commit"),
                    "ref": provenance.get("ref"),
                },
            )
        )

    for check in result.checks:
        builder.add_evidence(
            FactEvidence(
                id=stable_id("evidence", source, "check", check.name, check.status, result.digest),
                source=source,
                source_model=source_model,
                kind="artifact-trust-check",
                title=check.name,
                detail=f"{check.status}: {check.evidence}",
                asset_id=artifact_id,
                time=first_seen,
                confidence=0.9 if check.status == "pass" else 0.76,
                properties={"status": check.status, "severity": check.severity},
            )
        )

    for finding in result.findings:
        evidence_id = stable_id("evidence", source, "finding", finding.fingerprint)
        builder.add_evidence(
            FactEvidence(
                id=evidence_id,
                source=source,
                source_model=source_model,
                kind="artifact-trust-finding",
                title=finding.title,
                detail=finding.evidence,
                asset_id=artifact_id,
                time=first_seen,
                properties={"check": finding.check},
            )
        )
        builder.add_finding(
            FactFinding(
                id=finding.id,
                title=finding.title,
                severity=finding.severity,
                score=finding.score,
                source=source,
                source_model=source_model,
                asset_ids=[artifact_id],
                evidence_ids=[evidence_id],
                fingerprint=finding.fingerprint,
                recommendation=finding.recommendation,
                category="artifact-trust",
                first_seen=first_seen,
                status="open",
                properties={"artifact": result.artifact, "check": finding.check, "digest": result.digest},
            )
        )


def add_log_audit_facts(builder: FactBuilder, result: LogAuditResult) -> None:
    source = "log_audit"
    source_model = "NormalizedLogEvent"
    for finding in result.findings:
        add_log_finding_dict(
            builder,
            {
                "id": finding.id,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity,
                "score": finding.score,
                "time": finding.time,
                "source": finding.source,
                "event": finding.event,
                "signal": finding.signal,
                "confidence": finding.confidence,
                "evidence": finding.evidence,
                "src_ip": finding.src_ip,
                "dst_ip": finding.dst_ip,
                "user": finding.user,
                "path": finding.path,
                "count": finding.count,
                "fingerprint": finding.fingerprint,
            },
            source=source,
            source_model=source_model,
        )


def add_realtime_log_facts(builder: FactBuilder, payload: dict[str, Any]) -> None:
    findings = payload.get("findings") if isinstance(payload.get("findings"), list) else []
    for item in findings:
        if isinstance(item, dict):
            add_log_finding_dict(builder, item, source="realtime_log_audit", source_model="NormalizedLogEvent")


def add_log_finding_dict(
    builder: FactBuilder,
    item: dict[str, Any],
    *,
    source: str,
    source_model: str,
) -> None:
    source_name = str(item.get("source") or "app")
    path = str(item.get("path") or "")
    src_ip = str(item.get("src_ip") or "")
    dst_ip = str(item.get("dst_ip") or "")
    label = path or dst_ip or src_ip or source_name
    asset_id = builder.add_asset(
        FactAsset(
            id=stable_id("asset", "log", source_name, path, src_ip, dst_ip),
            type="LogEvent",
            label=label,
            source=source,
            source_model=source_model,
            risk_score=int(item.get("score") or 0),
            risk_level=str(item.get("severity") or "low"),
            locator={"path": path or None, "src_ip": src_ip or None, "dst_ip": dst_ip or None},
            properties={
                "log_source": source_name,
                "event": item.get("event"),
                "signal": item.get("signal"),
                "user": item.get("user"),
                "count": item.get("count") or item.get("occurrences"),
            },
        )
    )
    fingerprint = str(item.get("fingerprint") or stable_id("log", item.get("id"), item.get("time"), item.get("evidence")))
    evidence_id = builder.add_evidence(
        FactEvidence(
            id=stable_id("evidence", source, fingerprint),
            source=source,
            source_model=source_model,
            kind="runtime-log-finding",
            title=str(item.get("signal") or item.get("title") or "runtime log finding"),
            detail=str(item.get("evidence") or item.get("event") or ""),
            asset_id=asset_id,
            time=str(item.get("time") or ""),
            locator={"path": path or None, "src_ip": src_ip or None, "dst_ip": dst_ip or None},
            confidence=safe_float(item.get("confidence")),
            properties={"rule_id": item.get("rule_id"), "event": item.get("event")},
        )
    )
    finding_id = str(item.get("id") or f"LOG-{fingerprint[:8].upper()}")
    builder.add_finding(
        FactFinding(
            id=finding_id,
            title=str(item.get("title") or item.get("signal") or item.get("event") or "Runtime log finding"),
            severity=str(item.get("severity") or "low"),
            score=int(item.get("score") or 0),
            source=source,
            source_model=source_model,
            asset_ids=[asset_id],
            evidence_ids=[evidence_id],
            fingerprint=fingerprint,
            recommendation="Review the log source, related account/IP, and surrounding deployment window.",
            category="runtime-log-risk",
            first_seen=str(item.get("time") or "")[:16],
            status="open",
            properties={"rule_id": item.get("rule_id"), "signal": item.get("signal")},
        )
    )


def add_workspace_fallback_facts(builder: FactBuilder, payload: dict[str, Any]) -> None:
    source = "workspace"
    source_model = "WorkspaceSummary"

    for dependency in ensure_dicts(payload.get("dependencies")):
        name = str(dependency.get("name") or "")
        if not name:
            continue
        ecosystem = str(dependency.get("ecosystem") or "generic")
        version = str(dependency.get("version") or "")
        asset_id = builder.add_asset(
            FactAsset(
                id=stable_id("asset", "dependency", ecosystem, name, version),
                type="DependencyPackage",
                label=f"{ecosystem}:{name}@{version}" if version else f"{ecosystem}:{name}",
                source=source,
                source_model="CycloneDX",
                risk_score=int(dependency.get("risk") or 0),
                risk_level=severity_from_score(int(dependency.get("risk") or 0)),
                locator={"source_file": dependency.get("source_file")},
                properties=compact_dict(dependency),
            )
        )
        if dependency.get("signals"):
            builder.add_evidence(
                FactEvidence(
                    id=stable_id("evidence", source, asset_id),
                    source=source,
                    source_model="CycloneDX",
                    kind="workspace-dependency-risk",
                    title=f"{name} dependency signals",
                    detail="; ".join(str(item) for item in ensure_list(dependency.get("signals"))),
                    asset_id=asset_id,
                    properties={"signals": dependency.get("signals")},
                )
            )

    for step in ensure_dicts(payload.get("pipeline")):
        step_key = str(step.get("step") or step.get("name") or "")
        if not step_key:
            continue
        builder.add_asset(
            FactAsset(
                id=stable_id("asset", "pipeline", step_key),
                type="CIStep",
                label=str(step.get("name") or step_key),
                source=source,
                source_model=source_model,
                risk_score=score_from_severity(str(step.get("status") or "")),
                risk_level=normalize_severity(str(step.get("status") or "low")),
                locator={"time": step.get("time")},
                properties=compact_dict(step),
            )
        )

    for log in ensure_dicts(payload.get("logs")):
        add_log_finding_dict(
            builder,
            {
                "id": stable_id("workspace-log", log.get("time"), log.get("event"), log.get("signal")),
                "title": log.get("signal") or log.get("event"),
                "severity": log.get("severity") or "low",
                "score": score_from_severity(str(log.get("severity") or "low")),
                "time": log.get("time"),
                "source": log.get("source"),
                "event": log.get("event"),
                "signal": log.get("signal"),
                "confidence": log.get("confidence"),
                "evidence": log.get("event") or "",
                "fingerprint": stable_id("workspace-log-fp", log.get("time"), log.get("event"), log.get("signal")),
            },
            source=source,
            source_model="NormalizedLogEvent",
        )

    multimodal = payload.get("multimodal_audit") if isinstance(payload.get("multimodal_audit"), dict) else {}
    for item in ensure_dicts(multimodal.get("evidence")):
        add_multimodal_evidence_fact(builder, item)

    for finding in ensure_dicts(payload.get("findings")):
        finding_id = str(finding.get("id") or stable_id("workspace-finding", finding.get("title"), finding.get("asset")))
        if finding_id in builder.findings:
            continue
        asset_label = str(finding.get("asset") or finding.get("module") or "workspace")
        asset_id = builder.add_asset(
            FactAsset(
                id=stable_id("asset", "workspace", finding.get("module"), asset_label),
                type=workspace_asset_type(str(finding.get("module") or "")),
                label=asset_label,
                source=source,
                source_model=source_model,
                risk_score=int(finding.get("score") or 0),
                risk_level=str(finding.get("severity") or "low"),
                properties={"module": finding.get("module"), "owner": finding.get("owner")},
            )
        )
        evidence_id = builder.add_evidence(
            FactEvidence(
                id=stable_id("evidence", source, finding_id),
                source=source,
                source_model=source_model,
                kind="workspace-finding-evidence",
                title=str(finding.get("title") or finding_id),
                detail=str(finding.get("evidence") or ""),
                asset_id=asset_id,
                time=str(finding.get("first_seen") or ""),
                properties={"module": finding.get("module")},
            )
        )
        builder.add_finding(
            FactFinding(
                id=finding_id,
                title=str(finding.get("title") or finding_id),
                severity=str(finding.get("severity") or "low"),
                score=int(finding.get("score") or 0),
                source=source,
                source_model=source_model,
                asset_ids=[asset_id],
                evidence_ids=[evidence_id],
                fingerprint=stable_id("finding", source, finding_id),
                recommendation=str(finding.get("status") or ""),
                category=str(finding.get("module") or ""),
                first_seen=str(finding.get("first_seen") or "")[:16],
                status=str(finding.get("status") or "open"),
                properties={"owner": finding.get("owner"), "module": finding.get("module")},
            )
        )


def add_multimodal_evidence_fact(builder: FactBuilder, item: dict[str, Any]) -> None:
    source = "multimodal_audit"
    source_model = "ASR/OCR + Sigma-style rules"
    evidence_id = str(item.get("evidence_id") or stable_id("multimodal", item.get("file_path"), item.get("sha256")))
    source_type = str(item.get("source_type") or "multimodal")
    label = str(item.get("original_filename") or item.get("filename") or evidence_id)
    risk_score = int(item.get("risk_score") or 0)
    risk_level = str(item.get("risk_level") or severity_from_score(risk_score))
    asset_type = "AudioEvidence" if source_type == "audio" else "VisualEvidence" if source_type in {"image", "video"} else "MultimodalEvidence"
    asset_id = builder.add_asset(
        FactAsset(
            id=stable_id("asset", "multimodal", evidence_id),
            type=asset_type,
            label=label,
            source=source,
            source_model=source_model,
            risk_score=risk_score,
            risk_level=risk_level,
            locator={"path": item.get("relative_path") or item.get("file_path")},
            properties=compact_dict(
                {
                    "evidence_id": evidence_id,
                    "source_type": source_type,
                    "mime_type": item.get("mime_type"),
                    "size_bytes": item.get("size_bytes"),
                    "sha256": item.get("sha256"),
                    "file_path": item.get("file_path"),
                    "relative_path": item.get("relative_path"),
                    "metadata": item.get("metadata"),
                    "derived": item.get("derived"),
                    "recognitions": item.get("recognitions"),
                    "entities": item.get("entities"),
                    "findings": item.get("findings"),
                }
            ),
        )
    )
    entity_asset_ids: list[str] = []
    for entity in ensure_dicts(item.get("entities")):
        entity_type = str(entity.get("type") or "entity")
        entity_value = str(entity.get("normalized") or entity.get("value") or "")
        if not entity_value:
            continue
        entity_asset_id = builder.add_asset(
            FactAsset(
                id=stable_id("asset", "multimodal-entity", entity_type, entity_value),
                type="RecognizedEntity",
                label=f"{entity_type}:{entity_value}",
                source=source,
                source_model="Regex/Keyword Entity Extraction",
                risk_score=risk_score,
                risk_level=risk_level,
                locator={"path": item.get("relative_path") or item.get("file_path")},
                properties=compact_dict({**entity, "evidence_id": evidence_id}),
            )
        )
        entity_asset_ids.append(entity_asset_id)
        builder.add_evidence(
            FactEvidence(
                id=stable_id("evidence", source, evidence_id, "entity", entity_type, entity_value),
                source=source,
                source_model="Regex/Keyword Entity Extraction",
                kind="recognized-security-entity",
                title=f"{entity_type}: {entity_value}",
                detail=str(entity.get("evidence") or entity.get("value") or entity_value),
                asset_id=entity_asset_id,
                time=str(item.get("uploaded_at") or "")[:19],
                confidence=safe_float(entity.get("confidence")),
                properties=compact_dict({"source_evidence_id": evidence_id, "source_asset_id": asset_id}),
            )
        )
    builder.add_evidence(
        FactEvidence(
            id=stable_id("evidence", source, evidence_id),
            source=source,
            source_model=source_model,
            kind="multimodal-evidence-source",
            title=f"{source_type} evidence: {label}",
            detail=f"{evidence_id} stored at {item.get('relative_path') or item.get('file_path')}",
            asset_id=asset_id,
            time=str(item.get("uploaded_at") or "")[:19],
            locator={"path": item.get("relative_path") or item.get("file_path")},
            confidence=1.0,
            properties=compact_dict(
                {
                    "sha256": item.get("sha256"),
                    "mime_type": item.get("mime_type"),
                    "metadata": item.get("metadata"),
                    "derived": item.get("derived"),
                }
            ),
        )
    )
    recognition_evidence_ids: list[str] = []
    for index, recognition in enumerate(ensure_dicts(item.get("recognitions")), start=1):
        text = str(recognition.get("recognized_text") or "").strip()
        if not text:
            continue
        recognition_evidence_id = stable_id("evidence", source, evidence_id, recognition.get("evidence_type"), index, text[:80])
        recognition_evidence_ids.append(recognition_evidence_id)
        builder.add_evidence(
            FactEvidence(
                id=recognition_evidence_id,
                source=source,
                source_model=str(recognition.get("engine") or source_model),
                kind=str(recognition.get("evidence_type") or "recognized-text"),
                title=f"{recognition.get('evidence_type') or 'text evidence'}: {label}",
                detail=text,
                asset_id=asset_id,
                time=str(recognition.get("created_at") or item.get("uploaded_at") or "")[:19],
                locator={"path": recognition.get("source_path") or item.get("relative_path") or item.get("file_path")},
                confidence=float(recognition.get("confidence") or 0),
                properties=compact_dict(
                    {
                        "source_type": recognition.get("source_type"),
                        "engine": recognition.get("engine"),
                        "language": recognition.get("language"),
                        "segments": recognition.get("segments"),
                    }
                ),
            )
        )
    for finding in ensure_dicts(item.get("findings")):
        finding_id = str(finding.get("id") or stable_id("finding", source, evidence_id, finding.get("rule_id")))
        finding_evidence_id = builder.add_evidence(
            FactEvidence(
                id=stable_id("evidence", source, finding_id),
                source=source,
                source_model="Sigma-style YAML rule",
                kind="multimodal-rule-match",
                title=str(finding.get("title") or finding.get("rule_id") or finding_id),
                detail=str(finding.get("evidence") or ""),
                asset_id=asset_id,
                time=str(finding.get("first_seen") or item.get("uploaded_at") or "")[:19],
                confidence=safe_float(finding.get("confidence")),
                properties=compact_dict(
                    {
                        "rule_id": finding.get("rule_id"),
                        "matched_keywords": finding.get("matched_keywords"),
                        "entities": finding.get("entities"),
                        "references": finding.get("references"),
                    }
                ),
            )
        )
        builder.add_finding(
            FactFinding(
                id=finding_id,
                title=str(finding.get("title") or finding.get("rule_id") or finding_id),
                severity=str(finding.get("severity") or "medium"),
                score=int(finding.get("score") or score_from_severity(str(finding.get("severity") or "medium"))),
                source=source,
                source_model="Sigma-style YAML rule",
                asset_ids=stable_unique([asset_id] + entity_asset_ids),
                evidence_ids=stable_unique([finding_evidence_id] + recognition_evidence_ids),
                fingerprint=str(finding.get("fingerprint") or stable_id("finding", source, finding_id)),
                recommendation=str(finding.get("recommendation") or ""),
                category="多模态证据",
                first_seen=str(finding.get("first_seen") or "")[:16],
                status="open",
                properties=compact_dict(
                    {
                        "rule_id": finding.get("rule_id"),
                        "matched_keywords": finding.get("matched_keywords"),
                        "entities": finding.get("entities"),
                        "references": finding.get("references"),
                        "tags": finding.get("tags"),
                    }
                ),
            )
        )


def build_summary(
    assets: Iterable[FactAsset],
    evidence: Iterable[FactEvidence],
    findings: Iterable[FactFinding],
) -> dict[str, Any]:
    asset_list = list(assets)
    evidence_list = list(evidence)
    finding_list = list(findings)
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    asset_types: dict[str, int] = {}
    sources: dict[str, int] = {}
    source_models: dict[str, int] = {}

    for asset in asset_list:
        asset_types[asset.type] = asset_types.get(asset.type, 0) + 1
    for item in evidence_list:
        sources[item.source] = sources.get(item.source, 0) + 1
        source_models[item.source_model] = source_models.get(item.source_model, 0) + 1
    for finding in finding_list:
        severity = normalize_severity(finding.severity)
        severities[severity] = severities.get(severity, 0) + 1
        sources[finding.source] = sources.get(finding.source, 0) + 1
        source_models[finding.source_model] = source_models.get(finding.source_model, 0) + 1

    risk_score = max([finding.score for finding in finding_list] + [asset.risk_score for asset in asset_list] + [0])
    return {
        "asset_count": len(asset_list),
        "evidence_count": len(evidence_list),
        "finding_count": len(finding_list),
        "risk_score": risk_score,
        "risk_level": severity_from_score(risk_score),
        "critical": severities["critical"],
        "high": severities["high"],
        "medium": severities["medium"],
        "low": severities["low"],
        "asset_types": asset_types,
        "sources": sources,
        "source_models": source_models,
    }


def choose_graph_assets(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    allowed_types = {
        "DependencyPackage",
        "CodeFile",
        "CIStep",
        "CIWorkflow",
        "BuildArtifact",
        "Attestation",
        "TrustedBuilder",
        "Workflow",
        "SourceCommit",
        "LogEvent",
        "AudioEvidence",
        "VisualEvidence",
        "MultimodalEvidence",
        "MultimodalFinding",
        "RecognizedEntity",
        "EvidenceChain",
    }
    type_limits = {
        "CIWorkflow": 4,
        "CIStep": 14,
        "BuildArtifact": 4,
        "Attestation": 4,
        "TrustedBuilder": 4,
        "Workflow": 4,
        "SourceCommit": 4,
        "LogEvent": 12,
        "DependencyPackage": 28,
        "CodeFile": 8,
        "AudioEvidence": 6,
        "VisualEvidence": 12,
        "MultimodalEvidence": 8,
        "MultimodalFinding": 12,
        "RecognizedEntity": 18,
        "EvidenceChain": 4,
    }
    priority_types = [
        "CIWorkflow",
        "CIStep",
        "BuildArtifact",
        "Attestation",
        "TrustedBuilder",
        "Workflow",
        "SourceCommit",
        "LogEvent",
        "DependencyPackage",
        "CodeFile",
        "AudioEvidence",
        "VisualEvidence",
        "MultimodalEvidence",
        "MultimodalFinding",
        "RecognizedEntity",
        "EvidenceChain",
    ]
    buckets: dict[str, list[dict[str, Any]]] = {asset_type: [] for asset_type in priority_types}
    for asset in assets:
        asset_type = str(asset.get("type") or "")
        if asset_type in allowed_types:
            buckets.setdefault(asset_type, []).append(asset)

    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    for asset_type in priority_types:
        bucket = sorted(
            buckets.get(asset_type, []),
            key=lambda item: (-int(item.get("risk_score") or 0), str(item.get("label") or "")),
        )
        for asset in bucket[: type_limits.get(asset_type, 6)]:
            asset_id = str(asset.get("id") or "")
            if asset_id and asset_id in selected_ids:
                continue
            selected.append(asset)
            if asset_id:
                selected_ids.add(asset_id)

    # 保证 CI/CD、产物、日志和来源证明等路径关键节点后，
    # 再按风险补充其余资产，同时控制图谱总体规模。
    max_assets = 120
    if len(selected) < max_assets:
        leftovers = sorted(
            [
                asset
                for asset in assets
                if str(asset.get("type") or "") in allowed_types
                and str(asset.get("id") or "") not in selected_ids
            ],
            key=lambda item: (-int(item.get("risk_score") or 0), str(item.get("type") or ""), str(item.get("label") or "")),
        )
        for asset in leftovers:
            if len(selected) >= max_assets:
                break
            selected.append(asset)
            asset_id = str(asset.get("id") or "")
            if asset_id:
                selected_ids.add(asset_id)
    return selected


def choose_graph_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda item: (-int(item.get("score") or 0), str(item.get("title") or "")))[:24]


def asset_to_graph_node(asset: dict[str, Any], evidence: list[dict[str, Any]]) -> GraphNode:
    asset_id = str(asset.get("id") or stable_id("asset", asset.get("type"), asset.get("label")))
    label = str(asset.get("label") or asset_id)
    asset_type = normalize_node_type(str(asset.get("type") or "Asset"))
    score = int(asset.get("risk_score") or 0)
    risk = normalize_severity(str(asset.get("risk_level") or severity_from_score(score)))
    description = node_description(asset_type, asset, evidence)
    return GraphNode(
        id=asset_id,
        label=label,
        type=asset_type,
        risk=risk,
        description=description,
        score=score,
        source=str(asset.get("source") or ""),
        source_model=str(asset.get("source_model") or ""),
        evidence_ids=[str(item.get("id")) for item in evidence if item.get("id")],
        properties=compact_dict(
            {
                "locator": asset.get("locator"),
                "properties": asset.get("properties"),
            }
        ),
    )


def finding_to_graph_node(finding: dict[str, Any]) -> GraphNode:
    finding_id = finding_node_id(finding)
    score = int(finding.get("score") or 0)
    node_type = "MultimodalFinding" if str(finding.get("source") or "") == "multimodal_audit" else "Finding"
    return GraphNode(
        id=finding_id,
        label=str(finding.get("title") or finding.get("id") or "Finding"),
        type=node_type,
        risk=normalize_severity(str(finding.get("severity") or severity_from_score(score))),
        description=str(finding.get("recommendation") or finding.get("category") or "Normalized security finding."),
        score=score,
        source=str(finding.get("source") or ""),
        source_model=str(finding.get("source_model") or ""),
        evidence_ids=ensure_string_list(finding.get("evidence_ids")),
        properties=compact_dict(
            {
                "category": finding.get("category"),
                "fingerprint": finding.get("fingerprint"),
                "status": finding.get("status"),
                "properties": finding.get("properties"),
            }
        ),
    )


def finding_node_id(finding: dict[str, Any]) -> str:
    return stable_id("finding-node", finding.get("id") or finding.get("fingerprint") or finding.get("title"))


def normalize_node_type(value: str) -> str:
    if value == "CIWorkflow":
        return "CIStep"
    if value == "TrustFinding":
        return "Finding"
    return value or "Asset"


def node_description(asset_type: str, asset: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
    properties = asset.get("properties") if isinstance(asset.get("properties"), dict) else {}
    if asset_type == "DependencyPackage":
        signals = ensure_list(properties.get("signals"))
        license_value = properties.get("license")
        pieces = []
        if signals:
            pieces.append("; ".join(str(item) for item in signals[:3]))
        if license_value:
            pieces.append(f"license={license_value}")
        return " | ".join(pieces) or "SBOM component normalized from dependency inventory."
    if asset_type == "CodeFile":
        locator = asset.get("locator") if isinstance(asset.get("locator"), dict) else {}
        path = locator.get("path") or asset.get("label")
        line = locator.get("line")
        return f"SARIF-style code location {path}{(':' + str(line)) if line else ''}."
    if asset_type == "CIStep":
        detail = properties.get("detail") or properties.get("workflow") or properties.get("step_name")
        return str(detail or "CI/CD workflow step or build provenance event.")
    if asset_type == "BuildArtifact":
        properties = asset.get("properties") if isinstance(asset.get("properties"), dict) else {}
        digest = properties.get("digest")
        trust_score = properties.get("trust_score")
        if digest:
            return f"Build artifact digest={digest}, trust_score={trust_score}."
        return "Virtual build artifact used to connect build provenance to runtime signals."
    if asset_type == "Attestation":
        return "SLSA/in-toto provenance attestation claiming artifact subject, builder, workflow, and source."
    if asset_type == "TrustedBuilder":
        return "Builder identity claimed by provenance and checked against trust policy."
    if asset_type == "Workflow":
        return "Workflow path claimed by provenance and checked against the allowed release workflow list."
    if asset_type == "SourceCommit":
        return "Source repository commit/ref claimed by provenance and checked against policy."
    if asset_type == "RuntimeService":
        return "Runtime service receiving deployed artifacts and emitting logs."
    if asset_type == "LogEvent":
        signal = properties.get("signal")
        event = properties.get("event")
        return str(signal or event or "Normalized runtime log event.")
    if asset_type in {"AudioEvidence", "VisualEvidence", "MultimodalEvidence"}:
        source_type = properties.get("source_type")
        path = properties.get("relative_path") or properties.get("file_path") or asset.get("label")
        findings = ensure_list(properties.get("findings"))
        entities = ensure_list(properties.get("entities"))
        if findings:
            return f"{source_type or 'multimodal'} evidence stored at {path}; {len(findings)} rule finding(s), {len(entities)} extracted entity/entities."
        return f"{source_type or 'multimodal'} evidence source stored at {path}."
    if asset_type == "MultimodalFinding":
        raw = properties.get("properties") if isinstance(properties.get("properties"), dict) else {}
        keywords = ensure_list(raw.get("matched_keywords"))
        rule_id = raw.get("rule_id")
        return f"Sigma-style multimodal rule finding {rule_id or ''}; matched keywords: {', '.join(str(item) for item in keywords[:5]) or 'n/a'}."
    if asset_type == "RecognizedEntity":
        entity_type = properties.get("type") or "entity"
        value = properties.get("normalized") or properties.get("value") or asset.get("label")
        return f"Security entity extracted from ASR/OCR text: {entity_type}={value}."
    if asset_type == "AttackStage":
        return str(asset.get("description") or "Mapped attack stage.")
    if evidence:
        return str(evidence[0].get("detail") or evidence[0].get("title") or "Evidence-backed asset.")
    return "Normalized graph asset."


def add_vulnerability_nodes(builder: GraphBuilder, facts: dict[str, Any]) -> None:
    for asset in ensure_dicts(facts.get("assets")):
        if str(asset.get("type") or "") != "DependencyPackage":
            continue
        asset_id = str(asset.get("id") or "")
        if not asset_id:
            continue
        properties = asset.get("properties") if isinstance(asset.get("properties"), dict) else {}
        vulnerabilities = ensure_dicts(properties.get("vulnerabilities"))
        signals = ensure_list(properties.get("signals"))
        if not vulnerabilities and dependency_has_vulnerability_signal(signals):
            vulnerabilities = [
                {
                    "id": stable_id("dependency-advisory", asset_id),
                    "severity": asset.get("risk_level") or "medium",
                    "summary": "; ".join(str(signal) for signal in signals[:4]),
                    "source": "dependency-signal",
                }
            ]
        for vulnerability in vulnerabilities:
            vuln_id = str(vulnerability.get("id") or vulnerability.get("source") or "")
            if not vuln_id:
                continue
            node_id = stable_id("vulnerability", vuln_id)
            severity = normalize_severity(str(vulnerability.get("severity") or asset.get("risk_level") or "low"))
            builder.add_node(
                GraphNode(
                    id=node_id,
                    label=vuln_id,
                    type="Vulnerability",
                    risk=severity,
                    description=str(vulnerability.get("summary") or vulnerability.get("affected") or "Dependency vulnerability."),
                    score=score_from_severity(severity),
                    source=str(asset.get("source") or "dependency_audit"),
                    source_model="CycloneDX",
                    properties=compact_dict(vulnerability),
                )
            )
            builder.add_edge(
                GraphEdge(
                    id=stable_id("edge", "HAS_VULNERABILITY", asset_id, node_id),
                    source=asset_id,
                    target=node_id,
                    type="HAS_VULNERABILITY",
                    label="存在漏洞",
                    confidence=0.9,
                    reason="Dependency component carries vulnerability metadata in SBOM-derived facts.",
                )
            )


def add_virtual_artifact_and_service(builder: GraphBuilder, workspace_payload: dict[str, Any]) -> None:
    workspace = workspace_payload.get("workspace") if isinstance(workspace_payload.get("workspace"), dict) else {}
    artifact_label = str(workspace.get("build") or "build-artifact")
    runtime_label = str(workspace.get("runtime") or "runtime-service")
    artifact_id = build_artifact_node_id(workspace_payload)
    service_id = runtime_service_node_id(workspace_payload)
    risk_score = int(workspace_payload.get("summary", {}).get("risk_score") or 0) if isinstance(workspace_payload.get("summary"), dict) else 0
    builder.add_node(
        GraphNode(
            id=artifact_id,
            label=artifact_label,
            type="BuildArtifact",
            risk=severity_from_score(risk_score),
            description="SLSA/in-toto style product node connecting CI steps to runtime deployment.",
            score=min(96, max(60, risk_score)),
            source="workspace",
            source_model="SLSA/in-toto",
            properties={"build": workspace.get("build"), "repository": workspace.get("repository")},
        )
    )
    builder.add_node(
        GraphNode(
            id=service_id,
            label=runtime_label,
            type="RuntimeService",
            risk=severity_from_score(risk_score),
            description="Runtime service deployed from the build artifact and used as the log source anchor.",
            score=min(96, max(55, risk_score)),
            source="workspace",
            source_model="Runtime",
            properties={"runtime": workspace.get("runtime")},
        )
    )
    builder.add_edge(
        GraphEdge(
            id=stable_id("edge", "ARTIFACT_DEPLOYED_AS", artifact_id, service_id),
            source=artifact_id,
            target=service_id,
            type="ARTIFACT_DEPLOYED_AS",
            label="部署为",
            confidence=0.82,
            reason="Workspace runtime metadata links the build artifact to the deployed service.",
        )
    )


def add_artifact_trust_edges(
    builder: GraphBuilder,
    artifact: GraphNode | None,
    attestation: GraphNode | None,
    trusted_builder: GraphNode | None,
    workflow: GraphNode | None,
    source_commit: GraphNode | None,
    findings: list[GraphNode],
) -> None:
    if artifact is None:
        return
    if attestation is not None:
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "ARTIFACT_ATTESTED_BY", artifact.id, attestation.id),
                source=artifact.id,
                target=attestation.id,
                type="ARTIFACT_ATTESTED_BY",
                label="attested by",
                confidence=0.92,
                reason="Artifact trust scan parsed a provenance attestation for this artifact digest.",
                evidence_ids=stable_unique(artifact.evidence_ids + attestation.evidence_ids),
                properties={"model": "SLSA/in-toto", "relationship": "artifact attested by provenance"},
            )
        )
    if source_commit is not None and workflow is not None:
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "SOURCE_COMMIT_TRIGGERS_WORKFLOW", source_commit.id, workflow.id),
                source=source_commit.id,
                target=workflow.id,
                type="SOURCE_COMMIT_TRIGGERS_WORKFLOW",
                label="triggers workflow",
                confidence=0.9,
                reason="Provenance binds the source repository commit/ref to the release workflow invocation.",
                evidence_ids=stable_unique(source_commit.evidence_ids + workflow.evidence_ids),
                properties={
                    "model": "SLSA materials",
                    "relationship": "source commit triggers release workflow",
                    "trust": "Repo, commit/ref, and workflow must match the release policy.",
                },
            )
        )
    if workflow is not None and trusted_builder is not None:
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "WORKFLOW_RUNS_ON_BUILDER", workflow.id, trusted_builder.id),
                source=workflow.id,
                target=trusted_builder.id,
                type="WORKFLOW_RUNS_ON_BUILDER",
                label="runs on",
                confidence=0.9,
                reason="Provenance runDetails links the allowed workflow to the trusted builder identity.",
                evidence_ids=stable_unique(workflow.evidence_ids + trusted_builder.evidence_ids),
                properties={
                    "model": "SLSA builder identity",
                    "relationship": "workflow runs on trusted builder",
                    "trust": "Builder identity and runner environment are checked against trust policy.",
                },
            )
        )
    if trusted_builder is not None:
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "BUILDER_PRODUCES_ARTIFACT", trusted_builder.id, artifact.id),
                source=trusted_builder.id,
                target=artifact.id,
                type="BUILDER_PRODUCES_ARTIFACT",
                label="produces artifact",
                confidence=0.88,
                reason="Trusted builder identity is the execution root that produced the artifact subject digest.",
                evidence_ids=stable_unique(trusted_builder.evidence_ids + artifact.evidence_ids),
                properties={
                    "model": "SLSA provenance",
                    "relationship": "trusted builder produces artifact",
                    "trust": "Artifact digest must match the attested subject produced by this builder.",
                },
            )
        )
    if attestation is not None and source_commit is not None:
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "ATTESTATION_CLAIMS_SOURCE", attestation.id, source_commit.id),
                source=attestation.id,
                target=source_commit.id,
                type="ATTESTATION_CLAIMS_SOURCE",
                label="claims source",
                confidence=0.88,
                reason="Provenance external/internal parameters claim source repository, commit, and ref.",
                evidence_ids=stable_unique(attestation.evidence_ids + source_commit.evidence_ids),
                properties={"model": "SLSA", "relationship": "provenance source material"},
            )
        )
    if attestation is not None and trusted_builder is not None:
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "ATTESTATION_CLAIMS_BUILDER", attestation.id, trusted_builder.id),
                source=attestation.id,
                target=trusted_builder.id,
                type="ATTESTATION_CLAIMS_BUILDER",
                label="claims builder",
                confidence=0.88,
                reason="Provenance runDetails.builder.id was checked against trusted builder policy.",
                evidence_ids=stable_unique(attestation.evidence_ids + trusted_builder.evidence_ids),
                properties={"model": "SLSA", "relationship": "builder identity"},
            )
        )
    if workflow is not None:
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "WORKFLOW_PRODUCES_ARTIFACT", workflow.id, artifact.id),
                source=workflow.id,
                target=artifact.id,
                type="WORKFLOW_PRODUCES_ARTIFACT",
                label="produces artifact",
                confidence=0.86,
                reason="Provenance claims this workflow produced the artifact subject digest.",
                evidence_ids=stable_unique(workflow.evidence_ids + artifact.evidence_ids),
                properties={"model": "GitHub Artifact Attestations", "relationship": "workflow produces artifact"},
            )
        )
    for finding in findings:
        if finding.source != "artifact_trust":
            continue
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "TRUST_FINDING_AFFECTS_ARTIFACT", finding.id, artifact.id),
                source=finding.id,
                target=artifact.id,
                type="TRUST_FINDING_AFFECTS_ARTIFACT",
                label="affects artifact",
                confidence=0.9,
                reason="Artifact trust finding references this verified artifact subject.",
                evidence_ids=stable_unique(finding.evidence_ids + artifact.evidence_ids),
                properties={"model": "DefectDojo-style finding", "relationship": "finding affects artifact"},
            )
        )
        if attestation is not None:
            builder.add_edge(
                GraphEdge(
                    id=stable_id("edge", "TRUST_FINDING_AFFECTS_ATTESTATION", finding.id, attestation.id),
                    source=finding.id,
                    target=attestation.id,
                    type="TRUST_FINDING_AFFECTS_ATTESTATION",
                    label="blocks proof",
                    confidence=0.9,
                    reason="Artifact trust finding blocks or weakens the provenance proof chain.",
                    evidence_ids=stable_unique(finding.evidence_ids + attestation.evidence_ids),
                    properties={"model": "SLSA/in-toto policy", "relationship": "finding blocks provenance proof"},
                )
            )


def add_multimodal_evidence_edges(
    builder: GraphBuilder,
    evidence_nodes: list[GraphNode],
    entity_nodes: list[GraphNode],
    finding_nodes: list[GraphNode],
    dependency_nodes: list[GraphNode],
    ci_nodes: list[GraphNode],
    log_nodes: list[GraphNode],
    service_id: str,
) -> None:
    for evidence in evidence_nodes:
        evidence_props = raw_node_properties(evidence)
        evidence_id = str(evidence_props.get("evidence_id") or "")
        if not evidence_id:
            continue
        related_entities = [
            entity for entity in entity_nodes
            if str(raw_node_properties(entity).get("evidence_id") or "") == evidence_id
        ]
        related_findings = [
            finding for finding in finding_nodes
            if set(finding.evidence_ids).intersection(evidence.evidence_ids)
            or evidence_id in str(finding.properties)
        ]
        for entity in related_entities:
            builder.add_edge(
                GraphEdge(
                    id=stable_id("edge", "MULTIMODAL_EXTRACTS_ENTITY", evidence.id, entity.id),
                    source=evidence.id,
                    target=entity.id,
                    type="MULTIMODAL_EXTRACTS_ENTITY",
                    label="识别出实体",
                    confidence=max(0.72, min(0.96, entity.score / 100 if entity.score else 0.82)),
                    reason="OpenCTI-style observable extracted from ASR/OCR text and attached to the evidence source.",
                    evidence_ids=stable_unique(evidence.evidence_ids + entity.evidence_ids),
                    properties={"model": "OpenCTI Observable", "relationship": "evidence extracts observable"},
                )
            )
        for finding in related_findings:
            builder.add_edge(
                GraphEdge(
                    id=stable_id("edge", "MULTIMODAL_TRIGGERS_RULE", evidence.id, finding.id),
                    source=evidence.id,
                    target=finding.id,
                    type="MULTIMODAL_TRIGGERS_RULE",
                    label="触发规则",
                    confidence=0.9,
                    reason="Sigma-style multimodal rule matched recognized text from this evidence source.",
                    evidence_ids=stable_unique(evidence.evidence_ids + finding.evidence_ids),
                    properties={"model": "Sigma/Wazuh", "relationship": "recognized text triggers rule finding"},
                )
            )
            for entity in related_entities:
                builder.add_edge(
                    GraphEdge(
                        id=stable_id("edge", "MULTIMODAL_FINDING_REFERENCES_ENTITY", finding.id, entity.id),
                        source=finding.id,
                        target=entity.id,
                        type="MULTIMODAL_FINDING_REFERENCES_ENTITY",
                        label="关联实体",
                        confidence=0.88,
                        reason="Multimodal rule finding contains this extracted observable in matched entities.",
                        evidence_ids=stable_unique(finding.evidence_ids + entity.evidence_ids),
                        properties={"model": "OpenCTI Relationship", "relationship": "finding references observable"},
                    )
                )
    for entity in entity_nodes:
        props = raw_node_properties(entity)
        entity_type = str(props.get("type") or "")
        entity_value = str(props.get("normalized") or props.get("value") or entity.label).lower()
        if not entity_value:
            continue
        if entity_type == "package":
            for dependency in matching_nodes_by_text(dependency_nodes, (entity_value,)):
                builder.add_edge(
                    GraphEdge(
                        id=stable_id("edge", "ENTITY_CORRELATES_DEPENDENCY", entity.id, dependency.id),
                        source=entity.id,
                        target=dependency.id,
                        type="ENTITY_CORRELATES_DEPENDENCY",
                        label="关联依赖包",
                        confidence=0.88,
                        reason="GUAC-style package observable matches an SBOM dependency component.",
                        evidence_ids=stable_unique(entity.evidence_ids + dependency.evidence_ids),
                        properties={"model": "GUAC", "relationship": "observable package maps to component"},
                    )
                )
        if entity_type in {"action", "package"}:
            for ci in matching_nodes_by_text(ci_nodes, (entity_value, "postinstall", "curl", "npm", "install"))[:3]:
                builder.add_edge(
                    GraphEdge(
                        id=stable_id("edge", "ENTITY_OBSERVED_IN_BUILD", entity.id, ci.id),
                        source=entity.id,
                        target=ci.id,
                        type="ENTITY_OBSERVED_IN_BUILD",
                        label="构建中出现",
                        confidence=0.76,
                        reason="ASR/OCR observable names build-time behavior also present in CI/CD context.",
                        evidence_ids=stable_unique(entity.evidence_ids + ci.evidence_ids),
                        properties={"model": "GUAC Evidence tree", "relationship": "observable appears in build"},
                    )
                )
        if entity_type == "service" and service_id in builder.nodes:
            service = builder.nodes[service_id]
            if entity_value in node_search_text(service).lower():
                builder.add_edge(
                    GraphEdge(
                        id=stable_id("edge", "ENTITY_CORRELATES_SERVICE", entity.id, service.id),
                        source=entity.id,
                        target=service.id,
                        type="ENTITY_CORRELATES_SERVICE",
                        label="关联运行服务",
                        confidence=0.86,
                        reason="OpenCTI observable service name matches the runtime service anchor.",
                        evidence_ids=stable_unique(entity.evidence_ids + service.evidence_ids),
                        properties={"model": "OpenCTI Observable", "relationship": "observable maps to infrastructure/service"},
                    )
                )
        if entity_type in {"ip", "api_path", "action", "service"}:
            for log in matching_nodes_by_text(log_nodes, (entity_value,))[:4]:
                builder.add_edge(
                    GraphEdge(
                        id=stable_id("edge", "ENTITY_CORRELATES_LOG", entity.id, log.id),
                        source=entity.id,
                        target=log.id,
                        type="ENTITY_CORRELATES_LOG",
                        label="日志印证",
                        confidence=0.84,
                        reason="OpenCTI observable from ASR/OCR text appears in runtime log evidence.",
                        evidence_ids=stable_unique(entity.evidence_ids + log.evidence_ids),
                        properties={"model": "OpenCTI/NetworkX", "relationship": "observable correlated with log"},
                    )
                )


def add_rule_edges_and_attack_paths(
    builder: GraphBuilder,
    facts: dict[str, Any],
    workspace_payload: dict[str, Any],
    evidence_by_id: dict[str, dict[str, Any]],
    findings_by_asset: dict[str, list[dict[str, Any]]],
) -> None:
    dependencies = nodes_by_type(builder, "DependencyPackage")
    code_files = nodes_by_type(builder, "CodeFile")
    ci_steps = nodes_by_type(builder, "CIStep")
    artifacts = nodes_by_type(builder, "BuildArtifact")
    attestations = nodes_by_type(builder, "Attestation")
    trusted_builders = nodes_by_type(builder, "TrustedBuilder")
    workflows = nodes_by_type(builder, "Workflow")
    source_commits = nodes_by_type(builder, "SourceCommit")
    logs = nodes_by_type(builder, "LogEvent")
    findings = nodes_by_type(builder, "Finding") + nodes_by_type(builder, "MultimodalFinding")
    multimodal_evidence = nodes_by_type(builder, "AudioEvidence") + nodes_by_type(builder, "VisualEvidence") + nodes_by_type(builder, "MultimodalEvidence")
    multimodal_findings = nodes_by_type(builder, "MultimodalFinding")
    recognized_entities = nodes_by_type(builder, "RecognizedEntity")
    artifact_id = build_artifact_node_id(workspace_payload)
    service_id = runtime_service_node_id(workspace_payload)

    top_dependency = top_node(dependencies)
    top_code = top_node(code_files)
    build_step = choose_step_node(ci_steps, ("build", "构建", "deploy", "发布", "release"))
    deploy_step = choose_step_node(ci_steps, ("deploy", "发布", "release", "prod"))
    top_ci = build_step or top_node(ci_steps)
    top_artifact = choose_artifact_node(artifacts) or builder.nodes.get(artifact_id)
    top_attestation = top_node(attestations)
    top_builder = top_node(trusted_builders)
    top_workflow = top_node(workflows)
    top_commit = top_node(source_commits)
    if top_artifact is not None:
        artifact_id = top_artifact.id
    add_artifact_trust_edges(builder, top_artifact, top_attestation, top_builder, top_workflow, top_commit, findings)
    add_multimodal_evidence_edges(
        builder,
        multimodal_evidence,
        recognized_entities,
        multimodal_findings,
        dependencies,
        ci_steps,
        logs,
        service_id,
    )
    if top_artifact is not None and top_artifact.id != build_artifact_node_id(workspace_payload):
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "ARTIFACT_DEPLOYED_AS_SERVICE", top_artifact.id, service_id),
                source=top_artifact.id,
                target=service_id,
                type="ARTIFACT_DEPLOYED_AS_SERVICE",
                label="deployed as",
                confidence=0.82,
                reason="Workspace runtime metadata links the verified artifact to the deployed service.",
                evidence_ids=top_artifact.evidence_ids,
                properties={"model": "Runtime deployment", "relationship": "artifact deployed as service"},
            )
        )
    top_log = choose_log_node(logs, ("egress", "外联", "admin", "export", "敏感")) or top_node(logs)
    sql_log = choose_log_node(logs, ("sql", "注入", "sleep", "union", "order_by"))

    if top_code and top_dependency:
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "DECLARES_DEPENDENCY", top_code.id, top_dependency.id),
                source=top_code.id,
                target=top_dependency.id,
                type="DECLARES_DEPENDENCY",
                label="声明依赖入口",
                confidence=0.62,
                reason="Repository or code context declares the risky SBOM component, giving the package a path into the software tree.",
                evidence_ids=stable_unique(top_code.evidence_ids + top_dependency.evidence_ids),
                properties={
                    "model": "GUAC",
                    "relationship": "software tree dependency",
                    "abuse": "If the package is malicious or vulnerable, it can be selected during dependency resolution.",
                    "trust": "Weak unless lockfile and registry policy pin the package source.",
                },
            )
        )

    if top_dependency and top_ci:
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "WORKFLOW_USES", top_ci.id, top_dependency.id),
                source=top_ci.id,
                target=top_dependency.id,
                type="WORKFLOW_USES",
                label="解析/使用依赖",
                confidence=0.72,
                reason="CI step and dependency risk coexist in the same build workspace; GUAC-style component relationship.",
                evidence_ids=stable_unique(top_dependency.evidence_ids + top_ci.evidence_ids),
                properties={
                    "model": "GUAC",
                    "relationship": "workflow uses package",
                    "abuse": "Build automation can resolve and execute package metadata or install hooks.",
                    "trust": "Depends on registry allowlist, lockfile integrity, and clean builder isolation.",
                },
            )
        )
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "DEPENDENCY_REACHES_BUILD", top_dependency.id, top_ci.id),
                source=top_dependency.id,
                target=top_ci.id,
                type="DEPENDENCY_REACHES_BUILD",
                label="可进入构建",
                confidence=0.72,
                reason="Dependency is resolved during CI/CD build execution.",
                evidence_ids=stable_unique(top_dependency.evidence_ids + top_ci.evidence_ids),
                properties={
                    "model": "GUAC",
                    "relationship": "package reaches builder",
                    "abuse": "A poisoned dependency can run install-time behavior or influence generated artifacts.",
                    "trust": "Not trusted without provenance tying materials to the produced artifact.",
                },
            )
        )

    for step in (top_ci, deploy_step):
        if step:
            builder.add_edge(
                GraphEdge(
                    id=stable_id("edge", "STEP_PRODUCES_ARTIFACT", step.id, artifact_id),
                    source=step.id,
                    target=artifact_id,
                    type="STEP_PRODUCES_ARTIFACT",
                    label="生成产物",
                    confidence=0.78,
                    reason="SLSA/in-toto rule maps CI step as a material/product transition.",
                    evidence_ids=step.evidence_ids,
                    properties={
                        "model": "SLSA/in-toto",
                        "relationship": "step product",
                        "abuse": "A compromised step or builder can produce a modified artifact.",
                        "trust": "Needs provenance/attestation with subject digest, builder identity, and materials.",
                    },
                )
            )

    if top_log:
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "SERVICE_EMITS_LOG", service_id, top_log.id),
                source=service_id,
                target=top_log.id,
                type="SERVICE_EMITS_LOG",
                label="产生日志",
                confidence=0.84,
                reason="Runtime service metadata anchors normalized log events.",
                evidence_ids=top_log.evidence_ids,
                properties={
                    "model": "Runtime evidence",
                    "relationship": "service emits observed behavior",
                    "abuse": "Runtime logs show whether the build-time risk manifested after deployment.",
                    "trust": "Stronger when timestamps align with deployment and multiple log sources agree.",
                },
            )
        )

    for log in logs[:8]:
        for finding in related_findings_for_asset(log.id, findings_by_asset, findings):
            builder.add_edge(
                GraphEdge(
                    id=stable_id("edge", "LOG_SUPPORTS_FINDING", log.id, finding.id),
                    source=log.id,
                    target=finding.id,
                    type="LOG_SUPPORTS_FINDING",
                    label="支撑告警",
                    confidence=0.9,
                    reason="Log finding evidence references this normalized LogEvent asset.",
                    evidence_ids=stable_unique(log.evidence_ids + finding.evidence_ids),
                    properties={
                        "model": "Evidence tree",
                        "relationship": "log evidence supports finding",
                        "abuse": "Observed event confirms a behavior rather than only a static vulnerability.",
                        "trust": "Uses parser confidence, rule confidence, and source diversity.",
                    },
                )
            )

    supply_stage = add_attack_stage(
        builder,
        "attack:supply-chain-compromise",
        "供应链投毒阶段",
        "critical",
        "MITRE ATT&CK context: supply-chain compromise and command-and-control style runtime behavior.",
        {"attack": "T1195 Supply Chain Compromise"},
    )
    app_stage = add_attack_stage(
        builder,
        "attack:application-exploitation",
        "应用攻击阶段",
        "high",
        "Runtime exploit traffic mapped to application exploitation.",
        {"attack": "T1190 Exploit Public-Facing Application"},
    )
    build_stage = add_attack_stage(
        builder,
        "attack:build-system-compromise",
        "构建链路风险阶段",
        "high",
        "SLSA/in-toto build integrity risk caused by mutable actions, broad permissions, or remote scripts.",
        {"attack": "T1195.002 Compromise Software Supply Chain"},
    )

    for finding in findings:
        mapped_stage = stage_for_finding(finding)
        stage_id = supply_stage
        if mapped_stage == "application":
            stage_id = app_stage
        elif mapped_stage == "build":
            stage_id = build_stage
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "FINDING_MAPS_TO_ATTACK_STAGE", finding.id, stage_id),
                source=finding.id,
                target=stage_id,
                type="FINDING_MAPS_TO_ATTACK_STAGE",
                label="映射到阶段",
                confidence=0.7,
                reason="Rule-based mapping from finding category/source to ATT&CK-style attack stage.",
                evidence_ids=finding.evidence_ids,
                properties={
                    "model": "ATT&CK/BloodHound-style path",
                    "relationship": "finding maps to attacker objective",
                    "abuse": "The finding represents a behavior or condition used in an attack path.",
                    "trust": "Mapping is heuristic and should be weighted below direct runtime evidence.",
                },
            )
        )

    top_multimodal_evidence, top_multimodal_finding, observable_node = choose_multimodal_path_seed(
        builder,
        multimodal_evidence,
        multimodal_findings,
        recognized_entities,
    )
    if top_multimodal_evidence and top_multimodal_finding and observable_node and top_dependency and top_ci and top_log:
        path_nodes = stable_unique(
            [
                top_multimodal_evidence.id,
                top_multimodal_finding.id,
                observable_node.id,
                top_dependency.id,
                top_ci.id,
                artifact_id,
                service_id,
                top_log.id,
                supply_stage,
            ]
        )
        builder.add_attack_path(
            AttackPath(
                id=stable_id("attack-path", "multimodal-supply-chain", *path_nodes),
                title="多模态证据印证供应链投毒到运行期异常路径",
                category="multimodal-supply-chain-correlation",
                severity="critical",
                score=path_score([top_multimodal_evidence, top_multimodal_finding, observable_node, top_dependency, top_ci, top_log], bonus=16),
                description="ASR/OCR 证据、规则命中、包名/IP/接口等 observable、SBOM 依赖、CI/CD 构建和运行期日志在同一条证据链上相互印证。",
                conclusion=path_conclusion("multimodal-supply-chain-correlation", path_nodes, builder, evidence_by_id),
                verdict=path_verdict("multimodal-supply-chain-correlation", path_nodes, builder, evidence_by_id),
                confidence=path_confidence(path_nodes, builder, evidence_by_id),
                entry_node_id=top_multimodal_evidence.id,
                target_node_id=top_log.id,
                node_ids=path_nodes,
                edge_ids=edge_ids_for_path(builder, path_nodes),
                evidence_ids=evidence_ids_for_nodes(builder, path_nodes),
                recommendation="优先封堵 OCR/ASR 中识别到的依赖包、外联 IP 和敏感接口，并把同时间窗的 CI/CD、SBOM、运行日志作为取证材料保留。",
                path_steps=path_steps_for_path(builder, path_nodes),
                evidence_summary=evidence_summary_for_path(builder, path_nodes, evidence_by_id),
                trust_chain=trust_chain_for_path(builder, path_nodes),
                gaps=evidence_gaps_for_path("multimodal-supply-chain-correlation", path_nodes, builder, evidence_by_id),
                choke_points=choke_points_for_path(builder, path_nodes),
                mappings=[
                    {"framework": "GUAC", "name": "software/evidence tree correlation"},
                    {"framework": "OpenCTI", "name": "observable confidence and relationship graph"},
                    {"framework": "NetworkX", "name": "path scoring and source diversity"},
                ],
                references=["GUAC", "OpenCTI", "NetworkX", "Sigma", "Wazuh"],
            )
        )

    if top_dependency and top_ci and top_log:
        path_nodes = stable_unique(
            [
                node_id_or_empty(top_code),
                top_dependency.id,
                top_ci.id,
                artifact_id,
                service_id,
                top_log.id,
                supply_stage,
            ]
        )
        builder.add_attack_path(
            AttackPath(
                id=stable_id("attack-path", "supply-chain", *path_nodes),
                title="证据可串成供应链投毒到运行期异常的攻击路径",
                category="supply-chain-compromise",
                severity="critical",
                score=path_score([top_dependency, top_ci, top_log], bonus=12),
                description="高危依赖、CI/CD 构建关系、产物部署和运行期异常日志位于同一条可达路径上。",
                conclusion=path_conclusion("supply-chain-compromise", [node_id for node_id in path_nodes if node_id], builder, evidence_by_id),
                verdict=path_verdict("supply-chain-compromise", [node_id for node_id in path_nodes if node_id], builder, evidence_by_id),
                confidence=path_confidence([node_id for node_id in path_nodes if node_id], builder, evidence_by_id),
                entry_node_id=first_node_id(path_nodes),
                target_node_id=top_log.id,
                node_ids=[node_id for node_id in path_nodes if node_id],
                edge_ids=edge_ids_for_path(builder, path_nodes),
                evidence_ids=evidence_ids_for_nodes(builder, path_nodes),
                recommendation="隔离高危依赖，使用干净 runner 重新构建，校验产物哈希，并排查运行期外联。",
                path_steps=path_steps_for_path(builder, path_nodes),
                evidence_summary=evidence_summary_for_path(builder, path_nodes, evidence_by_id),
                trust_chain=trust_chain_for_path(builder, path_nodes),
                gaps=evidence_gaps_for_path("supply-chain-compromise", path_nodes, builder, evidence_by_id),
                choke_points=choke_points_for_path(builder, path_nodes),
                mappings=[{"framework": "MITRE ATT&CK", "technique": "T1195", "name": "Supply Chain Compromise"}],
                references=["GUAC", "SLSA", "in-toto", "BloodHound CE", "MITRE ATT&CK STIX"],
            )
        )

    if top_code and sql_log:
        path_nodes = [top_code.id, sql_log.id, app_stage]
        builder.add_edge(
            GraphEdge(
                id=stable_id("edge", "CODE_RISK_REACHED_BY_LOG", top_code.id, sql_log.id),
                source=top_code.id,
                target=sql_log.id,
                type="LOG_SUPPORTS_FINDING",
                label="运行期触达",
                confidence=0.74,
                reason="Code risk category and runtime SQL injection log match the application attack rule.",
                evidence_ids=stable_unique(top_code.evidence_ids + sql_log.evidence_ids),
            )
        )
        builder.add_attack_path(
            AttackPath(
                id=stable_id("attack-path", "application", *path_nodes),
                title="证据可串成应用漏洞被运行期探测触达的攻击路径",
                category="application-exploitation",
                severity="high",
                score=path_score([top_code, sql_log], bonus=8),
                description="静态代码风险与 SQL 注入日志相互印证，说明风险点已被运行期请求触达。",
                conclusion=path_conclusion("application-exploitation", path_nodes, builder, evidence_by_id),
                verdict=path_verdict("application-exploitation", path_nodes, builder, evidence_by_id),
                confidence=path_confidence(path_nodes, builder, evidence_by_id),
                entry_node_id=top_code.id,
                target_node_id=sql_log.id,
                node_ids=path_nodes,
                edge_ids=edge_ids_for_path(builder, path_nodes),
                evidence_ids=evidence_ids_for_nodes(builder, path_nodes),
                recommendation="修复 SQL 拼接点，增加参数化查询和字段白名单，同时复核相关请求来源。",
                path_steps=path_steps_for_path(builder, path_nodes),
                evidence_summary=evidence_summary_for_path(builder, path_nodes, evidence_by_id),
                trust_chain=trust_chain_for_path(builder, path_nodes),
                gaps=evidence_gaps_for_path("application-exploitation", path_nodes, builder, evidence_by_id),
                choke_points=choke_points_for_path(builder, path_nodes),
                mappings=[{"framework": "MITRE ATT&CK", "technique": "T1190", "name": "Exploit Public-Facing Application"}],
                references=["SARIF", "BloodHound CE", "MITRE ATT&CK STIX", "React Flow"],
            )
        )

    build_risk = choose_step_node(ci_steps, ("write", "权限", "main", "remote", "curl", "未固定", "third-party"))
    if build_risk:
        path_nodes = [build_risk.id, artifact_id, service_id, build_stage]
        builder.add_attack_path(
            AttackPath(
                id=stable_id("attack-path", "build-integrity", *path_nodes),
                title="证据可串成构建链路完整性受损路径",
                category="build-integrity-risk",
                severity=build_risk.risk,
                score=path_score([build_risk], bonus=10),
                description="CI/CD 风险通过 SLSA/in-toto 的 step -> product 关系影响产物可信度，并继续到运行资产。",
                conclusion=path_conclusion("build-integrity-risk", path_nodes, builder, evidence_by_id),
                verdict=path_verdict("build-integrity-risk", path_nodes, builder, evidence_by_id),
                confidence=path_confidence(path_nodes, builder, evidence_by_id),
                entry_node_id=build_risk.id,
                target_node_id=service_id,
                node_ids=path_nodes,
                edge_ids=edge_ids_for_path(builder, path_nodes),
                evidence_ids=evidence_ids_for_nodes(builder, path_nodes),
                recommendation="收敛 workflow 权限，第三方 Action 固定到 commit SHA，并为产物增加 provenance/attestation。",
                path_steps=path_steps_for_path(builder, path_nodes),
                evidence_summary=evidence_summary_for_path(builder, path_nodes, evidence_by_id),
                trust_chain=trust_chain_for_path(builder, path_nodes),
                gaps=evidence_gaps_for_path("build-integrity-risk", path_nodes, builder, evidence_by_id),
                choke_points=choke_points_for_path(builder, path_nodes),
                mappings=[{"framework": "SLSA", "name": "Build provenance and integrity"}],
                references=["SLSA", "in-toto", "GUAC", "BloodHound CE"],
            )
        )

    trust_findings = [
        finding
        for finding in findings
        if finding.source == "artifact_trust" or finding.properties.get("category") == "artifact-trust"
    ]
    top_trust_finding = top_node(trust_findings)
    if top_artifact and top_attestation and (top_trust_finding or top_builder or top_workflow or top_commit):
        path_nodes = stable_unique(
            [
                node_id_or_empty(top_commit),
                node_id_or_empty(top_workflow),
                node_id_or_empty(top_builder),
                top_artifact.id,
                top_attestation.id,
            ]
            + ([node_id_or_empty(top_trust_finding), build_stage] if top_trust_finding else [])
        )
        trust_checks = artifact_trust_checks_for_path(workspace_payload)
        trust_score = artifact_trust_score_for_path(workspace_payload, top_artifact)
        is_verified_provenance = top_trust_finding is None
        path_severity = top_trust_finding.risk if top_trust_finding else top_artifact.risk
        builder.add_attack_path(
            AttackPath(
                id=stable_id("attack-path", "artifact-trust", *path_nodes),
                title="产物可信链路验证路径",
                category="verified-provenance-chain" if is_verified_provenance else "artifact-trust",
                severity=path_severity,
                score=trust_score or path_score([node for node in [top_artifact, top_attestation, top_trust_finding] if node is not None], bonus=10),
                description="commit、workflow、builder、artifact 与 provenance attestation 已被串成发布前/部署前可信验证链。",
                conclusion=artifact_trust_path_conclusion(path_nodes, builder),
                verdict="verified-provenance-chain" if is_verified_provenance else "provenance-risk-path",
                confidence=artifact_trust_confidence_for_path(trust_score, trust_checks, path_nodes, builder, evidence_by_id),
                entry_node_id=first_node_id(path_nodes),
                target_node_id=top_artifact.id,
                node_ids=path_nodes,
                edge_ids=edge_ids_for_path(builder, path_nodes),
                evidence_ids=evidence_ids_for_nodes(builder, path_nodes),
                recommendation="将该产物可信验证结果作为发布门禁；digest、签名、builder、workflow 或来源任一失败时阻断发布。",
                path_steps=path_steps_for_path(builder, path_nodes),
                evidence_summary=evidence_summary_for_path(builder, path_nodes, evidence_by_id),
                trust_chain=trust_chain_for_path(builder, path_nodes),
                checks=trust_checks,
                trust_score=trust_score,
                gaps=evidence_gaps_for_path("artifact-trust", path_nodes, builder, evidence_by_id),
                choke_points=choke_points_for_path(builder, path_nodes),
                mappings=[{"framework": "SLSA", "name": "Verify artifact provenance"}],
                references=["SLSA", "in-toto", "Sigstore Cosign", "GitHub Artifact Attestations", "GUAC"],
            )
        )


def add_attack_stage(
    builder: GraphBuilder,
    node_id: str,
    label: str,
    risk: str,
    description: str,
    properties: dict[str, Any],
) -> str:
    builder.add_node(
        GraphNode(
            id=node_id,
            label=label,
            type="AttackStage",
            risk=risk,
            description=description,
            score=score_from_severity(risk),
            source="attack-stage-mapping",
            source_model="MITRE ATT&CK STIX",
            properties=properties,
        )
    )
    return node_id


def map_finding_to_attack_stage(builder: GraphBuilder, finding: dict[str, Any]) -> None:
    # Stage nodes are created after all facts are loaded; edges are added in add_rule_edges_and_attack_paths.
    return None


def stage_for_finding(finding: GraphNode) -> str:
    searchable = f"{finding.label} {finding.description} {finding.source} {finding.properties}".lower()
    if any(token in searchable for token in ("sql", "xss", "application", "代码", "注入")):
        return "application"
    if any(token in searchable for token in ("cicd", "workflow", "github-actions", "action", "权限", "构建")):
        return "build"
    return "supply-chain"


def nodes_by_type(builder: GraphBuilder, node_type: str) -> list[GraphNode]:
    return [node for node in builder.nodes.values() if node.type == node_type]


def raw_node_properties(node: GraphNode) -> dict[str, Any]:
    props = node.properties.get("properties") if isinstance(node.properties.get("properties"), dict) else {}
    return props if isinstance(props, dict) else {}


def node_search_text(node: GraphNode) -> str:
    return f"{node.id} {node.label} {node.type} {node.description} {node.source} {node.source_model} {node.properties}"


def matching_nodes_by_text(nodes: list[GraphNode], tokens: tuple[str, ...]) -> list[GraphNode]:
    clean_tokens = [token.lower().strip() for token in tokens if token and token.strip()]
    if not clean_tokens:
        return []
    matches = []
    for node in nodes:
        searchable = node_search_text(node).lower()
        if any(token in searchable for token in clean_tokens):
            matches.append(node)
    return sorted(matches, key=lambda item: (-item.score, item.label))


def top_node(nodes: list[GraphNode]) -> GraphNode | None:
    if not nodes:
        return None
    return sorted(nodes, key=lambda item: (-item.score, item.label))[0]


def choose_step_node(nodes: list[GraphNode], tokens: tuple[str, ...]) -> GraphNode | None:
    candidates = []
    for node in nodes:
        searchable = f"{node.label} {node.description} {node.properties}".lower()
        if any(token.lower() in searchable for token in tokens):
            candidates.append(node)
    return top_node(candidates) or top_node(nodes)


def choose_log_node(nodes: list[GraphNode], tokens: tuple[str, ...]) -> GraphNode | None:
    candidates = []
    for node in nodes:
        searchable = f"{node.label} {node.description} {node.properties}".lower()
        if any(token.lower() in searchable for token in tokens):
            candidates.append(node)
    return top_node(candidates)


def choose_entity_node(nodes: list[GraphNode], entity_type: str) -> GraphNode | None:
    candidates = [
        node for node in nodes
        if str(raw_node_properties(node).get("type") or "").lower() == entity_type.lower()
    ]
    return top_node(candidates)


def choose_multimodal_path_seed(
    builder: GraphBuilder,
    evidence_nodes: list[GraphNode],
    finding_nodes: list[GraphNode],
    entity_nodes: list[GraphNode],
) -> tuple[GraphNode | None, GraphNode | None, GraphNode | None]:
    evidence_by_id = {node.id: node for node in evidence_nodes}
    finding_by_id = {node.id: node for node in finding_nodes}
    entity_by_id = {node.id: node for node in entity_nodes}
    preferred_entity_types = {"package": 0, "ip": 1, "api_path": 2, "service": 3, "action": 4}
    candidates: list[tuple[int, GraphNode, GraphNode, GraphNode]] = []
    for edge in builder.edges.values():
        if edge.type != "MULTIMODAL_TRIGGERS_RULE":
            continue
        evidence = evidence_by_id.get(edge.source)
        finding = finding_by_id.get(edge.target)
        if evidence is None or finding is None:
            continue
        entity_edges = [
            item for item in builder.edges.values()
            if item.source == finding.id
            and item.target in entity_by_id
            and item.type == "MULTIMODAL_FINDING_REFERENCES_ENTITY"
        ]
        if not entity_edges:
            entity_edges = [
                item for item in builder.edges.values()
                if item.source == evidence.id
                and item.target in entity_by_id
                and item.type == "MULTIMODAL_EXTRACTS_ENTITY"
            ]
        for entity_edge in entity_edges:
            entity = entity_by_id.get(entity_edge.target)
            if entity is None:
                continue
            entity_type = str(raw_node_properties(entity).get("type") or "")
            rank = preferred_entity_types.get(entity_type, 9)
            score = finding.score + evidence.score + entity.score - rank * 4
            candidates.append((score, evidence, finding, entity))
    if candidates:
        _, evidence, finding, entity = sorted(candidates, key=lambda item: (-item[0], item[1].label, item[2].label))[0]
        return evidence, finding, entity
    return top_node(evidence_nodes), top_node(finding_nodes), choose_entity_node(entity_nodes, "package") or top_node(entity_nodes)


def choose_artifact_node(nodes: list[GraphNode]) -> GraphNode | None:
    trusted = [node for node in nodes if node.source == "artifact_trust" or node.properties.get("properties", {}).get("digest")]
    return top_node(trusted) or top_node(nodes)


def related_findings_for_asset(
    asset_id: str,
    findings_by_asset: dict[str, list[dict[str, Any]]],
    finding_nodes: list[GraphNode],
) -> list[GraphNode]:
    related_raw_ids = {str(item.get("id") or "") for item in findings_by_asset.get(asset_id, [])}
    result = []
    for node in finding_nodes:
        raw_id = str(node.properties.get("properties", {}).get("id") or "")
        if raw_id in related_raw_ids or asset_id in str(node.properties):
            result.append(node)
    if result:
        return result[:4]
    return [node for node in finding_nodes if "log" in node.source.lower()][:4]


def path_score(nodes: list[GraphNode], *, bonus: int = 0) -> int:
    base = max([node.score for node in nodes] + [0])
    source_count = len({node.source for node in nodes if node.source})
    return min(100, base + bonus + min(10, source_count * 2) + min(8, len(nodes)))


def edge_ids_for_path(builder: GraphBuilder, node_ids: list[str]) -> list[str]:
    clean = [node_id for node_id in node_ids if node_id]
    edge_ids: list[str] = []
    for source, target in zip(clean, clean[1:]):
        match = next((edge for edge in builder.edges.values() if edge.source == source and edge.target == target), None)
        if match is None:
            match = next((edge for edge in builder.edges.values() if edge.source == target and edge.target == source), None)
        if match is not None:
            edge_ids.append(match.id)
    return edge_ids


def evidence_ids_for_nodes(builder: GraphBuilder, node_ids: list[str]) -> list[str]:
    evidence_ids: list[str] = []
    for node_id in node_ids:
        node = builder.nodes.get(node_id)
        if node is not None:
            evidence_ids.extend(node.evidence_ids)
    return stable_unique(evidence_ids)


def node_id_or_empty(node: GraphNode | None) -> str:
    return node.id if node is not None else ""


def first_node_id(node_ids: list[str]) -> str:
    return next((node_id for node_id in node_ids if node_id), "")


def edge_for_step(builder: GraphBuilder, source: str, target: str) -> GraphEdge | None:
    match = next((edge for edge in builder.edges.values() if edge.source == source and edge.target == target), None)
    if match is not None:
        return match
    return next((edge for edge in builder.edges.values() if edge.source == target and edge.target == source), None)


def path_steps_for_path(builder: GraphBuilder, node_ids: list[str]) -> list[dict[str, Any]]:
    clean = [node_id for node_id in node_ids if node_id]
    steps: list[dict[str, Any]] = []
    for index, (source_id, target_id) in enumerate(zip(clean, clean[1:]), start=1):
        source = builder.nodes.get(source_id)
        target = builder.nodes.get(target_id)
        edge = edge_for_step(builder, source_id, target_id)
        if source is None or target is None:
            continue
        edge_properties = edge.properties if edge is not None else {}
        steps.append(
            compact_dict(
                {
                    "index": index,
                    "source": source.label,
                    "source_type": source.type,
                    "target": target.label,
                    "target_type": target.type,
                    "relationship": edge.label if edge is not None else "关联",
                    "edge_type": edge.type if edge is not None else "",
                    "confidence": edge.confidence if edge is not None else 0.5,
                    "why_abusable": edge_properties.get("abuse") or (edge.reason if edge is not None else ""),
                    "trust_basis": edge_properties.get("trust") or source.source_model or target.source_model,
                    "model": edge_properties.get("model"),
                    "evidence_ids": edge.evidence_ids if edge is not None else [],
                }
            )
        )
    return steps


def evidence_summary_for_path(
    builder: GraphBuilder,
    node_ids: list[str],
    evidence_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    evidence_ids = evidence_ids_for_nodes(builder, node_ids)
    result: list[dict[str, Any]] = []
    for evidence_id in evidence_ids[:12]:
        item = evidence_by_id.get(evidence_id)
        if not item:
            continue
        result.append(
            compact_dict(
                {
                    "id": evidence_id,
                    "kind": item.get("kind"),
                    "title": item.get("title"),
                    "detail": short_text(str(item.get("detail") or ""), 180),
                    "source": item.get("source"),
                    "source_model": item.get("source_model"),
                    "time": item.get("time"),
                    "confidence": item.get("confidence"),
                }
            )
        )
    return result


def trust_chain_for_path(builder: GraphBuilder, node_ids: list[str]) -> list[dict[str, Any]]:
    clean = [node_id for node_id in node_ids if node_id]
    result: list[dict[str, Any]] = []
    for node_id in clean:
        node = builder.nodes.get(node_id)
        if node is None:
            continue
        if node.type == "Attestation":
            result.append({"node_id": node.id, "label": node.label, "action": "使用 gh/cosign 验证 envelope 签名，并确认 subject digest 与当前产物一致。"})
            continue
        if node.type == "TrustedBuilder":
            result.append({"node_id": node.id, "label": node.label, "action": "将 builder.id 纳入可信 builder 策略，未知 builder 产物一律重新构建。"})
            continue
        if node.type == "Workflow":
            result.append({"node_id": node.id, "label": node.label, "action": "仅允许受审计 release workflow 生成可部署产物。"})
            continue
        if node.type == "DependencyPackage":
            result.append(
                {
                    "model": "GUAC",
                    "claim": "软件树中存在可达依赖节点",
                    "subject": node.label,
                    "status": "observed",
                    "basis": node.source_model or node.source,
                }
            )
        elif node.type == "CIStep":
            result.append(
                {
                    "model": "in-toto",
                    "claim": "构建步骤将 material 转换为 product",
                    "subject": node.label,
                    "status": "needs-attestation" if node.risk in {"critical", "high"} else "observed",
                    "basis": "workflow evidence",
                }
            )
        elif node.type == "BuildArtifact":
            result.append(
                {
                    "model": "SLSA",
                    "claim": "产物需要 subject digest、builder identity 和 materials provenance",
                    "subject": node.label,
                    "status": "gap" if node.risk in {"critical", "high"} else "observed",
                    "basis": node.description,
                }
            )
        elif node.type == "Attestation":
            result.append(
                {
                    "model": "in-toto/SLSA",
                    "claim": "provenance attestation binds artifact subject digest to source, workflow, and builder claims",
                    "subject": node.label,
                    "status": "observed",
                    "basis": node.description,
                }
            )
        elif node.type == "TrustedBuilder":
            result.append(
                {
                    "model": "SLSA",
                    "claim": "builder identity is part of the enterprise root of trust",
                    "subject": node.label,
                    "status": "trusted" if node.risk == "low" else "needs-review",
                    "basis": node.description,
                }
            )
        elif node.type == "Workflow":
            result.append(
                {
                    "model": "GitHub Artifact Attestations",
                    "claim": "workflow path is allowed to produce release artifacts",
                    "subject": node.label,
                    "status": "observed",
                    "basis": node.description,
                }
            )
        elif node.type == "SourceCommit":
            result.append(
                {
                    "model": "SLSA materials",
                    "claim": "source repository and commit/ref are claimed by provenance",
                    "subject": node.label,
                    "status": "observed",
                    "basis": node.description,
                }
            )
        elif node.type == "LogEvent":
            result.append(
                {
                    "model": "Runtime evidence",
                    "claim": "运行期行为证明风险可能已经触发",
                    "subject": node.label,
                    "status": "observed",
                    "basis": node.source_model or node.source,
                }
            )
    return result


def evidence_gaps_for_path(
    category: str,
    node_ids: list[str],
    builder: GraphBuilder,
    evidence_by_id: dict[str, dict[str, Any]],
) -> list[str]:
    clean = [node_id for node_id in node_ids if node_id]
    node_types = {builder.nodes[node_id].type for node_id in clean if node_id in builder.nodes}
    source_models = {
        builder.nodes[node_id].source_model
        for node_id in clean
        if node_id in builder.nodes and builder.nodes[node_id].source_model
    }
    gaps: list[str] = []
    if category == "artifact-trust":
        if "Attestation" not in node_types:
            gaps.append("缺少 provenance/attestation，无法证明产物由声明的源码和构建流程生成。")
        if "TrustedBuilder" not in node_types:
            gaps.append("缺少可信 builder 身份，无法建立企业根信任。")
        has_trust_finding = any(
            builder.nodes[node_id].source == "artifact_trust" and builder.nodes[node_id].type == "Finding"
            for node_id in clean
            if node_id in builder.nodes
        )
        if not has_trust_finding:
            gaps.append("当前产物可信链未发现失败项；可继续补充 gh/cosign 在线验签记录和历史 hash 基线。")
        return gaps
    if "DependencyPackage" in node_types and "CIStep" not in node_types:
        gaps.append("缺少依赖被 CI/CD 解析或执行的直接证据。")
    if category == "multimodal-supply-chain-correlation":
        if not {"AudioEvidence", "VisualEvidence", "MultimodalEvidence"}.intersection(node_types):
            gaps.append("缺少截图 OCR、音频 ASR 或视频帧 OCR 证据，无法形成跨模态印证。")
        if "MultimodalFinding" not in node_types:
            gaps.append("缺少多模态规则命中结果，只能作为普通文本证据。")
        if "RecognizedEntity" not in node_types:
            gaps.append("缺少从 ASR/OCR 文本抽取出的 IP、包名、接口或服务实体。")
        if "LogEvent" not in node_types:
            gaps.append("缺少运行期日志印证，无法证明截图/语音里的行为确实落到生产服务。")
    if "CIStep" in node_types and "BuildArtifact" in node_types and not any("SLSA" in model or "in-toto" in model for model in source_models):
        gaps.append("缺少产物 provenance/attestation，无法强证明材料、builder 与产物摘要。")
    if category == "supply-chain-compromise" and "LogEvent" not in node_types:
        gaps.append("缺少运行期日志，当前只能证明供应链暴露面，不能证明已触发。")
    if category == "application-exploitation" and "CodeFile" not in node_types:
        gaps.append("缺少静态代码位置，无法把运行期请求绑定到具体漏洞点。")
    if not evidence_ids_for_nodes(builder, clean):
        gaps.append("路径节点没有关联证据片段，需要补充扫描结果或日志。")
    if not gaps and path_confidence(clean, builder, evidence_by_id) < 0.82:
        gaps.append("路径关系可达，但部分边是启发式关联；建议补充时间线、产物哈希或来源 IP 证据。")
    return gaps


def choke_points_for_path(builder: GraphBuilder, node_ids: list[str]) -> list[dict[str, Any]]:
    clean = [node_id for node_id in node_ids if node_id]
    result: list[dict[str, Any]] = []
    for node_id in clean:
        node = builder.nodes.get(node_id)
        if node is None:
            continue
        if node.type == "DependencyPackage":
            result.append({"node_id": node.id, "label": node.label, "action": "固定私有源、锁定版本并清理缓存包。"})
        elif node.type == "CIStep":
            result.append({"node_id": node.id, "label": node.label, "action": "收敛权限、固定 Action 到 commit SHA，并使用干净 runner。"})
        elif node.type == "BuildArtifact":
            result.append({"node_id": node.id, "label": node.label, "action": "重新构建并校验产物哈希/provenance。"})
        elif node.type == "RuntimeService":
            result.append({"node_id": node.id, "label": node.label, "action": "回滚或隔离服务实例，保留日志和镜像证据。"})
        elif node.type == "LogEvent":
            result.append({"node_id": node.id, "label": node.label, "action": "封禁相关来源/目的地址并扩大同时间窗排查。"})
    return result[:5]


def path_confidence(
    node_ids: list[str],
    builder: GraphBuilder,
    evidence_by_id: dict[str, dict[str, Any]],
) -> float:
    clean = [node_id for node_id in node_ids if node_id]
    edges = [edge_for_step(builder, source, target) for source, target in zip(clean, clean[1:])]
    edge_confidences = [edge.confidence for edge in edges if edge is not None]
    edge_value = sum(edge_confidences) / len(edge_confidences) if edge_confidences else 0.5
    evidence_ids = evidence_ids_for_nodes(builder, clean)
    evidence_sources = {
        str(evidence_by_id[evidence_id].get("source") or "")
        for evidence_id in evidence_ids
        if evidence_id in evidence_by_id
    }
    source_bonus = min(0.18, len([source for source in evidence_sources if source]) * 0.045)
    runtime_bonus = 0.08 if any(builder.nodes[node_id].type == "LogEvent" for node_id in clean if node_id in builder.nodes) else 0
    return round(min(0.98, edge_value * 0.78 + source_bonus + runtime_bonus), 2)


def path_verdict(
    category: str,
    node_ids: list[str],
    builder: GraphBuilder,
    evidence_by_id: dict[str, dict[str, Any]],
) -> str:
    clean = [node_id for node_id in node_ids if node_id]
    node_types = {builder.nodes[node_id].type for node_id in clean if node_id in builder.nodes}
    confidence = path_confidence(clean, builder, evidence_by_id)
    if category == "artifact-trust" and {"BuildArtifact", "Attestation"}.issubset(node_types):
        has_trust_finding = any(
            builder.nodes[node_id].source == "artifact_trust" and builder.nodes[node_id].type == "Finding"
            for node_id in clean
            if node_id in builder.nodes
        )
        return "provenance-risk-path" if has_trust_finding else "verified-provenance-chain"
    if category == "supply-chain-compromise" and {"DependencyPackage", "CIStep", "BuildArtifact", "RuntimeService", "LogEvent"}.issubset(node_types):
        return "likely-real-attack-path" if confidence >= 0.78 else "plausible-attack-path"
    if category == "multimodal-supply-chain-correlation":
        has_multimodal = bool({"AudioEvidence", "VisualEvidence", "MultimodalEvidence"}.intersection(node_types))
        if has_multimodal and {"MultimodalFinding", "RecognizedEntity", "DependencyPackage", "CIStep", "RuntimeService", "LogEvent"}.issubset(node_types):
            return "cross-modal-corroborated-path" if confidence >= 0.78 else "plausible-cross-modal-path"
    if category == "application-exploitation" and {"CodeFile", "LogEvent"}.issubset(node_types):
        return "runtime-touched-risk" if confidence >= 0.68 else "plausible-runtime-touch"
    if category == "build-integrity-risk" and {"CIStep", "BuildArtifact", "RuntimeService"}.issubset(node_types):
        return "provenance-risk-path"
    return "insufficient-evidence"


def artifact_trust_path_conclusion(node_ids: list[str], builder: GraphBuilder) -> str:
    clean = [node_id for node_id in node_ids if node_id in builder.nodes]
    labels_by_type = {builder.nodes[node_id].type: builder.nodes[node_id].label for node_id in clean}
    has_finding = any(builder.nodes[node_id].source == "artifact_trust" and builder.nodes[node_id].type == "Finding" for node_id in clean)
    artifact = labels_by_type.get("BuildArtifact", "artifact")
    workflow = labels_by_type.get("Workflow", "workflow")
    source = labels_by_type.get("SourceCommit", "source")
    builder_label = labels_by_type.get("TrustedBuilder", "builder")
    if has_finding:
        return (
            f"产物 {artifact} 的可信链存在阻断项；需要复核 {source} -> {workflow} -> "
            f"{builder_label} -> artifact -> attestation 的 digest、签名和策略匹配结果。"
        )
    return (
        f"产物 {artifact} 已串联 {source} -> {workflow} -> {builder_label} -> "
        "artifact -> attestation，当前未发现阻断项。"
    )


def artifact_trust_checks_for_path(workspace_payload: dict[str, Any]) -> list[dict[str, Any]]:
    artifact_trust = workspace_payload.get("artifact_trust") if isinstance(workspace_payload.get("artifact_trust"), dict) else {}
    raw_checks = ensure_dicts(artifact_trust.get("checks")) if artifact_trust else []
    provenance = artifact_trust.get("provenance") if isinstance(artifact_trust.get("provenance"), dict) else {}
    digest = str(artifact_trust.get("digest") or provenance.get("subject_digest") or "")
    policy = artifact_trust.get("policy") if isinstance(artifact_trust.get("policy"), dict) else {}

    by_name = {str(check.get("name") or ""): check for check in raw_checks}
    specs = [
        ("artifact_digest_matches_subject", "Digest", "匹配", digest or "产物 SHA256 与 attestation subject digest 匹配"),
        ("source_repository_allowed", "Repo", "匹配", provenance.get("source_repo") or policy.get("expected_repo") or "来源仓库匹配策略"),
        (
            "commit_matches_expected" if "commit_matches_expected" in by_name else "commit_or_branch_allowed",
            "Commit",
            "匹配",
            provenance.get("commit") or provenance.get("ref") or policy.get("expected_commit") or "commit/ref 匹配策略",
        ),
        ("workflow_allowed", "Workflow", "允许", provenance.get("workflow") or "release workflow 在允许列表中"),
        ("builder_trusted", "Builder", "可信", provenance.get("builder_id") or "builder.id 在可信列表中"),
        ("runner_environment_trusted", "Runner", "github-hosted", provenance.get("runner_environment") or "runner 环境可信"),
        (
            "provenance_predicate_type_slsa",
            "Predicate",
            "SLSA",
            provenance.get("predicateType") or provenance.get("predicate_type") or "SLSA provenance predicate",
        ),
        ("attestation_max_age", "Attestation", "新鲜", "attestation 创建时间满足策略窗口"),
        ("artifact_hash_baseline", "Hash baseline", "已检查", "历史 hash 基线已检查；无基线时不作为阻断项"),
        ("signature_verified", "Signature", "gh attestation verify 通过", "gh attestation verify 通过"),
    ]

    normalized: list[dict[str, Any]] = []
    for check_id, label, pass_label, fallback_evidence in specs:
        raw = by_name.get(check_id, {})
        status = str(raw.get("status") or "pass")
        display_value = trust_check_value(check_id, status, pass_label)
        normalized.append(
            compact_dict(
                {
                    "id": check_id,
                    "name": check_id,
                    "label": label,
                    "status": status,
                    "value": display_value,
                    "evidence": raw.get("evidence") or fallback_evidence,
                    "severity": raw.get("severity"),
                    "score": raw.get("score"),
                }
            )
        )
    return normalized


def trust_check_value(check_id: str, status: str, pass_label: str) -> str:
    if status == "pass":
        return pass_label
    if status == "skipped" and check_id == "artifact_hash_baseline":
        return "未配置基线"
    if status == "skipped":
        return "未配置策略"
    if status == "warn":
        return "需复核"
    if status == "missing":
        return "缺失"
    if status == "fail":
        return "失败"
    return status or pass_label


def artifact_trust_score_for_path(workspace_payload: dict[str, Any], artifact: GraphNode | None) -> int:
    artifact_trust = workspace_payload.get("artifact_trust") if isinstance(workspace_payload.get("artifact_trust"), dict) else {}
    raw_score = artifact_trust.get("trust_score") or artifact_trust.get("trustScore") if artifact_trust else None
    try:
        return max(0, min(100, int(raw_score)))
    except (TypeError, ValueError):
        pass
    if artifact is not None:
        try:
            return max(0, min(100, int(artifact.properties.get("trust_score"))))
        except (TypeError, ValueError):
            return 0
    return 0


def artifact_trust_confidence_for_path(
    trust_score: int,
    checks: list[dict[str, Any]],
    node_ids: list[str],
    builder: GraphBuilder,
    evidence_by_id: dict[str, dict[str, Any]],
) -> float:
    if checks:
        pass_like = sum(1 for check in checks if str(check.get("status")) in {"pass", "skipped"})
        coverage = pass_like / max(1, len(checks))
        score_value = (trust_score or 0) / 100
        return round(min(0.99, max(0.5, score_value * 0.7 + coverage * 0.29)), 2)
    return path_confidence(node_ids, builder, evidence_by_id)


def path_conclusion(
    category: str,
    node_ids: list[str],
    builder: GraphBuilder,
    evidence_by_id: dict[str, dict[str, Any]],
) -> str:
    verdict = path_verdict(category, node_ids, builder, evidence_by_id)
    confidence = path_confidence(node_ids, builder, evidence_by_id)
    if verdict == "likely-real-attack-path":
        return f"能串成一次高度可信的真实攻击路径：入口、构建、产物、运行期行为连续可达，综合置信度 {round(confidence * 100)}%。"
    if verdict == "cross-modal-corroborated-path":
        return f"OCR/ASR 多模态证据、规则命中、依赖/构建关系和运行期日志相互印证，能串成跨模态高可信供应链攻击路径，综合置信度 {round(confidence * 100)}%。"
    if verdict == "plausible-cross-modal-path":
        return f"多模态证据已与供应链和运行期节点形成可达关系，但仍有证据缺口；当前适合作为优先排查路径，综合置信度 {round(confidence * 100)}%。"
    if verdict == "runtime-touched-risk":
        return f"能串成运行期触达路径：静态风险点和日志探测互相印证，综合置信度 {round(confidence * 100)}%。"
    if verdict == "provenance-risk-path":
        return f"能串成构建完整性风险路径，但还需要 provenance/attestation 才能证明产物确被篡改，综合置信度 {round(confidence * 100)}%。"
    if verdict == "plausible-attack-path":
        return f"可以串成合理攻击路径，但仍有证据缺口；当前更适合作为优先排查路径，综合置信度 {round(confidence * 100)}%。"
    return f"证据目前不足以证明真实攻击路径，只能说明存在相邻风险信号，综合置信度 {round(confidence * 100)}%。"


def build_artifact_node_id(workspace_payload: dict[str, Any]) -> str:
    workspace = workspace_payload.get("workspace") if isinstance(workspace_payload.get("workspace"), dict) else {}
    return stable_id("asset", "build-artifact", workspace.get("build") or "build-artifact")


def runtime_service_node_id(workspace_payload: dict[str, Any]) -> str:
    workspace = workspace_payload.get("workspace") if isinstance(workspace_payload.get("workspace"), dict) else {}
    return stable_id("asset", "runtime-service", workspace.get("runtime") or "runtime-service")


def assign_node_positions(nodes: dict[str, GraphNode]) -> None:
    buckets: dict[int, list[GraphNode]] = {}
    for node in nodes.values():
        rank = NODE_TYPE_RANK.get(node.type, 99)
        buckets.setdefault(rank, []).append(node)
    for rank, bucket in buckets.items():
        for index, node in enumerate(sorted(bucket, key=lambda item: (-item.score, item.label))):
            if node.position:
                continue
            node.position = {"x": rank * 250, "y": 60 + index * 140}


def build_graph_summary(
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    attack_paths: list[AttackPath],
) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_edge_type: dict[str, int] = {}
    by_verdict: dict[str, int] = {}
    for node in nodes:
        by_type[node.type] = by_type.get(node.type, 0) + 1
    for edge in edges:
        by_edge_type[edge.type] = by_edge_type.get(edge.type, 0) + 1
    for path in attack_paths:
        by_verdict[path.verdict] = by_verdict.get(path.verdict, 0) + 1
    risk_score = max([node.score for node in nodes] + [path.score for path in attack_paths] + [0])
    average_confidence = round(sum(path.confidence for path in attack_paths) / len(attack_paths), 2) if attack_paths else 0
    actionable_count = sum(1 for path in attack_paths if path.verdict != "insufficient-evidence")
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "attack_path_count": len(attack_paths),
        "actionable_attack_path_count": actionable_count,
        "real_attack_path_count": by_verdict.get("likely-real-attack-path", 0),
        "path_verdicts": by_verdict,
        "average_path_confidence": average_confidence,
        "risk_score": risk_score,
        "risk_level": severity_from_score(risk_score),
        "node_types": by_type,
        "edge_types": by_edge_type,
    }


def dataclass_to_public(item: Any) -> dict[str, Any]:
    return {key: value for key, value in item.__dict__.items() if value not in (None, "", {})}


def dependency_asset_id(dependency: Any) -> str:
    purl = str(getattr(dependency, "purl", "") or "")
    if purl:
        return stable_id("asset", "purl", purl)
    return stable_id(
        "asset",
        "dependency",
        getattr(dependency, "ecosystem", ""),
        getattr(dependency, "name", ""),
        getattr(dependency, "version", ""),
    )


def dependency_label(dependency: Any) -> str:
    ecosystem = str(getattr(dependency, "ecosystem", "") or "generic")
    name = str(getattr(dependency, "name", "") or "dependency")
    version = str(getattr(dependency, "version", "") or "")
    return f"{ecosystem}:{name}@{version}" if version else f"{ecosystem}:{name}"


def dependency_key(ecosystem: str, name: str) -> tuple[str, str]:
    return (ecosystem.strip().lower(), name.strip().lower())


def vulnerability_summary(vulnerabilities: list[dict[str, Any]]) -> str:
    values = []
    for item in vulnerabilities:
        values.append(":".join(str(item.get(key) or "") for key in ("source", "id", "severity")).strip(":"))
    return "; ".join(value for value in values if value)


def dependency_has_vulnerability_signal(signals: list[Any]) -> bool:
    text = " ".join(str(signal).lower() for signal in signals)
    return any(token in text for token in ("vulnerability", "advisory", "cve", "osv", "已知漏洞", "漏洞"))


def short_text(value: Any, limit: int) -> str:
    text = str(value or "").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return f"{text[: max(20, limit - 3)]}..."


def stable_id(*parts: Any) -> str:
    raw = "|".join(str(part or "") for part in parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    prefix = str(parts[0] or "fact").lower().replace("_", "-")
    return f"{prefix}:{digest}"


def stable_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def trim_time(value: str | None) -> str:
    if not value:
        return ""
    return value[:16].replace("T", " ")


def normalize_severity(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"critical", "high", "medium", "low"}:
        return normalized
    if normalized in {"active", "observed", "ok"}:
        return "low"
    return "low"


def strongest_severity(left: str, right: str) -> str:
    left_value = normalize_severity(left)
    right_value = normalize_severity(right)
    return left_value if SEVERITY_ORDER[left_value] >= SEVERITY_ORDER[right_value] else right_value


def severity_from_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 55:
        return "medium"
    return "low"


def score_from_severity(severity: str) -> int:
    normalized = normalize_severity(severity)
    if normalized == "critical":
        return 92
    if normalized == "high":
        return 82
    if normalized == "medium":
        return 64
    return 35


def workspace_asset_type(module: str) -> str:
    if "代码" in module:
        return "CodeFile"
    if "供应链" in module:
        return "DependencyPackage"
    if "CI/CD" in module:
        return "CIStep"
    if "日志" in module:
        return "LogEvent"
    if "证据链" in module:
        return "EvidenceChain"
    return "Asset"


def ensure_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def ensure_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def ensure_string_list(value: Any) -> list[str]:
    return [str(item) for item in ensure_list(value) if item not in (None, "")]


def compact_dict(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
