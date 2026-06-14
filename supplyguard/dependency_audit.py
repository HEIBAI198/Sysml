"""Dependency audit scanner with lockfile, SBOM, and OSV adapters.

Version 2 keeps the offline manifest parser from the first pass, then upgrades
results with exact versions from lockfiles or frozen environments. External
tools are treated as optional adapters: if cdxgen, cyclonedx-py, or osv-scanner
is available, their facts are merged into the same DependencyRecord model; if
not, the scanner degrades cleanly.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from datetime import UTC, datetime
from difflib import SequenceMatcher
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Iterable
from urllib.parse import parse_qs, quote, urlparse
import uuid

from pydantic import BaseModel, ConfigDict, Field

from .config import ROOT
from .project_imports import ImportErrorDetail, load_import, load_latest_import

try:
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.version import InvalidVersion, Version
except Exception:  # pragma: no cover - only used in very small environments.
    InvalidRequirement = Exception
    InvalidSpecifier = Exception
    InvalidVersion = Exception
    Requirement = None  # type: ignore[assignment]
    SpecifierSet = None  # type: ignore[assignment]
    Version = None  # type: ignore[assignment]


DEFAULT_TARGET = ROOT
STORAGE_SBOM_DIR = ROOT / "storage" / "sbom"
MAX_MANIFESTS = 300
COMMAND_TIMEOUT_SECONDS = 45
CDXGEN_TIMEOUT_SECONDS = 120
OSV_TIMEOUT_SECONDS = 60
SUPPORTED_MANIFESTS = {"package.json", "requirements.txt"}
SUPPORTED_LOCKFILES = {"package-lock.json", "requirements.lock.txt"}
INSTALL_SCRIPT_NAMES = {"preinstall", "install", "postinstall", "prepare"}
NPM_DEPENDENCY_FIELDS = {
    "dependencies": "runtime",
    "devDependencies": "development",
    "peerDependencies": "peer",
    "optionalDependencies": "optional",
}
IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".venv-1",
    ".venv-sbom",
    "node_modules",
    "bower_components",
    "vendor",
    "dist",
    "build",
    "target",
    "out",
    ".next",
    ".nuxt",
    "coverage",
    "storage",
}
VENV_NAMES = {".venv", "venv", "env"}

SOURCE_CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".json",
}
MAX_REACHABILITY_FILES = 900
MAX_REACHABILITY_FILE_BYTES = 600_000
MAX_RUNTIME_EVIDENCE_ITEMS = 600

PYTHON_IMPORT_ALIASES = {
    "beautifulsoup4": ("bs4",),
    "django": ("django",),
    "fastapi": ("fastapi",),
    "flask": ("flask",),
    "httpx": ("httpx",),
    "jinja2": ("jinja2",),
    "pillow": ("PIL",),
    "pyjwt": ("jwt",),
    "pymongo": ("pymongo",),
    "python-jose": ("jose",),
    "python-multipart": ("multipart",),
    "pyyaml": ("yaml",),
    "requests": ("requests",),
    "starlette": ("starlette",),
    "urllib3": ("urllib3",),
    "uvicorn": ("uvicorn",),
}
SERVER_FRAMEWORK_PACKAGES = {
    "pypi": {"django", "fastapi", "flask", "starlette", "uvicorn"},
    "npm": {"@nestjs/core", "express", "fastify", "koa", "next"},
}
AUTH_PACKAGES = {
    "pypi": {"authlib", "passlib", "pyjwt", "python-jose"},
    "npm": {"jsonwebtoken", "next-auth", "passport"},
}
HTTP_CLIENT_PACKAGES = {
    "pypi": {"aiohttp", "httpx", "requests", "urllib3"},
    "npm": {"axios", "got", "node-fetch", "request"},
}
DESERIALIZATION_PACKAGES = {
    "pypi": {"pyyaml"},
    "npm": {"serialize-javascript"},
}
CYCLONEDX_STATE_BY_VEX_STATUS = {
    "affected": "exploitable",
    "not_affected": "not_affected",
    "under_investigation": "in_triage",
    "fixed": "resolved",
}
CYCLONEDX_JUSTIFICATIONS = {
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
}

SEVERITY_WEIGHTS = {"critical": 72, "high": 55, "medium": 35, "low": 16}
SEVERITY_FLOORS = {"critical": 92, "high": 78, "medium": 58, "low": 35}
OSV_SEVERITY_FALLBACK = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

LOCAL_VULNERABILITIES: list[dict[str, str]] = [
    {
        "id": "LOCAL-DEMO-NPM-0001",
        "ecosystem": "npm",
        "name": "serialize-javascript",
        "affected": "<3.1.1",
        "severity": "high",
        "summary": "Local demo advisory for unsafe serialize-javascript ranges.",
    },
    {
        "id": "LOCAL-DEMO-NPM-0002",
        "ecosystem": "npm",
        "name": "lodash",
        "affected": "<4.17.21",
        "severity": "high",
        "summary": "Local demo advisory for old lodash ranges.",
    },
    {
        "id": "LOCAL-DEMO-NPM-0003",
        "ecosystem": "npm",
        "name": "minimist",
        "affected": "<1.2.6",
        "severity": "high",
        "summary": "Local demo advisory for old minimist ranges.",
    },
    {
        "id": "LOCAL-DEMO-NPM-0004",
        "ecosystem": "npm",
        "name": "event-stream",
        "affected": "*",
        "severity": "critical",
        "summary": "Local demo malicious package incident signal.",
    },
    {
        "id": "LOCAL-DEMO-NPM-0005",
        "ecosystem": "npm",
        "name": "ua-parser-js",
        "affected": "<0.7.30",
        "severity": "critical",
        "summary": "Local demo advisory for compromised ua-parser-js ranges.",
    },
    {
        "id": "LOCAL-DEMO-PYPI-0001",
        "ecosystem": "pypi",
        "name": "pyjwt",
        "affected": "<2.4.0",
        "severity": "high",
        "summary": "Local demo advisory for older PyJWT ranges.",
    },
    {
        "id": "LOCAL-DEMO-PYPI-0002",
        "ecosystem": "pypi",
        "name": "pyyaml",
        "affected": "<6.0",
        "severity": "high",
        "summary": "Local demo advisory for older PyYAML ranges.",
    },
    {
        "id": "LOCAL-DEMO-PYPI-0003",
        "ecosystem": "pypi",
        "name": "django",
        "affected": "<3.2.25",
        "severity": "high",
        "summary": "Local demo advisory for old Django LTS ranges.",
    },
    {
        "id": "LOCAL-DEMO-PYPI-0004",
        "ecosystem": "pypi",
        "name": "fastapi",
        "affected": "<0.115.6",
        "severity": "medium",
        "summary": "Local demo policy flags older FastAPI ranges before 0.115.6.",
    },
]

POPULAR_PACKAGES = {
    "npm": {
        "react",
        "react-dom",
        "vue",
        "axios",
        "lodash",
        "express",
        "next",
        "typescript",
        "eslint",
        "vite",
        "webpack",
        "tailwindcss",
        "zod",
        "recharts",
        "lucide-react",
        "monaco-editor",
    },
    "pypi": {
        "requests",
        "fastapi",
        "django",
        "flask",
        "pydantic",
        "uvicorn",
        "numpy",
        "pandas",
        "pytest",
        "cryptography",
        "pyjwt",
        "pymongo",
        "httpx",
        "bandit",
        "checkov",
        "pyyaml",
        "python-multipart",
    },
}

SAFE_NPM_SCOPES = {
    "@types",
    "@vitejs",
    "@tanstack",
    "@radix-ui",
    "@hookform",
    "@tailwindcss",
    "@xyflow",
    "@eslint",
    "@faker-js",
    "@trivago",
    "@vitest",
}

KNOWN_LICENSES = {
    "npm": {
        "react": "MIT",
        "react-dom": "MIT",
        "axios": "MIT",
        "clsx": "MIT",
        "cmdk": "MIT",
        "date-fns": "MIT",
        "eslint": "MIT",
        "input-otp": "MIT",
        "lucide-react": "ISC",
        "monaco-editor": "MIT",
        "react-hook-form": "MIT",
        "react-top-loading-bar": "MIT",
        "recharts": "MIT",
        "sonner": "MIT",
        "tailwind-merge": "MIT",
        "tailwindcss": "MIT",
        "typescript": "Apache-2.0",
        "vite": "MIT",
        "zod": "MIT",
    },
    "pypi": {
        "bandit": "Apache-2.0",
        "checkov": "Apache-2.0",
        "fastapi": "MIT",
        "httpx": "BSD-3-Clause",
        "pydantic": "MIT",
        "pymongo": "Apache-2.0",
        "python-multipart": "Apache-2.0",
        "pyyaml": "MIT",
        "uvicorn": "BSD-3-Clause",
    },
}

COPYLEFT_LICENSE_HINTS = {"GPL", "AGPL", "LGPL", "SSPL"}


class DependencyAuditRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    import_id: str | None = Field(default=None, alias="importId")
    target_path: str | None = Field(default=None, alias="targetPath")
    runtime_log_paths: list[str] = Field(default_factory=list, alias="runtimeLogPaths")
    include_dev: bool = Field(default=True, alias="includeDev")
    max_manifests: int = Field(default=MAX_MANIFESTS, alias="maxManifests", ge=1, le=1000)
    mode: str = Field(default="auto", pattern="^(auto|manifest|lockfile|sbom)$")
    include_osv: bool = Field(default=True, alias="includeOsv")
    include_cdxgen: bool = Field(default=False, alias="includeCdxgen")
    include_cyclonedx_py: bool = Field(default=False, alias="includeCyclonedxPy")


@dataclass
class DependencyRecord:
    name: str
    ecosystem: str
    version: str
    scope: str
    source_file: str
    manifest_type: str
    license: str = "UNKNOWN"
    purl: str = ""
    risk: int = 0
    signals: list[str] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    reachability: dict[str, Any] = field(default_factory=dict)
    vex: list[dict[str, Any]] = field(default_factory=list)
    recommendation: str = ""
    requested_version: str | None = None
    version_source: str = "manifest"
    dependency_type: str = "direct"
    resolved: bool = False


@dataclass(frozen=True)
class DependencyFinding:
    id: str
    title: str
    severity: str
    score: int
    dependency: str
    ecosystem: str
    source_file: str
    evidence: str
    recommendation: str
    fingerprint: str


@dataclass(frozen=True)
class ToolStatus:
    name: str
    available: bool
    command: str
    version: str | None = None
    state: str = "ok"
    error: str | None = None


@dataclass(frozen=True)
class ToolResult:
    records: list[DependencyRecord] = field(default_factory=list)
    sbom: dict[str, Any] | None = None
    status: ToolStatus | None = None
    warnings: list[str] = field(default_factory=list)
    output_path: str | None = None


@dataclass(frozen=True)
class DependencyAuditResult:
    scan_id: str
    generated_at: str
    target_path: str
    target: dict[str, Any]
    dependencies: list[DependencyRecord]
    findings: list[DependencyFinding]
    summary: dict[str, Any]
    sbom: dict[str, Any]
    vex: dict[str, Any]
    report: str
    warnings: list[str] = field(default_factory=list)
    tools: list[ToolStatus] = field(default_factory=list)


def run_dependency_audit(request: DependencyAuditRequest | None = None) -> DependencyAuditResult:
    started_at = time.monotonic()
    payload = request or DependencyAuditRequest()
    target, target_info = resolve_dependency_target(payload)
    target_info = {**target_info, "path": str(target)}
    scan_id = datetime.now(UTC).strftime("dep-%Y%m%d%H%M%S")
    generated_at = datetime.now(UTC).isoformat()
    STORAGE_SBOM_DIR.mkdir(parents=True, exist_ok=True)

    warnings: list[str] = []
    tools: list[ToolStatus] = []
    manifests = discover_files(target, SUPPORTED_MANIFESTS, max_files=payload.max_manifests)
    lockfiles = discover_files(target, SUPPORTED_LOCKFILES, max_files=payload.max_manifests)
    external_requirements_lock = STORAGE_SBOM_DIR / "requirements.lock.txt"
    if external_requirements_lock.exists() and external_requirements_lock not in lockfiles:
        lockfiles.append(external_requirements_lock)
    requirements_locks = [path for path in lockfiles if path.name.lower() == "requirements.lock.txt"]
    package_locks = [path for path in lockfiles if path.name.lower() == "package-lock.json"]

    dependencies: list[DependencyRecord] = []
    if payload.mode != "sbom":
        dependencies.extend(parse_manifest_records(manifests, target, payload.include_dev, warnings))
        dependencies.extend(parse_lockfile_records(lockfiles, target, payload.include_dev, warnings))
        dependencies.extend(parse_environment_records(target, warnings))
        generated_lock = STORAGE_SBOM_DIR / "requirements.lock.txt"
        if generated_lock.exists() and generated_lock not in requirements_locks:
            requirements_locks.append(generated_lock)
            lockfiles.append(generated_lock)

    external_sboms: list[dict[str, Any]] = []
    if payload.mode in {"auto", "lockfile", "sbom"}:
        if payload.include_cdxgen:
            for project_dir in node_project_dirs(target):
                result = run_cdxgen(project_dir, target, scan_id)
                dependencies.extend(result.records)
                warnings.extend(result.warnings)
                if result.sbom:
                    external_sboms.append(result.sbom)
                if result.status:
                    tools.append(result.status)

        if payload.include_cyclonedx_py:
            for requirements_lock in requirements_locks:
                result = run_cyclonedx_py(requirements_lock, target, scan_id)
                dependencies.extend(result.records)
                warnings.extend(result.warnings)
                if result.sbom:
                    external_sboms.append(result.sbom)
                if result.status:
                    tools.append(result.status)

    dependencies = merge_dependency_records(dependencies)

    if payload.include_osv and payload.mode != "manifest":
        osv_targets: list[Path] = []
        osv_targets.extend(package_locks)
        osv_targets.extend(requirements_locks)
        for sbom in external_sboms:
            sbom_path = write_temp_sbom(scan_id, sbom)
            osv_targets.append(sbom_path)
        for osv_target in unique_paths(osv_targets):
            result = run_osv_scanner(osv_target, target)
            merge_osv_records(dependencies, result.records, warnings)
            warnings.extend(result.warnings)
            if result.status:
                tools.append(result.status)

    for dependency in dependencies:
        enrich_dependency(dependency)

    vex_context = build_vex_context(target, target_info)
    apply_vex_analysis(dependencies, vex_context)

    tools = dedupe_tool_statuses(tools)
    dependencies.sort(
        key=lambda item: (
            -item.risk,
            source_rank(item.version_source),
            item.ecosystem,
            item.name,
            item.source_file,
        )
    )
    findings = build_dependency_findings(dependencies)
    summary = build_dependency_summary(dependencies, findings, manifests, lockfiles, tools)
    summary["vex"] = build_vex_summary(dependencies)
    summary["reachability"] = build_reachability_summary(dependencies, vex_context)
    summary["duration_seconds"] = round(time.monotonic() - started_at, 2)
    summary["target"] = target_info
    sbom = build_cyclonedx_sbom(dependencies, target_info, scan_id, generated_at, external_sboms)
    vex = build_cyclonedx_vex(dependencies, target_info, scan_id, generated_at)
    report = build_dependency_report(target, dependencies, findings, summary, warnings, tools)

    return DependencyAuditResult(
        scan_id=scan_id,
        generated_at=generated_at,
        target_path=str(target),
        target=target_info,
        dependencies=dependencies,
        findings=findings,
        summary=summary,
        sbom=sbom,
        vex=vex,
        report=report,
        warnings=warnings,
        tools=tools,
    )


def resolve_dependency_target(request: DependencyAuditRequest) -> tuple[Path, dict[str, Any]]:
    runtime_log_paths = normalize_runtime_log_paths(request.runtime_log_paths)
    if request.import_id:
        target, target_info = import_dependency_target(request.import_id)
        return target, {**target_info, "runtimeLogPaths": runtime_log_paths}
    if request.target_path:
        target, target_info = path_dependency_target(request.target_path)
        return target, {**target_info, "runtimeLogPaths": runtime_log_paths}
    latest_import = load_latest_import()
    if latest_import is not None:
        source_path = Path(str(latest_import["sourcePath"]))
        if source_path.exists():
            return source_path.resolve(), {
                "importId": latest_import["importId"],
                "projectName": latest_import["projectName"],
                "sourceType": latest_import["sourceType"],
                "runtimeLogPaths": runtime_log_paths,
            }
    return DEFAULT_TARGET.resolve(), {
        "sourceType": "workspace",
        "projectName": DEFAULT_TARGET.name,
        "runtimeLogPaths": runtime_log_paths,
    }


def import_dependency_target(import_id: str) -> tuple[Path, dict[str, Any]]:
    try:
        metadata = load_import(import_id)
    except ImportErrorDetail as exc:
        raise ValueError(str(exc)) from exc
    source_path = Path(str(metadata["sourcePath"])).resolve()
    if not source_path.exists() or not source_path.is_dir():
        raise ValueError(f"Imported project source path is not available: {source_path}")
    return source_path, {
        "importId": metadata["importId"],
        "projectName": metadata["projectName"],
        "sourceType": metadata["sourceType"],
    }


def path_dependency_target(target_path: str) -> tuple[Path, dict[str, Any]]:
    candidate = Path(target_path).expanduser()
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    candidate = candidate.resolve()
    if not candidate.exists() or not candidate.is_dir():
        raise ValueError(f"Dependency scan target does not exist or is not a directory: {candidate}")
    if not is_within_root(candidate):
        raise ValueError(f"Dependency scan target must stay inside project root: {ROOT}")
    return candidate, {"sourceType": "path", "projectName": candidate.name}


def normalize_runtime_log_paths(paths: Iterable[str] | None) -> list[str]:
    normalized: list[str] = []
    for raw_path in paths or []:
        candidate = Path(str(raw_path)).expanduser()
        if not candidate.is_absolute():
            candidate = ROOT / candidate
        candidate = candidate.resolve()
        if not candidate.exists() or not candidate.is_file():
            raise ValueError(f"Runtime log path does not exist or is not a file: {candidate}")
        if not is_within_root(candidate):
            raise ValueError(f"Runtime log path must stay inside project root: {ROOT}")
        normalized.append(str(candidate))
    return list(dict.fromkeys(normalized))


def is_within_root(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT.resolve())
        return True
    except ValueError:
        return False


def discover_files(root: Path, names: set[str], *, max_files: int) -> list[Path]:
    result: list[Path] = []
    for current_dir, dir_names, file_names in os.walk(root):
        dir_names[:] = [name for name in dir_names if include_walk_dir(name)]
        for file_name in file_names:
            if file_name.lower() not in names:
                continue
            path = Path(current_dir) / file_name
            if path.name == "package-lock.json" and is_empty_root_lockfile(path):
                continue
            result.append(path)
            if len(result) >= max_files:
                return sorted(result)
    return sorted(result)


def include_walk_dir(name: str) -> bool:
    lower = name.lower()
    if lower in VENV_NAMES:
        return False
    return lower not in IGNORED_DIRS and not lower.startswith(".venv")


def is_empty_root_lockfile(path: Path) -> bool:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    packages = payload.get("packages")
    return isinstance(packages, dict) and len(packages) == 0


def parse_manifest_records(
    manifests: list[Path],
    root: Path,
    include_dev: bool,
    warnings: list[str],
) -> list[DependencyRecord]:
    records: list[DependencyRecord] = []
    if not manifests:
        warnings.append("No package.json or requirements.txt was found.")
    for manifest in manifests:
        if manifest.name == "package.json":
            records.extend(parse_package_json(manifest, root, include_dev=include_dev, warnings=warnings))
        elif manifest.name == "requirements.txt":
            records.extend(parse_requirements(manifest, root, warnings=warnings))
    return records


def parse_lockfile_records(
    lockfiles: list[Path],
    root: Path,
    include_dev: bool,
    warnings: list[str],
) -> list[DependencyRecord]:
    records: list[DependencyRecord] = []
    for lockfile in lockfiles:
        if lockfile.name == "package-lock.json":
            records.extend(parse_package_lock(lockfile, root, include_dev=include_dev, warnings=warnings))
        elif lockfile.name == "requirements.lock.txt":
            records.extend(parse_requirements_lock(lockfile, root, warnings=warnings))
    return records


def parse_package_json(
    manifest: Path,
    root: Path,
    *,
    include_dev: bool,
    warnings: list[str],
) -> list[DependencyRecord]:
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        warnings.append(f"{relative_posix(manifest, root)} parse failed: {exc}")
        return []
    if not isinstance(data, dict):
        warnings.append(f"{relative_posix(manifest, root)} is not a valid package.json object.")
        return []

    records: list[DependencyRecord] = []
    for field_name, scope in NPM_DEPENDENCY_FIELDS.items():
        if field_name == "devDependencies" and not include_dev:
            continue
        raw_dependencies = data.get(field_name)
        if not isinstance(raw_dependencies, dict):
            continue
        for name, version in raw_dependencies.items():
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            dependency = DependencyRecord(
                name=name.strip(),
                ecosystem="npm",
                version=version.strip() or "*",
                requested_version=version.strip() or "*",
                scope=scope,
                source_file=relative_posix(manifest, root),
                manifest_type="package.json",
                version_source="manifest",
                dependency_type="direct",
            )
            metadata = npm_dependency_metadata(manifest.parent, dependency.name)
            dependency.license = metadata.get("license") or known_license(dependency) or "UNKNOWN"
            for script_name in metadata.get("install_scripts", []):
                dependency.signals.append(f"install script: {script_name}")
            records.append(dependency)
    return records


def parse_package_lock(
    lockfile: Path,
    root: Path,
    *,
    include_dev: bool,
    warnings: list[str],
) -> list[DependencyRecord]:
    try:
        data = json.loads(lockfile.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        warnings.append(f"{relative_posix(lockfile, root)} parse failed: {exc}")
        return []
    if not isinstance(data, dict):
        return []

    records: list[DependencyRecord] = []
    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        records.extend(parse_package_lock_packages(lockfile, root, packages, include_dev=include_dev))
    else:
        dependencies = data.get("dependencies")
        if isinstance(dependencies, dict):
            records.extend(parse_package_lock_dependencies(lockfile, root, dependencies, include_dev=include_dev))
    return records


def parse_package_lock_packages(
    lockfile: Path,
    root: Path,
    packages: dict[str, Any],
    *,
    include_dev: bool,
) -> list[DependencyRecord]:
    root_package = packages.get("")
    direct_names = direct_npm_names_from_lock_root(root_package) if isinstance(root_package, dict) else set()
    records: list[DependencyRecord] = []
    for package_path, info in packages.items():
        if not package_path or not isinstance(info, dict):
            continue
        if "node_modules/" not in package_path:
            continue
        name = npm_name_from_lock_path(package_path)
        if not name:
            continue
        is_dev = bool(info.get("dev"))
        if is_dev and not include_dev:
            continue
        version = str(info.get("version") or "*")
        scope = "development" if is_dev else "runtime"
        dependency = DependencyRecord(
            name=name,
            ecosystem="npm",
            version=version,
            requested_version=str(info.get("resolved") or ""),
            scope=scope,
            source_file=relative_posix(lockfile, root),
            manifest_type="package-lock.json",
            license=parse_license_value(info.get("license")) or known_license_by_name("npm", name) or "UNKNOWN",
            version_source="lockfile",
            dependency_type="direct" if name in direct_names else "transitive",
            resolved=True,
        )
        if isinstance(info.get("hasInstallScript"), bool) and info["hasInstallScript"]:
            dependency.signals.append("install script")
        records.append(dependency)
    return records


def parse_package_lock_dependencies(
    lockfile: Path,
    root: Path,
    dependencies: dict[str, Any],
    *,
    include_dev: bool,
) -> list[DependencyRecord]:
    records: list[DependencyRecord] = []

    def visit(name: str, info: dict[str, Any], direct: bool) -> None:
        is_dev = bool(info.get("dev"))
        if is_dev and not include_dev:
            return
        dependency = DependencyRecord(
            name=name,
            ecosystem="npm",
            version=str(info.get("version") or "*"),
            requested_version=str(info.get("from") or info.get("resolved") or ""),
            scope="development" if is_dev else "runtime",
            source_file=relative_posix(lockfile, root),
            manifest_type="package-lock.json",
            license=known_license_by_name("npm", name) or "UNKNOWN",
            version_source="lockfile",
            dependency_type="direct" if direct else "transitive",
            resolved=True,
        )
        records.append(dependency)
        nested = info.get("dependencies")
        if isinstance(nested, dict):
            for child_name, child_info in nested.items():
                if isinstance(child_info, dict):
                    visit(child_name, child_info, direct=False)

    for name, info in dependencies.items():
        if isinstance(info, dict):
            visit(name, info, direct=True)
    return records


def direct_npm_names_from_lock_root(root_package: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for field_name in NPM_DEPENDENCY_FIELDS:
        values = root_package.get(field_name)
        if isinstance(values, dict):
            names.update(str(name) for name in values)
    return names


def npm_name_from_lock_path(package_path: str) -> str | None:
    parts = package_path.replace("\\", "/").split("node_modules/")
    if not parts:
        return None
    name = parts[-1]
    if not name:
        return None
    subparts = name.split("/")
    if subparts[0].startswith("@") and len(subparts) >= 2:
        return f"{subparts[0]}/{subparts[1]}"
    return subparts[0]


def parse_requirements(manifest: Path, root: Path, warnings: list[str]) -> list[DependencyRecord]:
    return parse_requirements_file(manifest, root, warnings=warnings, visited=set(), version_source="manifest")


def parse_requirements_lock(lockfile: Path, root: Path, warnings: list[str]) -> list[DependencyRecord]:
    return parse_requirements_file(lockfile, root, warnings=warnings, visited=set(), version_source="environment")


def parse_requirements_file(
    manifest: Path,
    root: Path,
    *,
    warnings: list[str],
    visited: set[Path],
    version_source: str,
) -> list[DependencyRecord]:
    resolved = manifest.resolve()
    if resolved in visited:
        return []
    visited.add(resolved)
    try:
        lines = manifest.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        warnings.append(f"{relative_posix(manifest, root)} read failed: {exc}")
        return []

    records: list[DependencyRecord] = []
    for raw_line in lines:
        line = strip_requirement_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith(("-r ", "--requirement ")) and version_source == "manifest":
            include_path = line.split(maxsplit=1)[1].strip()
            child = (manifest.parent / include_path).resolve()
            if child.exists():
                records.extend(
                    parse_requirements_file(
                        child,
                        root,
                        warnings=warnings,
                        visited=visited,
                        version_source=version_source,
                    )
                )
            else:
                warnings.append(f"{relative_posix(manifest, root)} references missing requirements file: {include_path}")
            continue
        if line.startswith(("-c ", "--constraint ", "--")):
            continue
        dependency = parse_requirement_line(line, manifest, root, warnings, version_source=version_source)
        if dependency is not None:
            dependency.license = known_license(dependency) or "UNKNOWN"
            records.append(dependency)
    return records


def parse_requirement_line(
    line: str,
    manifest: Path,
    root: Path,
    warnings: list[str],
    *,
    version_source: str,
) -> DependencyRecord | None:
    editable = False
    value = line
    if value.startswith(("-e ", "--editable ")):
        editable = True
        value = value.split(maxsplit=1)[1].strip()

    direct_name = requirement_name_from_url(value)
    if direct_name:
        dependency = DependencyRecord(
            name=direct_name,
            ecosystem="pypi",
            version="URL/VCS",
            requested_version=value,
            scope="runtime",
            source_file=relative_posix(manifest, root),
            manifest_type=manifest.name,
            signals=["editable install" if editable else "URL/VCS source"],
            version_source=version_source,
            dependency_type="direct",
        )
        return dependency

    if Requirement is not None:
        try:
            parsed = Requirement(value)
            version = str(parsed.specifier) if parsed.specifier else "*"
            if parsed.url:
                version = "URL/VCS"
            exact = exact_version(version)
            dependency = DependencyRecord(
                name=canonical_pypi_name(parsed.name),
                ecosystem="pypi",
                version=exact or version,
                requested_version=version,
                scope="runtime",
                source_file=relative_posix(manifest, root),
                manifest_type=manifest.name,
                version_source=version_source,
                dependency_type="direct" if version_source == "manifest" else "transitive",
                resolved=bool(exact),
            )
            if parsed.url:
                dependency.signals.append("URL/VCS source")
            if editable:
                dependency.signals.append("editable install")
            return dependency
        except InvalidRequirement:
            pass

    match = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*([<>=!~].*)?$", value)
    if not match:
        warnings.append(f"{relative_posix(manifest, root)} skipped unparsable dependency line: {line}")
        return None
    version = (match.group(2) or "*").strip()
    exact = exact_version(version)
    return DependencyRecord(
        name=canonical_pypi_name(match.group(1)),
        ecosystem="pypi",
        version=exact or version,
        requested_version=version,
        scope="runtime",
        source_file=relative_posix(manifest, root),
        manifest_type=manifest.name,
        version_source=version_source,
        dependency_type="direct" if version_source == "manifest" else "transitive",
        resolved=bool(exact),
    )


def parse_environment_records(root: Path, warnings: list[str]) -> list[DependencyRecord]:
    records: list[DependencyRecord] = []
    for python_exe in discover_python_envs(root):
        try:
            process = subprocess.run(
                [str(python_exe), "-m", "pip", "freeze", "--all"],
                cwd=root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            warnings.append(f"pip freeze failed for {relative_posix(python_exe, root)}: {exc}")
            continue
        if process.returncode != 0:
            warnings.append(f"pip freeze failed for {relative_posix(python_exe, root)}: {process.stderr.strip()}")
            continue
        lock_path = STORAGE_SBOM_DIR / "requirements.lock.txt"
        lock_path.write_text(process.stdout, encoding="utf-8")
        for line in process.stdout.splitlines():
            dependency = parse_frozen_requirement_line(line, root, lock_path)
            if dependency:
                records.append(dependency)
        break
    return records


def discover_python_envs(root: Path) -> list[Path]:
    candidates: list[Path] = []
    for name in [".venv-sbom", ".venv", "venv", "env"]:
        scripts_python = root / name / "Scripts" / "python.exe"
        bin_python = root / name / "bin" / "python"
        if scripts_python.exists():
            candidates.append(scripts_python)
        if bin_python.exists():
            candidates.append(bin_python)
    if Path(sys.executable).exists() and is_within_root(Path(sys.executable)):
        candidates.append(Path(sys.executable))
    return candidates


def parse_frozen_requirement_line(line: str, root: Path, source_path: Path) -> DependencyRecord | None:
    value = strip_requirement_comment(line).strip()
    if not value or value.startswith("-"):
        return None
    match = re.match(r"^([A-Za-z0-9_.-]+)==(.+)$", value)
    if not match:
        return None
    name, version = match.groups()
    dependency = DependencyRecord(
        name=canonical_pypi_name(name),
        ecosystem="pypi",
        version=version,
        requested_version=f"=={version}",
        scope="runtime",
        source_file=relative_posix(source_path, root),
        manifest_type="pip-freeze",
        license=known_license_by_name("pypi", name) or "UNKNOWN",
        version_source="environment",
        dependency_type="transitive",
        resolved=True,
    )
    return dependency


def run_cdxgen(project_dir: Path, root: Path, scan_id: str) -> ToolResult:
    command = find_command("cdxgen") or find_command("npx")
    if command is None:
        return ToolResult(
            status=ToolStatus(
                name="cdxgen",
                available=False,
                command="cdxgen",
                state="missing",
                error="cdxgen/npx was not found.",
            )
        )
    output_path = STORAGE_SBOM_DIR / f"cdxgen-{scan_id}-{safe_filename(relative_posix(project_dir, root))}.cdx.json"
    if Path(command).name.lower().startswith("npx"):
        cmd = [command, "-y", "@cyclonedx/cdxgen", "-o", str(output_path), str(project_dir)]
    else:
        cmd = [command, "-o", str(output_path), str(project_dir)]
    try:
        process = run_command(cmd, root, timeout_seconds=CDXGEN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return ToolResult(
            status=ToolStatus(
                name="cdxgen",
                available=True,
                command=" ".join(cmd[:3]),
                state="failed",
                error=f"Timed out after {CDXGEN_TIMEOUT_SECONDS}s.",
            ),
            warnings=[f"cdxgen timed out for {relative_posix(project_dir, root)}."],
        )
    if process.returncode != 0:
        return ToolResult(
            status=ToolStatus(
                name="cdxgen",
                available=True,
                command=" ".join(cmd[:3]),
                version=None,
                state="failed",
                error=(process.stderr or process.stdout).strip()[:400],
            ),
            warnings=[f"cdxgen failed for {relative_posix(project_dir, root)}."],
        )
    sbom = read_json_file(output_path)
    records = parse_cyclonedx_components(sbom, root, source_file=relative_posix(output_path, root), source="cdxgen")
    return ToolResult(
        records=records,
        sbom=sbom,
        output_path=str(output_path),
        status=ToolStatus(name="cdxgen", available=True, command=" ".join(cmd[:3]), state="ok"),
    )


def run_cyclonedx_py(requirements_lock: Path, root: Path, scan_id: str) -> ToolResult:
    command = find_cyclonedx_py_command(root)
    if command is None:
        return ToolResult(
            status=ToolStatus(
                name="cyclonedx-py",
                available=False,
                command="cyclonedx-py",
                state="missing",
                error="cyclonedx-py was not found.",
            )
        )
    output_path = STORAGE_SBOM_DIR / f"cyclonedx-py-{scan_id}.cdx.json"
    cmd = [
        command,
        "requirements",
        str(requirements_lock),
        "-o",
        str(output_path),
        "--of",
        "JSON",
    ]
    try:
        process = run_command(cmd, root, timeout_seconds=COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return ToolResult(
            status=ToolStatus(
                name="cyclonedx-py",
                available=True,
                command="cyclonedx-py requirements",
                state="failed",
                error=f"Timed out after {COMMAND_TIMEOUT_SECONDS}s.",
            ),
            warnings=[f"cyclonedx-py timed out for {relative_posix(requirements_lock, root)}."],
        )
    if process.returncode != 0:
        return ToolResult(
            status=ToolStatus(
                name="cyclonedx-py",
                available=True,
                command="cyclonedx-py requirements",
                state="failed",
                error=(process.stderr or process.stdout).strip()[:400],
            ),
            warnings=[f"cyclonedx-py failed for {relative_posix(requirements_lock, root)}."],
        )
    sbom = read_json_file(output_path)
    records = parse_cyclonedx_components(sbom, root, source_file=relative_posix(output_path, root), source="cyclonedx-py")
    return ToolResult(
        records=records,
        sbom=sbom,
        output_path=str(output_path),
        status=ToolStatus(name="cyclonedx-py", available=True, command="cyclonedx-py requirements", state="ok"),
    )


def run_osv_scanner(target_file: Path, root: Path) -> ToolResult:
    command = find_command("osv-scanner")
    if command is None:
        return ToolResult(
            status=ToolStatus(
                name="OSV-Scanner",
                available=False,
                command="osv-scanner",
                state="missing",
                error="osv-scanner was not found.",
            )
        )
    cmd = [command, "scan", "--format", "json", "-L", str(target_file)]
    try:
        process = run_command(cmd, root, timeout_seconds=OSV_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return ToolResult(
            status=ToolStatus(
                name="OSV-Scanner",
                available=True,
                command="osv-scanner scan --format json",
                state="failed",
                error=f"Timed out after {OSV_TIMEOUT_SECONDS}s.",
            ),
            warnings=[f"OSV-Scanner timed out for {relative_posix(target_file, root)}."],
        )
    if process.returncode not in {0, 1}:
        return ToolResult(
            status=ToolStatus(
                name="OSV-Scanner",
                available=True,
                command="osv-scanner scan --format json",
                state="failed",
                error=(process.stderr or process.stdout).strip()[:400],
            ),
            warnings=[f"OSV-Scanner failed for {relative_posix(target_file, root)}."],
        )
    try:
        data = json.loads(process.stdout or "{}")
    except json.JSONDecodeError:
        return ToolResult(
            status=ToolStatus(
                name="OSV-Scanner",
                available=True,
                command="osv-scanner scan --format json",
                state="failed",
                error="OSV output was not valid JSON.",
            )
        )
    records = parse_osv_results(data, root, source_file=relative_posix(target_file, root))
    state = "ok" if records else "ok"
    return ToolResult(
        records=records,
        status=ToolStatus(
            name="OSV-Scanner",
            available=True,
            command="osv-scanner scan --format json",
            state=state,
        ),
    )


def run_command(cmd: list[str], cwd: Path, *, timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        shell=False,
    )


def find_command(name: str) -> str | None:
    command = shutil.which(name)
    if command:
        return command
    if name != "osv-scanner":
        return None
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        return None
    packages_dir = Path(local_app_data) / "Microsoft" / "WinGet" / "Packages"
    if not packages_dir.exists():
        return None
    for candidate in packages_dir.glob("Google.OSVScanner_*/*osv-scanner.exe"):
        if candidate.exists():
            return str(candidate)
    return None


def find_cyclonedx_py_command(root: Path) -> str | None:
    candidates = [
        root / ".venv-cyclonedx" / "Scripts" / "cyclonedx-py.exe",
        ROOT / ".venv-cyclonedx" / "Scripts" / "cyclonedx-py.exe",
        root / ".venv-cyclonedx" / "bin" / "cyclonedx-py",
        ROOT / ".venv-cyclonedx" / "bin" / "cyclonedx-py",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return find_command("cyclonedx-py")


def read_json_file(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def node_project_dirs(root: Path) -> list[Path]:
    dirs: list[Path] = []
    for package_json in discover_files(root, {"package.json"}, max_files=MAX_MANIFESTS):
        dirs.append(package_json.parent)
    return sorted(set(dirs))


def parse_cyclonedx_components(
    sbom: dict[str, Any],
    root: Path,
    *,
    source_file: str,
    source: str,
) -> list[DependencyRecord]:
    components = sbom.get("components")
    if not isinstance(components, list):
        return []
    records: list[DependencyRecord] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        name = component.get("name")
        version = component.get("version")
        if not isinstance(name, str) or not name:
            continue
        ecosystem = ecosystem_from_component(component)
        if ecosystem not in {"npm", "pypi"}:
            continue
        dependency = DependencyRecord(
            name=canonical_dependency_name(ecosystem, name),
            ecosystem=ecosystem,
            version=str(version or "*"),
            requested_version=str(version or "*"),
            scope="runtime",
            source_file=source_file,
            manifest_type=f"{source}-sbom",
            license=license_from_component(component) or known_license_by_name(ecosystem, name) or "UNKNOWN",
            purl=str(component.get("purl") or ""),
            version_source="sbom",
            dependency_type="transitive",
            resolved=bool(version),
        )
        records.append(dependency)
    return records


def ecosystem_from_component(component: dict[str, Any]) -> str:
    purl = str(component.get("purl") or "").lower()
    if purl.startswith("pkg:npm/"):
        return "npm"
    if purl.startswith("pkg:pypi/"):
        return "pypi"
    properties = component.get("properties")
    if isinstance(properties, list):
        for prop in properties:
            if not isinstance(prop, dict):
                continue
            if str(prop.get("name") or "").endswith("ecosystem"):
                value = str(prop.get("value") or "").lower()
                if value in {"npm", "pypi"}:
                    return value
    return ""


def license_from_component(component: dict[str, Any]) -> str | None:
    licenses = component.get("licenses")
    if not isinstance(licenses, list):
        return None
    values: list[str] = []
    for item in licenses:
        if not isinstance(item, dict):
            continue
        license_info = item.get("license")
        if isinstance(license_info, dict):
            value = license_info.get("id") or license_info.get("name")
            if isinstance(value, str) and value:
                values.append(value)
        expression = item.get("expression")
        if isinstance(expression, str) and expression:
            values.append(expression)
    return " OR ".join(values) if values else None


def parse_osv_results(data: dict[str, Any], root: Path, *, source_file: str) -> list[DependencyRecord]:
    records: list[DependencyRecord] = []
    result_items = data.get("results")
    if not isinstance(result_items, list):
        return records
    for result in result_items:
        if not isinstance(result, dict):
            continue
        packages = result.get("packages")
        if not isinstance(packages, list):
            continue
        for package_item in packages:
            if not isinstance(package_item, dict):
                continue
            package = package_item.get("package")
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            version = package.get("version")
            ecosystem = normalize_ecosystem(str(package.get("ecosystem") or ""))
            if not isinstance(name, str) or ecosystem not in {"npm", "pypi"}:
                continue
            dependency = DependencyRecord(
                name=canonical_dependency_name(ecosystem, name),
                ecosystem=ecosystem,
                version=str(version or "*"),
                requested_version=str(version or "*"),
                scope="runtime",
                source_file=source_file,
                manifest_type="osv-scanner",
                license=known_license_by_name(ecosystem, name) or "UNKNOWN",
                version_source="osv",
                dependency_type="transitive",
                resolved=bool(version),
            )
            vulnerabilities = package_item.get("vulnerabilities")
            if isinstance(vulnerabilities, list):
                dependency.vulnerabilities.extend(normalize_osv_vulnerability(item) for item in vulnerabilities if isinstance(item, dict))
            if dependency.vulnerabilities:
                records.append(dependency)
    return records


def normalize_osv_vulnerability(item: dict[str, Any]) -> dict[str, Any]:
    severity = osv_severity(item)
    affected = fixed_versions_text(item)
    return {
        "id": str(item.get("id") or "OSV-UNKNOWN"),
        "source": "osv",
        "severity": severity,
        "affected": affected or "see OSV record",
        "summary": str(item.get("summary") or item.get("details") or "OSV vulnerability"),
        "confidence": "high",
        "aliases": item.get("aliases") or [],
        "fixed_versions": fixed_versions(item),
    }


def osv_severity(item: dict[str, Any]) -> str:
    severities = item.get("severity")
    if isinstance(severities, list):
        for severity_item in severities:
            if not isinstance(severity_item, dict):
                continue
            score = str(severity_item.get("score") or "")
            label = str(severity_item.get("type") or "")
            if "CVSS" in label.upper():
                parsed = cvss_severity(score)
                if parsed:
                    return parsed
    database_specific = item.get("database_specific")
    if isinstance(database_specific, dict):
        severity = str(database_specific.get("severity") or "").upper()
        if severity in OSV_SEVERITY_FALLBACK:
            return OSV_SEVERITY_FALLBACK[severity]
    return "high"


def cvss_severity(score: str) -> str | None:
    match = re.search(r"/AV:", score)
    if match:
        return None
    try:
        value = float(score)
    except ValueError:
        return None
    if value >= 9:
        return "critical"
    if value >= 7:
        return "high"
    if value >= 4:
        return "medium"
    return "low"


def fixed_versions(item: dict[str, Any]) -> list[str]:
    versions: list[str] = []
    affected = item.get("affected")
    if not isinstance(affected, list):
        return versions
    for affected_item in affected:
        if not isinstance(affected_item, dict):
            continue
        ranges = affected_item.get("ranges")
        if not isinstance(ranges, list):
            continue
        for range_item in ranges:
            events = range_item.get("events") if isinstance(range_item, dict) else None
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    versions.append(event["fixed"])
    return sorted(set(versions))


def fixed_versions_text(item: dict[str, Any]) -> str:
    versions = fixed_versions(item)
    return f"fixed in {', '.join(versions[:5])}" if versions else ""


def merge_osv_records(
    dependencies: list[DependencyRecord],
    osv_records: list[DependencyRecord],
    warnings: list[str],
) -> None:
    index = record_index(dependencies)
    for osv_record in osv_records:
        key = record_key(osv_record)
        target = index.get(key)
        if target is None:
            dependencies.append(osv_record)
            index[key] = osv_record
            continue
        for vuln in osv_record.vulnerabilities:
            add_unique_vulnerability(target, vuln)
        if osv_record.source_file not in target.source_file:
            target.source_file = f"{target.source_file}; {osv_record.source_file}"
        if target.version_source == "manifest":
            target.version_source = "osv"
    if osv_records:
        warnings.append(f"OSV matched {len(osv_records)} vulnerable package records.")


def merge_dependency_records(records: list[DependencyRecord]) -> list[DependencyRecord]:
    merged: dict[tuple[str, str, str], DependencyRecord] = {}
    by_name: dict[tuple[str, str], DependencyRecord] = {}
    for record in records:
        normalize_record(record)
        key = record_key(record)
        existing = merged.get(key)
        if existing is None:
            name_key = (record.ecosystem, canonical_dependency_name(record.ecosystem, record.name))
            existing_name = by_name.get(name_key)
            if existing_name is not None and should_replace_manifest(existing_name, record):
                remove_key = record_key(existing_name)
                merged.pop(remove_key, None)
                existing = existing_name
            elif existing_name is not None and should_keep_existing(existing_name, record):
                merge_record_into(existing_name, record)
                continue
        if existing is None:
            merged[key] = record
            by_name[(record.ecosystem, canonical_dependency_name(record.ecosystem, record.name))] = record
        else:
            merge_record_into(existing, record)
            merged[record_key(existing)] = existing
    return list(merged.values())


def should_replace_manifest(existing: DependencyRecord, candidate: DependencyRecord) -> bool:
    if existing.version_source == "manifest" and candidate.version_source in {"lockfile", "environment", "sbom", "osv"}:
        return True
    if not existing.resolved and candidate.resolved:
        return True
    return False


def should_keep_existing(existing: DependencyRecord, candidate: DependencyRecord) -> bool:
    if existing.version_source in {"lockfile", "environment", "sbom", "osv"} and candidate.version_source == "manifest":
        return True
    if existing.resolved and not candidate.resolved:
        return True
    return False


def merge_record_into(existing: DependencyRecord, candidate: DependencyRecord) -> None:
    if source_rank(candidate.version_source) < source_rank(existing.version_source):
        existing.version_source = candidate.version_source
    if not existing.resolved and candidate.resolved:
        existing.version = candidate.version
        existing.resolved = True
    if not existing.requested_version and candidate.requested_version:
        existing.requested_version = candidate.requested_version
    if candidate.dependency_type == "direct":
        existing.dependency_type = "direct"
    if existing.license == "UNKNOWN" and candidate.license != "UNKNOWN":
        existing.license = candidate.license
    if candidate.purl and not existing.purl:
        existing.purl = candidate.purl
    existing.scope = strongest_scope(existing.scope, candidate.scope)
    existing.source_file = merge_source_file(existing.source_file, candidate.source_file)
    existing.manifest_type = merge_source_file(existing.manifest_type, candidate.manifest_type)
    for signal in candidate.signals:
        add_unique(existing.signals, signal)
    for vuln in candidate.vulnerabilities:
        add_unique_vulnerability(existing, vuln)


def normalize_record(record: DependencyRecord) -> None:
    record.ecosystem = normalize_ecosystem(record.ecosystem)
    record.name = canonical_dependency_name(record.ecosystem, record.name)
    if record.version.startswith("=="):
        record.version = record.version[2:]
    record.resolved = record.resolved or bool(exact_version(record.version))
    if not record.purl:
        record.purl = build_purl(record.ecosystem, record.name, record.version)


def record_key(record: DependencyRecord) -> tuple[str, str, str]:
    return (
        normalize_ecosystem(record.ecosystem),
        canonical_dependency_name(record.ecosystem, record.name),
        record.version or "*",
    )


def record_index(records: list[DependencyRecord]) -> dict[tuple[str, str, str], DependencyRecord]:
    return {record_key(record): record for record in records}


def source_rank(source: str) -> int:
    return {
        "lockfile": 0,
        "environment": 1,
        "sbom": 2,
        "osv": 2,
        "manifest": 5,
    }.get(source, 4)


def strongest_scope(left: str, right: str) -> str:
    order = {"runtime": 0, "peer": 1, "optional": 2, "development": 3}
    return left if order.get(left, 9) <= order.get(right, 9) else right


def merge_source_file(left: str, right: str) -> str:
    values = [item.strip() for item in f"{left}; {right}".split(";") if item.strip()]
    return "; ".join(dict.fromkeys(values))


def add_unique(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def add_unique_vulnerability(record: DependencyRecord, vulnerability: dict[str, Any]) -> None:
    vuln_id = vulnerability.get("id")
    if any(existing.get("id") == vuln_id and existing.get("source") == vulnerability.get("source") for existing in record.vulnerabilities):
        return
    record.vulnerabilities.append(vulnerability)


def enrich_dependency(dependency: DependencyRecord) -> None:
    dependency.purl = build_purl(dependency.ecosystem, dependency.name, dependency.version)
    if dependency.license == "UNKNOWN":
        dependency.license = known_license(dependency) or "UNKNOWN"

    signals = list(dict.fromkeys(dependency.signals))
    for vulnerability in match_local_vulnerabilities(dependency):
        add_unique_vulnerability(dependency, vulnerability)
    for vulnerability in dependency.vulnerabilities:
        source = "OSV" if vulnerability.get("source") == "osv" else "local advisory"
        add_unique(signals, f"{source}: {vulnerability['id']}")

    typo_signal = typosquatting_signal(dependency)
    if typo_signal:
        add_unique(signals, typo_signal)
    if dependency.license == "UNKNOWN":
        add_unique(signals, "unknown license")
    elif license_has_copyleft_hint(dependency.license):
        add_unique(signals, f"license needs review: {dependency.license}")
    if is_unpinned_version(dependency):
        add_unique(signals, "version not pinned")
    if dependency.resolved:
        add_unique(signals, f"exact version from {dependency.version_source}")
    if dependency.dependency_type == "transitive":
        add_unique(signals, "transitive dependency")
    if is_url_or_vcs_source(dependency.version):
        add_unique(signals, "URL/VCS source")
    if dependency.ecosystem == "npm" and looks_internal_npm_name(dependency.name):
        add_unique(signals, "possible dependency confusion")

    dependency.signals = signals
    dependency.risk = score_dependency(dependency)
    dependency.recommendation = dependency_recommendation(dependency)


def build_vex_context(target: Path, target_info: dict[str, Any]) -> dict[str, Any]:
    source_index = build_source_reachability_index(target)
    attack_surface = discover_attack_surface(target)
    runtime_log_paths = target_info.get("runtimeLogPaths") if isinstance(target_info.get("runtimeLogPaths"), list) else []
    runtime = load_runtime_log_evidence(runtime_log_paths, use_global=not bool(target_info.get("importId")))
    return {
        "target": target_info,
        "source_index": source_index,
        "attack_surface": attack_surface,
        "runtime": runtime,
        "references": [
            {
                "name": "CycloneDX VEX",
                "url": "https://cyclonedx.org/capabilities/vex/",
            },
            {
                "name": "CycloneDX Security Use Cases",
                "url": "https://cyclonedx.org/use-cases/security/",
            },
            {
                "name": "Endor Labs Reachability Analysis",
                "url": "https://docs.endorlabs.com/scan/sca/reachability-analysis",
            },
        ],
    }


def build_source_reachability_index(target: Path) -> dict[str, Any]:
    index: dict[str, Any] = {
        "files_scanned": 0,
        "files_skipped": 0,
        "python_imports": {},
        "javascript_imports": {},
        "warnings": [],
    }
    for path in iter_reachability_files(target):
        if index["files_scanned"] >= MAX_REACHABILITY_FILES:
            index["files_skipped"] += 1
            continue
        try:
            if path.stat().st_size > MAX_REACHABILITY_FILE_BYTES:
                index["files_skipped"] += 1
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            index["warnings"].append(f"{relative_posix(path, target)} read failed: {exc}")
            continue
        rel = relative_posix(path, target)
        index["files_scanned"] += 1
        if path.suffix.lower() == ".py":
            index_python_imports(index, rel, text)
        elif path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            index_javascript_imports(index, rel, text)
    return index


def iter_reachability_files(target: Path) -> Iterable[Path]:
    for current_dir, dir_names, file_names in os.walk(target):
        dir_names[:] = [name for name in dir_names if include_walk_dir(name)]
        for file_name in file_names:
            path = Path(current_dir) / file_name
            if path.suffix.lower() in SOURCE_CODE_EXTENSIONS:
                yield path


def index_python_imports(index: dict[str, Any], rel: str, text: str) -> None:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        index_python_imports_with_regex(index, rel, text)
        return

    module_aliases: dict[str, list[str]] = {}
    lines = text.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = python_module_root(alias.name)
                if not root:
                    continue
                display = line_preview(lines, getattr(node, "lineno", 0))
                add_reachability_evidence(
                    index["python_imports"],
                    root,
                    "imports",
                    rel,
                    getattr(node, "lineno", 0),
                    display or f"import {alias.name}",
                )
                alias_name = alias.asname or root
                module_aliases.setdefault(root, []).append(alias_name)
        elif isinstance(node, ast.ImportFrom):
            if not node.module:
                continue
            root = python_module_root(node.module)
            if not root:
                continue
            display = line_preview(lines, getattr(node, "lineno", 0))
            add_reachability_evidence(
                index["python_imports"],
                root,
                "imports",
                rel,
                getattr(node, "lineno", 0),
                display or f"from {node.module} import ...",
            )

    for root, aliases in module_aliases.items():
        for alias in aliases:
            pattern = re.compile(rf"\b{re.escape(alias)}\s*(?:\.|\()", re.MULTILINE)
            match = pattern.search(text)
            if match:
                line_number = text.count("\n", 0, match.start()) + 1
                add_reachability_evidence(
                    index["python_imports"],
                    root,
                    "calls",
                    rel,
                    line_number,
                    line_preview(lines, line_number) or f"{alias} used",
                )


def index_python_imports_with_regex(index: dict[str, Any], rel: str, text: str) -> None:
    lines = text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        import_match = re.match(r"\s*import\s+([A-Za-z_][A-Za-z0-9_\.]*)", line)
        from_match = re.match(r"\s*from\s+([A-Za-z_][A-Za-z0-9_\.]*)\s+import\s+", line)
        module = import_match.group(1) if import_match else from_match.group(1) if from_match else ""
        root = python_module_root(module)
        if root:
            add_reachability_evidence(index["python_imports"], root, "imports", rel, line_number, line.strip())


def index_javascript_imports(index: dict[str, Any], rel: str, text: str) -> None:
    import_pattern = re.compile(
        r"(?:import\s+(?:[^'\";]+?\s+from\s+)?['\"]([^'\"]+)['\"]|"
        r"require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)|"
        r"import\s*\(\s*['\"]([^'\"]+)['\"]\s*\))",
        re.MULTILINE,
    )
    lines = text.splitlines()
    for match in import_pattern.finditer(text):
        raw_name = next((group for group in match.groups() if group), "")
        package_name = javascript_package_name(raw_name)
        if not package_name:
            continue
        line_number = text.count("\n", 0, match.start()) + 1
        add_reachability_evidence(
            index["javascript_imports"],
            package_name,
            "imports",
            rel,
            line_number,
            line_preview(lines, line_number) or f"import {raw_name}",
        )
        add_javascript_call_evidence(index, package_name, rel, text, lines, match.group(0), line_number)


def add_javascript_call_evidence(
    index: dict[str, Any],
    package_name: str,
    rel: str,
    text: str,
    lines: list[str],
    import_text: str,
    import_line: int,
) -> None:
    alias_match = re.match(r"\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require", import_text)
    default_match = re.match(r"\s*import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from", import_text)
    namespace_match = re.match(r"\s*import\s+\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from", import_text)
    alias = ""
    for match in (alias_match, default_match, namespace_match):
        if match:
            alias = match.group(1)
            break
    if not alias:
        return
    pattern = re.compile(rf"\b{re.escape(alias)}\s*(?:\.|\()", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return
    line_number = text.count("\n", 0, match.start()) + 1
    if line_number == import_line:
        return
    add_reachability_evidence(
        index["javascript_imports"],
        package_name,
        "calls",
        rel,
        line_number,
        line_preview(lines, line_number) or f"{alias} used",
    )


def add_reachability_evidence(
    bucket: dict[str, Any],
    key: str,
    kind: str,
    path: str,
    line: int,
    snippet: str,
) -> None:
    normalized = key.strip().lower()
    if not normalized:
        return
    entry = bucket.setdefault(normalized, {"imports": [], "calls": [], "files": []})
    evidence = compact_dict({"path": path, "line": line, "snippet": snippet[:180]})
    if evidence not in entry[kind]:
        entry[kind].append(evidence)
    if path not in entry["files"]:
        entry["files"].append(path)
    entry[kind] = entry[kind][:8]
    entry["files"] = entry["files"][:8]


def python_module_root(module: str) -> str:
    root = module.strip().split(".", 1)[0]
    return root.lower()


def javascript_package_name(raw_name: str) -> str:
    if not raw_name or raw_name.startswith((".", "/", "#")):
        return ""
    if raw_name.startswith("@"):
        parts = raw_name.split("/")
        return "/".join(parts[:2]).lower() if len(parts) >= 2 else raw_name.lower()
    return raw_name.split("/", 1)[0].lower()


def line_preview(lines: list[str], line_number: int) -> str:
    if line_number <= 0 or line_number > len(lines):
        return ""
    return re.sub(r"\s+", " ", lines[line_number - 1].strip())[:180]


def discover_attack_surface(target: Path) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    service_hints: set[str] = set()
    files_scanned = 0
    for current_dir, dir_names, file_names in os.walk(target):
        dir_names[:] = [name for name in dir_names if include_walk_dir(name)]
        for file_name in file_names:
            path = Path(current_dir) / file_name
            lower_name = file_name.lower()
            if path.suffix.lower() not in SOURCE_CODE_EXTENSIONS and lower_name not in {
                "dockerfile",
                "docker-compose.yml",
                "docker-compose.yaml",
                "compose.yml",
                "compose.yaml",
            }:
                continue
            if files_scanned >= MAX_REACHABILITY_FILES:
                continue
            try:
                if path.stat().st_size > MAX_REACHABILITY_FILE_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            files_scanned += 1
            rel = relative_posix(path, target)
            scan_attack_surface_text(text, rel, lower_name, evidence, service_hints)
    return {
        "exposed": bool(evidence),
        "evidence": evidence[:12],
        "service_hints": sorted(service_hints),
        "files_scanned": files_scanned,
    }


def scan_attack_surface_text(
    text: str,
    rel: str,
    lower_name: str,
    evidence: list[dict[str, Any]],
    service_hints: set[str],
) -> None:
    lines = text.splitlines()
    patterns = [
        (re.compile(r"\bEXPOSE\s+([0-9]+)", re.IGNORECASE), "container exposes port", "container"),
        (re.compile(r"ports\s*:|['\"]?[0-9.]*:[0-9]+:[0-9]+['\"]?"), "compose publishes port", "container"),
        (re.compile(r'"(?:preinstall|install|postinstall|prepare)"\s*:', re.IGNORECASE), "package install script entry", "package-script"),
        (re.compile(r"@\w+\.(?:get|post|put|delete|patch|route)\s*\(", re.IGNORECASE), "Python web route", "python-web"),
        (re.compile(r"\bFastAPI\s*\(|\bAPIRouter\s*\(", re.IGNORECASE), "FastAPI application", "fastapi"),
        (re.compile(r"\bFlask\s*\(", re.IGNORECASE), "Flask application", "flask"),
        (re.compile(r"\buvicorn\.run\s*\(", re.IGNORECASE), "uvicorn runtime", "uvicorn"),
        (re.compile(r"\burlpatterns\s*=", re.IGNORECASE), "Django URL configuration", "django"),
        (re.compile(r"\bexpress\s*\(\)|\bapp\.(?:get|post|put|delete|patch)\s*\(", re.IGNORECASE), "Express route", "express"),
        (re.compile(r"\.listen\s*\(|createServer\s*\(", re.IGNORECASE), "Node service listener", "node-web"),
        (re.compile(r"\b(?:desktopAppEntry|checkUpdate)\s*\(|\bapp\.whenReady\s*\(|\bBrowserWindow\s*\(", re.IGNORECASE), "desktop application entry", "desktop-app"),
        (re.compile(r"\b(?:axios|fetch)\s*(?:\.\s*(?:get|post|request))?\s*\(\s*['\"]https?://", re.IGNORECASE), "desktop update network entry", "desktop-update"),
    ]
    for pattern, label, service_hint in patterns:
        match = pattern.search(text)
        if not match:
            continue
        line_number = text.count("\n", 0, match.start()) + 1
        if lower_name == "dockerfile" and label != "container exposes port":
            continue
        evidence.append(
            compact_dict(
                {
                    "path": rel,
                    "line": line_number,
                    "kind": label,
                    "snippet": line_preview(lines, line_number) or match.group(0)[:120],
                }
            )
        )
        service_hints.add(service_hint)


def load_runtime_log_evidence(log_paths: Iterable[str] | None = None, *, use_global: bool = True) -> dict[str, Any]:
    if log_paths:
        findings: list[dict[str, Any]] = []
        events = load_runtime_log_files(log_paths)
    elif use_global:
        storage_dir = ROOT / "storage" / "log_audit"
        findings = load_runtime_log_findings(storage_dir / "findings.json")
        events = load_runtime_log_events(storage_dir / "events.jsonl")
    else:
        findings = []
        events = []
    classified = [classify_runtime_record(item, "finding") for item in findings]
    classified.extend(classify_runtime_record(item, "event") for item in events)
    classified = [item for item in classified if item.get("categories")]
    category_counts: dict[str, int] = {}
    for item in classified:
        for category in item.get("categories", []):
            category_counts[category] = category_counts.get(category, 0) + 1
    return {
        "evidence": classified[:MAX_RUNTIME_EVIDENCE_ITEMS],
        "category_counts": category_counts,
        "finding_count": len(findings),
        "event_count": len(events),
    }


def load_runtime_log_files(paths: Iterable[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path_text in paths:
        if len(records) >= MAX_RUNTIME_EVIDENCE_ITEMS:
            break
        path = Path(path_text)
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if len(records) >= MAX_RUNTIME_EVIDENCE_ITEMS:
                        break
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        payload = json.loads(text)
                    except json.JSONDecodeError:
                        payload = {"raw": text, "message": text}
                    if isinstance(payload, dict):
                        payload.setdefault("filename", path.name)
                        payload.setdefault("line_number", line_number)
                        records.append(payload)
        except OSError:
            continue
    return records


def load_runtime_log_findings(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    findings = payload.get("findings") if isinstance(payload, dict) else payload
    if not isinstance(findings, list):
        return []
    return [item for item in findings[:MAX_RUNTIME_EVIDENCE_ITEMS] if isinstance(item, dict)]


def load_runtime_log_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if len(events) >= MAX_RUNTIME_EVIDENCE_ITEMS:
                    break
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    events.append(payload)
    except OSError:
        return []
    return events


def classify_runtime_record(record: dict[str, Any], kind: str) -> dict[str, Any]:
    text = " ".join(
        str(record.get(key) or "")
        for key in ("rule_id", "title", "signal", "evidence", "event", "message", "path", "raw", "source")
    ).lower()
    categories: list[str] = []
    if any(token in text for token in ("sql", "injection", "sleep(", "union select", "../", "traversal", "xss")):
        categories.append("injection")
    if any(token in text for token in ("/admin", "/export", "/config", "sensitive", "secret")):
        categories.append("sensitive_path")
    if any(token in text for token in ("401", "403", "brute", "auth", "login", "jwt", "token")):
        categories.append("auth")
    if any(token in text for token in ("egress", "outbound", "beacon", "dst_ip", "connect to")) or record.get("dst_ip"):
        categories.append("egress")
    if record.get("path") or str(record.get("source") or "").lower() == "web":
        categories.append("web")
    if record.get("severity") in {"critical", "high"}:
        categories.append("high_signal")
    return compact_dict(
        {
            "kind": kind,
            "id": record.get("id") or record.get("fingerprint"),
            "rule_id": record.get("rule_id"),
            "severity": record.get("severity"),
            "score": record.get("score"),
            "time": record.get("time"),
            "source": record.get("source"),
            "path": record.get("path"),
            "event": record.get("event") or record.get("message"),
            "categories": sorted(set(categories)),
            "evidence": record.get("evidence") or record.get("raw") or record.get("message"),
        }
    )


def apply_vex_analysis(dependencies: list[DependencyRecord], context: dict[str, Any]) -> None:
    for dependency in dependencies:
        usage = dependency_usage_context(dependency, context["source_index"])
        surface = dependency_attack_surface_context(dependency, context["attack_surface"], usage)
        dependency.reachability = build_dependency_reachability(dependency, usage, surface, context["runtime"])
        statements: list[dict[str, Any]] = []
        for vulnerability in dependency.vulnerabilities:
            runtime = runtime_context_for_vulnerability(dependency, vulnerability, context["runtime"], usage, surface)
            statement = build_vex_statement(dependency, vulnerability, usage, surface, runtime)
            statements.append(statement)
            vulnerability["vex"] = statement
            vulnerability["analysis"] = cyclonedx_analysis(statement)
        dependency.vex = statements
        apply_vex_signals_and_risk(dependency)


def dependency_usage_context(dependency: DependencyRecord, source_index: dict[str, Any]) -> dict[str, Any]:
    candidates = dependency_import_candidates(dependency)
    bucket_name = "python_imports" if dependency.ecosystem == "pypi" else "javascript_imports"
    bucket = source_index.get(bucket_name) if isinstance(source_index.get(bucket_name), dict) else {}
    import_evidence: list[dict[str, Any]] = []
    call_evidence: list[dict[str, Any]] = []
    files: list[str] = []
    for candidate in candidates:
        entry = bucket.get(candidate.lower())
        if not isinstance(entry, dict):
            continue
        import_evidence.extend(item for item in entry.get("imports", []) if isinstance(item, dict))
        call_evidence.extend(item for item in entry.get("calls", []) if isinstance(item, dict))
        files.extend(str(item) for item in entry.get("files", []) if item)
    import_evidence = stable_dicts(import_evidence)[:8]
    call_evidence = stable_dicts(call_evidence)[:8]
    files = list(dict.fromkeys(files))[:8]
    return {
        "imported": bool(import_evidence),
        "called": bool(call_evidence),
        "candidates": sorted(candidates),
        "files": files,
        "evidence": import_evidence,
        "call_evidence": call_evidence,
        "files_scanned": int(source_index.get("files_scanned") or 0),
        "files_skipped": int(source_index.get("files_skipped") or 0),
    }


def dependency_import_candidates(dependency: DependencyRecord) -> set[str]:
    canonical = canonical_dependency_name(dependency.ecosystem, dependency.name)
    if dependency.ecosystem == "pypi":
        aliases = set(PYTHON_IMPORT_ALIASES.get(canonical, ()))
        aliases.add(canonical.replace("-", "_"))
        aliases.add(canonical.replace("-", ""))
        return {alias.lower() for alias in aliases if alias}
    if dependency.ecosystem == "npm":
        return {canonical.lower()}
    return {canonical.lower()}


def dependency_attack_surface_context(
    dependency: DependencyRecord,
    attack_surface: dict[str, Any],
    usage: dict[str, Any],
) -> dict[str, Any]:
    service_package = dependency_is_service_package(dependency)
    related = bool(usage.get("imported")) or service_package
    exposed = bool(attack_surface.get("exposed")) and related
    return {
        "exposed": exposed,
        "global_exposed": bool(attack_surface.get("exposed")),
        "service_package": service_package,
        "service_hints": attack_surface.get("service_hints", []),
        "evidence": list(attack_surface.get("evidence", []))[:6] if exposed else [],
    }


def dependency_is_service_package(dependency: DependencyRecord) -> bool:
    return canonical_dependency_name(dependency.ecosystem, dependency.name) in SERVER_FRAMEWORK_PACKAGES.get(
        dependency.ecosystem,
        set(),
    )


def build_dependency_reachability(
    dependency: DependencyRecord,
    usage: dict[str, Any],
    surface: dict[str, Any],
    runtime: dict[str, Any],
) -> dict[str, Any]:
    runtime_context = runtime_context_for_dependency(dependency, runtime)
    confidence = 0.2
    if usage.get("imported"):
        confidence += 0.25
    if usage.get("called"):
        confidence += 0.2
    if surface.get("exposed"):
        confidence += 0.2
    if runtime_context.get("matched"):
        confidence += 0.25
    return {
        "imported": bool(usage.get("imported")),
        "called": bool(usage.get("called")),
        "attack_surface": bool(surface.get("exposed")),
        "runtime_trace": bool(runtime_context.get("matched")),
        "confidence": round(min(0.98, confidence), 2),
        "import_candidates": usage.get("candidates", []),
        "code_evidence": list(usage.get("evidence", []))[:5],
        "call_evidence": list(usage.get("call_evidence", []))[:5],
        "attack_surface_evidence": list(surface.get("evidence", []))[:5],
        "runtime_evidence": list(runtime_context.get("evidence", []))[:5],
    }


def runtime_context_for_dependency(dependency: DependencyRecord, runtime: dict[str, Any]) -> dict[str, Any]:
    wanted = runtime_categories_for_dependency(dependency, {})
    return select_runtime_evidence(runtime, wanted)


def runtime_context_for_vulnerability(
    dependency: DependencyRecord,
    vulnerability: dict[str, Any],
    runtime: dict[str, Any],
    usage: dict[str, Any],
    surface: dict[str, Any],
) -> dict[str, Any]:
    wanted = runtime_categories_for_dependency(dependency, vulnerability)
    selected = select_runtime_evidence(runtime, wanted)
    if not selected["matched"] and usage.get("imported") and surface.get("exposed"):
        selected["nearby_high_signal"] = bool(runtime.get("category_counts", {}).get("high_signal"))
    return selected


def runtime_categories_for_dependency(dependency: DependencyRecord, vulnerability: dict[str, Any]) -> set[str]:
    canonical = canonical_dependency_name(dependency.ecosystem, dependency.name)
    categories: set[str] = set()
    if canonical in SERVER_FRAMEWORK_PACKAGES.get(dependency.ecosystem, set()):
        categories.update({"web", "sensitive_path", "injection"})
    if canonical in AUTH_PACKAGES.get(dependency.ecosystem, set()):
        categories.add("auth")
    if canonical in HTTP_CLIENT_PACKAGES.get(dependency.ecosystem, set()):
        categories.add("egress")
    if canonical in DESERIALIZATION_PACKAGES.get(dependency.ecosystem, set()):
        categories.update({"injection", "sensitive_path"})

    text = " ".join(
        str(vulnerability.get(key) or "")
        for key in ("id", "summary", "details", "affected")
    ).lower()
    if any(token in text for token in ("sql", "injection", "xss", "deserialize", "yaml", "rce", "traversal")):
        categories.update({"injection", "sensitive_path"})
    if any(token in text for token in ("jwt", "auth", "token", "session")):
        categories.add("auth")
    if any(token in text for token in ("ssrf", "request", "redirect", "egress", "http")):
        categories.add("egress")
    return categories


def select_runtime_evidence(runtime: dict[str, Any], wanted: set[str]) -> dict[str, Any]:
    if not wanted:
        return {"matched": False, "categories": [], "evidence": []}
    selected: list[dict[str, Any]] = []
    for item in runtime.get("evidence", []):
        if not isinstance(item, dict):
            continue
        categories = set(str(category) for category in item.get("categories", []))
        if categories.intersection(wanted):
            selected.append(item)
    return {
        "matched": bool(selected),
        "categories": sorted(wanted),
        "evidence": selected[:6],
    }


def build_vex_statement(
    dependency: DependencyRecord,
    vulnerability: dict[str, Any],
    usage: dict[str, Any],
    surface: dict[str, Any],
    runtime: dict[str, Any],
) -> dict[str, Any]:
    fixed = installed_version_is_fixed(dependency, vulnerability)
    status = determine_vex_status(fixed, usage, surface, runtime)
    justification = vex_justification(status, usage, surface, runtime)
    response = vex_response(status, vulnerability)
    detail = vex_detail(status, dependency, vulnerability, usage, surface, runtime, fixed)
    cyclonedx_state = CYCLONEDX_STATE_BY_VEX_STATUS[status]
    confidence = vex_confidence(status, usage, surface, runtime, fixed)
    return compact_dict(
        {
            "id": str(vulnerability.get("id") or "unknown"),
            "source": str(vulnerability.get("source") or "unknown"),
            "dependency": f"{dependency.name}@{dependency.version}",
            "purl": dependency.purl,
            "status": status,
            "cyclonedx_state": cyclonedx_state,
            "justification": justification,
            "response": response,
            "detail": detail,
            "confidence": confidence,
            "severity": vulnerability.get("severity"),
            "fixed_versions": vulnerability.get("fixed_versions") or [],
            "reachability": {
                "imported": bool(usage.get("imported")),
                "called": bool(usage.get("called")),
                "attack_surface": bool(surface.get("exposed")),
                "runtime_trace": bool(runtime.get("matched")),
                "nearby_high_signal": bool(runtime.get("nearby_high_signal")),
                "code_evidence": list(usage.get("evidence", []))[:3],
                "call_evidence": list(usage.get("call_evidence", []))[:3],
                "attack_surface_evidence": list(surface.get("evidence", []))[:3],
                "runtime_evidence": list(runtime.get("evidence", []))[:3],
            },
        }
    )


def determine_vex_status(
    fixed: bool,
    usage: dict[str, Any],
    surface: dict[str, Any],
    runtime: dict[str, Any],
) -> str:
    if fixed:
        return "fixed"
    if runtime.get("matched") and (usage.get("imported") or usage.get("called") or surface.get("exposed")):
        return "affected"
    if usage.get("called") and surface.get("exposed"):
        return "affected"
    if usage.get("imported") and surface.get("exposed"):
        return "under_investigation"
    if usage.get("imported") or runtime.get("matched") or surface.get("exposed") or runtime.get("nearby_high_signal"):
        return "under_investigation"
    return "not_affected"


def vex_justification(
    status: str,
    usage: dict[str, Any],
    surface: dict[str, Any],
    runtime: dict[str, Any],
) -> str | None:
    if status == "not_affected":
        if not usage.get("imported") and not usage.get("called"):
            return "code_not_reachable"
        if not surface.get("exposed"):
            return "requires_environment"
        if not runtime.get("matched"):
            return "protected_at_runtime"
    if status == "fixed":
        return "protected_by_mitigating_control"
    return None


def vex_response(status: str, vulnerability: dict[str, Any]) -> list[str]:
    fixed_versions = vulnerability.get("fixed_versions")
    if status in {"affected", "under_investigation"} and fixed_versions:
        return ["update"]
    if status == "fixed":
        return ["update"]
    if status == "not_affected":
        return ["will_not_fix"]
    return []


def vex_detail(
    status: str,
    dependency: DependencyRecord,
    vulnerability: dict[str, Any],
    usage: dict[str, Any],
    surface: dict[str, Any],
    runtime: dict[str, Any],
    fixed: bool,
) -> str:
    code = "called" if usage.get("called") else "imported" if usage.get("imported") else "not imported in scanned source"
    attack_surface = "exposed" if surface.get("exposed") else "no related exposed service found"
    logs = "runtime trace matched" if runtime.get("matched") else "no matching exploit trace in persisted logs"
    if fixed:
        return f"{dependency.name} is at a fixed version for {vulnerability.get('id')}; code={code}; logs={logs}."
    if status == "affected":
        return f"{dependency.name} has reachable vulnerable code with {attack_surface}; {logs}."
    if status == "under_investigation":
        return f"{dependency.name} has partial reachability evidence for {vulnerability.get('id')}: code={code}; service={attack_surface}; logs={logs}."
    return f"{dependency.name} is present in SBOM, but {code}; {attack_surface}; {logs}."


def vex_confidence(
    status: str,
    usage: dict[str, Any],
    surface: dict[str, Any],
    runtime: dict[str, Any],
    fixed: bool,
) -> str:
    if fixed:
        return "high"
    if runtime.get("matched") and (usage.get("called") or surface.get("exposed")):
        return "high"
    if status == "affected":
        return "medium"
    if status == "not_affected" and usage.get("files_scanned", 0) > 0 and not usage.get("files_skipped"):
        return "medium"
    if status == "under_investigation":
        return "medium"
    return "low"


def installed_version_is_fixed(dependency: DependencyRecord, vulnerability: dict[str, Any]) -> bool:
    fixed_versions = [str(item) for item in vulnerability.get("fixed_versions", []) if item]
    if not fixed_versions:
        return False
    current = exact_version(dependency.version)
    if not current:
        return False
    return any(version_gte(current, fixed_version) for fixed_version in fixed_versions)


def version_gte(current: str, minimum: str) -> bool:
    if Version is not None:
        try:
            return Version(current) >= Version(minimum)
        except (InvalidVersion, ValueError):
            pass
    return version_tuple_for_compare(current) >= version_tuple_for_compare(minimum)


def cyclonedx_analysis(statement: dict[str, Any]) -> dict[str, Any]:
    analysis: dict[str, Any] = {
        "state": statement.get("cyclonedx_state") or "in_triage",
        "detail": statement.get("detail") or "",
    }
    justification = statement.get("justification")
    if justification in CYCLONEDX_JUSTIFICATIONS:
        analysis["justification"] = justification
    response = statement.get("response")
    if isinstance(response, list) and response:
        analysis["response"] = response
    return analysis


def apply_vex_signals_and_risk(dependency: DependencyRecord) -> None:
    if not dependency.vulnerabilities:
        return
    statuses = [str(item.get("status") or "") for item in dependency.vex]
    if dependency.reachability.get("imported"):
        add_unique(dependency.signals, "reachable import detected")
    if dependency.reachability.get("called"):
        add_unique(dependency.signals, "reachable call detected")
    if dependency.reachability.get("attack_surface"):
        add_unique(dependency.signals, "related service attack surface exposed")
    if dependency.reachability.get("runtime_trace"):
        add_unique(dependency.signals, "runtime exploit trace matched")
    if statuses:
        add_unique(dependency.signals, "VEX: " + ", ".join(sorted(set(statuses))))

    if statuses and all(status in {"not_affected", "fixed"} for status in statuses):
        floor = 68 if dependency_has_non_vulnerability_supply_chain_risk(dependency) else 42
        dependency.risk = min(dependency.risk, floor)
    elif "affected" in statuses:
        max_severity = strongest_vulnerability_severity(dependency.vulnerabilities)
        dependency.risk = max(dependency.risk, SEVERITY_FLOORS.get(max_severity, 78) + 8)
        dependency.risk = min(100, dependency.risk)
    elif "under_investigation" in statuses:
        dependency.risk = max(dependency.risk, 62)

    dependency.recommendation = dependency_vex_recommendation(dependency) or dependency.recommendation


def dependency_has_non_vulnerability_supply_chain_risk(dependency: DependencyRecord) -> bool:
    text = " ".join(dependency.signals).lower()
    return any(token in text for token in ("dependency confusion", "typosquatting", "install script", "url/vcs source"))


def strongest_vulnerability_severity(vulnerabilities: list[dict[str, Any]]) -> str:
    severity = "low"
    for vulnerability in vulnerabilities:
        severity = stronger_dependency_severity(severity, str(vulnerability.get("severity") or "low"))
    return severity


def stronger_dependency_severity(left: str, right: str) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return left if order.get(left, 1) >= order.get(right, 1) else right


def dependency_vex_recommendation(dependency: DependencyRecord) -> str:
    statuses = {str(item.get("status") or "") for item in dependency.vex}
    if "affected" in statuses:
        return "Treat as exploitable in this product context: update or mitigate, verify exposed routes, and review matching runtime logs."
    if "under_investigation" in statuses:
        return "Triage reachability: confirm call paths, route exposure, exploit preconditions, and runtime log correlation before accepting or suppressing."
    if statuses and statuses.issubset({"fixed"}):
        return "VEX marks this vulnerability as fixed; keep the fixed version pinned and retain the statement for audit evidence."
    if statuses and statuses.issubset({"not_affected", "fixed"}):
        return "VEX marks this dependency vulnerability as not affected in the scanned context; keep the statement current when imports, routes, or logs change."
    return ""


def stable_dicts(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for value in values:
        key = json.dumps(value, ensure_ascii=False, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def match_local_vulnerabilities(dependency: DependencyRecord) -> list[dict[str, Any]]:
    canonical = canonical_dependency_name(dependency.ecosystem, dependency.name)
    matches: list[dict[str, Any]] = []
    for item in LOCAL_VULNERABILITIES:
        if item["ecosystem"] != dependency.ecosystem:
            continue
        if canonical_dependency_name(dependency.ecosystem, item["name"]) != canonical:
            continue
        confidence = affected_confidence(dependency.version, item["affected"])
        if confidence is None:
            continue
        matches.append(
            {
                "id": item["id"],
                "source": "local",
                "severity": item["severity"],
                "affected": item["affected"],
                "summary": item["summary"],
                "confidence": confidence,
                "fixed_versions": [],
            }
        )
    return matches


def affected_confidence(version_spec: str, affected: str) -> str | None:
    if affected == "*":
        return "high"
    exact = exact_version(version_spec)
    if exact:
        return "high" if version_in_range(exact, affected) else None
    lower_bound = likely_lower_bound(version_spec)
    if lower_bound and version_in_range(lower_bound, affected):
        return "medium"
    if version_spec.strip() in {"", "*", "latest"}:
        return "low"
    return None


def exact_version(version_spec: str) -> str | None:
    value = version_spec.strip()
    if not value:
        return None
    if value.startswith("==="):
        return value[3:].strip()
    if value.startswith("=="):
        return value[2:].strip()
    if re.fullmatch(r"v?\d+(?:\.\d+){0,4}(?:[-+][A-Za-z0-9_.-]+)?", value):
        return value.lstrip("v")
    return None


def likely_lower_bound(version_spec: str) -> str | None:
    value = version_spec.strip()
    if not value:
        return None
    if value[0] in {"^", "~"}:
        match = re.search(r"\d+(?:\.\d+){0,4}(?:[-+][A-Za-z0-9_.-]+)?", value)
        return match.group(0) if match else None
    match = re.search(r"(?:>=|>|~=)\s*v?(\d+(?:\.\d+){0,4}(?:[-+][A-Za-z0-9_.-]+)?)", value)
    if match:
        return match.group(1)
    return exact_version(value)


def version_in_range(version: str, specifier: str) -> bool:
    if SpecifierSet is not None and Version is not None:
        try:
            return SpecifierSet(specifier).contains(Version(version), prereleases=True)
        except (InvalidSpecifier, InvalidVersion, ValueError):
            pass
    return fallback_version_in_range(version, specifier)


def fallback_version_in_range(version: str, specifier: str) -> bool:
    version_tuple = version_tuple_for_compare(version)
    for part in [item.strip() for item in specifier.split(",") if item.strip()]:
        match = re.match(r"(<=|>=|<|>|==|=)\s*v?([A-Za-z0-9_.+-]+)", part)
        if not match:
            continue
        operator, target = match.groups()
        target_tuple = version_tuple_for_compare(target)
        if operator in {"==", "="} and version_tuple != target_tuple:
            return False
        if operator == "<" and not version_tuple < target_tuple:
            return False
        if operator == "<=" and not version_tuple <= target_tuple:
            return False
        if operator == ">" and not version_tuple > target_tuple:
            return False
        if operator == ">=" and not version_tuple >= target_tuple:
            return False
    return True


def version_tuple_for_compare(version: str) -> tuple[int, ...]:
    values = re.findall(r"\d+", version)
    return tuple(int(item) for item in values[:5]) or (0,)


def typosquatting_signal(dependency: DependencyRecord) -> str | None:
    if dependency.ecosystem == "npm" and npm_scope(dependency.name) in SAFE_NPM_SCOPES:
        return None
    canonical = canonical_dependency_name(dependency.ecosystem, dependency.name)
    normalized = normalize_for_similarity(canonical)
    if not normalized:
        return None
    for popular in POPULAR_PACKAGES.get(dependency.ecosystem, set()):
        popular_canonical = canonical_dependency_name(dependency.ecosystem, popular)
        if canonical == popular_canonical:
            continue
        popular_normalized = normalize_for_similarity(popular_canonical)
        if abs(len(normalized) - len(popular_normalized)) > 3:
            continue
        ratio = SequenceMatcher(None, normalized, popular_normalized).ratio()
        if ratio >= 0.92:
            return f"possible typosquatting: close to {popular} ({ratio:.2f})"
    return None


def normalize_for_similarity(name: str) -> str:
    if name.startswith("@") and "/" in name:
        name = name.split("/", 1)[1]
    return re.sub(r"[^a-z0-9]", "", name.lower())


def score_dependency(dependency: DependencyRecord) -> int:
    score = 8
    for vulnerability in dependency.vulnerabilities:
        severity = vulnerability.get("severity", "low")
        confidence = vulnerability.get("confidence", "medium")
        weight = SEVERITY_WEIGHTS.get(severity, 12)
        if confidence == "medium":
            weight = int(weight * 0.8)
        elif confidence == "low":
            weight = int(weight * 0.55)
        if vulnerability.get("source") == "osv":
            weight += 8
        score += weight
        score = max(score, SEVERITY_FLOORS.get(severity, 30))

    for signal in dependency.signals:
        if signal.startswith("possible typosquatting"):
            score += 26
        elif signal == "possible dependency confusion":
            score += 30
        elif signal.startswith("install script"):
            score += 18
        elif signal == "URL/VCS source":
            score += 20
        elif signal == "version not pinned":
            score += 8
        elif signal == "unknown license":
            score += 8
        elif signal.startswith("license needs review"):
            score += 18

    if dependency.dependency_type == "transitive":
        score = max(0, score - 3)
    if dependency.scope == "development":
        score = max(0, score - 6)
    return min(100, score)


def dependency_recommendation(dependency: DependencyRecord) -> str:
    osv_vulns = [item for item in dependency.vulnerabilities if item.get("source") == "osv"]
    if osv_vulns:
        fixed = sorted({version for item in osv_vulns for version in item.get("fixed_versions", [])})
        fixed_text = f" Fixed versions: {', '.join(fixed[:5])}." if fixed else ""
        return f"Upgrade or replace this package and verify the resolved lockfile version.{fixed_text}"
    if dependency.vulnerabilities:
        ids = ", ".join(item["id"] for item in dependency.vulnerabilities[:3])
        return f"Upgrade or replace the dependency and verify the exact resolved version. Matched: {ids}."
    if any(signal.startswith("possible typosquatting") for signal in dependency.signals):
        return "Manually verify package name, publisher, and download source before allowing it in CI."
    if "possible dependency confusion" in dependency.signals:
        return "Confirm this is a private package and force resolution through the internal registry."
    if any(signal.startswith("install script") for signal in dependency.signals):
        return "Review install script behavior and run builds with minimal network and filesystem privileges."
    if "URL/VCS source" in dependency.signals:
        return "Pin URL/VCS dependencies to a trusted commit or released artifact."
    if dependency.license == "UNKNOWN":
        return "Confirm package license from lockfile, package metadata, or SBOM source."
    if "version not pinned" in dependency.signals:
        return "Generate and enforce a lockfile so CI uses the same resolved version."
    return "Low risk in this scan; keep lockfiles and vulnerability data current."


def build_dependency_findings(dependencies: list[DependencyRecord]) -> list[DependencyFinding]:
    findings: list[DependencyFinding] = []
    for dependency in dependencies:
        if dependency.vulnerabilities and dependency_vulnerabilities_not_actionable(dependency):
            continue
        if dependency.risk < 55 and not dependency.vulnerabilities:
            continue
        fingerprint = dependency_fingerprint(dependency)
        findings.append(
            DependencyFinding(
                id=f"DEP-{hashlib.sha1(fingerprint.encode('utf-8')).hexdigest()[:8].upper()}",
                title=dependency_finding_title(dependency),
                severity=risk_severity(dependency.risk),
                score=dependency.risk,
                dependency=f"{dependency.name}@{dependency.version}",
                ecosystem=dependency.ecosystem,
                source_file=dependency.source_file,
                evidence="; ".join(dependency.signals) or "risk score exceeded threshold",
                recommendation=dependency.recommendation,
                fingerprint=fingerprint,
            )
        )
    return sorted(findings, key=lambda item: (-item.score, item.ecosystem, item.dependency))


def dependency_vulnerabilities_not_actionable(dependency: DependencyRecord) -> bool:
    if not dependency.vex:
        return False
    statuses = {str(item.get("status") or "") for item in dependency.vex}
    return dependency.risk < 55 and bool(statuses) and statuses.issubset({"not_affected", "fixed"})


def dependency_finding_title(dependency: DependencyRecord) -> str:
    if dependency.vex and any(item.get("status") == "affected" for item in dependency.vex):
        return f"{dependency.name} has exploitable VEX context"
    if dependency.vex and any(item.get("status") == "under_investigation" for item in dependency.vex):
        return f"{dependency.name} vulnerability needs reachability triage"
    if any(item.get("source") == "osv" for item in dependency.vulnerabilities):
        return f"{dependency.name} matched OSV vulnerabilities"
    if dependency.vulnerabilities:
        return f"{dependency.name} matched local vulnerability data"
    if any(signal.startswith("possible typosquatting") for signal in dependency.signals):
        return f"{dependency.name} has suspicious package-name similarity"
    if "possible dependency confusion" in dependency.signals:
        return f"{dependency.name} has dependency-confusion signals"
    return f"{dependency.name} dependency risk needs review"


def build_dependency_summary(
    dependencies: list[DependencyRecord],
    findings: list[DependencyFinding],
    manifests: list[Path],
    lockfiles: list[Path],
    tools: list[ToolStatus],
) -> dict[str, Any]:
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    ecosystem_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    unknown_licenses = 0
    vulnerable = 0
    suspicious = 0
    exact_versions = 0
    transitive = 0
    osv_matches = 0

    for dependency in dependencies:
        severity_counts[risk_severity(dependency.risk)] += 1
        ecosystem_counts[dependency.ecosystem] = ecosystem_counts.get(dependency.ecosystem, 0) + 1
        source_counts[dependency.version_source] = source_counts.get(dependency.version_source, 0) + 1
        if dependency.license == "UNKNOWN":
            unknown_licenses += 1
        if dependency.vulnerabilities:
            vulnerable += 1
        if any(item.get("source") == "osv" for item in dependency.vulnerabilities):
            osv_matches += 1
        if any("typosquatting" in signal or "dependency confusion" in signal for signal in dependency.signals):
            suspicious += 1
        if dependency.resolved:
            exact_versions += 1
        if dependency.dependency_type == "transitive":
            transitive += 1

    risk_score = max([dependency.risk for dependency in dependencies], default=0)
    return {
        "total_dependencies": len(dependencies),
        "manifest_count": len(manifests),
        "lockfile_count": len(lockfiles),
        "finding_count": len(findings),
        "risk_score": risk_score,
        "risk_level": risk_severity(risk_score),
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
        "ecosystems": ecosystem_counts,
        "version_sources": source_counts,
        "unknown_licenses": unknown_licenses,
        "vulnerable_dependencies": vulnerable,
        "osv_matches": osv_matches,
        "suspicious_names": suspicious,
        "exact_versions": exact_versions,
        "transitive_dependencies": transitive,
        "manifests": [path.name for path in manifests],
        "lockfiles": [path.name for path in lockfiles],
        "tools": [serialize_tool_status(status) for status in tools],
    }


def build_vex_summary(dependencies: list[DependencyRecord]) -> dict[str, Any]:
    counts = {"affected": 0, "not_affected": 0, "under_investigation": 0, "fixed": 0}
    statement_count = 0
    components_with_vex = 0
    lowered_noise = 0
    for dependency in dependencies:
        if dependency.vex:
            components_with_vex += 1
        statuses = [str(item.get("status") or "") for item in dependency.vex]
        for status in statuses:
            if status in counts:
                counts[status] += 1
                statement_count += 1
        if statuses and set(statuses).issubset({"not_affected", "fixed"}):
            lowered_noise += 1
    actionable = counts["affected"] + counts["under_investigation"]
    reduction = round((counts["not_affected"] + counts["fixed"]) / statement_count * 100, 1) if statement_count else 0
    return {
        "statement_count": statement_count,
        "component_count": components_with_vex,
        "affected": counts["affected"],
        "not_affected": counts["not_affected"],
        "under_investigation": counts["under_investigation"],
        "fixed": counts["fixed"],
        "actionable": actionable,
        "noise_reduced": lowered_noise,
        "false_positive_reduction_percent": reduction,
        "states": counts,
    }


def build_reachability_summary(dependencies: list[DependencyRecord], context: dict[str, Any]) -> dict[str, Any]:
    imported = sum(1 for dependency in dependencies if dependency.reachability.get("imported"))
    called = sum(1 for dependency in dependencies if dependency.reachability.get("called"))
    exposed = sum(1 for dependency in dependencies if dependency.reachability.get("attack_surface"))
    runtime = sum(1 for dependency in dependencies if dependency.reachability.get("runtime_trace"))
    source_index = context.get("source_index") if isinstance(context.get("source_index"), dict) else {}
    attack_surface = context.get("attack_surface") if isinstance(context.get("attack_surface"), dict) else {}
    runtime_context = context.get("runtime") if isinstance(context.get("runtime"), dict) else {}
    return {
        "imported_dependencies": imported,
        "called_dependencies": called,
        "attack_surface_dependencies": exposed,
        "runtime_trace_dependencies": runtime,
        "source_files_scanned": int(source_index.get("files_scanned") or 0),
        "source_files_skipped": int(source_index.get("files_skipped") or 0),
        "service_exposed": bool(attack_surface.get("exposed")),
        "service_hints": attack_surface.get("service_hints", []),
        "runtime_log_findings": int(runtime_context.get("finding_count") or 0),
        "runtime_log_events": int(runtime_context.get("event_count") or 0),
        "runtime_categories": runtime_context.get("category_counts", {}),
    }


def build_cyclonedx_sbom(
    dependencies: list[DependencyRecord],
    target_info: dict[str, Any],
    scan_id: str,
    generated_at: str,
    external_sboms: list[dict[str, Any]],
) -> dict[str, Any]:
    root_ref = f"pkg:generic/{quote(str(target_info.get('projectName') or 'workspace'), safe='')}?scan={scan_id}"
    components: list[dict[str, Any]] = []
    bom_refs: set[str] = set()
    bom_refs_by_dependency_id: dict[int, str] = {}
    for dependency in dependencies:
        bom_ref = dependency.purl or build_purl(dependency.ecosystem, dependency.name, dependency.version)
        if bom_ref in bom_refs:
            bom_ref = f"{bom_ref}#{hashlib.sha1(dependency.source_file.encode('utf-8')).hexdigest()[:8]}"
        bom_refs.add(bom_ref)
        bom_refs_by_dependency_id[id(dependency)] = bom_ref
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": dependency.name,
            "version": dependency.version,
            "purl": dependency.purl,
            "scope": cyclonedx_scope(dependency.scope),
            "licenses": [cyclonedx_license(dependency.license)],
            "properties": [
                {"name": "supplyguard:ecosystem", "value": dependency.ecosystem},
                {"name": "supplyguard:source_file", "value": dependency.source_file},
                {"name": "supplyguard:dependency_scope", "value": dependency.scope},
                {"name": "supplyguard:dependency_type", "value": dependency.dependency_type},
                {"name": "supplyguard:version_source", "value": dependency.version_source},
                {"name": "supplyguard:requested_version", "value": dependency.requested_version or ""},
                {"name": "supplyguard:risk_score", "value": str(dependency.risk)},
                {"name": "supplyguard:signals", "value": "; ".join(dependency.signals)},
                {"name": "supplyguard:reachable_import", "value": str(bool(dependency.reachability.get("imported"))).lower()},
                {"name": "supplyguard:reachable_call", "value": str(bool(dependency.reachability.get("called"))).lower()},
                {"name": "supplyguard:attack_surface", "value": str(bool(dependency.reachability.get("attack_surface"))).lower()},
                {"name": "supplyguard:runtime_trace", "value": str(bool(dependency.reachability.get("runtime_trace"))).lower()},
            ],
        }
        if dependency.vulnerabilities:
            component["properties"].append(
                {
                    "name": "supplyguard:vulnerabilities",
                    "value": "; ".join(f"{item.get('source')}:{item.get('id')}" for item in dependency.vulnerabilities),
                }
            )
        if dependency.vex:
            component["properties"].append(
                {
                    "name": "supplyguard:vex_statuses",
                    "value": "; ".join(
                        f"{item.get('id')}={item.get('status')}" for item in dependency.vex
                    ),
                }
            )
        components.append(component)

    payload: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": generated_at,
            "tools": [
                {
                    "vendor": "SupplyGuard",
                    "name": "Dependency Audit + VEX Reachability",
                    "version": "2.0",
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": str(target_info.get("projectName") or "workspace"),
            },
            "properties": [
                {"name": "supplyguard:external_sbom_count", "value": str(len(external_sboms))},
            ],
        },
        "components": components,
        "dependencies": [
            {
                "ref": root_ref,
                "dependsOn": [component["bom-ref"] for component in components],
            }
        ],
    }
    vulnerabilities = build_cyclonedx_vulnerabilities(dependencies, bom_refs_by_dependency_id)
    if vulnerabilities:
        payload["vulnerabilities"] = vulnerabilities
    return payload


def build_cyclonedx_vex(
    dependencies: list[DependencyRecord],
    target_info: dict[str, Any],
    scan_id: str,
    generated_at: str,
) -> dict[str, Any]:
    root_ref = f"pkg:generic/{quote(str(target_info.get('projectName') or 'workspace'), safe='')}?scan={scan_id}"
    bom_refs_by_dependency_id = {
        id(dependency): dependency.purl or build_purl(dependency.ecosystem, dependency.name, dependency.version)
        for dependency in dependencies
    }
    statements = [
        statement
        for dependency in dependencies
        for statement in dependency.vex
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": generated_at,
            "tools": [
                {
                    "vendor": "SupplyGuard",
                    "name": "VEX Reachability Analysis",
                    "version": "1.0",
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": str(target_info.get("projectName") or "workspace"),
            },
            "properties": [
                {"name": "supplyguard:vex_statement_count", "value": str(len(statements))},
                {"name": "supplyguard:vex_status_model", "value": "affected/not_affected/under_investigation/fixed"},
            ],
        },
        "vulnerabilities": build_cyclonedx_vulnerabilities(dependencies, bom_refs_by_dependency_id),
        "properties": [
            {"name": "supplyguard:vex_summary", "value": json.dumps(build_vex_summary(dependencies), sort_keys=True)},
        ],
    }


def build_cyclonedx_vulnerabilities(
    dependencies: list[DependencyRecord],
    bom_refs_by_dependency_id: dict[int, str],
) -> list[dict[str, Any]]:
    vulnerabilities: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for dependency in dependencies:
        component_ref = bom_refs_by_dependency_id.get(id(dependency)) or dependency.purl
        for vulnerability in dependency.vulnerabilities:
            vuln_id = str(vulnerability.get("id") or "unknown")
            key = (component_ref, vuln_id)
            if key in seen:
                continue
            seen.add(key)
            statement = vulnerability.get("vex") if isinstance(vulnerability.get("vex"), dict) else {}
            vulnerabilities.append(
                compact_dict(
                    {
                        "bom-ref": stable_id("vulnerability", component_ref, vuln_id),
                        "id": vuln_id,
                        "source": {"name": str(vulnerability.get("source") or "unknown")},
                        "ratings": [
                            {
                                "severity": cyclonedx_severity(str(vulnerability.get("severity") or "unknown")),
                                "method": "other",
                            }
                        ],
                        "description": str(vulnerability.get("summary") or vulnerability.get("details") or vuln_id),
                        "affects": [{"ref": component_ref}],
                        "analysis": vulnerability.get("analysis") or cyclonedx_analysis(statement),
                        "properties": [
                            {"name": "supplyguard:vex_status", "value": str(statement.get("status") or "")},
                            {"name": "supplyguard:vex_business_state", "value": str(statement.get("status") or "")},
                            {"name": "supplyguard:cyclonedx_analysis_state", "value": str(statement.get("cyclonedx_state") or "")},
                            {"name": "supplyguard:reachability_confidence", "value": str(statement.get("confidence") or "")},
                        ],
                    }
                )
            )
    return vulnerabilities


def cyclonedx_severity(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"critical", "high", "medium", "low", "info", "none", "unknown"}:
        return normalized
    return "unknown"


def build_dependency_report(
    target: Path,
    dependencies: list[DependencyRecord],
    findings: list[DependencyFinding],
    summary: dict[str, Any],
    warnings: list[str],
    tools: list[ToolStatus],
) -> str:
    top_rows = "\n".join(
        "| {name} | {ecosystem} | {version} | {source} | {dtype} | {license} | {vex} | {risk} | {signals} |".format(
            name=dependency.name,
            ecosystem=dependency.ecosystem,
            version=dependency.version.replace("|", "\\|"),
            source=dependency.version_source,
            dtype=dependency.dependency_type,
            license=dependency.license.replace("|", "\\|"),
            vex=markdown_cell(dependency_vex_status_text(dependency)),
            risk=dependency.risk,
            signals=", ".join(dependency.signals).replace("|", "\\|") or "-",
        )
        for dependency in dependencies[:50]
    )
    finding_rows = "\n".join(
        "| {id} | {severity} | {score} | {dependency} | {evidence} |".format(
            id=finding.id,
            severity=finding.severity,
            score=finding.score,
            dependency=finding.dependency,
            evidence=finding.evidence.replace("|", "\\|"),
        )
        for finding in findings[:50]
    )
    tool_rows = "\n".join(
        f"| {tool.name} | {tool.state} | {tool.available} | {markdown_cell(tool.error or '-')} |"
        for tool in tools
    )
    vex_rows = "\n".join(render_vex_report_row(dependency, statement) for dependency in dependencies for statement in dependency.vex)
    warning_rows = "\n".join(f"- {warning}" for warning in warnings)
    vex_summary = summary.get("vex") if isinstance(summary.get("vex"), dict) else {}
    reachability_summary = summary.get("reachability") if isinstance(summary.get("reachability"), dict) else {}

    return f"""# Supply Chain Dependency Audit Report

Generated at: {datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")}
Scan target: {target}

## Summary

- Dependencies: {summary['total_dependencies']}
- Exact versions: {summary['exact_versions']}
- Transitive dependencies: {summary['transitive_dependencies']}
- Manifest files: {summary['manifest_count']}
- Lockfiles: {summary['lockfile_count']}
- Overall risk score: {summary['risk_score']} / 100
- Vulnerable dependencies: {summary['vulnerable_dependencies']}
- OSV matches: {summary['osv_matches']}
- Suspicious package names: {summary['suspicious_names']}
- Unknown licenses: {summary['unknown_licenses']}
- VEX statements: {vex_summary.get('statement_count', 0)}
- VEX affected: {vex_summary.get('affected', 0)}
- VEX not affected / fixed: {int(vex_summary.get('not_affected', 0)) + int(vex_summary.get('fixed', 0))}
- Reachable imports: {reachability_summary.get('imported_dependencies', 0)}
- Runtime exploit traces: {reachability_summary.get('runtime_trace_dependencies', 0)}

## Scanner Tools

| Tool | State | Available | Detail |
| --- | --- | --- | --- |
{tool_rows or '| - | - | - | - |'}

## VEX and Reachability

| Vulnerability | Dependency | VEX Status | CycloneDX State | Code | Attack Surface | Logs | Detail |
| --- | --- | --- | --- | --- | --- | --- | --- |
{vex_rows or '| - | - | - | - | - | - | - | No VEX statements generated |'}

## High Risk Findings

| ID | Severity | Score | Dependency | Evidence |
| --- | --- | ---: | --- | --- |
{finding_rows or '| - | - | - | - | No high risk dependencies found |'}

## Dependency Risk Table

| Dependency | Ecosystem | Version | Source | Type | License | VEX | Risk | Signals |
| --- | --- | --- | --- | --- | --- | --- | ---: | --- |
{top_rows or '| - | - | - | - | - | - | - | - | - |'}

## Warnings

{warning_rows or '- Scan completed.'}
"""


def render_vex_report_row(dependency: DependencyRecord, statement: dict[str, Any]) -> str:
    reachability = statement.get("reachability") if isinstance(statement.get("reachability"), dict) else {}
    return "| {vuln} | {dependency} | {status} | {state} | {code} | {surface} | {logs} | {detail} |".format(
        vuln=markdown_cell(statement.get("id") or "-"),
        dependency=markdown_cell(f"{dependency.ecosystem}:{dependency.name}@{dependency.version}"),
        status=markdown_cell(statement.get("status") or "-"),
        state=markdown_cell(statement.get("cyclonedx_state") or "-"),
        code="called" if reachability.get("called") else "imported" if reachability.get("imported") else "not reachable",
        surface="exposed" if reachability.get("attack_surface") else "not exposed",
        logs="matched" if reachability.get("runtime_trace") else "none",
        detail=markdown_cell(shorten_report_text(statement.get("detail") or "-", 160)),
    )


def dependency_vex_status_text(dependency: DependencyRecord) -> str:
    if not dependency.vex:
        return "-"
    statuses = [str(item.get("status") or "") for item in dependency.vex if item.get("status")]
    return ", ".join(sorted(set(statuses))) or "-"


def shorten_report_text(value: Any, limit: int) -> str:
    text = str(value or "").replace("\n", " ").strip()
    if len(text) <= limit:
        return text
    return f"{text[: max(20, limit - 3)]}..."


def serialize_dependency_audit(result: DependencyAuditResult | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "scan_id": result.scan_id,
        "generated_at": result.generated_at,
        "target_path": result.target_path,
        "target": result.target,
        "summary": result.summary,
        "dependencies": [serialize_dependency(dependency) for dependency in result.dependencies],
        "findings": [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "score": finding.score,
                "dependency": finding.dependency,
                "ecosystem": finding.ecosystem,
                "source_file": finding.source_file,
                "evidence": finding.evidence,
                "recommendation": finding.recommendation,
                "fingerprint": finding.fingerprint,
            }
            for finding in result.findings
        ],
        "sbom": result.sbom,
        "vex": result.vex,
        "report": result.report,
        "warnings": result.warnings,
        "tools": [serialize_tool_status(status) for status in result.tools],
    }


def serialize_dependency(dependency: DependencyRecord) -> dict[str, Any]:
    return {
        "name": dependency.name,
        "version": dependency.version,
        "ecosystem": dependency.ecosystem,
        "scope": dependency.scope,
        "source_file": dependency.source_file,
        "manifest_type": dependency.manifest_type,
        "license": dependency.license,
        "purl": dependency.purl,
        "risk": dependency.risk,
        "signals": dependency.signals,
        "vulnerabilities": dependency.vulnerabilities,
        "reachability": dependency.reachability,
        "vex": dependency.vex,
        "recommendation": dependency.recommendation,
        "requested_version": dependency.requested_version,
        "version_source": dependency.version_source,
        "dependency_type": dependency.dependency_type,
        "resolved": dependency.resolved,
    }


def serialize_tool_status(status: ToolStatus) -> dict[str, Any]:
    return {
        "name": status.name,
        "available": status.available,
        "command": status.command,
        "version": status.version,
        "state": status.state,
        "error": status.error,
    }


def dedupe_tool_statuses(statuses: list[ToolStatus]) -> list[ToolStatus]:
    result: dict[tuple[str, str], ToolStatus] = {}
    state_rank = {"ok": 0, "partial": 1, "failed": 2, "missing": 3}
    for status in statuses:
        key = (status.name, status.command)
        existing = result.get(key)
        if existing is None or state_rank.get(status.state, 9) < state_rank.get(existing.state, 9):
            result[key] = status
    return list(result.values())


def empty_dependency_audit_payload() -> dict[str, Any]:
    return {
        "scan_id": None,
        "summary": {
            "total_dependencies": 0,
            "manifest_count": 0,
            "lockfile_count": 0,
            "finding_count": 0,
            "risk_score": 0,
            "risk_level": "low",
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "ecosystems": {},
            "version_sources": {},
            "unknown_licenses": 0,
            "vulnerable_dependencies": 0,
            "osv_matches": 0,
            "suspicious_names": 0,
            "exact_versions": 0,
            "transitive_dependencies": 0,
            "vex": {
                "statement_count": 0,
                "component_count": 0,
                "affected": 0,
                "not_affected": 0,
                "under_investigation": 0,
                "fixed": 0,
                "actionable": 0,
                "noise_reduced": 0,
                "false_positive_reduction_percent": 0,
                "states": {"affected": 0, "not_affected": 0, "under_investigation": 0, "fixed": 0},
            },
            "reachability": {
                "imported_dependencies": 0,
                "called_dependencies": 0,
                "attack_surface_dependencies": 0,
                "runtime_trace_dependencies": 0,
                "source_files_scanned": 0,
                "source_files_skipped": 0,
                "service_exposed": False,
                "service_hints": [],
                "runtime_log_findings": 0,
                "runtime_log_events": 0,
                "runtime_categories": {},
            },
            "tools": [],
        },
        "dependencies": [],
        "findings": [],
        "sbom": build_cyclonedx_sbom([], {"projectName": "workspace"}, "empty", datetime.now(UTC).isoformat(), []),
        "vex": build_cyclonedx_vex([], {"projectName": "workspace"}, "empty", datetime.now(UTC).isoformat()),
        "report": "# Supply Chain Dependency Audit Report\n\nNo dependency scan has run yet.\n",
        "warnings": [],
        "tools": [],
    }


def canonical_dependency_name(ecosystem: str, name: str) -> str:
    normalized = normalize_ecosystem(ecosystem)
    if normalized == "pypi":
        return canonical_pypi_name(name)
    return name.strip().lower()


def canonical_pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def normalize_ecosystem(ecosystem: str) -> str:
    value = ecosystem.strip().lower()
    if value in {"pypi", "python"}:
        return "pypi"
    if value in {"npm", "javascript", "node"}:
        return "npm"
    return value


def build_purl(ecosystem: str, name: str, version_spec: str) -> str:
    normalized = normalize_ecosystem(ecosystem)
    version = exact_version(version_spec)
    if normalized == "npm":
        if name.startswith("@") and "/" in name:
            scope, package = name.split("/", 1)
            path = f"{quote(scope, safe='')}/{quote(package, safe='')}"
        else:
            path = quote(name.lower(), safe="")
        return f"pkg:npm/{path}{('@' + quote(version, safe='')) if version else ''}"
    if normalized == "pypi":
        path = quote(canonical_pypi_name(name), safe="")
        return f"pkg:pypi/{path}{('@' + quote(version, safe='')) if version else ''}"
    return f"pkg:generic/{quote(name, safe='')}{('@' + quote(version, safe='')) if version else ''}"


def known_license(dependency: DependencyRecord) -> str | None:
    return known_license_by_name(dependency.ecosystem, dependency.name)


def known_license_by_name(ecosystem: str, name: str) -> str | None:
    normalized = normalize_ecosystem(ecosystem)
    canonical = canonical_dependency_name(normalized, name)
    return KNOWN_LICENSES.get(normalized, {}).get(canonical)


def parse_license_value(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        license_type = value.get("type") or value.get("name") or value.get("id")
        if isinstance(license_type, str) and license_type.strip():
            return license_type.strip()
    if isinstance(value, list):
        licenses = [parse_license_value(item) for item in value]
        licenses = [item for item in licenses if item]
        if licenses:
            return " OR ".join(licenses)
    return None


def license_has_copyleft_hint(license_value: str) -> bool:
    upper = license_value.upper()
    return any(hint in upper for hint in COPYLEFT_LICENSE_HINTS)


def is_unpinned_version(dependency: DependencyRecord) -> bool:
    if dependency.resolved:
        return False
    value = dependency.version.strip().lower()
    if value in {"", "*", "latest"}:
        return True
    if dependency.ecosystem == "npm":
        return value.startswith(("^", "~", ">", ">=", "<", "<=")) or "||" in value or "x" in value
    if dependency.ecosystem == "pypi":
        if value == "url/vcs":
            return False
        return not value.startswith("==") and not bool(exact_version(value))
    return False


def is_url_or_vcs_source(version: str) -> bool:
    value = version.strip().lower()
    return value == "url/vcs" or value.startswith(("git+", "http://", "https://", "file:", "github:"))


def looks_internal_npm_name(name: str) -> bool:
    lower = name.lower()
    if lower.startswith(("@acme/", "@company/", "@corp/", "@internal/")):
        return True
    return any(part in lower for part in ("internal-", "private-", "corp-"))


def npm_scope(name: str) -> str | None:
    if name.startswith("@") and "/" in name:
        return name.split("/", 1)[0]
    return None


def risk_severity(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 55:
        return "medium"
    return "low"


def cyclonedx_scope(scope: str) -> str:
    if scope in {"optional", "development"}:
        return "optional"
    return "required"


def cyclonedx_license(license_value: str) -> dict[str, Any]:
    if re.fullmatch(r"[A-Za-z0-9-.+]+", license_value) and license_value != "UNKNOWN":
        return {"license": {"id": license_value}}
    return {"license": {"name": license_value or "UNKNOWN"}}


def dependency_fingerprint(dependency: DependencyRecord) -> str:
    raw = "|".join(
        [
            dependency.ecosystem,
            canonical_dependency_name(dependency.ecosystem, dependency.name),
            dependency.version,
            dependency.version_source,
            dependency.source_file,
            ",".join(dependency.signals),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def relative_posix(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def strip_requirement_comment(line: str) -> str:
    for index, char in enumerate(line):
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def requirement_name_from_url(value: str) -> str | None:
    lower = value.lower()
    is_url = lower.startswith(("http://", "https://", "git+", "hg+", "svn+", "bzr+"))
    if not is_url:
        return None
    parsed = urlparse(value)
    fragment = parse_qs(parsed.fragment)
    egg = fragment.get("egg", [None])[0]
    if egg:
        return canonical_pypi_name(egg.split("[", 1)[0])
    name_match = re.search(r"/([A-Za-z0-9_.-]+?)(?:\.git|\.zip|\.tar\.gz|\.whl)?(?:$|[?#])", value)
    if name_match:
        return canonical_pypi_name(name_match.group(1))
    return "direct-url-package"


def npm_dependency_metadata(project_dir: Path, name: str) -> dict[str, Any]:
    package_path = npm_package_json_path(project_dir, name)
    if package_path is None or not package_path.exists():
        return {}
    try:
        data = json.loads(package_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    install_scripts = [
        script_name
        for script_name in INSTALL_SCRIPT_NAMES
        if isinstance(scripts, dict) and isinstance(scripts.get(script_name), str)
    ]
    return {
        "license": parse_license_value(data.get("license") or data.get("licenses")),
        "install_scripts": install_scripts,
    }


def npm_package_json_path(project_dir: Path, name: str) -> Path | None:
    node_modules = project_dir / "node_modules"
    if name.startswith("@") and "/" in name:
        scope, package = name.split("/", 1)
        return node_modules / scope / package / "package.json"
    if "/" in name:
        return None
    return node_modules / name / "package.json"


def safe_filename(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    return clean or "root"


def write_temp_sbom(scan_id: str, sbom: dict[str, Any]) -> Path:
    path = STORAGE_SBOM_DIR / f"merged-source-{scan_id}-{uuid.uuid4().hex[:8]}.cdx.json"
    path.write_text(json.dumps(sbom, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def unique_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    for path in paths:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


def markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|")


def compact_dict(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def stable_id(*parts: Any) -> str:
    raw = "|".join(str(part or "") for part in parts)
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    prefix = str(parts[0] or "id").lower().replace("_", "-")
    return f"{prefix}:{digest}"
