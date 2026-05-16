"""Document generation helpers for the SysML course design prototype."""

from __future__ import annotations

import copy
import base64
import hashlib
import html
import io
import json
import re
import shutil
import subprocess
import tempfile
import unicodedata
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_FONT,
    DEFAULT_THEME,
    DOCX_REFERENCE,
    FONT_PRESETS,
    OUTPUT_DIR,
    PANDOC_PATH,
    PDF_ENGINE,
    QUARTO_PATH,
    SYSTEM_CJK_FONTS,
    THEME_PRESETS,
)
from .metamodel import TYPE_LABELS, validate_repository


# ── Optional PDF deps ──────────────────────────────────────────────
try:
    from fpdf import FPDF  # type: ignore[import-untyped]

    _FPDF_AVAILABLE = True
except ImportError:
    FPDF = None  # type: ignore[assignment]
    _FPDF_AVAILABLE = False

try:
    from reportlab.pdfbase import pdfmetrics  # type: ignore[import-untyped]
    from reportlab.pdfbase.ttfonts import TTFont  # type: ignore[import-untyped]
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer  # type: ignore[import-untyped]
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # type: ignore[import-untyped]
    from reportlab.lib.pagesizes import A4  # type: ignore[import-untyped]
    from reportlab.lib.units import mm  # type: ignore[import-untyped]

    _REPORTLAB_AVAILABLE = True
except ImportError:
    pdfmetrics = None  # type: ignore[assignment]
    TTFont = None  # type: ignore[assignment]
    SimpleDocTemplate = None  # type: ignore[assignment]
    _REPORTLAB_AVAILABLE = False


Element = dict[str, Any]

TOKEN_RE = re.compile(r"\{\{\s*([a-zA-Z]+):([^}]+)\s*\}\}")

PANDOC_AVAILABLE = bool(PANDOC_PATH or QUARTO_PATH)


def pandoc_available() -> bool:
    return PANDOC_AVAILABLE


def quarto_available() -> bool:
    return bool(QUARTO_PATH)


def pandoc_command() -> list[str] | None:
    if PANDOC_PATH:
        return [PANDOC_PATH]
    if QUARTO_PATH:
        return [QUARTO_PATH, "pandoc"]
    return None


def _run_pandoc(args: list[str], input_text: str, timeout: int = 30) -> bytes | None:
    command = pandoc_command()
    if not command:
        return None
    try:
        result = subprocess.run(
            [*command, *args],
            input=input_text.encode("utf-8"),
            capture_output=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _run_quarto_render(
    markdown: str,
    output_format: str,
    timeout: int = 60,
) -> bytes | None:
    if not QUARTO_PATH:
        return None

    with tempfile.TemporaryDirectory() as tmp_dir:
        input_path = Path(tmp_dir) / "document.qmd"
        output_name = f"document.{output_format}"
        output_path = Path(tmp_dir) / output_name
        input_path.write_text(markdown, encoding="utf-8")

        try:
            result = subprocess.run(
                [
                    QUARTO_PATH,
                    "render",
                    str(input_path),
                    "--to",
                    output_format,
                    "--output",
                    output_name,
                    "--quiet",
                ],
                cwd=tmp_dir,
                capture_output=True,
                timeout=timeout,
            )
            if result.returncode == 0 and output_path.exists():
                return output_path.read_bytes()
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def cjk_mainfont() -> str:
    for font_name in (
        "Microsoft YaHei",
        "SimSun",
        "SimHei",
        "Noto Sans CJK SC",
        "Noto Serif CJK SC",
    ):
        if font_name in SYSTEM_CJK_FONTS:
            return font_name
    return next(iter(SYSTEM_CJK_FONTS), "Microsoft YaHei")


def qmd_document(markdown: str, title: str = "SysML 文档") -> str:
    return f"""---
title: "{_yaml_escape(title)}"
lang: zh-CN
format:
  html:
    embed-resources: true
    toc: true
  docx:
    toc: true
  pdf:
    documentclass: ctexart
    papersize: a4
    toc: true
    pdf-engine: lualatex
    mainfont: "{_yaml_escape(cjk_mainfont())}"
    CJKmainfont: "{_yaml_escape(cjk_mainfont())}"
---

{markdown}
"""


def _yaml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def markdown_to_html_pandoc(markdown: str) -> str | None:
    """Convert Markdown to HTML5 fragment using Pandoc with syntax highlighting and smart typography."""
    html_bytes = _run_pandoc(
        [
            "-f", "markdown+smart",
            "-t", "html5",
            "--highlight-style=tango",
            "--mathjax",
        ],
        markdown,
    )
    if html_bytes is None:
        return None
    return html_bytes.decode("utf-8")


def html_to_pdf_pandoc(html_content: str) -> bytes | None:
    """Convert HTML to PDF via Pandoc with a browser/HTML engine."""
    command = pandoc_command()
    if not command:
        return None

    engine = None
    if shutil.which("weasyprint"):
        engine = "weasyprint"
    elif shutil.which("wkhtmltopdf"):
        engine = "wkhtmltopdf"
    elif shutil.which("pdflatex"):
        engine = "pdflatex"
    else:
        return None

    args = ["-f", "html", "-t", "pdf", f"--pdf-engine={engine}"]
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
        tmp.write(html_content.encode("utf-8"))
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            [*command, *args, tmp_path],
            capture_output=True,
            timeout=60,
        )
        if result.returncode == 0:
            return result.stdout
    except (OSError, subprocess.SubprocessError):
        pass
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    return None


def markdown_to_pdf_pandoc(markdown: str, title: str = "SysML 文档") -> bytes | None:
    """Render Markdown to PDF through Pandoc/Quarto with Unicode-friendly defaults."""
    if QUARTO_PATH:
        pdf_bytes = _run_quarto_render(qmd_document(markdown, title), "pdf", timeout=90)
        if pdf_bytes:
            return pdf_bytes

    command = pandoc_command()
    if not command:
        return None

    if shutil.which("lualatex"):
        engine = "lualatex"
    elif shutil.which("xelatex"):
        engine = "xelatex"
    elif shutil.which("tectonic"):
        engine = "tectonic"
    elif shutil.which("weasyprint"):
        engine = "weasyprint"
    elif shutil.which("wkhtmltopdf"):
        engine = "wkhtmltopdf"
    else:
        return None

    args = [
        "-f",
        "markdown+smart",
        "-t",
        "pdf",
        f"--pdf-engine={engine}",
        "-V",
        "documentclass=ctexart",
        "-V",
        f"mainfont={cjk_mainfont()}",
        "-V",
        f"CJKmainfont={cjk_mainfont()}",
    ]
    return _run_pandoc(args, markdown, timeout=90)


def markdown_to_docx_pandoc(markdown: str, ref_doc: str | None = None) -> bytes | None:
    """Convert Markdown to DOCX using Pandoc, optionally with a reference document for styling."""
    if QUARTO_PATH:
        docx_bytes = _run_quarto_render(qmd_document(markdown), "docx", timeout=60)
        if docx_bytes:
            return docx_bytes

    args = ["-f", "markdown+smart", "-t", "docx"]
    if ref_doc or DOCX_REFERENCE:
        ref = (ref_doc or DOCX_REFERENCE).strip()
        if ref:
            args.extend(["--reference-doc", ref])
    return _run_pandoc(args, markdown, timeout=30)


def markdown_to_docx_builtin(markdown: str) -> bytes:
    """Generate a simple DOCX without Pandoc/Quarto."""
    body_parts: list[str] = []
    in_table = False
    table_rows: list[list[str]] = []

    def flush_table() -> None:
        nonlocal table_rows, in_table
        if table_rows:
            body_parts.append(_docx_table(table_rows))
        table_rows = []
        in_table = False

    for raw_line in markdown.splitlines():
        line = raw_line.strip()
        if not line:
            flush_table()
            body_parts.append("<w:p/>")
            continue

        if line.startswith("|") and line.endswith("|"):
            cells = split_table_row(line)
            if set(line.replace("|", "").replace(":", "").replace(" ", "")) == {"-"}:
                continue
            table_rows.append(cells)
            in_table = True
            continue

        flush_table()
        if line.startswith("# "):
            body_parts.append(_docx_paragraph(line[2:].strip(), "Heading1"))
        elif line.startswith("## "):
            body_parts.append(_docx_paragraph(line[3:].strip(), "Heading2"))
        elif line.startswith("### "):
            body_parts.append(_docx_paragraph(line[4:].strip(), "Heading3"))
        elif line.startswith("- "):
            body_parts.append(_docx_paragraph(f"• {line[2:].strip()}"))
        else:
            body_parts.append(_docx_paragraph(line.lstrip("#").strip()))

    flush_table()
    return _docx_package("\n".join(body_parts))


def _docx_package(document_body: str) -> bytes:
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"""
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""
    document_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    {document_body}
    <w:sectPr>
      <w:pgSz w:w="11906" w:h="16838"/>
      <w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/>
    </w:sectPr>
  </w:body>
</w:document>"""
    styles_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal">
    <w:name w:val="Normal"/>
    <w:rPr><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI" w:eastAsia="Microsoft YaHei"/><w:sz w:val="21"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading1">
    <w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>
    <w:pPr><w:spacing w:before="240" w:after="160"/></w:pPr>
    <w:rPr><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI" w:eastAsia="Microsoft YaHei"/><w:b/><w:sz w:val="32"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading2">
    <w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>
    <w:pPr><w:spacing w:before="200" w:after="120"/></w:pPr>
    <w:rPr><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI" w:eastAsia="Microsoft YaHei"/><w:b/><w:color w:val="0F766E"/><w:sz w:val="26"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading3">
    <w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/>
    <w:rPr><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI" w:eastAsia="Microsoft YaHei"/><w:b/><w:sz w:val="23"/></w:rPr>
  </w:style>
</w:styles>"""

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as docx:
        docx.writestr("[Content_Types].xml", content_types)
        docx.writestr("_rels/.rels", rels)
        docx.writestr("word/document.xml", document_xml)
        docx.writestr("word/styles.xml", styles_xml)
    return buffer.getvalue()


def _docx_paragraph(text: str, style: str | None = None) -> str:
    style_xml = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    return f"<w:p>{style_xml}<w:r><w:rPr>{_docx_run_fonts()}</w:rPr><w:t xml:space=\"preserve\">{html.escape(text)}</w:t></w:r></w:p>"


def _docx_table(rows: list[list[str]]) -> str:
    row_xml = []
    for row in rows:
        cells = "".join(
            f"<w:tc><w:tcPr><w:tcW w:w=\"2400\" w:type=\"dxa\"/></w:tcPr>{_docx_paragraph(cell)}</w:tc>"
            for cell in row
        )
        row_xml.append(f"<w:tr>{cells}</w:tr>")
    borders = """
      <w:tblBorders>
        <w:top w:val="single" w:sz="4" w:space="0" w:color="D8DEE8"/>
        <w:left w:val="single" w:sz="4" w:space="0" w:color="D8DEE8"/>
        <w:bottom w:val="single" w:sz="4" w:space="0" w:color="D8DEE8"/>
        <w:right w:val="single" w:sz="4" w:space="0" w:color="D8DEE8"/>
        <w:insideH w:val="single" w:sz="4" w:space="0" w:color="D8DEE8"/>
        <w:insideV w:val="single" w:sz="4" w:space="0" w:color="D8DEE8"/>
      </w:tblBorders>"""
    return f"<w:tbl><w:tblPr><w:tblW w:w=\"0\" w:type=\"auto\"/>{borders}</w:tblPr>{''.join(row_xml)}</w:tbl>"


def _docx_run_fonts() -> str:
    return '<w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI" w:eastAsia="Microsoft YaHei"/><w:sz w:val="21"/>'


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def elements_by_type(elements: dict[str, Element], element_type: str) -> list[Element]:
    return sorted(
        [copy.deepcopy(item) for item in elements.values() if item.get("type") == element_type],
        key=lambda item: item.get("id", ""),
    )


def get_path(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part, "")
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return ""
        else:
            return ""
    return current


def resolve_element_token(elements: dict[str, Element], expression: str) -> str:
    if "." not in expression:
        element = elements.get(expression.strip())
        return str(element.get("name", "")) if element else ""

    element_id, path = expression.split(".", 1)
    element = elements.get(element_id.strip())
    if not element:
        return ""
    value = get_path(element, path.strip())
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def render_template(template: str, elements: dict[str, Element]) -> str:
    """Render a compact DocGen-like template into Markdown."""

    def replace(match: re.Match[str]) -> str:
        token_type = match.group(1).lower()
        expression = match.group(2).strip()
        if token_type == "element":
            return resolve_element_token(elements, expression)
        if token_type == "table":
            return render_markdown_table(elements, expression)
        if token_type == "trace":
            return render_traceability_markdown(elements)
        if token_type == "model":
            return render_model_summary_markdown(elements)
        if token_type == "validation":
            return render_validation_markdown(elements)
        return match.group(0)

    return TOKEN_RE.sub(replace, template)


def render_model_summary_markdown(elements: dict[str, Element]) -> str:
    counts: dict[str, int] = {}
    for element in elements.values():
        counts[element.get("type", "Unknown")] = counts.get(element.get("type", "Unknown"), 0) + 1
    rows = [
        f"当前模型共包含 {len(elements)} 个 SysML 元素。以下统计来自 MMS 模型仓库，可随模型更新自动刷新。",
        "",
        "| 类型 | 数量 |",
        "| --- | ---: |",
    ]
    for key in sorted(counts):
        rows.append(f"| {TYPE_LABELS.get(key, key)} | {counts[key]} |")
    return "\n".join(rows)


def render_markdown_table(elements: dict[str, Element], table_name: str) -> str:
    name = table_name.lower()
    if name in {"requirements", "requirement", "req"}:
        return render_requirements_table(elements)
    if name in {"blocks", "block", "structure"}:
        return render_blocks_table(elements)
    if name in {"tests", "testcases", "verification"}:
        return render_tests_table(elements)
    if name in {"interfaces", "ports", "interface"}:
        return render_interfaces_table(elements)
    if name in {"constraints", "constraint"}:
        return render_constraints_table(elements)
    if name in {"states", "state"}:
        return render_states_table(elements)
    return ""


def render_requirements_table(elements: dict[str, Element]) -> str:
    rows = ["| ID | 名称 | 需求文本 | 验证方式 |", "| --- | --- | --- | --- |"]
    for item in elements_by_type(elements, "Requirement"):
        rows.append(
            "| {id} | {name} | {text} | {verification} |".format(
                id=item.get("id", ""),
                name=item.get("name", ""),
                text=item.get("attributes", {}).get("text", item.get("description", "")),
                verification=item.get("attributes", {}).get("verification", ""),
            )
        )
    return "\n".join(rows)


def render_blocks_table(elements: dict[str, Element]) -> str:
    rows = ["| ID | 名称 | 责任域 | 描述 |", "| --- | --- | --- | --- |"]
    for item in elements_by_type(elements, "Block"):
        rows.append(
            f"| {item.get('id', '')} | {item.get('name', '')} | "
            f"{item.get('owner', '')} | {item.get('description', '')} |"
        )
    return "\n".join(rows)


def render_tests_table(elements: dict[str, Element]) -> str:
    rows = ["| ID | 名称 | 方法 | 判据 |", "| --- | --- | --- | --- |"]
    for item in elements_by_type(elements, "TestCase"):
        rows.append(
            f"| {item.get('id', '')} | {item.get('name', '')} | "
            f"{item.get('attributes', {}).get('method', '')} | "
            f"{item.get('attributes', {}).get('criterion', item.get('description', ''))} |"
        )
    return "\n".join(rows)


def render_interfaces_table(elements: dict[str, Element]) -> str:
    rows = ["| ID | 类型 | 名称 | 方向/协议 | 描述 |", "| --- | --- | --- | --- | --- |"]
    for item in elements_by_type(elements, "Interface") + elements_by_type(elements, "Port"):
        attrs = item.get("attributes", {})
        protocol = attrs.get("protocol") or attrs.get("direction") or attrs.get("interface", "")
        rows.append(
            f"| {item.get('id', '')} | {TYPE_LABELS.get(item.get('type', ''), item.get('type', ''))} | "
            f"{item.get('name', '')} | {protocol} | {item.get('description', '')} |"
        )
    return "\n".join(rows)


def render_constraints_table(elements: dict[str, Element]) -> str:
    rows = ["| ID | 名称 | 表达式 | 描述 |", "| --- | --- | --- | --- |"]
    for item in elements_by_type(elements, "Constraint"):
        rows.append(
            f"| {item.get('id', '')} | {item.get('name', '')} | "
            f"{item.get('attributes', {}).get('expression', '')} | {item.get('description', '')} |"
        )
    return "\n".join(rows)


def render_states_table(elements: dict[str, Element]) -> str:
    rows = ["| ID | 状态 | 描述 |", "| --- | --- | --- |"]
    for item in elements_by_type(elements, "State"):
        rows.append(f"| {item.get('id', '')} | {item.get('name', '')} | {item.get('description', '')} |")
    return "\n".join(rows)


def build_traceability(elements: dict[str, Element]) -> list[dict[str, Any]]:
    requirements = elements_by_type(elements, "Requirement")
    rows: list[dict[str, Any]] = []
    for requirement in requirements:
        requirement_id = str(requirement.get("id", ""))
        satisfy_ids = trace_ids_for_requirement(elements, requirement, "satisfy")
        verify_ids = trace_ids_for_requirement(elements, requirement, "verify")
        refine_ids = trace_ids_for_requirement(elements, requirement, "refine")
        constrain_ids = trace_ids_for_requirement(elements, requirement, "constrain")
        satisfied_refs = refs_from_ids(elements, satisfy_ids, exclude_id=requirement_id)
        verified_refs = refs_from_ids(elements, verify_ids, exclude_id=requirement_id)
        refined_refs = refs_from_ids(elements, refine_ids, exclude_id=requirement_id)
        constrained_refs = refs_from_ids(elements, constrain_ids, exclude_id=requirement_id)
        rows.append(
            {
                "requirement": compact_ref(requirement),
                "satisfied_by": satisfied_refs,
                "verified_by": verified_refs,
                "refined_by": refined_refs,
                "constrained_by": constrained_refs,
                "status": trace_status(satisfied_refs, verified_refs),
            }
        )
    return rows


def trace_ids_for_requirement(elements: dict[str, Element], requirement: Element, relation_type: str) -> list[str]:
    requirement_id = str(requirement.get("id", ""))
    return unique_ids(
        [
            *related_targets(requirement, relation_type),
            *incoming_sources(elements, requirement_id, relation_type),
        ]
    )


def related_targets(element: Element, relation_type: str) -> list[str]:
    return [
        relation.get("target", "")
        for relation in element.get("relations", [])
        if relation.get("type") == relation_type and relation.get("target")
    ]


def incoming_sources(elements: dict[str, Element], target_id: str, relation_type: str) -> list[str]:
    sources = []
    for element_id, element in elements.items():
        for relation in element.get("relations", []):
            if relation.get("type") == relation_type and relation.get("target") == target_id:
                sources.append(element_id)
    return sources


def unique_ids(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def refs_from_ids(elements: dict[str, Element], element_ids: list[str], exclude_id: str = "") -> list[dict[str, str]]:
    return [
        compact_ref(elements[element_id])
        for element_id in element_ids
        if element_id in elements and element_id != exclude_id
    ]


def compact_ref(element: Element) -> dict[str, str]:
    return {
        "id": str(element.get("id", "")),
        "name": str(element.get("name", "")),
        "type": str(element.get("type", "")),
    }


def trace_status(satisfied_refs: list[dict[str, str]], verified_refs: list[dict[str, str]]) -> str:
    if satisfied_refs and verified_refs:
        return "closed"
    if satisfied_refs or verified_refs:
        return "partial"
    return "open"


def render_traceability_markdown(elements: dict[str, Element]) -> str:
    rows = ["| 需求 | 满足元素 | 验证元素 | 细化元素 | 约束 | 状态 |", "| --- | --- | --- | --- | --- | --- |"]
    for row in build_traceability(elements):
        req = row["requirement"]
        satisfied = ", ".join(f"{item['id']} {item['name']}" for item in row["satisfied_by"]) or "-"
        verified = ", ".join(f"{item['id']} {item['name']}" for item in row["verified_by"]) or "-"
        refined = ", ".join(f"{item['id']} {item['name']}" for item in row["refined_by"]) or "-"
        constrained = ", ".join(f"{item['id']} {item['name']}" for item in row["constrained_by"]) or "-"
        rows.append(
            f"| {req['id']} {req['name']} | {satisfied} | {verified} | {refined} | {constrained} | {row['status']} |"
        )
    return "\n".join(rows)


def render_validation_markdown(elements: dict[str, Element]) -> str:
    validation = validate_repository(elements)
    rows = ["| 严重级别 | 元素 | 问题 |", "| --- | --- | --- |"]
    for item in validation["issues"][:50]:
        rows.append(f"| {item['severity']} | {item['element_id']} | {item['message']} |")
    if len(rows) == 2:
        rows.append("| info | - | 未发现语义校验问题 |")
    return "\n".join(rows)


def default_document_template(project: dict[str, Any], branch_name: str) -> str:
    return f"""# {project.get("name", "SysML 模型文档")}

## 1. 文档说明

本文档由 SysML 模型数据自动生成，来源分支为 `{branch_name}`。文档中的需求、结构、接口、约束、验证用例和追踪关系均来自 MMS 模型仓库。

系统采用“一次编辑，处处使用”的模型驱动流程：工程师在 VE 或外部建模工具中维护模型，MDK 将模型同步到 MMS，DocGen 再按视图与模板生成工程文档。因此，文档不再是孤立副本，而是模型在指定提交上的可追溯视图。

## 2. 模型概览

{{{{model:summary}}}}

## 3. 需求基线

需求基线用于记录系统应满足的能力、约束和验证方式。下表直接从 Requirement 元素生成。

{{{{table:requirements}}}}

## 4. 系统结构

系统结构用于描述满足需求的 Block 及其责任域。

{{{{table:blocks}}}}

## 5. 接口与端口

接口与端口用于连接不同结构元素和外部系统，是跨专业协作时保持一致性的关键数据。

{{{{table:interfaces}}}}

## 6. 约束与验证

约束与验证用例共同支撑需求闭环，DocGen 会自动汇总约束表达式和测试判据。

{{{{table:constraints}}}}

{{{{table:tests}}}}

## 7. 追踪矩阵

追踪矩阵用于检查需求是否已被设计元素满足、是否已有验证用例覆盖，以及是否存在进一步细化或工程约束。

{{{{trace:matrix}}}}

## 8. SysML 语义校验

语义校验用于发现缺失属性、非法关系、目标元素不存在或关系目标类型不匹配等问题。

{{{{validation:issues}}}}
"""


def markdown_to_html(markdown: str) -> str:
    if PANDOC_AVAILABLE:
        pandoc_html = markdown_to_html_pandoc(markdown)
        if pandoc_html:
            return pandoc_html
    return _markdown_to_html_builtin(markdown)


def _inline_markdown_to_html(text: str) -> str:
    """Convert inline markdown: **bold**, *italic*, `code`, [link](url)."""
    result = html.escape(text)
    result = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", result)
    result = re.sub(r"(?<!\*)\*([^*\n]+?)\*(?!\*)", r"<em>\1</em>", result)
    result = re.sub(r"`([^`]+)`", r"<code>\1</code>", result)
    result = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', result)
    return result


def _markdown_to_html_builtin(markdown: str) -> str:
    """Stateful markdown-to-HTML converter: headings, lists, code blocks, blockquotes, tables, paragraphs."""
    lines = markdown.splitlines()
    parts: list[str] = []
    buf: list[str] = []
    in_code_block = False
    code_lang = ""

    def flush_paragraph() -> None:
        nonlocal buf
        if not buf:
            return
        text = " ".join(buf).strip()
        buf = []
        if not text:
            return
        if text.startswith("|") and text.endswith("|"):
            parts.append(markdown_table_to_html([text]))
        else:
            parts.append(f"<p>{_inline_markdown_to_html(text)}</p>")

    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()

        # fenced code block toggle
        if line.startswith("```"):
            if in_code_block:
                parts.append("</code></pre>")
                in_code_block = False
                i += 1
                continue
            flush_paragraph()
            in_code_block = True
            code_lang = line[3:].strip()
            lang_attr = f' class="language-{html.escape(code_lang)}"' if code_lang else ""
            parts.append(f"<pre><code{lang_attr}>")
            i += 1
            continue

        if in_code_block:
            parts.append(html.escape(raw))
            i += 1
            continue

        # blank line: flush accumulated paragraph
        if not line:
            flush_paragraph()
            i += 1
            continue

        # heading
        h = _match_heading(line)
        if h is not None:
            flush_paragraph()
            level, text = h
            parts.append(f"<h{level}>{html.escape(text)}</h{level}>")
            i += 1
            continue

        # thematic break
        if line.strip() in ("---", "***", "___", "- - -", "* * *"):
            flush_paragraph()
            parts.append("<hr>")
            i += 1
            continue

        # blockquote (single line)
        if line.startswith("> "):
            flush_paragraph()
            parts.append(f"<blockquote><p>{_inline_markdown_to_html(line[2:].strip())}</p></blockquote>")
            i += 1
            continue

        # table (collect consecutive rows)
        if line.startswith("|") and line.endswith("|"):
            flush_paragraph()
            table_lines = [line]
            j = i + 1
            while j < len(lines) and lines[j].rstrip().startswith("|") and lines[j].rstrip().endswith("|"):
                table_lines.append(lines[j].rstrip())
                j += 1
            parts.append(markdown_table_to_html(table_lines))
            i = j
            continue

        # unordered list
        if _list_prefix(line) == "-":
            flush_paragraph()
            items = []
            while i < len(lines) and _list_prefix(lines[i].rstrip()) == "-":
                items.append(lines[i].rstrip()[1:].strip())
                i += 1
            lis = "".join(f"<li>{_inline_markdown_to_html(item)}</li>" for item in items)
            parts.append(f"<ul>{lis}</ul>")
            continue

        # accumulate paragraph text
        buf.append(line)
        i += 1

    if in_code_block:
        parts.append("</code></pre>")
    flush_paragraph()
    return "\n".join(p for p in parts if p)


def _match_heading(line: str) -> tuple[int, str] | None:
    """Return (level, text) if line is a markdown heading."""
    m = re.match(r"^(#{1,6})\s+(.+)$", line.strip())
    if m:
        return len(m.group(1)), m.group(2).strip()
    return None


def _list_prefix(line: str) -> str:
    """Return '-' if line starts with a list marker, else ''."""
    if re.match(r"^-\s+", line):
        return "-"
    return ""


def inline_markdown_to_html(text: str) -> str:
    return _inline_markdown_to_html(text)


def markdown_table_to_html(lines: list[str]) -> str:
    if len(lines) < 2:
        return ""
    headers = split_table_row(lines[0])
    body_lines = lines[2:] if set(lines[1].replace("|", "").replace(":", "").replace(" ", "")) == {"-"} else lines[1:]
    parts = ['<table class="sysml-table"><thead><tr>']
    for header in headers:
        parts.append(f"<th>{html.escape(header)}</th>")
    parts.append("</tr></thead><tbody>")
    for line in body_lines:
        parts.append("<tr>")
        for cell in split_table_row(line):
            parts.append(f"<td>{html.escape(cell)}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table>")
    return "".join(parts)


def split_table_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def build_theme_css(theme_name: str, font_key: str) -> str:
    """Generate themed CSS from presets with customisable font."""
    theme = THEME_PRESETS.get(theme_name, THEME_PRESETS["default"])
    font = FONT_PRESETS.get(font_key, FONT_PRESETS["system"])
    ff = font["family"]
    return f"""\
  :root {{
    --bg: {theme["bg"]};
    --fg: {theme["fg"]};
    --muted: {theme["muted"]};
    --border: {theme["border"]};
    --accent: {theme["accent"]};
    --accent-fg: {theme["accent-fg"]};
    --heading: {theme["heading"]};
    --code-bg: {theme["code-bg"]};
    --table-stripe: {theme["table-stripe"]};
    --table-header-bg: {theme["table-header-bg"]};
    --table-header-fg: {theme["table-header-fg"]};
    --link: {theme["link"]};
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: {ff};
    color: var(--fg);
    background: {theme["page-bg"]};
    line-height: 1.75;
    -webkit-font-smoothing: antialiased;
  }}
  main {{
    max-width: 960px;
    margin: 0 auto;
    padding: 48px 40px 80px;
    background: var(--bg);
    min-height: 100vh;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06);
  }}
  h1 {{ font-size: 2rem; color: var(--heading); margin-bottom: 8px; font-weight: 700; letter-spacing: -0.02em; }}
  h2 {{
    font-size: 1.35rem; color: var(--accent); margin-top: 36px; margin-bottom: 12px;
    padding-bottom: 8px; border-bottom: 2px solid var(--border); font-weight: 600;
  }}
  h3 {{ font-size: 1.1rem; color: var(--heading); margin-top: 24px; margin-bottom: 8px; font-weight: 600; }}
  h4 {{ font-size: 1rem; color: var(--muted); margin-top: 16px; margin-bottom: 6px; font-weight: 600; }}
  p {{ margin-bottom: 12px; }}
  a {{ color: var(--link); text-decoration: none; border-bottom: 1px solid transparent; transition: border-color 0.15s; }}
  a:hover {{ border-bottom-color: var(--link); }}
  code {{
    background: var(--code-bg); border-radius: 4px; padding: 2px 6px;
    font-family: "Cascadia Code", "JetBrains Mono", "Fira Code", Consolas, monospace;
    font-size: 0.875em; color: #be123c;
  }}
  pre {{
    background: #1e293b; color: #e2e8f0; border-radius: 8px; padding: 16px 20px;
    overflow-x: auto; margin: 16px 0; font-size: 0.85rem; line-height: 1.6;
  }}
  pre code {{ background: none; color: inherit; padding: 0; font-size: inherit; }}
  blockquote {{
    border-left: 4px solid var(--accent); background: var(--accent-fg);
    padding: 12px 18px; margin: 16px 0; border-radius: 0 6px 6px 0; color: var(--fg);
  }}
  blockquote p:last-child {{ margin-bottom: 0; }}
  table {{
    width: 100%; border-collapse: collapse; margin: 18px 0 28px; font-size: 0.92rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06); border-radius: 8px; overflow: hidden;
  }}
  th, td {{ border: 1px solid var(--border); padding: 10px 14px; text-align: left; vertical-align: top; }}
  th {{ background: var(--table-header-bg); color: var(--table-header-fg); font-weight: 600; }}
  tbody tr:nth-child(even) {{ background: var(--table-stripe); }}
  ul, ol {{ margin: 8px 0 16px 24px; }}
  li {{ margin-bottom: 4px; }}
  hr {{ border: none; border-top: 1px solid var(--border); margin: 32px 0; }}
  img {{ max-width: 100%; border-radius: 6px; }}
  .metadata {{
    display: flex; flex-wrap: wrap; gap: 8px 20px; padding: 14px 0 20px;
    border-bottom: 1px solid var(--border); margin-bottom: 32px; color: var(--muted); font-size: 0.85rem;
  }}
  .meta-item strong {{ color: var(--fg); margin-right: 6px; }}
  .meta-item {{ display: inline-flex; align-items: baseline; gap: 4px; }}
  .callout {{ border-radius: 8px; padding: 14px 18px; margin: 18px 0; font-size: 0.92rem; }}
  .callout-note {{ background: #eff6ff; border: 1px solid #bfdbfe; color: #1e40af; }}
  .callout-warning {{ background: #fffbeb; border: 1px solid #fde68a; color: #92400e; }}
  .callout-tip {{ background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; }}

  @media print {{
    body {{ background: #fff; }}
    main {{ box-shadow: none; padding: 0; max-width: none; }}
    h2 {{ break-after: avoid; }}
    table {{ break-inside: avoid; }}
    pre, blockquote {{ break-inside: avoid; }}
    @page {{ margin: 2.5cm; size: A4; }}
  }}
  @media (max-width: 768px) {{
    main {{ padding: 24px 16px 48px; }}
    h1 {{ font-size: 1.5rem; }}
    table {{ font-size: 0.82rem; }}
  }}"""


def wrap_document_html(
    title: str,
    body: str,
    metadata: dict[str, Any],
    theme: str = "default",
    font: str = "system",
) -> str:
    theme_css = build_theme_css(theme, font)
    theme_label = THEME_PRESETS.get(theme, THEME_PRESETS["default"])["label"]
    font_label = FONT_PRESETS.get(font, FONT_PRESETS["system"])["label"]
    meta_rows = "".join(
        f"<span class=\"meta-item\"><strong>{html.escape(str(key))}</strong>{html.escape(str(value))}</span>"
        for key, value in metadata.items()
    )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="generator" content="SysML DocGen">
<meta name="theme" content="{html.escape(theme_label)}">
<meta name="font" content="{html.escape(font_label)}">
<style>
{theme_css}
</style>
</head>
<body>
<main>
<div class="metadata">{meta_rows}</div>
{body}
</main>
</body>
</html>"""


def html_to_pdf_bytes(html_content: str, markdown: str, title: str = "SysML 文档") -> bytes:
    """Render PDF: Quarto/Pandoc > built-in CJK layout > optional HTML/PDF tools > ASCII fallback."""

    # 1. Quarto/Pandoc from Markdown preserves Unicode and gives DOCX/PDF parity.
    if PANDOC_AVAILABLE and PDF_ENGINE in {"quarto", "pandoc"}:
        pdf_bytes = markdown_to_pdf_pandoc(markdown, title)
        if pdf_bytes:
            return pdf_bytes

    # 2. Built-in renderer keeps Chinese text, tables, wrapping and pagination without external tools.
    unicode_pdf = _unicode_pdf_fallback(markdown)
    if unicode_pdf:
        return unicode_pdf

    rl_pdf = _reportlab_pdf(markdown)
    if rl_pdf:
        return rl_pdf

    fpdf_pdf = _fpdf_markdown_pdf(markdown)
    if fpdf_pdf:
        return fpdf_pdf

    # 3. Pandoc with HTML engines, useful when the user explicitly selects wkhtmltopdf.
    if PANDOC_AVAILABLE and PDF_ENGINE in {"wkhtmltopdf", "weasyprint"}:
        pdf_bytes = html_to_pdf_pandoc(html_content)
        if pdf_bytes:
            return pdf_bytes

    # 4. WeasyPrint handles HTML/CSS well when its native libraries are complete.
    wp_pdf = _weasyprint_pdf(html_content)
    if wp_pdf:
        return wp_pdf

    # 5. direct wkhtmltopdf fallback.
    wkhtmltopdf = shutil.which("wkhtmltopdf")
    if wkhtmltopdf:
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                html_path = Path(tmp_dir) / "document.html"
                pdf_path = Path(tmp_dir) / "document.pdf"
                html_path.write_text(html_content, encoding="utf-8")
                subprocess.run(
                    [wkhtmltopdf, "--encoding", "UTF-8", str(html_path), str(pdf_path)],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
                return pdf_path.read_bytes()
        except (OSError, subprocess.SubprocessError):
            pass

    # 6. Last-resort simple PDF path.
    return markdown_to_simple_pdf(markdown)


def _reportlab_pdf(markdown: str) -> bytes | None:
    """Render markdown as PDF via reportlab with CJK font support."""
    if not _REPORTLAB_AVAILABLE:
        return None

    cjk_font_path = None
    for _name, path in SYSTEM_CJK_FONTS.items():
        if path.lower().endswith(".ttf"):
            cjk_font_path = path
            break
    if not cjk_font_path:
        cjk_font_path = next(iter(SYSTEM_CJK_FONTS.values()), None)
    if not cjk_font_path:
        return None

    try:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm, leftMargin=22 * mm, rightMargin=22 * mm)
        font_name = "SYSMLCJK"
        if cjk_font_path.lower().endswith(".ttc"):
            pdfmetrics.registerFont(TTFont(font_name, cjk_font_path, subfontIndex=0))
        else:
            pdfmetrics.registerFont(TTFont(font_name, cjk_font_path))

        styles = getSampleStyleSheet()
        cjk_body = ParagraphStyle('CJKBody', parent=styles['Normal'], fontName=font_name, fontSize=10, leading=16, spaceAfter=6)
        cjk_h1 = ParagraphStyle('CJKH1', parent=styles['Heading1'], fontName=font_name, fontSize=18, leading=24, spaceAfter=12, textColor='#0f172a')
        cjk_h2 = ParagraphStyle('CJKH2', parent=styles['Heading2'], fontName=font_name, fontSize=14, leading=20, spaceBefore=14, spaceAfter=8, textColor='#0f766e')
        cjk_h3 = ParagraphStyle('CJKH3', parent=styles['Heading3'], fontName=font_name, fontSize=12, leading=17, spaceBefore=10, spaceAfter=6)

        story = []
        for raw_line in markdown.splitlines():
            line = raw_line.strip()
            if not line:
                story.append(Spacer(1, 6))
                continue
            if set(line.replace("|", "").replace(":", "").replace(" ", "")) == {"-"}:
                continue
            if line.startswith("# ") and not line.startswith("## "):
                story.append(Paragraph(_escape_rl(line[2:].strip()), cjk_h1))
            elif line.startswith("## ") and not line.startswith("### "):
                story.append(Paragraph(_escape_rl(line[3:].strip()), cjk_h2))
            elif line.startswith("### "):
                story.append(Paragraph(_escape_rl(line[4:].strip()), cjk_h3))
            elif line.startswith("- "):
                story.append(Paragraph(f"&bull; {_escape_rl(line[2:].strip())}", cjk_body))
            elif line.startswith("|"):
                continue  # tables skipped in reportlab fallback
            else:
                stripped = line.lstrip("#").strip().replace("|", "  ")
                story.append(Paragraph(_escape_rl(stripped[:300]), cjk_body))
        doc.build(story)
        return buf.getvalue()
    except Exception:
        return None


def _escape_rl(text: str) -> str:
    """Escape text for reportlab XML."""
    return html.escape(text, quote=False)


def _weasyprint_pdf(html_content: str) -> bytes | None:
    """Render HTML to PDF with weasyprint (supports CSS + CJK fonts)."""
    try:
        from weasyprint import HTML  # type: ignore[import-untyped]  # noqa: F811
        doc = HTML(string=html_content)
        return doc.write_pdf()
    except Exception:
        return None


def markdown_to_simple_pdf(markdown: str) -> bytes:
    """Generate a basic PDF from markdown text.  Uses fpdf2 when available, otherwise a minimal
    ASCII-only fallback that warns about CJK limitations."""
    unicode_pdf = _unicode_pdf_fallback(markdown)
    if unicode_pdf:
        return unicode_pdf
    if _FPDF_AVAILABLE:
        pdf_bytes = _fpdf_markdown_pdf(markdown)
        if pdf_bytes:
            return pdf_bytes
    return _ascii_pdf_fallback(markdown)


def _fpdf_markdown_pdf(markdown: str) -> bytes | None:
    """Render markdown as PDF via fpdf2 with CJK support."""
    if FPDF is None:
        return None

    # Prefer TTF over TTC for better fpdf2 compatibility
    cjk_font_path = None
    for _name, path in SYSTEM_CJK_FONTS.items():
        if path.lower().endswith(".ttf"):
            cjk_font_path = path
            break
    if not cjk_font_path:
        cjk_font_path = next(iter(SYSTEM_CJK_FONTS.values()), None)
    if not cjk_font_path:
        return None
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.add_font("cjk", "", cjk_font_path)
        body_w = pdf.w - pdf.l_margin - pdf.r_margin
        pdf.set_font("cjk", size=10)
        for raw_line in markdown.splitlines():
            line = raw_line.strip()
            if not line:
                pdf.ln(4)
                continue
            if set(line.replace("|", "").replace(":", "").replace(" ", "")) == {"-"}:
                continue
            if line.startswith("# "):
                pdf.set_font("cjk", size=16)
                pdf.multi_cell(body_w, 9, line[2:].strip())
                pdf.set_font("cjk", size=10)
                pdf.ln(2)
            elif line.startswith("## "):
                pdf.set_font("cjk", size=13)
                pdf.multi_cell(body_w, 7, line[3:].strip())
                pdf.set_font("cjk", size=10)
                pdf.ln(1)
            elif line.startswith("### "):
                pdf.set_font("cjk", size=11)
                pdf.multi_cell(body_w, 6, line[4:].strip())
                pdf.set_font("cjk", size=10)
            elif line.startswith("- "):
                safe = _truncate_line(line[2:].strip(), 120)
                pdf.cell(6, 6, "-")
                pdf.multi_cell(body_w - 6, 6, safe)
            elif line.startswith("|") and line.endswith("|"):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                safe_cells = [_truncate_line(c, 50) for c in cells]
                for cell in safe_cells:
                    pdf.cell(body_w / max(len(safe_cells), 1), 6, cell, border=1)
                pdf.ln()
            else:
                stripped = line.lstrip("#").strip().replace("|", "  ")
                pdf.multi_cell(body_w, 6, _truncate_line(stripped, 200))
        return pdf.output()
    except Exception:
        return None


def _truncate_line(text: str, max_len: int) -> str:
    return text[:max_len]


def _unicode_pdf_fallback(markdown: str) -> bytes | None:
    """Layout-aware Unicode PDF with an embedded CJK font and Helvetica for Latin text."""
    font_path = _pdf_font_path()
    if not font_path:
        return None

    try:
        font_bytes = Path(font_path).read_bytes()
    except OSError:
        return None

    pages, used_text = _layout_unicode_pdf_pages(markdown)
    if not pages:
        pages = [["BT /F2 11 Tf 1 0 0 1 48 792 Tm (SysML DocGen) Tj ET"]]
    if not used_text:
        used_text = "SysML DocGen"

    cid_to_gid = _cid_to_gid_map(font_bytes, used_text)
    if not cid_to_gid:
        return None

    page_count = len(pages)
    cjk_font_obj = 3 + page_count
    cid_font_obj = cjk_font_obj + 1
    descriptor_obj = cjk_font_obj + 2
    font_file_obj = cjk_font_obj + 3
    cid_map_obj = cjk_font_obj + 4
    latin_font_obj = cjk_font_obj + 5
    to_unicode_obj = cjk_font_obj + 6
    content_base_obj = cjk_font_obj + 7
    page_refs = " ".join(f"{3 + index} 0 R" for index in range(page_count))

    font_descriptor = (
        b"<< /Type /FontDescriptor /FontName /SysMLCJK /Flags 4 "
        b"/FontBBox [0 -250 1000 1000] /ItalicAngle 0 /Ascent 880 /Descent -120 "
        + f"/CapHeight 700 /StemV 80 /FontFile2 {font_file_obj} 0 R >>".encode("ascii")
    )
    cid_font = (
        b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /SysMLCJK "
        b"/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> "
        + f"/FontDescriptor {descriptor_obj} 0 R /CIDToGIDMap {cid_map_obj} 0 R ".encode("ascii")
        + b"/DW 1000 /W [0 [500]] >>"
    )
    type0_font = (
        b"<< /Type /Font /Subtype /Type0 /BaseFont /SysMLCJK "
        + f"/Encoding /Identity-H /DescendantFonts [{cid_font_obj} 0 R] /ToUnicode {to_unicode_obj} 0 R >>".encode(
            "ascii"
        )
    )
    to_unicode = _to_unicode_cmap(used_text)
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{page_refs}] /Count {page_count} >>".encode("ascii"),
    ]
    for index in range(page_count):
        content_obj = content_base_obj + index
        objects.append(
            (
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                f"/Resources << /Font << /F1 {cjk_font_obj} 0 R /F2 {latin_font_obj} 0 R >> >> "
                f"/Contents {content_obj} 0 R >>"
            ).encode("ascii")
        )

    objects.extend(
        [
        type0_font,
        cid_font,
        font_descriptor,
        b"<< /Length " + str(len(font_bytes)).encode("ascii") + b" >>\nstream\n" + font_bytes + b"\nendstream",
        b"<< /Length " + str(len(cid_to_gid)).encode("ascii") + b" >>\nstream\n" + cid_to_gid + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(to_unicode)).encode("ascii") + b" >>\nstream\n" + to_unicode + b"\nendstream",
        ]
    )

    for page in pages:
        content = "\n".join(page).encode("ascii")
        objects.append(b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream")
    return _pdf_from_objects(objects)


PdfBlock = tuple[str, Any]


def _layout_unicode_pdf_pages(markdown: str) -> tuple[list[list[str]], str]:
    page_w = 595.0
    page_h = 842.0
    margin_x = 44.0
    margin_top = 54.0
    margin_bottom = 48.0
    body_w = page_w - margin_x * 2
    y = page_h - margin_top
    pages: list[list[str]] = [[]]
    used_text: list[str] = []

    def current() -> list[str]:
        return pages[-1]

    def new_page() -> None:
        nonlocal y
        pages.append([])
        y = page_h - margin_top

    def ensure(height: float) -> None:
        if y - height < margin_bottom and current():
            new_page()

    def draw_text(x: float, baseline: float, text: str, size: float = 10.0, color: tuple[float, float, float] | None = None) -> None:
        if not text:
            return
        used_text.append(text)
        current().extend(_pdf_text_commands(x, baseline, text, size, color))

    blocks = _pdf_markdown_blocks(markdown)
    if not blocks:
        blocks = [("paragraph", "SysML DocGen")]

    for block_type, payload in blocks:
        if block_type == "heading":
            level, text = payload
            size = 16.0 if level == 1 else 13.0 if level == 2 else 11.5
            line_h = size + 6.0
            wrapped = _wrap_pdf_text(text, body_w, size)
            block_h = len(wrapped) * line_h + (8.0 if level <= 2 else 4.0)
            ensure(block_h)
            if level == 2:
                current().append(f"0.15 0.47 0.43 RG {margin_x:.2f} {y - 4:.2f} {body_w:.2f} 0.8 re S 0 G")
                y -= 10.0
            for line in wrapped:
                draw_text(margin_x, y - size, line, size, (0.06, 0.09, 0.16) if level == 1 else (0.05, 0.46, 0.42))
                y -= line_h
            y -= 3.0
            continue

        if block_type == "paragraph":
            text = payload
            size = 9.6
            line_h = 14.5
            wrapped = _wrap_pdf_text(text, body_w, size)
            ensure(len(wrapped) * line_h + 6.0)
            for line in wrapped:
                draw_text(margin_x, y - size, line, size)
                y -= line_h
            y -= 5.0
            continue

        if block_type == "list":
            items = payload
            size = 9.6
            line_h = 14.5
            for item in items:
                wrapped = _wrap_pdf_text(item, body_w - 16.0, size)
                ensure(len(wrapped) * line_h + 2.0)
                draw_text(margin_x, y - size, "-", size)
                for index, line in enumerate(wrapped):
                    draw_text(margin_x + 14.0, y - size - index * line_h, line, size)
                y -= len(wrapped) * line_h + 2.0
            y -= 4.0
            continue

        if block_type == "table":
            rows = payload
            if not rows:
                continue
            col_widths = _pdf_table_column_widths(rows, body_w)
            font_size = 8.1 if len(col_widths) >= 4 else 8.6
            line_h = font_size + 3.3
            pad_x = 4.0
            pad_y = 5.0
            header_row = rows[0]

            def measure_row(row: list[str]) -> tuple[list[list[str]], float]:
                nonlocal y
                wrapped_cells = [
                    _wrap_pdf_text(cell, max(width - pad_x * 2, 18.0), font_size)
                    for cell, width in zip(_pad_pdf_row(row, len(col_widths)), col_widths)
                ]
                row_lines = max((len(cell_lines) for cell_lines in wrapped_cells), default=1)
                row_h = max(19.0, row_lines * line_h + pad_y * 2)
                return wrapped_cells, row_h

            def draw_row(
                row: list[str],
                is_header: bool = False,
                measured: tuple[list[list[str]], float] | None = None,
            ) -> None:
                nonlocal y
                wrapped_cells, row_h = measured or measure_row(row)
                ensure(row_h + 2.0)
                top = y
                bottom = y - row_h
                if is_header:
                    current().append(f"0.94 0.98 0.97 rg {margin_x:.2f} {bottom:.2f} {body_w:.2f} {row_h:.2f} re f 0 g")
                x = margin_x
                for width, lines in zip(col_widths, wrapped_cells):
                    current().append(f"0.82 0.87 0.91 RG {x:.2f} {bottom:.2f} {width:.2f} {row_h:.2f} re S 0 G")
                    text_y = top - pad_y - font_size
                    for line_index, text_line in enumerate(lines):
                        draw_text(
                            x + pad_x,
                            text_y - line_index * line_h,
                            text_line,
                            font_size,
                            (0.07, 0.31, 0.29) if is_header else None,
                        )
                    x += width
                y = bottom

            draw_row(header_row, True)
            for row in rows[1:]:
                measured = measure_row(row)
                if y - measured[1] < margin_bottom:
                    new_page()
                    draw_row(header_row, True)
                draw_row(row, measured=measured)
            y -= 11.0

    return pages, "\n".join(used_text)


def _pdf_markdown_blocks(markdown: str) -> list[PdfBlock]:
    blocks: list[PdfBlock] = []
    paragraph: list[str] = []
    lines = markdown.splitlines()
    index = 0

    def flush_paragraph() -> None:
        if paragraph:
            blocks.append(("paragraph", _strip_inline_markdown(" ".join(paragraph))))
            paragraph.clear()

    while index < len(lines):
        line = lines[index].strip()
        if not line:
            flush_paragraph()
            index += 1
            continue

        heading = _match_heading(line)
        if heading:
            flush_paragraph()
            level, text = heading
            blocks.append(("heading", (level, _strip_inline_markdown(text))))
            index += 1
            continue

        if line.startswith("|") and line.endswith("|"):
            flush_paragraph()
            table_lines = [line]
            index += 1
            while index < len(lines) and lines[index].strip().startswith("|") and lines[index].strip().endswith("|"):
                table_lines.append(lines[index].strip())
                index += 1
            rows = _pdf_table_rows(table_lines)
            if rows:
                blocks.append(("table", rows))
            continue

        if _list_prefix(line) == "-":
            flush_paragraph()
            items: list[str] = []
            while index < len(lines) and _list_prefix(lines[index].strip()) == "-":
                items.append(_strip_inline_markdown(lines[index].strip()[1:].strip()))
                index += 1
            blocks.append(("list", items))
            continue

        paragraph.append(line)
        index += 1

    flush_paragraph()
    return blocks


def _pdf_table_rows(lines: list[str]) -> list[list[str]]:
    rows: list[list[str]] = []
    for index, line in enumerate(lines):
        if index == 1 and _is_markdown_separator_row(line):
            continue
        rows.append([_strip_inline_markdown(cell) for cell in split_table_row(line)])
    return rows


def _is_markdown_separator_row(line: str) -> bool:
    cleaned = line.replace("|", "").replace(":", "").replace("-", "").replace(" ", "")
    return cleaned == ""


def _pdf_table_column_widths(rows: list[list[str]], total_width: float) -> list[float]:
    column_count = max((len(row) for row in rows), default=1)
    headers = [_normalize_pdf_header(cell) for cell in rows[0]] if rows else []
    if column_count == 4 and {"id", "name", "requirement_text", "verification"}.issubset(set(headers)):
        weights = [0.15, 0.18, 0.52, 0.15]
    elif column_count == 4 and "criterion" in headers:
        weights = [0.15, 0.22, 0.15, 0.48]
    elif column_count == 4 and "expression" in headers:
        weights = [0.15, 0.20, 0.30, 0.35]
    elif column_count == 4 and "description" in headers:
        weights = [0.15, 0.22, 0.18, 0.45]
    elif column_count == 5:
        weights = [0.15, 0.12, 0.17, 0.16, 0.40]
    elif column_count == 3:
        weights = [0.18, 0.22, 0.60] if "description" in headers else [0.20, 0.24, 0.56]
    elif column_count == 2:
        weights = [0.36, 0.64]
    else:
        weights = [1 / column_count] * column_count
    if len(weights) < column_count:
        weights.extend([1 / column_count] * (column_count - len(weights)))
    weights = weights[:column_count]
    total_weight = sum(weights) or 1
    return [total_width * weight / total_weight for weight in weights]


def _normalize_pdf_header(value: str) -> str:
    text = value.strip().lower()
    mapping = {
        "id": "id",
        "名称": "name",
        "name": "name",
        "需求文本": "requirement_text",
        "requirement text": "requirement_text",
        "验证方式": "verification",
        "verification": "verification",
        "责任域": "owner",
        "描述": "description",
        "description": "description",
        "方法": "method",
        "method": "method",
        "判据": "criterion",
        "criterion": "criterion",
        "表达式": "expression",
        "expression": "expression",
        "类型": "type",
        "type": "type",
        "方向/协议": "protocol",
        "direction/protocol": "protocol",
        "状态": "state",
        "state": "state",
    }
    return mapping.get(text, text)


def _pad_pdf_row(row: list[str], column_count: int) -> list[str]:
    if len(row) >= column_count:
        return row[:column_count]
    return [*row, *([""] * (column_count - len(row)))]


def _wrap_pdf_text(text: str, max_width: float, font_size: float) -> list[str]:
    text = " ".join(text.replace("\t", " ").split())
    if not text:
        return [""]
    lines: list[str] = []
    current = ""
    for token in _pdf_wrap_tokens(text):
        candidate = f"{current}{token}" if current else token.lstrip()
        if current and _pdf_text_width(candidate, font_size) > max_width:
            lines.append(current.rstrip())
            current = token.lstrip()
            while _pdf_text_width(current, font_size) > max_width and len(current) > 1:
                split_at = _pdf_split_text_at_width(current, max_width, font_size)
                lines.append(current[:split_at].rstrip())
                current = current[split_at:].lstrip()
        else:
            current = candidate
    if current:
        while _pdf_text_width(current, font_size) > max_width and len(current) > 1:
            split_at = _pdf_split_text_at_width(current, max_width, font_size)
            lines.append(current[:split_at].rstrip())
            current = current[split_at:].lstrip()
        lines.append(current.rstrip())
    return lines or [""]


def _pdf_wrap_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    buffer = ""
    for ch in text:
        if ch.isspace():
            if buffer:
                tokens.append(buffer)
                buffer = ""
            tokens.append(" ")
        elif _is_cjk_char(ch):
            if buffer:
                tokens.append(buffer)
                buffer = ""
            tokens.append(ch)
        else:
            buffer += ch
    if buffer:
        tokens.append(buffer)
    return tokens


def _pdf_split_text_at_width(text: str, max_width: float, font_size: float) -> int:
    width = 0.0
    for index, ch in enumerate(text, start=1):
        char_width = _pdf_text_width(ch, font_size)
        if width + char_width > max_width and index > 1:
            return index - 1
        width += char_width
    return max(1, len(text))


def _pdf_text_width(text: str, font_size: float) -> float:
    width = 0.0
    for ch in text:
        if _is_cjk_char(ch):
            width += font_size
        elif ch.isspace():
            width += font_size * 0.32
        elif ch in "ilI.,;:!|":
            width += font_size * 0.28
        elif ch in "mwMW@#%&":
            width += font_size * 0.72
        else:
            width += font_size * 0.52
    return width


def _pdf_text_commands(
    x: float,
    y: float,
    text: str,
    size: float,
    color: tuple[float, float, float] | None = None,
) -> list[str]:
    commands: list[str] = []
    if color:
        commands.append(f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg")
    cursor = x
    for font, run in _pdf_text_runs(text):
        if not run:
            continue
        if font == "latin":
            commands.append(f"BT /F2 {size:.2f} Tf 1 0 0 1 {cursor:.2f} {y:.2f} Tm ({_pdf_escape(run)}) Tj ET")
        else:
            commands.append(f"BT /F1 {size:.2f} Tf 1 0 0 1 {cursor:.2f} {y:.2f} Tm <{_utf16be_hex(run)}> Tj ET")
        cursor += _pdf_text_width(run, size)
    if color:
        commands.append("0 g")
    return commands


def _pdf_text_runs(text: str) -> list[tuple[str, str]]:
    runs: list[tuple[str, str]] = []
    active_font = ""
    buffer = ""
    for ch in text:
        font = "latin" if ord(ch) < 128 else "cjk"
        if font != active_font and buffer:
            runs.append((active_font, buffer))
            buffer = ""
        active_font = font
        buffer += ch
    if buffer:
        runs.append((active_font or "latin", buffer))
    return runs


def _is_cjk_char(ch: str) -> bool:
    if ord(ch) >= 128 and unicodedata.east_asian_width(ch) in {"W", "F", "A"}:
        return True
    return "\u4e00" <= ch <= "\u9fff"


def _strip_inline_markdown(text: str) -> str:
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", text)
    return html.unescape(text).strip()


def _pdf_font_path() -> str:
    for preferred in ("SimHei", "Microsoft YaHei", "Noto Sans CJK SC", "SimSun"):
        path = SYSTEM_CJK_FONTS.get(preferred, "")
        if path and path.lower().endswith((".ttf", ".otf")):
            return path
    for path in SYSTEM_CJK_FONTS.values():
        if path.lower().endswith((".ttf", ".otf")):
            return path
    return ""


def _utf16be_hex(value: str) -> str:
    return value.encode("utf-16-be", errors="replace").hex().upper()


def _cid_to_gid_map(font_bytes: bytes, text: str) -> bytes | None:
    cmap = _ttf_cmap(font_bytes)
    if not cmap:
        return None
    max_cid = max((ord(ch) for ch in text), default=0)
    if max_cid <= 0:
        return None
    values = bytearray((max_cid + 1) * 2)
    for ch in set(text):
        cid = ord(ch)
        gid = cmap.get(cid)
        if gid is None:
            continue
        values[cid * 2 : cid * 2 + 2] = gid.to_bytes(2, "big", signed=False)
    return bytes(values)


def _ttf_cmap(font_bytes: bytes) -> dict[int, int]:
    try:
        table_count = int.from_bytes(font_bytes[4:6], "big")
        cmap_offset = 0
        for index in range(table_count):
            record = 12 + index * 16
            tag = font_bytes[record : record + 4]
            if tag == b"cmap":
                cmap_offset = int.from_bytes(font_bytes[record + 8 : record + 12], "big")
                break
        if not cmap_offset:
            return {}

        subtable_count = int.from_bytes(font_bytes[cmap_offset + 2 : cmap_offset + 4], "big")
        selected_offset = 0
        selected_format = 0
        for index in range(subtable_count):
            record = cmap_offset + 4 + index * 8
            platform = int.from_bytes(font_bytes[record : record + 2], "big")
            encoding = int.from_bytes(font_bytes[record + 2 : record + 4], "big")
            offset = int.from_bytes(font_bytes[record + 4 : record + 8], "big")
            fmt = int.from_bytes(font_bytes[cmap_offset + offset : cmap_offset + offset + 2], "big")
            if fmt == 12 and platform == 3 and encoding in {10, 1}:
                selected_offset = cmap_offset + offset
                selected_format = fmt
                break
            if fmt == 4 and platform == 3 and encoding in {1, 10} and not selected_offset:
                selected_offset = cmap_offset + offset
                selected_format = fmt
        if selected_format == 12:
            return _ttf_cmap_format12(font_bytes, selected_offset)
        if selected_format == 4:
            return _ttf_cmap_format4(font_bytes, selected_offset)
    except (IndexError, ValueError, OverflowError):
        return {}
    return {}


def _ttf_cmap_format12(font_bytes: bytes, offset: int) -> dict[int, int]:
    group_count = int.from_bytes(font_bytes[offset + 12 : offset + 16], "big")
    cmap: dict[int, int] = {}
    pos = offset + 16
    for _ in range(group_count):
        start_char = int.from_bytes(font_bytes[pos : pos + 4], "big")
        end_char = int.from_bytes(font_bytes[pos + 4 : pos + 8], "big")
        start_gid = int.from_bytes(font_bytes[pos + 8 : pos + 12], "big")
        for codepoint in range(start_char, end_char + 1):
            cmap[codepoint] = start_gid + codepoint - start_char
        pos += 12
    return cmap


def _ttf_cmap_format4(font_bytes: bytes, offset: int) -> dict[int, int]:
    seg_count = int.from_bytes(font_bytes[offset + 6 : offset + 8], "big") // 2
    end_codes_offset = offset + 14
    start_codes_offset = end_codes_offset + seg_count * 2 + 2
    id_delta_offset = start_codes_offset + seg_count * 2
    id_range_offset_offset = id_delta_offset + seg_count * 2
    cmap: dict[int, int] = {}
    for index in range(seg_count):
        end_code = int.from_bytes(font_bytes[end_codes_offset + index * 2 : end_codes_offset + index * 2 + 2], "big")
        start_code = int.from_bytes(font_bytes[start_codes_offset + index * 2 : start_codes_offset + index * 2 + 2], "big")
        id_delta = int.from_bytes(font_bytes[id_delta_offset + index * 2 : id_delta_offset + index * 2 + 2], "big", signed=True)
        id_range_offset = int.from_bytes(font_bytes[id_range_offset_offset + index * 2 : id_range_offset_offset + index * 2 + 2], "big")
        for codepoint in range(start_code, end_code + 1):
            if codepoint == 0xFFFF:
                continue
            if id_range_offset == 0:
                glyph_id = (codepoint + id_delta) & 0xFFFF
            else:
                glyph_index_offset = id_range_offset_offset + index * 2 + id_range_offset + (codepoint - start_code) * 2
                glyph_id = int.from_bytes(font_bytes[glyph_index_offset : glyph_index_offset + 2], "big")
                if glyph_id:
                    glyph_id = (glyph_id + id_delta) & 0xFFFF
            if glyph_id:
                cmap[codepoint] = glyph_id
    return cmap


def _to_unicode_cmap(text: str) -> bytes:
    entries = []
    for codepoint in sorted({ord(ch) for ch in text}):
        if codepoint > 0xFFFF:
            continue
        hex_code = f"{codepoint:04X}"
        entries.append(f"<{hex_code}> <{hex_code}>")
    chunks = []
    for index in range(0, len(entries), 100):
        group = entries[index : index + 100]
        chunks.append(f"{len(group)} beginbfchar\n" + "\n".join(group) + "\nendbfchar")
    body = "\n".join(chunks)
    return f"""/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
/CMapName /SysMLCJK-UTF16 def
/CMapType 2 def
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
{body}
endcmap
CMapName currentdict /CMap defineresource pop
end
end
""".encode("ascii")


def _ascii_pdf_fallback(markdown: str) -> bytes:
    """Minimal ASCII-only PDF.  Non-Latin-1 characters are replaced — use wkhtmltopdf or fpdf2 for Chinese."""
    lines = _extract_pdf_lines(markdown)
    if not lines:
        lines = ["SysML DocGen"]

    text_commands = ["BT", "/F1 10 Tf", "14 TL", "48 792 Td"]
    for index, line in enumerate(lines[:52]):
        if index:
            text_commands.append("T*")
        text_commands.append(f"({_pdf_escape(line)}) Tj")
    text_commands.append("ET")
    content = "\n".join(text_commands).encode("latin-1", errors="replace")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream",
    ]
    return _pdf_from_objects(objects)


def _pdf_from_objects(objects: list[bytes]) -> bytes:
    payload = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(payload))
        payload.extend(f"{index} 0 obj\n".encode("ascii"))
        payload.extend(obj)
        payload.extend(b"\nendobj\n")

    xref_offset = len(payload)
    payload.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    payload.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        payload.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    payload.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(payload)


def _extract_pdf_lines(markdown: str) -> list[str]:
    """Extract printable lines from markdown for simple PDF rendering."""
    result = []
    for raw_line in markdown.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if set(line.replace("|", "").replace(":", "").replace(" ", "")) == {"-"}:
            continue
        line = line.lstrip("#").strip().replace("|", "  ")
        result.append(line[:110])
    return result


def _pdf_escape(value: str) -> str:
    return (
        value.encode("latin-1", errors="replace")
        .decode("latin-1")
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def generate_document(
    project: dict[str, Any],
    branch_name: str,
    template: str | None = None,
    output_format: str = "html",
    theme: str = "default",
    font: str = "system",
) -> dict[str, Any]:
    branch = project["branches"][branch_name]
    elements = branch.get("elements", {})
    source_commit = branch.get("head", "working")
    rendered_markdown = render_template(template or default_document_template(project, branch_name), elements)
    model_hash = stable_hash(elements)
    document_id = f"DOC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{model_hash[:6]}"
    metadata = {
        "项目": project.get("name", ""),
        "分支": branch_name,
        "提交": source_commit,
        "模型指纹": model_hash,
        "生成时间": utc_now(),
    }
    html_body = markdown_to_html(rendered_markdown)
    theme_name = theme if theme in THEME_PRESETS else DEFAULT_THEME
    font_name = font if font in FONT_PRESETS else DEFAULT_FONT
    html_content = wrap_document_html(project.get("name", "SysML 文档"), html_body, metadata, theme_name, font_name)
    pdf_bytes = html_to_pdf_bytes(
        html_content,
        rendered_markdown,
        project.get("name", "SysML 文档"),
    )

    document: dict[str, Any] = {
        "id": document_id,
        "title": project.get("name", "SysML 文档"),
        "created_at": metadata["生成时间"],
        "source_branch": branch_name,
        "source_commit": source_commit,
        "model_hash": model_hash,
        "format": output_format,
        "theme": theme_name,
        "font": font_name,
        "markdown": rendered_markdown,
        "html": html_content,
        "pdf_base64": base64.b64encode(pdf_bytes).decode("ascii"),
        "pdf_filename": f"{document_id}.pdf",
        "traceability": build_traceability(elements),
        "validation": validate_repository(elements),
    }

    docx_bytes = markdown_to_docx_pandoc(rendered_markdown)
    if not docx_bytes:
        docx_bytes = markdown_to_docx_builtin(rendered_markdown)
    document["docx_base64"] = base64.b64encode(docx_bytes).decode("ascii")
    document["docx_filename"] = f"{document_id}.docx"

    document["files"] = persist_document_outputs(document)
    branch.setdefault("documents", []).insert(0, document)
    branch["documents"] = branch["documents"][:20]
    return document


def persist_document_outputs(document: dict[str, Any], output_dir: Path = OUTPUT_DIR) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = document["id"]
    html_path = output_dir / f"{base_name}.html"
    markdown_path = output_dir / f"{base_name}.md"
    pdf_path = output_dir / f"{base_name}.pdf"
    html_path.write_text(document["html"], encoding="utf-8")
    markdown_path.write_text(document["markdown"], encoding="utf-8")
    pdf_path.write_bytes(base64.b64decode(document["pdf_base64"]))
    files: dict[str, str] = {
        "html": str(html_path),
        "markdown": str(markdown_path),
        "pdf": str(pdf_path),
    }
    if document.get("docx_base64"):
        docx_path = output_dir / f"{base_name}.docx"
        docx_path.write_bytes(base64.b64decode(document["docx_base64"]))
        files["docx"] = str(docx_path)
    return files
