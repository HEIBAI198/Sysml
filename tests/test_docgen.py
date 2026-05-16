import unittest
from pathlib import Path
from unittest.mock import patch

from sysml_docgen.auth import login, verify_token
from sysml_docgen.docgen import (
    _layout_unicode_pdf_pages,
    build_traceability,
    generate_document,
    html_to_pdf_bytes,
    markdown_to_docx_builtin,
    markdown_to_docx_pandoc,
    render_template,
)
from sysml_docgen.metamodel import build_diagram, validate_repository
from sysml_docgen.store import diff_snapshots
from sysml_docgen.xmi import elements_to_xmi, parse_xmi_elements


class DocGenTest(unittest.TestCase):
    def setUp(self):
        self.project = {
            "id": "demo",
            "name": "演示项目",
            "branches": {
                "main": {
                    "head": "C-0001",
                    "elements": {
                        "REQ-001": {
                            "id": "REQ-001",
                            "name": "连续供电",
                            "type": "Requirement",
                            "stereotype": "requirement",
                            "description": "保持供电",
                            "attributes": {"text": "应连续供电", "verification": "Test"},
                            "relations": [
                                {"type": "satisfy", "target": "BLK-001"},
                                {"type": "verify", "target": "TST-001"},
                            ],
                        },
                        "BLK-001": {
                            "id": "BLK-001",
                            "name": "电源模块",
                            "type": "Block",
                            "stereotype": "block",
                            "description": "提供电源",
                            "attributes": {},
                            "relations": [],
                        },
                        "IF-001": {
                            "id": "IF-001",
                            "name": "供电接口",
                            "type": "Interface",
                            "stereotype": "interfaceBlock",
                            "description": "28V 接口",
                            "attributes": {"protocol": "DC Power"},
                            "relations": [],
                        },
                        "TST-001": {
                            "id": "TST-001",
                            "name": "供电试验",
                            "type": "TestCase",
                            "stereotype": "testCase",
                            "description": "测试供电",
                            "attributes": {"method": "Test", "criterion": "通过"},
                            "relations": [],
                        },
                    },
                    "documents": [],
                }
            },
        }

    def test_template_resolves_element_fields(self):
        elements = self.project["branches"]["main"]["elements"]
        result = render_template("{{element:REQ-001.name}} {{element:REQ-001.attributes.text}}", elements)
        self.assertEqual(result, "连续供电 应连续供电")

    def test_traceability_closed_when_satisfied_and_verified(self):
        elements = self.project["branches"]["main"]["elements"]
        rows = build_traceability(elements)
        self.assertEqual(rows[0]["status"], "closed")
        self.assertEqual(rows[0]["satisfied_by"][0]["id"], "BLK-001")

    def test_traceability_accepts_incoming_design_and_test_relations(self):
        elements = {
            "REQ-010": {
                "id": "REQ-010",
                "name": "遥测需求",
                "type": "Requirement",
                "attributes": {"text": "应下传遥测", "verification": "Test"},
                "relations": [],
            },
            "BLK-010": {
                "id": "BLK-010",
                "name": "遥测模块",
                "type": "Block",
                "relations": [{"type": "satisfy", "target": "REQ-010"}],
            },
            "TST-010": {
                "id": "TST-010",
                "name": "遥测测试",
                "type": "TestCase",
                "relations": [{"type": "verify", "target": "REQ-010"}],
            },
        }
        rows = build_traceability(elements)
        self.assertEqual(rows[0]["status"], "closed")
        self.assertEqual(rows[0]["satisfied_by"][0]["id"], "BLK-010")
        self.assertEqual(rows[0]["verified_by"][0]["id"], "TST-010")

    def test_generate_document_outputs_html_markdown_and_validation(self):
        document = generate_document(self.project, "main")
        self.assertIn("演示项目", document["markdown"])
        self.assertIn("<!doctype html>", document["html"])
        self.assertIn("pdf_base64", document)
        self.assertIn("docx_base64", document)
        self.assertTrue(Path(document["files"]["html"]).exists())
        self.assertTrue(Path(document["files"]["pdf"]).exists())
        self.assertTrue(Path(document["files"]["docx"]).exists())
        self.assertIn("validation", document)
        self.assertEqual(len(self.project["branches"]["main"]["documents"]), 1)

    def test_pdf_fallback_returns_valid_pdf_bytes(self):
        pdf = html_to_pdf_bytes("<h1>Demo</h1>", "# Demo")
        self.assertTrue(pdf.startswith(b"%PDF-"))

    def test_quarto_pandoc_enables_docx_without_standalone_pandoc(self):
        expected = b"DOCXBYTES"
        with patch("sysml_docgen.docgen.QUARTO_PATH", "quarto"), patch(
            "sysml_docgen.docgen._run_quarto_render",
            return_value=expected,
        ) as render:
            docx = markdown_to_docx_pandoc("# 标题\n\n中文内容")

        self.assertEqual(docx, expected)
        render.assert_called_once()
        self.assertIn("format:", render.call_args.args[0])
        self.assertEqual(render.call_args.args[1], "docx")

    def test_builtin_docx_returns_valid_docx_package(self):
        docx = markdown_to_docx_builtin("# 标题\n\n| 列 | 值 |\n| --- | --- |\n| 中文 | 正常 |")
        self.assertTrue(docx.startswith(b"PK"))
        self.assertIn(b"word/document.xml", docx)

    def test_pdf_prefers_markdown_unicode_renderer_when_quarto_available(self):
        expected = b"%PDF-quarto"
        with patch("sysml_docgen.docgen.PANDOC_AVAILABLE", True), patch(
            "sysml_docgen.docgen.PDF_ENGINE",
            "quarto",
        ), patch(
            "sysml_docgen.docgen.markdown_to_pdf_pandoc",
            return_value=expected,
        ) as render:
            pdf = html_to_pdf_bytes("<h1>乱码?</h1>", "# 中文标题", "演示项目")

        self.assertEqual(pdf, expected)
        render.assert_called_once_with("# 中文标题", "演示项目")

    def test_builtin_pdf_layout_keeps_latin_text_and_wraps_tables(self):
        markdown = "\n".join(
            [
                "# Demo",
                "",
                "## Requirements",
                "| ID | Name | Requirement Text | Verification |",
                "| --- | --- | --- | --- |",
                *[
                    "| REQ-001 | Notebook energy margin requirement | "
                    "Battery SOC shall remain above 30 percent in the worst eclipse period. | Analysis |"
                    for _ in range(28)
                ],
            ]
        )

        pages, used_text = _layout_unicode_pdf_pages(markdown)
        content = "\n".join("\n".join(page) for page in pages)

        self.assertGreaterEqual(len(pages), 2)
        self.assertIn("(Requirements)", content)
        self.assertIn("(REQ-001)", content)
        self.assertIn(" re S", content)
        self.assertIn("Battery SOC shall remain", used_text)

    def test_xmi_roundtrip_preserves_elements_and_relations(self):
        export_payload = {
            "project": {"id": self.project["id"], "name": self.project["name"]},
            "elements": self.project["branches"]["main"]["elements"],
        }
        xmi = elements_to_xmi(export_payload)
        parsed = {element["id"]: element for element in parse_xmi_elements(xmi)}
        self.assertIn("REQ-001", parsed)
        self.assertIn("BLK-001", parsed)
        self.assertEqual(parsed["REQ-001"]["type"], "Requirement")
        self.assertIn({"type": "satisfy", "target": "BLK-001"}, parsed["REQ-001"]["relations"])

    def test_cameo_profile_stereotypes_and_connectors_are_parsed(self):
        xmi = """<?xml version="1.0" encoding="UTF-8"?>
<xmi:XMI xmlns:xmi="http://www.omg.org/spec/XMI/20131001"
         xmlns:uml="http://www.omg.org/spec/UML/20131001"
         xmlns:sysml="http://www.omg.org/spec/SysML/20181001">
  <uml:Model xmi:id="MODEL" name="Demo">
    <packagedElement xmi:type="uml:Class" xmi:id="BLK-POWER" name="PowerSystem">
      <ownedAttribute xmi:type="uml:Port" xmi:id="PRT-28V" name="P28V"/>
      <ownedConnector xmi:type="uml:Connector" xmi:id="CON-1">
        <end role="PRT-28V"/>
        <end role="IF-POWER"/>
      </ownedConnector>
    </packagedElement>
    <packagedElement xmi:type="uml:Interface" xmi:id="IF-POWER" name="PowerInterface"/>
  </uml:Model>
  <sysml:Block base_Class="BLK-POWER"/>
  <sysml:InterfaceBlock base_Interface="IF-POWER"/>
</xmi:XMI>"""
        parsed = {element["id"]: element for element in parse_xmi_elements(xmi)}
        self.assertEqual(parsed["BLK-POWER"]["type"], "Block")
        self.assertEqual(parsed["IF-POWER"]["type"], "Interface")
        self.assertEqual(parsed["PRT-28V"]["type"], "Port")
        self.assertIn({"type": "connect", "target": "IF-POWER"}, parsed["PRT-28V"]["relations"])

    def test_metamodel_validation_accepts_clean_model(self):
        elements = self.project["branches"]["main"]["elements"]
        result = validate_repository(elements)
        self.assertEqual(result["summary"]["errors"], 0)

    def test_build_diagram_returns_nodes_and_edges(self):
        elements = self.project["branches"]["main"]["elements"]
        diagram = build_diagram(elements, "requirements")
        self.assertGreaterEqual(len(diagram["nodes"]), 3)
        self.assertGreaterEqual(len(diagram["edges"]), 2)

    def test_diff_snapshots_reports_added_and_modified(self):
        before = {"REQ-001": {"id": "REQ-001", "name": "A", "type": "Requirement"}}
        after = {
            "REQ-001": {"id": "REQ-001", "name": "B", "type": "Requirement"},
            "BLK-001": {"id": "BLK-001", "name": "Block", "type": "Block"},
        }
        diff = diff_snapshots(before, after)
        self.assertEqual(diff["summary"], {"added": 1, "removed": 0, "modified": 1})

    def test_login_issues_verifiable_token(self):
        identity = login("engineer", "engineer123")
        self.assertIsNotNone(identity)
        verified = verify_token(identity["token"])
        self.assertEqual(verified["role"], "author")


if __name__ == "__main__":
    unittest.main()
