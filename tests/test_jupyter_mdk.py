import unittest

from mdk.jupyter import sysml_docgen_notebook as nb_mdk


class FakeMdkClient:
    def __init__(self):
        self.pushed = None

    def push_elements(self, elements, tool="jupyter", commit=True, message="", source=None):
        self.pushed = {
            "elements": elements,
            "tool": tool,
            "commit": commit,
            "message": message,
            "source": source,
        }
        return {"imported": len(elements), "elements": elements}


class JupyterMdkTest(unittest.TestCase):
    def test_requirement_element_matches_sysml_payload(self):
        element = nb_mdk.requirement_element(
            "REQ-NB-001",
            "Notebook requirement",
            "SOC shall remain above 30 percent.",
            relations=[{"type": "satisfy", "target": "BLK-BATTERY"}],
        )

        self.assertEqual(element["id"], "REQ-NB-001")
        self.assertEqual(element["type"], "Requirement")
        self.assertEqual(element["stereotype"], "requirement")
        self.assertEqual(element["attributes"]["verification"], "Analysis")
        self.assertEqual(element["relations"][0]["target"], "BLK-BATTERY")

    def test_push_elements_uses_live_jupyter_source(self):
        fake = FakeMdkClient()
        result = nb_mdk.push_elements(
            [{"id": "REQ-NB-002", "name": "Notebook sync", "type": "Requirement"}],
            message="unit test sync",
            mdk_client=fake,
        )

        self.assertEqual(result["imported"], 1)
        self.assertEqual(fake.pushed["tool"], "jupyter")
        self.assertTrue(fake.pushed["commit"])
        self.assertEqual(fake.pushed["source"]["adapter"], "sysml_docgen_notebook")

    def test_requirement_magic_builds_relations_from_cell(self):
        fake = FakeMdkClient()
        original_client = nb_mdk.client()
        try:
            nb_mdk._ACTIVE_CLIENT = fake
            result = nb_mdk.sysml_requirement_magic(
                'REQ-NB-003 "Magic requirement" --satisfy BLK-BATTERY',
                "SOC shall remain above 30 percent.",
            )
        finally:
            nb_mdk._ACTIVE_CLIENT = original_client

        self.assertEqual(result["imported"], 1)
        element = fake.pushed["elements"][0]
        self.assertEqual(element["attributes"]["text"], "SOC shall remain above 30 percent.")
        self.assertEqual(element["relations"][0], {"type": "satisfy", "target": "BLK-BATTERY"})


if __name__ == "__main__":
    unittest.main()
