"""Jupyter MDK integration for synchronizing notebook analysis with MMS.

Usage inside a notebook:

    %load_ext mdk.jupyter.sysml_docgen_notebook
    %sysml_config --server http://127.0.0.1:8000 --project satellite-power --branch main
    %%sysml_requirement REQ-JUP-010 "Energy margin requirement" --owner Analysis
    Battery SOC shall stay above 30 percent in worst-case load simulation.

The cell execution pushes a real model element to the SysML DocGen MMS.
"""

from __future__ import annotations

import argparse
import shlex
from typing import Any

from sysml_docgen.mdk import DEFAULT_BRANCH, DEFAULT_PROJECT, DEFAULT_SERVER, MdkClient, MdkConfig


_ACTIVE_CLIENT = MdkClient()


def configure(
    server: str = DEFAULT_SERVER,
    project: str = DEFAULT_PROJECT,
    branch: str = DEFAULT_BRANCH,
    username: str = "engineer",
    role: str = "author",
    token: str = "",
    timeout: int = 20,
) -> MdkClient:
    """Configure the notebook MDK connection and return the active client."""

    global _ACTIVE_CLIENT
    _ACTIVE_CLIENT = MdkClient(
        MdkConfig(
            server=server,
            project=project,
            branch=branch,
            username=username,
            role=role,
            token=token,
            timeout=timeout,
        )
    )
    return _ACTIVE_CLIENT


def client() -> MdkClient:
    """Return the active notebook MDK client."""

    return _ACTIVE_CLIENT


def requirement(
    element_id: str,
    name: str,
    text: str,
    owner: str = "Analysis",
    verification: str = "Analysis",
    relations: list[dict[str, str]] | None = None,
    description: str = "",
    commit: bool = True,
    message: str = "Jupyter requirement sync",
) -> dict[str, Any]:
    """Create or update one SysML Requirement from a notebook cell."""

    element = requirement_element(
        element_id=element_id,
        name=name,
        text=text,
        owner=owner,
        verification=verification,
        relations=relations,
        description=description,
    )
    return push_elements([element], commit=commit, message=message)


def test_case(
    element_id: str,
    name: str,
    method: str,
    criterion: str,
    owner: str = "Analysis",
    verifies: str | None = None,
    commit: bool = True,
    message: str = "Jupyter test case sync",
) -> dict[str, Any]:
    """Create or update one SysML TestCase from a notebook analysis."""

    relations = [{"type": "verify", "target": verifies}] if verifies else []
    element = {
        "id": element_id,
        "name": name,
        "type": "TestCase",
        "stereotype": "testCase",
        "owner": owner,
        "description": method,
        "attributes": {"method": method, "criterion": criterion},
        "relations": relations,
    }
    return push_elements([element], commit=commit, message=message)


def result_constraint(
    element_id: str,
    name: str,
    expression: str,
    owner: str = "Analysis",
    constrains: str | None = None,
    refines: str | None = None,
    commit: bool = True,
    message: str = "Jupyter constraint sync",
) -> dict[str, Any]:
    """Create or update one SysML Constraint from notebook results."""

    element = constraint_element(element_id, name, expression, owner=owner, constrains=constrains or refines)
    return push_elements([element], commit=commit, message=message)


def constraint_element(
    element_id: str,
    name: str,
    expression: str,
    owner: str = "Analysis",
    constrains: str | None = None,
) -> dict[str, Any]:
    """Build a SysML Constraint element without pushing it."""

    relations = [{"type": "constrain", "target": constrains}] if constrains else []
    return {
        "id": element_id,
        "name": name,
        "type": "Constraint",
        "stereotype": "constraintBlock",
        "owner": owner,
        "description": expression,
        "attributes": {"expression": expression},
        "relations": relations,
    }


def requirement_element(
    element_id: str,
    name: str,
    text: str,
    owner: str = "Analysis",
    verification: str = "Analysis",
    relations: list[dict[str, str]] | None = None,
    description: str = "",
) -> dict[str, Any]:
    """Build a SysML Requirement element without pushing it."""

    return {
        "id": element_id,
        "name": name,
        "type": "Requirement",
        "stereotype": "requirement",
        "owner": owner,
        "description": description,
        "attributes": {"text": text, "verification": verification},
        "relations": relations or [],
    }


def push_elements(
    elements: list[dict[str, Any]],
    message: str = "Jupyter analysis sync",
    commit: bool = True,
    mdk_client: MdkClient | None = None,
) -> dict[str, Any]:
    """Push model elements from the live notebook process to MMS."""

    active_client = mdk_client or _ACTIVE_CLIENT
    return active_client.push_elements(
        elements,
        tool="jupyter",
        commit=commit,
        message=message,
        source={"tool": "jupyter", "adapter": "sysml_docgen_notebook"},
    )


def validate() -> dict[str, Any]:
    """Validate the current MMS branch from inside Jupyter."""

    return _ACTIVE_CLIENT.validate()


def pull() -> str | dict[str, Any]:
    """Pull the current MMS branch from inside Jupyter."""

    return _ACTIVE_CLIENT.pull_model("json")


def generate_document(output_format: str = "html", template: str | None = None) -> dict[str, Any]:
    """Generate a DocGen document from the current MMS branch."""

    return _ACTIVE_CLIENT.generate_document(output_format, template)


def load_ipython_extension(ipython: Any) -> None:
    """Register notebook magics when loaded through %load_ext."""

    ipython.register_magic_function(sysml_config_magic, "line", "sysml_config")
    ipython.register_magic_function(sysml_health_magic, "line", "sysml_health")
    ipython.register_magic_function(sysml_validate_magic, "line", "sysml_validate")
    ipython.register_magic_function(sysml_requirement_magic, "cell", "sysml_requirement")
    ipython.register_magic_function(sysml_test_magic, "cell", "sysml_test")


def unload_ipython_extension(_: Any) -> None:
    """IPython extension unload hook."""


def sysml_config_magic(line: str) -> dict[str, str]:
    parser = argparse.ArgumentParser(prog="%sysml_config", add_help=False)
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--project", default=DEFAULT_PROJECT)
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument("--user", default="engineer")
    parser.add_argument("--role", default="author")
    parser.add_argument("--token", default="")
    args = parser.parse_args(shlex.split(line))
    configure(
        server=args.server,
        project=args.project,
        branch=args.branch,
        username=args.user,
        role=args.role,
        token=args.token,
    )
    return {
        "server": args.server,
        "project": args.project,
        "branch": args.branch,
        "username": args.user,
        "role": args.role,
    }


def sysml_health_magic(_: str) -> dict[str, Any]:
    return _ACTIVE_CLIENT.health()


def sysml_validate_magic(_: str) -> dict[str, Any]:
    return validate()


def sysml_requirement_magic(line: str, cell: str) -> dict[str, Any]:
    parser = argparse.ArgumentParser(prog="%%sysml_requirement", add_help=False)
    parser.add_argument("element_id")
    parser.add_argument("name")
    parser.add_argument("--owner", default="Analysis")
    parser.add_argument("--verification", default="Analysis")
    parser.add_argument("--satisfy")
    parser.add_argument("--verify")
    parser.add_argument("--refine")
    parser.add_argument("--no-commit", action="store_true")
    args = parser.parse_args(shlex.split(line))
    relations = _relations_from_args(args)
    return requirement(
        args.element_id,
        args.name,
        cell.strip(),
        owner=args.owner,
        verification=args.verification,
        relations=relations,
        commit=not args.no_commit,
    )


def sysml_test_magic(line: str, cell: str) -> dict[str, Any]:
    parser = argparse.ArgumentParser(prog="%%sysml_test", add_help=False)
    parser.add_argument("element_id")
    parser.add_argument("name")
    parser.add_argument("--owner", default="Analysis")
    parser.add_argument("--criterion", default="")
    parser.add_argument("--verifies")
    parser.add_argument("--no-commit", action="store_true")
    args = parser.parse_args(shlex.split(line))
    return test_case(
        args.element_id,
        args.name,
        method=cell.strip(),
        criterion=args.criterion,
        owner=args.owner,
        verifies=args.verifies,
        commit=not args.no_commit,
    )


def _relations_from_args(args: argparse.Namespace) -> list[dict[str, str]]:
    relations = []
    for relation_type in ("satisfy", "verify", "refine"):
        target = getattr(args, relation_type, None)
        if target:
            relations.append({"type": relation_type, "target": target})
    return relations
