"""Command-line MDK adapter for Cameo, Jupyter, MATLAB, JSON, and XMI flows."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sysml_docgen.mdk import (
    DEFAULT_BRANCH,
    DEFAULT_PROJECT,
    DEFAULT_SERVER,
    MdkClient,
    MdkConfig,
    MdkError,
    load_model_file,
    write_document,
)


def make_client(args: argparse.Namespace) -> MdkClient:
    return MdkClient(
        MdkConfig(
            server=args.server,
            project=args.project,
            branch=args.branch,
            username=args.user,
            role=args.role,
            token=args.token,
        )
    )


def parse(args: argparse.Namespace) -> None:
    model = load_model_file(args.file, args.tool)
    summary = {
        "source": model.get("source", {}),
        "format": model["format"],
        "element_count": len(model.get("elements", [])),
        "elements": model.get("elements", []),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def push(args: argparse.Namespace) -> None:
    result = make_client(args).push_file(
        args.file,
        tool=args.tool,
        commit=args.commit,
        message=args.message,
        validate=args.validate,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


def pull(args: argparse.Namespace) -> None:
    result = make_client(args).pull_model(args.format)
    text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"已导出到 {args.out}")
    else:
        print(text)


def validate(args: argparse.Namespace) -> None:
    result = make_client(args).validate()
    print(json.dumps(result, ensure_ascii=False, indent=2))


def generate(args: argparse.Namespace) -> None:
    template = Path(args.template).read_text(encoding="utf-8") if args.template else None
    document = make_client(args).generate_document(args.format, template)
    if args.out:
        write_document(document, args.format, args.out)
        print(f"已生成文档 {args.out}")
        return
    if args.format == "pdf":
        sys.stdout.buffer.write(base64.b64decode(document["pdf_base64"]))
    else:
        key = "markdown" if args.format == "markdown" else "html"
        print(document[key])


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--project", default=DEFAULT_PROJECT)
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument("--user", default="engineer")
    parser.add_argument("--role", choices=["admin", "author", "reader"], default="author")
    parser.add_argument("--token", default="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SysML DocGen MDK sync client")
    add_common_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    parse_parser = subparsers.add_parser("parse", help="parse a tool model into the normalized MDK payload")
    parse_parser.add_argument("--file", required=True)
    parse_parser.add_argument("--tool", default="auto")
    parse_parser.set_defaults(func=parse)

    push_parser = subparsers.add_parser("push", help="push a tool model into MMS")
    push_parser.add_argument("--file", required=True)
    push_parser.add_argument("--tool", default="auto")
    push_parser.add_argument("--commit", action="store_true")
    push_parser.add_argument("--message", default="MDK 同步提交")
    push_parser.add_argument("--validate", action="store_true")
    push_parser.set_defaults(func=push)

    pull_parser = subparsers.add_parser("pull", help="pull a branch model from MMS")
    pull_parser.add_argument("--out")
    pull_parser.add_argument("--format", choices=["json", "xmi"], default="json")
    pull_parser.set_defaults(func=pull)

    validate_parser = subparsers.add_parser("validate", help="validate the branch model after tool sync")
    validate_parser.set_defaults(func=validate)

    gen_parser = subparsers.add_parser("generate", help="generate a document through DocGen")
    gen_parser.add_argument("--template")
    gen_parser.add_argument("--format", choices=["html", "markdown", "pdf"], default="html")
    gen_parser.add_argument("--out")
    gen_parser.set_defaults(func=generate)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except MdkError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main(sys.argv[1:])
