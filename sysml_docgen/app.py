"""FastAPI application for the SysML DocGen architecture."""

from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .auth import identity_from_headers, login
from .config import (
    DEFAULT_FONT,
    DEFAULT_THEME,
    FONT_PRESETS,
    FRONTEND_DIST_DIR,
    MAX_MODEL_BYTES,
    OUTPUT_DIR,
    PANDOC_PATH,
    PDF_ENGINE,
    QUARTO_PATH,
    STATIC_DIR,
    THEME_PRESETS,
)
from .docgen import build_traceability, generate_document, html_to_pdf_bytes, pandoc_available, quarto_available
from .files import delete_output_file, list_output_files, resolve_output_file
from .metamodel import build_diagram, metamodel_payload
from .ops import configure_logging, metrics_payload, request_logging_middleware
from .repository import create_model_store
from .store import StoreError, enforce_role, project_summary
from .xmi import parse_xmi_elements


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(
        title="SysML DocGen",
        version="3.0",
        description="基于 SysML 模型的文档自动生成系统：MMS / VE / MDK / DocGen 一体化服务。",
    )
    app.state.store = create_model_store()
    app.state.frontend_dir = FRONTEND_DIST_DIR if (FRONTEND_DIST_DIR / "index.html").exists() else STATIC_DIR
    app.middleware("http")(request_logging_middleware)

    @app.middleware("http")
    async def project_access_middleware(request: Request, call_next: Any) -> Response:
        project_id = project_id_from_path(request.url.path)
        if project_id:
            try:
                project = app.state.store.get_project(project_id)
                identity = identity_from_headers(request.headers)
                enforce_role(request.method, effective_project_role(project, identity))
            except StoreError as exc:
                return JSONResponse({"error": str(exc)}, status_code=exc.status_code)
        return await call_next(request)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(StoreError)
    async def store_error_handler(_: Request, exc: StoreError) -> JSONResponse:
        return JSONResponse({"error": str(exc)}, status_code=exc.status_code)

    @app.exception_handler(HTTPException)
    async def http_error_handler(_: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    @app.get("/api/health", tags=["MMS"])
    async def health(identity: dict[str, str] = Depends(read_identity)) -> dict[str, Any]:
        store = app.state.store
        backend = "mongodb" if store.__class__.__name__ == "MongoModelStore" else "sqlite"
        doc_formats = ["html", "markdown", "pdf", "docx"]
        return {
            "status": "ok",
            "service": "SysML DocGen MMS",
            "version": "3.0",
            "framework": "fastapi",
            "storage": backend,
            "components": ["MMS", "MDK", "DocGen", "VE"],
            "capabilities": {
                "model_exchange": ["json", "xmi"],
                "document_formats": doc_formats,
                "pdf_engine": PDF_ENGINE,
                "pandoc": pandoc_available(),
                "pandoc_path": PANDOC_PATH,
                "quarto": quarto_available(),
                "quarto_path": QUARTO_PATH,
                "max_model_bytes": MAX_MODEL_BYTES,
                "output_dir": str(OUTPUT_DIR),
                "openapi": "/docs",
                "access_control": "project roles: admin / author / reader",
                "frontend": "external-dist" if app.state.frontend_dir != STATIC_DIR else "static-ve",
                "frontend_dir": str(app.state.frontend_dir),
                "themes": list(THEME_PRESETS.keys()),
                "fonts": list(FONT_PRESETS.keys()),
            },
            "identity": identity,
        }

    @app.get("/api/docgen/config", tags=["DocGen"])
    async def docgen_config() -> dict[str, Any]:
        return {
            "themes": {k: {"label": v["label"]} for k, v in THEME_PRESETS.items()},
            "fonts": {k: {"label": v["label"], "family": v["family"]} for k, v in FONT_PRESETS.items()},
            "defaults": {"theme": DEFAULT_THEME, "font": DEFAULT_FONT},
            "pandoc_available": pandoc_available(),
            "quarto_available": quarto_available(),
            "docx_available": True,
            "pdf_engine": PDF_ENGINE,
        }

    @app.get("/api/ready", tags=["Ops"])
    async def ready() -> dict[str, Any]:
        projects = app.state.store.list_projects()
        return {
            "ready": True,
            "storage": "mongodb" if app.state.store.__class__.__name__ == "MongoModelStore" else "sqlite",
            "projects": len(projects),
            "frontend": str(app.state.frontend_dir),
            "outputs": str(OUTPUT_DIR),
        }

    @app.get("/api/metrics", tags=["Ops"])
    async def metrics() -> Response:
        return Response(metrics_payload(), media_type="text/plain; version=0.0.4")

    @app.post("/api/auth/login", tags=["MMS"])
    async def auth_login(payload: dict[str, Any]) -> dict[str, Any]:
        identity = login(payload.get("username", ""), payload.get("password", ""))
        if not identity:
            raise HTTPException(status_code=401, detail="用户名或密码错误")
        return {"identity": identity}

    @app.get("/api/metamodel", tags=["MMS"])
    async def metamodel(_: dict[str, str] = Depends(authorize_read)) -> dict[str, Any]:
        return metamodel_payload()

    @app.get("/api/projects", tags=["MMS"])
    async def list_projects(_: dict[str, str] = Depends(authorize_read)) -> dict[str, Any]:
        return {"projects": app.state.store.list_projects()}

    @app.post("/api/projects", tags=["MMS"])
    async def create_project(payload: dict[str, Any], identity: dict[str, str] = Depends(authorize_write)) -> dict[str, Any]:
        return {"project": app.state.store.create_project(payload, identity["username"])}

    @app.get("/api/projects/{project_id}", tags=["MMS"])
    async def get_project(project_id: str, _: dict[str, str] = Depends(authorize_read)) -> dict[str, Any]:
        project = app.state.store.get_project(project_id)
        payload = project_summary(project)
        payload["roles"] = project.get("roles", {})
        return {"project": payload}

    @app.get("/api/projects/{project_id}/branches", tags=["MMS"])
    async def list_branches(project_id: str, _: dict[str, str] = Depends(authorize_read)) -> dict[str, Any]:
        return {"branches": app.state.store.list_branches(project_id)}

    @app.post("/api/projects/{project_id}/branches", tags=["MMS"])
    async def create_branch(
        project_id: str,
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        return {"branch": app.state.store.create_branch(project_id, payload, identity["username"])}

    @app.post("/api/projects/{project_id}/branches/{target_branch}/merge", tags=["MMS"])
    async def merge_branch(
        project_id: str,
        target_branch: str,
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        return app.state.store.merge_branch(
            project_id,
            target_branch,
            payload.get("source", "main"),
            identity["username"],
            bool(payload.get("force", False)),
        )

    @app.get("/api/projects/{project_id}/branches/{branch}/elements", tags=["MMS"])
    async def list_elements(
        project_id: str,
        branch: str,
        type: str | None = None,
        q: str | None = None,
        _: dict[str, str] = Depends(authorize_read),
    ) -> dict[str, Any]:
        return {"elements": app.state.store.list_elements(project_id, branch, type, q)}

    @app.post("/api/projects/{project_id}/branches/{branch}/elements", tags=["MMS"])
    async def create_element(
        project_id: str,
        branch: str,
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        return {"element": app.state.store.upsert_element(project_id, branch, payload, identity["username"])}

    @app.get("/api/projects/{project_id}/branches/{branch}/elements/{element_id}", tags=["MMS"])
    async def get_element(
        project_id: str,
        branch: str,
        element_id: str,
        _: dict[str, str] = Depends(authorize_read),
    ) -> dict[str, Any]:
        return {"element": app.state.store.get_element(project_id, branch, element_id)}

    @app.put("/api/projects/{project_id}/branches/{branch}/elements/{element_id}", tags=["MMS"])
    async def update_element(
        project_id: str,
        branch: str,
        element_id: str,
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        payload["id"] = element_id
        return {"element": app.state.store.upsert_element(project_id, branch, payload, identity["username"])}

    @app.delete("/api/projects/{project_id}/branches/{branch}/elements/{element_id}", tags=["MMS"])
    async def delete_element(
        project_id: str,
        branch: str,
        element_id: str,
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        return app.state.store.delete_element(project_id, branch, element_id, identity["username"])

    @app.post("/api/projects/{project_id}/branches/{branch}/commit", tags=["MMS"])
    async def commit(
        project_id: str,
        branch: str,
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        return {"commit": app.state.store.commit(project_id, branch, payload.get("message", "保存模型快照"), identity["username"])}

    @app.get("/api/projects/{project_id}/commits", tags=["MMS"])
    async def list_commits(project_id: str, _: dict[str, str] = Depends(authorize_read)) -> dict[str, Any]:
        return {"commits": app.state.store.list_commits(project_id)}

    @app.get("/api/projects/{project_id}/branches/{branch}/diff", tags=["MMS"])
    async def diff(
        project_id: str,
        branch: str,
        from_ref: str | None = Query(default=None, alias="from"),
        to: str | None = None,
        _: dict[str, str] = Depends(authorize_read),
    ) -> dict[str, Any]:
        return app.state.store.diff_commits(project_id, branch, from_ref, to)

    @app.post("/api/projects/{project_id}/branches/{branch}/rollback", tags=["MMS"])
    async def rollback(
        project_id: str,
        branch: str,
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        return app.state.store.rollback(project_id, branch, payload.get("commit", ""), identity["username"])

    @app.get("/api/projects/{project_id}/tags", tags=["MMS"])
    async def list_tags(project_id: str, _: dict[str, str] = Depends(authorize_read)) -> dict[str, Any]:
        return {"tags": app.state.store.list_tags(project_id)}

    @app.post("/api/projects/{project_id}/tags", tags=["MMS"])
    async def create_tag(
        project_id: str,
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        return {"tag": app.state.store.create_tag(project_id, payload, identity["username"])}

    @app.get("/api/projects/{project_id}/audit", tags=["MMS"])
    async def list_audit(
        project_id: str,
        limit: int = 80,
        _: dict[str, str] = Depends(authorize_read),
    ) -> dict[str, Any]:
        return {"events": app.state.store.list_audit(project_id, limit)}

    @app.post("/api/projects/{project_id}/branches/{branch}/import", tags=["MDK"])
    async def import_model(
        project_id: str,
        branch: str,
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        return app.state.store.import_elements(project_id, branch, payload, identity["username"])

    @app.get("/api/projects/{project_id}/branches/{branch}/export", tags=["MDK"])
    async def export_model(
        project_id: str,
        branch: str,
        format: str = "json",
        _: dict[str, str] = Depends(authorize_read),
    ) -> Any:
        if format.lower() == "xmi":
            return Response(app.state.store.export_branch_xmi(project_id, branch), media_type="application/xml")
        return app.state.store.export_branch(project_id, branch)

    @app.get("/api/projects/{project_id}/branches/{branch}/validate", tags=["MMS"])
    async def validate_model(project_id: str, branch: str, _: dict[str, str] = Depends(authorize_read)) -> dict[str, Any]:
        return app.state.store.validate_branch(project_id, branch)

    @app.post("/api/mms/projects", tags=["MMS"])
    async def mms_create_project(
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        return {"project": app.state.store.create_project(payload, identity["username"])}

    @app.get("/api/mms/models/{model_name}", tags=["MMS"])
    async def mms_get_model(
        model_name: str,
        project: str = "satellite-power",
        branch: str = "main",
        _: dict[str, str] = Depends(authorize_read),
    ) -> dict[str, Any]:
        elements = app.state.store.get_branch(project, branch).get("elements", {})
        if model_name in elements:
            return {"model": elements[model_name]}
        exported = app.state.store.export_branch(project, branch)
        exported["model_name"] = model_name
        return {"model": exported}

    @app.post("/api/mms/models", tags=["MMS"])
    async def mms_create_model(
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        project_id = payload.get("project") or payload.get("project_id") or "satellite-power"
        branch = payload.get("branch") or "main"
        model = payload.get("model") or payload
        result = app.state.store.import_elements(project_id, branch, normalize_model_payload(model), identity["username"])
        if payload.get("commit", True):
            result["commit"] = app.state.store.commit(
                project_id,
                branch,
                payload.get("message", f"Create model {payload.get('name', project_id)}"),
                identity["username"],
            )
        return result

    @app.put("/api/mms/models/{model_name}", tags=["MMS"])
    async def mms_update_model(
        model_name: str,
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        payload.setdefault("name", model_name)
        return await mms_create_model(payload, identity)

    @app.delete("/api/mms/models/{model_name}", tags=["MMS"])
    async def mms_delete_model(
        model_name: str,
        project: str = "satellite-power",
        branch: str = "main",
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        return app.state.store.delete_element(project, branch, model_name, identity["username"])

    @app.post("/api/mms/branches", tags=["MMS"])
    async def mms_create_branch(
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        project_id = payload.get("project") or payload.get("project_id") or payload.get("model_name") or "satellite-power"
        return {"branch": app.state.store.create_branch(project_id, payload, identity["username"])}

    @app.get("/api/mms/branches", tags=["MMS"])
    async def mms_get_branches(
        project: str = "satellite-power",
        _: dict[str, str] = Depends(authorize_read),
    ) -> dict[str, Any]:
        return {"branches": app.state.store.list_branches(project)}

    @app.get("/api/projects/{project_id}/branches/{branch}/diagram", tags=["VE"])
    async def diagram(
        project_id: str,
        branch: str,
        type: str = "requirements",
        _: dict[str, str] = Depends(authorize_read),
    ) -> dict[str, Any]:
        elements = app.state.store.get_branch(project_id, branch).get("elements", {})
        return {"diagram": build_diagram(elements, type)}

    @app.get("/api/projects/{project_id}/branches/{branch}/traceability", tags=["VE"])
    async def traceability(project_id: str, branch: str, _: dict[str, str] = Depends(authorize_read)) -> dict[str, Any]:
        elements = app.state.store.get_branch(project_id, branch).get("elements", {})
        return {"traceability": build_traceability(elements)}

    @app.get("/api/projects/{project_id}/branches/{branch}/documents", tags=["DocGen"])
    async def list_documents(project_id: str, branch: str, _: dict[str, str] = Depends(authorize_read)) -> dict[str, Any]:
        return {"documents": app.state.store.list_documents(project_id, branch)}

    @app.post("/api/projects/{project_id}/branches/{branch}/documents", tags=["DocGen"])
    async def create_document(
        project_id: str,
        branch: str,
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        project = app.state.store.get_project(project_id)
        document = generate_document(
            project,
            branch,
            payload.get("template"),
            payload.get("format", "html"),
            payload.get("theme", DEFAULT_THEME),
            payload.get("font", DEFAULT_FONT),
        )
        app.state.store.touch_project(project_id)
        app.state.store.save()
        app.state.store.record_audit(project_id, branch, "generate_document", identity["username"], document["id"])
        return {"document": document}

    @app.get("/api/projects/{project_id}/branches/{branch}/documents/{document_id}", tags=["DocGen"])
    async def get_document(
        project_id: str,
        branch: str,
        document_id: str,
        format: str = "json",
        _: dict[str, str] = Depends(authorize_read),
    ) -> Any:
        document = app.state.store.get_document(project_id, branch, document_id)
        if format == "html":
            return HTMLResponse(document["html"])
        if format == "markdown":
            return Response(document["markdown"], media_type="text/markdown")
        if format == "pdf":
            pdf_base64 = document.get("pdf_base64", "")
            pdf_bytes = (
                base64.b64decode(pdf_base64)
                if pdf_base64
                else html_to_pdf_bytes(
                    document.get("html", ""),
                    document.get("markdown", ""),
                    document.get("title", "SysML 文档"),
                )
            )
            return Response(pdf_bytes, media_type="application/pdf")
        if format == "docx":
            docx_base64 = document.get("docx_base64", "")
            if docx_base64:
                return Response(
                    base64.b64decode(docx_base64),
                    media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                )
            raise HTTPException(status_code=404, detail="DOCX not available, please regenerate this document")
        return {"document": document}

    @app.post("/api/mdk/parse", tags=["MDK"])
    async def parse_sysml(payload: dict[str, Any], _: dict[str, str] = Depends(authorize_read)) -> dict[str, Any]:
        source_format = str(payload.get("type") or payload.get("format") or "").lower()
        content = payload.get("content") or payload.get("xmi") or payload.get("json") or ""
        filename = str(payload.get("file_path") or payload.get("filename") or "")
        if len(str(content).encode("utf-8")) > MAX_MODEL_BYTES:
            raise HTTPException(status_code=413, detail="模型文件超过 10MB 限制")
        if not source_format:
            source_format = "xmi" if filename.lower().endswith((".xmi", ".xml")) else "json"

        if source_format == "xmi":
            elements = parse_xmi_elements(str(content))
        else:
            raw_model = json.loads(content) if isinstance(content, str) else content
            elements_payload = raw_model.get("elements", raw_model) if isinstance(raw_model, dict) else raw_model
            elements = list(elements_payload.values()) if isinstance(elements_payload, dict) else list(elements_payload or [])

        return {
            "parsed_model": {
                "name": payload.get("model_name") or Path(filename).stem or "ParsedModel",
                "type": source_format,
                "elements": elements,
                "element_count": len(elements),
            }
        }

    @app.post("/api/mdk/push", tags=["MDK"])
    async def mdk_push_model(
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> dict[str, Any]:
        project_id = payload.get("project") or payload.get("project_id") or "satellite-power"
        branch = payload.get("branch") or "main"
        model = payload.get("model") or payload
        result = app.state.store.import_elements(project_id, branch, model, payload.get("username") or identity["username"])
        if payload.get("commit"):
            result["commit"] = app.state.store.commit(
                project_id,
                branch,
                payload.get("message", "MDK push model"),
                payload.get("username") or identity["username"],
            )
        return result

    @app.get("/api/mdk/pull", tags=["MDK"])
    async def mdk_pull_model(
        project: str = "satellite-power",
        branch: str = "main",
        format: str = "json",
        _: dict[str, str] = Depends(authorize_read),
    ) -> Any:
        if format.lower() == "xmi":
            return Response(app.state.store.export_branch_xmi(project, branch), media_type="application/xml")
        return app.state.store.export_branch(project, branch)

    @app.post("/api/mdk/generate", tags=["MDK", "DocGen"])
    async def mdk_generate_doc(
        payload: dict[str, Any],
        identity: dict[str, str] = Depends(authorize_write),
    ) -> Any:
        project_id = payload.get("project") or payload.get("project_id") or payload.get("model_name") or "satellite-power"
        branch = payload.get("branch") or "main"
        doc_type = payload.get("doc_type") or payload.get("format") or "html"
        project = app.state.store.get_project(project_id)
        document = generate_document(
            project, branch, payload.get("template"), doc_type,
            payload.get("theme", DEFAULT_THEME),
            payload.get("font", DEFAULT_FONT),
        )
        app.state.store.touch_project(project_id)
        app.state.store.save()
        app.state.store.record_audit(project_id, branch, "mdk_generate_doc", identity["username"], document["id"])
        if doc_type == "html":
            return HTMLResponse(document["html"])
        if doc_type == "markdown":
            return Response(document["markdown"], media_type="text/markdown")
        if doc_type == "pdf":
            return Response(base64.b64decode(document["pdf_base64"]), media_type="application/pdf")
        if doc_type == "docx":
            docx_b64 = document.get("docx_base64", "")
            if docx_b64:
                return Response(base64.b64decode(docx_b64), media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
            raise HTTPException(status_code=422, detail="DOCX not available, please regenerate this document")
        return {"document": document}

    @app.post("/api/docgen/docx", tags=["DocGen"])
    async def generate_docx(payload: dict[str, Any], identity: dict[str, str] = Depends(authorize_write)) -> Response:
        project_id = payload.get("project") or payload.get("model_name") or "satellite-power"
        branch = payload.get("branch") or "main"
        document = generate_document(
            app.state.store.get_project(project_id), branch, payload.get("template"), "docx",
            payload.get("theme", DEFAULT_THEME), payload.get("font", DEFAULT_FONT),
        )
        app.state.store.record_audit(project_id, branch, "generate_docx", identity["username"], document["id"])
        docx_b64 = document.get("docx_base64", "")
        if not docx_b64:
            raise HTTPException(status_code=422, detail="DOCX not available, please regenerate this document")
        return Response(base64.b64decode(docx_b64), media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")

    @app.post("/api/docgen/html", tags=["DocGen"])
    async def generate_html(payload: dict[str, Any], identity: dict[str, str] = Depends(authorize_write)) -> HTMLResponse:
        project_id = payload.get("project") or payload.get("model_name") or "satellite-power"
        branch = payload.get("branch") or "main"
        document = generate_document(
            app.state.store.get_project(project_id), branch, payload.get("template"), "html",
            payload.get("theme", DEFAULT_THEME), payload.get("font", DEFAULT_FONT),
        )
        app.state.store.record_audit(project_id, branch, "generate_html", identity["username"], document["id"])
        return HTMLResponse(document["html"])

    @app.post("/api/docgen/pdf", tags=["DocGen"])
    async def generate_pdf(payload: dict[str, Any], identity: dict[str, str] = Depends(authorize_write)) -> Response:
        project_id = payload.get("project") or payload.get("model_name") or "satellite-power"
        branch = payload.get("branch") or "main"
        document = generate_document(
            app.state.store.get_project(project_id), branch, payload.get("template"), "pdf",
            payload.get("theme", DEFAULT_THEME), payload.get("font", DEFAULT_FONT),
        )
        app.state.store.record_audit(project_id, branch, "generate_pdf", identity["username"], document["id"])
        return Response(base64.b64decode(document["pdf_base64"]), media_type="application/pdf")

    @app.get("/api/files", tags=["Ops"])
    async def files(_: dict[str, str] = Depends(authorize_read)) -> dict[str, Any]:
        return {"files": list_output_files()}

    @app.get("/api/files/{filename}", tags=["Ops"])
    async def download_file(filename: str, _: dict[str, str] = Depends(authorize_read)) -> FileResponse:
        try:
            return FileResponse(resolve_output_file(filename))
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="文件不存在") from exc

    @app.delete("/api/files/{filename}", tags=["Ops"])
    async def remove_file(filename: str, _: dict[str, str] = Depends(authorize_write)) -> dict[str, str]:
        try:
            delete_output_file(filename)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="文件不存在") from exc
        return {"deleted": filename}

    app.mount("/", StaticFiles(directory=app.state.frontend_dir, html=True), name="ve")
    return app


async def read_identity(
    request: Request,
    authorization: str | None = Header(default=None),
    x_user: str | None = Header(default=None),
    x_role: str | None = Header(default=None),
) -> dict[str, str]:
    headers = {
        "Authorization": authorization or "",
        "X-User": x_user or "engineer",
        "X-Role": x_role or "author",
    }
    return identity_from_headers(headers)


async def authorize_read(request: Request, identity: dict[str, str] = Depends(read_identity)) -> dict[str, str]:
    enforce_role(request.method, identity["role"])
    return identity


async def authorize_write(request: Request, identity: dict[str, str] = Depends(read_identity)) -> dict[str, str]:
    enforce_role(request.method, identity["role"])
    return identity


def normalize_model_payload(model: dict[str, Any]) -> dict[str, Any]:
    if model.get("format") == "xmi" or model.get("xmi"):
        xmi_text = model.get("xmi") or model.get("content") or ""
        if len(str(xmi_text).encode("utf-8")) > MAX_MODEL_BYTES:
            raise HTTPException(status_code=413, detail="模型文件超过 10MB 限制")
        return {"format": "xmi", "xmi": xmi_text}

    if "elements" in model:
        encoded = json.dumps(model["elements"], ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_MODEL_BYTES:
            raise HTTPException(status_code=413, detail="模型文件超过 10MB 限制")
        return {"format": "json", "elements": model["elements"]}

    element = {
        "id": model.get("id") or model.get("name"),
        "name": model.get("name") or model.get("id"),
        "type": model.get("type", "Block"),
        "stereotype": model.get("stereotype", ""),
        "description": model.get("description", ""),
        "owner": model.get("owner", ""),
        "attributes": model.get("attributes", model.get("content", {})),
        "relations": model.get("relations", []),
    }
    return {"format": "json", "elements": [element]}


def project_id_from_path(path: str) -> str:
    parts = [part for part in path.strip("/").split("/") if part]
    if len(parts) >= 3 and parts[0] == "api" and parts[1] == "projects":
        return unquote(parts[2])
    return ""


def effective_project_role(project: dict[str, Any], identity: dict[str, str]) -> str:
    username = identity.get("username", "")
    roles = project.get("roles", {})
    for role in ("admin", "author", "reader"):
        if username in roles.get(role, []):
            return role
    return "reader" if roles else identity.get("role", "reader")


app = create_app()
