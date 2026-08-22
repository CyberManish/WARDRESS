"""CSP violation reporting (CYBER-14).

Two endpoints:
- POST /api/csp-report  — unauthenticated, receives browser-standard CSP
  violation reports and persists them.  Browsers send these automatically
  when a Content-Security-Policy report-uri / report-to directive fires.
- GET  /api/csp-reports  — authenticated (any role), paginated + filterable
  listing for the dashboard.

Site matching: the document-uri's origin (scheme + netloc) is compared
against every active monitored site's origin using stdlib urlparse —
the same library the rest of the project uses for URL handling.
"""

import logging
import uuid
from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.deps import CurrentUser
from app.models import CspReport, Site
from app.schemas import CspReportOut, CspReportPage

logger = logging.getLogger(__name__)

router = APIRouter(tags=["csp"])

DB = Annotated[AsyncSession, Depends(get_db)]

# Maximum body size for a CSP report (browsers send small JSON payloads;
# anything over 64 KB is suspicious or malformed).
_MAX_REPORT_BYTES = 64 * 1024


def _trunc(value: str | None, limit: int) -> str | None:
    """Truncate a string to *limit* characters, or return None."""
    if value is None:
        return None
    return str(value)[:limit]


def _safe_int(value) -> int | None:
    """Coerce to int or return None — never raise."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _origin(url: str) -> str:
    """Extract the origin (scheme + netloc) from a URL for matching."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}".lower().rstrip("/")


async def _match_site(db: AsyncSession, document_uri: str) -> uuid.UUID | None:
    """Find a monitored site whose URL origin matches the report's
    document-uri origin.  Returns the site ID or None."""
    report_origin = _origin(document_uri)
    if not report_origin or report_origin == "://":
        return None
    # Fetch all active sites and compare origins.  The sites table is
    # small (tens to low hundreds); a sequential scan is fine and avoids
    # building a LIKE/regex query that varies across dialects.
    sites = (await db.scalars(select(Site).where(Site.is_active.is_(True)))).all()
    for site in sites:
        if _origin(site.url) == report_origin:
            return site.id
    return None


# ---- POST /api/csp-report (unauthenticated, browser-facing) ----


@router.post("/api/csp-report", status_code=status.HTTP_204_NO_CONTENT)
async def receive_csp_report(request: Request, db: DB) -> Response:
    """Receive a browser-standard CSP violation report.

    Accepts both the legacy ``{"csp-report": {...}}`` format and the
    newer Reporting API v1 ``[{"body": {...}, ...}]`` format.  Unknown
    fields are silently ignored; missing required fields return 400.
    """
    # Content-type guard: browsers send application/csp-report or
    # application/json (Reporting API v1).  Reject anything else early.
    ct = (request.headers.get("content-type") or "").lower().split(";")[0].strip()
    if ct not in ("application/csp-report", "application/json", "application/reports+json"):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Unsupported content type; expected application/csp-report or application/json",
        )

    body = await request.body()
    if len(body) > _MAX_REPORT_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Report too large")
    if not body.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty report body")

    import json

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid JSON") from None

    # Extract the inner report dict.
    # Legacy format: {"csp-report": { ... }}
    # Reporting API v1: [{"body": { ... }, "type": "csp-violation", ...}]
    report: dict | None = None
    if isinstance(payload, dict) and "csp-report" in payload:
        report = payload["csp-report"]
    elif isinstance(payload, list) and payload:
        first = payload[0]
        if isinstance(first, dict) and isinstance(first.get("body"), dict):
            report = first["body"]
    elif isinstance(payload, dict):
        # Some browsers send the report fields at the top level.
        report = payload

    if not isinstance(report, dict):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Could not parse CSP report payload")

    # The only truly required field is document-uri.
    document_uri = report.get("document-uri") or report.get("documentURL") or ""
    violated_directive = (
        report.get("violated-directive")
        or report.get("violatedDirective")
        or report.get("effective-directive")
        or report.get("effectiveDirective")
        or "unknown"
    )

    if not document_uri:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing document-uri in CSP report")

    site_id = await _match_site(db, document_uri)

    user_agent = _trunc(request.headers.get("user-agent"), 512)

    row = CspReport(
        document_uri=_trunc(document_uri, 2048) or "",
        violated_directive=_trunc(violated_directive, 512) or "unknown",
        effective_directive=_trunc(
            report.get("effective-directive") or report.get("effectiveDirective"), 512
        ),
        blocked_uri=_trunc(report.get("blocked-uri") or report.get("blockedURL"), 2048),
        original_policy=_trunc(report.get("original-policy") or report.get("originalPolicy"), 4096),
        referrer=_trunc(report.get("referrer"), 2048),
        source_file=_trunc(report.get("source-file") or report.get("sourceFile"), 2048),
        line_number=_safe_int(report.get("line-number") or report.get("lineNumber")),
        column_number=_safe_int(report.get("column-number") or report.get("columnNumber")),
        status_code=_safe_int(report.get("status-code") or report.get("statusCode")),
        user_agent=user_agent,
        site_id=site_id,
        raw_report=report,
    )
    db.add(row)
    await db.commit()

    logger.info(
        "CSP report stored: document_uri=%s violated=%s site_id=%s",
        document_uri[:120],
        violated_directive[:80],
        site_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---- GET /api/csp-reports (authenticated, dashboard-facing) ----


@router.get("/api/csp-reports", response_model=CspReportPage)
async def list_csp_reports(
    user: CurrentUser,
    db: DB,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    site_id: Annotated[uuid.UUID | None, Query()] = None,
    violated_directive: Annotated[str | None, Query(max_length=128)] = None,
) -> CspReportPage:
    """Paginated listing of CSP violation reports, filterable by site and
    violated directive prefix."""
    query = select(CspReport)
    if site_id is not None:
        query = query.where(CspReport.site_id == site_id)
    if violated_directive:
        query = query.where(CspReport.violated_directive.startswith(violated_directive))

    total = await db.scalar(select(func.count()).select_from(query.subquery()))
    rows = (
        await db.scalars(query.order_by(CspReport.created_at.desc()).offset(offset).limit(limit))
    ).all()

    # Resolve site names in one query for display.
    site_ids = {r.site_id for r in rows if r.site_id is not None}
    names: dict[uuid.UUID, str] = {}
    if site_ids:
        site_rows = (
            await db.execute(select(Site.id, Site.name).where(Site.id.in_(site_ids)))
        ).all()
        names = {row[0]: row[1] for row in site_rows}

    items = [
        CspReportOut(
            **{
                k: v
                for k, v in CspReportOut.model_validate(r).model_dump().items()
                if k != "site_name"
            },
            site_name=names.get(r.site_id) if r.site_id else None,
        )
        for r in rows
    ]
    return CspReportPage(
        items=items,
        total=int(total or 0),
        offset=offset,
        limit=limit,
    )
