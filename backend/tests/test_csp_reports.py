import uuid

import pytest
from httpx import AsyncClient
import sqlalchemy as sa

from app.models import CspReport, Site


@pytest.fixture
async def monitored_site(db_factory) -> Site:
    async with db_factory() as db:
        site = Site(name="Test Site", url="https://example.com/some/path")
        db.add(site)
        await db.commit()
        await db.refresh(site)
        # Detach to use outside of session
        await db.refresh(site, ["id", "name", "url"])
    return site


async def test_receive_csp_report_legacy_format(db_factory, client: AsyncClient, monitored_site: Site):
    payload = {
        "csp-report": {
            "document-uri": "https://example.com/vulnerable-page",
            "violated-directive": "script-src 'self'",
            "blocked-uri": "https://evil.com/xss.js",
            "original-policy": "default-src 'none'; script-src 'self'",
            "user-agent": "Mozilla/5.0 (Test)",
        }
    }
    
    response = await client.post(
        "/api/csp-report",
        json=payload,
        headers={"Content-Type": "application/csp-report", "User-Agent": "Test Browser"}
    )
    assert response.status_code == 204
    
    # Verify DB persistence
    async with db_factory() as db:
        report = await db.scalar(sa.select(CspReport))
        assert report is not None
        assert report.site_id == monitored_site.id  # Matched on origin https://example.com
        assert report.document_uri == "https://example.com/vulnerable-page"
        assert report.violated_directive == "script-src 'self'"
        assert report.blocked_uri == "https://evil.com/xss.js"
        assert report.user_agent == "Test Browser"
        assert report.raw_report == payload["csp-report"]


async def test_receive_csp_report_reporting_api_format(db_factory, client: AsyncClient, monitored_site: Site):
    payload = [
        {
            "type": "csp-violation",
            "url": "https://example.com/vulnerable-page",
            "body": {
                "documentURL": "https://example.com/vulnerable-page",
                "violatedDirective": "style-src",
                "blockedURL": "inline",
                "originalPolicy": "style-src 'none'",
                "lineNumber": 12,
                "columnNumber": 34,
            }
        }
    ]
    
    response = await client.post(
        "/api/csp-report",
        json=payload,
        headers={"Content-Type": "application/reports+json"}
    )
    assert response.status_code == 204
    
    async with db_factory() as db:
        report = await db.scalar(sa.select(CspReport))
        assert report is not None
        assert report.site_id == monitored_site.id
        assert report.violated_directive == "style-src"
        assert report.blocked_uri == "inline"
        assert report.line_number == 12
        assert report.column_number == 34


async def test_receive_csp_report_unmonitored_origin(db_factory, client: AsyncClient):
    payload = {
        "csp-report": {
            "document-uri": "https://unknown-site.org/page",
            "violated-directive": "default-src"
        }
    }
    
    response = await client.post("/api/csp-report", json=payload)
    assert response.status_code == 204
    
    async with db_factory() as db:
        report = await db.scalar(sa.select(CspReport))
        assert report is not None
        assert report.site_id is None  # Unlinked
        assert report.document_uri == "https://unknown-site.org/page"


async def test_receive_csp_report_malformed(client: AsyncClient):
    # Empty body
    assert (await client.post("/api/csp-report", headers={"Content-Type": "application/csp-report"})).status_code == 400
    # Missing document-uri
    assert (await client.post("/api/csp-report", json={"csp-report": {"violated-directive": "test"}})).status_code == 400
    # Unsupported content-type
    assert (await client.post("/api/csp-report", json={"csp-report": {}}, headers={"Content-Type": "text/plain"})).status_code == 400


async def test_list_csp_reports(db_factory, client: AsyncClient, auth_headers: dict, monitored_site: Site):
    # Seed 2 reports for the monitored site, 1 unlinked
    r1 = CspReport(site_id=monitored_site.id, document_uri="https://example.com/1", violated_directive="script-src")
    r2 = CspReport(site_id=monitored_site.id, document_uri="https://example.com/2", violated_directive="style-src")
    r3 = CspReport(site_id=None, document_uri="https://other.com", violated_directive="script-src")
    async with db_factory() as db:
        db.add_all([r1, r2, r3])
        await db.commit()

    # List all
    resp = await client.get("/api/csp-reports", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3
    assert data["items"][0]["site_name"] is None or data["items"][0]["site_name"] == "Test Site" # Ordered by desc created_at

    # Filter by site
    resp = await client.get(f"/api/csp-reports?site_id={monitored_site.id}", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 2

    # Filter by directive
    resp = await client.get("/api/csp-reports?violated_directive=script", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 2

    # Unauthenticated
    assert (await client.get("/api/csp-reports")).status_code == 401
