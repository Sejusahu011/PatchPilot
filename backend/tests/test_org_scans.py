from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@patch("app.main.get_db", new_callable=AsyncMock)
@patch("app.main.fetch_org_repos", new_callable=AsyncMock)
@patch("app.main._run_org_batch")
def test_scan_org_valid_url(mock_run_batch, mock_fetch, mock_get_db, client):
    mock_db = AsyncMock()
    mock_get_db.return_value.__aenter__.return_value = mock_db
    mock_fetch.return_value = [
        {
            "html_url": "https://github.com/test/repo1",
            "default_branch": "main",
            "name": "repo1",
        }
    ]
    response = client.post(
        "/api/scans/org", json={"org_url": "https://github.com/test"}
    )

    assert response.status_code == 200
    assert response.json()["repo_count"] == 1
    assert "org_job_id" in response.json()


def test_scan_org_invalid_url(client):
    response = client.post(
        "/api/scans/org", json={"org_url": "https://gitlab.com/test"}
    )
    assert response.status_code == 400


@patch("app.main.fetch_org_repos", new_callable=AsyncMock)
def test_scan_org_empty(mock_fetch, client):
    mock_fetch.return_value = []
    response = client.post(
        "/api/scans/org", json={"org_url": "https://github.com/empty"}
    )
    assert response.status_code == 400


@pytest.mark.anyio
@patch("app.main.httpx.AsyncClient.get")
async def test_fetch_org_repos(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {"html_url": "url1", "default_branch": "main", "name": "r1", "archived": False},
        {"html_url": "url2", "default_branch": "main", "name": "r2", "archived": True},
    ]
    mock_get.return_value = mock_response

    from app.main import fetch_org_repos

    repos = await fetch_org_repos("test")

    assert len(repos) == 1
    assert repos[0]["name"] == "r1"


@patch("app.main.get_db", new_callable=AsyncMock)
def test_get_org_status_success(mock_get_db, client):
    mock_cursor = AsyncMock()
    mock_cursor.fetchone.return_value = {"status": "scanning"}
    mock_cursor.fetchall.return_value = [
        {"job_id": "1", "project_name": "r1", "status": "completed"}
    ]
    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_cursor
    mock_get_db.return_value = mock_db

    response = client.get("/api/scans/org/123/status")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "scanning"
    assert len(data["repos"]) == 1
    assert data["repos"][0]["project_name"] == "r1"


@patch("app.main.get_db", new_callable=AsyncMock)
def test_get_org_status_not_found(mock_get_db, client):
    mock_cursor = AsyncMock()
    mock_cursor.fetchone.return_value = None
    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_cursor
    mock_get_db.return_value = mock_db

    response = client.get("/api/scans/org/999/status")
    assert response.status_code == 404


@patch("app.main.get_db", new_callable=AsyncMock)
def test_abort_org_scan(mock_get_db, client):
    mock_db = AsyncMock()
    mock_get_db.return_value = mock_db

    response = client.post("/api/scans/org/123/abort")

    assert response.status_code == 200
    assert response.json() == {
        "status": "aborted",
        "org_job_id": "123",
        "mode": "pending",
    }


@patch("app.main.get_db", new_callable=AsyncMock)
def test_stream_org_status(mock_get_db, client):
    mock_cursor = AsyncMock()
    mock_cursor.fetchone.return_value = {"status": "completed"}
    mock_cursor.fetchall.return_value = [
        {"job_id": "1", "project_name": "r1", "status": "completed"}
    ]

    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_cursor
    mock_get_db.return_value = mock_db

    response = client.get("/api/scans/org/123/stream")

    assert response.status_code == 200
    assert "data:" in response.text
    assert "completed" in response.text
    assert "r1" in response.text


@patch("app.main.get_db", new_callable=AsyncMock)
def test_get_org_summary(mock_get_db, client):
    mock_db = AsyncMock()
    mock_get_db.return_value = mock_db
    mock_cursor_1 = AsyncMock()
    mock_cursor_1.fetchone.return_value = {"total": 10, "completed": 8, "failed": 2}

    mock_cursor_2 = AsyncMock()
    mock_cursor_2.fetchall.return_value = [{"severity": "CRITICAL", "count": 5}]

    mock_cursor_3 = AsyncMock()
    mock_cursor_3.fetchall.return_value = [{"repo_name": "frontend-app", "count": 12}]

    mock_db.execute.side_effect = [mock_cursor_1, mock_cursor_2, mock_cursor_3]

    response = client.get("/api/scans/org/123/summary")

    assert response.status_code == 200
    data = response.json()
    assert data["total_repositories"] == 10
    assert data["completed_repositories"] == 8
    assert data["severity_distribution"] == {"critical": 5}
    assert data["top_vulnerable_repositories"][0]["repo_name"] == "frontend-app"


@patch("app.main.get_db", new_callable=AsyncMock)
def test_get_org_findings(mock_get_db, client):
    mock_db = AsyncMock()
    mock_get_db.return_value = mock_db
    mock_cursor = AsyncMock()
    mock_cursor.fetchall.return_value = [
        {
            "id": "123-abc",
            "repo_name": "backend-api",
            "title": "Hardcoded Secret",
            "description": "Found an AWS key",
            "severity": "CRITICAL",
            "file_path": "config.py",
            "line_number": 42,
            "cwe": "CWE-798",
        }
    ]
    mock_db.execute.return_value = mock_cursor

    response = client.get("/api/scans/org/123/findings")

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["repo_name"] == "backend-api"
    assert data[0]["severity"] == "CRITICAL"
