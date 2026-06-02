from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
import httpx

from app.main import app

client = TestClient(app)


def test_scan_url_invalid_format():
    res = client.post(
        "/scan-url", data={"repo_url": "not-a-url", "project_name": "test_project"}
    )
    assert res.status_code == 422
    assert "Invalid GitHub URL format" in res.json()["detail"]


@patch("app.main.httpx.AsyncClient")
def test_scan_url_not_found(mock_async_client):
    mock_client = AsyncMock()
    mock_async_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_async_client.return_value.__aexit__ = AsyncMock(return_value=None)

    mock_response = httpx.Response(404)
    mock_client.head = AsyncMock(return_value=mock_response)

    res = client.post(
        "/scan-url",
        data={
            "repo_url": "https://github.com/owner/repo",
            "project_name": "test_project",
        },
    )
    assert res.status_code == 422
    assert "not found or is private" in res.json()["detail"]


@patch("app.main.httpx.AsyncClient")
def test_scan_url_timeout(mock_async_client):
    mock_client = AsyncMock()
    mock_async_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_async_client.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_client.head = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

    res = client.post(
        "/scan-url",
        data={
            "repo_url": "https://github.com/owner/repo",
            "project_name": "test_project",
        },
    )
    assert res.status_code == 422
    assert "Could not reach GitHub" in res.json()["detail"]


@patch("app.main.httpx.AsyncClient")
@patch("app.main.download_to_path", new_callable=AsyncMock)
@patch("app.main.unzip_to_dir")
@patch("app.main._scan_repo_dir")
def test_scan_url_success(mock_scan, mock_unzip, mock_download, mock_async_client):
    mock_client = AsyncMock()
    mock_async_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_async_client.return_value.__aexit__ = AsyncMock(return_value=None)
    mock_response = httpx.Response(200)
    mock_client.head = AsyncMock(return_value=mock_response)

    mock_scan.return_value = ([], [], [], [])

    res = client.post(
        "/scan-url",
        data={
            "repo_url": "https://github.com/owner/repo",
            "project_name": "test_project",
        },
    )
    assert res.status_code == 200
    assert res.json()["project_name"] == "test_project"
