"""Hugging Face API client using only urllib (zero external dependencies)."""

import json
import time
import urllib.request
import urllib.error
from typing import Optional

MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_RETRIES = 3
RETRY_DELAY = 1.0


class HFApiClient:
    """Lightweight Hugging Face Hub API client."""

    BASE = "https://huggingface.co"

    def __init__(self, token: Optional[str] = None):
        self.token = token
        self._cache: dict = {}

    def _headers(self) -> dict:
        headers = {"User-Agent": "hf-scanner/0.2.0"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(self, url: str, max_bytes: Optional[int] = None) -> bytes:
        """Make an HTTP GET request with retry logic."""
        if url in self._cache:
            return self._cache[url]

        req = urllib.request.Request(url, headers=self._headers())
        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    if max_bytes:
                        data = resp.read(max_bytes + 1)
                        if len(data) > max_bytes:
                            raise ValueError(
                                f"File exceeds {max_bytes // (1024*1024)}MB limit")
                    else:
                        data = resp.read()
                self._cache[url] = data
                return data
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    raise
                last_error = e
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
            except (urllib.error.URLError, OSError) as e:
                last_error = e
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
        raise RuntimeError(f"Request failed after {MAX_RETRIES} retries: {last_error}")

    def get_model_info(self, repo_id: str) -> dict:
        """Fetch model metadata from the HF API."""
        url = f"{self.BASE}/api/models/{repo_id}"
        data = self._request(url)
        return json.loads(data)

    def get_model_card(self, repo_id: str) -> str:
        """Fetch the model card (README.md) content."""
        url = f"{self.BASE}/{repo_id}/raw/main/README.md"
        data = self._request(url)
        return data.decode("utf-8", errors="replace")

    def list_repo_files(self, repo_id: str) -> list:
        """List all files in the repository."""
        url = f"{self.BASE}/api/models/{repo_id}"
        data = self._request(url)
        info = json.loads(data)
        siblings = info.get("siblings", [])
        return [s.get("rfilename", "") for s in siblings if s.get("rfilename")]

    def download_file(self, repo_id: str, filename: str) -> bytes:
        """Download a single file from the repository (max 10MB)."""
        url = f"{self.BASE}/{repo_id}/resolve/main/{filename}"
        return self._request(url, max_bytes=MAX_DOWNLOAD_BYTES)
