"""Hugging Face API client using only urllib (zero external dependencies).

Features:
- Token bucket rate limiting (respects HF X-RateLimit-* headers)
- Exponential backoff with jitter
- Deterministic failures for 401/403/404
- In-memory caching
- Preserves Authorization header on same-origin redirects for private/gated repos
"""

import json
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_RETRIES = 3
BASE_RETRY_DELAY = 1.0


# Custom redirect handler that preserves Authorization header for same-origin redirects
class _HFRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that keeps Authorization header for huggingface.co redirects."""

    def __init__(self, token: str | None):
        self.token = token

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Parse original and new URLs
        orig_parsed = urllib.parse.urlparse(req.full_url)
        new_parsed = urllib.parse.urlparse(newurl)

        # Only preserve Authorization header for same-origin (huggingface.co) redirects
        # Cross-origin redirects (e.g., to CDN) should not receive the token
        if self.token and orig_parsed.netloc == new_parsed.netloc:
            # Keep the Authorization header
            new_headers = dict(req.headers)
            new_headers["Authorization"] = f"Bearer {self.token}"
            return urllib.request.Request(newurl, headers=new_headers, method=req.get_method())
        else:
            # Strip Authorization header for cross-origin redirects
            new_headers = {k: v for k, v in req.headers.items() if k.lower() != "authorization"}
            return urllib.request.Request(newurl, headers=new_headers, method=req.get_method())


# Token bucket rate limiter (per-client)
class _TokenBucket:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, rate: float, burst: int):
        self.rate = rate  # tokens per second
        self.burst = burst  # max tokens
        self.tokens = float(burst)
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> float:
        """Consume tokens, return wait time in seconds (0 if available)."""
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return 0.0

            # Calculate wait time
            needed = tokens - self.tokens
            wait_time = needed / self.rate
            return wait_time


class HFApiClient:
    """Lightweight Hugging Face Hub API client with rate limiting."""

    BASE = "https://huggingface.co"

    def __init__(self, token: str | None = None):
        self.token = token
        self._cache: dict = {}
        # Rate limiter: starts conservative, updates from response headers
        self._rate_limiter = _TokenBucket(rate=10.0, burst=20)  # 10 req/s default
        self._cache_lock = threading.Lock()

    def _headers(self) -> dict:
        headers = {"User-Agent": "hf-scanner/0.2.0"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _update_rate_limit(self, headers: dict):
        """Update rate limiter from HF response headers."""
        # HF uses: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
        try:
            limit = int(headers.get("X-RateLimit-Limit", "600"))  # per minute
            remaining = int(headers.get("X-RateLimit-Remaining", "600"))
            reset = int(headers.get("X-RateLimit-Reset", "60"))

            if remaining < 10:
                # Conservative: slow down when close to limit
                self._rate_limiter.rate = max(1.0, remaining / max(1, reset))
                self._rate_limiter.burst = max(5, remaining)
        except (ValueError, TypeError):
            pass  # Keep current settings

    def _build_opener(self):
        """Build urllib opener with custom redirect handler for token preservation."""
        return urllib.request.build_opener(_HFRedirectHandler(self.token))

    def _request(self, url: str, max_bytes: int | None = None) -> bytes:
        """Make an HTTP GET request with rate limiting, retry logic, and caching."""
        # Check cache first
        with self._cache_lock:
            if url in self._cache:
                return self._cache[url]

        # Rate limiting
        wait_time = self._rate_limiter.consume(1)
        if wait_time > 0:
            time.sleep(wait_time)

        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme not in {"http", "https"}:
            raise ValueError("Hugging Face API URL must use http or https")
        req = urllib.request.Request(url, headers=self._headers())
        last_error = None
        opener = self._build_opener()

        for attempt in range(MAX_RETRIES):
            try:
                with opener.open(req, timeout=30) as resp:  # nosec B310
                    # Update rate limiter from response headers
                    self._update_rate_limit(dict(resp.headers))

                    if max_bytes:
                        data = resp.read(max_bytes + 1)
                        if len(data) > max_bytes:
                            raise ValueError(f"File exceeds {max_bytes // (1024 * 1024)}MB limit")
                    else:
                        data = resp.read()

                    # Cache successful response
                    with self._cache_lock:
                        self._cache[url] = data
                    return data

            except urllib.error.HTTPError as e:
                # Deterministic failures for auth/not found
                if e.code in (401, 403, 404):
                    raise
                last_error = e
                # Don't retry on 4xx client errors (except 429)
                if 400 <= e.code < 500 and e.code != 429:
                    raise
                if attempt < MAX_RETRIES - 1:
                    # Exponential backoff with jitter
                    delay = BASE_RETRY_DELAY * (2**attempt) + random.uniform(0, 0.5)  # noqa: S311 - retry jitter, not cryptographic randomness
                    if e.code == 429:
                        # Respect Retry-After header if present
                        retry_after = e.headers.get("Retry-After")
                        if retry_after and retry_after.isdigit():
                            delay = max(delay, int(retry_after))
                    time.sleep(delay)

            except (urllib.error.URLError, OSError) as e:
                last_error = e
                if attempt < MAX_RETRIES - 1:
                    delay = BASE_RETRY_DELAY * (2**attempt) + random.uniform(0, 0.5)  # noqa: S311 - retry jitter, not cryptographic randomness
                    time.sleep(delay)

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

    def fetch_range(self, repo_id: str, filename: str, n_bytes: int) -> bytes:
        """Fetch only the first ``n_bytes`` of a file using an HTTP Range request.

        This is what makes pre-download scanning possible: a malicious
        pickle declares its dangerous opcodes in the file header, and a
        safetensors metadata-injection lives in the leading JSON header. We can
        detect both by pulling a few KB instead of downloading multi-gigabyte
        weights. Falls back to a capped full read if the server ignores Range.
        """
        url = f"{self.BASE}/{repo_id}/resolve/main/{filename}"
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("URL must use http or https")

        wait = self._rate_limiter.consume(1)
        if wait > 0:
            time.sleep(wait)

        req = urllib.request.Request(url, headers=self._headers())
        req.add_header("Range", f"bytes=0-{max(0, n_bytes - 1)}")
        opener = self._build_opener()
        try:
            with opener.open(req, timeout=30) as resp:  # nosec B310
                return resp.read(n_bytes)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404):
                raise
            # Server ignored Range (200 instead of 206) or transient error:
            # fall back to a capped read so we still get the header bytes.
            return self._request(url, max_bytes=min(n_bytes, MAX_DOWNLOAD_BYTES))

    def head_file_size(self, repo_id: str, filename: str) -> int | None:
        """Return the file size in bytes via a HEAD request, or None if unknown."""
        url = f"{self.BASE}/{repo_id}/resolve/main/{filename}"
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("URL must use http or https")
        req = urllib.request.Request(url, headers=self._headers(), method="HEAD")
        opener = self._build_opener()
        try:
            with opener.open(req, timeout=30) as resp:  # nosec B310
                size = resp.headers.get("Content-Length") or resp.headers.get("X-Linked-Size")
                return int(size) if size and size.isdigit() else None
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError):
            return None
