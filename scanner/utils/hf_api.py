"""Hugging Face API client using only urllib (zero external dependencies).

Security properties
-------------------
- Redirect handler validates every redirect target:
    * Must use HTTPS (no HTTP downgrade).
    * Host must be in the HF_ALLOWED_HOSTS allowlist.
    * Authorization header is STRIPPED on any cross-origin redirect to prevent
      Bearer token forwarding to CDN or attacker-controlled hosts.
- All file downloads are pinned to an immutable commit SHA, not 'main'.
  Callers must resolve the repo to a commit SHA before listing/downloading.
- Rate limiting via token bucket (respects HF X-RateLimit-* headers).
- Exponential backoff with jitter on transient errors.
- In-memory caching keyed by URL.

SECURITY NOTE — redirect allowlist
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
HF resolves download URLs to CDN hosts.  The allowlist below covers known HF
CDN endpoints as of 2026.  If HF adds new CDN domains and downloads fail,
add them here after verification from huggingface.co documentation.
"""

import json
import random
import threading
import time
import urllib.error
import urllib.request
import urllib.parse

MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_RETRIES = 3
BASE_RETRY_DELAY = 1.0

# Allowlist of hosts that are permitted redirect targets.
# All must be accessed over HTTPS only.
# Authorization header is forwarded ONLY to huggingface.co and *.hf.co.
# For CDN hosts it is stripped to avoid token leakage.
HF_ALLOWED_HOSTS: frozenset[str] = frozenset({
    "huggingface.co",
    "www.huggingface.co",
    # HF CDN — large file downloads redirect here
    "cdn-lfs.huggingface.co",
    "cdn-lfs-us-1.huggingface.co",
    "cdn-lfs-eu-1.huggingface.co",
    # S3 presigned URLs issued by HF for private repos
    "s3.amazonaws.com",
    # hf.co shorthand aliases
    "hf.co",
})

# Hosts to which the Authorization header may be forwarded.
# CDN and S3 hosts must NOT receive the bearer token.
HF_AUTH_FORWARD_HOSTS: frozenset[str] = frozenset({
    "huggingface.co",
    "www.huggingface.co",
    "hf.co",
})


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that enforces HF security policy on every hop.

    Checks performed on each redirect Location:
    1. Scheme must be 'https' — rejects HTTP downgrade.
    2. Host must be in HF_ALLOWED_HOSTS — rejects exfiltration to attacker host.
    3. Authorization header is stripped for hosts not in HF_AUTH_FORWARD_HOSTS.

    Raises urllib.error.URLError with a descriptive message on any violation.
    """

    def __init__(self, original_headers: dict):
        super().__init__()
        # Store the original headers so we can selectively strip auth on redirect
        self._original_headers = original_headers

    def _check_redirect_target(self, newurl: str) -> None:
        parsed = urllib.parse.urlparse(newurl)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""

        if scheme != "https":
            raise urllib.error.URLError(
                f"Redirect security violation: scheme downgrade to '{scheme}' "
                f"from HTTPS. Refusing redirect to {newurl!r}."
            )

        # Normalise: strip port from comparison (HF uses standard 443)
        host_lower = host.lower()
        if host_lower not in HF_ALLOWED_HOSTS:
            raise urllib.error.URLError(
                f"Redirect security violation: target host '{host_lower}' is not "
                f"in the HF allowed-hosts list. Refusing redirect to {newurl!r}. "
                f"If this is a legitimate HF CDN host, add it to HF_ALLOWED_HOSTS "
                f"after verification."
            )

    def _build_redirected_request(
        self, req: urllib.request.Request, newurl: str
    ) -> urllib.request.Request:
        self._check_redirect_target(newurl)

        parsed = urllib.parse.urlparse(newurl)
        target_host = (parsed.hostname or "").lower()

        # Build new request preserving headers but stripping auth for CDN hosts
        new_headers = dict(req.headers)
        if target_host not in HF_AUTH_FORWARD_HOSTS:
            # Strip Authorization to prevent Bearer token leakage to CDN/S3
            new_headers.pop("Authorization", None)
            new_headers.pop("authorization", None)

        return urllib.request.Request(newurl, headers=new_headers)

    # Override both 301/302/303/307/308 handlers
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp,
        code: int,
        msg: str,
        headers,
        newurl: str,
    ) -> urllib.request.Request:
        return self._build_redirected_request(req, newurl)


class _TokenBucket:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, rate: float, burst: int):
        self.rate = rate  # tokens per second
        self.burst = burst  # max tokens
        self.tokens = float(burst)
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> float:
        """Consume tokens, return wait time in seconds (0 if immediately available)."""
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return 0.0

            needed = tokens - self.tokens
            return needed / self.rate


class HFApiClient:
    """Lightweight Hugging Face Hub API client with security-hardened redirect handling.

    All file operations should use an immutable commit SHA (not 'main') to
    avoid TOCTOU races between scan and deployment.  Use resolve_to_commit_sha()
    to pin a repo reference before listing/downloading files.
    """

    BASE = "https://huggingface.co"

    def __init__(self, token: str | None = None):
        self.token = token
        self._cache: dict = {}
        self._rate_limiter = _TokenBucket(rate=10.0, burst=20)
        self._cache_lock = threading.Lock()

    def _headers(self) -> dict:
        headers = {"User-Agent": "hf-scanner/0.2.0"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _update_rate_limit(self, headers: dict) -> None:
        try:
            remaining = int(headers.get("X-RateLimit-Remaining", "600"))
            reset = int(headers.get("X-RateLimit-Reset", "60"))
            if remaining < 10:
                self._rate_limiter.rate = max(1.0, remaining / max(1, reset))
                self._rate_limiter.burst = max(5, remaining)
        except (ValueError, TypeError):
            pass

    def _request(self, url: str, max_bytes: int | None = None) -> bytes:
        """Make an HTTPS GET request with safe redirect handling, rate limiting, and caching."""
        with self._cache_lock:
            if url in self._cache:
                return self._cache[url]

        # Validate the initial URL is HTTPS before we even send
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() != "https":
            raise ValueError(
                f"Security: only HTTPS requests are permitted; got scheme '{parsed.scheme}'"
            )

        wait = self._rate_limiter.consume(1)
        if wait > 0:
            time.sleep(wait)

        headers = self._headers()
        req = urllib.request.Request(url, headers=headers)
        redirect_handler = _SafeRedirectHandler(original_headers=headers)
        opener = urllib.request.build_opener(redirect_handler)

        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                with opener.open(req, timeout=30) as resp:
                    self._update_rate_limit(dict(resp.headers))

                    if max_bytes:
                        data = resp.read(max_bytes + 1)
                        if len(data) > max_bytes:
                            raise ValueError(
                                f"Download exceeds {max_bytes // (1024 * 1024)}MB safety limit"
                            )
                    else:
                        data = resp.read()

                    with self._cache_lock:
                        self._cache[url] = data
                    return data

            except urllib.error.HTTPError as e:
                if e.code in (401, 403, 404):
                    raise
                last_error = e
                if 400 <= e.code < 500 and e.code != 429:
                    raise
                if attempt < MAX_RETRIES - 1:
                    delay = BASE_RETRY_DELAY * (2 ** attempt) + random.uniform(0, 0.5)
                    if e.code == 429:
                        retry_after = e.headers.get("Retry-After", "")
                        if retry_after.isdigit():
                            delay = max(delay, int(retry_after))
                    time.sleep(delay)

            except (urllib.error.URLError, OSError) as e:
                last_error = e
                if attempt < MAX_RETRIES - 1:
                    delay = BASE_RETRY_DELAY * (2 ** attempt) + random.uniform(0, 0.5)
                    time.sleep(delay)

        raise RuntimeError(
            f"Request failed after {MAX_RETRIES} retries: {last_error}"
        )

    # ── Repository metadata ──────────────────────────────────────────────────

    def get_model_info(self, repo_id: str, revision: str | None = None) -> dict:
        """Fetch model metadata.  If revision is given, pin to that commit."""
        if revision:
            url = f"{self.BASE}/api/models/{repo_id}/revision/{revision}"
        else:
            url = f"{self.BASE}/api/models/{repo_id}"
        return json.loads(self._request(url))

    def resolve_to_commit_sha(self, repo_id: str, revision: str = "main") -> str:
        """Resolve a branch/tag name to its immutable commit SHA.

        This is the REQUIRED first step before listing or downloading files.
        Pinning to a commit SHA prevents TOCTOU: the branch can advance after
        the scan but before deployment; a commit SHA never changes.

        Returns
        -------
        str
            40-character hex commit SHA, e.g. 'a1b2c3d4...'

        Raises
        ------
        RuntimeError
            If the API does not return a recognisable commit SHA.
        ValueError
            If revision resolves to something that looks like a branch
            (not a 40-char hex string) — callers should re-resolve.
        """
        url = f"{self.BASE}/api/models/{repo_id}/revision/{revision}"
        info = json.loads(self._request(url))

        # The API returns the resolved sha in the top-level 'sha' field
        sha = info.get("sha", "")
        if not sha or len(sha) != 40 or not all(c in "0123456789abcdef" for c in sha.lower()):
            raise RuntimeError(
                f"HF API did not return a valid commit SHA for {repo_id}@{revision}: {sha!r}. "
                "Cannot proceed with immutable-revision scan."
            )
        return sha

    def get_model_card(self, repo_id: str, commit_sha: str) -> str:
        """Fetch the model card at a specific immutable commit SHA."""
        url = f"{self.BASE}/{repo_id}/raw/{commit_sha}/README.md"
        return self._request(url).decode("utf-8", errors="replace")

    def list_repo_files(self, repo_id: str, commit_sha: str) -> list[str]:
        """List all files in the repository at an immutable commit SHA.

        Parameters
        ----------
        repo_id:
            e.g. 'meta-llama/Llama-2-7b-hf'
        commit_sha:
            40-char immutable commit SHA from resolve_to_commit_sha().
            MUST be a commit SHA, not a branch name.
        """
        if not commit_sha or len(commit_sha) != 40:
            raise ValueError(
                f"list_repo_files requires a 40-char commit SHA; got {commit_sha!r}. "
                "Call resolve_to_commit_sha() first."
            )
        url = f"{self.BASE}/api/models/{repo_id}/revision/{commit_sha}"
        info = json.loads(self._request(url))
        siblings = info.get("siblings", [])
        return [s.get("rfilename", "") for s in siblings if s.get("rfilename")]

    def download_file(self, repo_id: str, filename: str, commit_sha: str) -> bytes:
        """Download a single file at an immutable commit SHA (max 10MB).

        Parameters
        ----------
        commit_sha:
            40-char immutable commit SHA. MUST NOT be 'main' or a branch name.
            Passing a branch name raises ValueError to prevent TOCTOU.
        """
        if not commit_sha or len(commit_sha) != 40:
            raise ValueError(
                f"download_file requires a 40-char commit SHA; got {commit_sha!r}. "
                "Using branch names creates a TOCTOU vulnerability. "
                "Call resolve_to_commit_sha() first."
            )
        url = f"{self.BASE}/{repo_id}/resolve/{commit_sha}/{filename}"
        return self._request(url, max_bytes=MAX_DOWNLOAD_BYTES)
