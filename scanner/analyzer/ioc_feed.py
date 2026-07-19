"""
Dynamic IOC Feed System — Fetch, cache, and merge threat intelligence.

Features:
1. Local JSON IOC database (scanner/data/iocs.json) as baseline
2. Remote feed URLs (configurable) for dynamic updates
3. TTL-based caching to avoid excessive network calls
4. Deduplication and merging across multiple sources
5. Graceful degradation when offline (uses cached/local data)

Feed format (each source returns JSON with optional fields):
{
    "domains": ["malicious-domain.com", ...],
    "suspicious_tlds": [".top", ...],
    "dangerous_packages": ["evil-pkg", ...],
    "ip_addresses": ["1.2.3.4", ...],
    "sha256_hashes": ["abc123...", ...],
    "urls": ["http://evil.com/payload", ...],
    "updated_at": "2026-07-01T00:00:00Z"
}
"""

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional


# Cache directory — use platform-appropriate user cache
def _get_cache_dir() -> str:
    """Get a writable cache directory for IOC feeds."""
    # Try XDG_CACHE_HOME (Linux), then LOCALAPPDATA (Windows), then fallback
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return os.path.join(xdg, "hf-scanner", "ioc_cache")
    localapp = os.environ.get("LOCALAPPDATA")
    if localapp:
        return os.path.join(localapp, "hf-scanner", "ioc_cache")
    # Fallback: ~/.cache/hf-scanner/ioc_cache
    return os.path.join(os.path.expanduser("~"), ".cache", "hf-scanner", "ioc_cache")

CACHE_DIR = _get_cache_dir()
DEFAULT_TTL_SECONDS = 3600  # 1 hour cache TTL
MAX_FEED_SIZE = 5_000_000  # 5MB max per feed download

# Default community feed URLs (can be overridden in config)
DEFAULT_FEED_URLS: list[str] = [
    # These would be real feed URLs in production
    # "https://raw.githubusercontent.com/your-org/threat-feeds/main/ml-iocs.json",
]


@dataclass
class IOCDatabase:
    """Merged IOC database from all sources."""
    domains: set[str] = field(default_factory=set)
    suspicious_tlds: set[str] = field(default_factory=set)
    dangerous_packages: set[str] = field(default_factory=set)
    ip_addresses: set[str] = field(default_factory=set)
    sha256_hashes: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    vulnerable_versions: dict[str, str] = field(default_factory=dict)
    last_updated: float = 0.0

    def to_dict(self) -> dict:
        return {
            "domains": sorted(self.domains),
            "suspicious_tlds": sorted(self.suspicious_tlds),
            "dangerous_packages": sorted(self.dangerous_packages),
            "ip_addresses": sorted(self.ip_addresses),
            "sha256_hashes": sorted(self.sha256_hashes),
            "urls": sorted(self.urls),
            "vulnerable_versions": self.vulnerable_versions,
            "last_updated": self.last_updated,
        }


def _load_local_iocs() -> dict:
    """Load the bundled IOC database."""
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "iocs.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _ensure_cache_dir():
    """Create cache directory if needed."""
    os.makedirs(CACHE_DIR, exist_ok=True)


def _cache_path(url: str) -> str:
    """Generate cache filename for a feed URL."""
    url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
    return os.path.join(CACHE_DIR, f"feed_{url_hash}.json")


def _cache_meta_path(url: str) -> str:
    """Metadata file tracking fetch time."""
    url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
    return os.path.join(CACHE_DIR, f"feed_{url_hash}.meta")


def _is_cache_fresh(url: str, ttl: int = DEFAULT_TTL_SECONDS) -> bool:
    """Check if cached feed is within TTL."""
    meta_path = _cache_meta_path(url)
    try:
        with open(meta_path, "r") as f:
            fetched_at = float(f.read().strip())
        return (time.time() - fetched_at) < ttl
    except (OSError, ValueError):
        return False


def _read_cached_feed(url: str) -> Optional[dict]:
    """Read cached feed data."""
    cache_file = _cache_path(url)
    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(url: str, data: dict):
    """Write feed data to cache."""
    _ensure_cache_dir()
    cache_file = _cache_path(url)
    meta_file = _cache_meta_path(url)
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(data, f)
        with open(meta_file, "w") as f:
            f.write(str(time.time()))
    except OSError:
        pass


def fetch_remote_feed(url: str, timeout: int = 10) -> Optional[dict]:
    """Fetch a single remote IOC feed with caching."""
    # Check cache first
    if _is_cache_fresh(url):
        cached = _read_cached_feed(url)
        if cached is not None:
            return cached

    # Fetch from network
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "hf-scanner/0.1.0 IOC-feed-client",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if int(resp.headers.get("Content-Length", 0)) > MAX_FEED_SIZE:
                return _read_cached_feed(url)  # Fallback to cache
            raw = resp.read(MAX_FEED_SIZE)
            data = json.loads(raw.decode("utf-8"))
            _write_cache(url, data)
            return data
    except (urllib.error.URLError, json.JSONDecodeError, OSError, ValueError):
        # Network failure — use cache if available
        return _read_cached_feed(url)


def build_ioc_database(
    feed_urls: Optional[list[str]] = None,
    no_network: bool = False,
    ttl: int = DEFAULT_TTL_SECONDS,
) -> IOCDatabase:
    """
    Build merged IOC database from local + remote sources.
    
    Args:
        feed_urls: Optional list of remote feed URLs
        no_network: If True, only use local/cached data
        ttl: Cache TTL in seconds
    
    Returns:
        Merged and deduplicated IOCDatabase
    """
    db = IOCDatabase()

    # 1. Load local baseline
    local = _load_local_iocs()
    db.domains.update(d.lower() for d in local.get("domains", []))
    db.suspicious_tlds.update(t.lower() for t in local.get("suspicious_tlds", []))
    db.dangerous_packages.update(p.lower() for p in local.get("dangerous_packages", []))
    db.vulnerable_versions.update(local.get("vulnerable_versions", {}))
    db.last_updated = time.time()

    # 2. Fetch remote feeds (unless offline)
    if not no_network:
        urls = feed_urls or DEFAULT_FEED_URLS
        for url in urls:
            feed_data = fetch_remote_feed(url)
            if feed_data:
                _merge_feed(db, feed_data)

    return db


def _merge_feed(db: IOCDatabase, feed: dict):
    """Merge a single feed into the database."""
    db.domains.update(d.lower() for d in feed.get("domains", []))
    db.suspicious_tlds.update(t.lower() for t in feed.get("suspicious_tlds", []))
    db.dangerous_packages.update(p.lower() for p in feed.get("dangerous_packages", []))
    db.ip_addresses.update(feed.get("ip_addresses", []))
    db.sha256_hashes.update(h.lower() for h in feed.get("sha256_hashes", []))
    db.urls.update(feed.get("urls", []))
    for pkg, ver in feed.get("vulnerable_versions", {}).items():
        # Keep the higher minimum version
        existing = db.vulnerable_versions.get(pkg)
        if existing is None or ver > existing:
            db.vulnerable_versions[pkg] = ver


def check_ioc(value: str, db: IOCDatabase) -> Optional[str]:
    """
    Check a single value against the IOC database.
    Returns the IOC category matched, or None.
    """
    lower = value.lower().strip()

    # Domain check
    if lower in db.domains:
        return "domain"
    for domain in db.domains:
        if lower.endswith("." + domain):
            return "domain"

    # TLD check
    for tld in db.suspicious_tlds:
        if lower.endswith(tld):
            return "suspicious_tld"

    # IP check
    if lower in db.ip_addresses:
        return "ip_address"

    # Hash check
    if lower in db.sha256_hashes:
        return "known_malicious_hash"

    # URL check
    if lower in db.urls:
        return "known_malicious_url"

    return None
