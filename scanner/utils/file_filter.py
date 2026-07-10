"""File walking utility with size filtering."""

import os
from typing import Generator, Tuple

SKIP_DIRS = {"__pycache__", ".git"}


def walk_files(root: str, max_size_kb: int = 512) -> Generator[Tuple[str, bool], None, None]:
    """Walk directory tree yielding (file_path, is_oversized) tuples.

    Skips __pycache__ and .git directories.
    Files larger than max_size_kb are yielded with is_oversized=True.
    """
    max_bytes = max_size_kb * 1024
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip directories in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            try:
                size = os.path.getsize(file_path)
            except OSError:
                continue
            is_oversized = size > max_bytes
            yield (file_path, is_oversized)
