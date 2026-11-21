"""File walking utility with size filtering."""

import os
import stat
from collections.abc import Generator
from pathlib import Path

SKIP_DIRS = {"__pycache__", ".git"}

# Windows marks junctions and other reparse points with this attribute.
_WINDOWS_REPARSE_POINT = 0x400


def _linked(entry: os.stat_result) -> bool:
    return stat.S_ISLNK(entry.st_mode) or bool(
        getattr(entry, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
    )


def walk_files(root: str, max_size_kb: int = 512) -> Generator[tuple[str, bool], None, None]:
    """Walk directory tree yielding (file_path, is_oversized) tuples.

    Skips __pycache__ and .git directories.
    Files larger than max_size_kb are yielded with is_oversized=True.
    """
    max_bytes = max_size_kb * 1024

    def traversal_error(error: OSError) -> None:
        raise error

    for dirpath, dirnames, filenames in os.walk(root, onerror=traversal_error):
        linked_dirs = [name for name in dirnames if os.path.islink(os.path.join(dirpath, name))]
        # Do not traverse links or repository/cache metadata.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d not in linked_dirs]
        for filename in (*filenames, *linked_dirs):
            file_path = os.path.join(dirpath, filename)
            try:
                size = os.lstat(file_path).st_size
            except OSError:
                # Let the reader report a skipped entry if it disappeared.
                size = 0
            yield file_path, size > max_bytes


def read_regular_file(root: str, path: str, limit: int) -> bytes:
    """Read at most limit bytes from a regular file inside the selected root."""
    root_path = Path(os.path.abspath(root))
    relative = Path(os.path.abspath(path)).relative_to(root_path)
    if not relative.parts:
        raise ValueError("Expected a regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        parent = os.open(root_path, directory_flags)
        try:
            for part in relative.parts[:-1]:
                child = os.open(part, directory_flags, dir_fd=parent)
                os.close(parent)
                parent = child
            fd = os.open(relative.name, flags | os.O_NOFOLLOW, dir_fd=parent)
        finally:
            os.close(parent)
    else:
        # Platforms without directory descriptors still reject links and
        # compare the opened file identity before parsing any bytes.
        if any(_linked((root_path / part).lstat()) for part in reversed(relative.parents)):
            raise ValueError("Linked files or directories are not inspected")
        candidate = root_path / relative
        entry = candidate.lstat()
        if _linked(entry) or not stat.S_ISREG(entry.st_mode):
            raise ValueError("Expected an unlinked regular file")
        fd = os.open(candidate, flags)
        try:
            if not os.path.samestat(entry, os.fstat(fd)):
                raise ValueError("File changed before it was opened")
        except BaseException:
            os.close(fd)
            raise

    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Expected a regular file")
        if info.st_size > limit:
            raise ValueError("File exceeds scan byte limit")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("File exceeds scan byte limit")
        return data
