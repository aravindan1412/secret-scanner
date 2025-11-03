import io
import math
from pathlib import Path
from typing import Iterable, List, Optional

from charset_normalizer import from_bytes
from pathspec import PathSpec
from pathspec.patterns.gitwildmatch import GitWildMatchPattern


BINARY_EXTENSIONS = {
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".psd", ".ico",
	".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
	".pdf", ".ttf", ".otf", ".woff", ".woff2",
	".mp3", ".mp4", ".mov", ".avi", ".mkv",
	".exe", ".dll", ".so", ".dylib", ".class", ".o", ".a",
}


def load_ignore_spec(root: Path, extra_files: List[Path], extra_globs: List[str]) -> Optional[PathSpec]:
	patterns: List[str] = []
	gitignore = root / ".gitignore"
	if gitignore.exists():
		patterns.extend(gitignore.read_text(encoding="utf-8", errors="ignore").splitlines())
	for f in extra_files:
		patterns.extend(f.read_text(encoding="utf-8", errors="ignore").splitlines())
	patterns.extend(extra_globs)
	patterns = [p for p in patterns if p and not p.strip().startswith("#")]
	if not patterns:
		return None
	return PathSpec.from_lines(GitWildMatchPattern, patterns)


def is_binary_path(path: Path) -> bool:
	return path.suffix.lower() in BINARY_EXTENSIONS


def is_likely_text(data: bytes) -> bool:
	# Use charset-normalizer to check plausibility of text
	try:
		best = from_bytes(data).best()
		return best is not None and best.encoding is not None
	except Exception:
		return False


def read_text_safely(path: Path, max_bytes: int) -> Optional[str]:
	try:
		with path.open("rb") as fh:
			data = fh.read(max_bytes + 1)
			if len(data) > max_bytes:
				return None
			if not is_likely_text(data):
				return None
			best = from_bytes(data).best()
			if best is None:
				return None
			return str(best)
	except Exception:
		return None


def shannon_entropy(s: str) -> float:
	if not s:
		return 0.0
	freq = {}
	for ch in s:
		freq[ch] = freq.get(ch, 0) + 1
	total = len(s)
	entropy = 0.0
	for count in freq.values():
		p = count / total
		entropy -= p * math.log2(p)
	return entropy


def sliding_windows(s: str, min_len: int = 20, max_len: int = 64):
	for size in range(min_len, max_len + 1):
		for i in range(0, len(s) - size + 1):
			yield s[i : i + size]

