import io
import math
from pathlib import Path
from typing import Iterable, List, Optional, Pattern

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

# Default excludes to avoid scanning massive dependency/build directories
DEFAULT_EXCLUDES = [
	"**/.git/**",
	"**/.venv/**",
	"**/venv/**",
	"**/node_modules/**",
	"**/dist/**",
	"**/build/**",
]

# Common text/code extensions we want to preferentially scan
ALLOWED_TEXT_EXTS = {
	".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".rb", ".php", ".cs",
	".c", ".h", ".cpp", ".hpp", ".m", ".mm", ".swift", ".kt", ".kts",
	".sh", ".ps1", ".bat", ".cmd",
	".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env",
	".md", ".txt", ".csv", ".sql",
}


def load_ignore_spec(root: Path, extra_files: List[Path], extra_globs: List[str]) -> Optional[PathSpec]:
	patterns: List[str] = []
	gitignore = root / ".gitignore"
	if gitignore.exists():
		patterns.extend(gitignore.read_text(encoding="utf-8", errors="ignore").splitlines())
	for f in extra_files:
		patterns.extend(f.read_text(encoding="utf-8", errors="ignore").splitlines())
	# Default excludes first, then user extras
	patterns.extend(DEFAULT_EXCLUDES)
	patterns.extend(extra_globs)
	patterns = [p for p in patterns if p and not p.strip().startswith("#")]
	if not patterns:
		return None
	return PathSpec.from_lines(GitWildMatchPattern, patterns)


def is_binary_path(path: Path) -> bool:
	return path.suffix.lower() in BINARY_EXTENSIONS


def is_text_path(path: Path) -> bool:
	# Fast path filter by extension
	return path.suffix.lower() in ALLOWED_TEXT_EXTS


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


_CANDIDATE_RE: Pattern[str] = __import__("re").compile(
	# Base64-ish, urlsafe, hex, long tokens connected by punctuation
	r"([A-Za-z0-9\-_/+=]{20,}|[0-9a-fA-F]{32,})"
)


def extract_entropy_candidates(line: str) -> List[str]:
	return [m.group(0) for m in _CANDIDATE_RE.finditer(line)]

