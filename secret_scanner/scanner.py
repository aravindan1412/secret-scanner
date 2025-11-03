from pathlib import Path
from typing import Dict, Iterable, List, Optional

from pathspec import PathSpec

from .patterns import iter_matches
from .util import is_binary_path, read_text_safely, shannon_entropy, sliding_windows


def should_ignore(path: Path, root: Path, spec: Optional[PathSpec]) -> bool:
	if spec is None:
		return False
	# Evaluate relative to root
	rel = str(path.relative_to(root))
	return spec.match_file(rel)


def scan_file(path: Path, root: Path, max_file_size: int, entropy_threshold: float, enable_entropy: bool) -> List[Dict[str, object]]:
	findings: List[Dict[str, object]] = []
	if is_binary_path(path):
		return findings
	content = read_text_safely(path, max_file_size)
	if content is None:
		return findings
	for idx, line in enumerate(content.splitlines(), start=1):
		# regex signatures
		for m in iter_matches(line):
			findings.append({
				"path": str(path),
				"line": idx,
				"rule": m["rule"],
				"match": m["match"],
			})
		# entropy
		if enable_entropy:
			for window in sliding_windows(line, 20, 64):
				if shannon_entropy(window) >= entropy_threshold:
					findings.append({
						"path": str(path),
						"line": idx,
						"rule": f"HighEntropy(>= {entropy_threshold})",
						"match": window,
					})
	return findings


def scan_path(
	target_path: Path,
	ignore_spec: Optional[PathSpec],
	max_file_size: int,
	entropy_threshold: float,
	enable_entropy: bool,
) -> List[Dict[str, object]]:
	results: List[Dict[str, object]] = []
	if target_path.is_file():
		if not should_ignore(target_path, target_path.parent, ignore_spec):
			results.extend(scan_file(target_path, target_path.parent, max_file_size, entropy_threshold, enable_entropy))
		return results

	root = target_path
	for path in root.rglob("*"):
		if path.is_dir():
			continue
		if should_ignore(path, root, ignore_spec):
			continue
		results.extend(scan_file(path, root, max_file_size, entropy_threshold, enable_entropy))
	return results

