import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from pathspec import PathSpec

from .patterns import iter_matches
from .util import (
	is_binary_path,
	is_text_path,
	read_text_safely,
	shannon_entropy,
	extract_entropy_candidates,
)


def should_ignore(path: Path, root: Path, spec: Optional[PathSpec]) -> bool:
	if spec is None:
		return False
	# Evaluate relative to root
	rel = str(path.relative_to(root))
	return spec.match_file(rel)


def scan_file(path: Path, root: Path, max_file_size: int, entropy_threshold: float, enable_entropy: bool) -> List[Dict[str, object]]:
	findings: List[Dict[str, object]] = []
	# Quick extension filters
	if is_binary_path(path) or not is_text_path(path):
		return findings
	content = read_text_safely(path, max_file_size)
	if content is None:
		return findings

	MAX_FINDINGS_PER_FILE = 200
	for idx, line in enumerate(content.splitlines(), start=1):
		# regex signatures
		for m in iter_matches(line):
			findings.append({
				"path": str(path),
				"line": idx,
				"rule": m["rule"],
				"match": m["match"],
			})
		# entropy (optimized: only evaluate candidate tokens)
		if enable_entropy and len(findings) < MAX_FINDINGS_PER_FILE:
			for token in extract_entropy_candidates(line):
				if shannon_entropy(token) >= entropy_threshold:
					findings.append({
						"path": str(path),
						"line": idx,
						"rule": f"HighEntropy(>= {entropy_threshold})",
						"match": token,
					})
					if len(findings) >= MAX_FINDINGS_PER_FILE:
						break
		if len(findings) >= MAX_FINDINGS_PER_FILE:
			break
	return findings


def scan_path(
	target_path: Path,
	ignore_spec: Optional[PathSpec],
	max_file_size: int,
	entropy_threshold: float,
	enable_entropy: bool,
    workers: int = 0,
) -> List[Dict[str, object]]:
	results: List[Dict[str, object]] = []

	# Build list of files to scan
	if target_path.is_file():
		files = [target_path]
		root = target_path.parent
	else:
		root = target_path
		files = [
			p for p in root.rglob("*")
			if p.is_file() and not should_ignore(p, root, ignore_spec)
		]

	if not files:
		return results

	max_workers = workers if workers and workers > 0 else min(32, (os.cpu_count() or 2) * 2)
	with ThreadPoolExecutor(max_workers=max_workers) as executor:
		future_to_path = {
			executor.submit(scan_file, p, root, max_file_size, entropy_threshold, enable_entropy): p
			for p in files
		}
		for future in as_completed(future_to_path):
			try:
				results.extend(future.result())
			except Exception:
				# Skip failures to ensure robust scanning
				continue

	return results

