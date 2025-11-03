import json
import sys
from pathlib import Path
from typing import List, Optional

import click

from .scanner import scan_path
from .util import load_ignore_spec


@click.group()
def main() -> None:
	"""Secret scanner CLI."""


@main.command(name="scan")
@click.argument("target", type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path))
@click.option("--json", "json_out", is_flag=True, help="Output results as JSON")
@click.option("--fail-on-findings", is_flag=True, help="Return non-zero exit code if findings exist")
@click.option("--max-file-size", type=int, default=512_000, show_default=True, help="Max bytes to scan per file")
@click.option("--entropy-threshold", type=float, default=4.0, show_default=True, help="Shannon entropy threshold")
@click.option("--no-entropy", is_flag=True, help="Disable entropy-based detection")
@click.option("--exclude", "excludes", multiple=True, help="Extra exclude glob(s), in addition to .gitignore")
@click.option("--ignore-file", multiple=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Additional ignore files (gitignore syntax)")
@click.option("--output-file", type=click.Path(dir_okay=False, path_type=Path), help="Write output to file instead of stdout")
def scan(
	target: Path,
	json_out: bool,
	fail_on_findings: bool,
	max_file_size: int,
	entropy_threshold: float,
	no_entropy: bool,
	excludes: List[str],
	ignore_file: List[Path],
	output_file: Optional[Path],
) -> None:
	ignore_spec = load_ignore_spec(target, list(ignore_file), list(excludes))
	results = scan_path(
		target_path=target,
		ignore_spec=ignore_spec,
		max_file_size=max_file_size,
		entropy_threshold=entropy_threshold,
		enable_entropy=not no_entropy,
	)

	if json_out:
		output = json.dumps({"findings": results}, indent=2)
	else:
		lines = []
		for r in results:
			lines.append(f"{r['path']}:{r['line']}: {r['rule']} -> {r['match']}")
		output = "\n".join(lines)

	if output_file:
		output_file.parent.mkdir(parents=True, exist_ok=True)
		output_file.write_text(output, encoding="utf-8")
	else:
		click.echo(output)

	if fail_on_findings and results:
		sys.exit(1)

