import re
from typing import Dict, List, Pattern, Tuple

# Patterns focus on high-signal, bounded false-positives
PATTERN_DEFS: List[Tuple[str, str, int]] = [
	("AWS Access Key", r"AKIA[0-9A-Z]{16}", 0),
	("AWS Secret Key", r"aws(.{0,20})?(secret|access).{0,20}?([A-Za-z0-9/+=]{40})", 0),
	("GitHub Token", r"ghp_[A-Za-z0-9]{36}", 0),
	("GitHub App Token", r"(gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}", 0),
	("Slack Token", r"xox[abpr]-[A-Za-z0-9-]{10,48}", 0),
	("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", 0),
	("Heroku API Key", r"heroku(.{0,20})?api(.{0,20})?key(.{0,20})?([0-9a-fA-F]{32})", 0),
	("Private Key Start", r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", 0),
	("JWT", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", 0),
	("Azure Storage Key", r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{80,}", 0),
	("Twilio API Key", r"SK[0-9a-fA-F]{32}", 0),
	("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24}", 0),
]

COMPILED_PATTERNS: List[Tuple[str, Pattern[str], int]] = [
	(rule, re.compile(pattern, re.IGNORECASE), group_idx) for rule, pattern, group_idx in PATTERN_DEFS
]


def iter_matches(line: str) -> List[Dict[str, str]]:
	findings: List[Dict[str, str]] = []
	for rule, regex, group_idx in COMPILED_PATTERNS:
		for match in regex.finditer(line):
			matched_text = match.group(group_idx) if group_idx > 0 else match.group(0)
			findings.append({"rule": rule, "match": matched_text})
	return findings

