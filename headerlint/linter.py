"""Core linting logic for raw HTTP header blocks.

Two layers of checks run over a header block:

  1. Protocol-level checks (always on): malformed lines, invalid header
     names, obsolete line folding, headers repeated where repetition has
     no defined meaning. These are things a real HTTP implementation
     would choke on or handle unpredictably.

  2. Policy-level checks (on unless --lenient): deprecated headers still
     present, and recommended response headers that are missing. These
     are opinions about good practice, not protocol requirements, which
     is why they're the ones the escape hatch turns off.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
STATUS_LINE_RE = re.compile(r"^HTTP/\d\.\d \d{3}")
REQUEST_LINE_RE = re.compile(r"^[A-Z]+ \S+ HTTP/\d\.\d$")

# Headers that legitimately appear more than once in a single message.
REPEATABLE = {"set-cookie", "warning", "via", "link"}

# Headers whose presence signals an outdated or withdrawn mechanism.
DEPRECATED_HEADERS = {
    "public-key-pins": "HPKP was removed from every major browser; it can only cause harm now",
    "public-key-pins-report-only": "HPKP was removed from every major browser",
    "x-xss-protection": "the XSS auditor it controlled has been removed from all major browsers",
    "pragma": "only 'no-cache' had any effect, and only for HTTP/1.0 caches; use Cache-Control",
}

# Response headers whose absence is worth flagging in strict mode.
RECOMMENDED_RESPONSE_HEADERS = {
    "strict-transport-security": "without it, a plain-HTTP request can be intercepted before the first redirect",
    "x-content-type-options": "without 'nosniff', some browsers will still sniff content types on this response",
}


@dataclass(frozen=True)
class Finding:
    line: int
    severity: str  # "error" or "warning"
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.line}: {self.severity}: {self.code}: {self.message}"


@dataclass
class HeaderLine:
    line: int
    raw: str
    name: str
    value: str


def _is_start_line(line: str) -> bool:
    return bool(STATUS_LINE_RE.match(line) or REQUEST_LINE_RE.match(line))


def parse(lines: list[str]) -> tuple[list[HeaderLine], list[Finding]]:
    """Parse raw lines into structured headers.

    Malformed lines are reported and dropped rather than guessed at - a
    linter that silently repairs bad input hides the thing it's supposed
    to be catching.
    """
    headers: list[HeaderLine] = []
    findings: list[Finding] = []
    last: HeaderLine | None = None

    for i, raw in enumerate(lines, start=1):
        if not raw.strip():
            last = None
            continue
        if i == 1 and _is_start_line(raw):
            last = None
            continue
        if raw[0] in " \t":
            # Obsolete line folding (RFC 7230 3.2.4): a continuation of the
            # previous header's value on its own line.
            if last is None:
                findings.append(Finding(
                    i, "error", "orphan-continuation",
                    "continuation line has no preceding header to attach to",
                ))
            else:
                findings.append(Finding(
                    i, "error", "obsolete-line-folding",
                    "header value continues on a following line; this is "
                    "obsolete and many parsers reject it outright",
                ))
            continue
        if ":" not in raw:
            findings.append(Finding(
                i, "error", "malformed-line",
                f"line has no ':' separating a header name from a value: {raw!r}",
            ))
            last = None
            continue
        name, _, value = raw.partition(":")
        if name != name.rstrip():
            findings.append(Finding(
                i, "error", "space-before-colon",
                f"whitespace between header name and ':' is not allowed: {raw!r}",
            ))
        stripped_name = name.strip()
        if not TOKEN_RE.match(stripped_name):
            findings.append(Finding(
                i, "error", "invalid-header-name",
                f"{stripped_name!r} contains characters not allowed in a header name",
            ))
            last = None
            continue
        header = HeaderLine(line=i, raw=raw, name=stripped_name, value=value.strip())
        headers.append(header)
        last = header

    return headers, findings


def _check_duplicates(headers: list[HeaderLine]) -> list[Finding]:
    findings = []
    seen: dict[str, int] = {}
    for h in headers:
        key = h.name.lower()
        if key in REPEATABLE:
            continue
        if key in seen:
            findings.append(Finding(
                h.line, "error", "duplicate-header",
                f"{h.name!r} was already set on line {seen[key]}; duplicates "
                "of this header have undefined precedence",
            ))
        else:
            seen[key] = h.line
    return findings


def _check_deprecated(headers: list[HeaderLine]) -> list[Finding]:
    findings = []
    for h in headers:
        reason = DEPRECATED_HEADERS.get(h.name.lower())
        if reason:
            findings.append(Finding(
                h.line, "warning", "deprecated-header",
                f"{h.name!r} is deprecated: {reason}",
            ))
    return findings


def _check_recommended(headers: list[HeaderLine], lines: list[str]) -> list[Finding]:
    if not lines or not STATUS_LINE_RE.match(lines[0]):
        return []  # only applies to responses, and we can't tell otherwise
    present = {h.name.lower() for h in headers}
    findings = []
    for name, reason in RECOMMENDED_RESPONSE_HEADERS.items():
        if name not in present:
            findings.append(Finding(
                1, "warning", "missing-recommended-header",
                f"response has no {name!r} header: {reason}",
            ))
    return findings


def lint(text: str, lenient: bool = False) -> list[Finding]:
    """Lint a block of raw HTTP header text.

    Strict by default: flags deprecated headers and missing security
    headers on top of outright protocol violations. Pass lenient=True to
    check protocol correctness only - useful for headers you don't
    control and can't change the security posture of.
    """
    lines = text.splitlines()
    headers, findings = parse(lines)
    findings.extend(_check_duplicates(headers))
    if not lenient:
        findings.extend(_check_deprecated(headers))
        findings.extend(_check_recommended(headers, lines))
    findings.sort(key=lambda f: (f.line, f.code))
    return findings
