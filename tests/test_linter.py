from __future__ import annotations

import unittest

from headerlint.linter import (
    Finding,
    _check_deprecated,
    _check_duplicates,
    _check_recommended,
    lint,
    parse,
)


def codes(findings: list[Finding]) -> list[str]:
    return [f.code for f in findings]


class ParseTests(unittest.TestCase):
    def test_parses_plain_headers(self):
        headers, findings = parse(["Content-Type: text/html", "X-Foo: bar"])
        self.assertEqual(findings, [])
        self.assertEqual([h.name for h in headers], ["Content-Type", "X-Foo"])
        self.assertEqual([h.value for h in headers], ["text/html", "bar"])

    def test_skips_response_status_line(self):
        headers, findings = parse(["HTTP/1.1 200 OK", "Server: nginx"])
        self.assertEqual(findings, [])
        self.assertEqual([h.name for h in headers], ["Server"])

    def test_skips_request_line(self):
        headers, findings = parse(["GET /path HTTP/1.1", "Host: example.com"])
        self.assertEqual(findings, [])
        self.assertEqual([h.name for h in headers], ["Host"])

    def test_start_line_only_recognized_on_first_line(self):
        # a line that looks like a status line is just a malformed header
        # once it isn't in the first-line position.
        headers, findings = parse(["Host: example.com", "HTTP/1.1 200 OK"])
        self.assertEqual([h.name for h in headers], ["Host"])
        self.assertEqual(codes(findings), ["malformed-line"])

    def test_line_with_no_colon_is_malformed(self):
        headers, findings = parse(["not a header line"])
        self.assertEqual(headers, [])
        self.assertEqual(codes(findings), ["malformed-line"])
        self.assertEqual(findings[0].line, 1)

    def test_invalid_characters_in_header_name(self):
        headers, findings = parse(["Foo Bar: baz"])
        self.assertEqual(headers, [])
        self.assertEqual(codes(findings), ["invalid-header-name"])

    def test_space_before_colon_is_flagged_but_header_kept(self):
        headers, findings = parse(["Content-Type : text/html"])
        self.assertEqual(codes(findings), ["space-before-colon"])
        self.assertEqual(len(headers), 1)
        self.assertEqual(headers[0].name, "Content-Type")
        self.assertEqual(headers[0].value, "text/html")

    def test_obsolete_line_folding(self):
        headers, findings = parse(["Content-Type: text/html", " charset=utf-8"])
        self.assertEqual(codes(findings), ["obsolete-line-folding"])
        self.assertEqual(findings[0].line, 2)
        # the folded line does not become a header of its own
        self.assertEqual(len(headers), 1)

    def test_orphan_continuation_at_start(self):
        headers, findings = parse([" charset=utf-8"])
        self.assertEqual(headers, [])
        self.assertEqual(codes(findings), ["orphan-continuation"])

    def test_blank_line_resets_continuation_context(self):
        headers, findings = parse(
            ["Content-Type: text/html", "", " charset=utf-8"]
        )
        self.assertEqual(len(headers), 1)
        self.assertEqual(codes(findings), ["orphan-continuation"])
        self.assertEqual(findings[0].line, 3)

    def test_malformed_line_clears_continuation_context(self):
        headers, findings = parse(
            ["Content-Type: text/html", "not a header", " charset=utf-8"]
        )
        self.assertEqual(len(headers), 1)
        self.assertEqual(codes(findings), ["malformed-line", "orphan-continuation"])


class DuplicateCheckTests(unittest.TestCase):
    def test_flags_duplicate_header_case_insensitively(self):
        headers, _ = parse(["Content-Type: text/html", "content-type: text/plain"])
        findings = _check_duplicates(headers)
        self.assertEqual(codes(findings), ["duplicate-header"])
        self.assertEqual(findings[0].line, 2)
        self.assertIn("line 1", findings[0].message)

    def test_repeatable_headers_are_not_flagged(self):
        headers, _ = parse(["Set-Cookie: a=1", "Set-Cookie: b=2", "Via: 1.1 proxy"])
        self.assertEqual(_check_duplicates(headers), [])


class DeprecatedCheckTests(unittest.TestCase):
    def test_flags_known_deprecated_header(self):
        headers, _ = parse(["X-XSS-Protection: 1; mode=block"])
        findings = _check_deprecated(headers)
        self.assertEqual(codes(findings), ["deprecated-header"])
        self.assertEqual(findings[0].severity, "warning")

    def test_ignores_headers_not_on_the_list(self):
        headers, _ = parse(["Content-Type: text/html"])
        self.assertEqual(_check_deprecated(headers), [])


class RecommendedCheckTests(unittest.TestCase):
    def test_flags_missing_recommended_headers_on_response(self):
        lines = ["HTTP/1.1 200 OK", "Content-Type: text/html"]
        headers, _ = parse(lines)
        findings = _check_recommended(headers, lines)
        self.assertEqual(
            codes(findings),
            ["missing-recommended-header", "missing-recommended-header"],
        )
        self.assertTrue(all(f.line == 1 for f in findings))

    def test_present_recommended_headers_are_not_flagged(self):
        lines = [
            "HTTP/1.1 200 OK",
            "Strict-Transport-Security: max-age=31536000",
            "X-Content-Type-Options: nosniff",
        ]
        headers, _ = parse(lines)
        self.assertEqual(_check_recommended(headers, lines), [])

    def test_does_not_apply_to_requests(self):
        lines = ["GET / HTTP/1.1", "Host: example.com"]
        headers, _ = parse(lines)
        self.assertEqual(_check_recommended(headers, lines), [])

    def test_does_not_apply_when_start_line_is_absent(self):
        lines = ["Content-Type: text/html"]
        headers, _ = parse(lines)
        self.assertEqual(_check_recommended(headers, lines), [])


class LintTests(unittest.TestCase):
    RESPONSE = (
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/html; charset=utf-8\n"
        "content-type: text/html\n"
        "X-XSS-Protection: 1; mode=block\n"
        "Server: nginx\n"
    )

    def test_strict_mode_reports_protocol_and_policy_findings(self):
        findings = lint(self.RESPONSE)
        self.assertEqual(
            [(f.line, f.code) for f in findings],
            [
                (1, "missing-recommended-header"),
                (1, "missing-recommended-header"),
                (3, "duplicate-header"),
                (4, "deprecated-header"),
            ],
        )

    def test_lenient_mode_skips_policy_findings(self):
        findings = lint(self.RESPONSE, lenient=True)
        self.assertEqual([(f.line, f.code) for f in findings], [(3, "duplicate-header")])

    def test_findings_are_sorted_by_line_then_code(self):
        # the duplicate-header finding (line 2) is appended to the findings
        # list after the malformed-line finding (line 3), since duplicate
        # checking runs as a separate pass once parsing is done - lint()
        # has to sort them back into line order itself.
        text = "Content-Type: text/html\ncontent-type: text/plain\nno colon here\n"
        findings = lint(text, lenient=True)
        self.assertEqual(
            [(f.line, f.code) for f in findings],
            [(2, "duplicate-header"), (3, "malformed-line")],
        )

    def test_clean_input_has_no_findings(self):
        text = (
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=31536000\n"
            "X-Content-Type-Options: nosniff\n"
        )
        self.assertEqual(lint(text), [])

    def test_finding_str_format(self):
        finding = Finding(3, "error", "duplicate-header", "'X' was already set")
        self.assertEqual(str(finding), "3: error: duplicate-header: 'X' was already set")


if __name__ == "__main__":
    unittest.main()
