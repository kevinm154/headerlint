# headerlint

A linter for raw HTTP header blocks. It reads a chunk of headers - pasted
from `curl -i`, saved from a proxy log, dumped by a test harness, whatever -
and reports problems with the line number they occurred on.

Most tools that touch HTTP headers either parse them permissively (because
that's what browsers and servers do in practice) or don't check them at all.
That's the right call for a production HTTP client, and the wrong call for a
linter: if you're specifically looking to review headers, you want to be
told about the duplicate `Content-Type`, the header that only has an effect
in HTTP/1.0, the response that forgot `Strict-Transport-Security`, not have
those things silently tolerated.

## Strict by default

Two kinds of things get flagged:

- **Protocol-level problems** - a line with no `:`, a header name with
  invalid characters, obsolete line folding, headers repeated in a way that
  has no defined meaning. These always run; they're not opinions.
- **Policy-level problems** - headers that are deprecated but still show up
  in the wild (`X-XSS-Protection`, `Public-Key-Pins`), and responses that
  are missing headers like `Strict-Transport-Security`. These run by
  default too, because "strict by default" is the point.

Pass `--lenient` to turn off the policy-level layer and check protocol
correctness only. Use it when you're linting headers you don't control and
have no way to change the security posture of - a vendor's API response, a
third-party webhook - and just want to know the headers are well-formed.

## Usage

```
$ python -m headerlint response.http
```

Given `response.http`:

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
content-type: text/html
X-XSS-Protection: 1; mode=block
Server: nginx
```

strict mode (the default) reports:

```
1: warning: missing-recommended-header: response has no 'strict-transport-security' header: without it, a plain-HTTP request can be intercepted before the first redirect
1: warning: missing-recommended-header: response has no 'x-content-type-options' header: without 'nosniff', some browsers will still sniff content types on this response
3: error: duplicate-header: 'content-type' was already set on line 2; duplicates of this header have undefined precedence
4: warning: deprecated-header: 'X-XSS-Protection' is deprecated: the XSS auditor it controlled has been removed from all major browsers
```

`headerlint --lenient response.http` reports only the duplicate header,
since that's a protocol-level finding rather than a policy one:

```
3: error: duplicate-header: 'content-type' was already set on line 2; duplicates of this header have undefined precedence
```

The exit code is `1` if any finding has severity `error`, `0` otherwise -
`warning` findings never fail the run on their own. Read from stdin with
`-`:

```
$ curl -si https://example.com | python -m headerlint -
```

## Library use

```python
from headerlint import lint

for finding in lint(header_text, lenient=False):
    print(finding.line, finding.severity, finding.code, finding.message)
```

`lint()` returns a list of `Finding` objects sorted by line number, so you
can wire it into whatever reporting format you actually need.

## Installing

No third-party dependencies - standard library only. To get the
`headerlint` command on your PATH:

```
$ pip install -e .
```

Or skip installing entirely and run it as a module from a checkout, as
shown above.

## Status

Early. The rule set covers the headers that come up most often in practice,
not every header in the registry. See the issue tracker for what's planned.
