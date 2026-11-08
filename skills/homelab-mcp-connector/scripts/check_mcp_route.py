#!/usr/bin/env python3
"""Read-only reachability check for a published OAuth-protected MCP route.

Usage: check_mcp_route.py https://<mcp-host>/mcp [--timeout 15]

Sends one GET for protected-resource metadata and one unauthenticated POST to
the MCP endpoint. Sends no credentials, makes no tool call and changes nothing.
Exit 0 only when metadata is 200 JSON naming this resource and the POST is
401 with a Bearer challenge whose resource_metadata is an https URL, and the
metadata lists https issuer URLs in authorization_servers.
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


def fetch(url, method="GET", body=None, timeout=15):
    if not url.startswith("https://"):
        raise ValueError("only https URLs are fetched")
    request = urllib.request.Request(  # noqa: S310 - scheme restricted to https above
        url,
        method=method,
        data=body,
        headers={"content-type": "application/json", "accept": "application/json, text/event-stream"},
    )
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read(65536)
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read(65536)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_AUTH_PARAM = re.compile(r'\s*([A-Za-z0-9_.-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s,]*)\s*(?:,|$)')


def is_https_url(value):
    if not isinstance(value, str) or not value:
        return False
    parts = urllib.parse.urlsplit(value)
    return parts.scheme == "https" and bool(parts.netloc)


def parse_bearer_challenge(header):
    """Return Bearer auth-params, or None when the scheme is not exactly Bearer."""
    scheme, _, rest = header.strip().partition(" ")
    if scheme.lower() != "bearer":
        return None
    params = {}
    position = 0
    rest = rest.strip()
    while position < len(rest):
        match = _AUTH_PARAM.match(rest, position)
        if not match or match.end() == position:
            return None
        value = match.group(2)
        if value.startswith('"'):
            value = re.sub(r"\\(.)", r"\1", value[1:-1])
        params[match.group(1).lower()] = value
        position = match.end()
    return params


def check_metadata(status, body, resource, metadata_url):
    if status != 200:
        return [
            f"metadata {metadata_url} -> HTTP {status} (502: bridge/service down; 302: wrongly behind forward-auth)"
        ]
    try:
        meta = json.loads(body)
    except ValueError:
        return ["metadata is not valid JSON"]
    if not isinstance(meta, dict):
        return ["metadata is not a JSON object"]
    failures = []
    if meta.get("resource") != resource:
        failures.append(f"metadata resource {meta.get('resource')!r} != {resource!r}")
    servers = meta.get("authorization_servers")
    if not isinstance(servers, list) or not servers or not all(is_https_url(s) for s in servers):
        failures.append("metadata authorization_servers must be a nonempty list of https issuer URLs")
    return failures


def check_challenge(status, headers):
    challenge = next((v for k, v in headers.items() if k.lower() == "www-authenticate"), "")
    params = parse_bearer_challenge(challenge)
    if status != 401 or params is None or not is_https_url(params.get("resource_metadata")):
        return [
            f"unauthenticated POST /mcp -> HTTP {status}, challenge {challenge[:120]!r}; "
            "expected 401 Bearer with an https resource_metadata URL"
        ]
    return []


def main():
    parser = argparse.ArgumentParser(
        description="Read-only reachability check for a published OAuth-protected MCP route."
    )
    parser.add_argument("resource", help="canonical MCP resource URL, e.g. https://mcp.example.com/mcp")
    parser.add_argument("--timeout", type=float, default=15)
    args = parser.parse_args()
    url = urllib.parse.urlsplit(args.resource)
    if url.scheme != "https" or not url.netloc or url.query or url.fragment:
        parser.error("resource must be an https URL without query or fragment")
    path = "" if url.path in ("", "/") else url.path
    metadata_url = f"https://{url.netloc}/.well-known/oauth-protected-resource{path}"
    failures = []

    try:
        status, _, body = fetch(metadata_url, timeout=args.timeout)
        problems = check_metadata(status, body, args.resource, metadata_url)
        failures.extend(problems)
        if not problems:
            print("metadata OK: resource and issuer URL present")
    except (urllib.error.URLError, OSError, ValueError) as error:
        failures.append(f"metadata request failed: {error}")

    try:
        status, headers, _ = fetch(args.resource, method="POST", body=b"{}", timeout=args.timeout)
        problems = check_challenge(status, headers)
        failures.extend(problems)
        if not problems:
            print("challenge OK: 401 Bearer resource_metadata")
    except (urllib.error.URLError, OSError) as error:
        failures.append(f"POST request failed: {error}")

    for failure in failures:
        print(f"FAIL {failure}")
    print("PASS" if not failures else "FAILED")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
