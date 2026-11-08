#!/usr/bin/env python3
"""Read-only reachability check for a published OAuth-protected MCP route.

Usage: check_mcp_route.py https://<mcp-host>/mcp [--timeout 15]

Sends one GET for protected-resource metadata and one unauthenticated POST to
the MCP endpoint. Sends no credentials, makes no tool call and changes nothing.
Exit 0 only when metadata is 200 JSON naming this resource and the POST is
401 with a Bearer resource_metadata challenge.
"""

import argparse
import json
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
        status, headers, body = fetch(metadata_url, timeout=args.timeout)
        if status != 200:
            failures.append(
                f"metadata {metadata_url} -> HTTP {status} (502: bridge/service down; 302: wrongly behind forward-auth)"
            )
        else:
            meta = json.loads(body)
            if meta.get("resource") != args.resource:
                failures.append(f"metadata resource {meta.get('resource')!r} != {args.resource!r}")
            if not meta.get("authorization_servers"):
                failures.append("metadata lists no authorization_servers")
            else:
                print(f"metadata OK: issuer {meta['authorization_servers'][0]}, scopes {meta.get('scopes_supported')}")
    except (urllib.error.URLError, OSError, ValueError) as error:
        failures.append(f"metadata request failed: {error}")

    try:
        status, headers, _ = fetch(args.resource, method="POST", body=b"{}", timeout=args.timeout)
        challenge = next((v for k, v in headers.items() if k.lower() == "www-authenticate"), "")
        if status != 401 or "resource_metadata=" not in challenge or not challenge.lower().startswith("bearer"):
            failures.append(
                f"unauthenticated POST /mcp -> HTTP {status}, challenge {challenge[:120]!r}; "
                "expected 401 Bearer resource_metadata"
            )
        else:
            print("challenge OK: 401 Bearer resource_metadata")
    except (urllib.error.URLError, OSError) as error:
        failures.append(f"POST request failed: {error}")

    for failure in failures:
        print(f"FAIL {failure}")
    print("PASS" if not failures else "FAILED")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
