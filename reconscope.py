#!/usr/bin/env python3
"""ReconScope: lightweight website reconnaissance for authorized assessments.

This tool performs a small number of non-destructive DNS, HTTP-header, TLS,
robots.txt, and sitemap checks. It does not brute-force paths or scan ports.
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import requests

try:
    import dns.resolver  # type: ignore
except ImportError:
    dns = None  # type: ignore
else:
    dns = __import__("dns")

APP_NAME = "ReconScope"
VERSION = "1.0.0"
USER_AGENT = f"ReconScope/{VERSION} (authorized-security-assessment)"
TIMEOUT_SECONDS = 6
MAX_TEXT_BYTES = 64 * 1024

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content Security Policy",
    "x-content-type-options": "MIME-sniffing protection",
    "referrer-policy": "Referrer policy",
    "permissions-policy": "Permissions policy",
    "x-frame-options": "Clickjacking protection (legacy alternative to CSP frame-ancestors)",
}


def normalize_target(value: str) -> tuple[str, str]:
    """Return (origin_url, hostname), validating that the input is HTTP(S)."""
    value = value.strip()
    if not value:
        raise ValueError("Target cannot be empty.")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http:// and https:// targets are supported.")
    if not parsed.hostname:
        raise ValueError("Target must include a valid hostname, for example example.com.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded usernames/passwords are not supported.")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Target URL contains an invalid port.") from exc
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if not host or any(ch.isspace() for ch in host):
        raise ValueError("Target hostname is invalid.")
    origin = urlunparse((parsed.scheme.lower(), parsed.netloc, "", "", "", ""))
    return origin, host


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def resolve_dns(hostname: str) -> dict[str, Any]:
    result: dict[str, Any] = {"hostname": hostname, "addresses": [], "records": {}, "notes": []}
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        result["addresses"] = sorted({info[4][0] for info in infos})
    except socket.gaierror as exc:
        result["notes"].append(f"System resolver: {exc}")

    if dns is None:
        result["notes"].append("Optional DNS record lookups are unavailable; install requirements.txt.")
        return result

    resolver = dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT_SECONDS
    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        try:
            answers = resolver.resolve(hostname, record_type, raise_on_no_answer=False)
            if answers.rrset:
                result["records"][record_type] = [str(answer).strip('"') for answer in answers]
            else:
                result["records"][record_type] = []
        except Exception as exc:
            result["records"][record_type] = []
            result["notes"].append(f"{record_type} lookup: {type(exc).__name__}")
    return result


def get_web_response(origin_url: str, timeout: float) -> tuple[dict[str, Any], str | None]:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
    errors: list[str] = []
    parsed = urlparse(origin_url)
    candidates = [origin_url]
    if parsed.scheme == "https":
        candidates.append(urlunparse(("http", parsed.netloc, "", "", "", "")))

    for candidate in candidates:
        start = time.perf_counter()
        try:
            with session.get(candidate, timeout=timeout, allow_redirects=True, stream=True) as response:
                elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
                headers = {key.lower(): value for key, value in response.headers.items()}
                present = [name for key, name in SECURITY_HEADERS.items() if key in headers]
                missing = [name for key, name in SECURITY_HEADERS.items() if key not in headers]
                cookies = response.headers.get("Set-Cookie", "")
                cookie_flags = {
                    "Secure": bool(re.search(r"(?:^|;\s*)secure(?:;|$)", cookies, re.I)),
                    "HttpOnly": bool(re.search(r"(?:^|;\s*)httponly(?:;|$)", cookies, re.I)),
                    "SameSite": bool(re.search(r"(?:^|;\s*)samesite=", cookies, re.I)),
                    "Set-Cookie header observed": bool(cookies),
                }
                tech_hints = []
                for header_name, label in (("server", "Server header"), ("x-powered-by", "X-Powered-By header"), ("x-generator", "Generator header")):
                    if headers.get(header_name):
                        tech_hints.append({"source": label, "value": headers[header_name][:200]})
                return {
                    "requested_url": candidate,
                    "final_url": response.url,
                    "status_code": response.status_code,
                    "reason": response.reason,
                    "elapsed_ms": elapsed_ms,
                    "content_type": headers.get("content-type", ""),
                    "server_header": headers.get("server"),
                    "redirect_count": len(response.history),
                    "https_used": urlparse(response.url).scheme == "https",
                    "security_headers_present": present,
                    "security_headers_missing": missing,
                    "cookie_flags": cookie_flags,
                    "technology_hints": tech_hints,
                    "notes": ["Header checks are indicators only; missing headers do not automatically prove an exploitable vulnerability."],
                }, None
        except requests.RequestException as exc:
            errors.append(f"{candidate}: {type(exc).__name__}")
    return {"errors": errors}, "Could not reach target over HTTPS or HTTP."


def analyze_tls(hostname: str, port: int = 443, timeout: float = TIMEOUT_SECONDS) -> dict[str, Any]:
    """Inspect a TLS certificate with normal certificate verification enabled."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                cert = tls_socket.getpeercert()
                expiry_raw = cert.get("notAfter")
                expiry_utc = None
                days_remaining = None
                if expiry_raw:
                    expiry_ts = ssl.cert_time_to_seconds(expiry_raw)
                    expiry_dt = datetime.fromtimestamp(expiry_ts, tz=timezone.utc)
                    expiry_utc = expiry_dt.isoformat(timespec="seconds")
                    days_remaining = (expiry_dt - datetime.now(timezone.utc)).days
                subject = {key: value for group in cert.get("subject", []) for key, value in group}
                issuer = {key: value for group in cert.get("issuer", []) for key, value in group}
                return {
                    "hostname": hostname, "port": port, "tls_version": tls_socket.version(),
                    "cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
                    "subject": subject, "issuer": issuer, "valid_from": cert.get("notBefore"),
                    "valid_until": expiry_utc, "days_remaining": days_remaining,
                    "subject_alt_names": [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"][:100],
                    "verification": "passed (system trust store)",
                }
    except Exception as exc:
        return {"hostname": hostname, "error": f"{type(exc).__name__}: {exc}", "verification": "not confirmed"}


def check_common_paths(final_url: str, timeout: float) -> dict[str, Any]:
    """Fetch only robots.txt and sitemap.xml; this is not directory brute forcing."""
    base = urlparse(final_url)
    origin = urlunparse((base.scheme, base.netloc, "", "", "", ""))
    results: dict[str, Any] = {}
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    for path in ("/robots.txt", "/sitemap.xml"):
        url = origin.rstrip("/") + path
        try:
            with session.get(url, timeout=timeout, allow_redirects=True, stream=True) as response:
                sample = b""
                for chunk in response.iter_content(chunk_size=8192):
                    sample += chunk
                    if len(sample) >= MAX_TEXT_BYTES:
                        sample = sample[:MAX_TEXT_BYTES]
                        break
                text_sample = sample.decode(response.encoding or "utf-8", errors="replace")
                results[path] = {
                    "status_code": response.status_code, "final_url": response.url,
                    "content_type": response.headers.get("Content-Type", ""),
                    "sample_bytes_read": len(sample), "sample_truncated": len(sample) >= MAX_TEXT_BYTES,
                    "sample_lines": text_sample.splitlines()[:20] if response.status_code < 400 else [],
                }
        except requests.RequestException as exc:
            results[path] = {"error": type(exc).__name__}
    return results


def run_assessment(target: str, timeout: float) -> dict[str, Any]:
    origin, hostname = normalize_target(target)
    report: dict[str, Any] = {
        "tool": APP_NAME, "version": VERSION, "created_at_utc": utc_now(),
        "target": {"input": target, "origin": origin, "hostname": hostname},
        "scope_note": "Run only against systems you own or have explicit permission to assess.",
    }
    print(f"[*] {APP_NAME} {VERSION} — authorized, low-impact checks")
    print(f"[*] Target: {hostname}")
    print("[1/4] Resolving DNS records...")
    report["dns"] = resolve_dns(hostname)
    print("[2/4] Inspecting HTTP response and security headers...")
    http_result, http_error = get_web_response(origin, timeout)
    report["http"] = http_result
    if http_error:
        report["http_error"] = http_error
    final_url = http_result.get("final_url", origin)
    print("[3/4] Checking TLS certificate (verification enabled)...")
    final_parsed = urlparse(final_url)
    if final_parsed.scheme == "https":
        report["tls"] = analyze_tls(final_parsed.hostname or hostname, final_parsed.port or 443, timeout)
    elif urlparse(origin).scheme == "https":
        origin_parsed = urlparse(origin)
        report["tls"] = analyze_tls(hostname, origin_parsed.port or 443, timeout)
    else:
        report["tls"] = {"note": "TLS check skipped because the final URL uses HTTP."}
    print("[4/4] Checking robots.txt and sitemap.xml...")
    report["public_files"] = check_common_paths(final_url, timeout) if "final_url" in http_result else {}
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="reconscope.py",
        description="ReconScope: low-impact website reconnaissance for authorized assessments.",
        epilog="Example: python reconscope.py example.com --authorized --output report.json",
    )
    parser.add_argument("target", help="Domain or HTTP(S) URL to assess")
    parser.add_argument("--authorized", action="store_true", help="Confirm you own the target or have written permission")
    parser.add_argument("--timeout", type=float, default=TIMEOUT_SECONDS, help=f"Per-request timeout in seconds (default: {TIMEOUT_SECONDS})")
    parser.add_argument("--output", type=Path, default=Path("recon-report.json"), help="JSON report path (default: recon-report.json)")
    args = parser.parse_args(argv)

    if not args.authorized:
        parser.error("You must pass --authorized to confirm you have permission to assess this target.")
    if not 1 <= args.timeout <= 30:
        parser.error("--timeout must be between 1 and 30 seconds.")
    try:
        report = run_assessment(args.target, args.timeout)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"[+] Report saved to: {args.output.resolve()}")
        http = report.get("http", {})
        if "status_code" in http:
            print(f"[+] HTTP status: {http['status_code']} | elapsed: {http['elapsed_ms']} ms")
        missing = http.get("security_headers_missing", [])
        if missing:
            print(f"[!] Missing security-header indicators: {len(missing)} (review report; not proof of a vulnerability)")
        return 0
    except (ValueError, OSError) as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
