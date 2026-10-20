#!/usr/bin/env python3
"""Probe Angelos (:5000) and Athens metrics (:9000) against their OpenAPI specs.

Reads path lists from angelos_api.yml and athens-metrics-api.yml next to the
repo root (or --spec-dir). Does not mutate edge state unless --mutate is set.

Examples:
  # Metrics + Angelos route reachability (no edge token needed)
  ./scripts/check_edge_apis.py --edge 203.0.113.10

  # Also call L4 options with a real edge token
  ./scripts/check_edge_apis.py --edge 203.0.113.10 --token "$EDGE_TOKEN"

  # Metrics only, one site, JSON report
  ./scripts/check_edge_apis.py --edge 203.0.113.10 --suite metrics --site-id 12 --json

  # Discover edges from the control plane, then probe each
  ./scripts/check_edge_apis.py --panel http://127.0.0.1:8080 --panel-token "$JWT" --all-edges

Exit codes: 0 = all PASS/WARN/SKIP, 1 = at least one FAIL, 2 = usage / setup error.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_METRICS_SPEC = REPO_ROOT / "athens-metrics-api.yml"
DEFAULT_ANGELOS_SPEC = REPO_ROOT / "angelos_api.yml"

PASS, FAIL, WARN, SKIP = "PASS", "FAIL", "WARN", "SKIP"
NOT_IMPLEMENTED_MARKERS = (
    "welcome to default server",
    "<!doctype html>",
    "<html",
    "404 not found",
)


@dataclass
class CheckResult:
    suite: str
    method: str
    path: str
    status: str
    http_status: int | None = None
    ms: int = 0
    detail: str = ""
    tags: list[str] = field(default_factory=list)

    def line(self, mask_host: str | None = None) -> str:
        path = self.path
        if mask_host and mask_host in path:
            path = path.replace(mask_host, mask_ip(mask_host))
        code = f"{self.http_status}" if self.http_status is not None else "-"
        return f"{self.status:4}  {self.ms:5}ms  HTTP {code:>3}  {self.method:6} {path}  {self.detail}"


def mask_ip(host: str) -> str:
    if ":" in host and host.count(":") > 1:
        parts = host.split(":")
        return ":".join(parts[:2] + ["••••"])
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.•••.•••"
    return host


def load_spec(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def resolve_ref(spec: dict[str, Any], node: Any) -> Any:
    if not isinstance(node, dict) or "$ref" not in node:
        return node
    ref = node["$ref"]
    if not ref.startswith("#/"):
        return node
    cur: Any = spec
    for part in ref[2:].split("/"):
        cur = cur[part]
    return cur


def response_schema(spec: dict[str, Any], op: dict[str, Any]) -> dict[str, Any] | None:
    responses = op.get("responses") or {}
    for code in ("200", "201", "204"):
        if code not in responses:
            continue
        resp = resolve_ref(spec, responses[code])
        content = resp.get("content") or {}
        for ctype in (
            "application/json",
            "application/x-ndjson",
            "text/plain",
            "application/octet-stream",
        ):
            if ctype in content:
                return resolve_ref(spec, content[ctype].get("schema") or {})
        # bare $ref response with nested content already resolved
        if "schema" in resp:
            return resolve_ref(spec, resp["schema"])
    return None


def required_keys(schema: dict[str, Any] | None) -> list[str]:
    if not schema or not isinstance(schema, dict):
        return []
    if schema.get("type") == "array":
        return []
    return list(schema.get("required") or [])


def tcp_open(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "open"
    except OSError as exc:
        return False, str(exc)


def http_request(
    method: str,
    url: str,
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes, int]:
    req = urllib.request.Request(url, data=body, method=method.upper())
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.getcode(), hdrs, raw, int((time.monotonic() - started) * 1000)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        hdrs = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
        return exc.code, hdrs, raw, int((time.monotonic() - started) * 1000)


def looks_unimplemented(body: bytes) -> bool:
    text = body[:500].decode("utf-8", errors="replace").strip().lower()
    return any(marker in text for marker in NOT_IMPLEMENTED_MARKERS)


def parse_json_body(body: bytes) -> tuple[Any | None, str]:
    if not body.strip():
        return None, "empty body"
    text = body.decode("utf-8", errors="replace").strip()
    try:
        return json.loads(text), ""
    except json.JSONDecodeError as exc:
        # Some Sparta error paths concatenate two JSON objects; take the first.
        decoder = json.JSONDecoder()
        try:
            data, _end = decoder.raw_decode(text)
            return data, ""
        except json.JSONDecodeError:
            preview = text[:80].replace("\n", " ")
            return None, f"not JSON ({exc.msg}): {preview!r}"


def validate_json(data: Any, schema: dict[str, Any] | None) -> str:
    if schema is None:
        return ""
    schema = schema if isinstance(schema, dict) else {}
    stype = schema.get("type")
    if stype == "array":
        if not isinstance(data, list):
            return f"expected array, got {type(data).__name__}"
        return ""
    if stype == "object" or schema.get("properties") or schema.get("required"):
        if not isinstance(data, dict):
            return f"expected object, got {type(data).__name__}"
        missing = [k for k in required_keys(schema) if k not in data]
        if missing:
            return f"missing required fields: {', '.join(missing)}"
    return ""


def sign_l7(path: str, body: bytes, token: str, now: int | None = None) -> dict[str, str]:
    """HMAC headers matching internal/api/edge_l7.go."""
    ts = str(now if now is not None else int(time.time()))
    body_hash = hashlib.sha256(body).hexdigest()
    message = f"POST\n{path}\n{ts}\n{body_hash}"
    sig = hmac.new(token.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Dorian-Timestamp": ts,
        "X-Dorian-Signature": f"v1={sig}",
    }


# ---------------------------------------------------------------------------
# Athens metrics
# ---------------------------------------------------------------------------


def metrics_paths(spec: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    out = []
    for path, item in (spec.get("paths") or {}).items():
        op = item.get("get")
        if op:
            out.append((path, op))
    return out


def check_metrics(
    host: str,
    port: int,
    spec: dict[str, Any],
    *,
    timeout: float,
    site_id: int | None,
) -> list[CheckResult]:
    results: list[CheckResult] = []
    base = f"http://{host}:{port}"

    ok, detail = tcp_open(host, port, timeout)
    results.append(
        CheckResult(
            suite="metrics",
            method="TCP",
            path=f"{host}:{port}",
            status=PASS if ok else FAIL,
            detail=detail,
        )
    )
    if not ok:
        return results

    # Cache latest timestamp per family so /stats calls use a real bucket.
    latest: dict[str, str] = {}

    for path, op in metrics_paths(spec):
        tags = list(op.get("tags") or [])
        summary = op.get("summary") or ""

        if path.endswith("/timestamps"):
            url = base + path
            code, _hdrs, body, ms = http_request("GET", url, timeout=timeout)
            if looks_unimplemented(body):
                results.append(
                    CheckResult("metrics", "GET", path, FAIL, code, ms, "not implemented (default page)", tags)
                )
                continue
            data, err = parse_json_body(body)
            if code != 200 or err:
                # Sparta down returns JSON 500 — treat as WARN for L4 timestamps.
                if code >= 500 and data and isinstance(data, dict) and data.get("error"):
                    results.append(
                        CheckResult(
                            "metrics",
                            "GET",
                            path,
                            WARN,
                            code,
                            ms,
                            f"edge error: {data.get('error')}",
                            tags,
                        )
                    )
                else:
                    results.append(
                        CheckResult("metrics", "GET", path, FAIL, code, ms, err or f"unexpected status", tags)
                    )
                continue
            if not isinstance(data, list):
                results.append(
                    CheckResult("metrics", "GET", path, FAIL, code, ms, f"expected array, got {type(data).__name__}", tags)
                )
                continue
            family = path[: -len("/timestamps")]
            if data:
                latest[family] = str(data[-1])
            results.append(
                CheckResult(
                    "metrics",
                    "GET",
                    path,
                    PASS,
                    code,
                    ms,
                    f"{len(data)} bucket(s)" + (f", latest={data[-1]}" if data else ", empty"),
                    tags,
                )
            )
            continue

        if path == "/access_logs":
            end = int(time.time())
            start = end - 3600
            query = {"start": start, "end": end, "limit": 5, "type": "access"}
            if site_id is not None:
                query["siteId"] = site_id
            url = base + path + "?" + urllib.parse.urlencode(query)
            code, hdrs, body, ms = http_request("GET", url, timeout=timeout)
            if looks_unimplemented(body):
                results.append(
                    CheckResult("metrics", "GET", path, FAIL, code, ms, "not implemented (default page)", tags)
                )
                continue
            if code == 416:
                results.append(
                    CheckResult("metrics", "GET", path, WARN, code, ms, "outside retention", tags)
                )
                continue
            if code != 200:
                data, _ = parse_json_body(body)
                msg = ""
                if isinstance(data, dict):
                    msg = str(data.get("error") or data)
                results.append(
                    CheckResult("metrics", "GET", path, FAIL, code, ms, msg or "unexpected status", tags)
                )
                continue
            # NDJSON: zero or more JSON objects, one per line.
            lines = [ln for ln in body.decode("utf-8", errors="replace").splitlines() if ln.strip()]
            bad = 0
            schema = response_schema(spec, op)
            for ln in lines:
                try:
                    row = json.loads(ln)
                except json.JSONDecodeError:
                    bad += 1
                    continue
                if schema and (err := validate_json(row, schema)):
                    bad += 1
                    results.append(
                        CheckResult("metrics", "GET", path, FAIL, code, ms, f"record invalid: {err}", tags)
                    )
                    break
            else:
                ctype = hdrs.get("content-type", "")
                note = f"{len(lines)} record(s)"
                if "ndjson" not in ctype and lines:
                    note += f" (content-type={ctype or 'missing'})"
                results.append(CheckResult("metrics", "GET", path, PASS if bad == 0 else FAIL, code, ms, note, tags))
            continue

        # Regular stats / req-status
        query: dict[str, Any] = {}
        family = path
        if family in latest:
            query["timestamp"] = latest[family]
        if site_id is not None and "siteId" in str(op.get("parameters") or []):
            query["siteId"] = site_id
        # Also detect SiteId $ref in parameters
        for param in op.get("parameters") or []:
            resolved = resolve_ref(spec, param)
            name = resolved.get("name")
            if name == "siteId" and site_id is not None:
                query["siteId"] = site_id
        url = base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        label = path + (("?" + urllib.parse.urlencode(query)) if query else "")
        code, hdrs, body, ms = http_request("GET", url, timeout=timeout)
        if looks_unimplemented(body):
            results.append(
                CheckResult("metrics", "GET", label, FAIL, code, ms, "not implemented (default page)", tags)
            )
            continue
        data, err = parse_json_body(body)
        if isinstance(data, dict) and (data.get("error") or data.get("status") == "error"):
            err_msg = str(data.get("error") or data.get("message") or data.get("details") or "edge error")
            # Operational edge faults (Sparta down, empty bucket) are warnings, not missing routes.
            status = WARN if code in (404, 500, 502, 503) or "not running" in err_msg.lower() else FAIL
            if code == 200 and "not running" not in err_msg.lower():
                status = FAIL
            results.append(
                CheckResult("metrics", "GET", label, status, code, ms, f"edge error: {err_msg}", tags)
            )
            continue
        if code != 200 or err:
            results.append(
                CheckResult("metrics", "GET", label, FAIL, code, ms, err or "unexpected status", tags)
            )
            continue
        schema = response_schema(spec, op)
        # Prefer example-based required keys when schema is a loose object.
        verr = validate_json(data, schema)
        if verr:
            results.append(CheckResult("metrics", "GET", label, FAIL, code, ms, verr, tags))
            continue
        # Soft check: known top-level keys for server / site traffic.
        if path == "/server_traffic_stats" and isinstance(data, dict):
            expect = ("request_count", "traffic_nic_rx", "traffic_l7_rx")
            missing = [k for k in expect if k not in data]
            if missing:
                results.append(
                    CheckResult(
                        "metrics",
                        "GET",
                        label,
                        FAIL,
                        code,
                        ms,
                        f"missing traffic fields: {', '.join(missing)}",
                        tags,
                    )
                )
                continue
        ctype = hdrs.get("content-type", "")
        note = summary or "ok"
        if isinstance(data, dict):
            note = f"keys={len(data)}"
        elif isinstance(data, list):
            note = f"{len(data)} item(s)"
        if "json" not in ctype:
            note += f" (content-type={ctype or 'missing'})"
        results.append(CheckResult("metrics", "GET", label, PASS, code, ms, note, tags))

    return results


# ---------------------------------------------------------------------------
# Angelos
# ---------------------------------------------------------------------------


def angelos_paths(spec: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    out = []
    for path, item in (spec.get("paths") or {}).items():
        # Edge → panel callback lives on the control plane, not on Angelos.
        if path == "/report_edge_configure":
            continue
        op = item.get("post")
        if op:
            out.append((path, op))
    return out


def check_angelos(
    host: str,
    port: int,
    spec: dict[str, Any],
    *,
    timeout: float,
    token: str | None,
    mutate: bool,
) -> list[CheckResult]:
    results: list[CheckResult] = []
    base = f"http://{host}:{port}"

    ok, detail = tcp_open(host, port, timeout)
    results.append(
        CheckResult(
            suite="angelos",
            method="TCP",
            path=f"{host}:{port}",
            status=PASS if ok else FAIL,
            detail=detail,
        )
    )
    if not ok:
        return results

    for path, op in angelos_paths(spec):
        tags = list(op.get("tags") or [])
        is_l4 = path.startswith("/API/L4/")
        is_l7 = path.startswith("/API/L7/")

        # --- Route existence probe (no mutation) ---
        # Empty JSON body. Expected:
        #   L4 → 401/403 invalid token
        #   L7 → 400 missing field, or 401 bad signature
        # Never 404 (missing route) or connection error.
        code, _hdrs, body, ms = http_request(
            "POST",
            base + path,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
            body=b"{}",
        )
        data, _ = parse_json_body(body)
        msg = ""
        if isinstance(data, dict):
            msg = str(data.get("message") or data.get("error") or data.get("status") or "")

        if code == 404 or looks_unimplemented(body):
            results.append(
                CheckResult("angelos", "POST", path, FAIL, code, ms, "route missing / not implemented", tags)
            )
            continue
        if is_l4 and code in (401, 403):
            results.append(
                CheckResult("angelos", "POST", path, PASS, code, ms, msg or "auth rejected empty token", tags)
            )
        elif is_l7 and code in (400, 401, 403):
            results.append(
                CheckResult("angelos", "POST", path, PASS, code, ms, msg or "validation/auth rejected", tags)
            )
        elif 200 <= code < 300:
            # Unexpected success with empty body — route exists but may have mutated.
            results.append(
                CheckResult(
                    "angelos",
                    "POST",
                    path,
                    WARN,
                    code,
                    ms,
                    "accepted empty body (check Angelos validation)",
                    tags,
                )
            )
        else:
            results.append(
                CheckResult("angelos", "POST", path, FAIL, code, ms, msg or "unexpected status", tags)
            )

    # --- Authenticated L4 options (safe read) ---
    if token:
        payload = json.dumps({"token": token}).encode("utf-8")
        code, _hdrs, body, ms = http_request(
            "POST",
            base + "/API/L4/options",
            timeout=timeout,
            headers={"Content-Type": "application/json"},
            body=payload,
        )
        data, err = parse_json_body(body)
        if code == 200 and isinstance(data, dict) and ("interfaces" in data or "attachModes" in data):
            n_if = len(data.get("interfaces") or [])
            n_modes = len(data.get("attachModes") or [])
            results.append(
                CheckResult(
                    "angelos",
                    "POST",
                    "/API/L4/options?token=…",
                    PASS,
                    code,
                    ms,
                    f"interfaces={n_if} attachModes={n_modes}",
                    ["L4"],
                )
            )
        else:
            msg = ""
            if isinstance(data, dict):
                msg = str(data.get("message") or data.get("error") or "")
            results.append(
                CheckResult(
                    "angelos",
                    "POST",
                    "/API/L4/options?token=…",
                    FAIL,
                    code,
                    ms,
                    msg or err or "options call failed",
                    ["L4"],
                )
            )

        # Signed L7 probe: missing required field should still 400 (proves HMAC accepted).
        l7_body = json.dumps({"serverId": 0, "siteId": 0, "rules": []}).encode("utf-8")
        path = "/API/L7/l7_update_whitelist"
        headers = sign_l7(path, l7_body, token)
        code, _hdrs, body, ms = http_request(
            "POST",
            base + path,
            timeout=timeout,
            headers=headers,
            body=l7_body,
        )
        data, _ = parse_json_body(body)
        msg = ""
        if isinstance(data, dict):
            msg = str(data.get("message") or data.get("error") or "")
        if code in (401, 403):
            results.append(
                CheckResult(
                    "angelos",
                    "POST",
                    path + " (signed)",
                    FAIL,
                    code,
                    ms,
                    msg or "signature rejected",
                    ["L7"],
                )
            )
        elif code in (400, 404, 422) or 200 <= code < 300:
            # 400 = signature accepted, payload rejected; 2xx = empty rules accepted.
            results.append(
                CheckResult(
                    "angelos",
                    "POST",
                    path + " (signed)",
                    PASS,
                    code,
                    ms,
                    msg or f"signed probe ok (HTTP {code})",
                    ["L7"],
                )
            )
        else:
            results.append(
                CheckResult(
                    "angelos",
                    "POST",
                    path + " (signed)",
                    FAIL,
                    code,
                    ms,
                    msg or "signed probe failed",
                    ["L7"],
                )
            )
    else:
        results.append(
            CheckResult(
                "angelos",
                "POST",
                "/API/L4/options (authenticated)",
                SKIP,
                detail="pass --token <edge servers.token> for a live L4 options check",
                tags=["L4"],
            )
        )

    if not mutate:
        results.append(
            CheckResult(
                "angelos",
                "-",
                "mutating L4/L7 pushes",
                SKIP,
                detail="omitted (add --mutate to push real config — not recommended on production)",
            )
        )

    return results


# ---------------------------------------------------------------------------
# Panel discovery
# ---------------------------------------------------------------------------


def discover_edges(panel: str, panel_token: str, timeout: float) -> list[dict[str, Any]]:
    panel = panel.rstrip("/")
    for path in ("/servers", "/api/v1/servers"):
        code, _h, body, _ms = http_request(
            "GET",
            panel + path,
            timeout=timeout,
            headers={"Authorization": f"Bearer {panel_token}"},
        )
        if code == 200:
            data, err = parse_json_body(body)
            if err:
                raise RuntimeError(f"panel {path}: {err}")
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and isinstance(data.get("items"), list):
                return data["items"]
    raise RuntimeError("could not list /servers from panel (check --panel-token)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def summarize(results: list[CheckResult]) -> dict[str, int]:
    counts = {PASS: 0, FAIL: 0, WARN: 0, SKIP: 0}
    for row in results:
        counts[row.status] = counts.get(row.status, 0) + 1
    return counts


def print_report(results: list[CheckResult], *, mask: bool, host: str) -> None:
    width = 78
    print("=" * width)
    title_host = mask_ip(host) if mask else host
    print(f"Edge API check · {title_host}")
    print("=" * width)
    current = None
    for row in results:
        if row.suite != current:
            current = row.suite
            print(f"\n[{current}]")
        print(row.line(mask_host=host if mask else None))
    counts = summarize(results)
    print("\n" + "-" * width)
    print(
        f"PASS {counts[PASS]}  FAIL {counts[FAIL]}  WARN {counts[WARN]}  SKIP {counts[SKIP]}  "
        f"total {len(results)}"
    )
    print("-" * width)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check Angelos and Athens metrics APIs against their OpenAPI specs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--edge", action="append", dest="edges", help="Edge IP or hostname (repeatable)")
    parser.add_argument("--all-edges", action="store_true", help="Discover edges via --panel")
    parser.add_argument("--panel", default=os.environ.get("PANEL_URL", ""), help="Control-plane base URL")
    parser.add_argument(
        "--panel-token",
        default=os.environ.get("PANEL_TOKEN", ""),
        help="Bearer token for the control plane (or PANEL_TOKEN)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("EDGE_TOKEN", os.environ.get("AGENT_TOKEN", "")),
        help="Edge servers.token for authenticated Angelos checks (or EDGE_TOKEN)",
    )
    parser.add_argument(
        "--suite",
        choices=("all", "metrics", "angelos"),
        default="all",
        help="Which APIs to probe (default: all)",
    )
    parser.add_argument("--metrics-port", type=int, default=int(os.environ.get("METRICS_PORT", "9000")))
    parser.add_argument("--angelos-port", type=int, default=int(os.environ.get("AGENT_PORT", "5000")))
    parser.add_argument("--site-id", type=int, default=None, help="Optional siteId for site-scoped metrics")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--mutate", action="store_true", help="Allow mutating pushes (unused unless extended)")
    parser.add_argument("--mask-ip", action="store_true", help="Mask IPs in the report")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--spec-dir", type=Path, default=REPO_ROOT, help="Directory with the OpenAPI YAML files")
    parser.add_argument(
        "--metrics-spec",
        type=Path,
        default=None,
        help="Override path to athens-metrics-api.yml",
    )
    parser.add_argument(
        "--angelos-spec",
        type=Path,
        default=None,
        help="Override path to angelos_api.yml",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    metrics_spec_path = args.metrics_spec or (args.spec_dir / "athens-metrics-api.yml")
    angelos_spec_path = args.angelos_spec or (args.spec_dir / "angelos_api.yml")

    edges: list[str] = list(args.edges or [])
    edge_tokens: dict[str, str] = {}

    if args.all_edges:
        if not args.panel or not args.panel_token:
            print("--all-edges needs --panel and --panel-token", file=sys.stderr)
            return 2
        try:
            servers = discover_edges(args.panel, args.panel_token, args.timeout)
        except Exception as exc:  # noqa: BLE001
            print(f"panel discovery failed: {exc}", file=sys.stderr)
            return 2
        for server in servers:
            ip = str(server.get("ip") or "").strip()
            if not ip:
                continue
            edges.append(ip)
            tok = str(server.get("token") or "").strip()
            if tok:
                edge_tokens[ip] = tok

    edges = list(dict.fromkeys(edges))  # preserve order, unique
    if not edges:
        print("Pass --edge HOST or --all-edges with panel credentials.", file=sys.stderr)
        return 2

    metrics_spec = load_spec(metrics_spec_path) if args.suite in ("all", "metrics") else {}
    angelos_spec = load_spec(angelos_spec_path) if args.suite in ("all", "angelos") else {}

    if args.suite in ("all", "metrics") and not metrics_spec.get("paths"):
        print(f"no paths in {metrics_spec_path}", file=sys.stderr)
        return 2
    if args.suite in ("all", "angelos") and not angelos_spec.get("paths"):
        print(f"no paths in {angelos_spec_path}", file=sys.stderr)
        return 2

    all_results: list[CheckResult] = []
    worst = 0

    for host in edges:
        token = args.token or edge_tokens.get(host) or None
        results: list[CheckResult] = []
        if args.suite in ("all", "metrics"):
            results.extend(
                check_metrics(
                    host,
                    args.metrics_port,
                    metrics_spec,
                    timeout=args.timeout,
                    site_id=args.site_id,
                )
            )
        if args.suite in ("all", "angelos"):
            results.extend(
                check_angelos(
                    host,
                    args.angelos_port,
                    angelos_spec,
                    timeout=args.timeout,
                    token=token,
                    mutate=args.mutate,
                )
            )
        all_results.extend(results)
        counts = summarize(results)
        if counts[FAIL]:
            worst = 1
        if args.json:
            continue
        print_report(results, mask=args.mask_ip, host=host)

    if args.json:
        payload = {
            "edges": [mask_ip(e) if args.mask_ip else e for e in edges],
            "counts": summarize(all_results),
            "results": [asdict(r) for r in all_results],
        }
        if args.mask_ip:
            for row in payload["results"]:
                row["path"] = row["path"].replace(edges[0], mask_ip(edges[0])) if edges else row["path"]
        json.dump(payload, sys.stdout, indent=2)
        print()

    return worst


if __name__ == "__main__":
    sys.exit(main())
