from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


WRITE_METHODS = {"post", "put", "patch", "delete"}


def audit(spec: dict[str, Any], allowed_hosts: set[str]) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    servers = spec.get("servers")
    if not isinstance(servers, list) or not servers:
        findings.append({"severity": "high", "code": "no_servers", "subject": "openapi"})
        servers = []
    hosts: set[str] = set()
    for server in servers:
        url = server.get("url", "") if isinstance(server, dict) else ""
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            findings.append({"severity": "high", "code": "server_not_https", "subject": str(url)})
        elif parsed.hostname not in allowed_hosts:
            findings.append({"severity": "high", "code": "server_host_not_allowlisted", "subject": parsed.hostname})
        else:
            hosts.add(parsed.hostname)
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        findings.append({"severity": "error", "code": "invalid_paths", "subject": "openapi"})
        paths = {}
    operations = 0
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            findings.append({"severity": "error", "code": "invalid_path_item", "subject": str(path)})
            continue
        for method, operation in path_item.items():
            method = str(method).lower()
            if method not in {"get", "head", "options", "post", "put", "patch", "delete"}:
                continue
            operations += 1
            subject = f"{method.upper()} {path}"
            if not isinstance(operation, dict):
                findings.append({"severity": "error", "code": "invalid_operation", "subject": subject})
                continue
            if not operation.get("operationId"):
                findings.append({"severity": "medium", "code": "missing_operation_id", "subject": subject})
            if "security" not in operation and "security" not in spec:
                findings.append({"severity": "high", "code": "operation_without_auth", "subject": subject})
            if method in WRITE_METHODS and operation.get("x-requires-human-approval") is not True:
                findings.append({"severity": "high", "code": "write_without_approval_contract", "subject": subject})
            if operation.get("requestBody") and not operation.get("x-input-validation"):
                findings.append({"severity": "medium", "code": "request_body_without_validation_note", "subject": subject})
    return {"operations_checked": operations, "allowlisted_hosts_used": sorted(hosts),
            "findings": findings, "pass": not any(x["severity"] in {"high", "error"} for x in findings)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a JSON OpenAPI contract; never calls its servers.")
    parser.add_argument("spec", type=Path)
    parser.add_argument("--allow-host", action="append", default=[], help="Exact permitted server hostname; repeat as needed")
    args = parser.parse_args()
    try:
        data = json.loads(args.spec.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("OpenAPI input must be a JSON object.")
        report = audit(data, set(args.allow_host))
        print(json.dumps(report, indent=2))
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
