#!/usr/bin/env python3
"""Build exactly 99 independent sing-box .srs rule sets for Karing."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import ipaddress
import json
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

import requests
import yaml

RULE_FIELDS = {
    "domain", "domain_suffix", "domain_keyword", "domain_regex",
    "ip_cidr", "source_ip_cidr", "port", "port_range",
    "source_port", "source_port_range", "process_name", "process_path",
    "network", "package_name",
}


def ordered_unique(values: Iterable[Any]) -> list[Any]:
    seen: set[str] = set()
    result: list[Any] = []
    for value in values:
        key = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def fetch(session: requests.Session, url: str, retries: int = 5) -> bytes:
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            response = session.get(url, timeout=(20, 150))
            response.raise_for_status()
            if not response.content:
                raise RuntimeError("empty response")
            return response.content
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < retries:
                time.sleep(min(2 ** (attempt - 1), 12))
    raise RuntimeError(f"download failed after {retries} attempts: {url}: {last_exc}")


def add(bucket: dict[str, list[Any]], field: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return
    bucket[field].append(value)


def normalize_domain(value: str) -> str:
    return value.strip().strip("'").strip('"').rstrip('.').lower()


def wildcard_to_regex(pattern: str) -> str:
    translated = fnmatch.translate(pattern)
    if translated.startswith("(?s:") and translated.endswith(")\\Z"):
        translated = translated[4:-3]
    return "^" + translated.strip("^").rstrip("$") + "$"


def strip_inline_comment(value: str) -> str:
    """Remove a YAML-style inline comment only when # follows whitespace."""
    return re.split(r"\s+#", value, maxsplit=1)[0].strip()


def quote_unquoted_wildcard_items(text: str) -> str:
    """Quote list items such as `- *.example.com` before PyYAML sees them.

    YAML interprets a leading asterisk as an alias token. Clash rule lists use it
    as an ordinary domain wildcard, so it must be treated as a string.
    """
    repaired: list[str] = []
    pattern = re.compile(r"^(\s*-\s*)(\*[^#\r\n]*?)(\s*(?:#.*)?)$")
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            value = match.group(2).strip()
            repaired.append(
                f"{match.group(1)}{json.dumps(value, ensure_ascii=False)}{match.group(3)}"
            )
        else:
            repaired.append(line)
    return "\n".join(repaired)


def extract_payload_fallback(text: str) -> list[str]:
    """Extract a simple Clash payload list without relying on YAML aliases.

    This fallback is intentionally conservative and is used only when the YAML
    parser still rejects an upstream list after wildcard repair.
    """
    lines = text.splitlines()
    payload_index: int | None = None
    payload_indent = -1
    for index, line in enumerate(lines):
        if re.match(r"^\s*payload\s*:\s*(?:#.*)?$", line):
            payload_index = index
            payload_indent = len(line) - len(line.lstrip())
            break
    if payload_index is None:
        return []

    items: list[str] = []
    for line in lines[payload_index + 1:]:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= payload_indent and not line.lstrip().startswith('-'):
            break
        match = re.match(r"^\s*-\s*(.*?)\s*$", line)
        if not match:
            continue
        value = strip_inline_comment(match.group(1))
        if not value:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            try:
                parsed = yaml.safe_load(value)
                if isinstance(parsed, str):
                    value = parsed
            except yaml.YAMLError:
                value = value[1:-1]
        items.append(value)
    return items


def load_clash_payload(text: str) -> list[Any]:
    repaired = quote_unquoted_wildcard_items(text)
    try:
        doc = yaml.safe_load(repaired)
    except yaml.YAMLError as first_error:
        fallback = extract_payload_fallback(text)
        if fallback:
            return fallback
        raise RuntimeError(f"YAML payload parse failed: {first_error}") from first_error

    payload = doc.get('payload') if isinstance(doc, dict) else doc
    if not isinstance(payload, list):
        fallback = extract_payload_fallback(text)
        if fallback:
            return fallback
        raise RuntimeError("YAML source does not contain a payload list")
    return payload


def parse_rule_item(raw: Any, default_behavior: str, bucket: dict[str, list[Any]], warnings: list[str]) -> None:
    if raw is None:
        return
    if not isinstance(raw, str):
        warnings.append(f"non-string item skipped: {raw!r}")
        return
    item = strip_inline_comment(raw.strip())
    if not item or item.startswith(('#', ';')):
        return

    parts = [part.strip() for part in item.split(',')]
    rule_type = parts[0].upper() if parts else ""
    typed = rule_type in {
        "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX",
        "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SOURCE-IP-CIDR",
        "DST-PORT", "PORT", "SRC-PORT", "SOURCE-PORT",
        "PROCESS-NAME", "PROCESS-PATH", "NETWORK", "PACKAGE-NAME",
        "MATCH", "RULE-SET", "GEOSITE", "GEOIP",
    }

    if typed:
        if len(parts) < 2 and rule_type != "MATCH":
            warnings.append(f"malformed rule skipped: {item}")
            return
        value = parts[1] if len(parts) >= 2 else ""
        if rule_type == "DOMAIN":
            add(bucket, "domain", normalize_domain(value))
        elif rule_type == "DOMAIN-SUFFIX":
            add(bucket, "domain_suffix", normalize_domain(value).lstrip('.'))
        elif rule_type == "DOMAIN-KEYWORD":
            add(bucket, "domain_keyword", value)
        elif rule_type == "DOMAIN-REGEX":
            add(bucket, "domain_regex", value)
        elif rule_type in {"IP-CIDR", "IP-CIDR6"}:
            try:
                add(bucket, "ip_cidr", str(ipaddress.ip_network(value, strict=False)))
            except ValueError:
                warnings.append(f"invalid CIDR skipped: {item}")
        elif rule_type in {"SRC-IP-CIDR", "SOURCE-IP-CIDR"}:
            try:
                add(bucket, "source_ip_cidr", str(ipaddress.ip_network(value, strict=False)))
            except ValueError:
                warnings.append(f"invalid source CIDR skipped: {item}")
        elif rule_type in {"DST-PORT", "PORT"}:
            if '-' in value:
                add(bucket, "port_range", value)
            else:
                try:
                    add(bucket, "port", int(value))
                except ValueError:
                    warnings.append(f"invalid port skipped: {item}")
        elif rule_type in {"SRC-PORT", "SOURCE-PORT"}:
            if '-' in value:
                add(bucket, "source_port_range", value)
            else:
                try:
                    add(bucket, "source_port", int(value))
                except ValueError:
                    warnings.append(f"invalid source port skipped: {item}")
        elif rule_type == "PROCESS-NAME":
            add(bucket, "process_name", value)
        elif rule_type == "PROCESS-PATH":
            add(bucket, "process_path", value)
        elif rule_type == "NETWORK":
            add(bucket, "network", value.lower())
        elif rule_type == "PACKAGE-NAME":
            add(bucket, "package_name", value)
        elif rule_type not in {"MATCH"}:
            warnings.append(f"unsupported Clash rule skipped: {item}")
        return

    if default_behavior == "ipcidr":
        try:
            add(bucket, "ip_cidr", str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            warnings.append(f"invalid CIDR skipped: {item}")
        return

    value = normalize_domain(item)
    if value.startswith("||") and value.endswith("^"):
        add(bucket, "domain_suffix", value[2:-1].lstrip('.'))
    elif value.startswith("+."):
        add(bucket, "domain_suffix", value[2:])
    elif value.startswith("*."):
        add(bucket, "domain_suffix", value[2:])
    elif value.startswith('.'):
        add(bucket, "domain_suffix", value[1:])
    elif '*' in value or '?' in value:
        add(bucket, "domain_regex", wildcard_to_regex(value))
    else:
        add(bucket, "domain", value)


def bucket_to_source(bucket: dict[str, list[Any]]) -> dict[str, Any]:
    rule: dict[str, Any] = {}
    for field in sorted(bucket):
        values = ordered_unique(bucket[field])
        if values:
            rule[field] = values
    if not rule:
        raise RuntimeError("no supported rules were produced")
    return {"version": 3, "rules": [rule]}


def convert_clash_yaml(content: bytes, behavior: str) -> tuple[dict[str, Any], list[str]]:
    text = content.decode('utf-8-sig')
    payload = load_clash_payload(text)
    bucket: dict[str, list[Any]] = defaultdict(list)
    warnings: list[str] = []
    for item in payload:
        parse_rule_item(item, behavior, bucket, warnings)
    return bucket_to_source(bucket), warnings


def convert_classical_text(content: bytes) -> tuple[dict[str, Any], list[str]]:
    text = content.decode('utf-8-sig')
    try:
        items = load_clash_payload(text)
    except RuntimeError:
        items = text.splitlines()
    bucket: dict[str, list[Any]] = defaultdict(list)
    warnings: list[str] = []
    for item in items:
        parse_rule_item(item, "classical", bucket, warnings)
    return bucket_to_source(bucket), warnings


def normalize_native_json(content: bytes) -> dict[str, Any]:
    doc = json.loads(content.decode('utf-8-sig'))
    if not isinstance(doc, dict) or not isinstance(doc.get('rules'), list):
        raise RuntimeError("native sing-box source JSON is malformed")

    unsupported: list[str] = []

    def inspect_rule(rule: Any, path: str = 'rules') -> None:
        if not isinstance(rule, dict):
            return
        if rule.get('type') == 'logical':
            for idx, child in enumerate(rule.get('rules', [])):
                inspect_rule(child, f"{path}.rules[{idx}]")
            return
        for key in rule:
            if key not in RULE_FIELDS and key not in {'type', 'invert'}:
                unsupported.append(f"{path}.{key}")

    for idx, rule in enumerate(doc['rules']):
        inspect_rule(rule, f"rules[{idx}]")
    if unsupported:
        raise RuntimeError(
            "source uses fields not covered by v3 compatibility mode: "
            + ', '.join(unsupported[:10])
        )
    doc['version'] = 3
    return doc


def validate_source(doc: dict[str, Any]) -> None:
    if doc.get('version') != 3 or not isinstance(doc.get('rules'), list) or not doc['rules']:
        raise RuntimeError("invalid generated source JSON")


def compile_srs(compiler: Path, source_json: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [str(compiler), str(source_json), str(output)],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"compiler failed: {proc.stderr.strip() or proc.stdout.strip()}")
    data = output.read_bytes()
    if len(data) < 8 or data[:3] != b'SRS':
        raise RuntimeError("compiler output does not have SRS magic bytes")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', default='providers.json')
    parser.add_argument('--compiler', default='bin/srscompiler')
    parser.add_argument('--rules-dir', default='rules')
    parser.add_argument('--source-dir', default='source-json')
    parser.add_argument('--report', default='build-report.json')
    parser.add_argument('--raw-base', default='')
    args = parser.parse_args()

    compiler = Path(args.compiler).resolve()
    if not compiler.is_file():
        raise SystemExit(f"compiler not found: {compiler}")

    rules_dir = Path(args.rules_dir)
    source_dir = Path(args.source_dir)
    rules_dir.mkdir(parents=True, exist_ok=True)
    source_dir.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(Path(args.manifest).read_text(encoding='utf-8'))
    providers = manifest['providers']
    if len(providers) != 99:
        raise SystemExit(f"manifest must contain exactly 99 providers, got {len(providers)}")

    outputs = [provider['output_file'] for provider in providers]
    if len(set(outputs)) != 99:
        raise SystemExit("manifest output_file values must be unique")

    for path in rules_dir.glob('*.srs'):
        path.unlink()
    for path in source_dir.glob('*.json'):
        path.unlink()

    session = requests.Session()
    session.headers.update({'User-Agent': 'karing-99-srs-builder/2.0 (+GitHub Actions)'})
    report: list[dict[str, Any]] = []
    failed: list[dict[str, str]] = []

    for idx, provider in enumerate(providers, 1):
        name = provider['name']
        print(f"[{idx:02d}/99] {name}", flush=True)
        try:
            content = fetch(session, provider['source_url'])
            source_type = provider['source_type']
            warnings: list[str] = []
            if source_type == 'metacubex-sing-json':
                doc = normalize_native_json(content)
            elif source_type in {'clash-domain-yaml', 'clash-ipcidr-yaml'}:
                doc, warnings = convert_clash_yaml(content, provider['behavior'])
            elif source_type == 'clash-classical-text':
                doc, warnings = convert_classical_text(content)
            else:
                raise RuntimeError(f"unknown source_type: {source_type}")
            validate_source(doc)

            stem = Path(provider['output_file']).stem
            source_path = source_dir / f"{stem}.json"
            output_path = rules_dir / provider['output_file']
            source_path.write_text(
                json.dumps(doc, ensure_ascii=False, indent=2) + '\n',
                encoding='utf-8',
            )
            compile_srs(compiler, source_path, output_path)
            report.append({
                'name': name,
                'output_file': provider['output_file'],
                'source_url': provider['source_url'],
                'source_json': str(source_path),
                'bytes': output_path.stat().st_size,
                'sha256': hashlib.sha256(output_path.read_bytes()).hexdigest(),
                'warnings': warnings,
            })
            if warnings:
                print(f"  warnings: {len(warnings)} (see build-report.json)")
        except Exception as exc:  # noqa: BLE001
            message = str(exc)
            failed.append({'name': name, 'source_url': provider['source_url'], 'error': message})
            print(f"  ERROR [{idx:02d}/99] {name}: {message}", file=sys.stderr, flush=True)
            print(f"::error title=Rule {idx:02d} failed::{name}: {message}", file=sys.stderr, flush=True)

    raw_base = args.raw_base.strip().rstrip('/')
    index = {
        'version': 1,
        'count': len(report),
        'generated_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'rules': [
            {
                **item,
                'url': f"{raw_base}/{item['output_file']}" if raw_base else item['output_file'],
            }
            for item in report
        ],
    }
    (rules_dir / 'index.json').write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )
    Path(args.report).write_text(
        json.dumps({'succeeded': report, 'failed': failed}, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )

    md = ['# Karing 远程规则地址', '', f'成功生成：**{len(report)} / 99**', '']
    if raw_base:
        for item in report:
            md.append(f"- `{item['name']}` — `{raw_base}/{item['output_file']}`")
    else:
        md.append('GitHub Actions 运行时会根据仓库名生成完整 Raw URL。')
    Path('KARING_URLS.md').write_text('\n'.join(md) + '\n', encoding='utf-8')

    if failed or len(report) != 99:
        print(f"Build failed: {len(report)} succeeded, {len(failed)} failed", file=sys.stderr)
        return 1
    print('Done: exactly 99 .srs files generated.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
