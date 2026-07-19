#!/usr/bin/env python3
"""Offline regression tests for the converter, including unquoted wildcards."""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from build_rules import compile_srs, convert_clash_yaml


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--compiler', required=True)
    args = parser.parse_args()

    wildcard_yaml = b"""payload:\n  - *.163yun.com\n  - '*.music.163.com'\n  - +.example.org\n  - DOMAIN-SUFFIX,typed.example\n"""
    doc, warnings = convert_clash_yaml(wildcard_yaml, 'domain')
    if warnings:
        raise RuntimeError(f"unexpected warnings: {warnings}")
    rule = doc['rules'][0]
    expected_suffixes = {'163yun.com', 'music.163.com', 'example.org', 'typed.example'}
    if not expected_suffixes.issubset(set(rule.get('domain_suffix', []))):
        raise RuntimeError(f"wildcard conversion failed: {rule}")

    ip_yaml = b"""payload:\n  - 192.168.1.9/24\n  - 2001:db8::1/64\n"""
    ip_doc, ip_warnings = convert_clash_yaml(ip_yaml, 'ipcidr')
    if ip_warnings:
        raise RuntimeError(f"unexpected IP warnings: {ip_warnings}")
    if set(ip_doc['rules'][0].get('ip_cidr', [])) != {'192.168.1.0/24', '2001:db8::/64'}:
        raise RuntimeError(f"IP normalization failed: {ip_doc}")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / 'test.json'
        output = root / 'test.srs'
        source.write_text(json.dumps(doc), encoding='utf-8')
        compile_srs(Path(args.compiler).resolve(), source, output)
        if output.read_bytes()[:3] != b'SRS':
            raise RuntimeError('compiled test file is not SRS')

    print('Self-test passed: wildcard YAML, CIDR normalization, and SRS compiler.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
