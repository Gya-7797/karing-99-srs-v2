#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

manifest = json.loads(Path('providers.json').read_text(encoding='utf-8'))
expected = {provider['output_file'] for provider in manifest['providers']}
actual = {path.name for path in Path('rules').glob('*.srs')}
errors: list[str] = []

if len(manifest['providers']) != 99:
    errors.append(f"manifest provider count: {len(manifest['providers'])}")
if len(expected) != 99:
    errors.append(f"manifest unique outputs: {len(expected)}")
if actual != expected:
    errors.append(f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}")

for path in Path('rules').glob('*.srs'):
    data = path.read_bytes()
    if len(data) < 8 or data[:3] != b'SRS':
        errors.append(f"invalid SRS: {path}")

if errors:
    print('\n'.join(errors), file=sys.stderr)
    raise SystemExit(1)
print('Validation passed: exactly 99 unique SRS files.')
