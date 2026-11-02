#!/usr/bin/env python3
"""Validate public files offline; no TShark or private evidence required."""
import json
from casebook import validate

if __name__ == '__main__':
    try:
        print(json.dumps(validate(),sort_keys=True))
    except (OSError,ValueError,KeyError) as exc:
        raise SystemExit(f'ERROR: {exc}')
