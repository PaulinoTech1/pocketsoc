"""Machine-readable stdout; operational logs stay on stderr."""
import json
import os
from pathlib import Path


def emit(value):
    print(json.dumps(value, ensure_ascii=True, allow_nan=False), flush=True)


def write_report(path, value, format):
    text = value if format == 'markdown' else json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + '\n'
    fd = os.open(Path(path).expanduser(), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(text)
