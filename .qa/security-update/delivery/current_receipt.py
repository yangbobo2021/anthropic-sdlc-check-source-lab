# SPDX-FileCopyrightText: 2026 boob.yang
import json
from pathlib import Path
import re
import sys

report, expected = sys.argv[1:3]
if not re.fullmatch(r"[0-9a-f]{40}", expected):
    raise SystemExit("invalid evaluated SHA")
if json.loads(Path(report).read_text())["sha"] != expected:
    raise SystemExit("receipt SHA differs from the checked commit")
