"""Exercise compatibility in a synthetic two-change candidate."""
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent
component = (root / "component.txt").read_text().strip()
profile = (root / "profile.txt").read_text().strip()
observed = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
supported = {"local": {"safe", "legacy", "compatible"}, "remote": {"safe", "compatible"}}
compatible = profile in supported[component]
print("SDLC0062_GROUP_FIXTURE=" + json.dumps({
    "head": observed, "github_sha": os.environ["GITHUB_SHA"], "event": os.environ["GITHUB_EVENT_NAME"],
    "component": component, "profile": profile, "compatible": compatible,
}), flush=True)
if not compatible:
    raise SystemExit("The remote component requires a compatible profile")
