"""Run one harmless report transition in the owned acceptance repository."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from time import monotonic, sleep
from urllib.parse import urlencode

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "delivery"))
from github_evidence import api, last_check

REPO = "yangbobo2021/anthropic-sdlc-check-source-lab"
SOURCE = "synthetic-security-recovery-evidence"
DECISION = "trusted-pr-security-review"
APP = 15368


def digest(filename):
    return sha256((HERE / "delivery" / filename).read_bytes()).hexdigest()


def checks(head, name):
    query = urlencode({"check_name": name, "filter": "all", "per_page": 100})
    return [row for row in api(f"repos/{REPO}/commits/{head}/check-runs?{query}")["check_runs"]
            if row["head_sha"] == head and row["app"]["id"] == APP and row["name"] == name]


def await_value(read, reason):
    deadline = monotonic() + 35
    while monotonic() < deadline:
        try:
            value = read()
            if value:
                return value
        except ValueError:
            pass
        sleep(1)
    raise RuntimeError(reason)


def projection(run):
    return {**{k: run[k] for k in ("id", "head_sha", "name", "status", "conclusion", "html_url")},
            "app_id": run["app"]["id"], "check_suite_id": run["check_suite"]["id"]}


def main():
    assert os.environ["GITHUB_REPOSITORY"] == REPO and os.environ["GITHUB_EVENT_NAME"] == "workflow_dispatch"
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    assert re.fullmatch(r"[1-9][0-9]*", str(event["inputs"]["pr_number"]))
    number = int(event["inputs"]["pr_number"])
    pull = api(f"repos/{REPO}/pulls/{number}")
    head = event["inputs"]["head_sha"]
    assert re.fullmatch(r"[0-9a-f]{40}", head)
    assert pull["head"]["sha"] == head and pull["state"] == "open"
    assert pull["base"]["ref"] == "sdlc0050-recovery-gate"
    assert pull["head"]["ref"] == "codex/sdlc0050-recovery-candidate"
    assert pull["base"]["repo"]["full_name"] == pull["head"]["repo"]["full_name"] == REPO
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == os.environ["SDLC_WORKFLOW_SHA"]
    phase = event["inputs"]["phase"]
    packet = upstream = None
    previous = {run["id"] for run in checks(head, DECISION)}
    if phase == "missing":
        assert checks(head, SOURCE) == []
    else:
        open_high = {"id": "synthetic-high", "severity": "high", "status": "open"}
        dispositions = {
            "clear": [],
            "open-high": [open_high],
            "stale-fix": [{**open_high, "status": "fixed", "verified_fix_sha": pull["base"]["sha"]}],
            "fixed": [{**open_high, "status": "fixed", "verified_fix_sha": head}],
        }
        assert pull["base"]["sha"] != head
        packet = {"source_sha": head, "status": "complete", "findings": dispositions[phase]}
        published = api(f"repos/{REPO}/check-runs", {
            "name": SOURCE, "head_sha": head, "status": "completed", "conclusion": "success",
            "output": {"title": "Synthetic acceptance report", "summary": "Acceptance fixture only",
                       "text": json.dumps(packet, sort_keys=True)},
        })
        assert published["app"]["id"] == APP
        upstream = await_value(
            lambda: next((run for run in [last_check(REPO, head, SOURCE, APP)]
                          if run["id"] == published["id"]), None),
            "New report has not become the current source check",
        )
        assert json.loads(upstream["output"]["text"]) == packet
    proc = subprocess.run([sys.executable, str(HERE / "delivery/github_evidence.py"), "security",
                           str(HERE / "policy.json")], capture_output=True, text=True, timeout=50)
    expected = 0 if phase in ("clear", "fixed") else 1
    outcome = "success" if expected == 0 else "failure"
    assert proc.returncode == expected, (proc.returncode, proc.stderr[-800:])
    decisions = await_value(lambda: [run for run in checks(head, DECISION) if run["id"] not in previous],
                            "No fresh security decision check")
    decision, = decisions
    assert decision["conclusion"] == outcome and decision["status"] == "completed"
    latest = last_check(REPO, head, DECISION, APP)
    assert latest["id"] == decision["id"]
    proof = {
        "phase": phase, "pr": number, "head": head, "base": pull["base"]["sha"],
        "workflow_sha": os.environ["SDLC_WORKFLOW_SHA"], "source": projection(upstream) if upstream else None,
        "packet": packet, "decision": projection(decision), "adapter_exit": proc.returncode,
        "adapter_sha256": digest("github_evidence.py"), "decision_sha256": digest("decision.py"),
    }
    print("SDLC0050_RECOVERY=" + json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    main()
