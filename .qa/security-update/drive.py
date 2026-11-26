"""Observe in-place updates to a synthetic report on one fixed acceptance PR."""

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
RECOVERY = HERE.parent / "security-recovery"
DELIVERY = RECOVERY / "delivery"
sys.path.insert(0, str(RECOVERY))
import drive as recovery

REPO, APP, DECISION = recovery.REPO, recovery.APP, recovery.DECISION
SOURCE = "synthetic-security-update-evidence"


def project(run):
    return {**recovery.projection(run), "completed_at": run["completed_at"],
            "report": json.loads(run["output"]["text"]) if run["name"] == SOURCE else None}


def update_report(report_id, payload):
    result = subprocess.run(
        ["gh", "api", f"repos/{REPO}/check-runs/{report_id}", "--method", "PATCH", "--input", "-"],
        input=json.dumps(payload), text=True, capture_output=True, check=True,
    )
    return json.loads(result.stdout)


def main():
    assert os.environ["GITHUB_REPOSITORY"] == REPO
    assert os.environ["GITHUB_EVENT_NAME"] == "workflow_dispatch"
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    assert sha == os.environ["SDLC_WORKFLOW_SHA"]
    inputs = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())["inputs"]
    head, phase = inputs["head_sha"], inputs["phase"]
    assert re.fullmatch(r"[0-9a-f]{40}", head)
    number = int(inputs["pr_number"])
    pull = recovery.api(f"repos/{REPO}/pulls/{number}")
    assert pull["state"] == "open" and pull["head"]["sha"] == head
    assert pull["base"]["ref"] == "sdlc0050-update-sandbox"
    assert pull["head"]["ref"] == "codex/sdlc0050-update-candidate"
    assert all(pull[side]["repo"]["full_name"] == REPO for side in ("base", "head"))

    prior = recovery.checks(head, SOURCE)
    before = {run["id"] for run in recovery.checks(head, DECISION)}
    high = {"id": "synthetic-high", "severity": "high", "status": "open"}
    findings = {"initial": [], "competing": [], "high": [high],
                "fixed": [{**high, "status": "fixed", "verified_fix_sha": head}]}[phase]
    packet = {"source_sha": head, "status": "complete", "findings": findings}
    payload = {
        "name": SOURCE, "status": "completed", "conclusion": "success",
        "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "output": {"title": "Synthetic security update", "summary": "Acceptance fixture only",
                   "text": json.dumps(packet, sort_keys=True)},
    }
    if phase in {"initial", "competing"}:
        assert len(prior) == (0 if phase == "initial" else 1)
        upstream = recovery.api(f"repos/{REPO}/check-runs", {**payload, "head_sha": head})
    else:
        report_id = int(inputs["report_id"])
        assert any(run["id"] == report_id for run in prior)
        upstream = update_report(report_id, payload)
    assert upstream["app"]["id"] == APP and upstream["head_sha"] == head
    assert json.loads(upstream["output"]["text"]) == packet

    def refreshed():
        reports = recovery.checks(head, SOURCE)
        current = next((run for run in reports if run["id"] == upstream["id"]), None)
        return reports if current and project(current) == project(upstream) else None

    all_reports = recovery.await_value(refreshed, "Report update not visible")
    latest = recovery.api(f"repos/{REPO}/commits/{head}/check-runs"
                          f"?check_name={SOURCE}&app_id={APP}&filter=latest&per_page=100")
    selected = recovery.last_check(REPO, head, SOURCE, APP)
    policy = {"security_review": {"name": SOURCE, "app_id": APP,
                                  "blocking_severities": ["critical", "high"]}}
    with TemporaryDirectory() as temp:
        config = Path(temp) / "policy.json"
        config.write_text(json.dumps(policy))
        result = subprocess.run([sys.executable, str(DELIVERY / "github_evidence.py"), "security", str(config)],
                                capture_output=True, text=True, timeout=45)
    decisions = recovery.await_value(
        lambda: [run for run in recovery.checks(head, DECISION) if run["id"] not in before],
        "New verdict not visible",
    )
    assert len(decisions) == 1
    decision = decisions[0]
    proof = {
        "phase": phase, "pr": number, "head": head, "workflow_sha": sha, "updated_report": project(upstream),
        "all_reports": [project(run) for run in all_reports], "latest_api": [project(run) for run in latest["check_runs"]],
        "adapter_selected": project(selected), "decision": project(decision), "exit_code": result.returncode,
        "delivery": {path.name: sha256(path.read_bytes()).hexdigest() for path in sorted(DELIVERY.glob("*.py"))},
    }
    print(json.dumps(proof, sort_keys=True), flush=True)
    expected = "failure" if phase == "high" else "success"
    assert (decision["conclusion"], result.returncode) == (expected, int(expected == "failure"))


if __name__ == "__main__":
    main()
