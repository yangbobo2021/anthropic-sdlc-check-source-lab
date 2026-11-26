"""Feed controlled PR receipts to the delivered GitHub evidence adapter."""
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from time import monotonic, sleep

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "delivery"))

from decision import review
from github_evidence import api, collect, last_check

REPO = "yangbobo2021/anthropic-sdlc-check-source-lab"
APP = 15368
BUILD = "scn04-fixture-build"
OPTIONAL = "scn04-deployment-smoke"
VERDICT = "trusted-sdlc-policy"
REVIEW = "Claude Code Review"


def publication(row):
    return {
        **{key: row[key] for key in ("id", "name", "head_sha", "conclusion", "details_url")},
        "app_id": row["app"]["id"],
        "output": {key: row["output"][key] for key in ("title", "text")},
    }


def fresh_check(head, name, seen, latest_id=None):
    deadline = monotonic() + 25
    while monotonic() < deadline:
        try:
            row = last_check(REPO, head, name, APP)
        except ValueError:
            sleep(1)
            continue
        if row["id"] not in seen and (latest_id is None or latest_id == row["id"]):
            return publication(row)
        sleep(1)
    raise RuntimeError(f"No fresh result for {name}")


def publish(head, name, conclusion, text=None):
    published = api(f"repos/{REPO}/check-runs", {
        "name": name, "head_sha": head, "status": "completed", "conclusion": conclusion,
        "output": {"title": "Synthetic fixture input", "summary": "Synthetic acceptance fixture only", "text": text or ""},
    })
    assert published["app"]["id"] == APP
    return fresh_check(head, name, set(), published["id"])


def check_ids(head, name):
    route = f"repos/{REPO}/commits/{head}/check-runs?check_name={name}&filter=all&per_page=100"
    return {row["id"] for row in api(route)["check_runs"] if row["app"]["id"] == APP}


def main():
    assert os.environ["GITHUB_REPOSITORY"] == REPO
    assert os.environ["GITHUB_EVENT_NAME"] == "workflow_dispatch"
    workflow = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    assert workflow == os.environ["SDLC_WORKFLOW_SHA"]
    payload = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    inputs = payload["inputs"]
    phase = inputs["phase"]
    head = inputs["head_sha"]
    assert re.fullmatch(r"[0-9a-f]{40}", head) and re.fullmatch(r"[1-9][0-9]*", str(inputs["pr_number"]))
    number = int(inputs["pr_number"])
    pr = api(f"repos/{REPO}/pulls/{number}")
    assert pr["state"] == "open" and pr["head"]["sha"] == head
    assert pr["head"]["ref"] == "codex/scn04-optional-candidate"
    assert pr["base"]["ref"] == "scn04-optional-gate"
    assert pr["base"]["repo"]["full_name"] == pr["head"]["repo"]["full_name"] == REPO
    previous = check_ids(head, VERDICT)
    review_rcpt = publish(head, REVIEW, "neutral",
                          '<!-- bughunter-severity: {"normal":0,"nit":0,"pre_existing":0} -->')
    build = publish(head, BUILD, "failure" if phase == "failed-build" else "success")
    if phase == "missing":
        assert not check_ids(head, OPTIONAL)
        optional = None
    elif phase == "bare-skipped":
        optional = publish(head, OPTIONAL, "skipped")
    else:
        assert phase in {"old-scope", "failed-build", "bound-waiver"}
        waiver = {
            "schema_version": 1, "source_sha": pr["base"]["sha"] if phase == "old-scope" else head,
            "check_name": OPTIONAL, "state": "not_applicable", "reason": "Documentation-only change",
        }
        optional = publish(head, OPTIONAL, "skipped", json.dumps(waiver, sort_keys=True))

    policy_path = HERE / "policy.json"
    policy = json.loads(policy_path.read_bytes())
    policy_decision, explanation = None, None
    mapped = None
    try:
        packet = collect(REPO, head, pr, policy)
        mapped = next(check for check in packet["checks"] if check["name"] == OPTIONAL)
        policy_decision = review(policy, packet, datetime.now(timezone.utc))
    except ValueError as error:
        explanation = str(error)
    actual = subprocess.run([sys.executable, str(HERE / "delivery/github_evidence.py"), "required", str(policy_path)],
                            check=False, timeout=45)
    success = phase == "bound-waiver"
    assert actual.returncode == (0 if success else 1)
    assert bool(policy_decision) is success
    expected_reason = {
        "missing": f"missing authenticated check: {OPTIONAL}",
        "bare-skipped": "Expecting value:",
        "old-scope": "applicability waiver scope mismatch",
        "failed-build": f"required check did not succeed: {BUILD}",
    }
    assert success or explanation.startswith(expected_reason[phase]), explanation
    if phase in {"failed-build", "bound-waiver"}:
        assert mapped["state"] == "not_applicable" and mapped["reason"] == "Documentation-only change"
    decision = fresh_check(head, VERDICT, previous)
    assert decision["conclusion"] == ("success" if success else "failure")
    proof = {
        "phase": phase, "workflow_sha": workflow, "pr": number, "head": head, "base": pr["base"]["sha"],
        "review": review_rcpt, "build": build, "optional": optional, "mapped": mapped,
        "policy_diagnosis": explanation, "adapter_exit": actual.returncode, "decision": decision,
        "digests": {path: sha256((HERE / path).read_bytes()).hexdigest()
                    for path in ("delivery/github_evidence.py", "delivery/decision.py", "policy.json")},
    }
    print("SCN04_OPTIONAL_PROOF=" + json.dumps(proof, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
