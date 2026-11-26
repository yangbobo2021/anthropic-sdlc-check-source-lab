"""Execute the shipped adapter with real GitHub Checks and synthetic reports."""

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from time import monotonic, sleep
from urllib.parse import urlencode

sys.path.insert(0, "scripts/sdlc")
from github_evidence import api, evaluated_event, last_check, security_verdict


def current_pr(repo, number, head=None):
    row = api(f"repos/{repo}/pulls/{number}")
    assert row["state"] == "open" and row["base"]["ref"] == "main"
    assert row["head"]["repo"]["full_name"] == repo and row["head"]["ref"].startswith("codex/source-case-")
    assert row["head"]["sha"] == (head or row["head"]["sha"])
    return row


def decision_checks(repo, head):
    query = urlencode({"check_name": "trusted-pr-security-review", "per_page": 100, "filter": "all"})
    rows = api(f"repos/{repo}/commits/{head}/check-runs?{query}")["check_runs"]
    return {row["id"]: row for row in rows if row["name"] == "trusted-pr-security-review"}


def wait_for(label, capture):
    deadline = monotonic() + 25
    while monotonic() <= deadline:
        try:
            result = capture()
            if result:
                return result
        except (KeyError, ValueError):
            pass
        sleep(1)
    raise RuntimeError(label)


def projection(row):
    return {
        "id": row["id"], "app_id": row["app"]["id"], "head_sha": row["head_sha"],
        "name": row["name"], "conclusion": row["conclusion"], "has_report_text": bool(row["output"]["text"]),
    }


def main():
    kind = os.environ["GITHUB_EVENT_NAME"]
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    repo = os.environ["GITHUB_REPOSITORY"]
    assert repo == "yangbobo2021/anthropic-sdlc-check-source-lab"
    policy_file = Path("probe/policy.json")
    policy = json.loads(policy_file.read_text())
    expected = policy["security_review"]
    producer = expected["app_id"]
    check_name = expected["name"]
    if kind == "check_run":
        upstream = event["check_run"]
        print("SDLC0050_TRIGGER="+json.dumps(projection(upstream), sort_keys=True), flush=True)
        assert event["action"] == "completed" and upstream["app"]["id"] == producer
        if upstream["name"] != check_name:
            raise RuntimeError(f"Native check name is {upstream['name']!r}")
        associated = upstream["pull_requests"]
        head = upstream["head_sha"]
        if associated:
            assert len(associated) == 1, len(associated)
            number = associated[0]["number"]
        else:
            candidates = [p for p in api(f"repos/{repo}/commits/{head}/pulls")
                          if p["state"] == "open" and p["head"]["sha"] == head]
            assert len(candidates) == 1, len(candidates)
            number = candidates[0]["number"]
        current_pr(repo, number, head)
        mode = "native-event"
    else:
        number = int(event["inputs"]["pr_number"])
        pr = current_pr(repo, number)
        head = pr["head"]["sha"]
        mode = event["inputs"]["mode"]
    before = decision_checks(repo, head)
    if mode == "wrong-source":
        report = {"source_sha": head, "status": "complete", "findings": []}
        reply = api(f"repos/{repo}/check-runs", {
            "name": check_name, "head_sha": head, "status": "completed", "conclusion": "success",
            "output": {"title": "Synthetic source isolation fixture", "summary": "Complete empty test packet",
                       "text": json.dumps(report, sort_keys=True)},
        })
        actual_source = reply["app"]["id"]
        assert actual_source == 15368 and actual_source != producer
        visible = wait_for("wait for the alternate source to become readable",
                           lambda: last_check(repo, head, check_name, actual_source))
        assert visible["id"] == reply["id"] and json.loads(visible["output"]["text"]) == report
        control = deepcopy(policy)
        control["security_review"]["app_id"] = actual_source
        security_verdict(repo, head, control)
        try:
            last_check(repo, head, check_name, producer)
        except ValueError as error:
            assert "missing authenticated check" in str(error), str(error)
        else:
            raise RuntimeError("wrong-source case must not contain a matching native producer record")
        upstream = visible
    elif mode in {"native-event", "native-readback"}:
        upstream = wait_for("wait for the native source to become readable",
                            lambda: last_check(repo, head, check_name, producer))
        assert upstream["app"]["id"] == producer and not upstream["output"]["text"]
    else:
        raise RuntimeError("unknown fixture mode")
    proc = subprocess.run([sys.executable, "scripts/sdlc/github_evidence.py", "security", str(policy_file)],
                          text=True, capture_output=True, timeout=60)
    print("SDLC0050_EVALUATED="+json.dumps({"mode":mode,"pr":number,"evaluation_sha":head,
        "event":kind,"adapter_exit":proc.returncode,"stderr":proc.stderr[-1500:]},sort_keys=True),flush=True)
    assert proc.returncode == 1, proc.returncode
    decisions = wait_for("wait for a fresh decision from the upstream adapter",
                         lambda: {key:value for key,value in decision_checks(repo, head).items() if key not in before})
    assert len(decisions) == 1
    decision = next(iter(decisions.values()))
    assert decision["conclusion"] == "failure" and decision["head_sha"] == head
    assert decision["app"]["id"] == 15368
    record = {"mode": mode, "event": kind, "pr": number, "head": head,
              "origin": projection(upstream), "decision": projection(decision),
              "configured_app_id": producer, "adapter_exit": proc.returncode,
              "same_body_control_accepted": mode == "wrong-source",
              "adapter_sha256": sha256(Path("scripts/sdlc/github_evidence.py").read_bytes()).hexdigest()}
    print("SDLC0050_SOURCE_PROOF="+json.dumps(record,sort_keys=True),flush=True)


if __name__ == "__main__":
    main()
