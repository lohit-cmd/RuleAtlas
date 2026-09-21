from .parsers import base
from .store import now


def seed(store):
    """Original synthetic examples, never represented as upstream/vendor rules."""
    source = {"repo": "local/demo-fixtures"}
    examples = [
        ("External member added to a sensitive group", "Sigma", "detection", ["T1098"], {"product": "google_workspace", "service": "admin"},
         "Detect membership changes that involve an external domain and a configured sensitive group.",
         "selection:\n  event: ADD_GROUP_MEMBER\n  group: sensitive_groups\n  external_domain: true\nfilter:\n  domain: approved_domains\ncondition: selection and not filter"),
        ("Cloud audit logging disabled", "SPL", "detection", ["T1562.008"], {"product": "aws", "service": "cloudtrail"},
         "Illustrative CloudTrail StopLogging query. Administrative changes may be legitimate.",
         'index=cloudtrail eventName=StopLogging errorCode!=* | stats count by userIdentity.arn recipientAccountId'),
        ("Suspicious PowerShell encoded command", "KQL", "detection", ["T1059.001"], {"product": "windows", "table": "DeviceProcessEvents"},
         "Illustrative process query for encoded PowerShell; it does not prove malicious execution.",
         'DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "pwsh.exe")\n| where ProcessCommandLine has "-EncodedCommand"'),
        ("Container shell execution", "Falco", "detection", ["T1059"], {"product": "linux", "source": "syscall"},
         "Shell execution in a container; additional context is needed to assess intent.",
         'condition: spawned_process and container and proc.name in (bash, sh)\npriority: NOTICE'),
        ("OAuth consent activity hunt", "KQL", "hunting", ["T1098"], {"product": "entra_id", "table": "AuditLogs"},
         "A broad consent-event hunt. It does not implement rarity, suspicious scopes, or actor baselines.",
         'AuditLogs\n| where OperationName has "Consent"\n| project TimeGenerated, InitiatedBy, TargetResources'),
        ("Example suspicious file marker", "YARA", "file-signature", [], {"product": "file"},
         "Synthetic non-malicious marker used only to exercise file-signature search.",
         'rule ruleatlas_demo_marker { strings: $a = "RULEATLAS_DEMO_ONLY" condition: $a }'),
        ("Group membership audit hunt", "Sigma", "hunting", ["T1098"], {"product": "google_workspace", "service": "admin"},
         "Broad group-addition visibility. No external-domain or sensitive-group condition.",
         'selection:\n  event: ADD_GROUP_MEMBER\ncondition: selection'),
        ("AWS console authentication failures", "Python", "detection", ["T1110"], {"product": "aws", "service": "cloudtrail"},
         "Single-event authentication-failure example; no brute-force aggregation implemented.",
         'def rule(event):\n    return event.get("eventName") == "ConsoleLogin" and event.get("errorMessage") == "Failed authentication"'),
    ]
    records = []
    for i, (title, language, kind, ids, telemetry, description, logic) in enumerate(examples):
        r = base(source, f"synthetic/example-{i+1}", "", "[Demo] " + title, logic,
            data={"id": f"ruleatlas-demo-{i+1}", "author": "RuleAtlas contributors", "tags": ids, "license": "MIT"},
            language=language, kind=kind, description=description, telemetry=telemetry)
        r["is_demo"] = True
        r["repository"] = "Original synthetic demo fixture"
        records.append(r)
    store.replace_source("demo", records, {"source_id": "demo", "status": "demo", "count": len(records),
        "last_success": now(), "notice": "Original synthetic examples only. No upstream rules loaded."})
    return len(records)

