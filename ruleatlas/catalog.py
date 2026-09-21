import json
import re
from pathlib import Path

CHECKS = ("ownership", "community_adoption", "engineering_quality", "maintenance", "traceability", "rule_validation")
REPO_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
ADAPTERS = {"sigma", "splunk", "elastic", "sentinel", "panther", "falco", "sublime", "yaral", "yara", "wazuh", "kql_markdown", "code", "snort", "capa"}


def migrate_source(source):
    """Repair known shipped defaults while keeping assessments and custom paths."""
    if source.get("repo") == "GoogleCloudPlatform/security-analytics" and source.get("patterns") == ["rules/yaral/*.yaral", "rules/yaral/*.yar", "rules/yaral/*.yara", "src/*.yaral"]:
        source["patterns"] = ["backends/chronicle/yaral/*.yaral"]
    if source.get("repo") == "nsacyber/ELITEWOLF" and source.get("patterns") == ["*.rules"]:
        source["patterns"] = ["ELITEWOLF_SNORT_*.txt"]
    if source.get("repo") == "wazuh/wazuh" and source.get("adapter") == "wazuh" and source.get("patterns") == ["ruleset/rules/*.xml"] and not source.get("ref"):
        source["ref"] = "v4.14.7"
        source["notes"] = "Wazuh 4.x XML rules pinned to v4.14.7; main uses a different format and is outside this adapter's scope."
    if source.get("repo") == "Azure/Azure-Sentinel" and source.get("adapter") == "sentinel":
        source["download_strategy"] = "archive"
        source.setdefault("archive_max_mib", 4096)
        source["notes"] = "Analytics and hunting queries. Full repository download can be several GiB; selected-files HTTPS uses less bandwidth but is slower. Only configured rule paths are extracted."
    if source.get("repo") == "joesecurity/sigma-rules" and source.get("adapter") == "sigma":
        source.setdefault("malformed_yaml", "retain_reference")
        source["notes"] = "Community Sigma rules. Malformed YAML is retained verbatim as reference content and flagged; it is not treated as a parsed detection."
    return source


def load_catalog(path=None):
    path = Path(path) if path else Path(__file__).with_name("sources.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    seen = set()
    for source in data["sources"]:
        migrate_source(source)
        if source.get("adapter") not in ADAPTERS or not isinstance(source.get("patterns"), list) or not source["patterns"] or any(not isinstance(p, str) or not p.strip() for p in source["patterns"]):
            raise ValueError("Every source needs a supported adapter and nonempty file patterns")
        if source.get("ref") and (not isinstance(source["ref"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", source["ref"])):
            raise ValueError("Invalid source branch/tag reference")
        if not REPO_PATTERN.fullmatch(source["repo"]) or source["id"] in seen:
            raise ValueError("Invalid repository or duplicate source ID")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", source["id"]):
            raise ValueError("Source IDs must contain lowercase letters, digits, hyphens or underscores")
        for check in CHECKS:
            entry = source["assessment"].get(check)
            if not entry or entry["status"] not in {"evidence_recorded", "needs_review"}:
                raise ValueError(f"Missing or invalid assessment: {check}")
        seen.add(source["id"])
    return data["sources"]


def source_by_id(source_id, catalog=None):
    return next((s for s in load_catalog(catalog) if s["id"] == source_id), None)
