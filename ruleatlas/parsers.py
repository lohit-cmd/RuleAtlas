"""Read detection content as data. Never import or execute upstream code."""
import ast
import json
import posixpath
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote

import yaml

from .store import ATTACK_ID

MAX_FILE = 2 * 1024 * 1024


def as_text(value):
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)


def base(source, path, commit, title, logic, *, data=None, language="Sigma", kind="detection", description="", telemetry=None):
    data = json.loads(json.dumps(data or {}, default=str))
    # Restrict structured mappings to mapping fields. A technique in a reference
    # URL or descriptive comparison is not automatically an authored mapping.
    mapping_fields = {k: data[k] for k in ("tags", "Tags", "threat", "relevantTechniques", "subTechniques", "techniques", "threatAnalysisTechniques", "tactics", "mitre", "mitre_attack_id", "mitreattack", "attack", "att&ck", "attack_ids", "Reports", "metadata_text") if k in data}
    metadata = as_text(mapping_fields)
    ids = sorted({m.group().upper() for m in ATTACK_ID.finditer(metadata)})
    # A local directory without a known revision must not produce a fabricated permalink.
    url = f'https://github.com/{source["repo"]}/blob/{quote(commit, safe="")}/{quote(path, safe="/")}' if commit else ""
    references = (data.get("references") or []) if isinstance(data, dict) else []
    if isinstance(references, str):
        references = [references]
    return {"rule_id": str(data.get("id") or data.get("rule_id") or title), "path": path, "title": str(title),
        "description": str(description or ""), "logic": str(logic), "language": language, "kind": kind,
        "attack_ids": ids, "attack_id_origin": "source text; mapping not confirmed" if "metadata_text" in data else "structured source metadata",
        "telemetry": telemetry or {}, "source_url": url, "repository": source["repo"],
        "commit": commit or "unknown local revision", "author": as_text(data.get("author", "not specified")),
        "maturity": str(data.get("status", data.get("maturity", "not specified"))),
        "references": [x for x in references if isinstance(x, str)],
        "license": str(data.get("license", "See upstream license; not inferred")),
        "validation": "untested", "parse_status": "format parsed; detection-engine syntax not validated",
        "dependencies": [], "metadata": data}


def parse_file(source, root, file, commit="", *, original_path=None, companions=None):
    root, file = Path(root).resolve(), Path(file)
    if file.is_symlink() or not file.resolve().is_relative_to(root):
        raise ValueError("Symlinks and paths outside source are not imported")
    if file.stat().st_size > MAX_FILE:
        raise ValueError("File exceeds 2 MiB limit")
    text = file.read_text(encoding="utf-8-sig")
    path = original_path or file.relative_to(root).as_posix()
    adapter = source["adapter"]
    if adapter in {"sigma", "splunk", "sentinel", "sublime", "panther", "falco"}:
        try:
            documents = list(yaml.safe_load_all(text))
        except (yaml.scanner.ScannerError, yaml.parser.ParserError, yaml.composer.ComposerError) as error:
            if source.get("malformed_yaml") != "retain_reference":
                raise
            # Preserve malformed upstream text for review without guessing how to repair its logic.
            item = base(source, path, commit, file.stem + " [unparsed YAML]", text,
                language="Unparsed YAML", kind="reference", description="Upstream YAML syntax failed; raw source retained for review.")
            item["parse_status"] = "parse failed; raw source retained"
            item["metadata"] = {"parse_error": str(error)[:500]}
            return [item]
        results = []
        for doc in documents:
            if adapter == "falco":
                for d in doc if isinstance(doc, list) else []:
                    if not isinstance(d, dict) or "rule" not in d or "condition" not in d:
                        continue
                    results.append(base(source, path, commit, d["rule"], yaml.safe_dump(d, sort_keys=False),
                        data=d, language="Falco", description=d.get("desc", ""), telemetry={"source": d.get("source", "syscall")}))
                continue
            if not isinstance(doc, dict):
                continue
            if adapter == "sigma":
                if not ("title" in doc or "rule" in doc) or not ("detection" in doc or "correlation" in doc):
                    continue
                logic = yaml.safe_dump({k: doc[k] for k in ("detection", "correlation") if k in doc}, sort_keys=False)
                item = base(source, path, commit, doc.get("title", doc.get("rule")), logic, data=doc,
                    kind="correlation" if "correlation" in doc else "detection", description=doc.get("description", ""), telemetry=doc.get("logsource", {}))
            elif adapter == "splunk":
                if "name" not in doc or "search" not in doc:
                    continue
                item = base(source, path, commit, doc["name"], str(doc["search"]), data=doc, language="SPL",
                    kind="hunting" if str(doc.get("type", "")).lower() == "hunting" else "detection",
                    description=doc.get("description", ""), telemetry={"data_source": doc.get("data_source", []), "implementation": doc.get("how_to_implement", "")})
                item["dependencies"] = [{"name": name, "type": "macro", "status": "unresolved"}
                    for name in sorted(set(re.findall(r"`([^`(]+)(?:\([^`]*\))?`", item["logic"])))]
            elif adapter == "sentinel":
                if "name" not in doc or "query" not in doc:
                    continue
                item = base(source, path, commit, doc["name"], str(doc["query"]), data=doc, language="KQL",
                    kind="hunting" if "hunting" in path.lower() else "detection", description=doc.get("description", ""),
                    telemetry={"connectors": doc.get("requiredDataConnectors", [])})
            elif adapter == "sublime":
                if "name" not in doc or "source" not in doc:
                    continue
                item = base(source, path, commit, doc["name"], str(doc["source"]), data=doc, language="MQL",
                    kind="hunting" if "discovery" in path else "detection", description=doc.get("description", ""), telemetry={"platform": "email"})
            elif adapter == "panther":
                if doc.get("AnalysisType") not in {"rule", "scheduled_rule", "policy", "correlation_rule"}:
                    continue
                filename = doc.get("Filename")
                logic = yaml.safe_dump(doc, sort_keys=False)
                if filename:
                    sibling = file.parent / filename
                    if companions is not None:
                        logical = posixpath.normpath(posixpath.join(posixpath.dirname(path), filename))
                        if logical.startswith(('/', '../')) or '\\' in logical:
                            raise ValueError("Panther code path escapes the repository")
                        sibling = companions.get(logical, root / "__missing_companion__")
                    if sibling.is_symlink() or not sibling.resolve().is_relative_to(root):
                        raise ValueError("Panther code path escapes the repository")
                    if not sibling.is_file() or sibling.stat().st_size > MAX_FILE:
                        raise ValueError("Missing or oversized Panther code dependency")
                    logic = sibling.read_text(encoding="utf-8")
                    ast.parse(logic)  # Parse only; never evaluate.
                item = base(source, path, commit, doc.get("DisplayName", doc.get("RuleID", doc.get("PolicyID", path))), logic,
                    data=doc, language="Python" if filename else "Panther YAML",
                    kind="configuration" if doc["AnalysisType"] == "policy" else "correlation" if doc["AnalysisType"] == "correlation_rule" else "detection",
                    description=doc.get("Description", ""), telemetry={"log_types": doc.get("LogTypes", [])})
                item["dependencies"] = [{"type": "helpers", "status": "not resolved", "name": "Python imports and Panther runtime"}]
            results.append(item)
        return results
    if adapter == "elastic":
        doc = tomllib.loads(text)
        d = doc.get("rule", {})
        if not d.get("name"):
            return []
        data = {**doc.get("metadata", {}), **d}
        if not d.get("query"):
            if d.get("type") != "machine_learning":
                return []
            return [base(source, path, commit, d["name"], json.dumps(d, indent=2, default=str),
                data=data, language="Elastic ML configuration", kind="configuration",
                description=d.get("description", ""), telemetry={"machine_learning_job_id": d.get("machine_learning_job_id", [])})]
        return [base(source, path, commit, d["name"], d["query"], data=data, language=str(d.get("language", "unknown")),
            description=d.get("description", ""), telemetry={"index": d.get("index", []), "integration": data.get("integration", [])})]
    if adapter == "wazuh":
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            raise ValueError("XML entities are not supported")
        # Wazuh regex text can contain literal backslash-angle sequences. XML-escape
        # the angle for ElementTree; the resulting regex text still contains exactly \<.
        xml_text = re.sub(r"\\<(?!/)", r"\\&lt;", text)
        tree = ET.fromstring("<ruleset>" + re.sub(r"<\?xml[^>]*\?>", "", xml_text) + "</ruleset>")
        return [base(source, path, commit, r.findtext("description") or f'Wazuh {r.get("id")}', ET.tostring(r, encoding="unicode"),
            data={"id": r.get("id"), "mitre": [i.text for i in r.findall("mitre/id")]}, language="Wazuh XML",
            telemetry={"decoder": r.findtext("decoded_as", "unspecified")}) for r in tree.iter("rule")]
    if adapter in {"yaral", "yara"}:
        if not re.search(r"\brule\s+\w+", text):
            return []
        names = re.findall(r"\brule\s+(\w+)", text)
        item = base(source, path, commit, names[0] if len(names) == 1 else f'{file.stem} ({len(names)} rules in file)', text,
            data={"metadata_text": text}, language="YARA-L" if adapter == "yaral" else "YARA",
            kind="detection" if adapter == "yaral" else "file-signature", description="Source file indexed verbatim; inspect individual conditions.")
        item["parse_status"] = "raw source indexed; syntax not validated"
        return [item]
    if adapter in {"kql_markdown", "code", "snort", "capa"}:
        if adapter == "kql_markdown":
            blocks = []
            # Parse complete fenced blocks so a closing fence is never mistaken for
            # an opening fence around ordinary Markdown prose.
            for match in re.finditer(r"^ {0,3}(`{3,}|~{3,})([^\n]*)\n(.*?)^ {0,3}\1[ \t]*$", text, re.S | re.M):
                language, block = match.group(2).strip().lower(), match.group(3)
                looks_kql = bool(re.search(r"(?im)^\s*(?:[a-z][\w.]*\s*\||let\s+\w+\s*=|(?:union|search|datatable|range|print)\b|\|\s*(?:where|extend|project|summarize|join|sort|take|order|distinct|lookup|evaluate)\b)", block))
                if language in {"kql", "kusto", "sql"} or (not language and looks_kql):
                    blocks.append((block, "SQL" if language == "sql" and not looks_kql else "KQL"))
            if file.suffix.lower() in {".kql", ".csl"}:
                blocks = [(text, "KQL")]
            if not blocks:
                return []
            title = next((line.lstrip("# ").strip() for line in text.splitlines() if line.startswith("#")), file.stem)
            records = [base(source, path, commit, f'{title} [query {i+1}]', block.strip(), data={"metadata_text": text},
                language=language, kind="hunting", description="Community query; deployment and behavioral applicability require review.") for i, (block, language) in enumerate(blocks) if block.strip()]
        elif adapter == "snort":
            records = [base(source, path, commit, re.search(r'msg:\s*"([^"]+)"', line).group(1) if re.search(r'msg:\s*"([^"]+)"', line) else f'{file.stem}:{i}', line,
                data={"id": f'{path}:{i}'}, language="Snort/Suricata", kind="network-signature") for i, line in enumerate(text.splitlines(), 1) if re.match(r"^(alert|drop|reject|pass)\s", line)]
        elif adapter == "capa":
            d = yaml.safe_load(text)
            if not isinstance(d, dict) or "rule" not in d:
                return []
            meta = d["rule"].get("meta", {})
            records = [base(source, path, commit, meta.get("name", file.stem), text, data=meta, language="capa", kind="capability")]
        else:
            records = [base(source, path, commit, file.stem, text, language=file.suffix.lstrip("."), kind="reference",
                description="Source code/reference artifact. Not classified as a deployable detection.")]
        for r in records:
            r["parse_status"] = "source extracted; detection-engine syntax not validated"
        return records
    raise ValueError(f"Unsupported adapter: {adapter}")
