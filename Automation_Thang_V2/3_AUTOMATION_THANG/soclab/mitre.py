"""Only retain trustworthy ATT&CK metadata or explicit curated rule maps.

This is NOT a detector or a claim of validated ATT&CK coverage.
"""
import json
from pathlib import Path
from .schema import TECHNIQUE


def load_mappings(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) - {"version", "wazuh_rule_ids", "suricata_sids"}:
        raise ValueError("Invalid detection mapping file")
    return data


def _clean(ids):
    if isinstance(ids, str):
        ids = [ids]
    if not isinstance(ids, list):
        return []
    return list(dict.fromkeys(x for x in ids if isinstance(x, str) and TECHNIQUE.fullmatch(x)))[:16]


def from_wazuh(alert, mappings=None):
    rule = alert.get("rule") or {}
    mitre = rule.get("mitre") or {}
    ids = _clean(mitre.get("id", [])) if isinstance(mitre, dict) else []
    tactics = mitre.get("tactic", []) if isinstance(mitre, dict) else []
    if isinstance(tactics, str):
        tactics = [tactics]
    if ids:
        return {"technique_ids": ids, "tactics": [x for x in tactics if isinstance(x, str)][:16],
                "mapping_source": "wazuh", "validation_status": "unverified"}
    rule_id = str(rule.get("id", ""))
    mapping = (mappings or {}).get("wazuh_rule_ids", {}).get(rule_id)
    if mapping:
        return {"technique_ids": _clean(mapping.get("technique_ids", [])),
                "tactics": mapping.get("tactics", [])[:16], "mapping_source": "curated_rule",
                "validation_status": mapping.get("validation_status", "proposed")}
    return {"technique_ids": [], "tactics": [], "mapping_source": "none", "validation_status": "unverified"}


def from_suricata(alert, mappings=None):
    data = alert.get("alert") or {}
    key = f"{data.get('gid', 1)}:{data.get('signature_id', '')}"
    mapping = (mappings or {}).get("suricata_sids", {}).get(key)
    if mapping:
        return {"technique_ids": _clean(mapping.get("technique_ids", [])),
                "tactics": mapping.get("tactics", [])[:16], "mapping_source": "curated_rule",
                "validation_status": mapping.get("validation_status", "proposed")}
    return {"technique_ids": [], "tactics": [], "mapping_source": "none", "validation_status": "unverified"}
