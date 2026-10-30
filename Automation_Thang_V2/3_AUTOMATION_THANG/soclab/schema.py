"""Strict, versioned event/prediction contract; MITRE data is descriptive, not authorization."""
import re
from datetime import datetime, timezone
from .common import APIError, ip, number

TECHNIQUE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?\Z")
ALLOWED_FIELDS = {"event_id", "timestamp", "source", "src_ip", "dst_ip", "severity", "event_type", "features",
                  "src_port", "dst_port", "protocol", "bytes", "rule_id", "sensor_id", "event_uid",
                  "evidence_id", "mitre", "quality"}
ALLOWED_EVENTS = {"brute_force", "port_scan", "fim", "auth_failure", "web_exploit", "other"}


def event(raw):
    required = {"event_id", "timestamp", "source", "src_ip", "severity", "event_type", "features"}
    if not isinstance(raw, dict) or not required <= raw.keys() or set(raw) - ALLOWED_FIELDS:
        raise APIError(422, "Invalid event fields; see docs/API.md")
    out = dict(raw)
    if not isinstance(out["event_id"], str) or not 1 <= len(out["event_id"]) <= 128:
        raise APIError(422, "event_id must contain 1..128 characters")
    if out["source"] not in ("wazuh", "suricata", "test"):
        raise APIError(422, "Unsupported source")
    if out["event_type"] not in ALLOWED_EVENTS:
        raise APIError(422, "Unsupported event_type")
    out["src_ip"] = ip(out["src_ip"])
    if "dst_ip" in out and out["dst_ip"] is not None:
        out["dst_ip"] = ip(out["dst_ip"])
    number(out["severity"], "severity", 0, 15, True)
    try:
        timestamp = datetime.fromisoformat(out["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("Timezone required")
        out["timestamp"] = timestamp.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, AttributeError) as exc:
        raise APIError(422, "timestamp must be ISO 8601 with timezone") from exc
    f = out["features"]
    names = {"failed_logins_60s", "unique_dst_ports_60s"}
    if not isinstance(f, dict) or set(f) != names:
        raise APIError(422, "features must contain failed_logins_60s and unique_dst_ports_60s")
    for name in names:
        if f[name] is not None:
            number(f[name], name, 0, 1000000, True)
    for name in ("src_port", "dst_port"):
        if name in out and out[name] is not None:
            number(out[name], name, 0, 65535, True)
    if "bytes" in out and out["bytes"] is not None:
        number(out["bytes"], "bytes", 0, 1e15)
    if "protocol" in out and (not isinstance(out["protocol"], str) or len(out["protocol"]) > 20):
        raise APIError(422, "Invalid protocol")
    for name in ("rule_id", "sensor_id", "event_uid", "evidence_id"):
        if name in out and out[name] is not None and (not isinstance(out[name], str) or not 1 <= len(out[name]) <= 128):
            raise APIError(422, f"Invalid {name}")
    mitre = out.get("mitre", {})
    if not isinstance(mitre, dict) or set(mitre) - {"technique_ids", "tactics", "mapping_source", "validation_status"}:
        raise APIError(422, "Invalid MITRE metadata")
    techniques = mitre.get("technique_ids", [])
    tactics = mitre.get("tactics", [])
    if (not isinstance(techniques, list) or len(techniques) > 16 or
        any(not isinstance(t, str) or not TECHNIQUE.fullmatch(t) for t in techniques)):
        raise APIError(422, "MITRE technique IDs must have format T1234 or T1234.001")
    if not isinstance(tactics, list) or len(tactics) > 16 or any(not isinstance(t, str) or len(t) > 80 for t in tactics):
        raise APIError(422, "Invalid MITRE tactics")
    if mitre.get("mapping_source", "none") not in ("wazuh", "curated_rule", "suricata_metadata", "none"):
        raise APIError(422, "Invalid MITRE mapping source")
    if mitre.get("validation_status", "unverified") not in ("unverified", "tested", "proposed"):
        raise APIError(422, "Invalid MITRE validation status")
    out["mitre"] = dict(mitre, technique_ids=list(dict.fromkeys(techniques)), tactics=list(dict.fromkeys(tactics)),
                        mapping_source=mitre.get("mapping_source", "none"),
                        validation_status=mitre.get("validation_status", "unverified"))
    quality = out.get("quality", {})
    if not isinstance(quality, dict) or set(quality) - {"counters", "timestamp"}:
        raise APIError(422, "Invalid quality metadata")
    if quality.get("counters", "unknown") not in ("observed", "unknown", "synthetic"):
        raise APIError(422, "Invalid counter provenance")
    if quality.get("timestamp", "unknown") not in ("source", "processing", "unknown"):
        raise APIError(422, "Invalid timestamp provenance")
    out["quality"] = {"counters": quality.get("counters", "unknown"), "timestamp": quality.get("timestamp", "unknown")}
    return out


def prediction(raw, event_id):
    if not isinstance(raw, dict) or raw.get("event_id") != event_id:
        raise APIError(502, "AI response event_id mismatch")
    if raw.get("score_semantics") != "higher_is_more_anomalous_0_1":
        raise APIError(502, "AI score semantics mismatch")
    if not isinstance(raw.get("model_version"), str) or not raw["model_version"]:
        raise APIError(502, "AI model_version missing")
    try:
        number(raw.get("anomaly_score"), "anomaly_score", 0, 1)
    except APIError as exc:
        raise APIError(502, "AI score invalid") from exc
    if not raw.get("is_mock", False) and not raw.get("calibration_version"):
        raise APIError(502, "Live AI calibration_version missing")
    return raw
