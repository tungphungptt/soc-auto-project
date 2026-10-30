# MITRE ATT&CK MAPPING - khong nham voi DETECTION COVERAGE

## 1. Luong du lieu

1. Rule Wazuh match -> `rule.id`, `rule.description`, `rule.mitre.id` (neu ruleset co metadata).
2. `bridge.build_event_from_wazuh` giu ma technique va tactic goc. Neu khong co, tra trong, tru khi `config/detection_mappings.json` co rule ID cu the da duoc duyet.
3. Suricata EVE JSON co `alert.gid` / `alert.signature_id`: chi map SID neu co bang mapping theo GID:SID, KHONG tu suy dien ma MITRE tu signature text.
4. `soclab/schema.py` validate MITRE `T1234` hoac `T1234.001`.
5. `soclab/automation.py` luu `mitre` va `rule_id` trong result/audit, khong dung technique ID de bo qua allowlist hay tu block.
6. `bridge.py` luu MITRE trong `soc-automation-results` cho Kibana Discover/Lens (index-pattern `soc-automation-results*`).

## 2. Bang use case trong bao cao

| Kich ban | ATT&CK technique tham chieu | Trang thai source V2 |
|---|---|---|
| SSH brute-force | T1110 | Co metadata native hoac curated rule 5712, status proposed neu chua co test |
| Discovery | T1046 | Can rule ID/SID duoc xac minh |
| Active scanning | T1595 | Can signature va kịch bản xac minh |
| Web exploit | T1190 | Can access log/NIDS rule tested |
| Remote services | T1021 | Can correlation host/network |
| Account manipulation | T1098 | Can host audit rule tested |

`event_type='port_scan'` khong tu suy ra T1046. Cu phap Wazuh `mitre: {id: [...], tactic: [...]}` co the duoc giu nguyen trong event khi da co. Vi du:

```json
{
  "event_id": "wazuh-1712345",
  "rule_id": "5712",
  "mitre": {
    "technique_ids": ["T1110"],
    "tactics": ["Credential Access"],
    "mapping_source": "wazuh",
    "validation_status": "unverified"
  }
}
```

## 3. Khong cong bo 100% coverage vi gan ID

Muốn tinh cover: chay case duong tinh + am tinh tren nguon log, giu `rule_id`, `sensor_id`, `evidence_id` va doi chieu alert. Script `scripts/mitre_coverage.py` chi tinh verified khi record co `validation_status=tested`, `passed=true`, va evidence_id. Den khi co kịch bản dau cuoi va ground truth, toan bo coverage trong bao cao van la use-case design.
