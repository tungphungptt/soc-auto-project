# API contract - SOC Automation v2 (demo HTTP, localhost)

## 1. Dich vu

| Process | Method + endpoint | Token |
|---|---|---|
| MockAI :8001 | POST /predict | SOC_AI_TOKEN |
| MockFirewall :8002 | POST /block, POST /unblock, GET /blocks | SOC_FIREWALL_TOKEN |
| Automation :8000 | POST /events, GET /audit | SOC_AUTOMATION_TOKEN |
| Automation :8000 | GET /reviews, POST /approve, GET /pending, POST /pending/retry | SOC_APPROVER_TOKEN |
| Automation live :8000 | GET /firewall/blocks, POST /firewall/unblock (owned IP only) | SOC_APPROVER_TOKEN |
| Tat ca | GET /health | Public localhost; chi liveness |

Token la `Authorization: Bearer <token>`. Request Content-Type phai la `application/json`.

## 2. Event schema cho POST /events

```json
{
  "event_id":"ssh-001",
  "timestamp":"2026-10-27T12:00:00+00:00",
  "source":"wazuh",
  "src_ip":"198.51.100.23",
  "dst_ip":"192.168.30.20",
  "dst_port":22,
  "severity":12,
  "event_type":"brute_force",
  "rule_id":"5712",
  "features":{"failed_logins_60s":null,"unique_dst_ports_60s":null},
  "quality":{"counters":"unknown","timestamp":"source"},
  "mitre":{"technique_ids":["T1110"],"tactics":["Credential Access"],"mapping_source":"wazuh","validation_status":"unverified"}
}
```

`null` = khong co bo dem duoc xac minh, AI fallback REVIEW; KHONG tu dien 30/100. Event tu `source=test` duoc phep tao trong Mock. Trong live, `source=test` khong the auto block.

## 3. Output

```json
{
  "decision":"REVIEW",
  "execution":"none",
  "reason":"ai_unavailable_or_invalid",
  "model_version":null,
  "risk_score":null,
  "anomaly_score":null,
  "event_id":"ssh-001",
  "mitre":{"technique_ids":["T1110"],"tactics":["Credential Access"],"mapping_source":"wazuh","validation_status":"unverified"}
}
```

Example la output rut gon, co the co them fields. Khi Mock test co du counter, BLOCK returns `execution=mock_applied`. Khi live alias duoc verify nhung chua probe, execution la `opnsense_alias_verified_traffic_unverified`, KHONG duoc goi la block success trong network.

## 4. Manual approval (SOC_DRY_RUN=false, approval_mode=manual)

```bash
curl -H 'Authorization: Bearer demo-approver-token' http://127.0.0.1:8000/reviews
curl -X POST http://127.0.0.1:8000/approve \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer demo-approver-token' \
  -d '{"event_id":"01_bruteforce","actor":"SOC-analyst","approve":true,"reason":"Validated on mock lab"}'
```

Ket qua approve duoc audit, khong co phe duyet tu dong khi policy bao manual. Event qua han, IP protected hoac policy doi -> KHONG block.

Khi firewall ack bi mat, `/pending` ghi pending event. `POST /pending/retry` su dung cung `event_id` de xuat lai cung `request_id`; can analyst xem alias sau timeout. Mat nhan tu event truoc khi pending tao ra khong duoc tu dong chuyen thanh block.

## 5. Error semantics

- 400 JSON khong hop le; 401 token sai; 403 chặn IP duoc bao ve; 409 event/request_id xung dot; 413 body qua lon; 415 Content-Type sai; 422 schema/time; 429 full alias; 502 upstream mismatch; 503 upstream not ready.
- `HTTP 200` chi la ket qua phan hoi API. Xac nhan mang that can probe dong nhat run_id va log rule, CARP.
