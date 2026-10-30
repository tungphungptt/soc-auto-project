# BIEN BAN DOI CHIEU CODE THANG VOI BAO CAO NHOM 1

Ngay danh gia: 2026-10-27. Co so: `NHOM1-BAOCAO-SOC.docx`, mục 2.7, 3.3.16–3.3.19 va `SOC_AUTO NHOM 1.zip` goc.

## A. NANG CAP DA CO TRONG SOURCE V2

| Hang muc | File | Cach kiem tra | Pham vi |
|---|---|---|---|
| Chay demo khong loi missing path | `demo.py`, `config/policy.json`, `examples/*.json` | `python demo.py --execute-mock` | Mock local |
| Mapping MITRE khong ep tu event type | `soclab/mitre.py`, `bridge.py`, `config/detection_mappings.json` | `tests/test_soc.py`, Wazuh `rule.mitre` | Metadata; unverified neu chua co test |
| Schema va version metadata | `soclab/schema.py` | Unit tests 07/08 | Schema hop le |
| Dung rule level cua Wazuh | `bridge.py` | `test_17_wazuh_level_filter` | Parser path |
| Khong dung feature co dinh | `bridge.py` | `test_16_wazuh_mitre_metadata_and_time` | None neu khong co so dem thuc |
| Timestamp tu nguon va ID khac nhau cua EVE | `bridge.py` | Tests 16, 18 | Khong chung minh dong bo NTP |
| SQLite outbox, cursor, retry | `soclab/outbox.py`, `bridge.py` | Test 20 | Local at-least-once, phai dung event_id dedup |
| Human approval | `soclab/automation.py`, `/approve`, `/reviews` | Tests 12, 13, 26; demo manual | HTTP; khong GUI |
| Risk, protected, dedup, TTL, audit | `soclab/policy.py`, `soclab/mock_firewall.py`, `soclab/automation.py` | Tests 01–15 | Mock |
| Circuit breaker AI/Firewall | `soclab/resilience.py` | Fail-closed + pending retry tests | In-memory cooldown, khong cluster HA |
| Real AI adapter + raw score | `soclab/ai_adapter.py`, `../2_AI_MINH/src/app.py` | Tests 23, 24 | Can validation normal dataset doc lap de calibrate |
| OPNsense API adapter | `soclab/opnsense.py` | Tests 21, 22 voi API gia lap | Chua ket noi vao firewall that; can auth/rules/probe |
| Ghi ket qua va MITRE vao ES | `bridge.py` | Kiem tra doc payload va outbox | Chua kiem thu voi Elastic real o lan ban giao |

## B. CHUAN AUTO-01..10: TOAN BO KHONG DONG NGHIA LIVE

- AUTO-01: token ben gui da co; cho live can cong khai TLS/reverse proxy va token rieng. API approver su dung token rieng.
- AUTO-02: schema/time validation va quy tac hop le da co.
- AUTO-03: event_uid, rule_id, MITRE metadata duoc giu lai; chain raw-event -> action chua co kiem chung e2e live.
- AUTO-04: protected list va enforcement scope da co theo policy demo; live config can Nam duyet.
- AUTO-05: policy version va nguyen tac risk da co, nguong demo khong phai benchmark khoa hoc.
- AUTO-06: event id, request id anti-replay, audit da co; dedup cap incident can du lieu tuuong quan that.
- AUTO-07: dry-run, mock, opnsense adapter da tach; live bi khoa nhieu lop, chua chay tren thiet bi.
- AUTO-08: TTL mock, OPNsense lease + xu ly expire theo contract da co; chua kiem thu reboot/failover live.
- AUTO-09: SQLite audit va event version co; chua day du data governance production.
- AUTO-10: xac nhan trang thai alias adapter; CHUA xac nhan traffic that, connection state va HA. Can LIVE-04/05/06.

## C. PHAN THUOC THANH VIEN KHAC

- Minh: Cung cap real AI endpoint va tap validation doc lap de sinh calibration. Ban `2_AI_MINH/src/app.py` duoc sua: bo score 0.95/0.05, tra raw_score + model hash; can test tren moi truong scikit-learn cua Minh.
- Tung: Wazuh/Suricata native rules co MITRE ID, telemetry host/flow va dem event that tren cua so 60s; phai test rule tren Wazuh that. Du lieu MITRE nguon khong phai chung nhan coverage.
- Nam: OPNsense alias type External, rule co tham chieu alias, account key it quyen, CA TLS, dai IP duoc phe duyet, network probe, CARP/failover va thu nghiem TTL.

## D. NHUNG VIỆC CHUA THE TU HOAN THIEN CHI BANG CODE

1. Live-01..09: khong co topologies VM, traffic host that va log nguyen nhan ket qua. Test code khong thay bang chung live.
2. Neu Wazuh rule chua gui MITRE: mapping status `proposed`, can validate rule va kịch bản dương/âm truoc khi danh `tested`.
3. Khong co du lieu normal validation doc lap; chua co calibrator artifact dung de dong auto block bang AI that.
4. Khong co SLA end-to-end hoac p95 chặn that; khong duoc dung 8.27ms va 14.05ms offline/Mock thay the.
5. SQLite, single worker API, HTTP stdlib, Docker setup la PoC/lab; khong phai deployment production multi-node. Canary, failover, queue capacity va security review can lam tiep.

## E. CACH DEMO THIET THUC

`python demo.py --execute-mock --manual-approval` -> RESPONSE REVIEW -> APPROVE -> BLOCK/MOCK_APPLIED, replay, audit. Sau do `python -m unittest discover -s tests -v`. Moi cau giai thich 'Mock' la dau ra cua mot backend gia lap, khong phải packet bi OPNsense chan.
