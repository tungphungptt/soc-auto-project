# SOC Automation - Thang (nang cap V2)

**Pham vi:** bo dieu phoi he thong SOC nhom 1. Ban nay CHAY MOCK MAC DINH. Chi la tinh dung logic dieu phoi, khong phai chung nhan SOC end-to-end. Xem `docs/BAN_GIAO.md` va `docs/GIOI_HAN.md` truoc khi bao ve.

## 1. Chay nhanh (Python 3.10+; khong can pip / Docker)

Giai nen ZIP, vao thu muc `3_AUTOMATION_THANG` va chay:

```bash
python demo.py --execute-mock
```

Ket qua du kien: `brute_force` BLOCK / mock_applied (Risk=93.3), `port_scan` BLOCK / mock_applied, `benign` OBSERVE, IP management/data center/outside scope REVIEW, replay=true.

Chay dry-run (KHONG them IP vao MockFirewall):

```bash
python demo.py
```

Chay ca phan duyet thu cong (tham khao `docs/API.md`):

```bash
python demo.py --execute-mock --manual-approval
```

Chay bo test:

```bash
python -m unittest discover -s tests -v
```

## 2. Chay 3 dich vu HTTP o 3 terminal

Moi terminal dat trong thu muc `3_AUTOMATION_THANG`:

```bash
python -m soclab ai          # 127.0.0.1:8001
python -m soclab firewall    # 127.0.0.1:8002 (SQLite Mock)
python -m soclab automation  # 127.0.0.1:8000
```

Mac dinh `SOC_DRY_RUN=true`. Neu muon apply vao MOCK:

```bash
SOC_DRY_RUN=false python -m soclab automation
```

Windows PowerShell: `$env:SOC_DRY_RUN="false"; python -m soclab automation`.

Tren terminal thu tu:

```bash
python send_event.py examples/01_bruteforce.json
python send_event.py examples/03_management.json
```

De giu ID va thoi gian: `--keep-id --keep-time` (can de timestamp trong khung cho phep).

`/health` chi la liveness; /audit va /blocks can token demo. Xem `docs/API.md`.

## 3. Source quan trong

- `soclab/automation.py`: risk decision, approval, dedup, pending, retry, audit.
- `soclab/policy.py` + `config/policy.json`: nguyen tac block, protected, TTL, risk.
- `soclab/schema.py`: hop dong event, MITRE, quality, AI prediction.
- `soclab/mitre.py` + `config/detection_mappings.json`: bao toan native Wazuh technique va bang mapping rule da duoc duyet. `proposed` KHONG la coverage da duoc test.
- `bridge.py` + `soclab/outbox.py`: Wazuh/Suricata JSON -> Automation -> ES voi SQLite outbox, bo loc Wazuh, timestamp nguon.
- `soclab/ai_adapter.py`: API adapter sang IsolationForest that; can independent validation calibration.
- `soclab/opnsense.py`: adapter alias cua OPNsense voi TLS, idempotency va cleanup.
- `soclab/mock_firewall.py`, `soclab/mock_ai.py`: double tests (khong chan mang).
- `scripts/build_calibration.py`: tao empirical score mapping tu tap validation DOC LAP. Khong kem tap validation that.
- `scripts/mitre_coverage.py`: chi dem coverage co evidence/test.

## 4. Bridge (khi co file log Wazuh/Suricata)

`bridge.py` chay doc log o paths duoc cau hinh bang `SOC_WAZUH_LOG` va `SOC_SURICATA_LOG` (mac dinh paths Linux). Khi bat lan dau, doc tu dau file; offset duoc luu trong `data/bridge.sqlite3`. Khong nen chi thang vao log dang chay ma khong du tinh dung luong khi test; co the dung file mau rieng.

```bash
python bridge.py --wazuh /duong/dan/alerts.json --suricata /duong/dan/eve.json
```

Neu khong co Elasticsearch, outbox se giu result chua gui duoc cho toi khi ES online. `python bridge.py --once` thu gui lai; chua phai bang chung full log pipeline da hoat dong.

**Khong chen 30 failed logins/100 ports gia khi doc alert.** Khi khong du ban ghi de tinh feature, `None` va AI fallback REVIEW; can feature extractor cua telemetry/flow de phat hien live.

## 5. OPNsense live (KHONG bat khi bao ve tren localhost)

**Live khong duoc bat mac dinh.** Xem `docs/SETUP_OPNSENSE.md` de biet 2 lan xac nhan, cau hinh alias, tokens, CA, rules va kiem tra block/unblock tren traffic.

Adapter dung duong dan official `POST /api/firewall/alias_util/add/<alias>`, `POST /delete/<alias>`, `GET /list/<alias>`; response `opnsense_alias_verified_traffic_unverified` chi xac nhan alias, khong duoc dung lam bang chung luu luong bi chan.

## 6. Doi chieu bao cao

Xem `docs/BAN_GIAO.md` cho ma tran yeu cau AUTO-01..10, `docs/MITRE_MAPPING.md` cho detection mapping, `docs/KIEM_THU.md` va `verification/` cho ket qua kiem thu da chay. Ban ZIP nay khong chua ket qua kiem chung live OPNsense/HA, chua co bo benchmark du lieu mang that.
