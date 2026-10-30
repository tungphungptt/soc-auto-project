# KIEM THU VA XAC MINH

`python -m unittest discover -s tests -v`

Test lab bao gom 31 cases: Mock BLOCK/OBSERVE/REVIEW, replay, schema, metadata MITRE, AI missing fallback, TTL, allowlist, approval/reject, pending idempotent retry, dry-run, Wazuh/Suricata parser, durable outbox, OPNsense adapter voi fake transport, score calibration contract va HTTP role separation.

Lenh demo:

```bash
python demo.py --execute-mock
python demo.py --execute-mock --manual-approval
python demo.py
```

`verification/test_results.txt`, `verification/demo_mock.jsonl`, `verification/demo_approval.jsonl` la log cua lenh da chay tai moi truong tao ban giao. Log chua duoc gan ket voi output Wazuh/Suricata/OPNsense that. Doi voi test live, chua co bo anh/video/packet capture tu may nhom.

Can chot environment Python, phien ban opnsense, so worker, log metadata, timestamp UTC, run_id, case_id, host IP/dst IP va duong dan moi truong truoc khi do latency end-to-end; khong cong bo ket qua clock gia lam network RTO.

Co the tao fixture khong can Wazuh:

```bash
python scripts/make_lab_logs.py
python bridge.py --wazuh examples/sample_logs/wazuh-alerts.jsonl --suricata examples/sample_logs/suricata-eve.jsonl
```

Cac fixture nay la log gia lap (KHONG phai evidence live), nen thieu counter va policy REVIEW; dung de test MITRE metadata + luu outbox. SQLite `outbox.deadletter` giu input khong hop le/permanent HTTP 4xx de kiem tra lai, khong chan muon. Outbox can gioi han dung luong khi trien khai lon.
