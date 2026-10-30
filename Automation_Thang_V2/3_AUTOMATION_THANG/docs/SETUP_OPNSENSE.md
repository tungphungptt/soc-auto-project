# OPNsense live adapter - PHAI DUOC NGUOI QUAN TRI CHO PHEP

Chuong trinh su dung API official OPNsense:

- POST `/api/firewall/alias_util/add/<alias>` JSON `{"address":"IP"}`
- POST `/api/firewall/alias_util/delete/<alias>` JSON `{"address":"IP"}`
- GET `/api/firewall/alias_util/list/<alias>` de verify entry

Tai lieu: https://docs.opnsense.org/manual/aliases.html va https://docs.opnsense.org/development/api/core/firewall.html

**Chu y:** alias khong tu chan traffic; Nam phai tao alias `External` (uu tien) va rule deny tham chieu alias, thong nhat interface + direction + network scope va state tracking. Doi voi host/network alias, API co the cap nhat cau hinh luu ben; can test tren OPNsense version dang dung. Khong dung `/flush` vi co the xoa ban ghi nguon khac.

## Chuan bi

1. Thong nhat nguon IP thu trong lab, protected management, DMZ, DC, VIP, IP cua monitoring, cap nhat `config/policy_live_template.json` thanh policy live da phe duyet, khong de placeholder.
2. Tao tai khoan API chi du quyen alias Util cho dung alias. Khong nhung key/secret vao ZIP.
3. Cau hinh HTTPS co CA hop le; `SOC_OPNSENSE_CA_FILE` tro toi CA tin cay, khong dung `curl -k` de xac minh.
4. Tao validation normal data doc lap, generate `SOC_AI_CALIBRATION` tu `scripts/build_calibration.py`; real AI minh tra `model_version` sha256 model.
5. Dung `approval_mode=manual`, `SOC_AI_MODE=real`, `SOC_FIREWALL_MODE=opnsense`, `SOC_DRY_RUN=false`. Cau hinh `SOC_POLICY` real.
6. Chỉ bật live sau khi nguoi van hanh dong y: `SOC_ENABLE_LIVE=true` va `SOC_LIVE_CONFIRM=I_ACCEPT_REAL_FIREWALL_CHANGES`. Token automation va approver phai random/khac demo.

## Kiem thu dua tren bang chung

- Gui mot event co nguon Wazuh/Suricata va feature da duoc xac minh, AI raw score hop le.
- Review + approve: xem `GET /reviews`, POST `/approve` bang token analyst.
- Quan sat output `opnsense_alias_verified_traffic_unverified`. Lay alias list, rule state va traffic probe; co log packet/connection before/after cung run_id.
- Cho het TTL, verify alias da duoc xoa va ket noi moi hoat dong lai. Thu reboot controller & OPNsense, duplicate request, HA.

**Khong duoc dung ip quan tri/dich vu thiet yeu lam nguon block test.** Khi API loi sau add, thao tac co the da ap dung; kiem tra alias truoc khi retry. Adapter chi xoa IP do no da quan ly, khong xoa IP da co truoc trong alias. Network effect la buoc kiem thu rieng.
