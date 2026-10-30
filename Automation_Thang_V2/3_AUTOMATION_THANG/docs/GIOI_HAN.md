# GIOI HAN VA MUC DO XAC MINH

**Co the khang dinh:** core MockAI/MockFirewall + Automation, logic BLOCK/REVIEW/OBSERVE, anti-replay event, protected IP, phan duyet thu cong o HTTP, audit SQLite, TTL Mock, MITRE metadata transport, outbox SQLite, OPNsense contract gia lap qua fake transport.

**Chua the khang dinh:** da chạy OPNsense that; da duoc firewall rule chan goi tin; TTL/unblock hoan toan tren HA OPNsense; Wazuh Active Response chay tren agent; dong bo du lieu toan topology; nguong AI co precision/recall thuc; MITRE coverage theo use case co test, canary, RTO end-to-end; resilience multi worker, bao mat production.

**Can kiem chung tren moi truong cua nhom:**

- REAL-01 Wazuh alert Wazuh -> Bridge -> AI endpoint real -> Automation, nguon log va timestamp goc.
- REAL-02 Suricata EVE JSON -> ES/Kibana, rule metadata, sensor ID, so ban ghi.
- REAL-03 OPNsense alias/rule reference, packet probe truoc/sau, IPv4/IPv6, state tracking.
- REAL-04 Block TTL, rollback + tcp connection restored, retry on reboot/HA.
- REAL-05 AI calibration tu validation independent, split, feature schema, FPR theo base rate.
- REAL-06 Wazuh Active Response thuc su kick script va khong double action voi Bridge.

**Cong viec ngoai pham vi:** full soc deployment, multi-node resilient queue, Elasticsearch version compatibility test, actual switch VLAN/HA config. Do khong co may lab noi truc tiep, nhung thu nghiem nay can do doi cua nhom tren may va nop bang chung rieng.
