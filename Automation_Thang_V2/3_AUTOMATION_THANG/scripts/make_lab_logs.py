"""Generate clearly marked SAMPLE records; they are NOT proof of Wazuh/Suricata live."""
import json
from datetime import datetime,timezone
from pathlib import Path
import uuid


def main():
    root=Path(__file__).resolve().parents[1]/'examples'/'sample_logs'
    root.mkdir(parents=True,exist_ok=True)
    ts=datetime.now(timezone.utc).isoformat()
    records={'wazuh-alerts.jsonl':{'id':'lab-'+uuid.uuid4().hex[:10],
      'timestamp':ts,'rule':{'id':'5712','level':12,'description':'SSH brute force lab fixture',
      'mitre':{'id':['T1110'],'tactic':['Credential Access']}},
      'data':{'srcip':'198.51.100.23','dstip':'10.0.30.20'}},
      'suricata-eve.jsonl':{'timestamp':ts,'flow_id':99,'event_type':'alert',
      'src_ip':'198.51.100.25','dest_ip':'10.0.30.20','dest_port':22,
      'alert':{'gid':1,'signature_id':222002,'signature':'possible port scan (lab)', 'severity':1}}}
    for file,e in records.items():
        (root/file).write_text(json.dumps(e,ensure_ascii=False)+'\n',encoding='utf-8')
        print(root/file)
    print('These events are SYNTHETIC. Bridge treats missing counters as unknown -> REVIEW.')

if __name__=='__main__':main()
