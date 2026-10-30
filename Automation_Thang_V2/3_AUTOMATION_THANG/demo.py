"""Single-command HTTP Mock demonstration with ephemeral SQLite state."""
import argparse
import json
import tempfile
import threading
from datetime import datetime,timezone
from pathlib import Path
from soclab.automation import Automation
from soclab.common import http_json,load_policy
from soclab.mock_ai import MockAI
from soclab.mock_firewall import MockFirewall
from soclab.server import make_server

ROOT=Path(__file__).resolve().parent

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--execute-mock',action='store_true')
    parser.add_argument('--manual-approval',action='store_true')
    args=parser.parse_args()
    policy=load_policy(str(ROOT/'config'/'policy.json'))
    with tempfile.TemporaryDirectory() as directory:
        ai,fw=MockAI(),MockFirewall(policy,Path(directory)/'fw.db')
        ai_s=make_server('ai',ai,port=0,token='demo-ai-token')
        fw_s=make_server('firewall',fw,port=0,token='demo-firewall-token')
        ai_url=f'http://127.0.0.1:{ai_s.server_port}'
        fw_url=f'http://127.0.0.1:{fw_s.server_port}'
        auto=Automation(policy,Path(directory)/'auto.db',
                        lambda e:http_json(ai_url+'/predict',e,'demo-ai-token'),
                        lambda a:http_json(fw_url+'/block',a,'demo-firewall-token'),
                        dry_run=not args.execute_mock,
                        approval_mode='manual' if args.manual_approval else 'auto')
        auto_s=make_server('automation',auto,port=0,token='demo-automation-token')
        servers=[ai_s,fw_s,auto_s]
        threads=[threading.Thread(target=s.serve_forever,kwargs={'poll_interval':0.1},daemon=True) for s in servers]
        for t in threads:t.start()
        try:
            base=f'http://127.0.0.1:{auto_s.server_port}'
            first=None
            for example in sorted((ROOT/'examples').glob('*.json')):
                e=json.loads(example.read_text(encoding='utf-8'))
                e['timestamp']=datetime.now(timezone.utc).isoformat()
                if first is None:first=dict(e)
                result=http_json(base+'/events',e,'demo-automation-token')
                print(json.dumps({'example':example.name,**result},ensure_ascii=False))
            if first:
                result=http_json(base+'/events',first,'demo-automation-token')
                print(json.dumps({'example':'replay_first_event',**result},ensure_ascii=False))
            if args.manual_approval and args.execute_mock:
                reviews=http_json(base+'/reviews',token='demo-approver-token')['reviews']
                if reviews:
                    rid=reviews[0]['event_id']
                    answer=http_json(base+'/approve',{'event_id':rid,'actor':'SOC analyst demo','approve':True,
                                                    'reason':'Approved for controlled mock test'},'demo-approver-token')
                    print(json.dumps({'example':'approved_review',**answer},ensure_ascii=False))
            print(json.dumps(http_json(fw_url+'/blocks',token='demo-firewall-token'),ensure_ascii=False))
        finally:
            for s in servers:s.shutdown();s.server_close()
            for t in threads:t.join()
            auto.conn.close();fw.conn.close()

if __name__=='__main__':main()
