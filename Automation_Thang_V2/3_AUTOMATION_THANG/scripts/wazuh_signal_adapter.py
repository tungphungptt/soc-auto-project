"""Optional Wazuh Active Response signal-only adapter.

It never calls a firewall directly. If enabled, ensure bridge.py is NOT simultaneously
sending the same source alerts; otherwise dedup still protects actions but adds noise.
Not verified on a running Wazuh manager yet.
"""
import json
import os
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from bridge import build_event_from_wazuh
from soclab.common import http_json


def main():
    if os.environ.get('SOC_ENABLE_WAZUH_AR_SIGNAL')!='true':
        print(json.dumps({'status':'disabled','note':'signal-only optional adapter'}))
        return
    raw=sys.stdin.buffer.read(65537)
    if len(raw)>65536:raise SystemExit('input too large')
    try: data=json.loads(raw)
    except ValueError:raise SystemExit('Wazuh AR JSON malformed')
    if data.get('command')!='add':
        print(json.dumps({'status':'ignored','reason':'not add signal'}))
        return
    alert=((data.get('parameters') or {}).get('alert') or {})
    e=build_event_from_wazuh(alert)
    if not e:
        print(json.dumps({'status':'ignored','reason':'no valid source event'}))
        return
    out=http_json(os.environ.get('SOC_AUTOMATION_URL','http://127.0.0.1:8000').rstrip('/')+'/events',e,
                  os.environ.get('SOC_AUTOMATION_TOKEN','demo-automation-token'))
    print(json.dumps({'status':'sent','decision':out.get('decision'), 'event_id':e['event_id']}))

if __name__=='__main__':main()
