"""Send a local demo JSON event, refreshing event_id/timestamp unless requested otherwise."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import uuid
from soclab.common import http_json


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('json_file')
    parser.add_argument('--keep-id',action='store_true')
    parser.add_argument('--keep-time',action='store_true')
    args=parser.parse_args()
    e=json.loads(Path(args.json_file).read_text(encoding='utf-8'))
    if not args.keep_id:e['event_id']=e['event_id']+'-'+uuid.uuid4().hex[:12]
    if not args.keep_time:e['timestamp']=datetime.now(timezone.utc).isoformat()
    url=os.environ.get('SOC_AUTOMATION_URL','http://127.0.0.1:8000').rstrip('/')
    token=os.environ.get('SOC_AUTOMATION_TOKEN','demo-automation-token')
    print(json.dumps(http_json(url+'/events',e,token),ensure_ascii=False,indent=2))

if __name__=='__main__':main()
