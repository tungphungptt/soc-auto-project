#!/usr/bin/env python3
"""Wazuh / Suricata JSON -> validated Automation event -> durable outbox -> Elasticsearch.

Only exact source rules carry ATT&CK metadata. Unknown features remain None rather
than invented counts. Without trustworthy counters, Automation must never auto-block.
"""
import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import threading
import time
from urllib import request, error

from soclab.common import canonical, http_json, APIError
from soclab.mitre import load_mappings, from_wazuh, from_suricata
from soclab.outbox import Outbox
from soclab.schema import event as validate_event

ROOT = Path(__file__).resolve().parent
AUTOMATION_URL = os.environ.get('SOC_AUTOMATION_URL','http://127.0.0.1:8000')
AUTOMATION_TOKEN = os.environ.get('SOC_AUTOMATION_TOKEN','demo-automation-token')
ES_URL = os.environ.get('SOC_ES_URL','http://127.0.0.1:9200').rstrip('/')
ES_INDEX = os.environ.get('SOC_ES_INDEX','soc-automation-results')
ES_TOKEN = os.environ.get('SOC_ES_API_KEY','')
WAZUH_ALERTS = os.environ.get('SOC_WAZUH_LOG','/var/ossec/logs/alerts/alerts.json')
SURICATA_ALERTS = os.environ.get('SOC_SURICATA_LOG','/var/log/suricata/eve.json')
MIN_WAZUH_LEVEL = int(os.environ.get('SOC_MIN_WAZUH_LEVEL','7'))


def valid_host_ip(value):
    if not isinstance(value,str): return None
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback: return None
        return str(ip)
    except ValueError:
        return None


def source_time(record):
    raw = record.get('timestamp')
    if isinstance(raw,str):
        try:
            dt = datetime.fromisoformat(raw.replace('Z','+00:00'))
            if dt.tzinfo is not None:
                return dt.astimezone(timezone.utc).isoformat(), 'source'
        except ValueError: pass
    return datetime.now(timezone.utc).isoformat(), 'processing'


def stable_id(prefix, record, ident=None):
    # Preserve original alert ID when present; fallback hashes the full raw record.
    value = str(ident) if ident is not None else hashlib.sha256(canonical(record).encode()).hexdigest()[:32]
    return (prefix+'-'+value)[:128]


class WindowCounter:
    """Counts observed alert records, not presumed authentication attempts."""
    def __init__(self):
        self.failed = defaultdict(deque)
        self.ports = defaultdict(deque)
        self.lock = threading.RLock()

    def observe(self, src, timestamp, auth_failure=False, dest_port=None):
        now = datetime.fromisoformat(timestamp).timestamp()
        with self.lock:
            fail = self.failed[src]
            ports = self.ports[src]
            while fail and (now-fail[0]) > 60: fail.popleft()
            while ports and (now-ports[0][0]) > 60: ports.popleft()
            if auth_failure: fail.append(now)
            if dest_port is not None: ports.append((now,int(dest_port)))
            return len(fail), len({port for _,port in ports})


def build_event_from_wazuh(alert, counters=None, mappings=None):
    if not isinstance(alert,dict): return None
    rule = alert.get('rule') or {}
    if not isinstance(rule,dict): return None
    try: level = int(rule.get('level',0))
    except (ValueError,TypeError): return None
    if level < MIN_WAZUH_LEVEL: return None
    data = alert.get('data') or {}
    if not isinstance(data,dict): data={}
    src = valid_host_ip(data.get('srcip') or data.get('src_ip') or alert.get('src_ip'))
    if not src: return None  # Never invent a source IP
    rule_id = str(rule.get('id',''))
    desc = str(rule.get('description','')).lower()
    event_type = ('brute_force' if 'brute force' in desc or rule_id in ('5712','5763')
                  else 'port_scan' if 'port scan' in desc or 'network scan' in desc
                  else 'fim' if 'integrity' in desc or 'fim' in desc
                  else 'auth_failure' if 'authentication failed' in desc or 'failed password' in desc
                  else 'other')
    ts,ts_quality = source_time(alert)
    # Unless a verified count exists in this alert, no invented value is allowed.
    failed = data.get('failed_logins_60s')
    if not isinstance(failed,int) or isinstance(failed,bool) or failed<0: failed=None
    port = data.get('dstport') or data.get('dst_port')
    port = int(port) if str(port).isdigit() and int(port)<=65535 else None
    observed_failed, observed_ports = counters.observe(src,ts,event_type=='auth_failure',port) if counters else (0,0)
    # Observed alerts do not mean observed login attempts; preserve unknown in this case.
    unique_ports = data.get('unique_dst_ports_60s')
    if not isinstance(unique_ports,int) or isinstance(unique_ports,bool) or unique_ports<0: unique_ports=None
    if unique_ports is None and counters and observed_ports: unique_ports=observed_ports
    if event_type=='auth_failure' and counters and failed is None:
        # Count of observed per-attempt alerts; remains preliminary, no automatic block.
        failed=observed_failed
    quality = ('observed' if failed is not None and unique_ports is not None and
               'failed_logins_60s' in data and 'unique_dst_ports_60s' in data else 'unknown')
    output = {'event_id': stable_id('wazuh',alert,alert.get('id')),
              'event_uid': stable_id('wazuh',alert,alert.get('id')),
              'timestamp':ts, 'source':'wazuh','src_ip':src,
              'severity':min(max(level,0),15),'event_type':event_type,
              'rule_id':rule_id or 'unknown',
              'features': {'failed_logins_60s':failed,'unique_dst_ports_60s':unique_ports},
              'quality': {'counters':quality,'timestamp':ts_quality},
              'mitre':from_wazuh(alert,mappings)}
    dst = valid_host_ip(data.get('dstip') or data.get('dst_ip'))
    if dst: output['dst_ip']=dst
    if port is not None: output['dst_port']=port
    return validate_event(output)


def build_event_from_suricata(alert, counters=None, mappings=None):
    if not isinstance(alert,dict): return None
    source=valid_host_ip(alert.get('src_ip'))
    if not source: return None
    ts,ts_quality=source_time(alert)
    port=alert.get('dest_port')
    port=int(port) if str(port).isdigit() and int(port)<=65535 else None
    failed,unique_ports=counters.observe(source,ts,False,port) if counters else (0,0)
    if alert.get('event_type') != 'alert': return None
    info=alert.get('alert') or {}
    if not isinstance(info,dict): return None
    sig=str(info.get('signature','')).lower()
    etype='port_scan' if 'scan' in sig or 'port sweep' in sig else 'web_exploit' if 'exploit' in sig else 'other'
    sid=str(info.get('signature_id','unknown'))
    severity=int(info.get('severity',3)) if str(info.get('severity',3)).isdigit() else 3
    # Suricata severity convention: 1 = high. Map to 15-level scale for the lab only.
    sev={1:13,2:9,3:5}.get(severity,3)
    event_id=stable_id('suricata',alert)
    out={'event_id':event_id,'event_uid':event_id,'source':'suricata','timestamp':ts,
         'src_ip':source,'severity':sev,'event_type':etype,
         'rule_id': f"{info.get('gid',1)}:{sid}",
         'features': {'failed_logins_60s':None,'unique_dst_ports_60s': unique_ports if counters else None},
         'quality': {'counters':'unknown','timestamp':ts_quality},
         'mitre':from_suricata(alert,mappings)}
    dst=valid_host_ip(alert.get('dest_ip'))
    if dst: out['dst_ip']=dst
    if port is not None: out['dst_port']=port
    if isinstance(alert.get('proto'),str):out['protocol']=alert['proto']
    if 'sensor_id' in alert:out['sensor_id']=str(alert['sensor_id'])
    return validate_event(out)


def es_post(doc):
    url=f'{ES_URL}/{ES_INDEX}/_doc'
    payload=canonical(doc).encode()
    headers={'Content-Type':'application/json'}
    if ES_TOKEN:headers['Authorization']='ApiKey '+ES_TOKEN
    req=request.Request(url,data=payload,headers=headers,method='POST')
    with request.build_opener(request.ProxyHandler({})).open(req,timeout=5) as response:
        if response.status not in (200,201): raise RuntimeError(f'ES returned {response.status}')
        return True


def send_to_automation(e):
    return http_json(AUTOMATION_URL+'/events',e,AUTOMATION_TOKEN,timeout=8)


def save_to_elasticsearch(e,result):
    return es_post({'@timestamp':datetime.now(timezone.utc).isoformat(),
                    'event_id':e['event_id'],'event_uid':e.get('event_uid',e['event_id']),
                    'rule_id':e.get('rule_id'),'mitre':e.get('mitre'),
                    'source':e['source'],'src_ip':e['src_ip'],'event_type':e['event_type'],
                    'decision':result.get('decision'),'risk_score':result.get('risk_score'),
                    'anomaly_score':result.get('anomaly_score'),
                    'model_version':result.get('model_version'),
                    'execution':result.get('execution'), 'event':e,'result':result})


def drain_outbox(outbox):
    done=0
    for eid,ev,result in outbox.due():
        try:
            if result is None:
                result=send_to_automation(ev)
                outbox.set_result(eid,result)
            save_to_elasticsearch(ev,result)
            outbox.complete(eid)
            done+=1
        except APIError as exc:
            if exc.status==502 and any(f'Upstream HTTP {code}' in exc.message for code in (400,403,409,413,415,422)):
                outbox.dead_letter(eid,exc.message)
            else:
                outbox.defer(eid,exc)
        except Exception as exc:
            outbox.defer(eid,exc)
    return done


def follow_file(path,parser,label,outbox,counters,mappings,stop):
    path=Path(path)
    while not stop.is_set():
        if not path.exists():
            stop.wait(1)
            continue
        try:
            stat=path.stat()
            size=stat.st_size
            pos=min(size,outbox.cursor(str(path),stat.st_ino))
            with path.open('r',encoding='utf-8',errors='replace') as handle:
                handle.seek(pos)
                while not stop.is_set():
                    line=handle.readline()
                    if not line:
                        if path.stat().st_ino != stat.st_ino or path.stat().st_size < handle.tell():
                            break
                        stop.wait(.5)
                        continue
                    after=handle.tell()
                    try:
                        record=json.loads(line)
                        ev=parser(record,counters,mappings)
                    except Exception as exc:
                        print(f'[BRIDGE] invalid {label} record: {type(exc).__name__}',flush=True)
                        ev=None
                    outbox.accept(str(path),stat.st_ino,after,ev)
        except (OSError,ValueError) as exc:
            print(f'[BRIDGE] source unavailable {label}: {exc}',flush=True)
            stop.wait(1)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--wazuh',default=WAZUH_ALERTS)
    parser.add_argument('--suricata',default=SURICATA_ALERTS)
    parser.add_argument('--outbox',default=str(ROOT/'data'/'bridge.sqlite3'))
    parser.add_argument('--mapping',default=str(ROOT/'config'/'detection_mappings.json'))
    parser.add_argument('--once',action='store_true',help='Attempt delivery of pending outbox items then exit')
    args=parser.parse_args()
    outbox=Outbox(args.outbox)
    if args.once:
        print({'delivered':drain_outbox(outbox),**outbox.counts()})
        return
    mappings=load_mappings(args.mapping)
    counter=WindowCounter()
    stop=threading.Event()
    threads=[threading.Thread(target=follow_file,args=(args.wazuh,build_event_from_wazuh,'wazuh',outbox,counter,mappings,stop),daemon=True),
             threading.Thread(target=follow_file,args=(args.suricata,build_event_from_suricata,'suricata',outbox,counter,mappings,stop),daemon=True)]
    for thread in threads: thread.start()
    print('[BRIDGE] running, durable SQLite outbox; Ctrl+C to stop')
    try:
        while True:
            drain_outbox(outbox)
            time.sleep(.75)
    except KeyboardInterrupt:
        stop.set()
        for t in threads:t.join(timeout=2)
        outbox.conn.close()

if __name__=='__main__':main()
