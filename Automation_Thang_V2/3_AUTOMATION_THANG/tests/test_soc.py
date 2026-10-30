import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from datetime import datetime,timezone
from unittest.mock import patch

from soclab.common import APIError,load_policy,canonical,http_json
from soclab.mock_ai import MockAI
from soclab.mock_firewall import MockFirewall
from soclab.automation import Automation
from soclab.schema import event
from soclab.mitre import from_wazuh, from_suricata,load_mappings
from soclab.outbox import Outbox
from soclab.opnsense import OPNsenseFirewall
from soclab.ai_adapter import RealAI
from soclab.server import make_app,make_server

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('socbridge', ROOT/'bridge.py')
bridge=importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def sample(eid='case-1',src='198.51.100.23',kind='brute_force',severity=12,failed=30,ports=1):
    return {'event_id':eid,'timestamp':datetime.now(timezone.utc).isoformat(),
            'source':'test','src_ip':src,'dst_ip':'10.0.30.20','dst_port':22,
            'severity':severity,'event_type':kind,
            'features':{'failed_logins_60s':failed,'unique_dst_ports_60s':ports},
            'mitre':{'technique_ids':['T1110'] if kind=='brute_force' else [],
                     'tactics':['Credential Access'] if kind=='brute_force' else [],
                     'mapping_source':'none','validation_status':'proposed'}}


class Cases(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.policy=load_policy(str(ROOT/'config'/'policy.json'))
        self.fw=MockFirewall(self.policy,Path(self.folder.name)/'fw.sqlite')
        self.addCleanup(self.fw.conn.close)
        self.auto=Automation(self.policy,Path(self.folder.name)/'auto.sqlite',MockAI().predict,self.fw.block,dry_run=False)
        self.addCleanup(self.auto.conn.close)

    def assertError(self,call,status):
        with self.assertRaises(APIError) as cm:call()
        self.assertEqual(cm.exception.status,status)

    def test_01_block(self):
        v=self.auto.process(sample())
        self.assertEqual(v['decision'],'BLOCK');self.assertEqual(v['execution'],'mock_applied')
        self.assertEqual(v['risk_score'],93.3)
        self.assertEqual(v['mitre']['technique_ids'],['T1110'])
        self.assertEqual(len(self.fw.blocks()['blocks']),1)

    def test_02_observe(self):
        v=self.auto.process(sample(kind='other',severity=2,failed=0))
        self.assertEqual(v['decision'],'OBSERVE')

    def test_03_protected(self):
        v=self.auto.process(sample(src='10.10.99.10',kind='port_scan',ports=100))
        self.assertEqual(v['decision'],'REVIEW');self.assertEqual(v['reason'],'protected_ip')

    def test_04_scope(self):
        v=self.auto.process(sample(src='10.10.40.25',kind='port_scan',ports=100))
        self.assertEqual(v['decision'],'REVIEW');self.assertEqual(v['reason'],'outside_enforcement_scope')

    def test_05_duplicate_replay(self):
        e=sample();self.auto.process(e)
        self.assertTrue(self.auto.process(e)['replayed'])
        self.assertEqual(len(self.fw.blocks()['blocks']),1)

    def test_06_changed_event_id_rejected(self):
        e=sample();self.auto.process(e)
        e['severity']=13
        self.assertError(lambda:self.auto.process(e),409)

    def test_07_invalid_token_schema_extra(self):
        e=sample();e['hack']='yes'
        self.assertError(lambda:event(e),422)

    def test_08_mitre_fields_and_invalid_id(self):
        e=sample();self.assertEqual(event(e)['mitre']['technique_ids'],['T1110'])
        e['mitre']['technique_ids']=['NOT_A_TECHNIQUE'];self.assertError(lambda:event(e),422)

    def test_09_null_counters_fail_review(self):
        e=sample();e['features']['failed_logins_60s']=None
        result=self.auto.process(e)
        self.assertEqual(result['decision'],'REVIEW');self.assertEqual(result['reason'],'ai_unavailable_or_invalid')

    def test_10_ttl_expire_mock(self):
        now=[time.time()]
        fw=MockFirewall(self.policy,Path(self.folder.name)/'clock.db',clock=lambda:now[0])
        self.addCleanup(fw.conn.close)
        fw.block({'request_id':'timed','ip':'198.51.100.33','ttl_seconds':3})
        self.assertEqual(len(fw.blocks()['blocks']),1)
        now[0]+=4
        self.assertEqual(fw.blocks()['blocks'],[])
        self.assertTrue(fw.conn.execute("SELECT 1 FROM audit WHERE action='EXPIRE'").fetchone())

    def test_11_allowlist_unblock_direct(self):
        self.assertError(lambda:self.fw.block({'request_id':'x','ip':'10.10.99.20','ttl_seconds':20}),403)
        self.assertEqual(self.fw.unblock({'ip':'198.51.100.23'})['status'],'unblocked')

    def test_12_manual_review_approve(self):
        auto=Automation(self.policy,Path(self.folder.name)/'manual.db',MockAI().predict,self.fw.block,
                        dry_run=False,approval_mode='manual')
        self.addCleanup(auto.conn.close)
        first=auto.process(sample('man-1'))
        self.assertEqual(first['decision'],'REVIEW')
        self.assertEqual(first['reason'],'approval_required')
        self.assertEqual(len(self.fw.blocks()['blocks']),0)
        self.assertEqual(len(auto.reviews()['reviews']),1)
        answer=auto.approve({'event_id':'man-1','actor':'analyst','approve':True,'reason':'controlled mock test'})
        self.assertEqual(answer['execution'],'mock_applied')
        self.assertEqual(len(self.fw.blocks()['blocks']),1)
        self.assertEqual(auto.reviews()['reviews'],[])

    def test_13_review_reject(self):
        auto=Automation(self.policy,Path(self.folder.name)/'reject.db',MockAI().predict,self.fw.block,
                        dry_run=False,approval_mode='manual')
        self.addCleanup(auto.conn.close)
        auto.process(sample('reject-1'))
        answer=auto.approve({'event_id':'reject-1','actor':'analyst','approve':False,'reason':'insufficient evidence'})
        self.assertEqual(answer['approval_status'],'rejected')
        self.assertEqual(len(self.fw.blocks()['blocks']),0)

    def test_14_pending_retry_idempotent(self):
        state={'calls':0}
        def unreliable(a):
            state['calls']+=1
            response=self.fw.block(a)
            if state['calls']==1:raise APIError(503,'pretend acknowledgement dropped')
            return response
        auto=Automation(self.policy,Path(self.folder.name)/'pend.db',MockAI().predict,unreliable,dry_run=False)
        self.addCleanup(auto.conn.close)
        e=sample('pending-1')
        self.assertError(lambda:auto.process(e),503)
        self.assertEqual(auto.pending()['pending_event_ids'],['pending-1'])
        result=auto.retry_pending({'event_id':'pending-1'})
        self.assertEqual(result['execution'],'mock_applied')
        self.assertEqual(auto.pending()['pending_event_ids'],[])

    def test_15_dry_run_does_not_mutate(self):
        auto=Automation(self.policy,Path(self.folder.name)/'dry.db',MockAI().predict,self.fw.block,dry_run=True)
        self.addCleanup(auto.conn.close)
        result=auto.process(sample('dry-1'))
        self.assertEqual(result['execution'],'dry_run')
        self.assertEqual(self.fw.blocks()['blocks'],[])

    def test_16_wazuh_mitre_metadata_and_time(self):
        a={'id':'123','timestamp':'2026-10-20T10:00:00Z','rule':{'id':'5712','level':10,'description':'SSH brute force',
            'mitre':{'id':['T1110'],'tactic':['Credential Access']}},'data':{'srcip':'198.51.100.12'}}
        e=bridge.build_event_from_wazuh(a)
        self.assertEqual(e['mitre']['technique_ids'],['T1110'])
        self.assertEqual(e['timestamp'],'2026-10-20T10:00:00+00:00')
        self.assertEqual(e['quality']['counters'],'unknown')
        self.assertIsNone(e['features']['failed_logins_60s'])

    def test_17_wazuh_level_filter(self):
        a={'id':'123','rule':{'id':'1234','level':2},'data':{'srcip':'198.51.100.12'}}
        self.assertIsNone(bridge.build_event_from_wazuh(a))

    def test_18_suricata_same_flow_unique_event_ids(self):
        a={'event_type':'alert','timestamp':'2026-10-22T10:00:00Z','src_ip':'198.51.100.13',
           'dest_ip':'10.0.30.20','flow_id':10,'alert':{'signature_id':1,'signature':'port scan','severity':1}}
        b=json.loads(json.dumps(a));b['alert']['signature_id']=2
        self.assertNotEqual(bridge.build_event_from_suricata(a)['event_id'],
                            bridge.build_event_from_suricata(b)['event_id'])

    def test_19_curated_mapping_proposed_not_validated(self):
        m=load_mappings(ROOT/'config'/'detection_mappings.json')
        a={'rule':{'id':'5712'}}
        self.assertEqual(from_wazuh(a,m)['validation_status'],'proposed')
        self.assertEqual(from_suricata({'alert':{'signature_id':999}},m)['technique_ids'],[])

    def test_20_outbox_persist_and_retry(self):
        path=Path(self.folder.name)/'outbox.db'
        ob=Outbox(path); e=sample('out-1')
        ob.accept('/tmp/a',12,100,e)
        self.assertEqual(ob.cursor('/tmp/a',12),100)
        self.assertEqual(len(ob.due()),1)
        ob.set_result('out-1',{'decision':'OBSERVE'})
        ob.defer('out-1','ES unavailable')
        self.assertEqual(ob.counts()['queued'],1)
        ob.conn.close()
        ob2=Outbox(path);self.addCleanup(ob2.conn.close)
        self.assertEqual(ob2.counts()['queued'],1)
        ob2.complete('out-1');self.assertEqual(ob2.counts()['queued'],0)

    def test_21_opnsense_fake_transport_verify_and_expire(self):
        ips=set();actions=[];clock=[time.time()]
        def transport(method,action,payload=None):
            actions.append((method,action))
            if action=='list':return {'rows':[{'ip':x} for x in sorted(ips)]}
            if action=='add':ips.add(payload['address']);return {'status':'done'}
            if action=='delete':ips.discard(payload['address']);return {'status':'done'}
            raise AssertionError(action)
        fw=OPNsenseFirewall(self.policy,Path(self.folder.name)/'opn.db','https://fw.example','SOC_AUTO_BLOCK',
                           'dummy-key','dummy-secret',clock=lambda:clock[0],transport=transport)
        self.addCleanup(fw.conn.close)
        result=fw.block({'request_id':'test-1','ip':'198.51.100.23','ttl_seconds':3})
        self.assertTrue(result['alias_verified']);self.assertFalse(result['network_verified'])
        self.assertEqual(result['status'],'alias_verified')
        self.assertEqual(len(ips),1)
        self.assertTrue(fw.block({'request_id':'test-1','ip':'198.51.100.23','ttl_seconds':3})['replayed'])
        clock[0]+=4;fw.expire();self.assertEqual(ips,set())
        self.assertIn(('POST','delete'),actions)

    def test_22_opnsense_does_not_unblock_unmanaged_alias(self):
        ips={'198.51.100.23'}
        def transport(method,action,payload=None):
            if action=='list':return {'rows':[{'ip':x} for x in ips]}
            raise AssertionError('Should never mutate unmanaged alias')
        fw=OPNsenseFirewall(self.policy,Path(self.folder.name)/'notown.db','https://fw.example','SOC_AUTO_BLOCK',
                           'dummy-key','dummy-secret',transport=transport)
        self.addCleanup(fw.conn.close)
        result=fw.block({'request_id':'test-2','ip':'198.51.100.23','ttl_seconds':5})
        self.assertFalse(result['managed_by_controller'])
        self.assertError(lambda:fw.unblock({'ip':'198.51.100.23'}),403)

    def test_23_real_ai_calibration_contract(self):
        path=Path(self.folder.name)/'cal.json'
        path.write_text(json.dumps({'model_version':'iforest-abcd','calibration_version':'val-v1',
                                    'validation_normal_scores':[i/100 for i in range(20)]}))
        holder={}
        def transport(payload):
            holder.update(payload)
            return {'event_id':payload['event_id'],'model_version':'iforest-abcd',
                    'raw_anomaly_score':0.15,'score_semantics':'higher_is_more_anomalous_raw'}
        ai=RealAI('http://127.0.0.1:8500',path,transport=transport)
        e=event(sample('real-1'));e['quality']={'counters':'observed','timestamp':'source'}
        result=ai.predict(e)
        self.assertEqual(result['anomaly_score'],0.8)
        self.assertEqual(holder['failed_count'],30)
        self.assertFalse(result['is_mock'])

    def test_24_real_ai_missing_data_refused(self):
        path=Path(self.folder.name)/'cal2.json'
        path.write_text(json.dumps({'model_version':'iforest-abcd','calibration_version':'val-v1',
                                    'validation_normal_scores':[i/100 for i in range(20)]}))
        ai=RealAI('http://127.0.0.1:8500',path,transport=lambda p:None)
        e=event(sample('real-2'))
        self.assertError(lambda:ai.predict(e),422)

    def test_25_live_requires_explicit_opt_in(self):
        with patch.dict(os.environ,{'SOC_FIREWALL_MODE':'opnsense','SOC_AI_MODE':'mock',
                                    'SOC_ENABLE_LIVE':'false'},clear=False):
            with self.assertRaises(ValueError):make_app('automation',self.policy,Path(self.folder.name)/'guard')

    def test_26_http_role_separation(self):
        auto=Automation(self.policy,Path(self.folder.name)/'http.db',MockAI().predict,self.fw.block,
                        dry_run=False,approval_mode='manual')
        self.addCleanup(auto.conn.close)
        server=make_server('automation',auto,port=0,token='demo-automation-token')
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.05},daemon=True)
        thread.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join()))
        url=f'http://127.0.0.1:{server.server_port}'
        self.assertEqual(http_json(url+'/events',sample('http-1'),'demo-automation-token')['reason'],'approval_required')
        self.assertError(lambda:http_json(url+'/reviews',token='demo-automation-token'),502)
        self.assertEqual(len(http_json(url+'/reviews',token='demo-approver-token')['reviews']),1)
        result=http_json(url+'/approve',{'event_id':'http-1','actor':'Analyst','approve':True,
                                        'reason':'controlled mock test'},'demo-approver-token')
        self.assertEqual(result['execution'],'mock_applied')

    def test_27_live_must_not_block_test_source(self):
        calls=[]
        def predict(e):
            return {'event_id':e['event_id'],'anomaly_score':0.99,'model_version':'iforest-validated',
                    'calibration_version':'val-v1','score_semantics':'higher_is_more_anomalous_0_1',
                    'is_mock':False}
        auto=Automation(self.policy,Path(self.folder.name)/'live-guard.db',predict,
                        lambda action:calls.append(action),dry_run=False,firewall_mode='opnsense',
                        approval_mode='manual',ai_mode='real')
        self.addCleanup(auto.conn.close)
        e=sample('source-test-1')
        e['quality']={'counters':'observed','timestamp':'source'}
        result=auto.process(e)
        self.assertEqual(result['decision'],'REVIEW')
        self.assertEqual(result['reason'],'unverified_source_or_model_for_live')
        self.assertEqual(calls,[])

    def test_28_bridge_outbox_delivery_metadata(self):
        outbox=Outbox(Path(self.folder.name)/'bridge-flow.db')
        self.addCleanup(outbox.conn.close)
        e=sample('mitre-flow')
        outbox.accept('/tmp/test',3,45,e)
        seen=[]
        with patch.object(bridge,'send_to_automation',side_effect=lambda v:{'decision':'REVIEW','event_id':v['event_id']}),\
             patch.object(bridge,'save_to_elasticsearch',side_effect=lambda ev,result:seen.append((ev,result)) or True):
            count=bridge.drain_outbox(outbox)
        self.assertEqual(count,1)
        self.assertEqual(seen[0][0]['mitre']['technique_ids'],['T1110'])
        self.assertEqual(outbox.counts()['queued'],0)

    def test_29_circuit_breaker(self):
        from soclab.resilience import CircuitBreaker
        now=[0.0]
        b=CircuitBreaker(threshold=2,cooldown=10,clock=lambda:now[0])
        def fail():raise APIError(503,'upstream down')
        self.assertError(lambda:b.call(fail),503)
        self.assertError(lambda:b.call(fail),503)
        self.assertError(lambda:b.call(lambda:'ok'),503)
        now[0]=11
        self.assertEqual(b.call(lambda:'ok'),'ok')

    def test_30_alias_pagination_fails_closed(self):
        def transport(method,action,payload=None):
            return {'rows':[{'ip':'198.51.100.100'}],'total':300}
        fw=OPNsenseFirewall(self.policy,Path(self.folder.name)/'paged.db','https://fw.example','SOC_AUTO_BLOCK',
                           'dummy-key','dummy-secret',transport=transport)
        self.addCleanup(fw.conn.close)
        self.assertError(lambda:fw.block({'request_id':'p','ip':'198.51.100.23','ttl_seconds':5}),502)

    def test_31_outbox_collision_deadletter(self):
        outbox=Outbox(Path(self.folder.name)/'collision.db')
        self.addCleanup(outbox.conn.close)
        e=sample('same-id')
        outbox.accept('/tmp/x',1,12,e)
        e2=json.loads(json.dumps(e));e2['severity']=13
        outbox.accept('/tmp/x',1,23,e2)
        self.assertEqual(outbox.counts()['deadletter'],1)
        self.assertEqual(outbox.counts()['queued'],1)

if __name__=='__main__':unittest.main()
