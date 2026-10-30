"""Versioned policy orchestrator; separate decision, approval and action evidence.

Default is MOCK. OPNSense actions only when an explicit live-approved application
injects the real firewall adapter. No MITRE ID is used as authority to block.
"""
import json
import threading
import time
from datetime import datetime
from .common import APIError, canonical, db, digest, number
from .schema import event, prediction
from .resilience import CircuitBreaker


class Automation:
    def __init__(self, policy, path, predict, block, dry_run=True, clock=time.time,
                 firewall_mode='mock', approval_mode=None, ai_mode='mock'):
        self.policy, self.predict, self.block = policy, predict, block
        self.clock, self.dry_run = clock, dry_run
        self.ai_breaker=CircuitBreaker()
        self.firewall_breaker=CircuitBreaker()
        self.firewall_mode, self.ai_mode = firewall_mode, ai_mode
        self.approval_mode = approval_mode or policy.data.get('approval_mode', 'auto')
        if self.approval_mode not in ('manual', 'auto'):
            raise ValueError('Invalid approval mode')
        self.conn, self.lock = db(path), threading.RLock()
        self.conn.executescript('''
            CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, fingerprint TEXT, response TEXT);
            CREATE TABLE IF NOT EXISTS pending(id TEXT PRIMARY KEY, fingerprint TEXT, decision TEXT,
                                               request TEXT, raw_event TEXT);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, time REAL, event_id TEXT, body TEXT);
            CREATE TABLE IF NOT EXISTS reviews(id TEXT PRIMARY KEY, fingerprint TEXT, raw_event TEXT,
                predecision TEXT, status TEXT NOT NULL, actor TEXT, reason TEXT, updated REAL);
        ''')
        cols={r[1] for r in self.conn.execute('PRAGMA table_info(pending)').fetchall()}
        if 'raw_event' not in cols:
            self.conn.execute('ALTER TABLE pending ADD COLUMN raw_event TEXT')

    def _audit(self, eid, value):
        with self.conn:
            self.conn.execute('INSERT INTO audit(time,event_id,body) VALUES(?,?,?)',
                              (self.clock(), eid, canonical(value)))

    def _save_result(self, eid, fingerprint, result):
        with self.conn:
            self.conn.execute('INSERT OR REPLACE INTO events VALUES(?,?,?)',
                              (eid, fingerprint, canonical(result)))
            self.conn.execute('DELETE FROM pending WHERE id=?', (eid,))
            self.conn.execute('INSERT INTO audit(time,event_id,body) VALUES(?,?,?)',
                              (self.clock(), eid, canonical(result)))

    def _action(self, e):
        return {'request_id':'soc-'+digest({'event':e,'policy':self.policy.data['version']}),
                'ip':e['src_ip'], 'ttl_seconds':self.policy.ttl}

    def _apply(self, result, action):
        ack=self.firewall_breaker.call(lambda:self.block(action))
        statuses = {'mock':('blocked','already_blocked'),
                    'opnsense':('alias_verified','alias_restored','already_blocked_managed','already_blocked_unmanaged')}
        if (not isinstance(ack,dict) or ack.get('mode') != self.firewall_mode
            or ack.get('ip')!=action['ip'] or ack.get('request_id')!=action['request_id']
            or ack.get('status') not in statuses[self.firewall_mode]):
            raise APIError(502, 'Firewall acknowledgement mismatch')
        try:
            number(ack.get('expires_at'), 'expires_at', 0, 1e12)
        except APIError as exc:
            raise APIError(502, 'Firewall expiry invalid') from exc
        execution = ('mock_applied' if ack['expires_at']>self.clock() else 'mock_expired') if self.firewall_mode=='mock' else 'opnsense_alias_verified_traffic_unverified'
        result.update(execution=execution, firewall=ack)
        return result

    def process(self, raw):
        e=event(raw)
        fingerprint, eid=digest(e), e['event_id']
        with self.lock:
            prior=self.conn.execute('SELECT fingerprint,response FROM events WHERE id=?',(eid,)).fetchone()
            if prior:
                if prior[0]!=fingerprint:raise APIError(409,'event_id reused with different content')
                return dict(json.loads(prior[1]),replayed=True)
            pending=self.conn.execute('SELECT fingerprint,decision,request FROM pending WHERE id=?',(eid,)).fetchone()
            if pending and pending[0]!=fingerprint:raise APIError(409,'Pending event_id reused with different content')
            age=self.clock()-datetime.fromisoformat(e['timestamp']).timestamp()
            if age>self.policy.data['max_event_age_seconds'] or age < -self.policy.data['max_future_skew_seconds']:
                self._audit(eid,{'decision':'REJECT','reason':'stale_or_future_event'})
                raise APIError(422,'Event outside time window; no new block issued')
            if pending:
                result,action=json.loads(pending[1]),json.loads(pending[2])
                guard=self.policy.guard(e['src_ip'])
                if guard or result['policy_version']!=self.policy.data['version'] or self.dry_run:
                    result.update(decision='REVIEW',reason=guard or 'policy_changed_or_dry_run_while_pending',execution='none')
                    self._save_result(eid,fingerprint,result)
                    return result
            else:
                # Any invalid/missing AI inference must fail safe; no invented benign score.
                try:
                    ai=prediction(self.ai_breaker.call(lambda:self.predict(e)),eid)
                except (APIError, TimeoutError, OSError, ValueError) as exc:
                    result={'event_id':eid, 'decision':'REVIEW', 'reason':'ai_unavailable_or_invalid',
                            'error_type':type(exc).__name__, 'risk_score':None,'anomaly_score':None,
                            'model_version':None,'policy_version':self.policy.data['version'],
                            'src_ip':e['src_ip'],'execution':'none','mode':self.firewall_mode,
                            'replayed':False,'mitre':e['mitre'],'rule_id':e.get('rule_id'),
                            'event_uid':e.get('event_uid',eid),'processed_at':self.clock()}
                    self._save_result(eid,fingerprint,result)
                    return result
                result=self.policy.decide(e,ai['anomaly_score'])
                if self.firewall_mode == 'opnsense' and result['decision']=='BLOCK':
                    if e['source']=='test' or ai.get('is_mock',False) or e['quality']['counters']!='observed' or e['quality']['timestamp']!='source':
                        result.update(decision='REVIEW',reason='unverified_source_or_model_for_live')
                result.update(event_id=eid, model_version=ai['model_version'],
                              calibration_version=ai.get('calibration_version'),
                              raw_anomaly_score=ai.get('raw_anomaly_score'),
                              replayed=False, execution='none', mode=self.firewall_mode,
                              ai_mode=self.ai_mode, mitre=e['mitre'], rule_id=e.get('rule_id'),
                              event_uid=e.get('event_uid',eid), processed_at=self.clock())
                action=self._action(e)
                result['action_id']=action['request_id'] if result['decision']=='BLOCK' else None
                if result['decision']=='BLOCK' and self.approval_mode=='manual' and not self.dry_run:
                    result.update(decision='REVIEW',reason='approval_required',approval_status='pending')
                    with self.conn:
                        self.conn.execute('INSERT INTO reviews VALUES(?,?,?,?,?,?,?,?)',
                                          (eid,fingerprint,canonical(e),canonical(result),'pending',None,None,self.clock()))
                    self._save_result(eid,fingerprint,result)
                    return result
                if result['decision']=='BLOCK':
                    result['execution']='dry_run' if self.dry_run else 'pending'
                if result['execution']=='pending':
                    with self.conn:
                        self.conn.execute('INSERT INTO pending VALUES(?,?,?,?,?)',
                                          (eid,fingerprint,canonical(result),canonical(action),canonical(e)))
            try:
                if result['decision']=='BLOCK' and result['execution']=='pending':
                    result=self._apply(result,action)
                self._save_result(eid,fingerprint,result)
                return result
            except (APIError,TimeoutError,OSError) as exc:
                # Keep pending request with SAME request_id, so operator can reconcile safely.
                self._audit(eid,{'decision':'ERROR','reason':str(exc)[:160],
                                 'execution':'unknown_if_request_reached_firewall',
                                 'rule_id':e.get('rule_id'),'mitre':e['mitre']})
                raise

    def reviews(self):
        with self.lock:
            rows=self.conn.execute("SELECT id,raw_event,predecision,updated FROM reviews WHERE status='pending' ORDER BY updated").fetchall()
        return {'reviews':[{'event_id':eid,'event':json.loads(raw), 'decision':json.loads(dec),
                            'created_at':ts} for eid,raw,dec,ts in rows]}

    def approve(self, raw):
        if not isinstance(raw,dict) or set(raw)!={'event_id','actor','approve','reason'}:
            raise APIError(422,'Expected event_id,actor,approve,reason')
        eid,actor,ok,reason=(raw[x] for x in ('event_id','actor','approve','reason'))
        if not isinstance(eid,str) or not 1<=len(eid)<=128 or not isinstance(actor,str) or not 1<=len(actor)<=100:
            raise APIError(422,'Invalid actor/event_id')
        if type(ok) is not bool or not isinstance(reason,str) or not 1<=len(reason)<=300:
            raise APIError(422,'Approval must be explicit with reason')
        with self.lock:
            row=self.conn.execute('SELECT fingerprint,raw_event,predecision,status FROM reviews WHERE id=?',(eid,)).fetchone()
            if not row: raise APIError(404,'Review not found')
            fingerprint,raw_event,predecision,status=row
            if status!='pending': raise APIError(409,'Review already finalized')
            e=event(json.loads(raw_event))
            result=json.loads(predecision)
            age=self.clock()-datetime.fromisoformat(e['timestamp']).timestamp()
            if not ok or age>self.policy.data['max_event_age_seconds'] or self.policy.guard(e['src_ip']) or self.dry_run:
                status='rejected' if not ok else 'expired_or_unsafe'
                result.update(decision='REVIEW',reason=status,approval_status=status,
                              approved_by=actor,approval_reason=reason,execution='none')
                with self.conn:self.conn.execute('UPDATE reviews SET status=?,actor=?,reason=?,updated=? WHERE id=?',
                                                  (status,actor,reason,self.clock(),eid))
                self._save_result(eid,fingerprint,result)
                return result
            if result.get('policy_version')!=self.policy.data['version']:
                raise APIError(409,'Policy changed; approval cannot execute old decision')
            action=self._action(e)
            try:
                result.update(decision='BLOCK',reason='approved_by_operator',approval_status='approved',
                              approved_by=actor,approval_reason=reason,execution='pending')
                with self.conn:
                    self.conn.execute('INSERT OR REPLACE INTO pending VALUES(?,?,?,?,?)',
                                      (eid,fingerprint,canonical(result),canonical(action),canonical(e)))
                result=self._apply(result,action)
            except (APIError,TimeoutError,OSError) as exc:
                self._audit(eid,{'decision':'ERROR','reason':'approval_dispatch_failed','actor':actor})
                # Keep review pending and pending request: repeated approval uses same request_id.
                raise
            with self.conn:
                self.conn.execute('UPDATE reviews SET status=?,actor=?,reason=?,updated=? WHERE id=?',
                                  ('approved',actor,reason,self.clock(),eid))
            self._save_result(eid,fingerprint,result)
            return result

    def pending(self):
        with self.lock:
            rows=self.conn.execute('SELECT id FROM pending ORDER BY id').fetchall()
        return {'pending_event_ids':[x[0] for x in rows]}

    def retry_pending(self,raw):
        if not isinstance(raw,dict) or set(raw)!={'event_id'} or not isinstance(raw['event_id'],str):
            raise APIError(422,'Expected event_id')
        with self.lock:
            row=self.conn.execute('SELECT raw_event FROM pending WHERE id=?',(raw['event_id'],)).fetchone()
            if not row or row[0] is None:raise APIError(404,'No retriable pending event')
            # Manually approved reviews must be retried by the operator via approval endpoint.
            review=self.conn.execute("SELECT status FROM reviews WHERE id=?",(raw['event_id'],)).fetchone()
            if review and review[0]=='pending':raise APIError(403,'Retry pending approval via approval endpoint')
        return self.process(json.loads(row[0]))

    def audit(self):
        with self.lock:
            rows=self.conn.execute('SELECT time,event_id,body FROM audit ORDER BY id DESC LIMIT 100').fetchall()
        return {'records':[{'time':t,'event_id':eid,**json.loads(body)} for t,eid,body in rows]}
