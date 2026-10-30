"""Contract adapter for Minh's real IsolationForest API, requiring independent calibration.
No calibration -> no live score -> Automation must stay in REVIEW.
"""
from bisect import bisect_right
import json
from pathlib import Path
from .common import APIError, http_json

class RealAI:
    def __init__(self, base_url, calibration_file, token=None, transport=None):
        data=json.loads(Path(calibration_file).read_text(encoding='utf-8'))
        self.version=data.get('model_version')
        self.calibration_version=data.get('calibration_version')
        scores=data.get('validation_normal_scores')
        if (not isinstance(self.version,str) or not self.version or
            not isinstance(self.calibration_version,str) or not self.calibration_version or
            not isinstance(scores,list) or len(scores)<20 or
            any(type(x) not in (int,float) for x in scores) or sorted(scores)!=scores):
            raise ValueError('Real AI requires a sorted independent validation score calibration (>=20 values)')
        self.scores=scores
        self.url=base_url.rstrip('/')+'/predict'
        self.token=token
        self.transport=transport or (lambda req:http_json(self.url,req,self.token))

    def predict(self, e):
        f=e['features']
        if e.get('quality',{}).get('counters')!='observed' or any(x is None for x in f.values()):
            raise APIError(422,'Unverified real feature counters; use REVIEW')
        # Explicit translation between Automation's event schema and Minh's FastAPI.
        if not e.get('dst_ip') or e.get('dst_port') is None:
            raise APIError(422,'Real inference requires observed dst_ip and dst_port')
        et={'brute_force':'authentication_failed','auth_failure':'authentication_failed'}.get(e['event_type'],e['event_type'])
        payload={'event_id':e['event_id'],'src_ip':e['src_ip'],'dst_ip':e['dst_ip'],
                 'src_port':e.get('src_port') or 0,'dst_port':e.get('dst_port'),
                 'protocol':e.get('protocol','TCP'), 'event_type':et,
                 'failed_count':f['failed_logins_60s'], 'bytes':e.get('bytes') or 0,
                 'timestamp':e['timestamp']}
        result=self.transport(payload)
        if not isinstance(result,dict) or result.get('event_id')!=e['event_id']:
            raise APIError(502,'Real AI response event mismatch')
        if result.get('model_version')!=self.version or result.get('score_semantics')!='higher_is_more_anomalous_raw':
            raise APIError(502,'Real model version/score semantics mismatch')
        raw=result.get('raw_anomaly_score')
        if type(raw) not in (int,float): raise APIError(502,'Raw score missing')
        import math
        if not math.isfinite(raw): raise APIError(502,'Raw score not finite')
        # Rank of raw anomaly score among NORMAL validation scores.
        # This is an empirical percentile, not P(attack|event).
        pct=bisect_right(self.scores,raw)/len(self.scores)
        return {'event_id':e['event_id'],'anomaly_score':round(pct,6),
                'score_semantics':'higher_is_more_anomalous_0_1',
                'raw_anomaly_score':raw,'model_version':self.version,
                'calibration_version':self.calibration_version,'is_mock':False}
