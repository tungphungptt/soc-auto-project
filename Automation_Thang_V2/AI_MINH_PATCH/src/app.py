from __future__ import annotations
"""Real raw-score FastAPI inference; no 0.95/0.05 replacement.

Requires external validation calibration before it can be used for blocking.
"""
import hashlib
import os
from contextlib import asynccontextmanager
from time import perf_counter
from typing import Optional
from fastapi import FastAPI,HTTPException,Request
from pydantic import BaseModel,Field
from src.config import EVALUATION_LOG_PATH,MODEL_PATH,BEST_MODEL_PATH
from src.predict import load_model,predict_one
from src.utils import setup_logger

logger=setup_logger('soc_auto.api',EVALUATION_LOG_PATH.parent/'api.log')
_artifacts=None
_model_version=None

class EventInput(BaseModel):
    event_id:str=Field(...,min_length=1,max_length=128)
    src_ip:str
    dst_ip:str
    src_port:int=Field(0,ge=0,le=65535)
    dst_port:int=Field(0,ge=0,le=65535)
    protocol:str='TCP'
    event_type:str='other'
    failed_count:int=Field(0,ge=0)
    bytes:float=Field(0.0,ge=0)
    timestamp:Optional[str]=None

@asynccontextmanager
async def lifespan(_:FastAPI):
    global _artifacts,_model_version
    path=BEST_MODEL_PATH if BEST_MODEL_PATH.exists() else MODEL_PATH
    try:
        _artifacts=load_model()
        _model_version='iforest-'+hashlib.sha256(path.read_bytes()).hexdigest()[:16]
        logger.info('model loaded, %s',_model_version)
    except (FileNotFoundError,ValueError,OSError) as exc:
        _artifacts=None
        logger.warning('model unavailable: %s',type(exc).__name__)
    yield

app=FastAPI(title='SOC Auto AI - real raw score',version='1.1',lifespan=lifespan)

@app.middleware('http')
async def log_requests(request:Request,call_next):
    t=perf_counter()
    try:
        secret=os.environ.get('SOC_REAL_AI_TOKEN')
        if secret and request.url.path=='/predict':
            import hmac
            if not hmac.compare_digest(request.headers.get('authorization',''), 'Bearer '+secret):
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=401,content={'error':'invalid token'})
        return await call_next(request)
    finally:
        logger.info('%s %s (%.2f ms)',request.method,request.url.path,(perf_counter()-t)*1000)

@app.get('/health')
def health()->dict:
    if _artifacts is None:raise HTTPException(status_code=503,detail='Model artifacts unavailable')
    return {'status':'ok','model':'IsolationForest','model_version':_model_version,
            'threshold_raw':float(_artifacts[3]),'score_semantics':'higher_is_more_anomalous_raw'}

@app.post('/predict')
def predict(e:EventInput)->dict:
    if _artifacts is None:raise HTTPException(status_code=503,detail='Model artifacts unavailable')
    try:
        result=predict_one(e.model_dump(),artifacts=_artifacts)
        raw=float(result['anomaly_score'])
        return {'event_id':e.event_id,'raw_anomaly_score':raw,
                'score_semantics':'higher_is_more_anomalous_raw',
                'model_version':_model_version,'is_anomaly':bool(result['is_anomaly']),
                'threshold_raw':float(result['threshold']),
                'is_mock':False}
    except Exception as exc:
        logger.exception('predict failed')
        raise HTTPException(status_code=500,detail='Prediction failed') from exc
