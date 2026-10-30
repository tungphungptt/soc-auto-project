"""Build a non-probabilistic percentile calibration from *independent* normal validation data.

Run only after creating a proper validation split without leakage. Do not include
this file as a claimed benchmark until an independently held-out set exists.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sys


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--ai-dir',required=True,help='Path to 2_AI_MINH')
    p.add_argument('--validation-jsonl',required=True)
    p.add_argument('--output',required=True)
    p.add_argument('--confirm-independent-split',action='store_true',required=True)
    args=p.parse_args()
    aid=Path(args.ai_dir).resolve()
    sys.path.insert(0,str(aid))
    from src.config import BEST_MODEL_PATH,MODEL_PATH
    from src.predict import predict_one,load_model
    path=BEST_MODEL_PATH if BEST_MODEL_PATH.exists() else MODEL_PATH
    version='iforest-'+hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    records=Path(args.validation_jsonl).read_bytes()
    dataset_hash=hashlib.sha256(records).hexdigest()
    model=load_model()
    scores=[]
    for line in records.splitlines():
        if not line.strip():continue
        obj=json.loads(line)
        is_anomaly=obj.get('is_anomaly_ground_truth')
        if is_anomaly not in (False,0): continue
        scores.append(float(predict_one(obj,artifacts=model)['anomaly_score']))
    if len(scores)<20:raise ValueError('Need >=20 independent NORMAL validation events')
    result={'model_version':version,'calibration_version':'val-cdf-'+dataset_hash[:12],
            'validation_sha256':dataset_hash,'validation_n_normal':len(scores),
            'validation_normal_scores':sorted(scores),
            'score_meaning':'empirical normal-reference percentile; NOT attack probability',
            'generated_at':datetime.now(timezone.utc).isoformat()}
    dest=Path(args.output);dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(f'Calibration written: {dest} (model={version}, normal_samples={len(scores)})')

if __name__=='__main__':main()
