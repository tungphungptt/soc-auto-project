"""Compute verified coverage from reviewed test records, not from declarations alone."""
import argparse
import json
from pathlib import Path


def main():
    p=argparse.ArgumentParser()
    p.add_argument('test_results_jsonl',help='JSON Lines: {event_id, mitre:{technique_ids}, validation_status:"tested", passed:true}')
    args=p.parse_args()
    planned=set();verified=set();evidence={}
    for line in Path(args.test_results_jsonl).read_text(encoding='utf-8').splitlines():
        if not line.strip():continue
        row=json.loads(line)
        for technique in row.get('mitre',{}).get('technique_ids',[]):
            planned.add(technique)
            if row.get('validation_status')=='tested' and row.get('passed') is True and row.get('evidence_id'):
                verified.add(technique)
                evidence.setdefault(technique,[]).append(row['evidence_id'])
    print(json.dumps({'declared':len(planned),'verified':len(verified),
                      'verified_percent':round(100*len(verified)/len(planned),2) if planned else None,
                      'verified_evidence':evidence},indent=2))

if __name__=='__main__':main()
