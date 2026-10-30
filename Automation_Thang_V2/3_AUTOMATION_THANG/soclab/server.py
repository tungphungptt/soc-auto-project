"""Minimal local lab API. Live mode is disabled unless explicitly enabled and approved."""
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .automation import Automation
from .common import APIError, canonical, http_json, load_policy
from .mock_ai import MockAI
from .mock_firewall import MockFirewall
from .opnsense import OPNsenseFirewall
from .ai_adapter import RealAI


def make_app(service, policy=None, data_dir=None, dry_run=None):
    policy=policy or load_policy()
    root=Path(data_dir or os.environ.get('SOC_DATA_DIR',str(Path(__file__).resolve().parents[1]/'data')))
    if service=='ai':return MockAI()
    if service=='firewall':return MockFirewall(policy,root/'firewall.sqlite3')
    if service!='automation':raise ValueError('Unknown service')
    fw_mode=os.environ.get('SOC_FIREWALL_MODE','mock')
    ai_mode=os.environ.get('SOC_AI_MODE','mock')
    if fw_mode not in ('mock','opnsense') or ai_mode not in ('mock','real'):
        raise ValueError('Invalid SOC_FIREWALL_MODE or SOC_AI_MODE')
    if dry_run is None:
        val=os.environ.get('SOC_DRY_RUN','true').lower()
        if val not in ('true','false'):raise ValueError('SOC_DRY_RUN must be true or false')
        dry_run=val=='true'
    ai_token=os.environ.get('SOC_AI_TOKEN','demo-ai-token')
    fw_token=os.environ.get('SOC_FIREWALL_TOKEN','demo-firewall-token')
    ai_url=os.environ.get('SOC_AI_URL','http://127.0.0.1:8001')
    fw_url=os.environ.get('SOC_FIREWALL_URL','http://127.0.0.1:8002')
    if ai_mode=='mock':predict=lambda e:http_json(ai_url+'/predict',e,ai_token)
    else:
        calibration=os.environ.get('SOC_AI_CALIBRATION')
        if not calibration:raise ValueError('SOC_AI_CALIBRATION is required for real AI')
        real_ai=RealAI(ai_url,calibration,token=os.environ.get('SOC_REAL_AI_TOKEN'))
        predict=real_ai.predict
    live_fw=None
    if fw_mode=='mock':block=lambda a:http_json(fw_url+'/block',a,fw_token)
    else:
        # Nothing can mutate a real firewall by accidentally setting SOC_DRY_RUN=false.
        if os.environ.get('SOC_ENABLE_LIVE')!='true' or os.environ.get('SOC_LIVE_CONFIRM')!='I_ACCEPT_REAL_FIREWALL_CHANGES':
            raise ValueError('Explicit live opt-in and confirmation are required')
        if ai_mode!='real' or policy.data.get('approval_mode')!='manual' or dry_run:
            raise ValueError('Live action requires real AI, manual approval and dry_run=false')
        if any('198.51.100.' in n or '192.0.2.' in n or '203.0.113.' in n for n in policy.data['auto_block_source_networks']):
            raise ValueError('Replace demonstration IP ranges with an approved live inventory')
        if any(os.environ.get(k,'').startswith('demo-') for k in ('SOC_AUTOMATION_TOKEN','SOC_APPROVER_TOKEN')):
            raise ValueError('Demo service tokens are forbidden in live mode')
        required=('SOC_OPNSENSE_URL','SOC_OPNSENSE_ALIAS','SOC_OPNSENSE_KEY','SOC_OPNSENSE_SECRET')
        if any(not os.environ.get(k) for k in required):raise ValueError('OPNsense integration credentials/config missing')
        live_fw=OPNsenseFirewall(policy,root/'opnsense.sqlite3',
                                  os.environ['SOC_OPNSENSE_URL'],os.environ['SOC_OPNSENSE_ALIAS'],
                                  os.environ['SOC_OPNSENSE_KEY'],os.environ['SOC_OPNSENSE_SECRET'],
                                  ca_file=os.environ.get('SOC_OPNSENSE_CA_FILE'))
        block=live_fw.block
    app=Automation(policy,root/'automation.sqlite3',predict,block,dry_run=dry_run,
                   firewall_mode=fw_mode,ai_mode=ai_mode)
    app.live_firewall=live_fw
    return app


def make_server(service,app,host='127.0.0.1',port=8000,token=None):
    token=token or os.environ.get('SOC_'+service.upper()+'_TOKEN','demo-'+service+'-token')
    approver=os.environ.get('SOC_APPROVER_TOKEN','demo-approver-token')
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_args):pass
        def setup(self):
            super().setup()
            self.connection.settimeout(5)
        def send(self,status,body):
            encoded=canonical(body).encode()
            self.send_response(status)
            self.send_header('Content-Type','application/json; charset=utf-8')
            self.send_header('Content-Length',str(len(encoded)))
            self.send_header('Connection','close')
            self.end_headers()
            self.wfile.write(encoded)
        def handle_api(self):
            try:
                if self.command=='GET' and self.path=='/health':
                    self.send(200,{'status':'ok','service':service,'mode':getattr(app,'firewall_mode','mock'),
                                   'note':'liveness only, not readiness or network proof'})
                    return
                actual=self.headers.get('Authorization','').encode()
                expected=approver if (service=='automation' and self.path in ('/reviews','/approve','/pending','/pending/retry','/firewall/blocks','/firewall/unblock')) else token
                if not hmac.compare_digest(actual,('Bearer '+expected).encode()):raise APIError(401,'Invalid service token')
                if self.command=='GET':
                    if service=='firewall' and self.path=='/blocks':answer=app.blocks()
                    elif service=='automation' and self.path=='/audit':answer=app.audit()
                    elif service=='automation' and self.path=='/reviews':answer=app.reviews()
                    elif service=='automation' and self.path=='/pending':answer=app.pending()
                    elif service=='automation' and self.path=='/firewall/blocks' and app.live_firewall:
                        answer=app.live_firewall.blocks()
                    else:raise APIError(404,'Unknown endpoint')
                elif self.command=='POST':
                    if self.headers.get('Transfer-Encoding'):raise APIError(400,'Transfer-Encoding unsupported')
                    try:size=int(self.headers.get('Content-Length','0'))
                    except ValueError as exc:raise APIError(400,'Invalid Content-Length') from exc
                    if not 0<size<=65536:raise APIError(413,'Body size must be 1..65536')
                    if self.headers.get('Content-Type','').split(';')[0]!='application/json':
                        raise APIError(415,'Use application/json')
                    try:raw=json.loads(self.rfile.read(size),parse_constant=lambda x:(_ for _ in ()).throw(ValueError(x)))
                    except (ValueError,UnicodeDecodeError) as exc:raise APIError(400,'Malformed JSON') from exc
                    routes={'ai':{'/predict':'predict'},'firewall':{'/block':'block','/unblock':'unblock'},
                            'automation':{'/events':'process','/approve':'approve','/pending/retry':'retry_pending'}}
                    if service=='automation' and self.path=='/firewall/unblock' and app.live_firewall:
                        answer=app.live_firewall.unblock(raw)
                    else:
                        method=routes[service].get(self.path)
                        if not method:raise APIError(404,'Unknown endpoint')
                        answer=getattr(app,method)(raw)
                else:raise APIError(405,'Unsupported method')
                self.send(200,answer)
            except APIError as exc:self.send(exc.status,{'error':exc.message,'service':service})
            except (TimeoutError,ConnectionError):self.close_connection=True
            except Exception:self.send(500,{'error':'Internal lab service error','service':service})
        do_GET=handle_api
        do_POST=handle_api
    class Server(ThreadingHTTPServer):
        daemon_threads=True
        _last_live_maintenance=0.0
        def service_actions(self):
            if service=='firewall':app.expire()
            if service=='automation' and getattr(app,'live_firewall',None):
                import time
                now=time.monotonic()
                if now-self._last_live_maintenance>=10:
                    self._last_live_maintenance=now
                    app.live_firewall.expire()
    return Server((host,port),Handler)
