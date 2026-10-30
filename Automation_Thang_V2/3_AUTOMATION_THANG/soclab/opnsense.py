"""Guarded OPNsense alias adapter, disabled by default, no operating-system commands.
Aliasing a host does NOT by itself prove that its traffic is blocked.
"""
import base64
import ipaddress
import json
import re
import ssl
import threading
import time
from urllib import request, parse, error
from .common import APIError, canonical, db, digest, ip, number, NoRedirect

ALIAS_RE=re.compile(r'[A-Za-z][A-Za-z0-9_]{0,63}\Z')

class OPNsenseFirewall:
    def __init__(self, policy, path, base_url, alias, key, secret, ca_file=None, clock=time.time, transport=None):
        self.policy,self.clock=policy,clock
        if not base_url.startswith('https://') or not base_url.rstrip('/').split('://')[1] or not ALIAS_RE.fullmatch(alias):
            raise ValueError('HTTPS base URL and an approved named alias are required')
        if not key or not secret:raise ValueError('Least-privilege OPNsense API key and secret required')
        self.base=base_url.rstrip('/')
        self.alias=alias
        self.auth=base64.b64encode((key+':'+secret).encode()).decode()
        self.context=ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        self.transport=transport or self._http
        self.conn,self.lock=db(path),threading.RLock()
        self.conn.executescript("""            CREATE TABLE IF NOT EXISTS managed_blocks(ip TEXT PRIMARY KEY, expires_at REAL, request_id TEXT);
            CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,fingerprint TEXT,response TEXT);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,time REAL,action TEXT,ip TEXT,details TEXT);
        """)

    def _http(self,method,path,payload=None):
        # Absolute preconfigured firewall endpoint; do not accept user-controlled URL paths.
        url=self.base+'/api/firewall/alias_util/'+path+'/'+parse.quote(self.alias,safe='')
        hdr={'Authorization':'Basic '+self.auth,'Content-Type':'application/json'}
        body=None if payload is None else canonical(payload).encode()
        req=request.Request(url,data=body,headers=hdr,method=method)
        opener=request.build_opener(request.ProxyHandler({}),NoRedirect(),request.HTTPSHandler(context=self.context))
        try:
            with opener.open(req,timeout=5) as res:
                raw=res.read(65537)
                if len(raw)>65536: raise APIError(502,'OPNsense response too large')
                return json.loads(raw)
        except (error.URLError,TimeoutError,OSError,ValueError) as exc:
            raise APIError(503,'OPNsense API unavailable/invalid response') from exc

    def _members(self):
        raw=self.transport('GET','list')
        # OPNsense alias_util/list uses a searchRecordset (rows/items).
        if not isinstance(raw,dict):raise APIError(502,'Alias list response not an object')
        rows=raw.get('rows',raw.get('items'))
        if not isinstance(rows,list):raise APIError(502,'Unknown alias list response schema')
        total=raw.get('total')
        if isinstance(total,int) and total>len(rows):
            raise APIError(502,'OPNsense alias list is paginated; refuse incomplete verification')
        members=set()
        for row in rows:
            if isinstance(row,str):value=row
            elif isinstance(row,dict):value=row.get('ip',row.get('address'))
            else:value=None
            if isinstance(value,str):
                try: members.add(str(ipaddress.ip_interface(value).ip))
                except ValueError: continue
        return members

    def _audit(self,action,address,details=''):
        self.conn.execute('INSERT INTO audit(time,action,ip,details) VALUES(?,?,?,?)',
                          (self.clock(),action,address,details[:200]))

    def block(self,raw):
        if not isinstance(raw,dict) or set(raw)!={'request_id','ip','ttl_seconds'}:
            raise APIError(422,'Expected request_id, ip and ttl_seconds')
        address=ip(raw['ip'])
        ttl=number(raw['ttl_seconds'],'TTL',1,self.policy.ttl,True)
        rid=raw['request_id']
        if not isinstance(rid,str) or not 1<=len(rid)<=128:raise APIError(422,'Invalid request_id')
        if guard:=self.policy.guard(address):raise APIError(403,guard)
        fingerprint=digest({'ip':address,'ttl':ttl})
        with self.lock,self.conn:
            previous=self.conn.execute('SELECT fingerprint,response FROM requests WHERE id=?',(rid,)).fetchone()
            if previous:
                if previous[0]!=fingerprint:raise APIError(409,'Changed request with same ID')
                return dict(json.loads(previous[1]),replayed=True)
            members=self._members()
            owned=self.conn.execute('SELECT expires_at FROM managed_blocks WHERE ip=?',(address,)).fetchone()
            if address in members:
                # Never claim ownership of a pre-existing alias entry.
                exp=owned[0] if owned else self.clock()+ttl
                status='already_blocked_managed' if owned else 'already_blocked_unmanaged'
            elif owned:
                # Restore our own nonexpired lease after firewall reload/reboot.
                response=self.transport('POST','add',{'address':address})
                if not isinstance(response,dict) or response.get('status')!='done' or address not in self._members():
                    raise APIError(503,'Cannot restore managed alias; manual investigation required')
                exp=owned[0]
                self._audit('RESTORE_ALIAS',address,'existing lease restored without TTL extension')
                status='alias_restored'
            else:
                count=self.conn.execute('SELECT COUNT(*) FROM managed_blocks').fetchone()[0]
                if count>=self.policy.data['max_active_blocks']:raise APIError(429,'Maximum active blocks')
                response=self.transport('POST','add',{'address':address})
                if not isinstance(response,dict) or response.get('status')!='done':
                    raise APIError(502,'Alias add response not done')
                if address not in self._members():
                    raise APIError(503,'Alias update not yet visible; check firewall state manually')
                exp=self.clock()+ttl
                self.conn.execute('INSERT INTO managed_blocks VALUES(?,?,?)',(address,exp,rid))
                self._audit('ADD_ALIAS',address,'alias verified, traffic unverified')
                status='alias_verified'
            output={'mode':'opnsense','status':status,'ip':address,'request_id':rid,
                    'expires_at':exp,'alias_verified':True,'network_verified':False,
                    'managed_by_controller':status!='already_blocked_unmanaged'}
            self.conn.execute('INSERT INTO requests VALUES(?,?,?)',(rid,fingerprint,canonical(output)))
            return output

    def unblock(self,raw):
        if not isinstance(raw,dict) or set(raw)!={'ip'}:raise APIError(422,'Expected ip only')
        address=ip(raw['ip'])
        with self.lock,self.conn:
            owned=self.conn.execute('SELECT ip FROM managed_blocks WHERE ip=?',(address,)).fetchone()
            if not owned:raise APIError(403,'Cannot remove unowned/pre-existing firewall alias entry')
            response=self.transport('POST','delete',{'address':address})
            if not isinstance(response,dict) or response.get('status')!='done':
                raise APIError(502,'Alias removal did not succeed')
            if address in self._members():raise APIError(503,'Alias removal unverified')
            self.conn.execute('DELETE FROM managed_blocks WHERE ip=?',(address,))
            self._audit('REMOVE_ALIAS',address,'alias removal verified, traffic unverified')
        return {'mode':'opnsense','status':'unblocked','ip':address,'alias_verified':True,'network_verified':False}

    def expire(self):
        with self.lock:
            expired=self.conn.execute('SELECT ip FROM managed_blocks WHERE expires_at<=?',(self.clock(),)).fetchall()
            active=self.conn.execute('SELECT ip FROM managed_blocks WHERE expires_at>?',(self.clock(),)).fetchall()
        for (address,) in expired:
            try: self.unblock({'ip':address})
            except APIError as exc:
                with self.lock,self.conn:self._audit('EXPIRY_RETRY',address,exc.message)
        # Non-expired entries are rechecked after restart; no new ownership is claimed.
        for (address,) in active:
            try:
                with self.lock:
                    if address in self._members():continue
                    answer=self.transport('POST','add',{'address':address})
                    if not isinstance(answer,dict) or answer.get('status')!='done' or address not in self._members():
                        raise APIError(503,'Active alias lease restore failed')
                    with self.conn:self._audit('RESTORE_ALIAS',address,'periodic lease reconcile')
            except APIError as exc:
                with self.lock,self.conn:self._audit('RECONCILE_RETRY',address,exc.message)

    def blocks(self):
        with self.lock:
            rows=self.conn.execute('SELECT ip,expires_at FROM managed_blocks ORDER BY ip').fetchall()
        return {'mode':'opnsense','blocks':[{'ip':x,'expires_at':t} for x,t in rows],
                'note':'alias status only; does not verify traffic'}
