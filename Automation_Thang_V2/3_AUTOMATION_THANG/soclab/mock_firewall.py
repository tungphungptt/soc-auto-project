import json
import threading
import time
from .common import APIError, canonical, db, digest, ip, number


class MockFirewall:
    """SQLite alias simulation only. No OPNsense, iptables, pf or OS commands."""
    def __init__(self, policy, path, clock=time.time):
        self.policy, self.clock = policy, clock
        self.conn, self.lock = db(path), threading.RLock()
        self.conn.executescript('''
            CREATE TABLE IF NOT EXISTS blocks(ip TEXT PRIMARY KEY, expires_at REAL, request_id TEXT);
            CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, fingerprint TEXT, response TEXT);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, time REAL, action TEXT, ip TEXT);
        ''')

    def _expire(self):
        now = self.clock()
        rows = self.conn.execute("SELECT ip FROM blocks WHERE expires_at<=?", (now,)).fetchall()
        for (address,) in rows:
            self.conn.execute("INSERT INTO audit(time,action,ip) VALUES(?,?,?)", (now, "EXPIRE", address))
        self.conn.execute("DELETE FROM blocks WHERE expires_at<=?", (now,))

    def expire(self):
        with self.lock, self.conn:
            self._expire()

    def block(self, raw):
        if not isinstance(raw, dict) or set(raw) != {"request_id", "ip", "ttl_seconds"}:
            raise APIError(422, "Expected request_id, ip and ttl_seconds")
        address = ip(raw["ip"])
        ttl = number(raw["ttl_seconds"], "TTL", 1, self.policy.ttl, True)
        rid = raw["request_id"]
        if not isinstance(rid, str) or not 1 <= len(rid) <= 128:
            raise APIError(422, "Invalid request_id")
        reason = self.policy.guard(address)
        if reason:
            raise APIError(403, reason)
        fingerprint = digest({"ip": address, "ttl": ttl})
        with self.lock, self.conn:
            self._expire()
            previous = self.conn.execute("SELECT fingerprint,response FROM requests WHERE id=?", (rid,)).fetchone()
            if previous:
                if previous[0] != fingerprint:
                    raise APIError(409, "request_id reused with different content")
                return dict(json.loads(previous[1]), replayed=True)
            active = self.conn.execute("SELECT expires_at FROM blocks WHERE ip=?", (address,)).fetchone()
            if active:
                expires, status = active[0], "already_blocked"
            else:
                count = self.conn.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
                if count >= self.policy.data["max_active_blocks"]:
                    raise APIError(429, "Maximum active mock blocks reached")
                expires, status = self.clock() + ttl, "blocked"
                self.conn.execute("INSERT INTO blocks VALUES(?,?,?)", (address, expires, rid))
                self.conn.execute("INSERT INTO audit(time,action,ip) VALUES(?,?,?)", (self.clock(), "BLOCK", address))
            result = {"mode": "mock", "status": status, "ip": address, "request_id": rid,
                      "expires_at": expires, "replayed": False}
            self.conn.execute("INSERT INTO requests VALUES(?,?,?)", (rid, fingerprint, canonical(result)))
            return result

    def unblock(self, raw):
        if not isinstance(raw, dict) or set(raw) != {"ip"}:
            raise APIError(422, "Expected ip only")
        address = ip(raw["ip"])
        with self.lock, self.conn:
            self._expire()
            self.conn.execute("DELETE FROM blocks WHERE ip=?", (address,))
            self.conn.execute("INSERT INTO audit(time,action,ip) VALUES(?,?,?)", (self.clock(), "UNBLOCK", address))
        return {"mode": "mock", "status": "unblocked", "ip": address}

    def blocks(self):
        with self.lock, self.conn:
            self._expire()
            rows = self.conn.execute("SELECT ip,expires_at FROM blocks ORDER BY ip").fetchall()
        return {"mode": "mock", "blocks": [{"ip": x, "expires_at": t} for x, t in rows]}
