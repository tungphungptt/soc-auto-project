"""Durable source cursor + delivery outbox, so transient API/ES outage does not drop events."""
import json
import sqlite3
import threading
import time
from .common import canonical, db

class Outbox:
    def __init__(self, dbpath, clock=time.time):
        self.conn, self.lock, self.clock = db(dbpath), threading.RLock(), clock
        self.conn.executescript("""            CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                result TEXT, attempts INTEGER NOT NULL DEFAULT 0, next_retry REAL NOT NULL DEFAULT 0,
                error TEXT, created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS cursors(path TEXT PRIMARY KEY, inode TEXT, position INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS deadletter(id TEXT PRIMARY KEY,payload TEXT NOT NULL,
                reason TEXT, created_at REAL NOT NULL);
        """)

    def cursor(self, path, inode):
        with self.lock:
            row = self.conn.execute('SELECT inode,position FROM cursors WHERE path=?', (path,)).fetchone()
        return row[1] if row and row[0] == str(inode) else 0

    def accept(self, path, inode, position, event=None):
        with self.lock, self.conn:
            if event is not None:
                old=self.conn.execute('SELECT payload FROM outbox WHERE id=?',(event['event_id'],)).fetchone()
                if old and old[0]!=canonical(event):
                    self.conn.execute('INSERT OR IGNORE INTO deadletter VALUES(?,?,?,?)',
                                      (event['event_id']+'-collision',canonical(event),'event_id collision in Bridge',self.clock()))
                else:
                    self.conn.execute('INSERT OR IGNORE INTO outbox(id,payload,created_at) VALUES(?,?,?)',
                                      (event['event_id'], canonical(event), self.clock()))
            self.conn.execute('INSERT OR REPLACE INTO cursors VALUES(?,?,?)', (path, str(inode), position))

    def due(self, limit=50):
        with self.lock:
            rows = self.conn.execute('SELECT id,payload,result FROM outbox WHERE next_retry<=? '
                                     'ORDER BY created_at LIMIT ?', (self.clock(), limit)).fetchall()
        return [(i, json.loads(payload), json.loads(result) if result else None) for i,payload,result in rows]

    def set_result(self, eid, result):
        with self.lock, self.conn:
            self.conn.execute('UPDATE outbox SET result=?,attempts=0,next_retry=0,error=NULL WHERE id=?',
                              (canonical(result),eid))

    def defer(self, eid, reason):
        with self.lock, self.conn:
            row = self.conn.execute('SELECT attempts FROM outbox WHERE id=?', (eid,)).fetchone()
            if row is None: return
            attempt = row[0] + 1
            wait = min(60, 2 ** min(attempt, 6))
            self.conn.execute('UPDATE outbox SET attempts=?,next_retry=?,error=? WHERE id=?',
                              (attempt, self.clock()+wait, str(reason)[:200], eid))

    def dead_letter(self,eid,reason):
        with self.lock,self.conn:
            row=self.conn.execute('SELECT payload FROM outbox WHERE id=?',(eid,)).fetchone()
            if row:
                self.conn.execute('INSERT OR REPLACE INTO deadletter VALUES(?,?,?,?)',
                                  (eid,row[0],str(reason)[:200],self.clock()))
                self.conn.execute('DELETE FROM outbox WHERE id=?',(eid,))

    def complete(self, eid):
        with self.lock, self.conn:
            self.conn.execute('DELETE FROM outbox WHERE id=?', (eid,))

    def counts(self):
        with self.lock:
            rows = self.conn.execute('SELECT COUNT(*), SUM(result IS NOT NULL) FROM outbox').fetchone()
            dlq=self.conn.execute('SELECT COUNT(*) FROM deadletter').fetchone()[0]
        return {'queued': rows[0], 'awaiting_elasticsearch': rows[1] or 0, 'deadletter':dlq}
