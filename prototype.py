"""Localhost HTTP + SQLite prototype and synthetic workload.

Configurations (Table 1):
  access_only         one endpoint-level event per request, no verifier, no mapping
  structured          gateway + application + database-change events, no verifier, no mapping
  structured_anchored structured events + handling controls + hash chain + checkpoint, NO mapping
  mapped_unanchored   structured events + handling controls + hash chain only, sixteen mapped paths
  mapped_anchored     structured events + handling controls + hash chain + checkpoint, sixteen mapped paths
"""
import http.client
import json
import random
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from integrity import sha256_hex

CONFIGS = {
    "access_only":         dict(structured=False, handling=False, chain=False, anchor=False, mapped=False),
    "structured":          dict(structured=True,  handling=False, chain=False, anchor=False, mapped=False),
    "structured_anchored": dict(structured=True,  handling=True,  chain=True,  anchor=True,  mapped=False),
    "mapped_unanchored":   dict(structured=True,  handling=True,  chain=True,  anchor=False, mapped=True),
    "mapped_anchored":     dict(structured=True,  handling=True,  chain=True,  anchor=True,  mapped=True),
}

ACTIVITIES = ["login_ok", "login_fail", "doc_update", "export", "doc_denied", "upload"]
SEEDS = [17, 29, 41, 53, 67]
REPETITIONS = 20  # per activity per seed -> 120 requests

PASSWORD_SENTINEL = "PASSWORD-SENTINEL-7f3a"
TOKEN_SENTINEL = "TOKEN-SENTINEL-91c2"
BODY_SENTINEL = "BODY-SENTINEL-c04e"

ROUTES = {
    "login_ok": "/login", "login_fail": "/login", "doc_update": "/documents/update",
    "export": "/documents/export", "doc_denied": "/documents/view", "upload": "/documents/upload",
}
PATH_ACTION = {"/documents/update": "update", "/documents/export": "export",
               "/documents/view": "view", "/documents/upload": "upload", "/login": "login"}


def now_utc():
    return datetime.now(timezone.utc).isoformat()


class App:
    """Application state shared by the handler for one run."""

    def __init__(self, config, seed, fault_skip_audit_on_update=None):
        self.cfg = CONFIGS[config]
        self.seed = seed
        self.events = []
        self.counter = 0
        self.update_count = 0
        self.fault = fault_skip_audit_on_update  # index of update whose audit write is lost
        self.halted = False
        self.db = sqlite3.connect(":memory:", check_same_thread=False)
        self.db.executescript(
            "CREATE TABLE accounts(name TEXT PRIMARY KEY, role TEXT, password TEXT);"
            "CREATE TABLE documents(id TEXT PRIMARY KEY, content TEXT, version INTEGER, restricted INTEGER);"
        )
        self.db.executemany("INSERT INTO accounts VALUES(?,?,?)", [
            ("alice", "editor", PASSWORD_SENTINEL), ("bob", "viewer", PASSWORD_SENTINEL),
            ("ivy", "investigator", PASSWORD_SENTINEL)])
        self.db.executemany("INSERT INTO documents VALUES(?,?,?,?)",
                            [(f"doc-{i}", f"initial-{i}", 1, 0) for i in range(1, 6)] + [("doc-restricted", "x", 1, 1)])
        self.db.commit()

    def next_request_id(self):
        self.counter += 1
        return f"req-{self.seed}-{self.counter:04d}"

    # -- request processing --------------------------------------------------------
    def handle(self, path, body):
        rid = self.next_request_id()
        account = body.get("account")
        status, outcome, obj, extra = 500, "error", None, {}
        db_event = None
        if path == "/login":
            obj = f"session:{account}"
            row = self.db.execute("SELECT password FROM accounts WHERE name=?", (account,)).fetchone()
            ok = row is not None and body.get("password") == row[0]
            status, outcome = (200, "success") if ok else (401, "denied")
        elif path == "/documents/update":
            obj = body["doc"]
            before = self.db.execute("SELECT content FROM documents WHERE id=?", (obj,)).fetchone()[0]
            self.db.execute("UPDATE documents SET content=?, version=version+1 WHERE id=?", (body["content"], obj))
            self.db.commit()  # audit event is generated after commit (crash gap)
            status, outcome = 200, "success"
            self.update_count += 1
            db_event = {"table": "documents", "object": obj,
                        "before_digest": sha256_hex(before.encode()), "after_digest": sha256_hex(body["content"].encode())}
            if self.fault is not None and self.update_count == self.fault:
                self.halted = True  # simulated crash: commit done, no audit written
                return rid, status
        elif path == "/documents/export":
            obj = body["doc"]
            status, outcome = 200, "success"
        elif path == "/documents/view":
            obj = body["doc"]
            restricted = self.db.execute("SELECT restricted FROM documents WHERE id=?", (obj,)).fetchone()[0]
            role = self.db.execute("SELECT role FROM accounts WHERE name=?", (account,)).fetchone()[0]
            status, outcome = (403, "denied") if restricted and role != "investigator" else (200, "success")
        elif path == "/documents/upload":
            obj = body["filename"]
            extra["content_digest"] = sha256_hex(body["content"].encode())
            status, outcome = 200, "success"
        self.log(rid, path, status, account, obj, outcome, extra, db_event)
        return rid, status

    def log(self, rid, path, status, account, obj, outcome, extra, db_event):
        ts = now_utc()
        if not self.cfg["structured"]:
            # access-only: endpoint record without account, object, or request identifier
            self.events.append({"ts": ts, "method": "POST", "path": path, "status": status})
            return
        self.events.append({"ts": ts, "component": "node-http", "source": "gateway", "request_id": rid,
                            "method": "POST", "path": path, "status": status})
        app_ev = {"ts": ts, "component": "app-web", "source": "application", "request_id": rid,
                  "account": account, "action": PATH_ACTION[path], "object": obj, "outcome": outcome}
        app_ev.update(extra)
        self.events.append(app_ev)
        if db_event:
            ev = {"ts": now_utc(), "component": "app-db", "source": "database", "request_id": rid}
            ev.update(db_event)
            self.events.append(ev)


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            rid, status = app.handle(self.path, body)
            self.send_response(status)
            self.send_header("X-Request-ID", rid)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass
    return Handler


def build_workload(seed):
    """Twenty repetitions of the six activities, shuffled independently per seed."""
    rng = random.Random(seed)
    plan = ACTIVITIES * REPETITIONS
    rng.shuffle(plan)
    requests = []
    for n, act in enumerate(plan, start=1):
        doc = f"doc-{rng.randint(1, 5)}"
        if act == "login_ok":
            body = {"account": "alice", "password": PASSWORD_SENTINEL}
            truth = dict(account="alice", action="login", object="session:alice", outcome="success")
        elif act == "login_fail":
            body = {"account": "bob", "password": "wrong-" + PASSWORD_SENTINEL[::-1]}
            truth = dict(account="bob", action="login", object="session:bob", outcome="denied")
        elif act == "doc_update":
            body = {"account": "alice", "token": TOKEN_SENTINEL, "doc": doc, "content": f"{BODY_SENTINEL}-{seed}-{n}"}
            truth = dict(account="alice", action="update", object=doc, outcome="success")
        elif act == "export":
            body = {"account": "ivy", "token": TOKEN_SENTINEL, "doc": doc}
            truth = dict(account="ivy", action="export", object=doc, outcome="success")
        elif act == "doc_denied":
            body = {"account": "bob", "token": TOKEN_SENTINEL, "doc": "doc-restricted"}
            truth = dict(account="bob", action="view", object="doc-restricted", outcome="denied")
        else:
            fname = f"upload-{seed}-{n}.bin"
            body = {"account": "alice", "token": TOKEN_SENTINEL, "filename": fname,
                    "content": f"{BODY_SENTINEL}-generated-{rng.random():.12f}"}
            truth = dict(account="alice", action="upload", object=fname, outcome="success")
        requests.append({"activity": act, "path": ROUTES[act], "body": body, "truth": truth})
    return requests


def run(config, seed, fault_skip_audit_on_update=None):
    """Execute one workload; return (events, truth records, app)."""
    app = App(config, seed, fault_skip_audit_on_update)
    server = HTTPServer(("127.0.0.1", 0), make_handler(app))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
    truths = []
    try:
        for req in build_workload(seed):
            if app.halted:
                break
            t0 = now_utc()
            payload = json.dumps(req["body"])
            conn.request("POST", req["path"], body=payload, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            resp.read()
            truth = dict(req["truth"], activity=req["activity"], t_start=t0, t_end=now_utc(),
                         request_id=resp.getheader("X-Request-ID"))
            truths.append(truth)
    finally:
        conn.close()
        server.shutdown()
        server.server_close()
    return app.events, truths, app
