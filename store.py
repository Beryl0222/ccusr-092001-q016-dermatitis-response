"""SQLite 持久层：事件、家庭合并、响应审计、纠正轨迹与唯一告警。

隐私红线（与接口约定一致，存储层不做例外）：
- 只存联系方式的加盐哈希（SHA-256），不存原始号码、姓名、精确地址或照片；
- 趋势/告警只读取事件时间与区域编码，不接触任何描述文本；
- 事实与响应仅用于本事件处置与人工复核，不向分析接口返回逐人记录。
"""

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS households (
    family_id TEXT PRIMARY KEY,
    contact_hash TEXT NOT NULL UNIQUE,
    region TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    family_id TEXT NOT NULL REFERENCES households(family_id),
    status TEXT NOT NULL,
    current_level TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    closed_at REAL
);
CREATE INDEX IF NOT EXISTS idx_events_family ON events(family_id);
CREATE TABLE IF NOT EXISTS fact_entries (
    fact_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL REFERENCES events(event_id),
    seq INTEGER NOT NULL,
    received_at REAL NOT NULL,
    source TEXT NOT NULL,
    raw_facts TEXT NOT NULL,
    normalized_facts TEXT NOT NULL,
    UNIQUE(event_id, seq)
);
CREATE TABLE IF NOT EXISTS responses (
    response_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES events(event_id),
    created_at REAL NOT NULL,
    rule_version TEXT NOT NULL,
    level TEXT NOT NULL,
    fact_snapshot TEXT NOT NULL,
    matched_rules TEXT NOT NULL,
    missing TEXT,
    anomalies TEXT,
    contradictions TEXT,
    tips TEXT,
    corrections TEXT,
    boundary TEXT
);
CREATE INDEX IF NOT EXISTS idx_responses_event ON responses(event_id);
CREATE TABLE IF NOT EXISTS corrections (
    correction_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    treatment TEXT NOT NULL,
    first_response_id TEXT NOT NULL,
    latest_response_id TEXT,
    status TEXT NOT NULL,
    issue_count INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE(event_id, treatment)
);
CREATE TABLE IF NOT EXISTS correction_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correction_id INTEGER NOT NULL REFERENCES corrections(correction_id),
    response_id TEXT,
    at REAL NOT NULL,
    action TEXT NOT NULL,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS event_status_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    at REAL NOT NULL,
    from_status TEXT,
    to_status TEXT,
    reason TEXT,
    response_id TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    region TEXT NOT NULL,
    window_start REAL NOT NULL,
    window_end REAL NOT NULL,
    metric TEXT NOT NULL DEFAULT '事件数',
    created_at REAL NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE(region, window_start, window_end, metric)
);
"""

CONTACT_SALT_KEY = "contact_salt"


class Store:
    """线程安全的 SQLite 封装。写操作串行化，分析侧只读聚合。"""

    def __init__(self, path=":memory:", salt=None, now=time.time):
        self.now = now
        self._lock = threading.RLock()
        if path != ":memory:":
            parent = os.path.dirname(os.path.abspath(path))
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.salt = salt or os.environ.get("HOTLINE_SALT") or self._load_or_create_salt()

    # ---- 基础 ----------------------------------------------------------

    def _load_or_create_salt(self):
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (CONTACT_SALT_KEY,)).fetchone()
        if row:
            return row["value"]
        salt = secrets.token_hex(32)
        self.conn.execute("INSERT INTO meta(key, value) VALUES(?, ?)", (CONTACT_SALT_KEY, salt))
        self.conn.commit()
        return salt

    def hash_contact(self, contact):
        return hashlib.sha256(f"{self.salt}|{contact.strip()}".encode("utf-8")).hexdigest()

    def close(self):
        with self._lock:
            self.conn.close()

    # ---- 家庭与事件 -----------------------------------------------------

    def find_or_create_family(self, contact, region):
        """同一联系方式（加盐哈希）永远映射到同一家庭；返回 (family_id, created)。"""
        contact_hash = self.hash_contact(contact)
        with self._lock:
            row = self.conn.execute(
                "SELECT family_id FROM households WHERE contact_hash=?", (contact_hash,)).fetchone()
            if row:
                return row["family_id"], False
            family_id = "fam-" + secrets.token_hex(6)
            self.conn.execute(
                "INSERT INTO households(family_id, contact_hash, region, created_at) VALUES(?,?,?,?)",
                (family_id, contact_hash, region, self.now()))
            self.conn.commit()
            return family_id, True

    def family_region(self, family_id):
        row = self.conn.execute("SELECT region FROM households WHERE family_id=?",
                                (family_id,)).fetchone()
        return row["region"] if row else None

    def open_event(self, family_id):
        """家庭当前未关闭的事件即原事件，重复来电话合并其下。"""
        row = self.conn.execute(
            "SELECT * FROM events WHERE family_id=? AND status != 'closed' "
            "ORDER BY created_at DESC LIMIT 1", (family_id,)).fetchone()
        return dict(row) if row else None

    def create_event(self, family_id):
        event_id = "evt-" + secrets.token_hex(6)
        ts = self.now()
        with self._lock:
            self.conn.execute(
                "INSERT INTO events(event_id, family_id, status, created_at, updated_at) "
                "VALUES(?,?,'open',?,?)", (event_id, family_id, ts, ts))
            self.conn.execute(
                "INSERT INTO event_status_log(event_id, at, from_status, to_status, reason) "
                "VALUES(?,?,'','open','事件建立')", (event_id, ts))
            self.conn.commit()
        return event_id

    def set_event_level(self, event_id, level):
        with self._lock:
            self.conn.execute("UPDATE events SET current_level=?, updated_at=? WHERE event_id=?",
                              (level, self.now(), event_id))
            self.conn.commit()

    def transition_status(self, event_id, to_status, reason, response_id=None):
        with self._lock:
            row = self.conn.execute("SELECT status FROM events WHERE event_id=?",
                                    (event_id,)).fetchone()
            old = row["status"]
            ts = self.now()
            if to_status == "closed":
                self.conn.execute(
                    "UPDATE events SET status=?, updated_at=?, closed_at=? WHERE event_id=?",
                    (to_status, ts, ts, event_id))
            else:
                self.conn.execute(
                    "UPDATE events SET status=?, updated_at=? WHERE event_id=?",
                    (to_status, ts, event_id))
            self.conn.execute(
                "INSERT INTO event_status_log(event_id, at, from_status, to_status, reason, response_id) "
                "VALUES(?,?,?,?,?,?)", (event_id, ts, old, to_status, reason, response_id))
            self.conn.commit()

    # ---- 事实与响应 -----------------------------------------------------

    def append_facts(self, event_id, raw_facts, normalized_facts, source):
        with self._lock:
            row = self.conn.execute(
                "SELECT COALESCE(MAX(seq), 0) AS m FROM fact_entries WHERE event_id=?",
                (event_id,)).fetchone()
            seq = row["m"] + 1
            self.conn.execute(
                "INSERT INTO fact_entries(event_id, seq, received_at, source, raw_facts, normalized_facts) "
                "VALUES(?,?,?,?,?,?)",
                (event_id, seq, self.now(), source,
                 json.dumps(raw_facts, ensure_ascii=False),
                 json.dumps(normalized_facts, ensure_ascii=False)))
            self.conn.commit()
        return seq

    def fact_entries(self, event_id):
        rows = self.conn.execute(
            "SELECT seq, received_at, source, raw_facts, normalized_facts "
            "FROM fact_entries WHERE event_id=? ORDER BY seq", (event_id,)).fetchall()
        return [dict(seq=r["seq"], received_at=r["received_at"], source=r["source"],
                     raw_facts=json.loads(r["raw_facts"]),
                     normalized_facts=json.loads(r["normalized_facts"])) for r in rows]

    def save_response(self, event_id, result):
        """持久化一次回复：完整记录所用事实快照、规则版本与命中规则。"""
        response_id = "rsp-" + secrets.token_hex(6)
        with self._lock:
            self.conn.execute(
                "INSERT INTO responses(response_id, event_id, created_at, rule_version, level, "
                "fact_snapshot, matched_rules, missing, anomalies, contradictions, tips, "
                "corrections, boundary) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (response_id, event_id, self.now(), result["规则版本"], result["等级"],
                 json.dumps(result["事实快照"], ensure_ascii=False),
                 json.dumps(result["命中规则"], ensure_ascii=False),
                 json.dumps(result["缺失事实"], ensure_ascii=False),
                 json.dumps(result["异常事实"], ensure_ascii=False),
                 json.dumps(result["矛盾事实"], ensure_ascii=False),
                 json.dumps(result["安全提示"], ensure_ascii=False),
                 json.dumps(result["需要纠正"], ensure_ascii=False),
                 result["边界声明"]))
            self.conn.commit()
        return response_id

    def responses(self, event_id):
        rows = self.conn.execute(
            "SELECT * FROM responses WHERE event_id=? ORDER BY created_at", (event_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            for key in ("fact_snapshot", "matched_rules", "missing", "anomalies",
                        "contradictions", "tips", "corrections"):
                d[key] = json.loads(d[key])
            out.append(d)
        return out

    # ---- 偏方纠正轨迹 ----------------------------------------------------

    def record_corrections(self, event_id, response_id, active_treatments, acknowledged=False):
        """登记/续记本次回复中的纠正项，返回每个处理的动作与当前状态。

        - 首次出现：issued；
        - 已纠正过、本次资料中仍在使用：reissued（纠正未被采纳，过程可追踪）；
        - acknowledged：家属在本次资料中确认停用。
        """
        actions = []
        with self._lock:
            ts = self.now()
            for treatment in active_treatments:
                row = self.conn.execute(
                    "SELECT * FROM corrections WHERE event_id=? AND treatment=?",
                    (event_id, treatment)).fetchone()
                if row is None:
                    cur = self.conn.execute(
                        "INSERT INTO corrections(event_id, treatment, first_response_id, "
                        "latest_response_id, status, created_at, updated_at) "
                        "VALUES(?,?,?,?,'issued',?,?)",
                        (event_id, treatment, response_id, response_id, ts, ts))
                    cid = cur.lastrowid
                    action = "issued"
                    status = "issued"
                else:
                    cid = row["correction_id"]
                    if acknowledged:
                        action, status = "acknowledged", "confirmed_stopped"
                    elif row["status"] == "confirmed_stopped":
                        # 曾确认停用又再次使用，重新发纠正
                        action, status = "reissued", "reissued"
                    else:
                        action, status = "repeated", "reissued"
                    self.conn.execute(
                        "UPDATE corrections SET latest_response_id=?, status=?, issue_count=?, "
                        "updated_at=? WHERE correction_id=?",
                        (response_id, status, row["issue_count"] + 1, ts, cid))
                self.conn.execute(
                    "INSERT INTO correction_log(correction_id, response_id, at, action, detail) "
                    "VALUES(?,?,?,?,'')", (cid, response_id, ts, action))
                actions.append({"处理": treatment, "动作": action, "状态": status})
            self.conn.commit()
        return actions

    def confirm_correction_stopped(self, event_id, treatments):
        """随访坐席登记家属确认停用。"""
        ts = self.now()
        with self._lock:
            for treatment in treatments:
                row = self.conn.execute(
                    "SELECT * FROM corrections WHERE event_id=? AND treatment=?",
                    (event_id, treatment)).fetchone()
                if row is None:
                    continue
                self.conn.execute(
                    "UPDATE corrections SET status='confirmed_stopped', updated_at=? "
                    "WHERE correction_id=?", (ts, row["correction_id"]))
                self.conn.execute(
                    "INSERT INTO correction_log(correction_id, response_id, at, action, detail) "
                    "VALUES(?,NULL,?,'confirmed_stopped','随访确认停用')",
                    (row["correction_id"], ts))
            self.conn.commit()

    def correction_trail(self, event_id):
        rows = self.conn.execute(
            "SELECT c.treatment, c.status, c.issue_count, c.created_at, c.updated_at, l.at, l.action "
            "FROM corrections c JOIN correction_log l ON l.correction_id=c.correction_id "
            "WHERE c.event_id=? ORDER BY l.at", (event_id,)).fetchall()
        return [dict(r) for r in rows]

    # ---- 分析侧只读 -----------------------------------------------------

    def event_buckets(self, since, until=None, region=None):
        """仅返回分析所需：事件编号（非个人标识）、区域、建单时间。"""
        until = until if until is not None else self.now()
        sql = ("SELECT e.event_id AS event_id, e.family_id AS family_id, h.region AS region, "
               "e.created_at AS created_at FROM events e JOIN households h ON h.family_id=e.family_id "
               "WHERE e.created_at >= ? AND e.created_at < ?")
        params = [since, until]
        if region:
            sql += " AND region=?"
            params.append(region)
        rows = self.conn.execute(sql, params).fetchall()
        return [dict(event_id=r["event_id"], family_id=r["family_id"],
                     region=r["region"], created_at=r["created_at"]) for r in rows]

    def insert_alert(self, region, window_start, window_end, payload, metric="事件数"):
        """唯一约束保证同一区域同一聚集窗口只产生一条告警。"""
        alert_id = "alr-" + secrets.token_hex(6)
        with self._lock:
            try:
                self.conn.execute(
                    "INSERT INTO alerts(alert_id, region, window_start, window_end, metric, "
                    "created_at, payload) VALUES(?,?,?,?,?,?,?)",
                    (alert_id, region, window_start, window_end, metric, self.now(),
                     json.dumps(payload, ensure_ascii=False)))
                self.conn.commit()
            except sqlite3.IntegrityError:
                row = self.conn.execute(
                    "SELECT * FROM alerts WHERE region=? AND window_start=? AND window_end=? "
                    "AND metric=?", (region, window_start, window_end, metric)).fetchone()
                return dict(row), False
        return {"alert_id": alert_id, "region": region, "window_start": window_start,
                "window_end": window_end, "metric": metric, "payload": payload}, True
