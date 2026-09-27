"""SQLite 存储层：事件、时间线、纠正轨迹、审计、告警与聚合归档。

隐私要点：
- 只保存家庭假名的加盐哈希（family_pseudonym_hash），不保存原始假名，也不保存任何 PII/图片；
- event_id 为随机不可猜测标识，凭标识才可查询；
- 每条时间线记录写入当时的归一化事实、结构化结论、命中规则与规则版本/哈希；
- 所有写操作同步进入 audit_log，内容只存规范 JSON 的摘要与动作，不额外留存原文。
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

CST = timezone(timedelta(hours=8))


def now_cst() -> datetime:
    return datetime.now(tz=CST)


def iso(ts: datetime | None = None) -> str:
    return (ts or now_cst()).isoformat(timespec="seconds")


def today_cst() -> str:
    return now_cst().date().isoformat()


def canonical_digest(obj) -> str:
    """对事实与结论做规范序列化后的 sha256，用于审计防篡改比对。"""
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    family_hash TEXT NOT NULL,
    region TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    window_expires_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    current_decision TEXT,
    current_level TEXT,
    rule_version TEXT NOT NULL,
    latest_facts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_merge ON events(family_hash, region, window_expires_at);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);

CREATE TABLE IF NOT EXISTS timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL REFERENCES events(event_id),
    seq INTEGER NOT NULL,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    actor TEXT NOT NULL,
    facts TEXT NOT NULL,
    result TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    rule_hash TEXT NOT NULL,
    UNIQUE(event_id, seq)
);

CREATE TABLE IF NOT EXISTS corrections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL REFERENCES events(event_id),
    correction_id TEXT NOT NULL,
    treatment TEXT NOT NULL,
    advised_at TEXT NOT NULL,
    acknowledged_at TEXT,
    resolution TEXT,
    UNIQUE(event_id, correction_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    event_id TEXT,
    rule_version TEXT,
    digest TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    region TEXT NOT NULL,
    day TEXT NOT NULL,
    count INTEGER NOT NULL,
    baseline_median REAL NOT NULL,
    rule_version TEXT NOT NULL,
    created_ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_region_day ON alerts(region, day);

-- 保留期后用的去标识化日聚合（仅地区×日计数）
CREATE TABLE IF NOT EXISTS daily_counts (
    region TEXT NOT NULL,
    day TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY(region, day)
);
"""


def load_or_create_salt(path: Path | None) -> str:
    """盐值从环境变量读取；否则落到仅服务账户可读的文件。"""
    env = os.environ.get("HOTLINE_SALT")
    if env:
        return env
    if path is None:
        path = Path("data") / ".salt"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_hex(32)
    path.write_text(salt, encoding="utf-8")
    os.chmod(path, 0o600)
    return salt


def merge_facts(old: dict, new: dict) -> dict:
    """把后续补充并入既有事实：新证据覆盖 unknown，治疗史取并集。"""
    merged = dict(old)
    for key, value in new.items():
        if value is not None and value != [] and value != "unknown":
            merged[key] = value
        elif key not in merged:
            merged[key] = value
    merged["prior_home_treatments"] = sorted(
        set(merged.get("prior_home_treatments", [])) | set(new.get("prior_home_treatments", []))
    )
    return merged


class Store:
    def __init__(self, db_path: str | Path, salt: str, merge_window_hours: int = 72):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.salt = salt
        self.merge_window = timedelta(hours=merge_window_hours)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- 标识与审计 ----------------------------------------------------

    def family_hash(self, pseudonym: str) -> str:
        key = pseudonym.strip().lower()
        return hashlib.sha256(f"{self.salt}|{key}".encode("utf-8")).hexdigest()

    @staticmethod
    def new_event_id() -> str:
        return "EVT" + secrets.token_hex(8)

    def _audit(self, action: str, actor: str, event_id: str | None,
               rule_version: str | None, payload) -> None:
        self._conn.execute(
            "INSERT INTO audit_log(ts, action, actor, event_id, rule_version, digest) VALUES(?,?,?,?,?,?)",
            (iso(), action, actor, event_id, rule_version, canonical_digest(payload)),
        )

    # ---- 事件 ----------------------------------------------------------

    def find_mergeable_event(self, pseudonym: str, region: str, now: datetime | None = None) -> str | None:
        """同家庭假名 + 同地区且仍在合并窗口内的最近事件。"""
        now = now or now_cst()
        with self._lock:
            row = self._conn.execute(
                """SELECT event_id FROM events
                   WHERE family_hash=? AND region=? AND window_expires_at >= ?
                   ORDER BY created_at DESC LIMIT 1""",
                (self.family_hash(pseudonym), region.strip(), iso(now)),
            ).fetchone()
            return row["event_id"] if row else None

    def create_event(self, pseudonym: str, facts: dict, result: dict,
                     rule_hash: str, actor: str, now: datetime | None = None) -> str:
        now = now or now_cst()
        event_id = self.new_event_id()
        expires = iso(now + self.merge_window)
        with self._lock:
            self._conn.execute(
                """INSERT INTO events(event_id, family_hash, region, created_at, updated_at,
                   window_expires_at, status, current_decision, current_level, rule_version, latest_facts)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (event_id, self.family_hash(pseudonym), facts["region"], iso(now), iso(now),
                 expires, self._status_for(result), result["decision"], result.get("level"),
                 result["rule_version"], json.dumps(facts, ensure_ascii=False)),
            )
            self._append_timeline(event_id, 1, "intake", actor, facts, result, rule_hash, now)
            self._upsert_corrections(event_id, facts, result, now)
            self._audit("event.create", actor, event_id, result["rule_version"],
                        {"facts": facts, "result": result})
            self._conn.commit()
        return event_id

    def add_supplement(self, event_id: str, submitted_facts: dict, merged_facts: dict,
                       result: dict, rule_hash: str, actor: str,
                       now: datetime | None = None) -> int:
        """把补充材料并入原事件：时间线追加原始提交，事件主档更新为合并事实并重定级。"""
        now = now or now_cst()
        with self._lock:
            exists = self._conn.execute(
                "SELECT 1 FROM events WHERE event_id=?", (event_id,),
            ).fetchone()
            if exists is None:
                raise KeyError(event_id)
            row = self._conn.execute(
                "SELECT MAX(seq) AS seq FROM timeline WHERE event_id=?",
                (event_id,),
            ).fetchone()
            seq = (row["seq"] or 0) + 1
            self._append_timeline(event_id, seq, "supplement", actor,
                                  submitted_facts, result, rule_hash, now)
            self._upsert_corrections(event_id, merged_facts, result, now)
            self._conn.execute(
                """UPDATE events SET updated_at=?, status=?, current_decision=?, current_level=?,
                   rule_version=?, latest_facts=? WHERE event_id=?""",
                (iso(now), self._status_for(result), result["decision"], result.get("level"),
                 result["rule_version"], json.dumps(merged_facts, ensure_ascii=False), event_id),
            )
            self._audit("event.supplement", actor, event_id, result["rule_version"],
                        {"facts": submitted_facts, "result": result, "seq": seq})
            self._conn.commit()
        return seq

    @staticmethod
    def _status_for(result: dict) -> str:
        return {
            "ESCALATE_OFFLINE": "escalated",
            "HUMAN_REVIEW": "in_review",
            "REQUIRE_INFO": "needs_info",
            "SELF_CARE": "open",
        }.get(result["decision"], "open")

    def _append_timeline(self, event_id, seq, kind, actor, facts, result, rule_hash, now) -> None:
        self._conn.execute(
            """INSERT INTO timeline(event_id, seq, ts, kind, actor, facts, result, rule_version, rule_hash)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (event_id, seq, iso(now), kind, actor,
             json.dumps(facts, ensure_ascii=False), json.dumps(result, ensure_ascii=False),
             result["rule_version"], rule_hash),
        )

    def _upsert_corrections(self, event_id, facts, result, now) -> None:
        advised = {c["id"]: c for c in result.get("corrections", [])}
        for cid, entry in advised.items():
            self._conn.execute(
                """INSERT INTO corrections(event_id, correction_id, treatment, advised_at)
                   VALUES(?,?,?,?) ON CONFLICT(event_id, correction_id) DO NOTHING""",
                (event_id, cid, entry["treatment"], iso(now)),
            )

    def acknowledge_correction(self, event_id: str, correction_id: str,
                               resolution: str | None, now: datetime | None = None) -> bool:
        """坐席/家长确认已按纠正建议处置（如已洗去牙膏），形成纠正闭环。"""
        now = now or now_cst()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE corrections SET acknowledged_at=?, resolution=? "
                "WHERE event_id=? AND correction_id=? AND acknowledged_at IS NULL",
                (iso(now), resolution, event_id, correction_id),
            )
            if cur.rowcount:
                self._audit("correction.ack", "agent", event_id, None,
                            {"correction_id": correction_id, "resolution": resolution})
                self._conn.commit()
            return cur.rowcount > 0

    def event_family_hash(self, event_id: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT family_hash FROM events WHERE event_id=?", (event_id,),
            ).fetchone()
        return row["family_hash"] if row else None

    def get_event(self, event_id: str) -> dict | None:
        with self._lock:
            ev = self._conn.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
            if ev is None:
                return None
            timeline = self._conn.execute(
                "SELECT seq, ts, kind, actor, facts, result, rule_version, rule_hash "
                "FROM timeline WHERE event_id=? ORDER BY seq", (event_id,),
            ).fetchall()
            corrections = self._conn.execute(
                "SELECT correction_id, treatment, advised_at, acknowledged_at, resolution "
                "FROM corrections WHERE event_id=? ORDER BY id", (event_id,),
            ).fetchall()
        return {
            "event_id": ev["event_id"],
            "region": ev["region"],
            "created_at": ev["created_at"],
            "updated_at": ev["updated_at"],
            "status": ev["status"],
            "current_decision": ev["current_decision"],
            "current_level": ev["current_level"],
            "rule_version": ev["rule_version"],
            "latest_facts": json.loads(ev["latest_facts"]),
            "timeline": [
                {
                    "seq": r["seq"], "ts": r["ts"], "kind": r["kind"], "actor": r["actor"],
                    "facts": json.loads(r["facts"]),
                    "result": json.loads(r["result"]),
                    "rule_version": r["rule_version"], "rule_hash": r["rule_hash"][:12] + "…",
                }
                for r in timeline
            ],
            "corrections": [dict(r) for r in corrections],
        }

    # ---- 趋势与告警 ----------------------------------------------------

    def daily_counts(self, days: int, now: datetime | None = None) -> dict[str, dict[str, int]]:
        """近 days 天（含今天）地区×日计数；合并窗口内只有 intake 计数，补充不重复计数。

        已过保留期的日子取 daily_counts 归档，近期取 events 表实时聚合。
        """
        now = now or now_cst()
        start = (now - timedelta(days=days - 1)).date()
        with self._lock:
            live = self._conn.execute(
                "SELECT region, substr(created_at,1,10) AS day, COUNT(*) AS n FROM events "
                "WHERE created_at >= ? GROUP BY region, day",
                (start.isoformat(),),
            ).fetchall()
            archived = self._conn.execute(
                "SELECT region, day, count FROM daily_counts WHERE day >= ?",
                (start.isoformat(),),
            ).fetchall()
        series: dict[str, dict[str, int]] = {}
        for r in archived:
            series.setdefault(r["region"], {})[r["day"]] = r["count"]
        for r in live:  # 实时数据覆盖同日归档（正常不会重叠）
            series.setdefault(r["region"], {})[r["day"]] = r["n"]
        return series

    def first_event_date(self) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT MIN(created_at) AS m FROM events").fetchone()
        return row["m"][:10] if row and row["m"] else None

    def raise_alert(self, alert_id: str, region: str, day: str, count: int,
                    baseline_median: float, rule_version: str, now: datetime | None = None) -> bool:
        """确定性告警ID + 主键唯一约束，保证聚集性上升只产生一条告警。"""
        now = now or now_cst()
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO alerts(alert_id, region, day, count, baseline_median, rule_version, created_ts) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (alert_id, region, day, count, baseline_median, rule_version, iso(now)),
                )
                self._audit("alert.raise", "system", None, rule_version,
                            {"alert_id": alert_id, "region": region, "day": day,
                             "count": count, "baseline_median": baseline_median})
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def recent_alert_dates(self, region: str, within_days: int, day: str) -> list[str]:
        start = (datetime.fromisoformat(day) - timedelta(days=within_days)).date().isoformat()
        with self._lock:
            rows = self._conn.execute(
                "SELECT day FROM alerts WHERE region=? AND day >= ? AND day < ? ORDER BY day",
                (region, start, day),
            ).fetchall()
        return [r["day"] for r in rows]

    def list_alerts(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT alert_id, region, day, count, baseline_median, rule_version, created_ts "
                "FROM alerts ORDER BY day DESC, region").fetchall()
        return [dict(r) for r in rows]

    # ---- 保留期 --------------------------------------------------------

    def purge_raw_events(self, retain_days: int, now: datetime | None = None) -> int:
        """超过保留期的原始事件材料清除；清除前把计数固化到 daily_counts。"""
        now = now or now_cst()
        cutoff = (now - timedelta(days=retain_days)).date().isoformat()
        with self._lock:
            old_rows = self._conn.execute(
                "SELECT region, substr(created_at,1,10) AS day, COUNT(*) AS n FROM events "
                "WHERE substr(created_at,1,10) < ? GROUP BY region, day", (cutoff,),
            ).fetchall()
            for r in old_rows:
                self._conn.execute(
                    "INSERT INTO daily_counts(region, day, count) VALUES(?,?,?) "
                    "ON CONFLICT(region, day) DO UPDATE SET count=excluded.count",
                    (r["region"], r["day"], r["n"]),
                )
            old_ids = [
                row["event_id"] for row in self._conn.execute(
                    "SELECT event_id FROM events WHERE substr(created_at,1,10) < ?", (cutoff,),
                ).fetchall()
            ]
            deleted = len(old_ids)
            # 子表有外键约束，先删时间线与纠正记录，再删事件
            self._conn.executemany("DELETE FROM timeline WHERE event_id=?",
                                   [(eid,) for eid in old_ids])
            self._conn.executemany("DELETE FROM corrections WHERE event_id=?",
                                   [(eid,) for eid in old_ids])
            self._conn.executemany("DELETE FROM events WHERE event_id=?",
                                   [(eid,) for eid in old_ids])
            self._audit("retention.purge", "system", None, None,
                        {"cutoff": cutoff, "deleted": deleted, "archived_cells": len(old_rows)})
            self._conn.commit()
        return deleted
