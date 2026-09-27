"""虫媒皮炎分级响应服务测试。

覆盖：服务身份、规则冻结/防篡改/一致性、分级安全边界、事件合并与重定级、
纠正轨迹、聚集告警唯一性、去标识化抑制、保留期、HTTP 接口。
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
import urllib.request
from datetime import datetime, timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path

import analytics
import rulebook
import service as service_mod
import triage
from store import CST, Store, load_or_create_salt

RULES = rulebook.load_rules()
RULE_HASH = rulebook.load_manifest()["versions"][RULES["rule_version"]]["sha256"]

GOOD = {
    "family_pseudonym": "张家",
    "region": "310104",
    "exposure_scenario": "室内趋光",
    "lesion_signs": ["线状红斑", "灼痛"],
    "time_since_exposure_hours": 2,
}


def minimal_result(decision="SELF_CARE", level="居家观察"):
    return {
        "decision": decision, "level": level, "dispatch": None,
        "rule_version": RULES["rule_version"], "actions": [], "corrections": [],
        "uncertainties": [], "fired_rules": [], "advice_text": "",
        "missing_fields": [], "facts": {},
    }


class HealthTest(unittest.TestCase):
    def test_identity(self):
        self.assertEqual(service_mod.health(), {"status": "ok", "service": "dermatitis-response"})

    def test_service_health_reports_rule_version(self):
        svc = make_service()
        try:
            self.assertEqual(svc.health()["service"], "dermatitis-response")
            self.assertEqual(svc.health()["rule_version"], RULES["rule_version"])
            self.assertEqual(len(svc.health()["rule_hash"]), 12)
        finally:
            svc.close()


def make_service(tmpdir=None):
    tmpdir = tmpdir or tempfile.mkdtemp()
    return service_mod.Service(db_path=os.path.join(tmpdir, "t.db"), salt="unit-test-salt")


class TriageTest(unittest.TestCase):
    def test_missing_required_fields_never_low_risk(self):
        result = triage.evaluate({"region": "310104", "lesion_signs": ["线状红斑"]}, RULES)
        self.assertEqual(result["decision"], "REQUIRE_INFO")
        self.assertIsNone(result["level"])
        self.assertIn("exposure_scenario", result["missing_fields"])
        self.assertIn("time_since_exposure_hours", result["missing_fields"])
        # 只允许始终适用的通用冲洗提示，不允许居家观察类提示
        self.assertTrue({a["id"] for a in result["actions"]} <= {"A-WASH-01", "A-DONT-01"})
        self.assertIn("请勿据此判断情况轻微", result["advice_text"])

    def test_all_danger_signs_escalate(self):
        for sign in RULES["danger_signs"]:
            with self.subTest(sign=sign):
                payload = dict(GOOD, lesion_signs=[sign])
                result = triage.evaluate(payload, RULES)
                self.assertEqual(result["decision"], "ESCALATE_OFFLINE", sign)
                self.assertEqual(result["level"], "尽快就医")
                self.assertEqual(result["dispatch"], "human_agent_and_offline")
                self.assertIn("R-DANGER-01", result["fired_rules"])
                self.assertIn(sign, result["matched_danger_signs"])

    def test_unknown_lesions_without_photo_goes_human(self):
        payload = dict(GOOD, lesion_signs="unknown",
                       exposure_scenario="unknown",
                       time_since_exposure_hours="unknown")
        result = triage.evaluate(payload, RULES)
        self.assertEqual(result["decision"], "HUMAN_REVIEW")
        self.assertEqual(result["level"], "人工复核")
        self.assertNotEqual(result["level"], "居家观察")

    def test_infant_escalation(self):
        payload = dict(GOOD, age_band="婴幼儿(0-3)")
        result = triage.evaluate(payload, RULES)
        self.assertEqual(result["decision"], "HUMAN_REVIEW")
        self.assertIn("R-AGE-01", result["fired_rules"])

    def test_unreadable_photo_escalates_and_clear_photo_releases(self):
        result = triage.evaluate(dict(GOOD, photo_assessment="无法判断"), RULES)
        self.assertEqual(result["decision"], "HUMAN_REVIEW")
        self.assertIn("R-PHOTO-01", result["fired_rules"])
        result2 = triage.evaluate(dict(GOOD, photo_assessment="清晰可判读"), RULES)
        self.assertEqual(result2["decision"], "SELF_CARE")

    def test_self_care_with_soap_within_six_hours(self):
        result = triage.evaluate(GOOD, RULES)
        self.assertEqual(result["decision"], "SELF_CARE")
        self.assertEqual(result["level"], "居家观察")
        self.assertIn("A-WASH-02", {a["id"] for a in result["actions"]})
        late = dict(GOOD, time_since_exposure_hours=8)
        result_late = triage.evaluate(late, RULES)
        self.assertNotIn("A-WASH-02", {a["id"] for a in result_late["actions"]})

    def test_folk_remedy_corrections(self):
        for treatment, cid in [("牙膏", "C-TP-01"), ("酒精", "C-AL-01"),
                               ("碘伏", "C-IOD-01"), ("搔抓或挑破", "C-SCR-01"),
                               ("不明偏方", "C-UNK-01")]:
            with self.subTest(treatment=treatment):
                result = triage.evaluate(dict(GOOD, prior_home_treatments=[treatment]), RULES)
                self.assertTrue(any(c["id"] == cid for c in result["corrections"]))

    def test_pii_and_media_fields_are_rejected(self):
        for bad in [{"电话": "13800000000"}, {"name": "张三"}, {"照片": "x.jpg"},
                    {"住址": "某路1号"}, {"备注": "随便写的原文"}]:
            with self.subTest(bad=bad):
                with self.assertRaises(triage.ValidationError):
                    triage.evaluate(dict(GOOD, **bad), RULES)

    def test_undeclared_fields_and_bad_enums_rejected(self):
        with self.assertRaises(triage.ValidationError):
            triage.evaluate(dict(GOOD, lesion_signs=["奇怪表现"]), RULES)
        with self.assertRaises(triage.ValidationError):
            triage.evaluate(dict(GOOD, exposure_scenario="火山"), RULES)
        with self.assertRaises(triage.ValidationError):
            triage.evaluate(dict(GOOD, time_since_exposure_hours=99999), RULES)

    def test_deterministic_with_evidence_chain(self):
        r1 = triage.evaluate(dict(GOOD, lesion_signs=["水疱"]), RULES)
        r2 = triage.evaluate(dict(GOOD, lesion_signs=["水疱"]), RULES)
        self.assertEqual(json.dumps(r1, ensure_ascii=False, sort_keys=True),
                         json.dumps(r2, ensure_ascii=False, sort_keys=True))
        self.assertEqual(r1["rule_version"], RULES["rule_version"])
        self.assertTrue(r1["fired_rules"])
        self.assertIn("不能替代", r1["disclaimer"])


class EventLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.svc = make_service(self.tmp)

    def tearDown(self):
        self.svc.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_needs_info_event_becomes_self_care_then_escalates(self):
        first = self.svc.intake({"family_pseudonym": "张家", "region": "310104",
                                 "lesion_signs": ["线状红斑"]})
        self.assertEqual(first["decision"], "REQUIRE_INFO")
        eid = first["event_id"]
        self.assertTrue(eid)
        second = self.svc.intake(dict(GOOD, prior_home_treatments=["牙膏"]))
        self.assertEqual(second.get("merged_into_event"), eid)
        self.assertEqual(second["decision"], "SELF_CARE")
        third = self.svc.intake({"family_pseudonym": "张家", "region": "310104",
                                 "exposure_scenario": "室内趋光",
                                 "lesion_signs": ["水疱"],
                                 "time_since_exposure_hours": 10})
        self.assertEqual(third.get("merged_into_event"), eid)
        self.assertEqual(third["decision"], "ESCALATE_OFFLINE")
        detail = self.svc.event_detail(eid)
        self.assertEqual(len(detail["timeline"]), 3)
        self.assertEqual(detail["status"], "escalated")
        # 每次回复都记录规则版本与哈希
        for item in detail["timeline"]:
            self.assertEqual(item["rule_version"], RULES["rule_version"])
            self.assertTrue(item["rule_hash"].endswith("…"))

    def test_merge_window_and_region_scope(self):
        r = self.svc.intake(GOOD)
        eid = r["event_id"]
        again = self.svc.intake(GOOD)
        self.assertEqual(again.get("merged_into_event"), eid)
        # 窗口外：新事件
        store = self.svc.store
        old = datetime.now(tz=CST) - timedelta(hours=73)
        store._conn.execute("UPDATE events SET created_at=?, window_expires_at=? WHERE event_id=?",
                            (old.isoformat(timespec="seconds"),
                             (old + timedelta(hours=72)).isoformat(timespec="seconds"), eid))
        store._conn.commit()
        new = self.svc.intake(GOOD)
        self.assertNotEqual(new["event_id"], eid)
        # 同家庭不同地区：新事件
        other = self.svc.intake(dict(GOOD, region="310101"))
        self.assertNotIn("merged_into_event", other)

    def test_explicit_event_id_requires_family_match(self):
        eid = self.svc.intake(GOOD)["event_id"]
        with self.assertRaises(triage.ValidationError):
            self.svc.intake(dict(GOOD, family_pseudonym="他家", event_id=eid))
        with self.assertRaises(triage.ValidationError):
            self.svc.intake(dict(GOOD, event_id="EVTffffffffffffffff"))

    def test_no_region_is_transient_and_not_persisted(self):
        r = self.svc.intake({"family_pseudonym": "陈家", "lesion_signs": ["灼痛"]})
        self.assertFalse(r["persisted"])
        self.assertIsNone(r["event_id"])
        self.assertEqual(r["decision"], "REQUIRE_INFO")

    def test_correction_tracking_and_ack_idempotent(self):
        eid = self.svc.intake(dict(GOOD, prior_home_treatments=["牙膏"]))["event_id"]
        ack = self.svc.acknowledge_correction(eid, {"correction_id": "C-TP-01",
                                                    "resolution": "已用清水洗去"})
        self.assertEqual(ack["status"], "acknowledged")
        detail = self.svc.event_detail(eid)
        corr = detail["corrections"][0]
        self.assertEqual(corr["treatment"], "牙膏")
        self.assertIsNotNone(corr["acknowledged_at"])
        self.assertFalse(self.svc.store.acknowledge_correction(eid, "C-TP-01", "重复登记"))
        with self.assertRaises(triage.ValidationError):
            self.svc.acknowledge_correction(eid, {"correction_id": "C-NOPE-99"})

    def test_raw_pseudonym_never_stored(self):
        self.svc.intake(GOOD)
        raw = Path(self.svc.store.db_path).read_bytes()
        self.assertNotIn("张家".encode("utf-8"), raw)
        # 相同假名 + 相同盐得到相同哈希（可合并），换盐则不同
        h1 = self.svc.store.family_hash("张家")
        other_store = Store(os.path.join(self.tmp, "other.db"), salt="different-salt")
        try:
            self.assertNotEqual(h1, other_store.family_hash("张家"))
        finally:
            other_store.close()


class AnalyticsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.svc = make_service(self.tmp)
        self.today = datetime.now(tz=CST).replace(hour=9)
        self.day = self.today.date().isoformat()

    def tearDown(self):
        self.svc.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed(self, region, n, when):
        for i in range(n):
            self.svc.store.create_event(
                f"fam-{region}-{when.toordinal()}-{i}",
                {"region": region, "prior_home_treatments": []},
                minimal_result(), RULE_HASH, "test", now=when)

    def test_alert_thresholds(self):
        for back in range(1, 15):
            self._seed("A", 6, self.today - timedelta(days=back))
        self._seed("A", 15, self.today)
        findings = analytics.evaluate_clusters(self.svc.store.daily_counts(16),
                                               self.day, RULES)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["baseline_median"], 6)
        # 完整基线下未达倍数（11 < 中位数6的2倍=12）不告警
        for back in range(1, 15):
            self._seed("B", 6, self.today - timedelta(days=back))
        self._seed("B", 11, self.today)
        findings_b = analytics.evaluate_clusters(self.svc.store.daily_counts(16),
                                                 self.day, RULES)
        self.assertNotIn("B", {f["region"] for f in findings_b})

    def test_insufficient_baseline_no_alert(self):
        self._seed("NEW", 50, self.today)
        self.assertEqual(analytics.scan(self.svc.store, RULES, self.day), [])

    def test_alert_is_unique_across_repeated_scans(self):
        for back in range(1, 15):
            self._seed("A", 6, self.today - timedelta(days=back))
        self._seed("A", 15, self.today)
        first = self.svc.scan_alerts(self.day)
        self.assertEqual(first["count"], 1)
        second = self.svc.scan_alerts(self.day)
        self.assertEqual(second["count"], 0)
        self.assertEqual(len(self.svc.list_alerts()["alerts"]), 1)
        # 确定性派生：相同键永远同一 ID
        self.assertEqual(analytics.alert_id(RULES["rule_version"], "A", self.day),
                         first["new_alerts"][0]["alert_id"])

    def test_region_cooldown(self):
        for back in range(1, 16):
            self._seed("A", 6, self.today - timedelta(days=back))
        self._seed("A", 15, self.today)
        first = analytics.scan(self.svc.store, RULES, self.day)
        self.assertEqual(len(first), 1)
        # 2 天后再次满足聚集阈值：冷却窗口内不重复告警
        self._seed("A", 15, self.today + timedelta(days=2))
        raised = analytics.scan(self.svc.store, RULES,
                                (self.today + timedelta(days=2)).date().isoformat())
        self.assertEqual(raised, [])
        self.assertEqual(len(self.svc.list_alerts()["alerts"]), 1)
        # 8 天后（冷却已过）允许新的、不同 ID 的告警
        self._seed("A", 15, self.today + timedelta(days=8))
        far = analytics.scan(self.svc.store, RULES,
                             (self.today + timedelta(days=8)).date().isoformat())
        self.assertEqual(len(far), 1)
        self.assertNotEqual(far[0]["alert_id"], first[0]["alert_id"])

    def test_public_trends_suppress_small_cells_and_no_totals(self):
        self._seed("LOW", 3, self.today)
        self._seed("OK", 7, self.today)
        out = self.svc.public_trends(16)
        top_level = set(out) - {"cells", "note", "suppression_policy",
                                "granularity", "time_bucket", "minimum_cell_count"}
        self.assertFalse(top_level, f"公开输出出现额外聚合字段: {top_level}")
        for cell in out["cells"]:
            self.assertEqual(set(cell), {"region", "day", "count", "status"})
        cells = {(c["region"], c["status"]): c for c in out["cells"]}
        self.assertIsNone(cells[("LOW", "suppressed")]["count"])
        self.assertEqual(cells[("OK", "published")]["count"], 7)

    def test_retention_archives_counts_then_removes_raw(self):
        old = self.today - timedelta(days=91)
        self._seed("OLD", 8, old)
        purged = self.svc.run_retention()["purged_events"]
        self.assertEqual(purged, 8)
        self.assertEqual(self.svc.store.daily_counts(100)["OLD"][old.date().isoformat()], 8)
        rows = self.svc.store._conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE region='OLD'").fetchone()
        self.assertEqual(rows["n"], 0)
        rows = self.svc.store._conn.execute("SELECT COUNT(*) AS n FROM timeline").fetchone()
        self.assertEqual(rows["n"], 0)


class RulebookTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.rules_dir = Path(self.tmp) / "rules"
        self.rules_dir.mkdir()
        shutil.copy(rulebook.RULES_DIR / "v1.0.0.json", self.rules_dir)
        shutil.copy(rulebook.DOMAIN_PATH, Path(self.tmp) / "domain.json")
        self._saved = (rulebook.RULES_DIR, rulebook.MANIFEST_PATH, rulebook.DOMAIN_PATH)
        rulebook.RULES_DIR = self.rules_dir
        rulebook.MANIFEST_PATH = self.rules_dir / "manifest.json"
        rulebook.DOMAIN_PATH = Path(self.tmp) / "domain.json"

    def tearDown(self):
        rulebook.RULES_DIR, rulebook.MANIFEST_PATH, rulebook.DOMAIN_PATH = self._saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_freeze_and_load(self):
        rulebook.freeze()
        rules = rulebook.load_rules()
        self.assertEqual(rules["rule_version"], "1.0.0")

    def test_tampered_file_is_rejected(self):
        rulebook.freeze()
        p = self.rules_dir / "v1.0.0.json"
        p.write_text(p.read_text(encoding="utf-8").replace("2.0", "9.9"), encoding="utf-8")
        with self.assertRaises(rulebook.RuleError):
            rulebook.load_rules()

    def test_domain_misalignment_rejected(self):
        rulebook.freeze()
        domain = json.loads(rulebook.DOMAIN_PATH.read_text(encoding="utf-8"))
        domain["危险信号"].append("皮肤坏死")
        rulebook.DOMAIN_PATH.write_text(json.dumps(domain, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(rulebook.RuleError):
            rulebook.load_rules()

    def test_filename_version_mismatch_rejected(self):
        p = self.rules_dir / "v1.0.0.json"
        data = json.loads(p.read_text(encoding="utf-8"))
        data["rule_version"] = "2.0.0"
        p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        with self.assertRaises(rulebook.RuleError):
            rulebook.freeze(write=False)


class HttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.svc = make_service(cls.tmp)
        service_mod.Handler.service = cls.svc
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), service_mod.Handler)
        cls.port = cls.server.server_address[1]
        import threading
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls._old_key = service_mod.REQUIRE_REVIEW_KEY
        service_mod.REQUIRE_REVIEW_KEY = "secret"

    @classmethod
    def tearDownClass(cls):
        service_mod.REQUIRE_REVIEW_KEY = cls._old_key
        cls.server.shutdown()
        cls.server.server_close()
        cls.svc.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _request(self, method, path, body=None, headers=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_health_and_intake_flow(self):
        status, body = self._request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["rule_version"], RULES["rule_version"])

        status, body = self._request("POST", "/v1/events", dict(GOOD, lesion_signs=["水疱"]))
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"], "ESCALATE_OFFLINE")
        self.assertTrue(body["message"].startswith("【即时处置】"))
        self.assertIn("不能替代医生面诊", body["disclaimer"])
        eid = body["event_id"]

        status, body = self._request("GET", f"/v1/events/{eid}")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["timeline"]), 1)

        status, _ = self._request("GET", "/v1/events/EVT0000000000000000")
        self.assertEqual(status, 404)

    def test_pii_rejected_over_http(self):
        status, body = self._request("POST", "/v1/events", dict(GOOD, 电话="138"))
        self.assertEqual(status, 400)
        self.assertIn("不接收", body["error"])

    def test_internal_endpoints_require_key(self):
        status, _ = self._request("POST", "/v1/alerts/scan", {})
        self.assertEqual(status, 403)
        status, body = self._request("POST", "/v1/alerts/scan", {},
                                     {"X-Internal-Key": "secret"})
        self.assertEqual(status, 200)
        self.assertIn("new_alerts", body)

    def test_public_trends_open(self):
        status, body = self._request("GET", "/v1/trends/public")
        self.assertEqual(status, 200)
        self.assertIn("minimum_cell_count", body)


class SaltTest(unittest.TestCase):
    def test_salt_file_permissions_and_reuse(self):
        tmp = tempfile.mkdtemp()
        path = Path(tmp) / ".salt"
        s1 = load_or_create_salt(path)
        mode = path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)
        s2 = load_or_create_salt(path)
        self.assertEqual(s1, s2)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
