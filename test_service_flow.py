"""端到端测试：家庭合并、纠正轨迹、单调升级、审计、趋势抑制、唯一告警、HTTP 边界。"""

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from triage_rules import RulePack
from store import Store
from hotline import HotlineService
import service as service_mod

MILD = {"疑似虫体接触": True, "部位": ["四肢"], "皮损表现": ["线状红斑"]}
RULES_DIR = Path(__file__).parent / "rules"


class FrozenClock:
    def __init__(self, start=1_790_000_000.0):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, hours):
        self.t += hours * 3600


class FlowTest(unittest.TestCase):

    def setUp(self):
        self.clock = FrozenClock()
        self.store = Store(":memory:", salt="unit-test-salt", now=self.clock)
        self.pops = {"R001": 80000, "R002": 60000, "tiny": 100}
        self.svc = HotlineService(self.store, RulePack.load(RULES_DIR), self.pops)

    # ---- 事件合并 -------------------------------------------------------

    def test_same_family_supplements_merge_into_original_event(self):
        first = self.svc.intake("13900000001", "R001",
                                {**MILD, "已采用处理": ["牙膏"]})
        self.assertTrue(first["新事件"])
        event_id = first["事件号"]

        self.clock.advance(3)
        second = self.svc.intake("13900000001", "R001", {"皮损表现": ["水疱"]})
        self.assertFalse(second["新事件"])
        self.assertTrue(second["合并于原事件"])
        self.assertEqual(second["事件号"], event_id)
        self.assertEqual(second["资料批次"], 2)

        # 另一户是独立事件
        other = self.svc.intake("13900000002", "R001", MILD)
        self.assertTrue(other["新事件"])
        self.assertNotEqual(other["事件号"], event_id)

    def test_contact_hash_strips_spacing_and_merges(self):
        a = self.svc.intake(" 13900000003 ", "R001", MILD)
        b = self.svc.intake("13900000003", "R001", {"皮损表现": ["瘙痒"]})
        self.assertEqual(a["事件号"], b["事件号"])

    # ---- 纠正轨迹 -------------------------------------------------------

    def test_correction_trail_is_tracked(self):
        r1 = self.svc.intake("13900000004", "R001", {**MILD, "已采用处理": ["牙膏"]})
        event_id = r1["事件号"]
        self.assertEqual(r1["纠正"][0]["追踪"], "issued")

        self.clock.advance(1)
        r2 = self.svc.intake("13900000004", "R001",
                             {"皮损表现": ["灼痛"], "已采用处理": ["牙膏"]})
        self.assertEqual(r2["纠正"][0]["追踪"], "repeated")

        # 随访确认停用后，不再重复纠正
        self.clock.advance(1)
        self.svc.intake("13900000004", "R001", {"随访确认": True},
                        stopped_treatments=["牙膏"])
        r3 = self.svc.intake("13900000004", "R001", {"皮损表现": ["灼痛"]})
        self.assertEqual(r3["纠正"], [])

        actions = [row["action"] for row in self.store.correction_trail(event_id)]
        self.assertEqual(actions, ["issued", "repeated", "confirmed_stopped"])

    # ---- 单调性与审计 ----------------------------------------------------

    def test_escalation_is_monotonic(self):
        r1 = self.svc.intake("13900000005", "R001", MILD)
        self.assertEqual(r1["等级"], "居家观察")
        self.clock.advance(1)
        # 报告大面积（12%）升级尽快就医
        r2 = self.svc.intake("13900000005", "R001", {"范围占体表面积百分比": 12})
        self.assertEqual(r2["等级"], "尽快就医")
        self.clock.advance(1)
        # 家属改口把面积说成 3%：标量以后报为准，自动流程也不得降级，
        # 由 S-MONOTONIC 兜底维持原等级，等人工核实
        r3 = self.svc.intake("13900000005", "R001", {"范围占体表面积百分比": 3})
        self.assertEqual(r3["等级"], "尽快就医")
        ids = {m["id"] for m in r3["依据"]["命中规则"]}
        self.assertIn("S-MONOTONIC", ids)

        # 累积性事实（糜烂渗出一旦报告）则由规则本身持续命中，双保险
        self.clock.advance(1)
        r4 = self.svc.intake("13900000015", "R001",
                             {**MILD, "皮损表现": ["线状红斑", "糜烂渗出"]})
        self.clock.advance(1)
        r5 = self.svc.intake("13900000015", "R001", {"皮损表现": ["瘙痒"]})
        self.assertEqual(r5["等级"], "尽快就医")
        self.assertIn("R-EMERG-EROSION", {m["id"] for m in r5["依据"]["命中规则"]})

    def test_every_response_is_audited_with_facts_and_rules(self):
        r = self.svc.intake("13900000006", "R001", {**MILD, "已采用处理": ["碘伏"]})
        record = self.svc.event_record(r["事件号"])
        self.assertEqual(len(record["响应记录"]), 1)
        audit = record["响应记录"][0]
        self.assertTrue(audit["规则版本"])
        self.assertTrue(audit["命中规则"])
        self.assertIn("碘伏", audit["事实快照"]["已采用处理"])
        self.assertEqual(len(record["事实批次"]), 1)

    # ---- 入参边界 -------------------------------------------------------

    def test_free_text_address_rejected(self):
        with self.assertRaises(ValueError):
            self.svc.intake("13900000007", "XX路12号3栋", MILD)

    def test_short_contact_rejected(self):
        with self.assertRaises(ValueError):
            self.svc.intake("12", "R001", MILD)

    def test_unknown_fact_fields_rejected(self):
        with self.assertRaises(ValueError):
            self.svc.intake("13900000017", "R001", {**MILD, "照片base64": "AAAA"})
        with self.assertRaises(ValueError):
            self.svc.intake("13900000018", "R001", {**MILD, "详细地址": "某路某号"})

    def test_long_free_text_in_enum_rejected(self):
        with self.assertRaises(ValueError):
            self.svc.intake("13900000019", "R001",
                            {**MILD, "皮损表现": ["红斑" * 20]})

    def test_no_raw_contact_persisted(self):
        contact = "13900008888"
        self.svc.intake(contact, "R001", MILD)
        tables = [r[0] for r in self.store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            cols = [r[1] for r in self.store.conn.execute(f"PRAGMA table_info({table})")]
            for col in cols:
                rows = self.store.conn.execute(
                    f"SELECT CAST({col} AS TEXT) FROM {table} WHERE {col} IS NOT NULL")
                for (value,) in rows:
                    self.assertNotIn(contact, value or "")

    # ---- 趋势与告警 ------------------------------------------------------

    def test_trends_k_anonymity_suppresses_small_cells(self):
        for i in range(3):
            self.svc.intake(f"1391000000{i}", "R001", MILD)
        report = self.svc.trends(self.clock.t - 10 * 86400, until=self.clock.t + 1)
        # 3 户 < k(5)，R001 整体抑制
        self.assertNotIn("R001", report["序列"])

    def test_trends_publish_above_k_and_count_families_once(self):
        for i in range(6):
            self.svc.intake(f"1392000000{i}", "R002", MILD)
        # 其中一户多次补充，不应重复计数
        self.svc.intake("13920000000", "R002", {"皮损表现": ["瘙痒"]})
        report = self.svc.trends(self.clock.t - 10 * 86400, until=self.clock.t + 1)
        (series,) = report["序列"].values()
        self.assertEqual(list(series.values())[0], 6)

    def test_small_population_region_never_published(self):
        for i in range(6):
            self.svc.intake(f"1393000000{i}", "tiny", MILD)
        report = self.svc.trends(self.clock.t - 10 * 86400, until=self.clock.t + 1)
        self.assertNotIn("tiny", report["序列"])

    def test_cluster_alert_unique_and_family_based(self):
        # 1 户多次来电 + 另外 3 户 = 4 户，虽事件互动很多但不达 5 户阈值
        for _ in range(6):
            self.svc.intake("13940000000", "R002", MILD)
        for i in range(1, 4):
            self.svc.intake(f"1394000000{i}", "R002", MILD)
        created, _ = self.svc.scan_clusters(now_ts=self.clock.t + 1)
        self.assertEqual(created, [])

        # 再增 2 户达到 5 户阈值
        for i in range(4, 6):
            self.svc.intake(f"1394000000{i}", "R002", MILD)
        created, existing = self.svc.scan_clusters(now_ts=self.clock.t + 1)
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0]["region"], "R002")
        # 同一窗口重复扫描不再产生新告警
        again, _ = self.svc.scan_clusters(now_ts=self.clock.t + 1)
        self.assertEqual(again, [])
        total = self.store.conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
        self.assertEqual(total, 1)

    def test_alert_blocked_for_small_population_region(self):
        for i in range(6):
            self.svc.intake(f"1395000000{i}", "tiny", MILD)
        created, _ = self.svc.scan_clusters(now_ts=self.clock.t + 1)
        self.assertEqual(created, [])


class HttpTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db_path = str(Path(self.tmp.name) / "test.db")
        pop_path = str(Path(self.tmp.name) / "pops.json")
        Path(pop_path).write_text(json.dumps({"R001": 80000}), encoding="utf-8")
        self.svc, pack = service_mod.build_service(db_path, str(RULES_DIR), pop_path,
                                                   salt="http-salt")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0),
                                          service_mod.make_handler(self.svc, pack))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def _request(self, method, path, payload=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_health_reports_rule_version(self):
        status, body = self._request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["service"], "dermatitis-response")
        self.assertTrue(body["规则版本"])

    def test_intake_and_trends_over_http(self):
        status, body = self._request("POST", "/v1/intake",
                                     {"contact": "13960000001", "region": "R001", "facts": MILD})
        self.assertEqual(status, 200)
        self.assertEqual(body["等级"], "居家观察")
        self.assertIn("不能替代", body["边界声明"])
        self.assertIn("依据", body)

        status, body = self._request("GET", "/v1/trends?since=1")
        self.assertEqual(status, 200)
        self.assertIn("k_匿名", body)

    def test_http_rejects_free_text_region(self):
        status, body = self._request("POST", "/v1/intake",
                                     {"contact": "13960000002",
                                      "region": "某街道某小区1号", "facts": MILD})
        self.assertEqual(status, 400)
        self.assertIn("区域", body["错误"])

    def test_http_rejects_oversized_body(self):
        big = {"contact": "13960000003", "region": "R001",
               "facts": {"备注": "x" * 20000}}
        status, _ = self._request("POST", "/v1/intake", big)
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
