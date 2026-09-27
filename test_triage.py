"""规则引擎测试：分级、不足兜底、危险信号不被拉低、偏方纠正。"""

import json
import unittest
from pathlib import Path

from triage_rules import RulePack, evaluate, INSUFFICIENT_ID, RulePackError

PACK = RulePack.load(Path(__file__).parent / "rules")


def result(facts, contradictions=None):
    return evaluate(PACK, facts, contradictions=contradictions)


class TriageTest(unittest.TestCase):

    def test_mild_contact_rinse_and_home(self):
        r = result({"疑似虫体接触": True, "部位": ["四肢"],
                    "皮损表现": ["线状红斑", "灼痛"]})
        self.assertEqual(r["等级"], "居家观察")
        ids = {m["id"] for m in r["命中规则"]}
        self.assertIn("R-RINSE-CONTACT", ids)
        self.assertIn("R-HOME-MILD", ids)
        # 冲洗提示必须随接触给出
        self.assertIn("rinse-water", {t["id"] for t in r["安全提示"]})

    def test_danger_signs_escalate(self):
        for sign in ("糜烂渗出", "密集脓疱"):
            with self.subTest(sign=sign):
                r = result({"疑似虫体接触": True, "部位": ["躯干"], "皮损表现": [sign]})
                self.assertEqual(r["等级"], "尽快就医")
        r = result({"疑似虫体接触": True, "部位": ["面颈"], "皮损表现": ["水疱"]})
        self.assertEqual(r["等级"], "尽快就医")

    def test_insufficient_never_low_risk(self):
        r = result({"疑似虫体接触": True})
        self.assertEqual(r["等级"], "人工复核")
        self.assertTrue(r["缺失事实"])
        self.assertEqual(r["命中规则"][0]["id"], INSUFFICIENT_ID)
        # 空事实同样不得落到居家观察
        r = result({})
        self.assertEqual(r["等级"], "人工复核")

    def test_danger_signal_with_missing_facts_still_er(self):
        """资料不足但已出现危险信号：等级取兜底与命中规则的最高者。"""
        r = result({"皮损表现": ["大面积红斑", "糜烂渗出"]})
        self.assertEqual(r["等级"], "尽快就医")
        self.assertIn("疑似虫体接触", r["缺失事实"])
        ids = {m["id"] for m in r["命中规则"]}
        self.assertIn(INSUFFICIENT_ID, ids)
        self.assertIn("R-EMERG-EROSION", ids)

    def test_uninterpretable_values_not_low_risk(self):
        r = result({"疑似虫体接触": True, "部位": ["四肢"],
                    "皮损表现": ["片状红斑"], "症状持续小时": "很久"})
        self.assertEqual(r["等级"], "人工复核")
        self.assertTrue(r["异常事实"])

    def test_unknown_enum_value_not_low_risk(self):
        r = result({"疑似虫体接触": True, "部位": ["四肢"],
                    "皮损表现": ["片状红斑", "随便写的"]})
        self.assertEqual(r["等级"], "人工复核")
        self.assertTrue(any("未知取值" in p for p in r["异常事实"]))

    def test_contradiction_denies_contact_but_reports_lesion(self):
        r = result({"疑似虫体接触": False, "部位": ["四肢"], "皮损表现": ["水疱"]})
        # 矛盾不允许低风险结论；四肢水疱本身即需人工复核
        self.assertEqual(r["等级"], "人工复核")
        self.assertTrue(r["矛盾事实"])
        self.assertIn("R-REVIEW-BLISTER", {m["id"] for m in r["命中规则"]})

    def test_explicit_contradictions_force_review(self):
        r = result({"疑似虫体接触": True, "部位": ["四肢"],
                    "皮损表现": ["线状红斑"]}, contradictions=["前后说法不一"])
        self.assertEqual(r["等级"], "人工复核")

    def test_dangerous_home_remedies_corrected(self):
        r = result({"疑似虫体接触": True, "部位": ["四肢"],
                    "皮损表现": ["片状红斑"],
                    "已采用处理": ["牙膏", "酒精", "碘伏"]})
        names = {c["处理"] for c in r["需要纠正"]}
        self.assertEqual(names, {"牙膏", "酒精", "碘伏"})
        for c in r["需要纠正"]:
            self.assertTrue(c["纠正指令"])
            self.assertTrue(c["风险"])

    def test_large_area_threshold(self):
        r = result({"疑似虫体接触": True, "部位": ["多处"],
                    "皮损表现": ["片状红斑"], "范围占体表面积百分比": 10})
        self.assertEqual(r["等级"], "尽快就医")
        self.assertIn("R-EMERG-LARGE-AREA", {m["id"] for m in r["命中规则"]})

    def test_every_reply_carries_boundary_and_version(self):
        r = result({"疑似虫体接触": True, "部位": ["四肢"], "皮损表现": ["瘙痒"]})
        self.assertTrue(r["边界声明"])
        self.assertEqual(r["规则版本"], PACK.version)
        self.assertIn("不能替代", r["边界声明"])

    def test_domain_alignment(self):
        domain = json.loads((Path(__file__).parent / "domain.json").read_text(encoding="utf-8"))
        PACK.cross_check_domain(domain)  # 不抛异常即通过

    def test_invalid_pack_rejected(self):
        bad = json.loads(json.dumps(PACK.data))
        bad["分级规则"][0]["等级"] = "不存在的等级"
        with self.assertRaises(RulePackError):
            RulePack(bad)


if __name__ == "__main__":
    unittest.main()
