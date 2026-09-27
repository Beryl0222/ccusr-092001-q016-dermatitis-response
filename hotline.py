"""热线事件编排：接报、家庭合并、分级调用、纠正生命周期与状态流转。

编排层不产生医学结论，结论只来自当前版本的规则包；每次回复都持久化
所用事实、规则版本与命中规则。线上回复一律附带边界声明，不冒充诊断。
"""

import re

from triage_rules import evaluate
from analytics import scan_clusters

REGION_RE = re.compile(r"^[A-Za-z0-9_-]{2,16}$")
CONTACT_MIN_LEN = 4

# 自动分级对应的事件状态
_LEVEL_STATUS = {"立即冲洗": "open", "居家观察": "open",
                 "人工复核": "review", "尽快就医": "escalated_care"}

_LIST_KEYS = ("暴露场景", "部位", "皮损表现", "已采用处理")
_BOOL_KEYS = ("疑似虫体接触", "发热", "随访确认")
_SCALAR_KEYS = ("人群", "范围占体表面积百分比", "症状持续小时")

# 这些标量在补充资料中发生变化属于前后矛盾，需要人工复核
_IMMUTABLE_OR_FUNDAMENTAL = ("人群",)


class HotlineError(ValueError):
    """入参不合法（含疑似把自由文本当作区域编码等隐私风险）。"""


def _validate_contact(contact):
    if not isinstance(contact, str) or len(contact.strip()) < CONTACT_MIN_LEN:
        raise HotlineError("联系方式缺失或过短")
    return contact.strip()


def _validate_region(region):
    if not isinstance(region, str) or not REGION_RE.match(region):
        raise HotlineError("区域必须为2-16位编码（字母数字/_-），不得提交地址文本")
    return region


def _validate_facts_shape(pack, facts):
    """最少必要信息：只接受规则包登记的事实键，且值必须是短标量/短枚举数组。

    以此拒绝照片、base64、长段自由文本等任何非约定材料。
    """
    allowed = set(pack.enums["事实键"])
    unknown = set(facts) - allowed
    if unknown:
        raise HotlineError(f"非约定事实字段，本服务不收集：{sorted(unknown)}")
    list_keys = ("暴露场景", "部位", "皮损表现", "已采用处理")
    for key in list_keys:
        if key not in facts:
            continue
        values = facts[key]
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or not all(
                isinstance(v, str) and 0 < len(v) <= 30 for v in values):
            raise HotlineError(f"{key}必须是不超过30字的枚举值数组")
    for key in ("疑似虫体接触", "发热", "随访确认"):
        if key in facts and not isinstance(facts[key], bool):
            raise HotlineError(f"{key}必须是布尔值")
    if "人群" in facts and (not isinstance(facts["人群"], str) or len(facts["人群"]) > 20):
        raise HotlineError("人群必须是不超过20字的枚举值")
    for key in ("范围占体表面积百分比", "症状持续小时"):
        value = facts.get(key)
        if value is not None and (isinstance(value, bool)
                                  or not isinstance(value, (int, float)) or value < 0):
            raise HotlineError(f"{key}必须是非负数值")


def merge_facts(entries):
    """把同一事件历次补充资料重放为当前事实快照，并产出矛盾说明。

    列表类事实（皮损、处理等）按时间并集；标量以后来的非空值为准；
    基础判断（是否接触）前后反复、不可变属性变化记为矛盾。
    """
    merged = {key: [] for key in _LIST_KEYS}
    merged.update({key: None for key in _BOOL_KEYS + _SCALAR_KEYS})
    contradictions = []

    prev_contact_flag = None
    immutable_seen = {}
    for entry in entries:
        facts = entry["normalized_facts"]
        for key in _LIST_KEYS:
            for value in facts.get(key) or []:
                if value not in merged[key]:
                    merged[key].append(value)
        for key in _BOOL_KEYS:
            value = facts.get(key)
            if value is not None:
                if key == "疑似虫体接触" and prev_contact_flag is not None \
                        and value != prev_contact_flag:
                    contradictions.append(f"疑似虫体接触由{'是' if prev_contact_flag else '否'}"
                                          f"改为{'是' if value else '否'}")
                if key == "疑似虫体接触":
                    prev_contact_flag = value
                merged[key] = value
        for key in _SCALAR_KEYS:
            value = facts.get(key)
            if value is not None:
                if key in _IMMUTABLE_OR_FUNDAMENTAL and key in immutable_seen \
                        and immutable_seen[key] != value:
                    contradictions.append(f"{key}前后不一致")
                immutable_seen.setdefault(key, value)
                # 可变标量（如症状持续小时）以后报值为准；不可变属性变化记矛盾但也采用最新值
                merged[key] = value
    merged["皮损表现"] = sorted(merged["皮损表现"])
    merged["已采用处理"] = sorted(merged["已采用处理"])
    merged["部位"] = sorted(merged["部位"])
    merged["暴露场景"] = sorted(merged["暴露场景"])
    return merged, sorted(set(contradictions))


def _active_treatments(store, event_id, entries, merged):
    """结合停用确认，判断哪些已报告处理当前仍在使用。"""
    stops = {}
    for row in store.correction_trail(event_id):
        if row["action"] == "confirmed_stopped":
            stops[row["treatment"]] = row["at"]
    last_report = {}
    for entry in entries:
        for treatment in entry["normalized_facts"].get("已采用处理") or []:
            last_report[treatment] = entry["received_at"]
    return sorted(t for t in merged["已采用处理"]
                  if t not in stops or last_report.get(t, 0) >= stops[t])


class HotlineService:
    def __init__(self, store, pack, region_populations=None):
        self.store = store
        self.pack = pack
        self.region_populations = region_populations or {}

    # ---- 接报 ----------------------------------------------------------

    def intake(self, contact, region, facts, source="热线来电", stopped_treatments=None):
        """接收一次来电或补充资料，返回对外回复内容（不含任何诊断用语）。"""
        contact = _validate_contact(contact)
        region = _validate_region(region)
        if not isinstance(facts, dict):
            raise HotlineError("事实必须为对象")
        _validate_facts_shape(self.pack, facts)
        if stopped_treatments is not None and (
                not isinstance(stopped_treatments, list)
                or not all(isinstance(t, str) and len(t) <= 30 for t in stopped_treatments)):
            raise HotlineError("stopped_treatments 必须是处理名称数组")

        family_id, family_created = self.store.find_or_create_family(contact, region)
        event = self.store.open_event(family_id)
        new_event = event is None
        if new_event:
            event_id = self.store.create_event(family_id)
        else:
            event_id = event["event_id"]

        if stopped_treatments:
            self.store.confirm_correction_stopped(event_id, list(stopped_treatments))

        seq = self.store.append_facts(event_id, facts,
                                      _pre_normalize(facts), source)
        entries = self.store.fact_entries(event_id)
        merged, contradictions = merge_facts(entries)

        active = _active_treatments(self.store, event_id, entries, merged)
        effective = dict(merged)
        effective["已采用处理"] = active

        result = evaluate(self.pack, effective, contradictions=contradictions)
        # 单调性：事件一旦因证据升级，后续补充资料不得由自动流程降级；
        # 每次评估本身仍完整落库，是否降级只能由人工坐席判断。
        if event is not None and event["current_level"]:
            prev_level = event["current_level"]
            if self.pack.level_rank(prev_level) > self.pack.level_rank(result["等级"]):
                result["等级"] = prev_level
                result["命中规则"].insert(
                    0, {"id": "S-MONOTONIC", "等级": prev_level,
                        "理由": f"事件此前已评估为{prev_level}，自动流程不降级，维持原等级由人工跟进。"})
                prior = next((r for r in reversed(self.store.responses(event_id))
                              if r["level"] == prev_level), None)
                if prior:
                    have = {t["id"] for t in result["安全提示"]}
                    result["安全提示"].extend(t for t in prior["tips"] if t["id"] not in have)
        response_id = self.store.save_response(event_id, result)
        correction_actions = self.store.record_corrections(
            event_id, response_id, [c["处理"] for c in result["需要纠正"]])
        self.store.set_event_level(event_id, result["等级"])

        new_status = _LEVEL_STATUS[result["等级"]]
        if event is None:
            if new_status != "open":
                self.store.transition_status(
                    event_id, new_status, f"自动分级：{result['等级']}", response_id)
        elif event["status"] != new_status:
            self.store.transition_status(
                event_id, new_status, f"自动分级：{result['等级']}", response_id)

        return {
            "事件号": event_id,
            "新事件": new_event,
            "合并于原事件": not new_event,
            "资料批次": seq,
            "等级": result["等级"],
            "建议文本": [t["文本"] for t in result["安全提示"]],
            "纠正": [{"处理": c["处理"], "风险": c["风险"], "纠正指令": c["纠正指令"],
                      "追踪": next((a["动作"] for a in correction_actions
                                    if a["处理"] == c["处理"]), "active")}
                     for c in result["需要纠正"]],
            "仍需补充": result["缺失事实"],
            "无法解释的信息": result["异常事实"],
            "前后矛盾": result["矛盾事实"],
            "依据": {"规则版本": result["规则版本"],
                    "命中规则": [{"id": m["id"], "理由": m["理由"]} for m in result["命中规则"]]},
            "边界声明": result["边界声明"],
            "事件状态": new_status,
        }

    # ---- 人工坐席动作 ---------------------------------------------------

    def agent_transition(self, event_id, to_status, reason):
        allowed = {"open", "review", "escalated_care", "closed"}
        if to_status not in allowed:
            raise HotlineError("非法状态")
        self.store.transition_status(event_id, to_status, reason)
        return {"事件号": event_id, "事件状态": to_status}

    def event_record(self, event_id):
        """返回事件处置轨迹：事实批次、响应审计、纠正轨迹。"""
        responses = self.store.responses(event_id)
        return {
            "事件号": event_id,
            "事实批次": self.store.fact_entries(event_id),
            "响应记录": [{"response_id": r["response_id"], "created_at": r["created_at"],
                          "规则版本": r["rule_version"], "等级": r["level"],
                          "事实快照": r["fact_snapshot"], "命中规则": r["matched_rules"],
                          "缺失": r["missing"], "异常": r["anomalies"],
                          "矛盾": r["contradictions"]} for r in responses],
            "纠正轨迹": self.store.correction_trail(event_id),
        }

    # ---- 分析 -----------------------------------------------------------

    def trends(self, since, until=None):
        from analytics import trends as _trends
        return _trends(self.store, self.pack, since, until, self.region_populations)

    def scan_clusters(self, now_ts=None):
        return scan_clusters(self.store, self.pack, now_ts, self.region_populations)


def _pre_normalize(facts):
    """落库前的轻量归一化（字段已通过形状校验）。"""
    out = {}
    for key in _LIST_KEYS:
        values = facts.get(key) or []
        if isinstance(values, str):
            values = [values]
        out[key] = sorted(set(values)) if isinstance(values, list) else []
    for key in _BOOL_KEYS:
        out[key] = facts.get(key)
    for key in _SCALAR_KEYS:
        out[key] = facts.get(key)
    return out
