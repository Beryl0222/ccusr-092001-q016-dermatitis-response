"""确定性分级判定引擎。

设计原则：
- 纯函数、无 I/O，同版本规则 + 同一事实必然得到同一结论，便于审计与复测；
- 只接受白名单字段，显式拒绝 PII（姓名、电话、住址等），服务不接收也不存储图片；
- 信息不足时绝不产出“居家观察/无大碍”类低风险结论；
- 每条结论都附带使用的事实(facts)与命中的规则ID(rules)及规则版本。
"""

from __future__ import annotations

from typing import Any

UNKNOWN_TOKENS = {"unknown", "unknown", "不确定", "未知", "不清楚"}

# 显式拒绝的个人标识字段（防止热线误传 PII 进系统）
FORBIDDEN_FIELDS = {
    "姓名", "name", "真实姓名",
    "电话", "手机", "phone", "mobile", "tel", "联系方式",
    "身份证", "id_card", "idcard", "证件号",
    "住址", "地址", "address", "门牌号",
    "微信", "wechat", "qq",
    "学校", "幼儿园", "工作单位", "单位",
    "ip", "email", "邮箱",
    "照片", "图片", "photo", "image", "video", "视频",
    "备注", "留言", "description", "note", "comment",
}

# 允许进入判定的字段白名单（event_id/family_pseudonym 由 API 层处理）
ACCEPTED_FIELDS = {
    "region", "exposure_scenario", "lesion_signs",
    "time_since_exposure_hours", "age_band", "photo_assessment",
    "prior_home_treatments",
}

DISCLAIMER = "本提示为依据现有资料的标准化即时处置建议，不能替代医生面诊诊断。"

# 判定结果类型
DECISION_REQUIRE_INFO = "REQUIRE_INFO"        # 缺少最小必要信息
DECISION_HUMAN_REVIEW = "HUMAN_REVIEW"        # 转人工坐席复核
DECISION_OFFLINE = "ESCALATE_OFFLINE"         # 尽快线下就医（同步转人工）
DECISION_SELF_CARE = "SELF_CARE"              # 冲洗 + 居家观察


class ValidationError(ValueError):
    """提交内容含非法字段或取值越界。"""


def _is_unknown(value: Any) -> bool:
    return value is None or (isinstance(value, str) and value.strip().lower() in UNKNOWN_TOKENS)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()]
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    raise ValidationError(f"取值应为字符串或列表: {value!r}")


def validate_and_normalize(raw: dict, rules: dict) -> dict:
    """白名单校验并把提交内容归一化为可审计事实。"""
    if not isinstance(raw, dict):
        raise ValidationError("请求体必须是 JSON 对象")

    illegal = sorted(set(raw) & FORBIDDEN_FIELDS)
    if illegal:
        raise ValidationError(
            f"系统不接收个人标识或多媒体字段: {'、'.join(illegal)}；"
            "图片仅由坐席线下判读并以 photo_assessment 结论录入"
        )
    unknown_keys = sorted(set(raw) - ACCEPTED_FIELDS - {"event_id", "family_pseudonym"})
    if unknown_keys:
        raise ValidationError(f"未在规则 {rules['rule_version']} 中登记的字段: {'、'.join(unknown_keys)}")

    field_rules = rules["field_rules"]
    facts: dict[str, Any] = {}

    # region：必填，非空字符串，仅做粗粒度地区聚合；未提供则缺键
    if "region" in raw:
        region = raw.get("region")
        if not _is_unknown(region):
            if not isinstance(region, str) or not region.strip():
                raise ValidationError("region 必须是非空字符串（行政区代码或标准化地名）")
            facts["region"] = region.strip()

    # exposure_scenario：枚举或显式 unknown；键缺失表示表单未填
    if "exposure_scenario" in raw:
        scenario = raw["exposure_scenario"]
        enum = field_rules["exposure_scenario"]["values"]
        if _is_unknown(scenario):
            facts["exposure_scenario"] = "unknown"
        else:
            if scenario not in enum:
                raise ValidationError(f"exposure_scenario 必须是 {enum} 或 unknown")
            facts["exposure_scenario"] = scenario

    # lesion_signs：枚举列表或显式 unknown
    if "lesion_signs" in raw:
        signs_raw = raw["lesion_signs"]
        if _is_unknown(signs_raw):
            facts["lesion_signs"] = ["unknown"]
        else:
            signs = _as_list(signs_raw)
            valid = set(field_rules["lesion_signs"]["values"])
            bad = sorted(set(signs) - valid)
            if bad:
                raise ValidationError(f"lesion_signs 含未登记取值: {'、'.join(bad)}；不明表现请使用坐席判读流程")
            facts["lesion_signs"] = signs or ["unknown"]

    # time_since_exposure_hours：数字或 unknown
    if "time_since_exposure_hours" in raw:
        hours = raw["time_since_exposure_hours"]
        if _is_unknown(hours):
            facts["time_since_exposure_hours"] = None
        else:
            if isinstance(hours, bool) or not isinstance(hours, (int, float)):
                raise ValidationError("time_since_exposure_hours 必须是数字或 unknown")
            spec = field_rules["time_since_exposure_hours"]
            if not (spec["min"] <= hours <= spec["max"]):
                raise ValidationError(f"time_since_exposure_hours 超出范围 [{spec['min']},{spec['max']}]")
            facts["time_since_exposure_hours"] = float(hours)

    # age_band：可选枚举
    age_band = raw.get("age_band")
    if age_band is not None:
        if _is_unknown(age_band):
            facts["age_band"] = None
        else:
            valid = set(field_rules["age_band"]["values"])
            if age_band not in valid:
                raise ValidationError(f"age_band 必须是 {sorted(valid)}")
            facts["age_band"] = age_band

    # photo_assessment：坐席人工判读结论，可选枚举
    photo = raw.get("photo_assessment")
    if photo is not None:
        valid = set(field_rules["photo_assessment"]["values"])
        if not _is_unknown(photo) and photo not in valid:
            raise ValidationError(f"photo_assessment 必须是 {sorted(valid)}")
        facts["photo_assessment"] = None if _is_unknown(photo) else photo

    # prior_home_treatments：可选枚举列表
    treatments = raw.get("prior_home_treatments")
    if treatments is not None:
        items = _as_list(treatments)
        valid = set(field_rules["prior_home_treatments"]["values"])
        bad = sorted(set(items) - valid)
        if bad:
            raise ValidationError(
                f"prior_home_treatments 含未登记取值: {'、'.join(bad)}；"
                "未列明的土法请统一记为「不明偏方」"
            )
        facts["prior_home_treatments"] = items
    else:
        facts["prior_home_treatments"] = []

    return facts


def _immediate_actions(facts: dict, rules: dict, *, danger: bool) -> list[dict]:
    actions: list[dict] = []
    hours = facts.get("time_since_exposure_hours")
    for action in rules["immediate_actions"]:
        trigger = action["trigger"]
        if trigger.get("always_for_new_exposure"):
            actions.append({"id": action["id"], "text": action["text"]})
        elif "time_since_exposure_hours_lte" in trigger:
            if hours is not None and hours <= trigger["time_since_exposure_hours_lte"]:
                actions.append({"id": action["id"], "text": action["text"]})
        elif trigger.get("no_danger_sign") and not danger:
            actions.append({"id": action["id"], "text": action["text"]})
    return actions


def _corrections(facts: dict, rules: dict) -> list[dict]:
    table = rules["home_treatment_corrections"]
    out = []
    for item in facts.get("prior_home_treatments", []):
        entry = table.get(item)
        if entry:
            out.append({
                "id": entry["id"],
                "treatment": item,
                "risk": entry["risk"],
                "correction": entry["correction"],
            })
    return out


def evaluate(raw: dict, rules: dict) -> dict:
    """依据规则对一次提交做分级，返回结构化结论与证据链。"""
    facts = validate_and_normalize(raw, rules)

    missing = [f for f in rules["required_minimum_fields"] if f not in facts]
    corrections = _corrections(facts, rules)

    base = {
        "rule_version": rules["rule_version"],
        "facts": facts,
        "missing_fields": missing,
        "fired_rules": [],
        "actions": [],
        "corrections": corrections,
        "level": None,
        "dispatch": None,
        "uncertainties": [],
        "disclaimer": DISCLAIMER,
    }

    # 1) 最小必要信息缺失：只给通用冲洗提示，禁止低风险结论
    if missing:
        base.update({
            "decision": DECISION_REQUIRE_INFO,
            "actions": [
                {"id": a["id"], "text": a["text"]}
                for a in rules["immediate_actions"]
                if a["trigger"].get("always_for_new_exposure")
            ],
            "advice_text": (
                "资料尚不足以分级（缺少：" + "、".join(missing) +
                "）。请先立即用大量清水冲洗接触部位；不要涂抹牙膏、酒精、碘伏或其他偏方。"
                "请补充上述信息或等待人工坐席，在此之前请勿据此判断情况轻微。"
            ),
        })
        base["uncertainties"].append("缺少最小必要字段，未给出风险分级")
        return base

    signs = set(facts["lesion_signs"])
    fired: list[str] = []
    danger_signs = sorted(signs & set(rules["danger_signs"]))
    danger = bool(danger_signs)

    # 2) 危险信号 → 尽快就医 + 转人工
    if danger:
        rule = rules["escalation_rules"][0]
        fired.append(rule["id"])
        base["fired_rules"] = fired
        base.update({
            "decision": DECISION_OFFLINE,
            "level": rule["level"],
            "dispatch": rule["dispatch"],
            "matched_danger_signs": danger_signs,
            "actions": _immediate_actions(facts, rules, danger=True),
            "advice_text": rule["advice"],
        })
        base["corrections"] = corrections
        return base

    # 3) 升级类规则（婴幼儿、照片不可判读）
    review_reasons: list[str] = []
    for rule in rules["escalation_rules"][1:]:
        when = rule["when"]
        hit = True
        if "age_band_in" in when and facts.get("age_band") not in when["age_band_in"]:
            hit = False
        if "and_any_lesion_sign_in" in when and not (signs & set(when["and_any_lesion_sign_in"])):
            hit = False
        if "photo_assessment_in" in when and facts.get("photo_assessment") not in when["photo_assessment_in"]:
            hit = False
        if hit:
            fired.append(rule["id"])
            review_reasons.append(rule["advice"])

    # 4) 皮损情况未知且无照片结论 → 人工复核（不得低风险）
    lesion_unknown = signs == {"unknown"} or not signs
    photo_ok = facts.get("photo_assessment") == "清晰可判读"
    if lesion_unknown and not photo_ok:
        base["uncertainties"].append("皮损表现未确认，且无清晰可判读的照片结论")
        review_reasons.append(
            rules["insufficient_info_policy"]["text"]
        )

    if review_reasons:
        base["fired_rules"] = fired
        base.update({
            "decision": DECISION_HUMAN_REVIEW,
            "level": "人工复核",
            "dispatch": "human_agent",
            "actions": _immediate_actions(facts, rules, danger=False),
            "advice_text": " ".join(review_reasons),
        })
        return base

    # 5) 信息完整且无危险信号：立即冲洗 + 居家观察
    base["fired_rules"] = fired
    base.update({
        "decision": DECISION_SELF_CARE,
        "level": "居家观察",
        "dispatch": None,
        "actions": _immediate_actions(facts, rules, danger=False),
        "advice_text": (
            "目前资料未见大面积红斑、水疱、密集脓疱或糜烂渗出等危险信号，"
            "请按上述冲洗与冷湿敷建议处置并居家观察；若皮损范围扩大、出现水疱脓疱或糜烂渗液，"
            "立即停止自行处理并尽快就医。"
        ),
    })
    if facts["exposure_scenario"] == "unknown":
        base["uncertainties"].append("暴露场景未确认")
    if facts.get("time_since_exposure_hours") is None:
        base["uncertainties"].append("暴露时间未确认，6小时内肥皂水清洗建议无法判定是否适用")
    return base


def build_message(result: dict) -> str:
    """把结构化结论拼成可发送给家长的文本（含边界声明）。"""
    parts = []
    if result["actions"]:
        parts.append("【即时处置】")
        parts.extend(f"{a['id']} {a['text']}" for a in result["actions"])
    if result["corrections"]:
        parts.append("【关于已使用的处理方式】")
        for c in result["corrections"]:
            parts.append(f"{c['id']}（{c['treatment']}）{c['risk']} {c['correction']}")
    parts.append("【分级建议】")
    level = result["level"] or "暂不分级"
    parts.append(f"{result['decision']}｜建议等级：{level}。{result['advice_text']}")
    parts.append(DISCLAIMER)
    return "\n".join(parts)
