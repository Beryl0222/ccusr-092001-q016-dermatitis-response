"""版本化规则引擎：依据事实快照计算分级建议。

引擎不内置任何医学结论，全部口径来自规则包 JSON。资料不足、事实无法解释
或互相矛盾时固定升级为“人工复核”，且永不输出低于已有证据的等级。
"""

import json
import re
from pathlib import Path

# 不足兜底在响应中的固定标识，便于审计检索
INSUFFICIENT_ID = "S-INSUFFICIENT"

_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


class RulePackError(ValueError):
    """规则包结构或引用不合法。"""


class RulePack:
    """不可变规则包的加载与校验。"""

    def __init__(self, data, source=None):
        self.data = data
        self.source = source
        self.version = data.get("pack_version")
        self.validate()

    @classmethod
    def load(cls, path):
        path = Path(path)
        if path.is_dir():
            packs = sorted(path.glob("pack-*.json"),
                           key=lambda p: _semver_key(p.stem[len("pack-"):]))
            if not packs:
                raise RulePackError(f"目录 {path} 下没有规则包")
            path = packs[-1]
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        return cls(data, source=str(path))

    @property
    def enums(self):
        return self.data["枚举"]

    @property
    def levels(self):
        return self.enums["建议等级"]

    def validate(self):
        data = self.data
        for key in ("pack_version", "枚举", "危险处理", "安全提示", "分级规则",
                    "基础事实要求", "不足处置", "等级优先级", "分析参数"):
            if key not in data:
                raise RulePackError(f"规则包缺少字段：{key}")
        if not _SEMVER_RE.match(str(self.version)):
            raise RulePackError(f"规则版本不是语义版本号：{self.version}")

        enums = self.enums
        for name in ("暴露场景", "皮损表现", "部位", "建议等级", "事实键"):
            if name not in enums or not isinstance(enums[name], list):
                raise RulePackError(f"枚举缺失或不是列表：{name}")

        known_levels = set(self.levels)
        if set(data["等级优先级"]) != known_levels:
            raise RulePackError("等级优先级必须且只能覆盖全部建议等级")

        for item in data["危险处理"]:
            for key in ("处理", "风险", "纠正指令"):
                if not item.get(key):
                    raise RulePackError(f"危险处理条目缺少 {key}")

        for tip in data["安全提示"]:
            if tip["等级"] not in known_levels:
                raise RulePackError(f"安全提示引用未知等级：{tip['id']}")

        for rule in data["分级规则"]:
            if rule["等级"] not in known_levels:
                raise RulePackError(f"规则 {rule.get('id')} 引用未知等级")
            self._validate_condition(rule.get("id"), rule.get("条件", {}), enums)

        if data["不足处置"]["等级"] not in known_levels:
            raise RulePackError("不足处置等级非法")
        params = data["分析参数"]
        for key in ("k_匿名", "趋势最小单元数", "聚集窗口小时", "聚集基线倍数", "聚集最小增量"):
            if not isinstance(params[key], (int, float)) or params[key] <= 0:
                raise RulePackError(f"分析参数非法：{key}")
        return True

    def _validate_condition(self, rule_id, cond, enums):
        for value in cond.get("事实包含任一", []):
            if value not in enums["皮损表现"]:
                raise RulePackError(f"规则 {rule_id} 引用未知皮损表现：{value}")
        for value in cond.get("部位包含任一", []):
            if value not in enums["部位"]:
                raise RulePackError(f"规则 {rule_id} 引用未知部位：{value}")
        for key in cond.get("事实", {}):
            if key not in enums["事实键"]:
                raise RulePackError(f"规则 {rule_id} 引用未知事实键：{key}")
        for key in cond.get("数值不小于", {}):
            if key not in enums["事实键"]:
                raise RulePackError(f"规则 {rule_id} 引用未知数值事实：{key}")

    def cross_check_domain(self, domain):
        """与 domain.json 的公共分类法对齐检查。"""
        for key in ("暴露场景", "危险信号", "建议等级"):
            enum_name = {"危险信号": "皮损表现"}.get(key, key)
            missing = set(domain[key]) - set(self.enums[enum_name])
            if missing:
                raise RulePackError(f"规则包未覆盖 domain.json 中的 {key}：{sorted(missing)}")

    def level_rank(self, level):
        return self.data["等级优先级"][level]


def _semver_key(version):
    return tuple(int(part) for part in _SEMVER_RE.match(version).groups())


def normalize_facts(raw, enums):
    """归一化输入事实，返回 (facts, problems)。

    problems 收集无法解释或越界的取值；任一问题存在即不得低风险分级。
    """
    facts = {}
    problems = []

    list_keys = ("暴露场景", "部位", "皮损表现", "已采用处理")
    for key in list_keys:
        values = raw.get(key) or []
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            problems.append(f"{key}取值无法解释")
            values = []
        facts[key] = sorted({str(v) for v in values if v})

    for key in ("疑似虫体接触", "发热", "随访确认"):
        value = raw.get(key)
        if value is not None and not isinstance(value, bool):
            problems.append(f"{key}取值无法解释")
            value = None
        facts[key] = value

    value = raw.get("人群")
    if value is not None and not isinstance(value, str):
        problems.append("人群取值无法解释")
        value = None
    facts["人群"] = value

    for key in ("范围占体表面积百分比", "症状持续小时"):
        num = raw.get(key)
        if num is None:
            facts[key] = None
        elif isinstance(num, bool) or not isinstance(num, (int, float)) or num < 0:
            problems.append(f"{key}取值无法解释")
            facts[key] = None
        else:
            facts[key] = float(num)

    enum_map = {"暴露场景": "暴露场景", "部位": "部位", "皮损表现": "皮损表现"}
    for key, enum_name in enum_map.items():
        allowed = set(enums[enum_name])
        for value in facts[key]:
            if value not in allowed:
                problems.append(f"{key}含未知取值：{value}")
    return facts, problems


def _rule_matches(cond, facts):
    if "事实包含任一" in cond and not set(cond["事实包含任一"]) & set(facts["皮损表现"]):
        return False
    if "部位包含任一" in cond and not set(cond["部位包含任一"]) & set(facts["部位"]):
        return False
    for key, expected in cond.get("事实", {}).items():
        if facts.get(key) != expected:
            return False
    for key, threshold in cond.get("数值不小于", {}).items():
        value = facts.get(key)
        if value is None or value < threshold:
            return False
    return True


def evaluate(pack, raw_facts, contradictions=None):
    """依据规则包对事实快照分级。

    contradictions：同一事件历史中无法同时成立的事实描述（如先否认接触后承认），
    存在矛盾时同样触发不足兜底。
    """
    facts, problems = normalize_facts(raw_facts, pack.enums)
    contradictions = list(contradictions or [])

    missing = [key for key in pack.data["基础事实要求"]
               if facts.get(key) is None or facts.get(key) == []]
    if facts.get("疑似虫体接触") is False and (facts["皮损表现"] or facts["部位"]):
        # 否认虫体接触却描述皮损：不能按隐翅虫皮炎给低风险结论，转人工判断其他病因
        contradictions.append("否认虫体接触但报告皮损表现")

    insufficient = bool(missing or problems or contradictions)

    # 即使资料不足也照常评估：已报告的危险信号必须照常升级，
    # 不足兜底只抬高下限，绝不允许把证据支持的高等级拉低。
    matched = []
    for rule in pack.data["分级规则"]:
        if _rule_matches(rule["条件"], facts):
            matched.append({"id": rule["id"], "等级": rule["等级"], "理由": rule["理由"]})

    corrections = _corrections(pack, facts)

    if insufficient:
        fallback = pack.data["不足处置"]
        matched = ([{"id": INSUFFICIENT_ID, "等级": fallback["等级"], "理由": fallback["理由"]}]
                   + matched)
    elif not matched:
        # 事实完整但未命中任何规则：证据缺口上仍须人工复核
        matched = [{"id": INSUFFICIENT_ID, "等级": "人工复核",
                    "理由": "当前事实未命中任何分级规则，不得在证据缺口上给出低风险结论。"}]

    final_level = max((m["等级"] for m in matched), key=pack.level_rank)

    return {
        "等级": final_level,
        "规则版本": pack.version,
        "命中规则": matched,
        "缺失事实": sorted(set(missing)),
        "异常事实": sorted(set(problems)),
        "矛盾事实": contradictions,
        "需要纠正": corrections,
        "安全提示": _tips(pack, facts, matched),
        "边界声明": pack.data["边界声明"],
        "事实快照": facts,
    }


def _corrections(pack, facts):
    known = {item["处理"]: item for item in pack.data["危险处理"]}
    return [{"处理": name, "风险": known[name]["风险"], "纠正指令": known[name]["纠正指令"]}
            for name in facts["已采用处理"] if name in known]


def _tips(pack, facts, matched):
    levels = {m["等级"] for m in matched}
    if facts.get("疑似虫体接触") is True:
        levels.add("立即冲洗")
    return [{"id": tip["id"], "文本": tip["文本"]}
            for tip in pack.data["安全提示"] if tip["等级"] in levels]
