"""版本化规则库的加载、冻结与一致性校验。

规则文件位于 rules/v<语义版本>.json；rules/manifest.json 记录每个版本
正文的 sha256，运行时按清单校验，规则正文被篡改或未冻结都会被拒绝。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent / "rules"
MANIFEST_PATH = RULES_DIR / "manifest.json"
DOMAIN_PATH = Path(__file__).resolve().parent / "domain.json"
SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


class RuleError(Exception):
    """规则文件、清单或一致性检查失败。"""


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8") or "null")
    except FileNotFoundError as exc:
        raise RuleError(f"文件不存在: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuleError(f"JSON 无法解析: {path}: {exc}") from exc


def load_manifest() -> dict:
    if not MANIFEST_PATH.exists():
        raise RuleError("规则清单 manifest.json 不存在，请先执行: python -m rulebook --freeze")
    manifest = _load_json(MANIFEST_PATH)
    if not isinstance(manifest, dict) or "versions" not in manifest:
        raise RuleError("manifest.json 结构无效，缺少 versions")
    return manifest


def freeze(write: bool = True) -> dict:
    """计算 rules/ 下全部规则正文的哈希，生成或校验清单。"""
    versions: dict[str, dict[str, str]] = {}
    for path in sorted(RULES_DIR.glob("v*.json")):
        m = SEMVER_RE.match(path.stem)
        if not m:
            raise RuleError(f"规则文件名应为 vX.Y.Z.json: {path.name}")
        rule = _load_json(path)
        declared = str(rule.get("rule_version", ""))
        if declared != f"{m.group(1)}.{m.group(2)}.{m.group(3)}":
            raise RuleError(f"{path.name} 的 rule_version 与文件名不一致: {declared!r}")
        versions[declared] = {"file": path.name, "sha256": _sha256_file(path)}
    if not versions:
        raise RuleError("rules/ 下没有任何规则文件")
    active = max(versions, key=lambda v: tuple(int(x) for x in v.split(".")))
    manifest = {"schema": 1, "active": active, "versions": versions}
    if write:
        MANIFEST_PATH.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return manifest


def _validate_structure(rule: dict) -> None:
    for key in ("rule_version", "required_minimum_fields", "danger_signs",
                "escalation_rules", "immediate_actions", "advice_levels",
                "insufficient_info_policy", "merge_policy", "analytics"):
        if key not in rule:
            raise RuleError(f"规则缺少必需键: {key}")
    declared_levels = set(rule["advice_levels"])
    for esc in rule["escalation_rules"]:
        if esc.get("level") not in declared_levels:
            raise RuleError(f"升级规则 {esc.get('id')} 的等级未在 advice_levels 声明")
        if not esc.get("id"):
            raise RuleError("存在缺少 id 的升级规则")
    if rule["insufficient_info_policy"].get("never_emit_low_risk_when_unknown") is not True:
        raise RuleError("信息不足策略必须禁止在不确定时给出低风险结论")
    for field_name in rule["required_minimum_fields"]:
        if field_name not in rule["field_rules"]:
            raise RuleError(f"最小必要字段 {field_name} 没有 field_rules 定义")
    analytics = rule["analytics"]
    if int(analytics["min_cell_count"]) < 1:
        raise RuleError("最小格子数必须 >= 1")
    cluster = analytics["cluster_rule"]
    if cluster["min_baseline_points"] > cluster["baseline_days"]:
        raise RuleError("最小基线点数不能大于基线窗口天数")


def check_domain_alignment(rule: dict, domain: dict) -> None:
    """规则的枚举必须与公共卫生基线资料 domain.json 保持一致（允许超集）。"""
    for sign in domain.get("危险信号", []):
        if sign not in rule["danger_signs"]:
            raise RuleError(f"规则缺少 domain.json 中的危险信号: {sign}")
    for scenario in domain.get("暴露场景", []):
        values = rule["field_rules"]["exposure_scenario"]["values"]
        if scenario not in values:
            raise RuleError(f"规则缺少 domain.json 中的暴露场景: {scenario}")
    for level in domain.get("建议等级", []):
        if level not in rule["advice_levels"]:
            raise RuleError(f"规则缺少 domain.json 中的建议等级: {level}")


def load_rules(version: str | None = None, *, verify_domain: bool = True) -> dict:
    """加载并校验规则；默认加载 manifest 中的 active 版本。"""
    manifest = load_manifest()
    version = version or manifest["active"]
    entry = manifest["versions"].get(version)
    if entry is None:
        raise RuleError(f"清单中没有规则版本: {version}")
    path = RULES_DIR / entry["file"]
    actual = _sha256_file(path)
    if actual != entry["sha256"]:
        raise RuleError(
            f"规则文件被篡改且未重新冻结: {entry['file']}\n"
            f"  清单哈希: {entry['sha256']}\n  实际哈希: {actual}"
        )
    rule = _load_json(path)
    _validate_structure(rule)
    if verify_domain:
        check_domain_alignment(rule, _load_json(DOMAIN_PATH))
    rule["_manifest"] = {k: v for k, v in manifest.items() if k != "versions"}
    return rule


def active_version() -> str:
    return load_manifest()["active"]


def main() -> None:
    parser = argparse.ArgumentParser(description="规则库冻结与校验")
    parser.add_argument("--freeze", action="store_true", help="重算哈希并写入 manifest.json")
    parser.add_argument("--check", action="store_true", help="校验清单、结构与 domain 一致性")
    args = parser.parse_args()
    if args.freeze:
        manifest = freeze(write=True)
        print(f"已冻结 {len(manifest['versions'])} 个规则版本，active={manifest['active']}")
    if args.check or not args.freeze:
        freeze(write=False)
        rule = load_rules()
        print(f"规则检查通过: active=v{rule['rule_version']} sha256={load_manifest()['versions'][rule['rule_version']]['sha256'][:12]}…")


if __name__ == "__main__":
    main()
