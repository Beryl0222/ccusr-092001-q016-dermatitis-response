"""去标识化趋势与聚集性告警。

两层可见性严格分离：
- 内部检测（evaluate_clusters / scan）使用真实计数，结果只对公共卫生处置账号可见；
- 公开输出（public_trends）对每个 地区×日 格子做最小计数抑制：低于阈值的格子
  既不显示计数也不显示任何可反推的分母/合计，仅标记 suppressed，避免差分推断。

告警唯一性：alert_id 由 规则版本|地区|日期 确定性派生，配合数据库主键约束，
同一聚集性上升无论扫描多少次只产生一条告警；另有同地区冷却窗口。
"""

from __future__ import annotations

import hashlib
import statistics
from datetime import date, datetime, timedelta
from typing import Iterable


def alert_id(rule_version: str, region: str, day: str) -> str:
    digest = hashlib.sha256(
        f"cluster|{rule_version}|{region}|{day}".encode("utf-8")
    ).hexdigest()[:16]
    return f"ALERT-{digest}"


def median_baseline(series: dict[str, int], target_day: str,
                    baseline_days: int) -> tuple[float | None, int]:
    """返回目标日之前 baseline_days 天中、已有数据日的中位数与有效基线点数。"""
    target = date.fromisoformat(target_day)
    values: list[int] = []
    for back in range(1, baseline_days + 1):
        key = (target - timedelta(days=back)).isoformat()
        if key in series:
            values.append(series[key])
    if not values:
        return None, 0
    return float(statistics.median(values)), len(values)


def evaluate_clusters(counts: dict[str, dict[str, int]], target_day: str,
                      rules: dict) -> list[dict]:
    """对指定日期做全地区聚集性判定（纯函数，便于复测）。"""
    cfg = rules["analytics"]["cluster_rule"]
    findings: list[dict] = []
    for region, series in sorted(counts.items()):
        today_count = series.get(target_day)
        if today_count is None:
            continue
        median, points = median_baseline(series, target_day, cfg["baseline_days"])
        if median is None or points < cfg["min_baseline_points"]:
            continue
        if (today_count >= median * cfg["multiplier"]
                and today_count - median >= cfg["min_absolute_increase"]):
            findings.append({
                "alert_id": alert_id(rules["rule_version"], region, target_day),
                "region": region,
                "day": target_day,
                "count": today_count,
                "baseline_median": median,
                "baseline_points": points,
                "multiplier": cfg["multiplier"],
                "rule_version": rules["rule_version"],
            })
    return findings


def scan(store, rules, target_day: str | None = None) -> list[dict]:
    """扫描并落库告警；冷却期内或已存在的确定性告警不重复产生。"""
    target_day = target_day or datetime.now().astimezone().date().isoformat()
    days = rules["analytics"]["cluster_rule"]["baseline_days"] + 1
    counts = store.daily_counts(days)
    findings = evaluate_clusters(counts, target_day, rules)
    cooldown = rules["analytics"]["alert_dedup"]["per_region_cooldown_days"]
    raised: list[dict] = []
    for f in findings:
        if store.recent_alert_dates(f["region"], cooldown, f["day"]):
            continue
        ok = store.raise_alert(
            f["alert_id"], f["region"], f["day"], f["count"],
            f["baseline_median"], f["rule_version"],
        )
        if ok:
            raised.append(f)
    return raised


def public_trends(counts: dict[str, dict[str, int]], rules: dict,
                  regions: Iterable[str] | None = None) -> dict:
    """生成可公开的去标识化趋势：低计数格子抑制，不输出任何合计。"""
    k = int(rules["analytics"]["min_cell_count"])
    selected = sorted(regions) if regions is not None else sorted(counts)
    cells = []
    for region in selected:
        series = counts.get(region, {})
        for day in sorted(series):
            n = series[day]
            cells.append({
                "region": region,
                "day": day,
                "count": n if n >= k else None,
                "status": "published" if n >= k else "suppressed",
            })
    return {
        "granularity": rules["analytics"]["region_granularity"],
        "time_bucket": rules["analytics"]["time_bucket"],
        "minimum_cell_count": k,
        "suppression_policy": rules["analytics"]["suppression"],
        "cells": cells,
        "note": "低于最小格子数的计数不予公布，且不提供地区合计，以防由差值反推个人。",
    }
