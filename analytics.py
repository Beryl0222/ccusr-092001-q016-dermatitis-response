"""去标识化趋势与聚集性告警。

所有输入只含事件编号、家庭编号、区域编码与时间——不含描述、照片、联系方式等。
公开前两道闸：区域人口下限与 k-匿名格子抑制；告警在存储层有唯一约束，
同一对齐窗口内每个区域最多一条。
"""

from collections import defaultdict
from datetime import datetime, timezone

HOUR = 3600.0


def _day_key(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def _aligned_window(now_ts, window_hours):
    width = window_hours * HOUR
    start = (int(now_ts) // int(width)) * int(width)
    return float(start), float(start + width)


def trends(store, pack, since, until=None, region_populations=None):
    """按区域×天返回计数；低于 k 的格子抑制，未登记人口或人口不足的区域整体不发布。

    计数按去重家庭计（同一家庭补充资料不重复计数），抑制格子输出为 None，
    调用方不得把 None 渲染成 0。
    """
    until = until if until is not None else store.now()
    params = pack.data["分析参数"]
    k = int(params["k_匿名"])
    min_population = int(params["最小区域人口"])

    rows = store.event_buckets(since, until)

    families = defaultdict(set)          # (region, day) -> {family_id}
    region_total = defaultdict(set)      # region -> {family_id}
    for row in rows:
        region = row["region"]
        families[(region, _day_key(row["created_at"]))].add(row["family_id"])
        region_total[region].add(row["family_id"])

    days = sorted({day for (_, day) in families})
    series = {}
    suppressed_regions = []
    for region in sorted(region_total):
        if region_populations is not None:
            pop = region_populations.get(region)
            if pop is None or pop < min_population:
                suppressed_regions.append(region)
                continue
        cells = []
        publish = True
        for day in days:
            count = len(families.get((region, day), set()))
            if count == 0:
                cells.append(None)
            elif count < k:
                cells.append(None)  # k-匿名抑制
                publish = False
            else:
                cells.append(count)
        if len(region_total[region]) < k:
            publish = False
        if publish:
            series[region] = dict(zip(days, cells))
        else:
            suppressed_regions.append(region)

    return {
        "时间粒度": "天（UTC）",
        "区域粒度": params["区域粒度"],
        "k_匿名": k,
        "区间": [_day_key(since), _day_key(until)],
        "序列": series,
        "抑制区域数": len(set(suppressed_regions)),
    }


def scan_clusters(store, pack, now_ts=None, region_populations=None):
    """扫描各区域当前 72h 对齐窗口是否相对基线翻倍上升，触发则写入唯一告警。

    返回 (alerts_new, alerts_seen)：本次新建与窗口内已存在的告警。
    """
    now_ts = now_ts if now_ts is not None else store.now()
    params = pack.data["分析参数"]
    window_hours = int(params["聚集窗口小时"])
    multiplier = float(params["聚集基线倍数"])
    min_increment = int(params["聚集最小增量"])
    k = int(params["k_匿名"])
    min_population = int(params["最小区域人口"])

    window_start, window_end = _aligned_window(now_ts, window_hours)
    width = window_hours * HOUR
    # 基线：当前窗口之前 4 个等长窗口的平均每窗家庭数
    baseline_start = window_start - 4 * width

    rows = store.event_buckets(baseline_start, window_end)
    current = defaultdict(set)
    baseline_windows = defaultdict(lambda: [set() for _ in range(4)])
    for row in rows:
        region = row["region"]
        ts = row["created_at"]
        if ts >= window_start:
            current[region].add(row["family_id"])
        else:
            idx = int((ts - baseline_start) // width)
            if 0 <= idx < 4:
                baseline_windows[region][idx].add(row["family_id"])

    created, existing = [], []
    for region, families in current.items():
        if region_populations is not None:
            pop = region_populations.get(region)
            if pop is None or pop < min_population:
                continue
        cur = len(families)
        if cur < max(k, min_increment):
            continue
        base_counts = [len(s) for s in baseline_windows.get(region, [set()] * 4)]
        baseline = sum(base_counts) / 4.0
        if baseline > 0 and cur < baseline * multiplier:
            continue
        increment = cur - baseline
        if increment < min_increment:
            continue
        payload = {"窗口家庭数": cur, "基线均值": round(baseline, 2),
                   "倍数": round(cur / baseline, 2) if baseline > 0 else None,
                   "区域粒度": params["区域粒度"], "时间粒度小时": params["时间粒度小时"]}
        alert, is_new = store.insert_alert(region, window_start, window_end, payload)
        (created if is_new else existing).append(alert)
    return created, existing
