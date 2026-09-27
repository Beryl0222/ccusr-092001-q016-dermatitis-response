"""虫媒皮炎（隐翅虫相关皮炎）分级响应服务。

边界（任何回复都附带）：
- 服务只做规则化即时分级与标准处置提示，不做诊断，不替代医生面诊；
- 不接收图片、姓名、电话、住址等 PII：照片由坐席判读后以 photo_assessment 结论录入；
- 信息不足时只返回通用冲洗提示并要求补充/转人工，绝不给出低风险结论。

接口：
  GET  /health                         服务身份与现行规则版本
  POST /v1/events                      新建或（按家庭+地区+72h窗口）合并事件
  GET  /v1/events/{id}                 凭事件标识查询完整时间线与纠正轨迹
  POST /v1/events/{id}/corrections     坐席登记偏方纠正闭环
  GET  /v1/trends/public               去标识化公开趋势（低计数格子抑制）
  POST /v1/alerts/scan                 聚集性扫描（内部），触发唯一告警
  GET  /v1/alerts                      告警列表（内部）
  POST /v1/admin/retention             执行保留期清理（内部）
"""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import analytics
import rulebook
import triage
from store import Store, load_or_create_salt, merge_facts, now_cst, today_cst

SERVICE_ID = "dermatitis-response"

REQUIRE_REVIEW_KEY = os.environ.get("HOTLINE_INTERNAL_KEY", "")


class Service:
    """装配规则、存储与分级逻辑，便于测试中直接调用。"""

    def __init__(self, db_path: str = "data/hotline.db", rules: dict | None = None,
                 salt: str | None = None):
        self.rules = rules or rulebook.load_rules()
        manifest = rulebook.load_manifest()
        self.rule_hash = manifest["versions"][self.rules["rule_version"]]["sha256"]
        self.store = Store(
            db_path, salt or load_or_create_salt(None),
            merge_window_hours=self.rules["merge_policy"]["window_hours"],
        )

    def close(self) -> None:
        self.store.close()

    def health(self) -> dict:
        return {
            "status": "ok",
            "service": SERVICE_ID,
            "rule_version": self.rules["rule_version"],
            "rule_hash": self.rule_hash[:12],
        }

    # ---- 事件受理 ------------------------------------------------------

    def intake(self, payload: dict, actor: str = "hotline") -> dict:
        """受理一次提交：校验 → 分级 → 新建事件或并入原事件。

        - region 是建档前提（也是趋势聚合与合并键）；连地区都缺失时只回通用提示，不落库；
        - 指定 event_id 的补充必须通过家庭假名哈希校验；
        - 补充材料与历史事实合并后重新分级，保证后续危险信号能把旧事件升级。
        """
        family_pseudonym = payload.get("family_pseudonym")
        if not isinstance(family_pseudonym, str) or not family_pseudonym.strip():
            raise triage.ValidationError("family_pseudonym 必填（家庭自定代号，不要填真实姓名）")
        result = triage.evaluate(payload, self.rules)
        facts = result["facts"]
        family_h = self.store.family_hash(family_pseudonym)

        event_id = payload.get("event_id")
        if event_id:
            event = self.store.get_event(event_id)
            if event is None:
                raise triage.ValidationError(f"event_id 不存在: {event_id}")
            if self.store.event_family_hash(event_id) != family_h:
                raise triage.ValidationError("家庭假名与该事件不匹配，拒绝并入")
            return self._attach_supplement(event_id, facts, actor)

        # 自动合并：同家庭 + 同地区 + 72 小时窗口
        region = facts.get("region")
        if not region:
            # 连地区都没有，无法建档也无法定位合并；返回暂存级通用提示
            return self._transient_response(result)
        merge_id = self.store.find_mergeable_event(family_pseudonym, region)
        if merge_id:
            return self._attach_supplement(merge_id, facts, actor)

        event_id = self.store.create_event(
            family_pseudonym, facts, result, self.rule_hash, actor,
        )
        return self._response(event_id, result, merged=False, seq=1)

    def _attach_supplement(self, event_id: str, submitted_facts: dict, actor: str) -> dict:
        event = self.store.get_event(event_id)
        merged = merge_facts(event["latest_facts"], submitted_facts)
        re_result = triage.evaluate(merged, self.rules)
        seq = self.store.add_supplement(
            event_id, submitted_facts, merged, re_result, self.rule_hash, actor,
        )
        return self._response(event_id, re_result, merged=True, seq=seq)

    def _response(self, event_id: str, result: dict, *, merged: bool, seq: int) -> dict:
        key = "merged_into_event" if merged else "event_id"
        return {
            key: event_id,
            "seq": seq,
            "decision": result["decision"],
            "level": result["level"],
            "dispatch": result["dispatch"],
            "matched_danger_signs": result.get("matched_danger_signs", []),
            "missing_fields": result["missing_fields"],
            "actions": result["actions"],
            "corrections": result["corrections"],
            "uncertainties": result["uncertainties"],
            "fired_rules": result["fired_rules"],
            "advice_text": result["advice_text"],
            "message": triage.build_message(result),
            "rule_version": result["rule_version"],
            "rule_hash": self.rule_hash[:12],
            "disclaimer": result["disclaimer"],
        }

    def _transient_response(self, result: dict) -> dict:
        """材料不足以建档时的临时响应：只有通用冲洗提示，明确不分級、不存事件。"""
        return {
            "event_id": None,
            "persisted": False,
            "decision": result["decision"],
            "level": None,
            "dispatch": None,
            "matched_danger_signs": [],
            "missing_fields": result["missing_fields"],
            "actions": result["actions"],
            "corrections": result["corrections"],
            "uncertainties": result["uncertainties"] + ["未建档：缺少地区信息，补充后重新提交"],
            "fired_rules": result["fired_rules"],
            "advice_text": result["advice_text"],
            "message": triage.build_message(result),
            "rule_version": result["rule_version"],
            "rule_hash": self.rule_hash[:12],
            "disclaimer": result["disclaimer"],
        }

    def event_detail(self, event_id: str) -> dict | None:
        return self.store.get_event(event_id)

    def acknowledge_correction(self, event_id: str, body: dict) -> dict:
        correction_id = body.get("correction_id")
        if not isinstance(correction_id, str) or not correction_id.strip():
            raise triage.ValidationError("correction_id 必填")
        resolution = body.get("resolution")
        if resolution is not None and not isinstance(resolution, str):
            raise triage.ValidationError("resolution 必须是字符串")
        ok = self.store.acknowledge_correction(event_id, correction_id.strip(), resolution)
        if not ok:
            raise triage.ValidationError("纠正记录不存在或已闭环")
        return {"status": "acknowledged", "event_id": event_id,
                "correction_id": correction_id.strip()}

    # ---- 趋势与告警 ----------------------------------------------------

    def public_trends(self, days: int = 30) -> dict:
        counts = self.store.daily_counts(days)
        return analytics.public_trends(counts, self.rules)

    def scan_alerts(self, day: str | None = None) -> dict:
        day = day or today_cst()
        raised = analytics.scan(self.store, self.rules, day)
        return {"day": day, "new_alerts": raised,
                "count": len(raised), "dedup": "deterministic_id + region cooldown"}

    def list_alerts(self) -> dict:
        return {"alerts": self.store.list_alerts()}

    def run_retention(self) -> dict:
        days = self.rules["retention"]["raw_event_days"]
        deleted = self.store.purge_raw_events(days)
        return {"retention_days": days, "purged_events": deleted}


class Handler(BaseHTTPRequestHandler):
    service: Service

    # ---- HTTP 基础 -----------------------------------------------------

    def _send(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise triage.ValidationError(f"请求体不是合法 JSON: {exc}")
        if not isinstance(data, dict):
            raise triage.ValidationError("请求体必须是 JSON 对象")
        return data

    def _check_internal(self) -> bool:
        if not REQUIRE_REVIEW_KEY:
            return True  # 未配置内部密钥时仅建议在隔离网络部署
        return self.headers.get("X-Internal-Key") == REQUIRE_REVIEW_KEY

    def log_message(self, *_args):
        return

    # ---- 路由 ----------------------------------------------------------

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        try:
            if path == "/health":
                self._send(200, self.service.health())
            elif path == "/v1/trends/public":
                self._send(200, self.service.public_trends())
            elif path == "/v1/alerts":
                if not self._check_internal():
                    self._send(403, {"error": "需要内部密钥"})
                    return
                self._send(200, self.service.list_alerts())
            elif path.startswith("/v1/events/"):
                event_id = path.split("/", 3)[3]
                detail = self.service.event_detail(event_id)
                if detail is None:
                    self._send(404, {"error": "事件不存在"})
                else:
                    self._send(200, detail)
            else:
                self._send(404, {"error": "未找到接口"})
        except triage.ValidationError as exc:
            self._send(400, {"error": str(exc)})
        except Exception as exc:  # 防御：错误不回显堆栈
            self._send(500, {"error": "服务内部错误", "type": type(exc).__name__})

    def do_POST(self):
        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        try:
            body = self._read_json()
            actor = self.headers.get("X-Actor", "hotline")
            if path == "/v1/events":
                self._send(200, self.service.intake(body, actor=actor))
            elif path.startswith("/v1/events/") and path.endswith("/corrections"):
                event_id = path.split("/")[3]
                self._send(200, self.service.acknowledge_correction(event_id, body))
            elif path == "/v1/alerts/scan":
                if not self._check_internal():
                    self._send(403, {"error": "需要内部密钥"})
                    return
                self._send(200, self.service.scan_alerts(body.get("day")))
            elif path == "/v1/admin/retention":
                if not self._check_internal():
                    self._send(403, {"error": "需要内部密钥"})
                    return
                self._send(200, self.service.run_retention())
            else:
                self._send(404, {"error": "未找到接口"})
        except triage.ValidationError as exc:
            self._send(400, {"error": str(exc)})
        except KeyError:
            self._send(404, {"error": "事件不存在"})
        except Exception as exc:
            self._send(500, {"error": "服务内部错误", "type": type(exc).__name__})


def health():
    """兼容旧测试的稳定服务身份。"""
    return {"status": "ok", "service": SERVICE_ID}


def main() -> None:
    parser = argparse.ArgumentParser(description="隐翅虫皮炎分级响应热线服务")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", default="data/hotline.db")
    parser.add_argument("--check", action="store_true", help="校验规则清单、结构与 domain 一致性后退出")
    args = parser.parse_args()
    if args.check:
        rulebook.freeze(write=False)
        rules = rulebook.load_rules()
        hsh = rulebook.load_manifest()["versions"][rules["rule_version"]]["sha256"]
        print(f"基础检查通过：active=v{rules['rule_version']} sha256={hsh[:12]}…")
        return
    service = Service(db_path=args.db)
    Handler.service = service
    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"{SERVICE_ID} 监听 :{args.port}，规则 v{service.rules['rule_version']}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        service.close()


if __name__ == "__main__":
    main()
