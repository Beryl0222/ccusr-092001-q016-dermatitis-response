"""虫媒皮炎分级响应服务入口。

HTTP 边界：
- 只接收结构化事实，不接收照片与自由文本地址（区域必须是编码）；
- GET 只读接口不返回任何逐人事实，趋势输出经 k-匿名抑制；
- 每次自动回复携带规则版本、命中规则与边界声明。
"""

import argparse
import json
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from triage_rules import RulePack, RulePackError
from store import Store
from hotline import HotlineService, HotlineError

SERVICE_ID = "dermatitis-response"
MAX_BODY_BYTES = 16 * 1024


def health():
    """返回稳定的服务身份。"""
    return {"status": "ok", "service": SERVICE_ID}


def _load_populations(path):
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("区域人口文件必须是 区域编码->人口数 的对象")
    return {str(k): int(v) for k, v in data.items()}


def build_service(db_path=":memory:", rules_path="rules", populations_path=None, salt=None):
    pack = RulePack.load(rules_path)
    with open("domain.json", encoding="utf-8") as fh:
        pack.cross_check_domain(json.load(fh))
    store = Store(db_path, salt=salt)
    populations = _load_populations(populations_path)
    return HotlineService(store, pack, populations), pack


def make_handler(service, pack):

    class Handler(BaseHTTPRequestHandler):

        def _send(self, code, payload):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY_BYTES:
                raise HotlineError("请求体缺失或超出大小上限（不接收照片/附件）")
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise HotlineError(f"请求体不是合法JSON：{exc}")
            if not isinstance(data, dict):
                raise HotlineError("请求体必须是JSON对象")
            return data

        def do_GET(self):
            parsed = urlparse(self.path)
            try:
                if parsed.path == "/health":
                    payload = health()
                    payload["规则版本"] = pack.version
                    payload["规则文件"] = pack.source
                    self._send(200, payload)
                    return
                if parsed.path == "/v1/trends":
                    q = parse_qs(parsed.query)
                    since = _require_ts(q, "since")
                    until = _parse_ts(q.get("until", [None])[0])
                    self._send(200, service.trends(since, until))
                    return
                if parsed.path.startswith("/v1/events/"):
                    event_id = parsed.path.rsplit("/", 1)[-1]
                    if not event_id:
                        self._send(404, {"错误": "未知路径"})
                        return
                    self._send(200, service.event_record(event_id))
                    return
                self._send(404, {"错误": "未知路径"})
            except (HotlineError, ValueError) as exc:
                self._send(400, {"错误": str(exc)})
            except Exception:  # noqa: BLE001 - 服务不应因单请求异常退出
                traceback.print_exc()
                self._send(500, {"错误": "服务内部错误"})

        def do_POST(self):
            parsed = urlparse(self.path)
            try:
                data = self._read_json()
                if parsed.path == "/v1/intake":
                    reply = service.intake(
                        data.get("contact"), data.get("region"),
                        data.get("facts", {}), source=data.get("source", "热线来电"),
                        stopped_treatments=data.get("stopped_treatments"))
                    self._send(200, reply)
                    return
                if parsed.path == "/v1/agent/transition":
                    self._send(200, service.agent_transition(
                        data["event_id"], data["to_status"], data.get("reason", "人工操作")))
                    return
                if parsed.path == "/v1/clusters/scan":
                    created, existing = service.scan_clusters(
                        _parse_ts(data.get("now")) if data.get("now") else None)
                    self._send(200, {"新建告警": created, "既有告警": existing})
                    return
                self._send(404, {"错误": "未知路径"})
            except HotlineError as exc:
                self._send(400, {"错误": str(exc)})
            except Exception:  # noqa: BLE001
                traceback.print_exc()
                self._send(500, {"错误": "服务内部错误"})

        def log_message(self, *_args):
            return

    return Handler


def _require_ts(q, name):
    raw = q.get(name, [None])[0]
    ts = _parse_ts(raw)
    if ts is None:
        raise ValueError(f"缺少时间戳参数：{name}")
    return ts


def _parse_ts(raw):
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        raise ValueError(f"时间戳必须是Unix秒：{raw}")


def run_check():
    pack = RulePack.load("rules")
    with open("domain.json", encoding="utf-8") as fh:
        pack.cross_check_domain(json.load(fh))
    print(f"检查通过：规则包 {pack.version}（{pack.source}）与 domain.json 分类一致")


def main():
    parser = argparse.ArgumentParser(description="隐翅虫皮炎分级响应热线服务")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--check", action="store_true", help="校验规则包与分类法后退出")
    parser.add_argument("--rules", default="rules", help="规则包文件或目录")
    parser.add_argument("--db", default="data/hotline.db", help="SQLite 路径，默认 data/hotline.db")
    parser.add_argument("--populations", default=None,
                        help="区域人口JSON（区域编码->常住人口）；提供后启用人口下限闸门")
    args = parser.parse_args()

    if args.check:
        run_check()
        return

    service, pack = build_service(args.db, args.rules, args.populations)
    print(f"服务启动：规则 {pack.version}，监听 0.0.0.0:{args.port}")
    ThreadingHTTPServer(("0.0.0.0", args.port), make_handler(service, pack)).serve_forever()


if __name__ == "__main__":
    main()
