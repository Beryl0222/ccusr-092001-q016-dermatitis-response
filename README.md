# 虫媒皮炎分级响应（隐翅虫相关皮炎热线服务）

雨后隐翅虫相关皮炎就诊增多时，社区坐席收到的照片与描述质量不一，家长常先用牙膏、
酒精、碘伏处理。本服务为健康热线提供**有严格边界**的事件响应：收集最少必要信息，
给出发版可追踪的标准化即时提示，把危险表现升级到人工坐席或线下就医；**线上不做诊断**。

## 安全与边界（硬约束）

- 每条回复都带免责声明；结论只分「立即冲洗 / 居家观察 / 人工复核 / 尽快就医」，
  不表述为确诊。
- **不确定时绝不给低风险结论**：表单缺项只回通用冲洗提示并要求补充；皮损情况未知且
  无清晰可判读的照片结论时一律转人工。
- 服务**不接收图片与 PII**（姓名、电话、住址、证件、学校/单位、自由留言等字段直接拒绝）。
  照片由坐席人工判读后只录入 `photo_assessment` 结论（清晰可判读/模糊/光线不足/无法判断）。
- 家庭只用自定**假名**，库存加盐哈希（盐见「部署」），数据库中不出现任何原始假名。
- 出现「大面积红斑、水疱、密集脓疱、糜烂渗出」任一表现 → 尽快线下就医 + 转人工坐席。
- 即时处置标准化：大量清水冲洗 ≥10 分钟；6 小时内可肥皂水轻洗；禁止牙膏/酒精/碘伏等
  偏方与挑破水疱；无危险信号时冷湿敷 + 居家观察。

## 规则版本化

- 规则正文：`rules/vX.Y.Z.json`；`rules/manifest.json` 冻结每个版本的 sha256。
- 规则调整必须新建版本文件并重新冻结：`python3 rulebook.py --freeze`，
  启动与 `--check` 都会按清单校验哈希，正文被篡改即拒绝加载。
- 规则枚举必须覆盖 `domain.json` 的暴露场景、危险信号与建议等级，否则校验失败。
- 每条事件时间线记录当时的归一化事实、结构化结论、命中规则 ID、规则版本与哈希，
  可按版本复盘。

## 事件合并与纠正轨迹

- 同一家庭假名（哈希）+ 同一地区 + 72 小时窗口内的补充材料自动并入原事件
  （`rules` 中 `merge_policy` 可调）；每次补充都在时间线追加一条并基于合并事实重新定级，
  后续出现水疱等危险信号会把旧事件升级。
- 指定 `event_id` 补充需家庭假名哈希匹配，防止串档。
- 牙膏/酒精/碘伏/挑破/不明偏方的每次纠正都有独立 ID，坐席可登记「已洗去/已停用」闭环；
  所有写操作进 `audit_log`（仅存规范 JSON 摘要哈希）。

## 趋势与告警（去标识化）

- 按**地区（区县级）× 日**聚合。公开接口 `/v1/trends/public` 对计数低于 5
  （`min_cell_count`）的格子抑制为 `suppressed`，不显示计数，也不提供任何地区合计/分母，
  防止差分反推。
- 聚集判定：当日计数 ≥ 前 14 个有效日中位数的 2 倍且绝对增量 ≥ 5；基线点不足 7 个不告警。
- 告警 ID 由 `规则版本|地区|日期` 确定性派生并受数据库唯一约束，同一上升无论扫描多少次
  只产生一条告警；同地区 7 日冷却。
- 原始事件材料保留 90 天，到期清除前把计数固化进只含聚合数的 `daily_counts`。

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 服务身份、现行规则版本与哈希前缀 |
| POST | `/v1/events` | 受理/自动合并；支持显式 `event_id` 补充 |
| GET | `/v1/events/{id}` | 事件时间线、当前定级、纠正轨迹 |
| POST | `/v1/events/{id}/corrections` | 登记偏方纠正闭环 |
| GET | `/v1/trends/public` | 去标识化公开趋势 |
| POST | `/v1/alerts/scan` | 聚集扫描（内部，需密钥） |
| GET | `/v1/alerts` | 告警列表（内部，需密钥） |
| POST | `/v1/admin/retention` | 保留期清理（内部，需密钥） |

内部接口通过 `X-Internal-Key` 校验，密钥由环境变量 `HOTLINE_INTERNAL_KEY` 配置。

### 请求示例

```bash
curl -s localhost:8000/v1/events -H 'Content-Type: application/json' -d '{
  "family_pseudonym": "小雨家",
  "region": "310104",
  "exposure_scenario": "室内趋光",
  "lesion_signs": ["线状红斑", "灼痛"],
  "time_since_exposure_hours": 2,
  "age_band": "儿童(4-11)",
  "prior_home_treatments": ["牙膏"]
}'
```

允许字段只有 `region / exposure_scenario / lesion_signs / time_since_exposure_hours /
age_band / photo_assessment / prior_home_treatments`（后三个可缺省），其余一律报错。

## 运行与验证

```bash
python3 rulebook.py --freeze     # 调整规则后重新冻结清单
python3 service.py --check       # 校验清单哈希、结构与 domain 一致性
python3 service.py --port 8000   # 启动服务
python3 -m unittest -v           # 33 项测试
```

## 部署注意

- 设置 `HOTLINE_SALT`（家庭假名哈希盐）与 `HOTLINE_INTERNAL_KEY` 环境变量；
  未设盐时会在数据目录生成权限 0600 的盐文件。
- 仅依赖 Python 3.11+ 标准库；SQLite 数据文件位于 `data/`（已 gitignore）。
- 本服务为公共卫生处置工具，不替代医疗机构诊断系统。
