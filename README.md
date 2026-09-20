# 虫媒皮炎分级响应

项目为公共卫生热线统一暴露场景、危险信号与建议等级。`domain.json` 同时明确线上服务的边界，个体信息只用于当前事件处置。

运行 `python3 service.py --check` 检查配置，执行 `python3 -m unittest -v` 验证服务身份；后端启动后提供 `/health`。
