# 更新日志

## 2026-07-27 · 全面重构（refactor/modular-ui → main）

### 后端：3558 行单文件拆分为模块（零行为变化）

原 `app.py` 单文件（前后端 + 内嵌脚本混在一起）拆分为：

```
app.py        # 瘦入口 + 测试兼容 re-export
config.py     # 环境变量与常量
db.py         # SQLite 连接、schema 初始化、列迁移、种子数据
security.py   # 密码/session/agent token 哈希、登录限速
sources.py    # 优选源解析、去重、TCP 检测、ip_checks 写入
substore.py   # 订阅验证、Sub-Store 上传
sync.py       # webhook / sync_command / agent pending 同步链
state.py      # collect_state() 状态聚合
server.py     # HTTP 路由（唯一懂 HTTP 的模块）
```

验证方式：拆分前后函数/常量清单一致；内嵌脚本与 HTML 字符串字节级比对一致；`python3 -m py_compile` + 单元测试 + 启动冒烟（healthz/登录/state）全过。

### 内嵌脚本：`detect_*` 收敛为单一来源

原 collector / agent / webhook 三个内嵌脚本各复制一份 `detect_*` 函数（改一处要同步三处）。现在：

- `scripts/detect_common.py` 是唯一实现
- `scripts/{collector,agent}.py.tpl`、`scripts/install.sh.tpl` 为模板
- `embedded.py` 启动时在内存中拼装 `/install.sh`，改 `detect_common.py` 两个脚本自动生效
- `collect_texts` 按扫描行为差异拆为 `collect_texts_wide`（collector）/ `collect_texts_targeted`（agent），各自行为不变

**唯一有意行为变更**：collector 优选源 fallback 上限 20 行 → 100 行（与 agent 对齐）。

### 前端：推翻重做（Linear 浅色风，零构建）

- 内嵌 HTML 字符串删除，改为 `static/` 独立静态文件：`index.html` / `login.html` / `css/app.css` / `js/*.js`（原生 ES Modules，无 npm 无构建）
- 新布局：左栏 VPS 信息卡（状态点 + 回传时间 + 到期·续费·流量，**到期 ≤5 天橙色高亮**）；主区统计卡/信息编辑/订阅/SubStore/优选源/IP 明细；右栏仅同步链路 + 任务日志
- 「同步到其他 VPS」常驻栏改为「一键同步 ▾」下拉勾选目标
- 强约束达成：36 个按钮全部有真实 API/逻辑绑定 + 反馈（toast / loading / 弹窗），无占位按钮，无 UI 重叠，浏览器控制台零报错（headless Chrome 实测）
- 旧交互全部保留：`normalizeCurrent` 真实 vps id、右键菜单、采集结果粘贴导入、Sub-Store 三格式切换等
- 新增：任务日志 8s 轮询、VPS 搜索过滤、IP 明细筛选真实可用

### 同步链路：递进亮灯

右栏同步链路改为按真实同步状态递进亮灯：通过哪步亮哪步（绿），失败亮红并阻断后续，Agent 待执行亮黄灯脉冲。判定依据从"永不出现的关键词"修正为真实状态文本（`webhook HTTP 2xx` / `command exit 0` / `Agent done` / `CDN已更新` / `验证 HTTP 2xx`）。

### 部署

- 已从洛杉矶迁移至**弗里蒙特**（`ssh frm`，`/root/data/docker_data/anyvps`）
- Dockerfile：`COPY *.py` + `COPY scripts/` + `COPY static/`
- 线上验证：容器 healthy、8 台 VPS / 152 条检测 / 28440 条任务数据完好、Cloudflare Challenge / 登录限速 / noindex 均生效
- 回滚备份：`/var/backups/anyvps-refactor-20260727-121759`
