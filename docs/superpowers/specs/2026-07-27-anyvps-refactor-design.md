# AnyVPS 重构设计文档

日期：2026-07-27 · 状态：待用户确认

## 1. 背景与动机

AnyVPS 目前是一个 3558 行的单文件 `app.py`（Python stdlib，无框架），部署在弗里蒙特 VPS（已从洛杉矶迁移），线上地址 `https://anyvps.240314.xyz`，GitHub 私有仓库 `zane0314/anyvps-cdn`。

痛点：

- **A. 单文件难维护**：前后端混在一个文件，改动易出 bug（如 `currentId=1` 事故）
- **B. 代码重复**：collector / agent / webhook receiver 三个内嵌脚本各复制一套 `detect_*` 函数，改一处要同步三处
- **D. 扩展受阻**：加新功能必须在 3558 行里翻找，心智负担大
- **前端推翻重做**：现 UI 为深色单页，目标是浅色简约科技感

## 2. 需求

### 2.1 功能需求（强约束：现有功能全部保留）

| 功能 | 说明 |
|---|---|
| VPS 清单 | 列表、添加、编辑（名称/角色/到期/续费金额币种/月流量/状态/优选管理页/健康检查）、删除 |
| 左栏信息卡 | 每台显示：状态点、名称、回传/最近同步时间、到期·续费·流量 |
| 到期提醒 | 到期 ≤ 5 天的日期橙色高亮 |
| 通用订阅地址 | 3x-ui / 八合一 / CDN 三条，可编辑可复制 |
| SubStore 转换订阅 | 上传、刷新（noCache）、验证（优先验最后上传链接） |
| 优选 IP 源 | 多行编辑、解析并检测 IP、去重、保存配置 |
| 源内 IP 明细检测 | 表格 + 筛选（全部/可用/低延迟/异常） |
| 一键同步 | 选择目标 VPS（下拉勾选），走 webhook / sync_command / agent pending 三条链路 |
| 同步链路 | 状态展示（原右栏保留） |
| 任务日志 | 实时日志（原右栏保留） |
| 远端采集 / 安装入口 | 弹窗：远端采集脚本、3x-ui-zane 安装命令 |
| Agent 体系 | `/install.sh`、注册、心跳、poll、report、daily snapshot |
| 登录安全 | 密码登录、session、失败限速、Cloudflare Managed Challenge |

### 2.2 非功能需求

- 后端保持 Python stdlib 单进程，不引入 Web 框架
- 前端纯静态文件 + 原生 JS（ES Modules），零构建工具
- 线上 SQLite 数据零破坏迁移（`ensure_columns` 逻辑保留）
- 部署方式不变：Docker 容器 + nginx 反代 + Cloudflare

## 3. 架构设计

### 3.1 后端模块边界

```
anyvps/
├── app.py            # 入口：装配 + 启动（<100 行）
├── config.py         # 环境变量与常量
├── db.py             # 连接、init_db、ensure_columns、seed
├── security.py       # 密码/session/限速/agent token
├── sources.py        # 优选源解析、去重、TCP 检测、ip_checks
├── substore.py       # 订阅验证、上传 Sub-Store
├── sync.py           # webhook / sync_command / pending / sync_sources()
├── state.py          # collect_state() 聚合
├── server.py         # Handler 路由（唯一懂 HTTP 的模块）
└── static/           # index.html / css / js（ES Modules）
```

依赖方向：`server.py → 业务模块 → db.py / config.py`，业务模块之间互不 import。

### 3.2 内嵌脚本收敛（消灭痛点 B）

```
scripts/
├── detect_common.py    # 唯一一份 detect_* 实现
├── collector.py.tpl    # 含 __DETECT_COMMON__ 占位
├── agent.py.tpl
├── webhook.py.tpl
└── install.sh.tpl
```

`app.py` 启动时在内存中把 `detect_common.py` 内联进各模板，生成 INSTALL_SCRIPT 等常量。改 detect 逻辑只改一个文件，三个脚本自动生效。

### 3.3 前端

- `static/index.html` + `css/app.css` + `js/{main,api,sidebar,sections,sync,util}.js`
- 视觉：Linear 浅色风（#f7f8fa 底、白卡、#e8e9ec 细边框、#5e6ad2 靛蓝点缀）
- 布局（已确认 mockup v2）：左栏 VPS 信息卡 + 底部「添加 VPS / 远端采集·安装」；主区自上而下：统计卡 → VPS 信息编辑 → 通用订阅 → SubStore 转换 → 优选 IP 源 → IP 明细表；右栏仅「同步链路 + 任务日志」
- 「同步到其他 VPS」常驻栏取消，改为「一键同步 ▾」下拉勾选目标
- 前端只与 JSON API 交互，API 响应格式在拆 `server.py` 时整理并固定

## 4. 阶段目标

### 阶段 1：后端拆模块（纯搬家，行为不变）
- 按 3.1 边界拆分，`app.py` 变入口
- 不改任何端点行为、不改 DB 结构

### 阶段 2：detect_common 收敛
- 建 `scripts/` 模板体系，启动时内存拼装
- collector / agent / webhook 三脚本共用一份 detect 实现

### 阶段 3：新前端
- `static/` 落地，Linear 浅色风，布局 v2
- 所有交互走 JSON API

### 阶段 4：部署弗里蒙特 + 验收
- 线上部署、数据兼容验证、全功能回归

## 5. 验收标准

### 阶段 1
- [ ] `python3 -m py_compile` 全部模块通过
- [ ] 本地启动后现有 API 端点全部返回与重构前一致的结果
- [ ] 弗里蒙特部署后 `/healthz` 200，容器 healthy
- [ ] 登录、列表加载、保存、同步各跑通一次

### 阶段 2
- [ ] `rg` 确认 `detect_source_file` 等函数全仓库仅一份实现
- [ ] `/install.sh` 公网输出含内联后的 detect 逻辑且可执行
- [ ] 一台测试 VPS 走通 register → sync pending → agent poll → report 全链路

### 阶段 3（含用户强约束）
- [ ] **页面上每一个按钮都有明确反馈**（loading / 成功 / 失败提示），无任何点击无响应的按钮
- [ ] **无 UI 元素重叠**（各分辨率下左栏/主区/右栏/弹窗不互相遮挡）
- [ ] **所有功能真实可用**：每个按钮背后都有真实 API 调用并产生真实效果，无占位/假按钮
- [ ] 布局与 mockup v2 一致；左栏信息卡完整；到期 ≤ 5 天橙色高亮
- [ ] 浏览器控制台无 JS 报错

### 阶段 4
- [ ] 弗里蒙特线上 SQLite 数据完整（8 台 VPS、订阅、源、日志）
- [ ] Cloudflare Challenge、noindex、Cookie 属性、登录限速均生效
- [ ] 全功能回归清单逐项通过

## 6. 约束

1. **强约束（用户指定）**：web 所有按钮有反馈、无重叠、真实可用
2. **强约束**：现有功能全部保留，不允许静默砍功能
3. 不把 VPS SSH 密码、Cloudflare 全局 key、长期 API token 存入 SQLite
4. 保留安全机制：`X-Robots-Tag: noindex`、`HttpOnly; Secure; SameSite=Lax` Cookie、登录限速（10 分钟 5 次）、`/login` 与 `/api/login` 的 Cloudflare Managed Challenge
5. 后端只用 Python stdlib；前端零构建工具
6. 最小改动原则：重构不加新功能（新功能另开项目）
7. 部署目标：弗里蒙特 VPS（洛杉矶已迁移）

## 7. 明确不做（YAGNI）

- 不换 FastAPI / Go
- 不引入 npm / Vite / 前端框架
- 不做多用户权限体系
- 不改 agent 通信协议（仅收敛代码，不改行为）
