<div align="center">

# VShell

**逆向工程研究 · Go**

基于二进制分析与行为验证，对 VShell v3.0 进行不完整、独立的重新实现研究。

[English](README.md) · [简体中文](README.zh-CN.md)

</div>

> **研究声明：** 本项目尚未完成，仅用于授权环境中的安全研究与学习；与原作者无关联，不附带原版软件许可，功能和协议兼容性均不作保证。

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![Research](https://img.shields.io/badge/方向-逆向工程-64748b)](#逆向工程状态)
[![License](https://img.shields.io/badge/license-见%20license.txt-red)](license.txt)

---

## 简介

VShell 是对原版 VShell C2（命令与控制）管理框架的不完整开源复刻。包含 Web 管理面板、多协议 C2 引擎（HTTP/HTTPS、DNS、KCP、WebSocket/CDN）以及具备远程终端、屏幕直播、插件执行能力的 Agent。项目通过对原版 Windows 二进制（`v_windows_amd64.exe`）进行逆向分析并重新实现，内部细节大量依赖静态分析推断，可能存在缺失或不准确之处。

---

## 功能特性

| 模块 | 功能 |
|---|---|
| **Web 管理面板** | 登录认证、Basic Auth、JWT、仪表盘、客户端/监听器/任务管理、文件上传下载、屏幕查看 |
| **C2 引擎** | HTTP/HTTPS、DNS、KCP、CDN WebSocket 多协议监听；在线监控、健康检查、维护任务 |
| **Agent** | 远程终端、屏幕流、插件执行、任务下发/结果回传；VerifyKey + 加密盐握手 |
| **通知** | 钉钉 / 企业微信机器人告警（可选） |
| **持久化** | SQLite（web）+ JSON（engine）双存储 |

---

## 目录结构

```
vshell/
├── main.go            # 入口：加载配置、初始化引擎/数据库/路由
├── conf/              # 配置文件（gitignore 排除，含密钥）
├── c2engine/          # C2 引擎：监听器、协议、KCP/DNS、存储（SQL 层）
├── agent/             # Agent：终端/屏幕/插件；ldflags 注入配置
├── controllers/       # Web API 控制器
├── router/            # HTTP 路由与中间件
├── utils/             # 配置解析、认证、许可证、通知
└── static/            # 前端 SPA（从原版二进制提取）
```

---

## 快速开始

### 1. 构建

```bash
# 服务端 (Web + C2 Engine)
go build -o vshell-server .

# Agent（独立 module）
cd agent && go build -o agent.exe .
```

### 2. 配置

创建 `conf/setting.conf`（模板见 `utils/config.go` 的 `generateConfigContent`）：

```ini
master_type=web              # web / gui / all
web_port=8082
web_ip=0.0.0.0
web_basic_auth=true          # 防止被资产测绘收录
web_username=admin
web_password=<你的强密码>      # 留空则启动时自动生成随机密码并打印
web_jwt_secret=              # 留空则每次启动随机生成
```

> **安全提醒**：若 `setting.conf` 不存在，服务启动时自动生成随机管理密码并打印在日志中，代码内**不包含任何硬编码凭据**。请务必在部署后修改默认配置。

### 3. 运行

```bash
./vshell-server
# 浏览器访问: http://<ip>:8082/login
```

### 4. 构建 Agent（注入配置）

Agent 连接配置在编译时通过 `ldflags` 注入（对应 `agent/main.go` 中的 `ServerAddr`、`VerifyKey`、`EncryptSalt`）：

```bash
cd agent
go build -ldflags "\
  -X main.ServerAddr=REPLACE_SERVER_ADDR___XXXXXXXXXXXXXXXXXXXXXXXX \
  -X main.VerifyKey=REPLACE_VERIFY_KEY___XXXXXXXXXXXXXXXXXXXXXXXX \
  -X main.EncryptSalt=REPLACE_ENCRYPT_SALT_XXXXXXXXXXXXXXXXXXXXXXXX" \
  -o agent.exe .
```

### 5. 创建监听器

通过 Web 面板 API 动态创建监听器（`c2engine.NewListener(listenAddr, connectAddr, mode, verifyKey, encryptSalt, remark)`），支持模式：`http` / `https` / `dns` / `kcp` / `websocket`（CDN）。

---

## 逆向工程进度

> 本项目对原版 Windows 二进制（`v_windows_amd64.exe`，garble 混淆 Go 1.21+）进行**自顶向下**逆向：每个模块与 Ghidra 反编译结果 1:1 对齐，禁止自行臆造实现。以下为当前状态。

### 已实现（1:1 对齐 + 测试验证）

| 模块 | 对齐内容 | 验证 |
|---|---|---|
| `c2engine/storage.go` | SQL 层（clients/listeners/hosts/tasks 全表）与反编译 SQL 逐字段一致 | 运行时 DB schema 动态比对 ✓ |
| `c2engine/wire.go` | 24B 类型化字段帧（kind 字节 + flags + 3 dword） | 单测 ✓ |
| `c2engine/channel_frame.go` | 频道/隧道帧协议（FUN_011b4040/011b5600/011b5b40 等 6 函数） | 6 测试 ✓ |
| `c2engine/dns.go` | DNS 信道 = Go 标准 base32（无填充）；查询 = `[8B agent ID][消息].domain` | 测试 ✓ |
| `c2engine/kcp.go / protocol.go / engine.go` | KCP/协议/监听器调度 | 测试 ✓ |
| `controllers/*`（16 文件） | 全部控制器对齐反编译 API（登录/客户端/监听器/文件/下载/屏幕/隧道/插件） | 测试 ✓ |
| `router/` + `utils/` | 路由、中间件、配置、认证、许可证、通知 | 测试 ✓ |

**破解成果**：
- 登录：password = `web_password` 原文 → JWT（admin/qwe123qwe）
- 线格式：`<u32 LE 长度><加密载荷>`（strace 实锤）
- AES 密钥：`22f97f672c3c5113d31fcaaad26fce42`（密钥调度逆推，rk1 验证）
- Agent 二进制提取：5+ 变体（linux_amd64/386/arm、darwin、tcp/dns/ws），动态注册 clientId 2-14
- Agent 配置 JSON：`{server,type,vkey,proxy,salt,l,e,d,h}` 全捕获
- **消息帧结构**：`[16B IV][21B ct]` = 37B；PT = JSON 直接（`{"VerifyKey":"0l...`）
- **counter 结构**：`[rbx 运行时常量][len 0x0015×4 广播]`；state = counter XOR key
- **消息加密算法（0x458f00）完全破解**（session 533，gdb XMM 追踪）：state=aesenc(ctr^key)、3×aesenc 自密钥、双块路径、CBC 链——字节级验证；Go 实现见 `agent/message_crypto.go`。后续 gdb（session 535）显示 0x458f00 的 `rcx=0x15` 调用实际是 garble 字符串解密；消息加密循环经函数指针分派，尚未静态定位。块密码本身与 gdb XMM 捕获字节级一致。
- 线帧模块 `agent/message_wire.go`：`<u32 LE len><[16B IV][ct]>`，ct = payload XOR 密钥流（msgKeyStream）；IV 每消息独立。注意：解密方向尚未逆出——已恢复的密钥流依赖明文（CBC 链输入），服务器侧解密仍待解决。
- 服务器 AES-128（FUN_0053a1e0）实现验证 roundtrip；T 表 = 标准 Td0 字节交换变体
- Channel/隧道对象（会话 230-237）、Client 结构体（22 字段 @ 0x1bb9580）、Checkin 链全部解码

### 未实现

| 项 | 状态 | 难度 |
|---|---|---|
| **0x458f00 精确轮结构** | **已破解**（session 533）：counter=[rbx LE][len 广播]；state=aesenc(ctr^key)；3×aesenc 自密钥；21B 走双块路径；CBC 链——与 gdb XMM 捕获字节级验证 | 完成 |
| **Agent 999 函数全量映射** | **632 函数已映射**（`.re/decomp/agent_map_*.txt`）：完整管线解码——主状态机 0xfb1440 → 解码 → 表达式引擎 → 执行器（182-opcode 0x101df40 + 0x155-opcode 0x10f3220）→ 24B 帧构建 → 传输（池化连接 0xfc7560）→ 会话 CRUD → 结果发送；SQLite 驱动 + garble 字符串池（0xf50000-0xfb0000）、脚本解释器链（词法 0x10f9bc0 → 循环 0x10f8e40 → 核心 0x10f3220 → 执行器 0x10fa480）、插件子系统（分派 0x1153100 → 任务执行 0x1152dc0）。架构文档：`.re/AGENT_ARCHITECTURE.md` | 大量 |
| **Agent 源码对齐** | `agent/main.go`（1607 行）为早期未对齐版本；实际加密 = 自定义链（非标准 AES-GCM）。`message_crypto.go`（0x458f00 链，字节级验证）+ `message_wire.go`（u32-LE 帧）+ `transport_real.go`（池化 TCP，FUN_00fc7560/00fc9de0）已落地；main.go 现可经 'tcp'/'raw' 模式走对齐传输。命令/终端/屏幕路径仍为重建实现 | 高 |
| **消息解密方向** | 密钥流 = msgKeyStream(pt) 依赖明文（CBC 链）；服务器侧逆实现尚未推导 | 高 |
| **serT 状态机字符串** | FUN_017019c0 深加密，已放弃静态解 | 极高 |
| **226B 解密 stub** | FUN_011a02e0/01564720 静态求解受阻 | 高 |
| **DNS 注册完整闭环** | 需消息帧解密完成后验证 | 中 |

---

## 已知限制

> 由于是**不完整**逆向工程，以下方面可能与原版不一致：

- **License 校验**：原版 RSA 私钥**未包含**在仓库中（`conf/license.pem` 需自行配置）；未配置时运行在"观察模式"，许可证值来自观测推断（`LicenseName=public, LimitClient=99, VIP=true`）。
- **前端资产**：`static/` 中的 SPA 提取自原版二进制，部分表单默认值可能与新版不同。
- **Agent 行为**：平台特化代码（进程隐藏、持久化等）为最小实现。
- **协议兼容性**：与官方服务端/客户端的互通性**未经保证**，仅供独立研究。

---

## 技术栈

Go 1.25 · gorilla/websocket · kcp-go/v5 · modernc.org/sqlite · gorilla/sessions

---

## 许可

本仓库不含原版许可；所有权利归原版作者所有。**仅供研究使用，禁止商用或非法用途。**
