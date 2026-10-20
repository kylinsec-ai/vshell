// Package c2engine/stream_hub 实现终端与屏幕实时流的查看者注册表。
// Package c2engine/stream_hub implements the viewer registry that relays an
// agent's live terminal output and screen frames to web-panel WebSocket
// viewers.
//
// 数据通路（对齐原版控制器 FUN_018eeee0 屏幕 / FUN_018f06c0 终端：
// 均以客户端 ID 为键建立会话，再把服务端 <-> 代理的流式载荷原样转发给浏览器）：
//
//	agent → listener /api/result ("terminal_output:…" / "screen_frame:…")
//	      → forwardStreamingResult → StreamHub.Publish
//	      → 对应客户端 ID 的所有 WebSocket 查看者
//	viewer → WebSocket → StreamHub.Send (终端按键等) → 代理任务队列
//
// 由于 c2engine 不能反向引用 controllers（会形成循环导入），查看者以
// StreamViewer 接口注入：控制器实现它（底层是 gorilla/websocket 连接），
// 引擎只负责按客户端 ID 路由。
// Compatibility notes in this file describe the current implementation and available analysis evidence; they are not a guarantee of complete behavioral parity.
// Treat security-sensitive assumptions as unverified until confirmed by tests or direct review.

package c2engine

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"strings"
	"sync"
)

// StreamViewer 是一个 WebSocket 查看者（终端或屏幕）。
// StreamViewer is a single WebSocket viewer (terminal or screen).
type StreamViewer interface {
	// SendBinary 向查看者发送二进制帧（屏幕帧：zlib 压缩图像）。
	// SendBinary sends a binary frame (screen frames: zlib-compressed image).
	SendBinary(data []byte) error
	// SendText 向查看者发送文本帧（终端输出：原始 shell 字节）。
	// SendText(data []byte) sends a text frame (terminal output: raw shell bytes).
	SendText(data []byte) error
	// SendJSON 向查看者发送控制消息（{type:"10"} 等）。
	SendJSON(v interface{}) error
	// Close 关闭查看者连接。
	Close() error
}

// streamKind 区分终端流与屏幕流（二者按客户端 ID 各自独立注册）。
// streamKind distinguishes the terminal stream from the screen stream; the two
// register independently under the same client ID.
type streamKind int

const (
	streamTerminal streamKind = iota
	streamScreen
)

// StreamHub 按 (客户端 ID, 流类型) 维护查看者集合，并把代理结果路由过去。
var (
	streamMu       sync.RWMutex
	streamViewers  = map[streamKind]map[int64]map[StreamViewer]struct{}{}
	streamSessions = map[streamKind]map[int64]*StreamSession{}
)

// StreamTerminal / StreamScreen 是查看会话的流类型标识。
// StreamTerminal / StreamScreen identify a viewing session's stream kind.
const (
	StreamTerminal = "terminal"
	StreamScreen   = "screen"
)

// StreamTimeout 是查看会话命令的默认超时（秒）。
// StreamTimeout is the default timeout for viewing-session commands.
//
// Interactive commands (terminal_start/input, screen_capture_start) are
// deliberately short-lived: the agent answers them immediately with an ack and
// then streams output through separate result submissions, so a long timeout
// would only delay stuck-task cleanup.
const StreamTimeout = 5

// StreamSession 是一次查看会话（一个查看者 + 该查看者归属的任务 ID）。
// StreamSession is one viewing session: a viewer plus the task ID that carries
// this viewer's traffic down to the agent.
type StreamSession struct {
	Viewer   StreamViewer
	ClientID int64
	TaskID   int64
}

// RegisterViewer 登记一个查看者。
// RegisterViewer adds a viewer to the (kind, clientID) set.
func RegisterViewer(kind string, clientID int64, v StreamViewer) {
	k := parseStreamKind(kind)
	streamMu.Lock()
	defer streamMu.Unlock()
	m := streamViewers[k]
	if m == nil {
		m = map[int64]map[StreamViewer]struct{}{}
		streamViewers[k] = m
	}
	set := m[clientID]
	if set == nil {
		set = map[StreamViewer]struct{}{}
		m[clientID] = set
	}
	set[v] = struct{}{}
}

// UnregisterViewer 注销一个查看者。
// UnregisterViewer removes a viewer from the (kind, clientID) set.
func UnregisterViewer(kind string, clientID int64, v StreamViewer) {
	k := parseStreamKind(kind)
	streamMu.Lock()
	defer streamMu.Unlock()
	m := streamViewers[k]
	if m == nil {
		return
	}
	if set := m[clientID]; set != nil {
		delete(set, v)
		if len(set) == 0 {
			delete(m, clientID)
		}
	}
}

// ViewerCount 返回某客户端某类流的查看者数量（测试与诊断用）。
// ViewerCount returns how many viewers watch a given client's stream.
func ViewerCount(kind string, clientID int64) int {
	k := parseStreamKind(kind)
	streamMu.RLock()
	defer streamMu.RUnlock()
	if m := streamViewers[k]; m != nil {
		return len(m[clientID])
	}
	return 0
}

// SetStreamSession 记录查看会话（查看者 <-> 代理任务 ID）。
// SetStreamSession records a viewing session (viewer -> agent task ID).
func SetStreamSession(kind string, clientID int64, s *StreamSession) {
	k := parseStreamKind(kind)
	streamMu.Lock()
	defer streamMu.Unlock()
	m := streamSessions[k]
	if m == nil {
		m = map[int64]*StreamSession{}
		streamSessions[k] = m
	}
	m[clientID] = s
}

// GetStreamSession 取回查看会话。
// GetStreamSession returns the viewing session for a client, if any.
func GetStreamSession(kind string, clientID int64) *StreamSession {
	k := parseStreamKind(kind)
	streamMu.RLock()
	defer streamMu.RUnlock()
	if m := streamSessions[k]; m != nil {
		return m[clientID]
	}
	return nil
}

// ClearStreamSession 清除查看会话。
// ClearStreamSession drops the viewing session for a client.
func ClearStreamSession(kind string, clientID int64) {
	k := parseStreamKind(kind)
	streamMu.Lock()
	defer streamMu.Unlock()
	if m := streamSessions[k]; m != nil {
		delete(m, clientID)
	}
}

// publish 把一帧载荷投递给某客户端某类流的全部查看者，返回投递到的查看者数。
// publish fans a payload out to every viewer of (kind, clientID) and returns
// how many viewers accepted it.
func publish(kind streamKind, clientID int64, payload []byte, binary bool) int {
	streamMu.RLock()
	var targets []StreamViewer
	if m := streamViewers[kind]; m != nil {
		for v := range m[clientID] {
			targets = append(targets, v)
		}
	}
	streamMu.RUnlock()

	delivered := 0
	for _, v := range targets {
		var err error
		if binary {
			err = v.SendBinary(payload)
		} else {
			err = v.SendText(payload)
		}
		if err == nil {
			delivered++
		}
	}
	return delivered
}

// streamResultPrefix 与 agent 端提交的流式结果前缀一致。
// streamResultPrefix matches the prefixes the agent uses for streaming results.
const (
	terminalResultPrefix = "terminal_output:"
	screenResultPrefix   = "screen_frame:"
)

// HandleStreamingResult 解析代理提交的流式结果并转发给查看者。
// 返回 true 表示该结果属于流式类型（调用方不应把它当作普通任务结果存储）。
//
// screen_frame 载荷格式：screen_frame:<format>:<index>[:<quality>]:<base64>
//   - <base64> 是已采集的完整图像文件（PNG）。
//   - 最后一个 ":" 之后才是 base64，因此新老格式（含/不含 quality 段）都能解析。
//   - 浏览器端（SPA 的 F(screenWsData)）先 inflate 再当 <img> 用，因此这里
//     用 zlib 压缩后再下发（原版屏幕协议同样压缩图像以节省带宽）。
//
// terminal_output 载荷格式：terminal_output:<base64 of raw shell bytes>
//   - xterm.js 需要原始字节，原文直接以文本帧下发。
func HandleStreamingResult(clientID int64, result string) bool {
	switch {
	case strings.HasPrefix(result, terminalResultPrefix):
		raw, err := base64.StdEncoding.DecodeString(
			strings.TrimPrefix(result, terminalResultPrefix))
		if err != nil {
			// Not base64: forward the raw remainder verbatim.
			raw = []byte(strings.TrimPrefix(result, terminalResultPrefix))
		}
		publish(streamTerminal, clientID, raw, false)
		return true

	case strings.HasPrefix(result, screenResultPrefix):
		payload := strings.TrimPrefix(result, screenResultPrefix)
		// The base64 blob is always the last ":"-separated field; the leading
		// format / index / quality fields carry no viewer-side data.
		if i := strings.LastIndex(payload, ":"); i >= 0 {
			payload = payload[i+1:]
		}
		img, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			img = []byte(payload)
		}
		frame, err := compressStreamFrame(img)
		if err != nil {
			frame = img
		}
		publish(streamScreen, clientID, frame, true)
		return true
	}
	return false
}

// StreamSessionTaskID 返回查看会话当前的代理任务 ID（0 表示无）。
// StreamSessionTaskID returns the session's current agent task ID (0 = none).
func StreamSessionTaskID(kind string, clientID int64) int64 {
	if s := GetStreamSession(kind, clientID); s != nil {
		return s.TaskID
	}
	return 0
}

// compressStreamFrame zlib-compresses a screen frame. The SPA inflates every
// binary screen message before handing it to <img> (module F in
// static/assets/vBhoZX99Z.js is pako's zlib inflate).
//
// 压缩级别是占位值（zlib.BestSpeed），不是原版参数：原版屏幕通道的质量
// 换算函数尚未定位，quality 目前只用于构造 screen_capture_start（见
// controllers/screen.go 的 screenCaptureParams，同样标为占位）。SPA 只要求
// "能 inflate"，因此任意合法 zlib 级别都能工作——但不要把它当成对齐结果。
//
// The level is a placeholder, not the original's parameter: only "the SPA must be
// able to inflate it" is established, and any valid zlib level satisfies that.
func compressStreamFrame(img []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(img); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseStreamKind(kind string) streamKind {
	if kind == "screen" {
		return streamScreen
	}
	return streamTerminal
}
