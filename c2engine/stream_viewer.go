// Package c2engine/stream_viewer 提供 StreamViewer 的 gorilla/websocket 实现。
// Package c2engine/stream_viewer provides the gorilla/websocket implementation
// of StreamViewer, so the panel's WebSocket handlers can register a live viewer
// with the StreamHub without c2engine importing controllers.
// Compatibility notes in this file describe the current implementation and available analysis evidence; they are not a guarantee of complete behavioral parity.
// Treat security-sensitive assumptions as unverified until confirmed by tests or direct review.

package c2engine

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsStreamViewer 把一条 WebSocket 连接包装成 StreamViewer。
// wsStreamViewer wraps one WebSocket connection as a StreamViewer.
//
// gorilla/websocket allows only one concurrent writer per connection, so every
// send goes through writeMu.
type wsStreamViewer struct {
	conn    *websocket.Conn
	writeMu sync.Mutex
	kind    string
	client  int64
}

// NewWSStreamViewer 包装连接为查看者。
// NewWSStreamViewer wraps a connection as a viewer.
//
// Callers must run a reader on the connection (the panel handlers do): a
// connection is only ever driven by one reader goroutine, and having the
// handler read is what keeps the viewer's disconnect observable.
func NewWSStreamViewer(conn *websocket.Conn, kind string, clientID int64) StreamViewer {
	return &wsStreamViewer{conn: conn, kind: kind, client: clientID}
}

// CloseOnExit 让查看者连接在会话结束时退出（发送关闭帧后关闭连接）。
// CloseOnExit ends the viewer connection when a session shuts down.
func (v *wsStreamViewer) CloseOnExit() {
	v.Close()
}

// write 写入一条消息（串行化；带写超时，避免慢查看者挂死转发协程）。
func (v *wsStreamViewer) write(msgType int, data []byte) error {
	v.writeMu.Lock()
	defer v.writeMu.Unlock()
	_ = v.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return v.conn.WriteMessage(msgType, data)
}

// SendBinary 发送二进制帧（屏幕帧）。
func (v *wsStreamViewer) SendBinary(data []byte) error {
	return v.write(websocket.BinaryMessage, data)
}

// SendText 发送文本帧（终端输出）。
func (v *wsStreamViewer) SendText(data []byte) error {
	return v.write(websocket.TextMessage, data)
}

// SendJSON 发送控制消息。
func (v *wsStreamViewer) SendJSON(payload interface{}) error {
	v.writeMu.Lock()
	defer v.writeMu.Unlock()
	_ = v.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return v.conn.WriteJSON(payload)
}

// Close 关闭连接。
func (v *wsStreamViewer) Close() error {
	return v.conn.Close()
}
