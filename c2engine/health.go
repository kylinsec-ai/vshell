package c2engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Health Checker - periodic health monitoring for tunnels and hosts
// 健康检查器——对隧道与反代 Host 的周期性健康监测
// ============================================================================
// HealthChecker performs periodic health checks on tunnels and reverse proxies.
type HealthChecker struct {
	mu       sync.RWMutex
	engine   *Engine
	interval time.Duration
	running  bool
	stopCh   chan struct{}
}

var healthChecker *HealthChecker
var healthOnce sync.Once
// GetHealthChecker returns the singleton health checker.
func GetHealthChecker() *HealthChecker {
	healthOnce.Do(func() {
		healthChecker = &HealthChecker{
			engine:   GetEngine(),
			interval: 30 * time.Second,
			stopCh:   make(chan struct{}),
		}
	})
	return healthChecker
}
// Start begins periodic health checking.
func (hc *HealthChecker) Start() {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if hc.running {
		return
	}

	hc.running = true
	go hc.run()
	Logf("Health checker started (interval: %v)", hc.interval)
}
// Stop halts health checking.
func (hc *HealthChecker) Stop() {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if !hc.running {
		return
	}

	close(hc.stopCh)
	hc.running = false
}

func (hc *HealthChecker) run() {
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-hc.stopCh:
			return
		case <-ticker.C:
			hc.checkAll()
		}
	}
}

func (hc *HealthChecker) checkAll() {
	hc.engine.mu.RLock()
	tunnels := make([]*Tunnel, 0, len(hc.engine.tunnels))
	for _, t := range hc.engine.tunnels {
		tunnels = append(tunnels, t)
	}
	hosts := make([]*Host, 0, len(hc.engine.hosts))
	for _, h := range hc.engine.hosts {
		hosts = append(hosts, h)
	}
	hc.engine.mu.RUnlock()

	// Limit concurrent health checks to prevent unbounded goroutine growth
	maxConcurrent := 20
	sem := make(chan struct{}, maxConcurrent)

	// Check tunnels
	for _, t := range tunnels {
		sem <- struct{}{}
		go func(tunnel *Tunnel) {
			defer func() { <-sem }()
			hc.checkTunnel(tunnel)
		}(t)
	}

	// Check hosts
	for _, h := range hosts {
		sem <- struct{}{}
		go func(host *Host) {
			defer func() { <-sem }()
			hc.checkHost(host)
		}(h)
	}
}

func (hc *HealthChecker) checkTunnel(t *Tunnel) {
	if t.Health.CheckType == "" {
		return // No health check configured
	}

	switch t.Health.CheckType {
	case "tcp":
		hc.checkTCP(t.TargetAddr, t.Health)
	case "http":
		hc.checkHTTP(t.TargetAddr, t.Health)
	case "icmp":
		hc.checkICMP(t.TargetAddr, t.Health)
	default:
		t.Health.RecordSuccess()
	}

	if t.Health.IsFailing() {
		Logf("Tunnel %d health check failed (%d/%d), marking for restart",
			t.ID, t.Health.failCount, t.Health.MaxFail)
	}
}

func (hc *HealthChecker) checkHost(h *Host) {
	target := h.TargetStr
	if h.Health.CheckType == "" {
		return
	}

	switch h.Health.CheckType {
	case "tcp":
		hc.checkTCP(target, h.Health)
	case "http":
		hc.checkHTTP(target, h.Health)
	case "icmp":
		hc.checkICMP(target, h.Health)
	default:
		h.Health.RecordSuccess()
	}

	if h.Health.IsFailing() {
		Logf("Host %d health check failed (%d/%d)", h.ID, h.Health.failCount, h.Health.MaxFail)
	}
}

func (hc *HealthChecker) checkTCP(addr string, health *Health) {
	if addr == "" {
		health.RecordSuccess()
		return
	}

	conn, err := net.DialTimeout("tcp", addr, health.CheckTimeout)
	if err != nil {
		health.RecordFail()
		return
	}
	conn.Close()
	health.RecordSuccess()
}

func (hc *HealthChecker) checkHTTP(url string, health *Health) {
	if url == "" {
		health.RecordSuccess()
		return
	}

	// Ensure URL has scheme
	if len(url) > 0 && url[0] != 'h' {
		url = "http://" + url
	}

	client := &http.Client{Timeout: health.CheckTimeout}
	resp, err := client.Get(url)
	if err != nil {
		health.RecordFail()
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		health.RecordSuccess()
	} else {
		health.RecordFail()
	}
}

// checkICMP performs an ICMP echo (ping) health check using the system ping command.
// On Windows: ping -n 1 -w <timeout_ms> <host>
// On Linux/macOS: ping -c 1 -W <timeout_sec> <host>
func (hc *HealthChecker) checkICMP(target string, health *Health) {
	if target == "" {
		health.RecordSuccess()
		return
	}

	// Extract host from "host:port" format if present
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}

	timeout := health.CheckTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		timeoutMs := int(timeout.Milliseconds())
		if timeoutMs < 1000 {
			timeoutMs = 1000
		}
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", timeoutMs), host)
	} else {
		timeoutSec := int(timeout.Seconds())
		if timeoutSec < 1 {
			timeoutSec = 1
		}
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutSec), host)
	}

	output, err := cmd.CombinedOutput()
	outStr := string(output)

	// Check for success indicators in output regardless of exit code.
	// Some ping implementations return non-zero on certain failures while
	// the output still shows a reply (e.g., "Reply from" on Windows or
	// "bytes from" on Linux with partial loss). Rely on the output text
	// rather than the process exit code.
	if strings.Contains(outStr, "TTL=") || strings.Contains(outStr, "ttl=") ||
		strings.Contains(outStr, "bytes from") || strings.Contains(outStr, "1 received") ||
		strings.Contains(outStr, "Reply from") {
		health.RecordSuccess()
		return
	}

	if err != nil {
		health.RecordFail()
		return
	}
	health.RecordFail()
}

// ============================================================================
// Periodic Maintenance - cleanup stale sessions, idle terminals, etc.
// 周期性维护——清理过期会话、空闲终端等
// ============================================================================
// MaintenanceRunner handles periodic cleanup tasks.
type MaintenanceRunner struct {
	mu       sync.RWMutex
	engine   *Engine
	interval time.Duration
	running  bool
	stopCh   chan struct{}
}

var maintenance *MaintenanceRunner
var maintOnce sync.Once
// GetMaintenanceRunner returns the singleton maintenance runner.
func GetMaintenanceRunner() *MaintenanceRunner {
	maintOnce.Do(func() {
		maintenance = &MaintenanceRunner{
			engine:   GetEngine(),
			interval: 60 * time.Second,
			stopCh:   make(chan struct{}),
		}
	})
	return maintenance
}
// Start begins periodic maintenance.
func (mr *MaintenanceRunner) Start() {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	if mr.running {
		return
	}

	mr.running = true
	go mr.run()
	Logf("Maintenance runner started (interval: %v)", mr.interval)
}
// Stop halts maintenance.
func (mr *MaintenanceRunner) Stop() {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	if !mr.running {
		return
	}

	close(mr.stopCh)
	mr.running = false
}

func (mr *MaintenanceRunner) run() {
	ticker := time.NewTicker(mr.interval)
	defer ticker.Stop()

	for {
		select {
		case <-mr.stopCh:
			return
		case <-ticker.C:
			mr.cleanupStaleClients()
			mr.cleanupStaleTasks()
			mr.cleanupOfflineTunnels()
		}
	}
}

// cleanupStaleClients marks clients as offline if they haven't checked in
func (mr *MaintenanceRunner) cleanupStaleClients() {
	cutoff := time.Now().Add(-5 * time.Minute)

	mr.engine.mu.Lock()
	defer mr.engine.mu.Unlock()

	staleCount := 0
	for _, client := range mr.engine.clients {
			if client.LastSeen.Before(cutoff) {
				client.IsConnect = false
				client.NowConn = 0
				staleCount++
		}
	}

	if staleCount > 0 {
		Logf("Maintenance: marked %d clients as offline", staleCount)
	}
}

// cleanupStaleTasks marks timed-out tasks as failed
func (mr *MaintenanceRunner) cleanupStaleTasks() {
	cutoff := time.Now().Add(-10 * time.Minute)

	mr.engine.mu.Lock()
	defer mr.engine.mu.Unlock()

	staleCount := 0
	for _, task := range mr.engine.tasks {
			if task.Status == "dispatched" && task.SentAt.Before(cutoff) {
				task.Status = "timeout"
				staleCount++
		}
	}

	if staleCount > 0 {
		Logf("Maintenance: marked %d tasks as timeout", staleCount)
	}
}

// cleanupOfflineTunnels stops tunnels for offline clients
func (mr *MaintenanceRunner) cleanupOfflineTunnels() {
	mr.engine.mu.Lock()
	defer mr.engine.mu.Unlock()

	for _, t := range mr.engine.tunnels {
		if client, ok := mr.engine.clients[t.ClientID]; ok {
			if !client.IsConnect {
				t.RunStatus = false
			}
		}
	}
}

// ============================================================================
// Heartbeat Monitor - tracks agent connectivity
// 心跳监视器——跟踪 Agent 连接状态
// ============================================================================

// HeartbeatMonitor tracks agent heartbeats and triggers alerts
type HeartbeatMonitor struct {
	mu            sync.RWMutex
	engine        *Engine
	missedBeats   map[int64]int     // clientID -> consecutive missed heartbeats
	maxMissedBeats int
	onDisconnect  func(clientID int64)
}

var heartbeatMon *HeartbeatMonitor
var heartbeatOnce sync.Once

// GetHeartbeatMonitor returns the singleton heartbeat monitor
func GetHeartbeatMonitor() *HeartbeatMonitor {
	heartbeatOnce.Do(func() {
		heartbeatMon = &HeartbeatMonitor{
			engine:         GetEngine(),
			missedBeats:    make(map[int64]int),
			maxMissedBeats: 3,
		}
	})
	return heartbeatMon
}

// SetOnDisconnect sets the callback for client disconnect
func (hm *HeartbeatMonitor) SetOnDisconnect(fn func(clientID int64)) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.onDisconnect = fn
}

// RecordHeartbeat records a heartbeat from a client
func (hm *HeartbeatMonitor) RecordHeartbeat(clientID int64) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	hm.missedBeats[clientID] = 0

	// Update client in engine
	if client := hm.engine.GetClient(clientID); client != nil {
		client.UpdateSeen()
	}
}

// CheckHeartbeats checks all clients for missed heartbeats
func (hm *HeartbeatMonitor) CheckHeartbeats() {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	for id := range hm.missedBeats {
		hm.missedBeats[id]++
		if hm.missedBeats[id] >= hm.maxMissedBeats {
			Logf("Heartbeat: client %d missed %d heartbeats, marking as disconnected", id, hm.missedBeats[id])
			if hm.onDisconnect != nil {
				hm.onDisconnect(id)
			}
			delete(hm.missedBeats, id)
		}
	}
}

// ============================================================================
// System Monitor - resource usage and stats
// ============================================================================

// SystemStats holds system-level statistics
type SystemStats struct {
	StartTime      time.Time `json:"start_time"`
	UptimeSeconds  int64     `json:"uptime_seconds"`
	TotalCheckins  int64     `json:"total_checkins"`
	TotalCommands  int64     `json:"total_commands"`
	TotalUploads   int64     `json:"total_uploads"`
	TotalDownloads int64     `json:"total_downloads"`
	ActiveClients  int       `json:"active_clients"`
	ActiveListeners int      `json:"active_listeners"`
	ActiveTunnels  int       `json:"active_tunnels"`
}

var sysStats = &SystemStats{
	StartTime: time.Now(),
}
var sysStatsMu sync.RWMutex

// GetSystemStats returns current system statistics
func GetSystemStats() *SystemStats {
	sysStatsMu.RLock()
	defer sysStatsMu.RUnlock()

	engine := GetEngine()
	stats := engine.GetStats()

	s := *sysStats // Copy
	s.UptimeSeconds = int64(time.Since(s.StartTime).Seconds())
	s.ActiveClients = stats.OnlineClients
	s.ActiveListeners = stats.TotalListeners
	s.ActiveTunnels = stats.ActiveTunnels
	return &s
}

// IncrementCheckins increments the checkin counter
func IncrementCheckins() {
	sysStatsMu.Lock()
	defer sysStatsMu.Unlock()
	sysStats.TotalCheckins++
}

// IncrementCommands increments the command counter
func IncrementCommands() {
	sysStatsMu.Lock()
	defer sysStatsMu.Unlock()
	sysStats.TotalCommands++
}

// IncrementUploads increments the upload counter
func IncrementUploads() {
	sysStatsMu.Lock()
	defer sysStatsMu.Unlock()
	sysStats.TotalUploads++
}

// IncrementDownloads increments the download counter
func IncrementDownloads() {
	sysStatsMu.Lock()
	defer sysStatsMu.Unlock()
	sysStats.TotalDownloads++
}

// ============================================================================
// Tunnel Auto-Recovery
// ============================================================================

// RecoveryManager attempts to auto-restart failed tunnels
type RecoveryManager struct {
	mu           sync.RWMutex
	engine       *Engine
	maxRetries   int
	retryDelays  map[int64]int // tunnel ID -> retry count
}

var recovery *RecoveryManager
var recoveryOnce sync.Once

// GetRecoveryManager returns the singleton recovery manager
func GetRecoveryManager() *RecoveryManager {
	recoveryOnce.Do(func() {
		recovery = &RecoveryManager{
			engine:      GetEngine(),
			maxRetries:  3,
			retryDelays: make(map[int64]int),
		}
	})
	return recovery
}

// AttemptRecovery tries to restart a failed tunnel
func (rm *RecoveryManager) AttemptRecovery(tunnelID int64) error {
	rm.mu.Lock()
	retries := rm.retryDelays[tunnelID]
	if retries >= rm.maxRetries {
		delete(rm.retryDelays, tunnelID)
		rm.mu.Unlock()
		return fmt.Errorf("max retries (%d) exceeded for tunnel %d", rm.maxRetries, tunnelID)
	}

	rm.retryDelays[tunnelID] = retries + 1
	rm.mu.Unlock()

	// Exponential backoff (not holding the lock during sleep)
	delay := time.Duration(1<<uint(retries)) * time.Second
	time.Sleep(delay)

	tunnel := rm.engine.GetTunnel(tunnelID)
	if tunnel == nil {
		return fmt.Errorf("tunnel %d not found", tunnelID)
	}

	Logf("Recovery: restarting tunnel %d (attempt %d/%d)", tunnelID, retries+1, rm.maxRetries)

	// Reset health state
	tunnel.Health.RecordSuccess()
	tunnel.RunStatus = true

	return nil
}

// ============================================================================
// Convenience: start all background services
// ============================================================================

// StartBackgroundServices starts all periodic background tasks
func StartBackgroundServices() {
	GetHealthChecker().Start()
	GetMaintenanceRunner().Start()

	// Start heartbeat checker
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			GetHeartbeatMonitor().CheckHeartbeats()
		}
	}()

	Logf("All background services started")
}

// StopBackgroundServices stops all background tasks
func StopBackgroundServices() {
	GetHealthChecker().Stop()
	GetMaintenanceRunner().Stop()
	Logf("All background services stopped")
}

// ============================================================================
// Context-aware health check
// ============================================================================

// HealthCheck performs a one-time health check with timeout
func HealthCheck(target string, checkType string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	switch checkType {
	case "tcp":
		return tcpCheck(ctx, target)
	case "http":
		return httpCheck(ctx, target)
	case "icmp":
		return icmpCheck(ctx, target)
	default:
		return fmt.Errorf("unknown check type: %s", checkType)
	}
}

func tcpCheck(ctx context.Context, addr string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func httpCheck(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode >= 500 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func icmpCheck(ctx context.Context, target string) error {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "3000", host)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "3", host)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ping failed: %w (output: %s)", err, string(output))
	}

	outStr := string(output)
	if strings.Contains(outStr, "TTL=") || strings.Contains(outStr, "ttl=") ||
		strings.Contains(outStr, "bytes from") || strings.Contains(outStr, "Reply from") {
		return nil
	}
	return fmt.Errorf("no ping response from %s", host)
}

