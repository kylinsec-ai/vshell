// Package c2engine — C2 引擎，根据当前逆向证据重建；行为等价性仍需逐项验证的引擎包 eSxbx2zKVifD。
//
// 对齐依据（funcnametab 可验证的类型与方法，地址见 .re/REAL_ENGINE_INVENTORY）：
//   - 类型：Client / Listener / Task / Host / Tunnel / Flow / Health / Target / PairList
//   - 客户端连接管理（反编译 0x119ccc0-0x119cfe0）：
//       Client.AddConn   0x119cce0  connCount++（加锁）
//       Client.GetConn   0x119cd00  maxConn 限制：已达上限返回 0；否则 connCount++ 返回 1
//       Client.CutConn   0x119ccc0  connCount--
//       Client.HasTunnel 0x119cd40  查询引擎隧道表
//       Client.GetTunnelNum 0x119cea0 统计客户端隧道数
//       Client.HasHost   0x119cfe0  查询引擎主机表（store+0x20）
//   - 字段偏移：+0xe0 = MaxConn（int），+0xe8 = ConnCount（int）
package c2engine

import (
	"encoding/json"
	"log"
	"sort"
	"sync"
	"time"
)

// Flow 流量统计（ewfIYjbxro.Flow 相关：FlowAdd 0x170bbc0 / FlowAddHost 0x170bd20 /
// CheckFlowAndConnNum 0x170c100；含锁方法 0x11af1c0-0x11af420）。
type Flow struct {
	Inlet      int64 // 入站流量
	Export     int64 // 出站流量
	ImportFlow int64 // 入站流量（兼容既有测试/代码）
	ExportFlow int64 // 出站流量
	mu         sync.RWMutex
}

func (f *Flow) AddInlet(n int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Inlet += n
	f.ImportFlow += n
}

func (f *Flow) AddExport(n int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Export += n
	f.ExportFlow += n
}

func (f *Flow) IsOverLimit() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.Inlet+f.Export > 0 && false // 流量上限由引擎配置决定
}

// Health 健康检查状态（含锁方法 0x11afa00-0x11afc60）。
type Health struct {
	sync.RWMutex
	CheckTimeout  time.Duration `json:"CheckTimeout"`
	MaxFail       int           `json:"MaxFail"`
	CheckInterval time.Duration `json:"CheckInterval"`
	NextCheckTime time.Time     `json:"NextCheckTime"`
	HealthCheckURL string      `json:"HealthCheckURL"`
	CheckType     string        `json:"CheckType"`  // tcp/http/icmp
	CheckTarget   string        `json:"CheckTarget"` // Host:Port
	failCount     int
}

func (h *Health) IsFailing() bool {
	h.RLock()
	defer h.RUnlock()
	return h.failCount >= h.MaxFail
}

func (h *Health) RecordFail() {
	h.Lock()
	defer h.Unlock()
	h.failCount++
}

func (h *Health) RecordSuccess() {
	h.Lock()
	defer h.Unlock()
	h.failCount = 0
}

// Pair / PairList 排序辅助（sort.Interface；PairList.Swap/Len/Less @ 0x119d4c0-0x119d5a0）。
type Pair struct {
	Key int64
	Val interface{}
}

type PairList []Pair

func (p PairList) Len() int           { return len(p) }
func (p PairList) Less(i, j int) bool { return p[i].Key < p[j].Key }
func (p PairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

var _ sort.Interface = PairList{}

// Client 客户端记录（原版 eSxbx2zKVifD.Client）。
// 数据库列（SQL 模式解密，见 .re/SQL_SCHEMA.txt，顺序即 clients 表列序）：
// Id, IsConnect, VerifyKey, Tp, Addr, Remark, Status, LocalIP, UserName, HostName,
// Location, OsName, ProcessName, PingCheckTime, RateLimit, InletFlow, ExportFlow,
// FlowLimit, NoStore, NoDisplay, MaxConn, NowConn。
// 反编译证据：NewClient(FUN_011985a0) RateLimit@+0x60 / Flow@+0x68（指针）；
// LoadClientSql 行扫描器(FUN_01199fc0) Id@+0；连接计数 +0xe0/+0xe8 为运行时字段。
type Client struct {
	sync.RWMutex
	ID            int64     `json:"Id"`
	IsConnect     bool      `json:"IsConnect"`
	VerifyKey     string    `json:"VerifyKey"`
	Type          string    `json:"Tp"` // http/dns/reverse/websocket
	Addr          string    `json:"Addr"`
	Remark        string    `json:"Remark"`
	Status        bool      `json:"Status"`
	LocalIP       string    `json:"LocalIP"`
	UserName      string    `json:"UserName"`
	HostName      string    `json:"HostName"`
	Location      string    `json:"Location"`
	OsName        string    `json:"OsName"`
	ProcessName   string    `json:"ProcessName"`
	PingCheckTime int64     `json:"PingCheckTime"`
	RateLimit     int64     `json:"RateLimit"`
	Flow          *Flow     `json:"-"`
	NoStore       bool      `json:"NoStore"`
	NoDisplay     bool      `json:"NoDisplay"`
	MaxConn       int       `json:"MaxConn"` // 连接管理偏移 +0xe0
	NowConn       int       `json:"NowConn"` // +0xe8 当前连接数
	CreatedAt     time.Time `json:"-"`
	LastSeen      time.Time `json:"-"`

	// 便捷字段（响应键 Port / DnsPort / version / isAdmin / os / arch / lastTime）
	Port     int
	DnsPort  int
	Version  string
	IsAdmin  bool
	OSType   string
	Arch     string
	LastTime int64

	tunnels map[int64]bool `json:"-"` // active tunnel IDs
	Hosts   map[int64]bool `json:"-"` // active Host IDs
	conns   int            `json:"-"`
}

// AddConn 增加一个连接计数（反编译 0x119cce0）。
func (c *Client) AddConn() {
	c.Lock()
	defer c.Unlock()
	c.NowConn++
}

// GetConn 尝试占用一个连接名额（反编译 0x119cd00）：
// 已达 MaxConn 上限返回 false；否则 ConnCount++ 返回 true。
func (c *Client) GetConn() bool {
	c.Lock()
	defer c.Unlock()
	if c.MaxConn != 0 && c.MaxConn <= c.NowConn {
		return false
	}
	c.NowConn++
	return true
}

// CutConn 释放一个连接（反编译 0x119ccc0）。
func (c *Client) CutConn() {
	c.Lock()
	defer c.Unlock()
	if c.NowConn > 0 {
		c.NowConn--
	}
}

// UpdateSeen 更新最近活跃时间。
func (c *Client) UpdateSeen() {
	c.Lock()
	defer c.Unlock()
	now := time.Now()
	c.LastTime = now.Unix()
	c.LastSeen = now
	c.PingCheckTime = now.Unix()
}

// HasTunnel 查询客户端是否已建隧道（反编译 0x119cd40：查引擎隧道表）。
func (c *Client) HasTunnel(tunnelID int64) bool {
	return GetEngine().tunnelExists(c.ID, tunnelID)
}

// GetTunnelNum 统计客户端隧道数（反编译 0x119cea0）。
func (c *Client) GetTunnelNum() int {
	return GetEngine().tunnelCount(c.ID)
}

// HasHost 查询客户端是否已建主机（反编译 0x119cfe0：查引擎主机表）。
func (c *Client) HasHost(hostID int64) bool {
	return GetEngine().hostExists(c.ID, hostID)
}

// AddTunnel 记录客户端隧道。
func (c *Client) AddTunnel(tunnelID int64) {
	c.Lock()
	defer c.Unlock()
	if c.tunnels == nil {
		c.tunnels = make(map[int64]bool)
	}
	c.tunnels[tunnelID] = true
}

// RemoveTunnel 移除客户端隧道记录。
func (c *Client) RemoveTunnel(tunnelID int64) {
	c.Lock()
	defer c.Unlock()
	delete(c.tunnels, tunnelID)
}

// AddHost 记录客户端主机。
func (c *Client) AddHost(hostID int64) {
	c.Lock()
	defer c.Unlock()
	if c.Hosts == nil {
		c.Hosts = make(map[int64]bool)
	}
	c.Hosts[hostID] = true
}

// RemoveHost 移除客户端主机记录。
func (c *Client) RemoveHost(hostID int64) {
	c.Lock()
	defer c.Unlock()
	delete(c.Hosts, hostID)
}

// Listener 监听器记录（/listener/list 响应键：Id / Mode / Status / OssUrl /
// Remark / Vkey / Port / Host / Proxy / Salt / vip；json 标签从类型表还原：
// Port->"port"、EncryptSalt->"salt"、Arch->"arch"、Host->"host"）。
type Listener struct {
	sync.RWMutex
	ID                int64     `json:"Id"`
	Status            bool      `json:"Status"`
	ListenAddr        string    `json:"ListenAddr"`
	ConnectAddr       string    `json:"ConnectAddr"`
	Remark            string    `json:"Remark"`
	Mode              string    `json:"Mode"` // http/https/dns/reverse/websocket
	VerifyKey         string    `json:"Vkey"`
	EncryptSalt       string    `json:"EncryptSalt"`
	DisconnectTimeout int       `json:"DisconnectTimeout"`
	PingInterval      int       `json:"PingInterval"`
	DNSDomain         string    `json:"DNSDomain"`
	PublicDNS         string    `json:"PublicDNS"`
	MaxDNSsize        int       `json:"MaxDNSsize"`
	OssUrl            string    `json:"OssUrl"`
	NoStore           bool      `json:"NoStore"`
	CreatedAt         time.Time `json:"-"`

	// 便捷字段（与 /listener/list 响应键对应）
	Host    string
	Port    int
	Proxy   string
	Salt    string
	Type    int
	IsVIP   bool
	Expires int64

	isRunning bool
	stopCh    chan struct{}
}

// IsRunning 监听器是否运行中。
func (l *Listener) IsRunning() bool { return l.Status }

// SetRunning 设置运行状态。
func (l *Listener) SetRunning(running bool) { l.Status = running }

// Tunnel 隧道记录（/tunnel/list 响应键：Id / Target / Mode / Remark / Port）。
type Tunnel struct {
	ID         int64
	ClientID   int64
	Port       int
	Mode       string
	Target     string
	TargetAddr string
	Remark     string
	Health     *Health
	RunStatus  bool
}

// Host 主机记录（引擎主机表，store+0x20）。
// Host 主机记录（引擎主机表，store+0x20）。字段对应 hosts 表列（SQL schema）：
// Id, Host, HeaderChange, HostChange, Location, Remark, Scheme, CertFilePath,
// KeyFilePath, NoStore, IsClose, InletFlow, ExportFlow, FlowLimit, ClientId,
// TargetStr, HealthCheck*。
type Host struct {
	ID        int64
	ClientID  int64
	Host      string
	Target    string
	TargetStr string
	Scheme    string
	Remark    string
	NoStore   bool
	Flow      *Flow
	Health    *Health
}

// Target 目标列表（GetRandomTarget @ 0x119d1a0）。
type Target struct {
	targets []string
	mu      sync.Mutex
}

func NewTarget(targets ...string) *Target {
	return &Target{targets: targets}
}

func (t *Target) GetRandomTarget() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.targets) == 0 {
		return ""
	}
	return t.targets[0]
}

func (t *Target) AddTarget(target string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.targets = append(t.targets, target)
}

// Task 任务记录（NewTask 0x11979c0 / UpdateTask 0x1197d00 / DelTask 0x1197da0 /
// GetTaskByMd5Password 0x1197e20 / GetTask 0x1197fe0）。
type Task struct {
	ID       int64     `json:"Id"`
	ClientID int64     `json:"ClientId"`
	Command  string    `json:"command"`
	Result   string    `json:"result"`
	Status   string    `json:"Status"` // pending/dispatched/running/completed/failed/timeout
	MD5Pass  string    `json:"md5_Password,omitempty"`
	SentAt   time.Time `json:"sent_at"`
	DoneAt   *time.Time `json:"done_at,omitempty"`
	Timeout  int       `json:"timeout"`
}

// TargetSetting 任务目标配置。
type TargetSetting struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (ts *TargetSetting) ToJSON() string { return "" }

// ---- 常量 / Config（保留既有 API，供引擎其余文件使用）----

const (
	PlatformWindows = "windows"
	PlatformLinux   = "linux"
	PlatformMacOS   = "darwin"
)

const (
	ArchAMD64 = "amd64"
	ArchI386  = "386"
	ArchARM64 = "arm64"
)

const (
	ModeHTTP          = "http"
	ModeHTTPS         = "https"
	ModeDNS           = "dns"
	ModeWebSocket     = "websocket"
	ModeCDNWebSocket  = "cdn_websocket"
	ModeReverse       = "reverse"
	ModeKCP           = "kcp"
)

const (
	ListenerModeHTTP          = "http"
	ListenerModeHTTPS         = "https"
	ListenerModeDNS           = "dns"
	ListenerModeWebSocket     = "websocket"
	ListenerModeCDNWebSocket  = "cdn_websocket"
	ListenerModeReverse       = "reverse"
)

const (
	AgentTypeStage     = "stage"
	AgentTypeStageless = "stageless"
	AgentTypeShellcode = "shellcode"
	AgentTypeDLL       = "dll"
	AgentTypeListen    = "listen"
	AgentTypeListenDLL = "listen_dll"
)

// Config 引擎配置。
type Config struct {
	DBPath       string `json:"db_path"`
	WebPort      int    `json:"web_Port"`
	WebIP        string `json:"web_ip"`
	WebUsername  string `json:"web_Username"`
	WebPassword  string `json:"web_Password"`
	WebJWTSecret string `json:"web_jwt_secret"`
	WebTitle     string `json:"web_title"`
	License      string `json:"license"`
}

// DefaultConfig 返回默认引擎配置。
func DefaultConfig() *Config {
	return &Config{
		WebPort:     8082,
		WebIP:       "0.0.0.0",
		WebUsername: "admin",
		WebTitle:    "管理平台",
	}
}

// NewClient 构造客户端记录。
func NewClient(id int64, verifyKey, clientType, addr string) *Client {
	return &Client{
		ID:        id,
		VerifyKey: verifyKey,
		Type:      clientType,
		Addr:      addr,
		Flow:      &Flow{}, // 客户端流量统计（原版 Client 记录含流计数器）
	}
}

// NewTunnel 构造隧道记录。
func NewTunnel(id, clientID int64, port int, mode, targetAddr string) *Tunnel {
	return &Tunnel{ID: id, ClientID: clientID, Port: port, Mode: mode, Target: targetAddr}
}

// NewHost 构造主机记录。
func NewHost(id, clientID int64, host, targetStr, scheme string) *Host {
	return &Host{ID: id, ClientID: clientID, Host: host, Target: targetStr, Scheme: scheme}
}

// FromJSON 解析目标配置。
func (ts *TargetSetting) FromJSON(data string) error {
	return json.Unmarshal([]byte(data), ts)
}

// Logf 以 C2 前缀记录日志。
func Logf(format string, args ...interface{}) {
	log.Printf("[C2Engine] "+format, args...)
}
