package c2engine

// ============================================================================
// 原版字符串解密链：家族 B（garble 的 po 类型 / 每包 decFunc）
// Original string-decryption chain, family B (garble's po type / decFunc)
// ============================================================================
//
// 反编译证据（v_windows_amd64.exe）：
//
//	FUN_019146e0（0x19146e0，家族 B 的写字节闭包，逐条指令已核对）：
//
//	    R8  = closure[0x10]   ; 指向捕获的种子（*uint8）
//	    RDX = closure[0x8]    ; 指向捕获的缓冲区描述符
//	    R9  = closure[0x18]   ; 指向捕获的输出切片
//	    cVar1 = *R8                  ; 当前种子值
//	    ... 若容量不足则 FUN_004476e0 扩容 ...
//	    buf[len-1] = param_1 - cVar1 ; 写入：值 - 当前种子
//	    *R8 = *R8 + param_1          ; 种子自增：seed += 值
//
//	也就是说：闭包每被调用一次，就把调用参数减去"当前种子"写出一字节，
//	并把种子按该参数推进。于是第 i 次调用写出的字节为
//
//	    seed_{i+1} = seed_i + v_i          （v_i 为闭包参数，即反编译的
//	    out_i      = v_i - seed_i          常数块字节）
//
//	构造器（FUN_01914a40 / FUN_01914b40 / FUN_01914c40 / FUN_01913320 /
//	FUN_01913640）以“计数器写法”调用该闭包：控制流是一个 while+switch
//	状态机，
//
//	    bVar2 = 步号 * 步序 ^ bVar2          （FUN_01913320/01913640 的种子递推）
//	    ...
//	    local_2f[uVar4] = local_2f[uVar5] ^ bVar2  /  -= / +=   （参数置换）
//
//	收尾 FUN_0044ac40(0, buf, n) 产出 n 字节 Go 字符串。
//
// 已验证的部分：
//   - 写字节语义 out_i = v_i - seed_i, seed_{i+1} = seed_i + v_i（逐指令核对）；
//   - 家族 A 的置换链（见 po_decode.go，两条向量已逐字节还原）。
//
// 未解决（不猜测 / NOT recovered, deliberately not guessed）：
//   家族 B 中"步号/步序/k"如何在无外层循环计数器的构造器里推进，
//   以及 while+switch 状态机的步进调度（Ghidra 无法直接反编译该 switch），
//   尚未完全确定；因此本文件不产出任何家族 B 的具体字符串，
//   控制器对这类字符串（如 shellcode 分支的魔数）不做伪造还原。
//
// Family B's per-write semantics are confirmed instruction-by-instruction
// (out_i = v_i - seed_i, seed advances by v_i); the step/key scheduling of the
// constructor state machines is still unrecovered, so no family-B string is
// synthesised here.
//
// ============================================================================
// 家族 B 的实际变体（第二轮取证已确定）：整池相减叠加
// The family-B variant actually used by the binary: whole-pool subtract overlay
// ============================================================================
//
// 反编译证据（v_windows_amd64.exe）：
//
//	加载器 FUN_0116d020（0x116d020，RVA 0x116d020，与 Ghidra VA 相同）：
//	    源阵列：MOV RSI,[0x1d3adcb] ; MOV ECX,0x135e ; REP MOVSQ   → 拷到 [RSP+0x9b28]
//	    目标阵列：同法拷 [0x1d448ca] (0x135e*8 字节)            → 拷到 [RSP+0x29]
//	    回写：MOV RAX,[0x1e431460] ; MOV [0x1e490a08],RAX      ; 池基址全局
//	         MOV [0x1e490867],[RAX+3]    ; 池头第 2 个 dword（错位 3 字节）
//
//	解码器 FUN_010952e0 @0x109b473（唯一在派发器内读池基址的指令）：
//	    0x109b473  MOV RAX,[0x1e490a08]       ; 池基址
//	    0x109b47a  ADD RAX,0x4aa1             ; 字符串偏移
//	    0x109b480  CALL FUN_0040abc0          ; 转成 runtime 字符串头
//
//	消费闭包 FUN_0116d0c2（派发器内的逐字节还原）：
//	    0x116d0c2  MOVZX EDX,[RSP+RAX+0x9b19] ; 源阵列（15 字节前缀 + 0x1d3adcb）
//	    0x116d0ca  MOVZX ESI,[RSP+RAX+0x1a]   ; 目标阵列（15 字节前缀 + 0x1d448ca）
//	    0x116d0cf  SUB ESI,EDX                ; 逐字节相减
//	    0x116d0d1  MOV [RSP+RAX+0x1a],SIL     ; 就地写回目标阵列
//	    0x116d0e0  CMP RAX,0x9aff            ; 池长度 0x9aff = 39679
//	    0x116d0f4  CALL FUN_0044ac40(0,&[RSP+0x1a],0x9aff)   ; 产出 39679 字节 Go 字符串
//
//	即：明文池 = 目标阵列 - 源阵列（逐字节 mod 256），两个阵列的前缀由两个
//	imm64 组成，**第二个 imm64 写在第一个的第 8 字节上**（0x9b19+8 与 0x9b21-1
//	重合），因此有效前缀是 15 字节而不是 16 —— 这一点由 67 个加载器偏移同时
//	判定：15 字节前缀让 66/67 个偏移都落在串首（16 字节前缀一个都不落）。
//
//	Geometry that follows from the loader (all measured, not assumed):
//	  .rdata 阵列为 0x135e 个 qword（含 MOVSQ 的 rep 计数），池长 0x9aff；
//	  两份前缀均为 15 字节（第二 imm64 覆盖第一 imm64 的末字节）；
//	  加载器 0x117b954 的 67 条 MOV RAX,[池]; ADD RAX,imm 中偏移即串首：
//	  0x4531 处正是 "analysis_limit"，且与表记录 0 的 V=0x00453101 吻合；
//	  派发器的 0x49f3 处是 "-%T"、0x49f7 处是 "fast"、0x4a4a 处是 "reset" ——
//	  都是**串首**（不是被 NUL 前导的串），也就是说派发器读的就是这份池。
//
// 已验证：用上述引擎逐字节解出派发器池 0x9aff 字节，池头即 "3.41.2"，并命中
// Go runtime / SQLite / regexp 等本仓库依赖确实链接进来的字符串；相减方向、
// 前缀长度、池头位置与池长四者同时自洽。
//
// 未解出（不猜测，NOT recovered）：0x1e302680 表**不是** per-opcode 命令表。
//	它是 SQLite 的 sqlite3Pragma 列表（67 条），由 FUN_01094d80（二分查找）
//	与 0x1094e60 使用；记录 0 的目标 0x1e494578 由 0x117b961 写入
//	[0x1e490a08]+0x451e。所以它的字符串当然全在 SQLite 池里。
//	派发器 0x109578e 的 24 字节记录指针来自 FUN_01094d80 的返回值 ——
//	**不是** 0x1e302680 那个表。per-opcode 名称真正所在的表尚未定位：
//	已排除 (a) 0x1e302680（SQLite）、(b) 文件镜像中任何带重定位的表
//	（[0x1e302680,0x1e302cc8) 零重定位）、(c) 我解码的全部 881 个可解池
//	（其中无 ifconfig/whoami/screenshot/socks5/tasklist/netstat）。
//
// The 0x1e302680 table is SQLite's sqlite3Pragma list, not a VShell opcode
// table; the dispatcher's 24-byte record comes from FUN_01094d80, not from it.
// Where the per-opcode name table lives remains unresolved and is recorded as
// such — no structural inference is presented as a finding.

// PoPoolSrc48 / PoPoolDst48 是派发器池前 48 字节的两份输入阵列，直接取自
// FUN_0116d020 载入的 .rdata 常数：每个阵列的有效前缀是 15 字节（两个 imm64
// 在 +8 处重叠，第二个覆盖第一个的末字节），之后接 .rdata 常数块。
// PoPoolWant48 是相减结果（池头），作为回归向量钉死运算方向与前缀长度。
var (
	// 源阵列 [RSP+0x9b19]：15 字节前缀 + .rdata 0x1d3adcb
	PoPoolSrc48 = []byte{
		0x45, 0x54, 0xa7, 0x62, 0xb8, 0xd9, 0xc5, 0x8c, 0xaa, 0xa4, 0x83, 0x8e,
		0xcb, 0x70, 0x20, 0x17, 0x9d, 0x18, 0xa3, 0xc6, 0x83, 0xaa, 0x73, 0x01,
		0x02, 0xa7, 0x74, 0x23, 0x30, 0xcc, 0xa9, 0xfb, 0x19, 0x4a, 0x77, 0x01,
		0xb5, 0x6d, 0x3d, 0xf1, 0xf2, 0x27, 0x8b, 0xef, 0x55, 0xe5, 0xbd, 0x92,
	}
	// 目标阵列 [RSP+0x1a]：15 字节前缀 + .rdata 0x1d448ca
	PoPoolDst48 = []byte{
		0x78, 0x82, 0xdb, 0x93, 0xe6, 0x0b, 0xc5, 0xcd, 0xfe, 0xf3, 0xd0, 0xd7,
		0x0e, 0xcf, 0x69, 0x65, 0xf1, 0x6a, 0xec, 0x14, 0xd6, 0xf3, 0xb6, 0x54,
		0x3f, 0xd8, 0x74, 0x66, 0x7f, 0x19, 0xf9, 0x44, 0x65, 0x8f, 0xc9, 0x3e,
		0x22, 0xe0, 0xb3, 0x54, 0x1f, 0x58, 0xc4, 0x1f, 0x85, 0xe5, 0x01, 0xd7,
	}
	// 池头明文（0x116d0cf 的 SUB ESI,EDX 结果；Go 链接器 buildinfo 块）
	PoPoolWant48 = []byte("3.41.2\x00ATOMIC_INTRINSICS=1\x00COMPILER=msvc-1900\x00DE")
)

// PoPoolSubtract 是 0x116d0cf 的逐字节还原：out_i = dst_i - src_i（mod 256）。
//
// PoPoolSubtract is the byte-wise recovery at 0x116d0cf: out_i = dst_i - src_i.
func PoPoolSubtract(dst, src []byte) []byte {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = dst[i] - src[i]
	}
	return out
}

// PoPoolLen 是加载器写入的池长度（0x116d0e0 的 CMP RAX,0x9aff）。
const PoPoolLen = 0x9aff

// PoPoolBaseGlobal 是保存池基址的全局（0x1178c51 写入，0x109b473 读出）。
const PoPoolBaseGlobal = 0x1e490a08

// PoPoolLoadFunc 是加载器函数的入口（拷贝两份阵列并写池基址全局）。
const PoPoolLoadFunc = 0x116d020

// PoPoolSubtractSite 是派发器内做逐字节相减的站点（SUB ESI,EDX）。
const PoPoolSubtractSite = 0x116d0c2

// PoEmit 按家族 B 的写字节语义把常数块 vals 展开为闭包输出：
// out_i = v_i - seed_i，seed_{i+1} = seed_i + v_i。
//
// PoEmit applies family B's write semantics to a constant block: each byte is
// `v - seed`, and the running seed advances by `v`.
func PoEmit(seed byte, vals ...byte) []byte {
	out := make([]byte, 0, len(vals))
	s := seed
	for _, v := range vals {
		out = append(out, v-s)
		s += v
	}
	return out
}
// PoEmitVector pins family B's write semantics against the decompilation.
type PoEmitVector struct {
	Name string
	Seed byte
	Vals []byte
	Want []byte
}

// PoEmitVectors 取自 FUN_019146e0 的语义（out = v - seed，seed += v）。
// 这些向量不依赖任何未解出的调度，可直接对拍实现。
var PoEmitVectors = []PoEmitVector{
	{
		Name: "first byte is v minus the initial seed",
		Seed: 0x01,
		Vals: []byte{0x01, 0x02, 0x03},
		// 1-1=0；seed=2 → 2-2=0；seed=4 → 3-4=0xff
		Want: []byte{0x00, 0x00, 0xff},
	},
	{
		Name: "seed advances by each value",
		Seed: 0x10,
		Vals: []byte{0x20, 0x05, 0xff},
		// 0x20-0x10=0x10；seed=0x30 → 0x05-0x30=0xd5；seed=0x35 → 0xff-0x35=0xca
		Want: []byte{0x10, 0xd5, 0xca},
	},
}

// PoPoolVectors 是整池相减解码的回归向量：两份前 48 字节阵列必须解出池头
// （Go buildinfo 魔数前缀 "3.41.2" 之后的 NUL 分隔串）。
//
// PoPoolVectors pins the whole-pool subtract decode against the loader's arrays.
var PoPoolVectors = []struct {
	Name     string
	Dst, Src []byte
	Want     []byte
}{
	{
		Name: "dispatcher pool head",
		Dst:  PoPoolDst48,
		Src:  PoPoolSrc48,
		Want: []byte("3.41.2\x00ATOMIC_INTRINSICS=1\x00COMPILER=msvc-1900\x00DE"),
	},
}
