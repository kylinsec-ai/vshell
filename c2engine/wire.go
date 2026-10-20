package c2engine

// Agent 线协议字段帧编码（对照逆向证据重建（尚需测试验证等价性） FUN_0100d160 反编译）。
//
// 线格式 = 24 字节类型化字段记录序列：
//
//	+0x00 kind u8        （帧码：0x54 列表行 / 0xa6 ack / 0xb1 pong / 0xb2 ping / …）
//	+0x01 flags u8
//	+0x02 u16
//	+0x04 u32
//	+0x08 u32
//	+0x0c u32
//	+0x10 u64
//
// 缓冲：+0x88 数据指针 / +0x90 计数 / +0x94 容量（FUN_0100d160 语义）。
// 当前 kcp.go 的 JSON 消息为近似实现，需逐步迁移到本字段帧编码。

// AgentField 一条 24 字节线字段。
type AgentField struct {
	Kind  uint8  // +0x00
	Flags uint8  // +0x01
	W     uint16 // +0x02
	A     uint32 // +0x04
	B     uint32 // +0x08
	C     uint32 // +0x0c
	D     uint64 // +0x10
}

// 常用帧码（30-case 任务分派反编译，见 .re/AGENT_TASKS.md）。
const (
	FrameListRow  = 0x54 // 列表行
	FrameAck      = 0xa6 // 确认
	FramePong     = 0xb1 // pong
	FramePing     = 0xb2 // ping
	FrameDump     = 0x9b // 进程/任务转储
	FrameSessRow  = 0x12 // 会话行
	FrameDetail   = 0x75 // 详情
	FrameBig      = 0x94 // 大数据帧
	FrameSub      = 0x1d // 子级
	FrameElem     = 0x5e // 元素
	FrameVar      = 0x29 // 变量
	FrameSet      = 0x47 // 设置
	FrameGet      = 0x56 // 获取
	FrameMode     = 0x3b // 模式
	FrameScalar   = 0x48 // 标量结果
)

// AgentFrame 字段帧缓冲（对齐 FUN_0100d160 的 +0x88/+0x90/+0x94 结构）。
type AgentFrame struct {
	data  []AgentField // +0x88 数据
	count int          // +0x90 计数
	cap   int          // +0x94 容量
}

// NewAgentFrame 创建字段帧缓冲。
func NewAgentFrame(capacity int) *AgentFrame {
	return &AgentFrame{data: make([]AgentField, 0, capacity), cap: capacity}
}

// Append 追加一条字段（对齐 FUN_0100d160：写入后计数+1，返回写入前的索引）。
func (f *AgentFrame) Append(kind uint8, a, b, c uint32, d uint64) int {
	if f.count >= f.cap {
		// 扩容（原版 FUN_0100d0a0）
		newCap := f.cap * 2
		if newCap == 0 {
			newCap = 8
		}
		nd := make([]AgentField, len(f.data), newCap)
		copy(nd, f.data)
		f.data = nd
		f.cap = newCap
	}
	idx := f.count
	f.data = append(f.data, AgentField{Kind: kind, A: a, B: b, C: c, D: d})
	f.count++
	return idx
}

// Len 返回当前字段数。
func (f *AgentFrame) Len() int { return f.count }

// Bytes 序列化为 24 字节记录序列（对齐线格式布局）。
func (f *AgentFrame) Bytes() []byte {
	out := make([]byte, 0, f.count*24)
	for i := range f.count {
		fd := f.data[i]
		out = append(out, fd.Kind, fd.Flags, byte(fd.W), byte(fd.W>>8),
			byte(fd.A), byte(fd.A>>8), byte(fd.A>>16), byte(fd.A>>24),
			byte(fd.B), byte(fd.B>>8), byte(fd.B>>16), byte(fd.B>>24),
			byte(fd.C), byte(fd.C>>8), byte(fd.C>>16), byte(fd.C>>24),
			byte(fd.D), byte(fd.D>>8), byte(fd.D>>16), byte(fd.D>>24),
			byte(fd.D>>32), byte(fd.D>>40), byte(fd.D>>48), byte(fd.D>>56))
	}
	return out
}

// ParseAgentFrame 解析 24 字节记录序列。
func ParseAgentFrame(data []byte) []AgentField {
	var fields []AgentField
	for i := 0; i+24 <= len(data); i += 24 {
		fields = append(fields, AgentField{
			Kind:  data[i],
			Flags: data[i+1],
			W:     uint16(data[i+2]) | uint16(data[i+3])<<8,
			A:     uint32(data[i+4]) | uint32(data[i+5])<<8 | uint32(data[i+6])<<16 | uint32(data[i+7])<<24,
			B:     uint32(data[i+8]) | uint32(data[i+9])<<8 | uint32(data[i+10])<<16 | uint32(data[i+11])<<24,
			C:     uint32(data[i+12]) | uint32(data[i+13])<<8 | uint32(data[i+14])<<16 | uint32(data[i+15])<<24,
			D:     uint64(data[i+16]) | uint64(data[i+17])<<8 | uint64(data[i+18])<<16 | uint64(data[i+19])<<24 | uint64(data[i+20])<<32 | uint64(data[i+21])<<40 | uint64(data[i+22])<<48 | uint64(data[i+23])<<56,
		})
	}
	return fields
}
