package c2engine

// Channel 帧线协议（对照逆向证据重建（尚需测试验证等价性）服务端 tunnel/channel 反编译）。
//
// 线格式（FUN_011b6ba0 构建 / FUN_011b7020 解析，会话 230-237 解码）：
//
//	+0x00 type u8     帧类型（见 ChannelType 常量）
//	+0x01 id   u32   小端会话/通道 id
//	+0x05 data []byte 载荷（type 5 = 8 字节数据字段）
//
// 帧最大长度 0xff5（4085），缓冲结构 +0x10 数据指针 / +0x18 容量 0xff5 /
// +0x20 长度（与 FUN_011b7020 的校验一致：数据帧最小 0xd = 头 5 + 8）。
//
// 构建规则（FUN_011b6ba0）：类型 0/3/4/8 走载荷复制路径，类型 5 提取
// 8 字节数据字段，类型 1/2/6/7 直接返回（服务端不发送这些类型）。
//
// 读分发（FUN_011b5600）按类型处理：
//
//	0x00 结束帧（收尾载荷）    0x06 ACK（FUN_011b0a60 + 队列）
//	0x08 通道数据（+0x60 缓冲） 0x01/0x02 会话数据（两个缓冲）
//	0x03/0x04 会话命令          0x05 会话（8 字节数据）
//	0x07 关闭                   其他 错误（FUN_011b7380）

import "encoding/binary"

// ChannelMaxFrame 单帧最大长度（0xff5，FUN_011b6ba0/011b7020 的容量常量）。
const ChannelMaxFrame = 0xff5

// ChannelMinDataFrame 数据帧最小长度（头 5 字节 + 8 字节数据字段）。
const ChannelMinDataFrame = 0xd

// ChannelHeaderLen 帧头长度（type u8 + id u32）。
const ChannelHeaderLen = 5

// ChannelType 通道帧类型（读分发 FUN_011b5600 逐类型解码）。
type ChannelType uint8

const (
	ChannelEnd      ChannelType = 0x00 // 结束帧
	ChannelSessData ChannelType = 0x01 // 会话数据缓冲一
	ChannelSessData2 ChannelType = 0x02 // 会话数据缓冲二
	ChannelSessCmd  ChannelType = 0x03 // 会话命令一
	ChannelSessCmd2 ChannelType = 0x04 // 会话命令二
	ChannelSess     ChannelType = 0x05 // 会话（8 字节数据字段）
	ChannelAck      ChannelType = 0x06 // ACK
	ChannelClose    ChannelType = 0x07 // 关闭
	ChannelData     ChannelType = 0x08 // 通道数据
)

// ChannelFrame 一条通道帧（对齐 FUN_011b7020 解析产物）。
type ChannelFrame struct {
	Type ChannelType
	ID   uint32
	Data []byte
}

// BuildChannelFrame 构建通道帧线字节（对齐 FUN_011b6ba0）：
// 头 [0] type + [1..5] id 小端 + [5..] 载荷；容量 0xff5。
// 类型 1/2/6/7 不构建（服务端只发送 0/3/4/5/8，对齐原版直接返回路径）。
func BuildChannelFrame(t ChannelType, id uint32, data []byte) []byte {
	switch t {
	case ChannelEnd, ChannelSessCmd, ChannelSessCmd2, ChannelData, ChannelSess:
		// 可发送类型
	default:
		return nil
	}
	total := ChannelHeaderLen + len(data)
	if total > ChannelMaxFrame {
		total = ChannelMaxFrame
		data = data[:ChannelMaxFrame-ChannelHeaderLen]
	}
	out := make([]byte, total)
	out[0] = byte(t)
	binary.LittleEndian.PutUint32(out[1:5], id)
	copy(out[5:], data)
	return out
}

// ParseChannelFrame 解析通道帧（对齐 FUN_011b7020）：
// 校验长度 >= 5，提取 type/id，type 5 提取 [5..13] 的 8 字节数据字段，
// 返回帧与解析后的载荷长度（uint16 截断，与原版返回一致）。
func ParseChannelFrame(frame []byte) (ChannelFrame, int) {
	if len(frame) < ChannelHeaderLen {
		return ChannelFrame{}, 0
	}
	f := ChannelFrame{
		Type: ChannelType(frame[0]),
		ID:   binary.LittleEndian.Uint32(frame[1:5]),
	}
	if f.Type == ChannelSess && len(frame) >= ChannelMinDataFrame {
		f.Data = frame[5 : 5+8]
		return f, len(frame)
	}
	f.Data = frame[ChannelHeaderLen:]
	return f, len(frame)
}
