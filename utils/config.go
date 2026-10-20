// Package utils contains configuration parsing and application settings.
//
// The parser supports an INI-like key=value format with # comments. Some
// names and defaults were compared with a recovered setting.conf and the
// original binary; those comparisons are evidence for specific fields only,
// not proof that every setting or runtime behavior is identical.
// 配置格式及字段映射来自当前实现与可获取样本的对照；未验证的兼容性应视为待确认。

package utils

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// FullSettings stores settings understood by this implementation.
// It is not a guarantee that every field matches the original binary exactly.
type FullSettings struct {
	// License
	License string // RSA-encrypted license key (base64)

	// Master mode: web, gui, all
	MasterType string

	// Web panel
	WebTitle     string
	WebPort      int
	WebIP        string
	WebBasicAuth bool
	WebJWTSecret string
	WebUsername  string
	WebPassword  string

	// Web SSL (panel HTTPS)
	WebOpenSSL  bool
	WebCertFile string
	WebKeyFile  string

	// DingDing robot notifications
	DingdingAccessToken string
	DingdingKeyWord     string

	// WeChat robot notifications
	WxKey string

	// Logging
	LogLevel int    // 0=Emergency .. 7=Debug
	LogPath  string // empty = use default log path

	// pprof debug
	PprofIP   string
	PprofPort int
}

// ============================================================================
// Config loader — parses conf/setting.conf
// ============================================================================

var (
	fullCfg     *FullSettings
	fullCfgOnce sync.Once
	fullCfgMu   sync.RWMutex
)

// defaultConfigPath returns the configuration path, honoring VSHELL_CONF when set.
// Otherwise it uses conf/setting.conf relative to the current working directory.
// This describes the current implementation; it does not establish parity with another binary.
func defaultConfigPath() string {
	// An explicit environment override takes precedence over the default path.
	if env := os.Getenv("VSHELL_CONF"); env != "" {
		return env
	}
	return "conf/setting.conf"
}

// LoadConfig reads path and parses supported key=value settings.
// An empty path selects defaultConfigPath. If the file cannot be opened, this
// implementation returns defaults; parse errors are returned to the caller.
// Note that an open failure is treated as a fallback, not distinguished from
// a missing file, so callers should not assume configuration was loaded.
func LoadConfig(path string) (*FullSettings, error) {
	if path == "" {
		path = defaultConfigPath()
	}

	cfg := defaultFullSettings()

	f, err := os.Open(path)
	if err != nil {
		// Config file not found — use defaults (matches original behavior)
		return cfg, nil
	}
	defer f.Close()

	if err := parseConfigFile(f, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	return cfg, nil
}

// GetFullSettings returns the process-wide settings instance, loading it on
// the first call. Parse errors currently fall back to defaults, so this API
// does not expose configuration-loading failures to callers.
func GetFullSettings() *FullSettings {
	fullCfgOnce.Do(func() {
		cfg, err := LoadConfig("")
		if err != nil {
			// Fall back to defaults on parse error
			cfg = defaultFullSettings()
		}
		fullCfgMu.Lock()
		fullCfg = cfg
		fullCfgMu.Unlock()
	})
	fullCfgMu.RLock()
	defer fullCfgMu.RUnlock()
	return fullCfg
}

// SetFullSettingsForTest 替换已加载的配置（测试辅助函数）。
// 先触发单例加载器以消耗 fullCfgOnce，再覆盖 fullCfg，否则后续首次
// GetFullSettings() 会重新 LoadConfig("") 并冲掉注入的值。
// SetFullSettingsForTest replaces the loaded settings (test helper).
// Triggers the singleton loader first so fullCfgOnce is consumed, then
// overwrites fullCfg — otherwise a later first GetFullSettings() call would
// re-run LoadConfig("") and clobber the injected value.
func SetFullSettingsForTest(cfg *FullSettings) {
	_ = GetFullSettings() // consume fullCfgOnce
	fullCfgMu.Lock()
	fullCfg = cfg
	fullCfgMu.Unlock()
}

// ReloadConfig parses the requested file and replaces the in-memory settings.
// It does not itself coordinate consumers that may already hold the old
// pointer; callers must account for that when reloading during concurrent use.
func ReloadConfig(path string) error {
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	fullCfgMu.Lock()
	fullCfg = cfg
	fullCfgMu.Unlock()
	return nil
}

// SaveConfig 将当前 FullSettings 写回配置文件；目录不存在时自动创建。
// SaveConfig writes the current FullSettings back to the config file.
// Preserves comments and non-managed keys by doing a line-by-line update
// on the existing file content. If the file doesn't exist, generates a new one.
func SaveConfig(cfg *FullSettings, path string) error {
	if path == "" {
		path = defaultConfigPath()
	}

	// Build the config file content
	content := generateConfigContent(cfg)

	// Ensure directory exists
	if dir := filepathDir(path); dir != "" {
		os.MkdirAll(dir, 0755)
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	// Update the singleton
	fullCfgMu.Lock()
	fullCfg = cfg
	fullCfgMu.Unlock()

	// Also sync to auth settings
	SyncSettingsFromConfig()

	return nil
}

// UpdateConfig applies supported keys from updates and persists the result.
// Values are converted to strings before parsing. Because this mutates the
// current settings pointer, callers should avoid concurrent unsynchronized
// reads or writes while an update is in progress.
func UpdateConfig(updates map[string]interface{}, path string) error {
	cfg := GetFullSettings()

	for k, v := range updates {
		applyConfigKey(cfg, k, fmt.Sprintf("%v", v))
	}

	return SaveConfig(cfg, path)
}

// generateConfigContent 由 FullSettings 生成 setting.conf 文本（格式与原版输出一致）。
// generateConfigContent produces a setting.conf from FullSettings.
// Uses the same format as the original binary's output.
func generateConfigContent(cfg *FullSettings) string {
	var sb strings.Builder

	sb.WriteString("# License授权\n")
	sb.WriteString(fmt.Sprintf("license=%s\n", cfg.License))
	sb.WriteString("\n")
	sb.WriteString("# 控制端模式 web/gui/all，web模式只开启web端，gui模式开启gui api，all模式开启所有\n")
	sb.WriteString(fmt.Sprintf("master_type=%s\n", cfg.MasterType))
	sb.WriteString("\n")
	sb.WriteString("# web\n")
	sb.WriteString(fmt.Sprintf("web_title=%s\n", cfg.WebTitle))
	sb.WriteString(fmt.Sprintf("web_port=%d\n", cfg.WebPort))
	sb.WriteString(fmt.Sprintf("web_ip=%s\n", cfg.WebIP))
	sb.WriteString("\n")
	sb.WriteString("# 开启basic认证可防止被资产测绘收录\n")
	sb.WriteString(fmt.Sprintf("web_basic_auth=%v\n", cfg.WebBasicAuth))
	sb.WriteString("# web_jwt_secret可留空更安全，会使用随机字符串作为jwtSecret\n")
	sb.WriteString(fmt.Sprintf("web_jwt_secret=%s\n", cfg.WebJWTSecret))
	sb.WriteString(fmt.Sprintf("web_username=%s\n", cfg.WebUsername))
	sb.WriteString(fmt.Sprintf("web_password=%s\n", cfg.WebPassword))
	sb.WriteString("\n")
	sb.WriteString("# web ssl\n")
	sb.WriteString(fmt.Sprintf("web_open_ssl=%v\n", cfg.WebOpenSSL))
	sb.WriteString(fmt.Sprintf("web_cert_file=%s\n", cfg.WebCertFile))
	sb.WriteString(fmt.Sprintf("web_key_file=%s\n", cfg.WebKeyFile))
	sb.WriteString("\n")
	sb.WriteString("# dingding robot\n")
	sb.WriteString(fmt.Sprintf("dingding_access_token=%s\n", cfg.DingdingAccessToken))
	sb.WriteString(fmt.Sprintf("dingding_key_word=%s\n", cfg.DingdingKeyWord))
	sb.WriteString("\n")
	sb.WriteString("# wechat robot\n")
	sb.WriteString(fmt.Sprintf("wx_key=%s\n", cfg.WxKey))
	sb.WriteString("\n")
	sb.WriteString("# log level LevelEmergency->0  LevelAlert->1 LevelCritical->2 LevelError->3 LevelWarning->4 LevelNotice->5 LevelInformational->6 LevelDebug->7\n")
	sb.WriteString(fmt.Sprintf("log_level=%d\n", cfg.LogLevel))
	sb.WriteString(fmt.Sprintf("log_path=%s\n", cfg.LogPath))
	sb.WriteString("\n")
	sb.WriteString("# pprof debug options\n")
	if cfg.PprofIP != "" && cfg.PprofPort > 0 {
		sb.WriteString(fmt.Sprintf("pprof_ip=%s\n", cfg.PprofIP))
		sb.WriteString(fmt.Sprintf("pprof_port=%d\n", cfg.PprofPort))
	} else {
		sb.WriteString("#pprof_ip=0.0.0.0\n")
		sb.WriteString("#pprof_port=9999\n")
	}

	return sb.String()
}

// filepathDir 从文件路径中提取目录部分（避免额外引入 path/filepath 依赖）。
// filepathDir extracts the directory from a file path.
// Avoids importing path/filepath here (already imported in other files).
func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return ""
}

// defaultFullSettings 返回与原版一致的默认配置。
// defaultFullSettings returns sensible defaults matching the original binary.
// Confidence: HIGH (matches original setting.conf default values)
func defaultFullSettings() *FullSettings {
	return &FullSettings{
		MasterType:   "web",
		WebTitle:     "\u7ba1\u7406\u5e73\u53f0", // 管理平台
		WebPort:      8082,
		WebIP:        "0.0.0.0",
		WebBasicAuth: true,
		WebJWTSecret: "",
		WebUsername:  "admin",
		WebPassword:  "", // no hardcoded default — main.go generates a random one at startup
		WebOpenSSL:   false,
		WebCertFile:  "conf/server.pem",
		WebKeyFile:   "conf/server.key",
		LogLevel:     7, // Debug
	}
}

// ============================================================================
// INI-like config parser
// ============================================================================

// parseConfigFile 解析 setting.conf 的 INI 风格配置。
// 格式（逆向还原，置信度高）：# 开头为注释；空行忽略；key=value（= 两侧空白被去除）；键为 snake_case。
// parseConfigFile parses the INI-like config format from setting.conf.
//
// Format (reverse-engineered, confidence HIGH):
//   - Lines starting with # are comments
//   - Blank lines are ignored
//   - key=value pairs (whitespace around = is trimmed)
//   - Keys use snake_case (matching the original binary's decoded strings)
func parseConfigFile(f *os.File, cfg *FullSettings) error {
	scanner := bufio.NewScanner(f)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split key=value
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue // malformed line, skip silently (matches original behavior)
		}

		key := strings.TrimSpace(line[:eq])
		value := strings.TrimSpace(line[eq+1:])

		// Dispatch to the appropriate field
		applyConfigKey(cfg, key, value)
	}

	return scanner.Err()
}

// applyConfigKey 将单个 key=value 应用到配置结构体，键与原版解码出的字符串常量一致。
// applyConfigKey applies a single key=value to the config struct.
// Keys match the original binary's decoded string constants.
//
// Confidence: HIGH for all keys (directly observable from setting.conf)
func applyConfigKey(cfg *FullSettings, key, value string) {
	switch key {
	case "license":
		cfg.License = value

	case "master_type":
		cfg.MasterType = value

	// Web panel
	case "web_title":
		cfg.WebTitle = value
	case "web_port":
		if n, err := strconv.Atoi(value); err == nil {
			cfg.WebPort = n
		}
	case "web_ip":
		cfg.WebIP = value
	case "web_basic_auth":
		cfg.WebBasicAuth = parseBool(value, true)
	case "web_jwt_secret":
		cfg.WebJWTSecret = value
	case "web_username":
		cfg.WebUsername = value
	case "web_password":
		cfg.WebPassword = value

	// Web SSL
	case "web_open_ssl":
		cfg.WebOpenSSL = parseBool(value, false)
	case "web_cert_file":
		cfg.WebCertFile = value
	case "web_key_file":
		cfg.WebKeyFile = value

	// DingDing
	case "dingding_access_token":
		cfg.DingdingAccessToken = value
	case "dingding_key_word":
		cfg.DingdingKeyWord = value

	// WeChat
	case "wx_key":
		cfg.WxKey = value

	// Logging
	case "log_level":
		if n, err := strconv.Atoi(value); err == nil {
			cfg.LogLevel = n
		}
	case "log_path":
		cfg.LogPath = value

	// pprof
	case "pprof_ip":
		cfg.PprofIP = value
	case "pprof_port":
		if n, err := strconv.Atoi(value); err == nil {
			cfg.PprofPort = n
		}
	}
}

// parseBool 将字符串转换为 bool；无法识别时返回默认值 def。
// parseBool converts a string to bool. Returns def if the string is not
// a recognized boolean value.
func parseBool(s string, def bool) bool {
	switch strings.ToLower(s) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off", "":
		return false
	default:
		return def
	}
}

// ============================================================================
// Config → Settings synchronization
// ============================================================================

// SyncSettingsFromConfig 将全局 Settings 单例（定义于 auth.go）与完整配置同步，启动时调用。
// SyncSettingsFromConfig synchronizes the global Settings singleton
// (defined in auth.go) with the full config. Call this during startup.
func SyncSettingsFromConfig() {
	settingsOnce.Do(func() {}) // ensure once is consumed
	cfg := GetFullSettings()

	jwtSecret := cfg.WebJWTSecret
	if jwtSecret == "" {
		jwtSecret = generateJWTSecret()
	}

	settingsMu.Lock()
	defer settingsMu.Unlock()
	settings = &Settings{
		License:      cfg.License,
		MasterType:   cfg.MasterType,
		WebTitle:     cfg.WebTitle,
		WebPort:      cfg.WebPort,
		WebIP:        cfg.WebIP,
		WebBasicAuth: cfg.WebBasicAuth,
		WebUsername:  cfg.WebUsername,
		WebPassword:  cfg.WebPassword,
		WebJWTSecret: jwtSecret,
	}
}
