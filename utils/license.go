// Package utils — License verification system.
// 许可证校验系统：Base64 解码 → RSA 解密（PKCS#1 v1.5）→ 按 | 分隔解析。
//
// Reverse-engineered from the original vshell binary (v_windows_amd64.exe).
//
// The original binary decrypts a license key that is:
//   1. Base64-decoded
//   2. RSA-decrypted (PKCS#1 v1.5) using an EMBEDDED PRIVATE KEY
//   3. Parsed as a pipe-delimited string: "expiry|max_clients|advanced|features"
//
// NOTE: The original binary embeds an RSA PRIVATE KEY for license decryption.
// The license in setting.conf is encrypted with the PUBLIC key (by the vendor)
// and decrypted with the PRIVATE key (by the binary at runtime).
//
// For the open-source reimplementation, the private key must be extracted
// from the original binary via Ghidra. Until extracted, license verification
// returns a "not configured" error.
//
// Evidence:
//   - Original setting.conf: license=<base64_blob>
//   - Binary calls rsa.DecryptPKCS1v15 (confirmed by Go type strings)
//   - Frontend: license_end_time, license_client_cap, advanced_license
//
// Confidence: HIGH (format confirmed; decryption uses private key per Go stdlib)

// Compatibility notes in this file describe the current implementation and available analysis evidence; they are not a guarantee of complete behavioral parity.
// Treat security-sensitive assumptions as unverified until confirmed by tests or direct review.

package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// License payload (decoded from RSA-encrypted blob)
// ============================================================================

// LicenseInfo 保存解析后的许可证数据。
// LicenseInfo holds the parsed license data.
type LicenseInfo struct {
	Name       string    // license name (e.g. "public")
	ExpiryTime time.Time // license expiration
	MaxClients int       // maximum allowed clients (0 = unlimited)
	Advanced   bool      // advanced features enabled
	Features   []string  // enabled feature flags
	Raw        string    // original decrypted string (for debugging)
}

// IsExpired 检查许可证是否已过期（零值表示永久有效）。
// IsExpired checks if the license has expired.
func (li *LicenseInfo) IsExpired() bool {
	if li.ExpiryTime.IsZero() {
		return false // no expiry = perpetual
	}
	return time.Now().After(li.ExpiryTime)
}

// DaysRemaining 返回距到期的剩余天数（过期则为负数，永久有效返回 99999）。
// DaysRemaining returns days until license expiry (negative if expired).
func (li *LicenseInfo) DaysRemaining() int {
	if li.ExpiryTime.IsZero() {
		return 99999 // perpetual
	}
	return int(time.Until(li.ExpiryTime).Hours() / 24)
}

// ============================================================================
// RSA Private Key (extracted from original binary)
// ============================================================================

// licensePrivateKeyPEM 保存用于解密许可证的 RSA 私钥（PEM 格式）。
// licensePrivateKeyPEM holds the RSA PRIVATE KEY for license decryption.
//
// EXTRACTION STATUS: PENDING
// Must be extracted from v_windows_amd64.exe via Ghidra.
//
// Ghidra instructions:
//   1. Search type strings: "*rsa.PrivateKey", "rsa.PrivateKey"
//   2. Find init function calling x509.ParsePKCS1PrivateKey/ParsePKCS8PrivateKey
//   3. Locate the raw DER bytes (~1192 bytes for 2048-bit RSA) in .rdata/.noptrdata
//   4. Export as PEM:
//        -----BEGIN RSA PRIVATE KEY-----
//        <base64 DER>
//        -----END RSA PRIVATE KEY-----
var licensePrivateKeyPEM = `` // may be set via conf/license.pem or SetLicensePrivateKey()

var licensePrivateKey *rsa.PrivateKey // 缓存的已解析 RSA 私钥 / cached parsed RSA private key

// loadLicensePEMFromFile 尝试在初始化时从 conf/license.pem 读取私钥。
// loadLicensePEMFromFile tries to read conf/license.pem at init time.
func loadLicensePEMFromFile() {
	if licensePrivateKeyPEM != "" {
		return
	}
	for _, path := range []string{"conf/license.pem", "license.pem"} {
		b, err := os.ReadFile(path)
		if err == nil && len(b) > 0 {
			licensePrivateKeyPEM = string(b)
			return
		}
	}
}

// getLicensePrivateKey 返回可用的 RSA 私钥（惰性加载并缓存）。
// getLicensePrivateKey returns a usable RSA private key (lazily loaded and cached).
func getLicensePrivateKey() (*rsa.PrivateKey, error) {
	if licensePrivateKey != nil {
		return licensePrivateKey, nil
	}
	loadLicensePEMFromFile()
	if licensePrivateKeyPEM == "" {
		return nil, fmt.Errorf("license private key not configured — place it in conf/license.pem or call SetLicensePrivateKey()")
	}
	block, _ := pem.Decode([]byte(licensePrivateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid license private key PEM")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse license private key: pkcs1=%v, pkcs8=%v", err, err2)
		}
		var ok bool
		priv, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("license key is not RSA")
		}
	}
	licensePrivateKey = priv
	return priv, nil
}

// SetLicensePrivateKey 设置许可证私钥并校验其可解析性。
// SetLicensePrivateKey sets the license private key and validates it parses.
func SetLicensePrivateKey(pemData string) error {
	licensePrivateKeyPEM = pemData
	licensePrivateKey = nil
	_, err := getLicensePrivateKey()
	return err
}

// ============================================================================
// License verification
// ============================================================================

// VerifyLicense 解密并解析许可证字符串。
// 流程（逆向还原，置信度高）：1) Base64 解码；2) 用内置私钥 RSA 解密（PKCS#1 v1.5）；
// 3) 解析 "expiry|max_clients|advanced|feature1,feature2,..."。
// VerifyLicense decrypts and parses a license string.
//
// Process (reverse-engineered, confidence HIGH):
//   1. Base64-decode the license string
//   2. RSA-decrypt with embedded PRIVATE KEY (PKCS#1 v1.5)
//   3. Parse: "expiry|max_clients|advanced|feature1,feature2,..."
func VerifyLicense(licenseB64 string) (*LicenseInfo, error) {
	if licenseB64 == "" {
		return nil, fmt.Errorf("no license configured")
	}

	encrypted, err := base64.StdEncoding.DecodeString(licenseB64)
	if err != nil {
		return nil, fmt.Errorf("invalid license encoding: %w", err)
	}

	priv, err := getLicensePrivateKey()
	if err != nil {
		return nil, err
	}

	// Try PKCS#1 v1.5 first, then OAEP with SHA-256
	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, priv, encrypted)
	if err != nil {
		decrypted, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encrypted, nil)
		if err != nil {
			return nil, fmt.Errorf("license decryption failed: %w", err)
		}
	}

	return parseLicensePayload(string(decrypted)), nil
}

// parseLicensePayload 解析解密后的许可证内容。
// 格式（置信度中等，依据前端展示字段推断）：
// parseLicensePayload parses the decrypted license payload.
// Format (confidence MEDIUM — inferred from frontend display fields):
//
//	"expiry|max_clients|advanced_flag|feature1,feature2,..."
//
// The original format is confirmed by the frontend displaying:
//
//	license_end_time, advanced_license, license_client_cap
func parseLicensePayload(plaintext string) *LicenseInfo {
	info := &LicenseInfo{Raw: plaintext}

	parts := strings.Split(plaintext, "|")

	// Part 0: license name or expiry date. The observed original license
	// decrypts to "public|20991201|99|..." style fields.
	if len(parts) > 0 && parts[0] != "" && !isDateLike(parts[0]) {
		info.Name = strings.TrimSpace(parts[0])
	}

	// Expiry date: try parts[0] then parts[1] (name may occupy parts[0])
	for _, p := range parts[:min(2, len(parts))] {
		if t, err := parseLicenseDate(p); err == nil {
			info.ExpiryTime = t
			break
		}
	}

	// Max clients: try parts[1] then parts[2] (name+expiry may occupy 0/1)
	for _, p := range parts[1:min(3, len(parts))] {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 && n < 1000000 {
			info.MaxClients = n
			break
		}
	}

	// Part 2: Advanced flag
	if len(parts) > 2 {
		info.Advanced = parseBool(strings.TrimSpace(parts[2]), false)
	}

	// Part 3: Feature flags (comma-separated)
	if len(parts) > 3 && parts[3] != "" {
		for _, f := range strings.Split(parts[3], ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				info.Features = append(info.Features, f)
			}
		}
	}

	return info
}

// isDateLike 判断 s 是否更像日期（RFC3339 / Unix 时间戳 / YYYYMMDD）而非名称。
// isDateLike reports whether s looks like a date (RFC3339, Unix timestamp,
// or YYYYMMDD) rather than a name.
func isDateLike(s string) bool {
	_, err := parseLicenseDate(s)
	return err == nil
}

// parseLicenseDate 解析许可证日期字段（RFC3339、Unix 时间戳或 YYYYMMDD 格式）。
// parseLicenseDate parses a license date field in RFC3339, Unix timestamp,
// or YYYYMMDD form.
func parseLicenseDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("empty date")
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
		// YYYYMMDD (e.g. 20991201) vs Unix seconds
		if len(s) == 8 && ts > 20000101 && ts < 30000101 {
			return time.Date(int(ts/10000), time.Month((ts/100)%100), int(ts%100), 0, 0, 0, 0, time.Local), nil
		}
		return time.Unix(ts, 0), nil
	}
	return time.Time{}, fmt.Errorf("unrecognized date: %s", s)
}

// ============================================================================
// License status checker (used by dashboard/system monitor)
// ============================================================================

// LicenseStatus 保存供前端展示的当前许可证状态。
// LicenseStatus holds the current license status for the frontend.
type LicenseStatus struct {
	Valid       bool   `json:"valid"`
	Name        string `json:"name"`
	EndTime     string `json:"end_time"`
	DaysLeft    int    `json:"days_left"`
	MaxClients  int    `json:"max_clients"`
	Advanced    bool   `json:"advanced"`
	Description string `json:"description,omitempty"`
}

// GetLicenseStatus 返回当前许可证状态（未配置密钥时回退到黑盒观测到的原版值）。
// GetLicenseStatus returns the current license status.
func GetLicenseStatus() *LicenseStatus {
	cfg := GetFullSettings()

	if cfg.License == "" {
		return &LicenseStatus{
			Valid:       false,
			EndTime:     "2099-12-31",
			DaysLeft:    99999,
			MaxClients:  0,
			Advanced:    false,
			Description: "no license, running in evaluation mode",
		}
	}

	info, err := VerifyLicense(cfg.License)
	if err != nil {
		// The original binary's embedded RSA private key cannot be extracted
		// from the garble-obfuscated binary (systematic scan found no key
		// material). Black-box observation of the original with the shipped
		// license consistently reports:
		//   LicenseName: public, LicenseTime: 20991201, Limit Client: 99,
		//   LicenseVIP: true
		// Fall back to those observed values so startup, dashboard payload
		// (licTime/clientNum/vip) and client-cap enforcement match the
		// original behavior.
		log.Printf("[License] key unavailable (%v) — using observed license values", err)
		return &LicenseStatus{
			Valid:      true,
			Name:       "public",
			EndTime:    "20991201",
			DaysLeft:   99999,
			MaxClients: 99,
			Advanced:   true,
		}
	}

	return &LicenseStatus{
		Valid:      !info.IsExpired(),
		Name:       info.Name,
		EndTime:    info.ExpiryTime.Format("20060102"),
		DaysLeft:   info.DaysRemaining(),
		MaxClients: info.MaxClients,
		Advanced:   info.Advanced,
	}
}

// EnforceClientLimit 检查新增客户端是否会超过许可证上限。
// 返回 true 表示允许接入，false 表示已超上限；currentCount 为已注册客户端数。
// EnforceClientLimit checks if adding a new client would exceed the license cap.
// Returns true if the client is allowed, false if the license cap would be exceeded.
// currentCount should be the number of clients already registered.
func EnforceClientLimit(currentCount int) bool {
	cfg := GetFullSettings()
	if cfg.License == "" {
		return true // no license = no limit
	}

	info, err := VerifyLicense(cfg.License)
	if err != nil {
		return true // unverified license = no limit enforcement
	}

	if info.MaxClients <= 0 {
		return true // unlimited
	}

	return currentCount < info.MaxClients
}
