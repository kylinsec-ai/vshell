// Package utils — DingDing & WeChat robot notification system.
// 钉钉 / 企业微信机器人告警系统：新 Agent 上线、离线、监听启停、错误等事件推送。
//
// Reverse-engineered from the original vshell binary (v_windows_amd64.exe).
//
// The original binary sends notifications to DingDing (钉钉) and/or WeChat (微信)
// robots when significant events occur:
//   - New agent checks in
//   - Agent goes offline
//   - Listener starts/stops
//   - Errors or warnings
//
// Evidence:
//   - Original setting.conf field: dingding_access_token, dingding_key_word
//   - Original setting.conf field: wx_key
//   - Frontend references notification settings
//
// Confidence: MEDIUM (config fields confirmed; exact HTTP payload format
// for DingDing/WeChat webhook API is standard and well-documented)

// Compatibility notes in this file describe the current implementation and available analysis evidence; they are not a guarantee of complete behavioral parity.
// Treat security-sensitive assumptions as unverified until confirmed by tests or direct review.

package utils

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Notification types
// ============================================================================

// NotifyEvent 表示可触发通知的事件类型。
// NotifyEvent represents a notification-triggering event.
type NotifyEvent string

const (
	EventNewAgent     NotifyEvent = "new_agent"     // new agent checked in
	EventAgentOffline NotifyEvent = "agent_offline" // agent disconnected
	EventListenerStart NotifyEvent = "listener_start"
	EventListenerStop  NotifyEvent = "listener_stop"
	EventError         NotifyEvent = "error"
	EventWarning       NotifyEvent = "warning"
)

// NotifyPayload 保存单条事件的通知数据。
// NotifyPayload holds the notification data for a single event.
type NotifyPayload struct {
	Event     NotifyEvent `json:"event"`
	Title     string      `json:"title"`
	Content   string      `json:"content"`
	Timestamp time.Time   `json:"timestamp"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// ============================================================================
// Notifier — sends notifications to configured channels
// ============================================================================

// Notifier 管理向钉钉/企业微信机器人发送通知。
// Notifier manages notification delivery to DingDing/WeChat robots.
type Notifier struct {
	mu       sync.RWMutex
	cfg      *FullSettings
	client   *http.Client
	enabled  bool
	lastSend map[NotifyEvent]time.Time // rate limiting
}

var (
	notifier     *Notifier
	notifierOnce sync.Once
)

// GetNotifier 返回全局通知管理器（单例）。
// GetNotifier returns the global notification manager.
func GetNotifier() *Notifier {
	notifierOnce.Do(func() {
		notifier = &Notifier{
			cfg:      GetFullSettings(),
			client:   &http.Client{Timeout: 10 * time.Second},
			lastSend: make(map[NotifyEvent]time.Time),
		}
	})
	return notifier
}

// Start 启用通知系统并校验配置（至少配置一个渠道才生效）。
// Start enables the notification system and validates configuration.
func (n *Notifier) Start() {
	n.mu.Lock()
	defer n.mu.Unlock()

	hasDingDing := n.cfg.DingdingAccessToken != ""
	hasWeChat := n.cfg.WxKey != ""

	n.enabled = hasDingDing || hasWeChat

	if n.enabled {
		channels := []string{}
		if hasDingDing {
			channels = append(channels, "DingDing")
		}
		if hasWeChat {
			channels = append(channels, "WeChat")
		}
		log.Printf("[Notify] Enabled: %s", strings.Join(channels, ", "))
	} else {
		log.Printf("[Notify] No notification channels configured")
	}
}

// Send 向所有已配置渠道发送通知；每种事件类型限流（每 60 秒最多 1 条）。
// Send sends a notification to all configured channels.
// Rate-limited per event type (max 1 per 60 seconds).
func (n *Notifier) Send(payload *NotifyPayload) {
	if payload == nil {
		return
	}

	n.mu.RLock()
	enabled := n.enabled
	n.mu.RUnlock()

	if !enabled {
		return
	}

	// Rate limit: at most one notification per event type per 60 seconds
	n.mu.Lock()
	last, exists := n.lastSend[payload.Event]
	if exists && time.Since(last) < 60*time.Second {
		n.mu.Unlock()
		return
	}
	n.lastSend[payload.Event] = time.Now()
	n.mu.Unlock()

	// Read config once
	n.mu.RLock()
	cfg := n.cfg
	n.mu.RUnlock()

	if cfg.DingdingAccessToken != "" {
		go n.sendDingDing(cfg, payload)
	}
	if cfg.WxKey != "" {
		go n.sendWeChat(cfg, payload)
	}
}

// ============================================================================
// DingDing (钉钉) robot webhook
// ============================================================================

// DingDingMessage 是钉钉自定义机器人 webhook 的消息体。
// 参考：https://open.dingtalk.com/document/orgapp/custom-robot-access
// DingDingMessage is the webhook payload for DingDing robot.
type DingDingMessage struct {
	MsgType  string            `json:"msgtype"`
	Markdown *DingDingMarkdown `json:"markdown,omitempty"`
	Text     *DingDingText     `json:"text,omitempty"`
}

type DingDingMarkdown struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

type DingDingText struct {
	Content string `json:"content,omitempty"`
}

// sendDingDing 异步发送钉钉 markdown 消息。
// sendDingDing asynchronously sends a DingDing markdown message.
func (n *Notifier) sendDingDing(cfg *FullSettings, payload *NotifyPayload) {
	// Build markdown message
	emoji := dingDingEmoji(payload.Event)
	title := fmt.Sprintf("%s %s %s", emoji, payload.Title, emoji)

	text := fmt.Sprintf("## %s\n\n", title)
	text += fmt.Sprintf("**时间**: %s\n\n", payload.Timestamp.Format("2006-01-02 15:04:05"))
	text += fmt.Sprintf("**内容**: %s\n\n", payload.Content)

	for k, v := range payload.Metadata {
		text += fmt.Sprintf("- **%s**: %s\n", k, v)
	}

	msg := &DingDingMessage{
		MsgType: "markdown",
		Markdown: &DingDingMarkdown{
			Title: payload.Title,
			Text:  text,
		},
	}

	body, _ := json.Marshal(msg)

	// Build URL with access token and optional keyword
	url := fmt.Sprintf("https://oapi.dingtalk.com/robot/send?access_token=%s", cfg.DingdingAccessToken)

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[Notify:DingDing] Failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("[Notify:DingDing] Send failed: %v", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		log.Printf("[Notify:DingDing] Non-200 response: %d — %s", resp.StatusCode, string(respBody))
		return
	}

	// Parse response to check success
	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	json.Unmarshal(respBody, &result)

	if result.ErrCode != 0 {
		log.Printf("[Notify:DingDing] API error: %d — %s", result.ErrCode, result.ErrMsg)
	} else {
		log.Printf("[Notify:DingDing] Sent: %s", payload.Title)
	}
}

// dingDingEmoji 返回事件对应的表情符号。
// dingDingEmoji returns the emoji for an event type.
func dingDingEmoji(event NotifyEvent) string {
	switch event {
	case EventNewAgent:
		return "🟢"
	case EventAgentOffline:
		return "🔴"
	case EventListenerStart:
		return "▶️"
	case EventListenerStop:
		return "⏹️"
	case EventError:
		return "❌"
	case EventWarning:
		return "⚠️"
	default:
		return "📢"
	}
}

// ============================================================================
// WeChat (企业微信) robot webhook
// ============================================================================

// WeChatMessage 是企业微信机器人 webhook 的消息体。
// 参考：https://developer.work.weixin.qq.com/document/path/91770
// WeChatMessage is the webhook payload for WeChat Work robot.
type WeChatMessage struct {
	MsgType  string          `json:"msgtype"`
	Markdown *WeChatMarkdown `json:"markdown,omitempty"`
	Text     *WeChatText     `json:"text,omitempty"`
}

type WeChatMarkdown struct {
	Content string `json:"content"`
}

type WeChatText struct {
	Content       string   `json:"content"`
	MentionedList []string `json:"mentioned_list,omitempty"`
}

// sendWeChat 异步发送企业微信 markdown 消息。
// sendWeChat asynchronously sends a WeChat Work markdown message.
func (n *Notifier) sendWeChat(cfg *FullSettings, payload *NotifyPayload) {
	title := fmt.Sprintf("【%s】%s", eventLabel(payload.Event), payload.Title)

	content := fmt.Sprintf("## %s\n", title)
	content += fmt.Sprintf("> 时间: %s\n", payload.Timestamp.Format("2006-01-02 15:04:05"))
	content += fmt.Sprintf("> 内容: %s\n", payload.Content)

	for k, v := range payload.Metadata {
		content += fmt.Sprintf("> %s: <font color=\"info\">%s</font>\n", k, v)
	}

	msg := &WeChatMessage{
		MsgType: "markdown",
		Markdown: &WeChatMarkdown{
			Content: content,
		},
	}

	body, _ := json.Marshal(msg)

	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=%s", cfg.WxKey)

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[Notify:WeChat] Failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("[Notify:WeChat] Send failed: %v", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		log.Printf("[Notify:WeChat] Non-200 response: %d — %s", resp.StatusCode, string(respBody))
		return
	}

	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	json.Unmarshal(respBody, &result)

	if result.ErrCode != 0 {
		log.Printf("[Notify:WeChat] API error: %d — %s", result.ErrCode, result.ErrMsg)
	} else {
		log.Printf("[Notify:WeChat] Sent: %s", payload.Title)
	}
}

// eventLabel 返回事件的中文标签。
// eventLabel returns the Chinese label for an event type.
func eventLabel(event NotifyEvent) string {
	switch event {
	case EventNewAgent:
		return "新Agent上线"
	case EventAgentOffline:
		return "Agent离线"
	case EventListenerStart:
		return "监听启动"
	case EventListenerStop:
		return "监听停止"
	case EventError:
		return "错误"
	case EventWarning:
		return "警告"
	default:
		return "通知"
	}
}

// ============================================================================
// Convenience functions
// ============================================================================

// NotifyNewAgent 发送新 Agent 上线通知。
// NotifyNewAgent sends a new-agent-checkin notification.
func NotifyNewAgent(hostName, userName, osName, remoteAddr string, clientID int64) {
	GetNotifier().Send(&NotifyPayload{
		Event:   EventNewAgent,
		Title:   fmt.Sprintf("新Agent上线: %s", hostName),
		Content: fmt.Sprintf("Agent %d 已上线", clientID),
		Metadata: map[string]string{
			"主机名":   hostName,
			"用户名":   userName,
			"操作系统":  osName,
			"IP地址":  remoteAddr,
			"AgentID": fmt.Sprintf("%d", clientID),
		},
		Timestamp: time.Now(),
	})
}

// NotifyAgentOffline 发送 Agent 离线通知。
// NotifyAgentOffline sends an agent-disconnect notification.
func NotifyAgentOffline(hostName string, clientID int64) {
	GetNotifier().Send(&NotifyPayload{
		Event:   EventAgentOffline,
		Title:   fmt.Sprintf("Agent离线: %s", hostName),
		Content: fmt.Sprintf("Agent %d 已离线", clientID),
		Metadata: map[string]string{
			"主机名":   hostName,
			"AgentID": fmt.Sprintf("%d", clientID),
		},
		Timestamp: time.Now(),
	})
}

// NotifyListenerEvent 发送监听器启停通知。
// NotifyListenerEvent sends a listener start/stop notification.
func NotifyListenerEvent(event NotifyEvent, listenAddr, mode string, listenerID int64) {
	var titleFmt string
	if event == EventListenerStart {
		titleFmt = "监听启动: %s"
	} else {
		titleFmt = "监听停止: %s"
	}

	GetNotifier().Send(&NotifyPayload{
		Event:   event,
		Title:   fmt.Sprintf(titleFmt, listenAddr),
		Content: fmt.Sprintf("监听器 %d (%s 模式) 已%s", listenerID, mode, eventLabel(event)),
		Metadata: map[string]string{
			"地址":    listenAddr,
			"模式":    mode,
			"监听器ID": fmt.Sprintf("%d", listenerID),
		},
		Timestamp: time.Now(),
	})
}

// ============================================================================
// Signing utilities (for DingDing custom robot security)
// ============================================================================

// DingDingSign 为开启"加签"的钉钉机器人生成签名参数（timestamp + HMAC-SHA256）。
// DingDingSign generates the sign parameter for DingDing custom robot
// with additional security (secret-based signature).
// Only needed if the DingDing robot has "加签" (signature verification) enabled.
func DingDingSign(secret string, timestamp int64) (string, string) {
	stringToSign := fmt.Sprintf("%d\n%s", timestamp, secret)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(stringToSign))
	sign := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return sign, fmt.Sprintf("%d", timestamp)
}
