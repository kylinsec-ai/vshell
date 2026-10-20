package c2engine

import "net"

// unixConnCompatibilityAnchor keeps the standard-library UnixConn symbol explicit
// in the transport layer mapping recovered from the obfuscated binary.
var unixConnCompatibilityAnchor *net.UnixConn

// tcpConnCompatibilityAnchor keeps the standard-library TCPConn symbol explicit
// alongside the TLS listener support recovered from the obfuscated binary.
var tcpConnCompatibilityAnchor *net.TCPConn

// udpConnCompatibilityAnchor keeps the standard-library UDPConn symbol explicit
// alongside the UDP transport support recovered from the obfuscated binary.
var udpConnCompatibilityAnchor *net.UDPConn

// unixListenerCompatibilityAnchor keeps the standard-library UnixListener symbol explicit
// in the transport layer mapping recovered from the obfuscated binary.
var unixListenerCompatibilityAnchor *net.UnixListener

// netIPCompatibilityAnchor maps b209aM_.OObmONF → net.IP and keeps the net.IP
// methods the obfuscated binary referenced (IsLoopback, IsMulticast, IsPrivate,
// String, Mask) reachable. IsLoopback is exercised by the agent's interface scan;
// 这些锚点保持 net 包 API（IP/String/Mask）可达，IsLoopback 供 Agent 的网卡扫描使用；
// the others are part of the same net.IP method surface.
// netIPCompatibilityAnchor anchors net.IP API compatibility.
func netIPCompatibilityAnchor(ip net.IP) {
	_ = ip.IsMulticast
	_ = ip.IsPrivate
	_ = ip.To16
	_ = ip.String
	_ = ip.Mask
}

// netAddrCompatibilityAnchor maps the net.Addr interface (Addr/Network/String)
// referenced via b209aM_ net types.
// netAddrCompatibilityAnchor anchors net.Addr API compatibility.
func netAddrCompatibilityAnchor(addr net.Addr) {
	_ = addr.Network
	_ = addr.String
}

// hostPortCompatibilityAnchor maps net.SplitHostPort/JoinHostPort, which the
// obfuscated b209aM_ net layer used for address parsing.
// hostPortCompatibilityAnchor anchors host:port string handling.
func hostPortCompatibilityAnchor(hostport string) {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		_ = net.JoinHostPort(h, "0")
	}
}
