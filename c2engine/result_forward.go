// Package c2engine/result_forward defines the streaming-result forwarding hook:
// relays terminal output and screen frames live to web viewers.
package c2engine

import "strings"

// Result forwarding hooks.
//
// Agents submit task results to the LISTENER's /api/result endpoint. Streaming
// results — interactive terminal output ("terminal_output:…") and screen
// capture frames ("screen_frame:…") — must be relayed live to the web-panel
// WebSocket viewers (terminal / screen). c2engine cannot import controllers
// (that would be a cycle), so controllers register a single forwarder hook here
// and the listener result handlers call it for those streaming result types.

var resultForwardHook func(clientID int64, result string)
// SetResultForwardHook registers the controller-side forwarder. Called once at
// package init. Passing nil unregisters.
func SetResultForwardHook(f func(clientID int64, result string)) {
	resultForwardHook = f
}

// forwardStreamingResult 将流式结果交给注册的钩子。
// 返回 true 表示结果是流式类型（无论是否注册了钩子），调用方可将之视为已消费。
// forwardStreamingResult hands a streaming result to the registered hook.
// Returns true if the result was a streaming type (whether or not a hook was
// registered), so callers can treat it as consumed.
func forwardStreamingResult(clientID int64, result string) bool {
	if !IsStreamingResult(result) {
		return false
	}
	if resultForwardHook != nil {
		resultForwardHook(clientID, result)
	}
	// Fan the payload out to this client's live WebSocket viewers (terminal /
	// screen). The hook above is for controller-side consumers; HandleStreamingResult
	// is the engine-side relay and runs regardless of whether a hook is registered.
	HandleStreamingResult(clientID, result)
	return true
}
// IsStreamingResult reports whether a result payload is a live-streaming type
// that must be forwarded to a WebSocket viewer rather than only stored.
func IsStreamingResult(result string) bool {
	return strings.HasPrefix(result, "terminal_output:") ||
		strings.HasPrefix(result, "screen_frame:")
}
