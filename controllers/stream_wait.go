// Package controllers/stream_wait 提供任务结果等待原语。
// This file holds the shared helper the terminal and screen controllers use to
// collect an agent's answer to a one-shot command.
package controllers

import (
	"fmt"
	"time"

	"vshell/c2engine"
)
// shellWaitTimeout bounds how long a one-shot command waits for the agent.
const shellWaitTimeout = 20 * time.Second
// waitTaskResult polls a task until the agent's result submission moves it out
// of pending/dispatched, or the timeout expires.
//
// The agent answers a one-shot command (TerminalController.Shell) with a normal
// result, which the listener stores through Engine.UpdateTask. Streaming
// results (terminal/screen frames) do NOT update the task — the agent sends
// them through the same result endpoint but the listener forwards them to the
// viewers instead of storing them — so a command whose only answer is a stream
// keeps the task at "dispatched" until StreamTimeout. That is why streaming
// commands are dispatched without waiting (engineExecShellAsync).
func waitTaskResult(taskID int64, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		task := c2engine.GetEngine().GetTask(taskID)
		if task == nil {
			return "", fmt.Errorf("task %d disappeared", taskID)
		}
		switch task.Status {
		case "completed", "failed", "timeout":
			return task.Result, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return "", fmt.Errorf("task %d timed out", taskID)
}

// itoa 是 strconv.Itoa 的本地别名，避免在协议拼接处反复导入 strconv。
func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
