// Package controllers implements installation-related HTTP handlers.
// The current handlers and their side effects should be verified from implementation
// and tests; historical reverse-engineering notes are not compatibility guarantees.

package controllers

// InstallController 管理客户端持久化安装。
type InstallController struct {
	ApiBaseController
}

// Install 在客户端安装持久化（POST /install/install）。参数：id / name。
func (c *InstallController) Install() {
	id := int64(c.JsonGetInt("id"))
	name := c.JsonGetStr("name")
	if id == 0 {
		c.JsonErr("id err")
		return
	}
	dispatchCmd(id, "install "+name)
	c.JsonOkMessage("ok")
}

// Remove 移除客户端持久化（POST /install/remove）。参数：id / name。
func (c *InstallController) Remove() {
	id := int64(c.JsonGetInt("id"))
	name := c.JsonGetStr("name")
	if id == 0 {
		c.JsonErr("id err")
		return
	}
	dispatchCmd(id, "uninstall "+name)
	c.JsonOkMessage("ok")
}
