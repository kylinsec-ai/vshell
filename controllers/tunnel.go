// Package controllers implements tunnel-management HTTP handlers.
// Supported operations and their effects reflect the current implementation and
// should be verified through tests rather than assumed from historical analysis.

package controllers

// TunnelController 管理端口转发/隧道。
type TunnelController struct {
	ApiBaseController
}

// List 分页列出隧道（POST /tunnel/list）。
// 反编译（0x18f1140）参数：page / pageSize / field / order / search / sort；
// 响应 {"total":N,"items":[...]}，每项含 Id / Target / Mode / Remark / Port。
func (c *TunnelController) List() {
	page := c.JsonGetInt("page")
	if page < 1 {
		page = 1
	}
	pageSize := c.JsonGetInt("pageSize")
	if pageSize < 1 {
		pageSize = 10
	}
	list, total := engineGetTunnelList((page-1)*pageSize, pageSize,
		c.JsonGetStr("field"), c.JsonGetStr("order"),
		c.JsonGetStr("search"), c.JsonGetStr("sort"))
	items := make([]map[string]interface{}, 0, len(list))
	for _, t := range list {
		items = append(items, map[string]interface{}{
			"Id":     t.ID,
			"Target": t.Target,
			"Mode":   t.Mode,
			"Remark": t.Remark,
			"Port":   t.Port,
		})
	}
	c.JsonOkResult(map[string]interface{}{"total": total, "items": items})
}

// Add 新增隧道（POST /tunnel/add）。
// 反编译（0x18f31a0）参数：Port / Mode / Target / Remark。
func (c *TunnelController) Add() {
	t := EngineTunnel{
		Port:   c.JsonGetInt("Port"),
		Mode:   c.JsonGetStr("Mode"),
		Target: c.JsonGetStr("Target"),
		Remark: c.JsonGetStr("Remark"),
	}
	if t.Port == 0 || t.Target == "" {
		c.JsonErr("port and target required")
		return
	}
	if err := engineAddTunnel(t); err != nil {
		c.JsonErr("add tunnel failed: " + err.Error())
		return
	}
	c.JsonOkMessage("ok")
}

// Edit 编辑隧道（POST /tunnel/edit）。
// 反编译（0x18f2ce0）参数：Id / Port / Mode / Target / Remark。
func (c *TunnelController) Edit() {
	t := EngineTunnel{
		ID:     int64(c.JsonGetInt("Id")),
		Port:   c.JsonGetInt("Port"),
		Mode:   c.JsonGetStr("Mode"),
		Target: c.JsonGetStr("Target"),
		Remark: c.JsonGetStr("Remark"),
	}
	if t.ID == 0 {
		c.JsonErr("id err")
		return
	}
	if err := engineEditTunnel(t); err != nil {
		c.JsonErr("edit tunnel failed: " + err.Error())
		return
	}
	c.JsonOkMessage("ok")
}

// EditRemark 修改隧道备注（POST /tunnel/editremark）。参数：id / remark。
func (c *TunnelController) EditRemark() {
	id := int64(c.JsonGetInt("id"))
	remark := c.JsonGetStr("remark")
	if id == 0 {
		c.JsonErr("id err")
		return
	}
	// 原版仅更新备注字段
	engineEditTunnel(EngineTunnel{ID: id, Remark: remark})
	c.JsonOkMessage("ok")
}

// Del 删除隧道（POST /tunnel/del）。参数：id。
func (c *TunnelController) Del() {
	id := int64(c.JsonGetInt("id"))
	if id == 0 {
		c.JsonErr("id err")
		return
	}
	engineDelTunnel(id)
	c.JsonOkMessage("ok")
}

// DelList 批量删除隧道（POST /tunnel/dellist）。参数：id（逗号分隔）。
func (c *TunnelController) DelList() {
	ids := c.JsonGetIntList("id")
	if len(ids) == 0 {
		c.JsonErr("id err")
		return
	}
	id64 := make([]int64, len(ids))
	for i, v := range ids {
		id64[i] = int64(v)
	}
	engineDelTunnels(id64)
	c.JsonOkMessage("ok")
}

// Start 启动隧道（POST /tunnel/start）。参数：id。
func (c *TunnelController) Start() {
	id := int64(c.JsonGetInt("id"))
	if id == 0 {
		c.JsonErr("id err")
		return
	}
	engineStartTunnel(id)
	c.JsonOkMessage("ok")
}

// Stop 停止隧道（POST /tunnel/stop）。参数：id。
func (c *TunnelController) Stop() {
	id := int64(c.JsonGetInt("id"))
	if id == 0 {
		c.JsonErr("id err")
		return
	}
	engineStopTunnel(id)
	c.JsonOkMessage("ok")
}
