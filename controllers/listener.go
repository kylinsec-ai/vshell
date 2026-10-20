// Package controllers implements listener-management HTTP handlers.
// The available operations and their effects are defined by the current implementation;
// historical endpoint maps should not be treated as proof of behavioral parity.

package controllers

// ListenerController 管理 C2 监听器。
type ListenerController struct {
	ApiBaseController
}

// List 分页列出监听器（POST /listener/list）。
// 反编译（0x18ea020）参数：page / pageSize / status / field / order / search / sort；
// 响应 {"total":N,"items":[...]}，每项含 Id / Mode / Status / OssUrl / Remark / Vkey。
func (c *ListenerController) List() {
	page := c.JsonGetInt("page")
	if page < 1 {
		page = 1
	}
	pageSize := c.JsonGetInt("pageSize")
	if pageSize < 1 {
		pageSize = 10
	}
	status := c.JsonGetInt("status")
	list, total := engineGetListenerList((page-1)*pageSize, pageSize,
		c.JsonGetStr("field"), c.JsonGetStr("order"),
		c.JsonGetStr("search"), c.JsonGetStr("sort"), status)
	items := make([]map[string]interface{}, 0, len(list))
	for _, l := range list {
		items = append(items, map[string]interface{}{
			"Id":     l.ID,
			"Mode":   l.Mode,
			"Status": l.Status,
			"OssUrl": l.OssUrl,
			"Remark": l.Remark,
			"Vkey":   l.Vkey,
			"Port":   l.Port,
			"Host":   l.Host,
			"Proxy":  l.Proxy,
			"Salt":   l.Salt,
			"vip":    l.IsVIP,
		})
	}
	c.JsonOkResult(map[string]interface{}{"total": total, "items": items})
}

// Add 新增监听器（POST /listener/add）。
// 反编译（0x18ec880）参数：Mode / Vkey / OssUrl / Remark / vip。
func (c *ListenerController) Add() {
	l := EngineListener{
		Mode:   c.JsonGetStr("Mode"),
		Vkey:   c.JsonGetStr("Vkey"),
		OssUrl: c.JsonGetStr("OssUrl"),
		Remark: c.JsonGetStr("Remark"),
		IsVIP:  c.JsonGetBool("vip"),
	}
	if l.Mode == "" {
		c.JsonErr("mode required")
		return
	}
	if err := engineAddListener(l); err != nil {
		c.JsonErr("add listener failed: " + err.Error())
		return
	}
	c.JsonOkMessage("ok")
}

// Edit 编辑监听器（POST /listener/edit）。
// 反编译（0x18ec280）参数：Id / Mode / Vkey / OssUrl / Remark / vip。
func (c *ListenerController) Edit() {
	l := EngineListener{
		ID:     int64(c.JsonGetInt("Id")),
		Mode:   c.JsonGetStr("Mode"),
		Vkey:   c.JsonGetStr("Vkey"),
		OssUrl: c.JsonGetStr("OssUrl"),
		Remark: c.JsonGetStr("Remark"),
		IsVIP:  c.JsonGetBool("vip"),
	}
	if l.ID == 0 {
		c.JsonErr("id err")
		return
	}
	if err := engineEditListener(l); err != nil {
		c.JsonErr("edit listener failed: " + err.Error())
		return
	}
	c.JsonOkMessage("ok")
}

// EditRemark 修改监听器备注（POST /listener/editremark）。参数：id / remark。
func (c *ListenerController) EditRemark() {
	id := int64(c.JsonGetInt("id"))
	remark := c.JsonGetStr("remark")
	if id == 0 {
		c.JsonErr("id err")
		return
	}
	engineEditListenerRemark(id, remark)
	c.JsonOkMessage("ok")
}

// Del 删除监听器（POST /listener/del）。参数：id。
func (c *ListenerController) Del() {
	id := int64(c.JsonGetInt("id"))
	if id == 0 {
		c.JsonErr("id err")
		return
	}
	engineDelListener(id)
	c.JsonOkMessage("ok")
}

// DelList 批量删除监听器（POST /listener/dellist）。参数：id（逗号分隔）。
func (c *ListenerController) DelList() {
	ids := c.JsonGetIntList("id")
	if len(ids) == 0 {
		c.JsonErr("id err")
		return
	}
	id64 := make([]int64, len(ids))
	for i, v := range ids {
		id64[i] = int64(v)
	}
	engineDelListeners(id64)
	c.JsonOkMessage("ok")
}

// Start 启动监听器（POST /listener/start）。参数：id。
func (c *ListenerController) Start() {
	id := int64(c.JsonGetInt("id"))
	if id == 0 {
		c.JsonErr("id err")
		return
	}
	if err := engineStartListener(id); err != nil {
		c.JsonErr(err.Error())
		return
	}
	c.JsonOkMessage("ok")
}

// Stop 停止监听器（POST /listener/stop）。参数：id。
func (c *ListenerController) Stop() {
	id := int64(c.JsonGetInt("id"))
	if id == 0 {
		c.JsonErr("id err")
		return
	}
	engineStopListener(id)
	c.JsonOkMessage("ok")
}
